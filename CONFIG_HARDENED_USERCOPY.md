# Hardened usercopy

`CONFIG_HARDENED_USERCOPY` is a kernel configuration option in the Linux kernel
that enables additional security checks during the copy operations between
user-space and kernel-space memory. This feature is part of the kernel's efforts
to protect against various security vulnerabilities, such as buffer overflows
and data corruption.

When `CONFIG_HARDENED_USERCOPY` is enabled, the kernel performs extra
validations on the data being copied from user space to kernel space and vice
versa. These validations help ensure that the memory regions involved in the
copy operations are appropriately allocated, accessible, and do not exceed their
intended boundaries.

Some of the security enhancements provided by `CONFIG_HARDENED_USERCOPY` may
include:
- **Checking for valid memory regions**
The kernel checks whether the memory addresses provided during copy operations
are valid user or kernel addresses to prevent unauthorized access.
- **Boundary checks**
The kernel verifies that the amount of data being copied doesn't exceed the size
of the destination buffer, preventing buffer overflows and potential code
execution exploits.
- **Prohibited access to certain memory regions**
The kernel might restrict copying data to certain sensitive memory regions,
enhancing security and protecting against data corruption.

You can find a brief history of efforts and discussions that have been made
[here](https://lwn.net/Articles/695991/). Also, there is a full changelog and
history of the changes in the Linux source code available
[here](https://lore.kernel.org/lkml/20170628165520.GA129364@gmail.com/t/) and
[here](https://groups.google.com/g/linux.kernel/c/y9Dgu5HD1bg?pli=1).


Before start investigating the source code for this patch, let's have an
introduction to user space and kernel space.


- **User Space** is the memory area where user-level applications and processes
run. This is where most of the user's programs, such as web browsers, text
editors, games, and other applications, execute. User space applications
interact directly with the user and handle various tasks based on the user's
input. In user space, programs are executed in a restricted environment with
limited privileges. This means they cannot access or modify critical system
resources directly, such as hardware devices or low-level system memory.
Instead, they have to make system calls to the operating system kernel to
request access to these resources. User space offers better isolation between
different applications, ensuring that a malfunction or crash in one program does
not affect others. It also provides a level of security, as user space processes
are unable to compromise the integrity of the operating system or other
processes directly.

- **Kernel Space**, also known as supervisor mode or system space, is a
privileged memory area reserved for the operating system's core functions. It
contains the kernel, which is the heart of the operating system responsible for
managing hardware, memory, file systems, and various system services. The kernel
operates at a higher privilege level than user space processes. It has direct
access to system resources, hardware, and low-level memory. This access allows
it to perform critical tasks that require deep system integration, such as
controlling device drivers, managing memory, scheduling processes, and handling
interrupts. Since the kernel operates at a higher privilege level, it must be
protected from user space processes to maintain system stability and security.
Accidental or malicious access to kernel space by user space applications could
lead to system crashes, data corruption, or security breaches. Therefore, modern
operating systems implement mechanisms, such as memory protection, to prevent
unauthorized access from user space to kernel space.

In summary, user space is the area where user-level applications run, operating
in a restricted environment with limited privileges, while kernel space is a
privileged area where the core operating system functions execute, having direct
access to system resources. The separation of these two spaces is essential for
maintaining system stability, security, and isolation between user-level
processes and the operating system itself.


## Reading the Kernel Sources

To understand how it works, we read through the implementation in aid of the
text linked above.

### Configuration

Let's first look at how the configuration `CONFIG_HARDENED_USERCOPY` enables the
check in linux-6.4.8.

The main part of implementation can be fouond at `mm/usercopy.c`. Starting from
the bottom, `bypass_usercopy_checks` is used locally to determine whether the
checks should be performed. Note that because `CONFIG_HARDENED_USERCOPY=y` is
the default configuration on all architectures, `bypass_usercopy_checks` is more
likely to be false. So to utilize branch prediction,
`static_branch_unlikely(&bypass_usercopy_checks)` is used in the condition that
determines if the check is needed in `__check_object_size`.

### Implementation in the Kernel Headers

Before we dig into the implementation of the checks themselves, let's see how
and where the checks are utilized. `__check_object_size` handles all the checks
needed. It is the entry point to the meat of hardened usercopy from the kernel.
The API to access it is implemented in `include/linux/thread_info.h`, where we
can find two wrapper functions `check_object_size` and `check_copy_size`.

The checks are added in the shared kernel header `include/linux/uaccess.h`.
According to this comment:
```c
/* 
 * Architectures should provide two primitives (raw_copy_{to,from}_user())
 * and get rid of their private instances of copy_{to,from}_user() and
 * __copy_{to,from}_user{,_inatomic}().
 * 
 * ...
 * /
```

This makes the checks available to all architectures, and each architecture only
needs to implement the `raw_copy_{to,from}_user` functions, which is wrapped by
the checks.

#### `check_object_size`
`check_object_size` is a very thin wrapper on top of `__check_object_size`, with
an optimization that skips the check if `n`, the size of the memory object, is
constant and known during compilation. This exempts trusted calls from overflow
protection.

The main difference between the two is that `check_object_size` is used in the
inlined `__copy_{to,from}_user_inatomic()` variants, and `check_copy_size` is
used in the *optionally* inlined `_copy_{to,from}_user` functions depending on
the architecture. Note that `check_copy_size` is also used in
`copy_{from,to}_iter` and `copy_from_iter_nocache`, which are I/O related
functions that copy data to the kernel-space memory, so it makes sense to do the
boundary checks there as well.

### Logistics of the checks

#### `__check_object_size`
`__check_object_size` takes a pointer `ptr` inside the kernel-space memory, the
size `n` of the object to be copied, and a flag `to_user` indicating the
direction of the copy. As of 6.4.8, four checks are implemented. They are
executed in the following order:
- `check_bogus_address`
- `check_stack_object`
- `check_heap_object`
- `check_kernel_text_object`

#### `check_bogus_address`
`check_bogus_address` is obvious. It checks if the given pointer wraps around
the end of memory (i.e.: `ptr + (n - 1) < ptr`), if the pointer is NULL or
zero-sized.

```c
static inline void check_bogus_address(const unsigned long ptr, unsigned long n, bool to_user)
{
	/* Reject if object wraps past end of memory. */
	if (ptr + (n - 1) < ptr)
		usercopy_abort("wrapped address", NULL, to_user, 0, ptr + n);

	/* Reject if NULL or ZERO-allocation. */
	if (ZERO_OR_NULL_PTR(ptr))
		usercopy_abort("null address", NULL, to_user, ptr, n);
}
```

#### `check_stack_object`
`check_stack_object` performs a check and returns one of the four possible 
results:
`NOT_STACK`: not at all on the stack
`GOOD_FRAME`: fully within a valid stack frame
`GOOD_STACK`: within the current stack (when can't frame-check exactly)
`BAD_STACK`: error condition (invalid stack position or bad stack frame)

```c
static noinline int check_stack_object(const void *obj, unsigned long len)
{
    const void * const stack = task_stack_page(current);
    const void * const stackend = stack + THREAD_SIZE;
    int ret;

    /***/
}

```
It accesses `task_stack_page` to get the size of the current thread, and first
check if the pointer is actually pointing inside the stack. If not, it returns
`NOT_STACK`.
```c

static noinline int check_stack_object(const void *obj, unsigned long len)
{
    /***/

    /* Object is not on the stack at all. */
    if (obj + len <= stack || stackend <= obj)
        return NOT_STACK;

    /**/
}

```

`BAD_STACK` is returned if the object partially overlaps. And optionally, if the
information is available in the current architecture, it performs a check on the
stack frame. It is specifically implemented and improved in the
[x86](https://lwn.net/Articles/697545/) architecture to enhance the completeness
of the check. Interestingly, the only other modern architecture
that supports this at the time of writing is powerpc. There was a
[complaint](https://www.openwall.com/lists/kernel-hardening/2020/08/18/1) about
this in 2020.

```c
static noinline int check_stack_object(const void *obj, unsigned long len)
{
    /***/

    /*
    * Reject: object partially overlaps the stack (passing the
    * check above means at least one end is within the stack,
    * so if this check fails, the other end is outside the stack).
    */
    if (obj < stack || stackend < obj + len)
        return BAD_STACK;

    /* Check if object is safely within a valid frame. */
    ret = arch_within_stack_frames(stack, stackend, obj, len);
    if (ret)
        return ret;

    /***/
}
```


Another optional check depends on
`CONFIG_ARCH_HAS_CURRENT_STACK_POINTER` (enabled on mips) when the stack frame
check is not available. It works by merely checking if the address is on the
stack.

```c
static noinline int check_stack_object(const void *obj, unsigned long len)
{
    /***/

    /* Finally, check stack depth if possible. */
#ifdef CONFIG_ARCH_HAS_CURRENT_STACK_POINTER
    if (IS_ENABLED(CONFIG_STACK_GROWSUP)) {
        if ((void *)current_stack_pointer < obj + len)
            return BAD_STACK;
    } else {
        if (obj < (void *)current_stack_pointer)
            return BAD_STACK;
    }
#endif

    /***/
}
```

If none of above conditions are met, it will return `GOOD_STACK` which means the
object is placed within the current stack but it doesn't tell anything about the
frame-check.

#### `check_heap_object`
`check_heap_object` first checks if the address is within a high-memory page
that is temporarily mapped to the kernel virtual memory. It then checks if the
address is allocated via `vmalloc`, which allocates virtually contiguous
addresses, making sure that the object does not cross the end of the allocated
vmap_area. Only after that, it checks if the address is inside virtual memory,
if not so, it simply returns and moves on to the other check; otherwise, it
converts the pointed address from virtual memory to a folio. It checks if the
folio is a slab or a large folio, and checks correspondingly. If the folio is
neither, no additional checks are performed. I cannot tell for sure if there are
other cases of folio a check would be worthwhile, but slabs and large folio
happen to be the ones that are checked for. Some contextual information from
[here](https://lwn.net/Articles/695991/) might be useful to understand the
motive:

> Beyond that, if the kernel-space address points to an object that has been
> allocated from the slab allocator, the patches ensure that what is being
> copied fits within the size of the object allocated. This check is performed
> by calling PageSlab() on the kernel address to see if it lies within a page
> that is handled by the slab allocator; it then calls an allocator-specific
> routine to determine whether the amount of data to be copied is fully within
> an allocated object. If the address range is not handled by the slab
> allocator, the patches will test that it is either within a single or compound
> page and that it does not span independently allocated pages.

#### `check_kernel_text_object`
`check_kernel_text_object` is the final check that is performed. It first
determines if the object overlaps with the kernel text. Given the start
(`_stext`) and end (`_etext`) location of the kernel text, the check is
straightforward. Additionally, there is a caveat explained in the comments:
```c
/*
* Some architectures have virtual memory mappings with a secondary
* mapping of the kernel text, i.e. there is more than one virtual
* kernel address that points to the kernel image. It is usually
* when there is a separate linear physical memory mapping, in that
* __pa() is not just the reverse of __va(). This can be detected
* and checked:
*/
```
When this is the case, the same check is performed, but on the secondary
mapping.


Now that we have basic knowledge about how object size checks are performed,
let's investigate the kernel's source code and dig into details. before
continueing, it would be a good idea to read
[this](https://developer.ibm.com/articles/l-kernel-memory-access/) article about
memory management in kernel to have a gerenal idea about this concept.


#### `copy_from_user`
`copy_from_user` is a wrapper around `_copy_from_user` which performs validation on object being copied

```c
static __always_inline unsigned long __must_check
copy_from_user(void *to, const void __user *from, unsigned long n)
{
	if (check_copy_size(to, n, false))
		n = _copy_from_user(to, from, n);
	return n;
}
```
The function first checks whether the size of the copy operation is valid using
the `check_copy_size` function. If the size is valid, the function proceeds;
otherwise, it might indicate an error. If the size is valid, the function
performs the actual copy operation using the `_copy_from_user` function, which
copies n bytes of data from the from pointer (user-space memory) to the to
pointer (kernel-space memory).


`check_copy_size` is responsible for checking the validity of a memory copy
operation by assessing the size of the copy. The function first attempts to
determine the size of the object pointed to by addr using the
`__builtin_object_size` intrinsic. This helps in checking whether the size of
the memory being copied is within bounds.
```c
static __always_inline __must_check bool
check_copy_size(const void *addr, size_t bytes, bool is_source)
{
	int sz = __builtin_object_size(addr, 0);
	if (unlikely(sz >= 0 && sz < bytes)) {
		if (!__builtin_constant_p(bytes))
			copy_overflow(sz, bytes);
		else if (is_source)
			__bad_copy_from();
		else
			__bad_copy_to();
		return false;
	}
	if (WARN_ON_ONCE(bytes > INT_MAX))
		return false;
	check_object_size(addr, bytes, is_source);
	return true;
}
```

The function then calls [`check_object_size`](#check_object_size) to perform
additional size checks based on the addr and bytes.


### Error handling

There is a helper function named `usercopy_abort`, whose responsibility is
printing an emergency-level message noting the out-of-bounds access, and call
[`BUG()`](https://kernelnewbies.org/FAQ/BUG) to indicate that something is
seriously wrong and kill the process.




**Performance overhead**
