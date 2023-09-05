# hardened usercopy

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


Before starting to investigate the source code for this patch, let's have an
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
a privileged area where the core operating system functions execute, having direct
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
needed. It is the entry point to the meat of `hardened usercopy` from the kernel.
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
results: <br>
`NOT_STACK`: not at all on the stack <br>
`GOOD_FRAME`: fully within a valid stack frame <br>
`GOOD_STACK`: within the current stack (when can't frame-check exactly) <br>
`BAD_STACK`: error condition (invalid stack position or bad stack frame) <br>

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

`BAD_STACK` is returned if the object partially overlaps. Optionally, if the
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

```c
static inline void check_heap_object(const void *ptr, unsigned long n,
				     bool to_user)
{
	unsigned long addr = (unsigned long)ptr;
	unsigned long offset;
	struct folio *folio;

	if (is_kmap_addr(ptr)) {
		offset = offset_in_page(ptr);
		if (n > PAGE_SIZE - offset)
			usercopy_abort("kmap", NULL, to_user, offset, n);
		return;
	}

	if (is_vmalloc_addr(ptr) && !pagefault_disabled()) {
		struct vmap_area *area = find_vmap_area(addr);

		if (!area)
			usercopy_abort("vmalloc", "no area", to_user, 0, n);

		if (n > area->va_end - addr) {
			offset = addr - area->va_start;
			usercopy_abort("vmalloc", NULL, to_user, offset, n);
		}
		return;
	}

	if (!virt_addr_valid(ptr))
		return;

	folio = virt_to_folio(ptr);

	if (folio_test_slab(folio)) {
		/* Check slab allocator for flags and size. */
		__check_heap_object(ptr, n, folio_slab(folio), to_user);
	} else if (folio_test_large(folio)) {
		offset = ptr - folio_address(folio);
		if (n > folio_size(folio) - offset)
			usercopy_abort("page alloc", NULL, to_user, offset, n);
	}
}
```

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


#### `check_copy_size`
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

#### `_copy_from_user` & `__copy_from_user`

The functions _copy_from_user and __copy_from_user are both used to copy data
from user space to kernel space. However, they have some differences in terms of
usage and behavior.

```c
static inline __must_check unsigned long
_copy_from_user(void *to, const void __user *from, unsigned long n)
{
	unsigned long res = n;
	might_fault();
	if (!should_fail_usercopy() && likely(access_ok(from, n))) {
		instrument_copy_from_user_before(to, from, n);
		res = raw_copy_from_user(to, from, n);
		instrument_copy_from_user_after(to, from, n, res);
	}
	if (unlikely(res))
		memset(to + (n - res), 0, res);
	return res;
}
```

`_copy_from_user` is a safer version of the copy_from_user function. It performs
certain safety checks to ensure that the copy operation does not cause security
vulnerabilities or memory corruption. It includes additional checks to validate
the user space memory and ensure that the requested memory range is accessible
and readable. If the memory is not accessible, it will return the number of
bytes that could not be copied. `_copy_from_user` is designed to be used in
situations where you want to avoid potential security vulnerabilities, as it
performs these extra checks.

```c
static __always_inline __must_check unsigned long
__copy_from_user(void *to, const void __user *from, unsigned long n)
{
	unsigned long res;

	might_fault();
	instrument_copy_from_user_before(to, from, n);
	if (should_fail_usercopy())
		return n;
	check_object_size(to, n, false);
	res = raw_copy_from_user(to, from, n);
	instrument_copy_from_user_after(to, from, n, res);
	return res;
}
```

`__copy_from_user` is a lower-level version of the copy_from_user function. It
performs a simple memory copy operation without the additional security checks
and validation that `_copy_from_user` provides. It's considered a more "raw" or
"direct" form of memory copy, and as a result, it might not provide the same
level of safety checks as `_copy_from_user`. `__copy_from_user` is generally
used in scenarios where the code has already ensured the validity of the user
space memory, and the extra checks provided by `_copy_from_user` are not needed.

The key difference is in how they handle the case when the copy operation
encounters an error. In the `__copy_from_user` version, there's no provision to
fill the destination buffer with zeros if an error occurs. In the
`_copy_from_user` version, zeros out the remaining bytes of the destination
buffer if the copy operation was not fully successful.

### Error handling

There is a helper function named `usercopy_abort`, whose responsibility is
printing an emergency-level message noting the out-of-bounds access, and call
[`BUG()`](https://kernelnewbies.org/FAQ/BUG) to indicate that something is
seriously wrong and kills the process.


### Data Structures

#### Page

As mentioned before, memory management in the Linux kernel is done using pages. A
page is a basic unit of physical memory with a typical size of 4096 bytes.
let's have a look at the `page` struct.


The following lines are pulled from the latest version of the kernel which is
[6.4.11](https://elixir.bootlin.com/linux/v6.4.11/source/include/linux/mm_types.h#L74)
by the time of writing this document. 

```c
struct page {
	unsigned long flags;		/* Atomic flags, some possibly
								* updated asynchronously */
```

The first thing you see is the `flags` variable. You can find available values
for `flags` and detailed documentation
[here](https://elixir.bootlin.com/linux/v6.4.11/source/include/linux/page-flags.h)



After flags, there is a quite large union inside the `page` struct. This union
allows the struct `page` to represent different types of pages. Depending on the
type of page, different fields within this union will be used. Each comment
block inside the union represents a different type of page and its associated
fields.

```c
	/*
	 * Five words (20/40 bytes) are available in this union.
	 * WARNING: bit 0 of the first word is used for PageTail(). That
	 * means the other users of this union MUST NOT use the bit to
	 * avoid collision and false-positive PageTail().
	 */
	union {
		struct {	/* Page cache and anonymous pages */
			/***/
		};
		struct {	/* page_pool used by netstack */
			/***/
		};
		struct {	/* Tail pages of compound page */
			/***/
		};
		struct {	/* Page table pages */
			/***/
		};
		struct {	/* ZONE_DEVICE pages */
			/***/
		};

		/** @rcu_head: You can use this to free a page by RCU. */
		struct rcu_head rcu_head;
	};
```

This block represents pages used in the page cache and anonymous pages. Page
cache pages typically hold data read from or to be written to disk, while
anonymous pages are used for anonymous memory mappings like stack or heap.

```c
		struct {	/* Page cache and anonymous pages */
			/**
			* @lru: Pageout list, e.g., active_list protected by
			* lruvec->lru_lock.  Sometimes used as a generic list
			* by the page owner.
			*/
			union {
				struct list_head lru;

				/* Or, for the Unevictable "LRU list" slot */
				struct {
					/* Always even, to negate PageTail */
					void *__filler;
					/* Count page's or folio's mlocks */
					unsigned int mlock_count;
				};

				/* Or, free page */
				struct list_head buddy_list;
				struct list_head pcp_list;
			};
			/* See page-flags.h for PAGE_MAPPING_FLAGS */
			struct address_space *mapping;
			union {
				pgoff_t index;      /* Our offset within mapping. */
				unsigned long share; /* share count for fsdax */
			};
			/**
			* @private: Mapping-private opaque data.
			* Usually used for buffer_heads if PagePrivate.
			* Used for swp_entry_t if PageSwapCache.
			* Indicates order in the buddy system if PageBuddy.
			*/
			unsigned long private;
		};
```

The following union is used to represent different lists that this page can be a part of.
Depending on the situation, one of these unions' members will be active.

```c
			/**
			 * @lru: Pageout list, eg. active_list protected by
			 * lruvec->lru_lock.  Sometimes used as a generic list
			 * by the page owner.
			 */
			union {
				struct list_head lru;

				/* Or, for the Unevictable "LRU list" slot */
				struct {
					/* Always even, to negate PageTail */
					void *__filler;
					/* Count page's or folio's mlocks */
					unsigned int mlock_count;
				};

				/* Or, free page */
				struct list_head buddy_list;
				struct list_head pcp_list;
			};
```

`struct list_head lru`: Represents the LRU (Least Recently Used) list, which is
often used for pages that can be paged out to secondary storage when memory is
low. The comment mentions that it's protected by lruvec->lru_lock.


`struct { /* Unevictable "LRU list" slot */ }`: This part is for pages that are
considered "unevictable" and are placed in an LRU list slot. The `__filler` is
used to negate `PageTail`, and `mlock_count` is a count of mlocks (memory locks)
on the page.

`struct list_head buddy_list` and `struct list_head pcp_list`: These are lists
used for free pages in the memory buddy system. The buddy system is a memory
allocation algorithm that manages memory in blocks of powers of 2. These lists
are used to keep track of free pages.


```c
			/* See page-flags.h for PAGE_MAPPING_FLAGS */
			struct address_space *mapping;
			union {
				pgoff_t index;		/* Our offset within mapping. */
				unsigned long share;	/* share count for fsdax */
			};
```

`struct address_space *mapping`: This field points to the address space
structure associated with the page. An address space represents a mapping
between virtual memory and some underlying storage, often used for file-backed
memory mappings.

`union` within the block: This union represents two different ways of
representing an index or share count for the page, depending on the context.

`pgoff_t index`: Represents the offset of the page within the mapping. This is
typically used to locate the page's position within a file.

`unsigned long share`: Represents the share count for fsdax (file system-direct
access) pages. This is relevant when memory-mapped files are accessed without
copying data to user space.



```c
			/**
			 * @private: Mapping-private opaque data.
			 * Usually used for buffer_heads if PagePrivate.
			 * Used for swp_entry_t if PageSwapCache.
			 * Indicates order in the buddy system if PageBuddy.
			 */
			unsigned long private;
```

`unsigned long private`: This field is a catch-all for mapping-private opaque
data. Its specific usage depends on various page flags like `PagePrivate`,
`PageSwapCache`, and `PageBuddy`. It might be used, for example, for storing
buffer_heads if `PagePrivate`, for swp_entry_t if `PageSwapCache`, or to
indicate the order in the buddy system if PageBuddy.





```c
		struct { /* page_pool used by netstack */
			/**
			* @pp_magic: magic value to avoid recycling non
			* page_pool allocated pages.
			*/
			unsigned long pp_magic;
			struct page_pool *pp;
			unsigned long _pp_mapping_pad;
			unsigned long dma_addr;
			union {
				/**
				* dma_addr_upper: might require a 64-bit
				* value on 32-bit architectures.
				*/
				unsigned long dma_addr_upper;
				/**
				* For frag page support, not supported in
				* 32-bit architectures with 64-bit DMA.
				*/
				atomic_long_t pp_frag_count;
			};
		};
```

This part of the union represents pages that are used as part of a page pool in
the context of networking (netstack). Here's an explanation of its components:


`unsigned long pp_magic`: This field stores a magic value used to avoid
recycling pages that were not allocated from the page pool. This magic value
helps ensure that only pages allocated for this specific purpose are managed
within the page pool.

`struct page_pool *pp`: This field is a pointer to a page pool structure. Page
pools are commonly used in networking to efficiently manage memory for
network-related operations. They provide a way to allocate and deallocate memory
chunks quickly.

`unsigned long _pp_mapping_pad`: This field seems to be reserved or used as
padding and might not be actively used in this context.

`unsigned long dma_addr`: This field likely stores a DMA (Direct Memory Access)
address associated with the page. DMA is a technique used in computers to allow
peripheral devices to access memory without involving the CPU. This field may be
used for efficient data transfer between devices.


union within the block: This union represents two different ways of storing
information depending on the context.

`unsigned long dma_addr_upper`: This field may store the upper bits of the DMA
address. On 32-bit architectures with 64-bit DMA addresses, this is necessary to
represent the full address.

`atomic_long_t pp_frag_count`: This field appears to be related to fragmentation
page support. Fragmentation can occur when memory is allocated and deallocated
in smaller chunks, leaving gaps in memory. This field may be used to track the
fragmentation count, possibly to manage and defragment memory efficiently.




```c
		struct { /* Tail pages of compound page */
			unsigned long compound_head; /* Bit zero is set */
		};
```

This field stores information about the compound head of a compound page.
Compound pages are a memory management concept used in the Linux kernel. They
consist of a "head" page and a series of "tail" pages.

The `compound_head` field stores information about the head page of a compound
page. Compound head pages are used to manage memory allocations where multiple
physically contiguous pages are treated as a single logical unit. Bit zero of
this field is set, which can be used to distinguish compound head pages from
tail pages.

In a compound page, the head page contains control information, and the tail
pages hold the actual data. The `compound_head` field is used to identify the head
page and manage the relationship between the head and tail pages within a
compound page.


```c
		struct { /* Page table pages */
			unsigned long _pt_pad_1;     /* compound_head */
			pgtable_t pmd_huge_pte;      /* protected by page->ptl */
			unsigned long _pt_pad_2;     /* mapping */
			union {
				struct mm_struct *pt_mm;  /* x86 pgds only */
				atomic_t pt_frag_refcount; /* powerpc */
			};
		#if ALLOC_SPLIT_PTLOCKS
			spinlock_t *ptl;
		#else
			spinlock_t ptl;
		#endif
		};
```

This part of the union is related to pages used for managing page tables, a
fundamental aspect of virtual memory management in an operating system. Here's
an explanation of its components:

`unsigned long _pt_pad_1`: This field appears to be reserved or used as padding
and might not be actively used in this context.

`pgtable_t pmd_huge_pte`: This field is related to page table management and
represents a pointer to the page middle directory (PMD) huge page table entry
(PTE). It is protected by the page->ptl spinlock, indicating that access to this
field must be synchronized to prevent concurrent modifications.

`unsigned long _pt_pad_2`: Similar to _pt_pad_1, this field seems to be reserved
or used as padding and might not be actively used in this context.

union within the block: This union represents two different ways of storing
information depending on the architecture and context.

`struct mm_struct *pt_mm` (x86 pgds only): This field is used on x86
architecture for page table management. It stores a pointer to the memory
management structure (struct mm_struct) associated with the page. The memory
management structure keeps track of the virtual memory mappings for a particular
process.

`atomic_t pt_frag_refcount` (powerpc): On powerpc architecture, this field
represents an atomic reference count used for page table fragmentation
management. It is used to keep track of references to fragmented page tables.

Conditional compilation (`#if` and `#else`): Depending on the value of the
`ALLOC_SPLIT_PTLOCKS` macro, this code block includes either a pointer to a
spinlock (`spinlock_t *ptl`) or an actual spinlock (`spinlock_t ptl`) for page
table locking. Spinlocks are synchronization primitives used to protect critical
sections of code from concurrent execution.



```c
		struct { /* ZONE_DEVICE pages */
			/** @pgmap: Points to the hosting device page map. */
			struct dev_pagemap *pgmap;
			void *zone_device_data;
			/*
			* ZONE_DEVICE private pages are counted as being
			* mapped so the next 3 words hold the mapping, index,
			* and private fields from the source anonymous or
			* page cache page while the page is migrated to device
			* private memory.
			* ZONE_DEVICE MEMORY_DEVICE_FS_DAX pages also
			* use the mapping, index, and private fields when
			* pmem backed DAX files are mapped.
			*/
		};
```

This part of the union is related to pages that belong to the ZONE_DEVICE memory
zone, a concept used in memory management, especially for device-specific
memory. Here's an explanation of its components:

`struct dev_pagemap *pgmap`: This field points to the hosting device page map,
represented by a struct dev_pagemap. A device page map is a data structure used
to manage memory pages that are specific to a particular device or memory zone.

`void *zone_device_data`: This field appears to be a pointer to device-specific
data associated with the page or the `ZONE_DEVICE` memory zone. It's a
general-purpose pointer and its exact usage may depend on the specific device or
memory management requirements.


```c
		/** @rcu_head: You can use this to free a page by RCU. */
		struct rcu_head rcu_head;
```

`struct rcu_head rcu_head`: This field is of type struct rcu_head. It is part of
the Linux kernel's RCU (Read-Copy-Update) mechanism, which is a synchronization
technique used to safely and efficiently manage data structures that can be read
by multiple threads while being occasionally modified.

In the context of memory management, the `rcu_head` structure is used to mark
pages that are scheduled for deallocation using RCU. Instead of immediately
freeing a page when it's no longer needed, the RCU mechanism allows the page to
be reclaimed more efficiently in a deferred manner.

When a page needs to be freed, it is marked with an `rcu_head`, and the actual
freeing of the page is deferred until it is safe to do so. RCU ensures that no
threads are actively using the page before it is freed, preventing data races
and memory corruption.

Developers can use this rcu_head field to enqueue a page for RCU-based freeing
when it is no longer needed, providing a safe and efficient way to manage memory
in a multithreaded environment.


```c
	union { /* This union is 4 bytes in size. */
		/*
		* If the page can be mapped to userspace, encodes the number
		* of times this page is referenced by a page table.
		*/
		atomic_t _mapcount;

		/*
		* If the page is neither PageSlab nor mappable to userspace,
		* the value stored here may help determine what this page
		* is used for.  See page-flags.h for a list of page types
		* which are currently stored here.
		*/
		unsigned int page_type;
	};
```

This part of the union represents two different ways of storing information
based on the context and requirements of the struct page. Here's the
explanation:

`atomic_t _mapcount`: This field is of type `atomic_t`, which represents an
atomic integer. It is used to store the reference count for the page when the
page can be mapped to userspace. The reference count indicates the number of
times this page is currently referenced by page tables.

When a page is mapped to userspace, multiple page tables or mappings may
reference it, and this mapcount helps track how many such references exist. It's
essential for proper memory management, especially in a multi-threaded or
multi-process environment.

`unsigned int page_type`: This field is used when the page is neither a slab
page nor mappable to userspace. Instead, it stores a value that may help
determine the purpose or type of this page.

The comment suggests that this field can be used to identify the type of the
page based on certain page flags. The page-flags.h header file in the Linux
kernel contains a list of page types, and this field could potentially store an
identifier corresponding to one of these types.

This field is useful for distinguishing various types of pages in the kernel's
memory management system, even when they are not actively mapped to userspace.
It allows for efficient management and identification of different page types
within the kernel.


```c
	/* Usage count. *DO NOT USE DIRECTLY*. See page_ref.h */
	atomic_t _refcount;
```

The `atomic_t` _refcount field is responsible for tracking the usage count of a
page, but it should not be manipulated directly. Instead, developers should rely
on functions and macros provided in `page_ref.h` to ensure safe and consistent
reference counting, preventing memory management issues in the kernel.




```c
#ifdef CONFIG_MEMCG
	unsigned long memcg_data;
#endif
```

This code block is conditional and depends on whether the kernel configuration
has enabled memory control group (memcg) support (`CONFIG_MEMCG`).

If memcg support is enabled, this unsigned long field named `memcg_data` is
present. Memcg is a kernel feature that allows for fine-grained memory resource
management, often used in containerization environments like Docker. This field
likely holds some data or information related to memory control groups.


```c
	/*
	 * On machines where all RAM is mapped into kernel address space,
	 * we can simply calculate the virtual address. On machines with
	 * highmem some memory is mapped into kernel virtual memory
	 * dynamically, so we need a place to store that address.
	 * Note that this field could be 16 bits on x86 ... ;)
	 *
	 * Architectures with slow multiplication can define
	 * WANT_PAGE_VIRTUAL in asm/page.h
	 */
#if defined(WANT_PAGE_VIRTUAL)
	void *virtual;			/* Kernel virtual address (NULL if
					   not kmapped, ie. highmem) */
#endif /* WANT_PAGE_VIRTUAL */
```

This comment block discusses the handling of virtual addresses for pages,
particularly in systems with high memory (highmem). In some systems, all RAM is
mapped into the kernel address space, so virtual addresses can be easily
calculated. However, in systems with highmem, some memory is mapped into the
kernel virtual memory dynamically.

To accommodate this situation, a field named `virtual` is provided, which holds
the kernel virtual address for the page. This field can be used to store the
virtual address of the page when it is mapped into the kernel's address space.

It also mentions that on certain architectures (like x86), this field could
potentially be 16 bits in size, which means it might have limited capacity for
storing virtual addresses.

The comment also mentions the `WANT_PAGE_VIRTUAL` macro, which can be defined in
`asm/page.h`. This macro is related to architectures with slow multiplication
and likely affects how the virtual address is calculated or stored.


```c
#ifdef CONFIG_KMSAN
	/*
	 * KMSAN metadata for this page:
	 *  - shadow page: every bit indicates whether the corresponding
	 *    bit of the original page is initialized (0) or not (1);
	 *  - origin page: every 4 bytes contain an id of the stack trace
	 *    where the uninitialized value was created.
	 */
	struct page *kmsan_shadow;
	struct page *kmsan_origin;
#endif
```

If Kernel Memory Sanitizer (KMSAN) support is enabled, this part of the struct includes two fields:

`struct page *kmsan_shadow`: This field points to a "shadow page" associated
with the original page. The shadow page is used by KMSAN to track the
initialization state of individual bits in the original page. Each bit in the
shadow page corresponds to a bit in the original page, indicating whether it has
been initialized (0) or not (1).

`struct page *kmsan_origin`: This field points to an "origin page." For
uninitialized memory, KMSAN keeps track of where the uninitialized value was
created. This field points to a page that contains stack trace IDs, allowing
developers to trace back to the source of uninitialized memory.


```c
#ifdef LAST_CPUPID_NOT_IN_PAGE_FLAGS
	int _last_cpupid;
#endif
} _struct_page_alignment;
```

Once again, this code block is conditional and depends on a specific kernel
configuration flag (`LAST_CPUPID_NOT_IN_PAGE_FLAGS`).

If this flag is defined, an integer field named `_last_cpupid` is included. It
appears to be related to tracking the last CPU PID (process ID) but might be
specific to certain configurations or use cases.


#### Folio

In the Linux kernel's memory management, the fundamental unit is a "page,"
typically 4,096 bytes in size. This unit is a hardware-level concept, and
different CPU architectures may offer various page sizes, but a base page size
(often 4,096 bytes) is chosen. Compound pages, on the other hand, are used for
various purposes, such as "huge pages" and DMA buffers. These are essentially
groups of contiguous single pages.

The kernel represents memory pages with structures in the system memory map.
When compound pages are created, a page structure is marked as the "head
page," representing the entire compound page, while the others are labeled "tail
pages" with pointers to the head page.

However, this approach has led to ambiguity in how functions interact with
different types of pages. Functions that accept page structures as arguments may
be unclear about whether they should work on a head or tail page, and whether
they should operate on PAGE_SIZE bytes or the entire compound page. This
ambiguity could potentially lead to bugs in the kernel.

> A function that has a struct page argument might be expecting a head or base
> page and will BUG if given a tail page. It might work with any kind of page
> and operate on PAGE_SIZE bytes. It might work with any kind of page and
> operate on page_size() bytes if given a head page but PAGE_SIZE bytes if given
> a base or tail page. It might operate on page_size() bytes if passed a head or
> tail page. We have examples of all of these today.

To address this issue, Matthew Wilcox introduced the concept of a "page folio."
A page folio is essentially a page structure that is guaranteed not to be a tail
page. Functions accepting a folio as an argument are expected to operate on the
entire compound page, eliminating ambiguity.

The benefits of page folios are twofold. First, they enhance clarity in the
kernel's memory management subsystem. Second, as functions are converted to
accept folios, it becomes clear that they work on full compound pages rather
than tail pages. This helps reduce potential bugs in the kernel's memory
management.

You can find a more in-depth discussion about the context [here](https://lwn.net/Articles/849538/).


```c
struct folio {
	/* private: don't document the anon union */
	union {
		struct {
	/* public: */
			unsigned long flags;
			union {
				struct list_head lru;
	/* private: avoid cluttering the output */
				struct {
					void *__filler;
	/* public: */
					unsigned int mlock_count;
	/* private: */
				};
	/* public: */
			};
			struct address_space *mapping;
			pgoff_t index;
			void *private;
			atomic_t _mapcount;
			atomic_t _refcount;
#ifdef CONFIG_MEMCG
			unsigned long memcg_data;
#endif
	/* private: the union with struct page is transitional */
		};
		struct page page;
	};
	union {
		struct {
			unsigned long _flags_1;
			unsigned long _head_1;
	/* public: */
			unsigned char _folio_dtor;
			unsigned char _folio_order;
			atomic_t _entire_mapcount;
			atomic_t _nr_pages_mapped;
			atomic_t _pincount;
#ifdef CONFIG_64BIT
			unsigned int _folio_nr_pages;
#endif
	/* private: the union with struct page is transitional */
		};
		struct page __page_1;
	};
	union {
		struct {
			unsigned long _flags_2;
			unsigned long _head_2;
	/* public: */
			void *_hugetlb_subpool;
			void *_hugetlb_cgroup;
			void *_hugetlb_cgroup_rsvd;
			void *_hugetlb_hwpoison;
	/* private: the union with struct page is transitional */
		};
		struct {
			unsigned long _flags_2a;
			unsigned long _head_2a;
	/* public: */
			struct list_head _deferred_list;
	/* private: the union with struct page is transitional */
		};
		struct page __page_2;
	};
};
```
