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
- *Checking for valid memory regions* <br>
The kernel checks whether the memory addresses provided during copy operations
are valid user or kernel addresses to prevent unauthorized access.
- *Boundary checks* <br>
The kernel verifies that the amount of data being copied doesn't exceed the size
of the destination buffer, preventing buffer overflows and potential code
execution exploits.
- *Prohibited access to certain memory regions* <br>
The kernel might restrict copying data to certain sensitive memory regions,
enhancing security and protecting against data corruption.

You can find a brief history of efforts and discussions that have been made
[here](https://lwn.net/Articles/695991/). Also, there is a full changelog and
history of the changes in the Linux source code available
[here](https://lore.kernel.org/lkml/20170628165520.GA129364@gmail.com/t/) and
[here](https://groups.google.com/g/linux.kernel/c/y9Dgu5HD1bg?pli=1).
