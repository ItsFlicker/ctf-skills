# CTF Pwn - Kernel Objects

Every kernel exploit is built from the same handful of objects: one gets corrupted, one fills the freed slot, one leaks an address, one has a function pointer overwritten. This file is the catalogue - layout, cache, allocation path, and what each object gives you. Pair it with [kernel.md](kernel.md) for the exploitation flow.

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
| map kernel pages into userspace (USMA) | `pg_vec` (`struct pgv[]`) | 8 x block_nr, any cache | KERNEL | `setsockopt(PACKET_RX_RING)` -> `close(fd)` |
| text leak + **`cred` pointer leak** | `fs_context` | ~0x94 -> kmalloc-192 | KERNEL <= 5.14, ACCOUNT later | `fsopen()` -> `close(fd)` |
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

### pg_vec - `struct pgv[]` (any cache, `GFP_KERNEL`) - the USMA primitive

`setsockopt(fd, SOL_PACKET, PACKET_RX_RING, &req, ...)` on an `AF_PACKET`/`SOCK_RAW` socket -> `packet_set_ring()` -> `alloc_pg_vec()`:

```c
struct pgv { char *buffer; };            /* 8 bytes */

pg_vec = kcalloc(block_nr, sizeof(struct pgv), GFP_KERNEL | __GFP_NOWARN);
for (i = 0; i < block_nr; i++)
    pg_vec[i].buffer = alloc_one_pg_vec_page(order);   /* direct-map address */
```

- The array is `8 * tp_block_nr` bytes and `tp_block_nr` is user-controlled, so this object can be placed in **any** kmalloc cache (`0x130/8` entries -> kmalloc-512).
- Every `buffer` is a kernel virtual address of a page that `packet_mmap()` -> `vm_insert_page()` will map into userspace with `MAP_SHARED`. Corrupt the array and the next `mmap()` exposes those pages read-write - that is USMA, see [kernel-usma.md](kernel-usma.md).
- `validate_page_before_insert()` rejects `PageAnon | PageSlab | page_has_type`, so kernel text/rodata pages are valid targets while heap objects are not.
- Noise: `packet_set_ring()` allocates a **0x20** object immediately before the array; absorb it with another 0x20 `GFP_KERNEL` object (`shm_file_data` works) when the victim is kmalloc-32.
- Needs `CAP_NET_RAW`: `unshare(CLONE_NEWUSER | CLONE_NEWNET)` + `uid_map`/`gid_map`. `close(fd)` frees the array and its pages.

### fs_context (kmalloc-192, `GFP_KERNEL` until 5.14, `_ACCOUNT` after)

`fsopen("ext4", 0)` -> `fs_context_for_mount()` -> `alloc_fs_context()` -> `kzalloc(sizeof(struct fs_context), GFP_KERNEL)`; 0x94 bytes on 5.x, so kmalloc-192. The structure appeared in 5.1; commit `bb902cb47c` (Sep 2021) changed the allocation to `GFP_KERNEL_ACCOUNT`, so newer kernels put it in `kmalloc-cg-192`.

```c
struct fs_context {
    const struct fs_context_operations *ops;   // +0x00: -> ext4_context_ops in .rodata
    struct mutex uapi_mutex;                   // +0x08
    struct file_system_type *fs_type;          // +0x28
    void *fs_private;
    void *sget_key;
    struct dentry *root;
    struct user_namespace *user_ns;
    struct net *net_ns;
    const struct cred *cred;                   // mounter's credentials - a direct cred leak
    struct fc_log *log;
    const char *source;
    void *security;
    void *s_fs_info;
    unsigned int sb_flags, sb_flags_mask, s_iflags, lsm_flags;
    enum fs_context_purpose purpose:8;         /* phase:8, need_free:1, global:1 */
};
```

- **Leak:** `ops` is a `.rodata` pointer (text base) and `cred` is the mounting process's `struct cred *` - a single OOB read over this object gives both.
- **Control flow:** `fsconfig(fd, FSCONFIG_SET_STRING, key, value, 0)` -> `vfs_fsconfig_locked()` -> `vfs_parse_fs_param()` -> `fc->ops->parse_param(fc, param)`. Overwriting `ops` is an indirect call - under kCFI the prototype `int (*)(struct fs_context *, struct fs_parameter *)` must match.
- **USMA use:** the leaked `ops` points at `.rodata`, so a later `pg_vec` mapping can patch the real `parse_param` body instead of faking the table (see [kernel-usma.md](kernel-usma.md)).
- Flag churn matters: on 6.x the object is `_ACCOUNT`, so it sits next to `msg_msg` rather than next to `pg_vec`.

### Objects you cannot kmalloc-spray

- `cred` - from the dedicated `cred_jar`; reach it with an arbitrary write and patch `uid`/`gid`/`euid`/`egid` in place (or swap the whole pointer) rather than trying to reclaim a slot.
- `struct file` - `filp` cache; `f_op` hijack needs an arbitrary write, not a spray.
- `struct key` - `key_jar` (the *payload* is kmalloc'd, the key is not).
- `seq_file` - `seq_file_cache`; only the `seq_operations` next to it is sprayable.

### Putting them together

- **Leak -> write -> trigger**: `seq_operations` (32, cg) for text, `tty_struct` (1k, cg) for text+heap, `shm_file_data` (32, KERNEL) or `tty_file_private` for heap; then overwrite `modprobe_path` (arbitrary write) or a vtable (`tty->ops`, `pipe_buffer->ops`, `seq_operations->start`) and call into it.
- **Cross-cache**: when the vulnerable object is in a dedicated cache, free a whole slab page (drain the cache, or use `msg_msg`/`pipe_buffer` to reclaim a page returned to the buddy allocator - see the DiceCTF 2026 CPU-split technique in [kernel-techniques.md](kernel-techniques.md)).
- **GFP mismatch is the most common self-inflicted failure**: a `GFP_KERNEL` target and a `msg_msg` spray on 6.x will never share a slot. Check the allocation flag in the module source (or `pahole`/`crash` on the running kernel) before choosing the spray.
