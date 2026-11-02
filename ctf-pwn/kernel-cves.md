# CTF Pwn - 2026 Kernel LPE CVE Notes (April-October)

2026 produced an unusual density of Linux local-privilege-escalation CVEs, and one class dominates: bugs whose primitive is **a write into the page cache**, not a corrupted kernel object. That changes the exploitation playbook completely - no heap grooming, no KASLR leak, no ROP, and nothing for CFI, CET or SMEP to stop. This file records the ones worth knowing, with the dates and versions that matter, so a target can be matched against them quickly.

Scope: April-October 2026, Linux kernel, local privilege escalation (guest-to-host included where it is the same primitive). Not exhaustive; the page-cache family and the network-stack batch are the ones that keep coming up.

## The 2026 pattern: page-cache write instead of memory corruption

The primitive in these bugs is: *unprivileged process causes the kernel to modify bytes of a file it can read, in the page cache*. Two properties make it devastating:

- The corrupted page is **not marked dirty**, so it is never written back. The on-disk inode, its hashes, image digests and snapshot/disk scanners all see the original file.
- Every process that later reads the same file through the same `address_space` sees the poisoned bytes - including setuid binaries (`su`, `sudo`), shared libraries (`libc`), and, on an overlayfs node, the shared read-only lower layers of every container whose image hash matches.

Consequences for exploitation:

- You do not need kernel code execution, a KASLR leak, a stack pivot, or a CFI-valid call target. You need a *file* to patch and a path that will execute it. `su` is the classic: rewrite the password check, run it, get root.
- Protection state (SMEP/SMAP/KPTI/CET/kCFI/lockdown/module signing) is irrelevant to the primitive itself.
- Container escapes come for free when the poisoned file is shared: overlayfs lower layers (`f_mapping` is shared host-wide) or the host `runc` binary bind-mounted into the container by the runtime (the Dirty Pipe container-escape chain, replayed with a new write primitive).
- Detection must look at **resident page contents** (runtime memory hashing) or at the syscall that creates the primitive (seccomp: block `socket(AF_ALG, ...)`, or the affected netlink/module path). Disk integrity checks and registry scans are blind.

## The list

| CVE | Name | Public | Subsystem | Primitive |
|---|---|---|---|---|
| CVE-2026-31431 | Copy Fail | 2026-04-29 | `algif_aead` (AF_ALG) | controlled 4-byte page-cache write |
| CVE-2026-43284 | Dirty Frag | 2026-05 | network frag handling (skb) | page-cache write |
| CVE-2026-46300 | Fragnesia | 2026-05-13 | `skb_try_coalesce` + XFRM ESP-in-TCP | in-place AES-GCM decrypt into page cache |
| CVE-2026-43494 | PinTheft | 2026-05-19 | RDS (refcount) | page-cache poisoning |
| CVE-2026-43503 | DirtyClone | CVE 2026-05-23, public 2026-06-25 | same components as Dirty Frag/Fragnesia | page-cache write |
| CVE-2026-46331 | pedit COW | CVE 2026-06-16 | `act_pedit` (tc) | COW/page-cache write |
| CVE-2026-53359 | Januscape | 2026-07-06 | KVM nested virtualization | guest-to-host memory corruption |
| CVE-2026-80844 | DirtyAH6 | 2026-09-19 | IPv6 AH6/XFRM | OOB via malformed routing header |
| CVE-2026-81000 | TUNderflow | 2026-09-19 | TUN/TAP | size wrap -> heap overflow |
| CVE-2026-68121 | PPPoEject | 2026-09-19 | PPPoE TX | UAF via lower-device realloc |
| CVE-2026-74469 | DiagSpill | 2026-09-19 | SCTP `sctp_diag` | OOB write, no userns needed |

### Copy Fail - CVE-2026-31431 (2026-04-29)

Logic flaw in `algif_aead` (`AF_ALG` AEAD interface, present since 4.17): the kernel is tricked into decrypting into a buffer that is really a reference to page-cache-backed file data, giving an unprivileged user a **repeatable, controlled 4-byte write into any readable file's page cache**, without races. Patch reverts AF_ALG AEAD to an out-of-place operation (`a664bf3d603d`); the 732-byte reference PoC rewrites a setuid binary such as `su`.

Container angle (Xint): overlayfs lower layers are deduplicated by content hash, so two pods whose images share a base layer share the host `address_space`; poisoning a lower-layer file from one pod affects every co-located pod that reads it, and the on-disk layer is untouched. The container escape replays the Dirty Pipe `runc` chain: make `runc` visible inside the namespace, poison the pages of `/proc/<pid>/exe` through the shared cache, wait for the next `runc` invocation on the host.

### Dirty Frag - CVE-2026-43284 (2026-05)

Same outcome, different entry: fragmentation handling in the network stack lets a packet path operate on page-cache-backed data. It is the first of the "frag" family and the module blacklist used for it (`esp4`, `esp6`, `rxrpc`) also covers Fragnesia and DirtyClone.

### Fragnesia - CVE-2026-46300 (2026-05-13)

`skb_try_coalesce()` drops the `SKBFL_SHARED_FRAG` marker while coalescing, so the XFRM ESP-in-TCP path performs in-place AES-GCM decryption straight into page-cache-backed read-only files. Deterministic, no race; the PoC overwrites `/usr/bin/su` and gets a root shell in one command. Interim mitigation: blacklist `esp4`, `esp6`, `rxrpc` (breaks kernel-mode IPsec). Fixed in kernels released on/after 2026-05-13.

### PinTheft - CVE-2026-43494 (2026-05-19)

A page refcount bug in RDS (Reliable Datagram Sockets) that lets the attacker poison the page cache the same way Copy Fail / Dirty COW do - rewrite an in-memory setuid binary and get root. CVSS 3.1 7.8. Not affected by default on Ubuntu, which blacklists `rds` (the module only auto-loads on HPC setups); fix `e174929793195`.

### DirtyClone - CVE-2026-43503 (disclosed 2026-06-25)

JFrog's write-up of a page-cache-write variant that lives in the same components as Dirty Frag and Fragnesia, so the same module blacklist protects against all three. CVSS 3.1 8.8; local root on hosts, potential container escape. CVE record 2026-05-23, first Ubuntu fixes 2026-06-02.

### pedit COW - CVE-2026-46331 (CVE 2026-06-16)

Copy-on-write flaw in `act_pedit`, the tc action for arbitrary packet edits. Local root with a published exploit; potential container escape. Mitigation: block `act_pedit`. CVSS 3.1 7.8. Affects Ubuntu 18.04 and later.

### Januscape - CVE-2026-53359 (2026-07-06)

Different class: nested virtualization in KVM on Intel/AMD x86-64. A guest that can load modules or supply a kernel can manipulate page tables enough to crash - and reportedly exploit - the hypervisor or other guests. Not a host-local unprivileged bug: the attack surface is root inside a guest (or any tenant that gets nested virtualization). Mitigation: `options kvm_intel nested=0` / `kvm_amd nested=0`; CVSS 4 8.4. Write-up by Hyunwoo Kim (`V4bel`).

### The September network-stack quartet (2026-09-19)

Four independent local-root bugs, all in the network stack, disclosed together by Asim Manizada:

- **DirtyAH6 - CVE-2026-80844**: IPv6 AH6 accepts a malformed routing header describing more remaining segments than exist, derives an invalid range and accesses out of bounds. Needs AH6/XFRM plus either unprivileged user+network namespaces or `CAP_NET_ADMIN`/`CAP_NET_RAW`.
- **TUNderflow - CVE-2026-81000**: TUN/TAP mishandles an oversized receive-headroom value; a size calculation wraps, packet data lands past its allocation, later processing corrupts the heap. Needs TUN plus the headroom path and userns or `CAP_NET_ADMIN`.
- **PPPoEject - CVE-2026-68121**: the PPPoE transmit path keeps a pointer into a packet buffer across a lower-device callback that can replace the backing allocation; metadata updates then hit freed memory (UAF).
- **DiagSpill - CVE-2026-74469**: SCTP stores the peer-transport count in a field that wraps to zero for a large association; `sctp_diag` sizes a netlink response from that field but emits data for every peer, giving a large OOB write. **No user namespace or capability needed**; remote DoS is possible when `addip_noauth` is enabled (not default).

Mitigation is per-module (`ah6`, `tun`, `pppoe`, `sctp`/`sctp_diag`) or `user.max_user_namespaces=0`, which does *not* cover DiagSpill.

### Others worth tracking

- **Infinity Core** (CloudLinux, October 2026): a cluster of six kernel root bugs, CVE-2026-98260 and CVE-2026-98256 among them - details were still being published when this was written.
- **CVE-2026-63858**: nf_tables `nft_trans_chain_hooks` privilege escalation, reported against kernels up to 7.0.9 (VulDB); verify the affected range against the vendor before relying on it.

## Checking a target (and a CTF kernel)

```bash
uname -r                                   # match against the fixed versions per vendor
lsmod | grep -E 'algif_aead|esp4|esp6|rxrpc|rds|act_pedit|ah6|tun|pppoe|sctp'
grep -E 'CONFIG_(CRYPTO_USER_API_AEAD|XFRM|RDS|NET_SCH_INGRESS|SCTP|TUN|PPPOE)=' /boot/config-$(uname -r)
```

- `algif_aead` present (module or built-in) means Copy Fail applies; userspace only needs `socket(AF_ALG, SOCK_SEQPACKET, 0)` to be allowed.
- `esp4`/`esp6`/`rxrpc` cover the frag family; `act_pedit` covers pedit COW; `rds` covers PinTheft.
- For Kubernetes/container targets, the interesting question is **which files are shared**: overlayfs lower layers by layer hash, and the runtime binary bind-mounted inside the container (`runc`).
- A CTF kernel challenge that mirrors these bugs usually removes the leak on purpose: if the module gives you a "write 4 bytes anywhere in a file" style interface, check whether the intended path is `su`/`libc`/`runc`, not a heap object. The heap/ROP catalogue in [kernel-objects.md](kernel-objects.md) and [kernel-techniques.md](kernel-techniques.md) is the wrong toolbox for this class.

## References

- Copy Fail: <https://copy.fail/>, CERT/CC VU#260001 <https://kb.cert.org/vuls/id/260001>, Xint "From Pod to Host" <https://xint.io/blog/copy-fail-pod-to-host>
- Dirty Frag: Qualys <https://blog.qualys.com/product-tech/vulnmgmt-detection-response/2026/05/09/dirty-frag-using-the-page-caches-as-an-attack-surface>, Canonical <https://canonical.com/blog/dirty-frag-linux-vulnerability-fixes-available>
- Fragnesia: CERT.UG advisory <https://www.cert.ug/fragnesia-linux-kernel-local-privilege-escalation-xfrm-esp-tcp-cve-2026-46300>
- PinTheft: Ubuntu <https://ubuntu.com/blog/pintheft-linux-kernel-vulnerability-mitigation>
- DirtyClone: JFrog <https://research.jfrog.com/post/dissecting-and-exploiting-linux-lpe-variant-dirtyclone-cve-2026-43503>, Ubuntu <https://ubuntu.com/blog/dirtyclone-linux-vulnerability-fixes-available>
- pedit COW: Ubuntu <https://ubuntu.com/blog/pedit-cow-linux-vulnerability-fixes-available>
- Januscape: Ubuntu <https://ubuntu.com/blog/januscape-linux-vulnerability-mitigations-available>, write-up <https://github.com/V4bel/Januscape/blob/main/assets/write-up.md>
- Quartet: Red Hat RHSB-2026-011 <https://access.redhat.com/security/vulnerabilities/RHSB-2026-011>, researcher write-up <https://heyitsas.im/posts/lpe-quartet/>, oss-sec <https://www.openwall.com/lists/oss-security/2026/09/18/3>
