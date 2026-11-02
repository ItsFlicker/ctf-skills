# The September quartet: DirtyAH6, TUNderflow, PPPoEject, DiagSpill

Four network-stack local-root bugs by Asim Manizada, public 2026-09-18/19. The first three need unprivileged user namespaces (or an appropriately-CAP'd container); **DiagSpill needs neither**, only SCTP + `sctp_diag`.

## CVE-2026-80844 - DirtyAH6 (IPv6 AH6 / XFRM)

`ipv6_rearrange_rthdr()` reads the address count from `hdrlen` but moves an address pointer by `segments - segments_left` without checking `segments_left <= segments`. A raw IPv6 `HDRINCL` packet with `hdrlen=2` and `segments_left=255` moves the pointer back 4064 bytes and passes 4064 bytes to `memmove()` - OOB. Fix: reject `segments_left > segments` with `-EINVAL` (`7bad4bda74dc`). Reachable remotely (crash/DoS) on a router that adds AH in transport mode; remote root needs target-side grooming.

Weaponization in the PoC: corrupt `skb_shared_info` through the AH6 `memmove()`, then let a later ESP decrypt write into a file-backed fragment - replacing `pam_rootok.so` with `pam_permit.so`, so `su` stops asking for a password. PoC: <https://github.com/manizada/DirtyAH6>.

## CVE-2026-81000 - TUNderflow (TUN/TAP headroom)

`tun_set_headroom()` stores receive headroom in `tun->align`, which `tun_get_user()` also uses to size the head. A `netkit` device with 4096 bytes of headroom, under `VXLAN` and an Open vSwitch datapath, can pass 4160 bytes to a raw `TUN` port; `SKB_MAX_HEAD(4160)` underflows, `prepad + linear` and `len - linear` wrap, and `skb->data` ends up 64 bytes beyond a 4096-byte allocation. Fix: clamp headroom to `min(SKB_MAX_HEAD(0), U16_MAX-1)` minus the header budget and `pskb_may_pull()` before use (`447c9303942c`).

Weaponization: arrange file-backed pipe buffers next to the bad TUN packet; the OVS out-of-bounds write sets `PIPE_BUF_FLAG_CAN_MERGE` on one of them, then a pipe write replaces `pam_rootok.so` with `pam_permit.so` in `/etc/pam.d/su`. PoC: <https://github.com/manizada/TUNderflow>.

## CVE-2026-68121 - PPPoEject (PPPoE transmit)

`pppoe_sendmsg()` keeps a pointer into the skb head across `dev_hard_header()`; a device callback can call `pskb_expand_head()` and free that head, so the later PPPoE header/length writes hit freed memory (UAF). Fix: reload the header through `skb->network_header` after `dev_hard_header()` and keep that offset updated across `pskb_expand_head()` (`e9c238f6fe42`). Trigger: block the payload copy on FUSE while adding the first GRE/IP6GRE port to an empty team/bonding device.

Weaponization: race populated fd tables into the freed skb head, use the PPPoE writes to redirect one live fd to a fake `struct file`, then close it - controlled kernel callback, install root creds. PoC: <https://github.com/manizada/PPPoEject>.

## CVE-2026-74469 - DiagSpill (SCTP diagnostics)

An SCTP association can hold 65536 peer transports, but `transport_count` is 16 bits, so the 65536th wraps to 0. `sctp_diag` sizes the Netlink reply from that value but copies every peer: ~8 MiB out-of-bounds write. Fix: refuse a new unique peer when `transport_count == U16_MAX` (`bd0e9289e264`). Remote DoS when ASCONF/ADD-IP is on with SCTP-AUTH or `net.sctp.addip_noauth_enable=1` (off by default) and something like `ss` issues the diag request.

Weaponization: groom the diag overwrite into page tables, use the corrupted PTEs to map host memory, find and rewrite a `cred`, add a sudoers rule, root shell. PoC: <https://github.com/manizada/DiagSpill>.

## Versions and mitigation

First stable releases with all four fixes: `5.10.270`, `5.15.221`, `6.1.188`, `6.6.157`, `6.12.109`, `6.18.50`, `7.2.4`. Disabling `user.max_user_namespaces` covers the first three but **not** DiagSpill; disabling AH6/TUN/PPPoE/SCTP removes the underlying bugs. Full write-up with per-series affected/fixed tables: <https://heyitsas.im/posts/lpe-quartet/>, Red Hat bulletin <https://access.redhat.com/security/vulnerabilities/RHSB-2026-011>.

Note: these are memory-corruption bugs, not page-cache primitives - unlike the Copy Fail family they need grooming and a target-specific chain, which is why the PoCs are distro/kernel-tuned.
