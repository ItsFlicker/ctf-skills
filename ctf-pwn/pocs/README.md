# Offline PoC / exploit notes

Some contest environments only allow the AI API and the challenge platform: no GitHub, no package mirrors, no vendor advisories. These files keep the exploit mechanics *inside* the skill, so an agent can still work from them when every link in [../kernel-cves.md](../kernel-cves.md) is unreachable.

Rules:

- Research reproductions, not turnkey weapons. Run only on challenges or VMs you own.
- **Page-cache bugs persist after the exploit exits.** `su`, `libc`, `/etc/passwd` stay poisoned until eviction. Clean up with `echo 1 > /proc/sys/vm/drop_caches` (root) or a reboot, or the next `su` re-spawns your shell.
- Match the kernel before running: `uname -r`, module list and `CONFIG_*` in [../kernel-cves.md](../kernel-cves.md). Most of these are dead on a patched kernel and the PoC fails in confusing ways.
- These are recorded as text, not vendored repos: the full C/Python exploits are large and licence-bound, so each file keeps the trigger, the primitive and the required setup, and names the upstream repo for when the network is available.

| File | CVE | What it gives you |
|---|---|---|
| [copy-fail.md](copy-fail.md) | CVE-2026-31431 | the AF_ALG primitive, call sequence and a readable implementation |
| [fragnesia.md](fragnesia.md) | CVE-2026-46300 | XFRM ESP-in-TCP page-cache write: model, setup, one-byte-per-trigger loop |
| [pin-theft.md](pin-theft.md) | CVE-2026-43494 | io_uring fixed buffer + RDS zerocopy FOLL_PIN theft chain |
| [dirtyclone.md](dirtyclone.md) | CVE-2026-43503 | `__pskb_copy_fclone` flag loss + TEE + ESP-in-UDP in-place decrypt |
| [pedit-cow.md](pedit-cow.md) | CVE-2026-46331 | `act_pedit` COW range miscalculation |
| [lpe-quartet.md](lpe-quartet.md) | CVE-2026-80844 / -81000 / -68121 / -74469 | four network-stack LPEs: trigger, weaponization, PoC repos |
| [januscape.md](januscape.md) | CVE-2026-53359 | KVM nested-virtualisation guest-to-host primitive |

Common shape of the page-cache family (Copy Fail, Fragnesia, PinTheft, DirtyClone, pedit COW): get the kernel to write attacker-controlled bytes into the page cache of a **readable, file-backed** page, then execute that file. The page is not dirtied, so nothing on disk changes; the corruption is invisible to hash/integrity scanners and survives until eviction. No KASLR leak, no ROP, no CFI-valid target needed.
