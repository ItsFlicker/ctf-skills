# Januscape - CVE-2026-53359 (KVM nested virtualisation)

Guest-to-host bug in KVM on Intel/AMD x86-64: a guest that can load modules or supply a kernel can manipulate page tables enough to crash - and reportedly exploit - the hypervisor or sibling guests. Not a host-local unprivileged bug: the attack surface is root inside a guest (or any tenant allowed nested virtualisation).

## Practical notes

- Affected: nested virtualisation enabled (`/sys/module/kvm_intel/parameters/nested` or `kvm_amd` == 1). If a CSP does not expose nested virt, its tenants are not exposed.
- Mitigation: `options kvm_intel nested=0` / `options kvm_amd nested=0` (and `rmmod kvm_intel kvm_amd` first), or patch.
- CVSS 4 base 8.4 (other published scores ranged 7.8-9.3). Disclosed 2026-07-06; PoC that crashes the hypervisor, full exploit claimed.

## Why it is in this file

It is the one 2026 entry that is *not* a local unprivileged -> root bug, but it matters for two CTF-shaped scenarios: a kernel challenge whose host runs nested KVM, and a "pwn the hypervisor from the guest" challenge. The primitive is page-table manipulation from the guest, so the relevant background in this skill is the PTE-overlap material in [../kernel-techniques.md](../kernel-techniques.md), not the page-cache family.

Write-up and PoC: <https://github.com/V4bel/Januscape/blob/main/assets/write-up.md>; advisory: <https://ubuntu.com/blog/januscape-linux-vulnerability-mitigations-available>.
