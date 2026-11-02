# pedit COW - CVE-2026-46331 (`act_pedit`)

`act_pedit`, the traffic-control action for editing packet fields, can compute the copy-on-write writable range before all runtime packet offsets are known. When `pedit` later writes at an offset that lands in a shared (file-backed) page, the write goes into the page cache instead of a private copy. Unprivileged local root by poisoning a setuid binary (`/bin/su`); CVSS 3.1 7.8; CVE assigned 2026-06-16; affects Ubuntu 18.04+.

## Requirements

- `act_pedit` available (module or built-in) and the ability to set up the tc rules (network namespace + `CAP_NET_ADMIN` as usual).
- A readable setuid target.

## Shape of the exploit

1. Build the pedit action over a packet path where the target offset resolves into a file-backed page (page-cache page of the setuid binary).
2. Trigger the write - the shared page is modified without COW copying it first.
3. `execve` the target; on-disk bytes unchanged, so integrity checks stay clean.

Mitigation: block the module (`install act_pedit /bin/false`), or patch. PoC: <https://github.com/cherrycherrymay/PoC-CVE-2026-46331>; analysis: TuxCare "pedit COW"; distro advisory: <https://ubuntu.com/blog/pedit-cow-linux-vulnerability-fixes-available>.
