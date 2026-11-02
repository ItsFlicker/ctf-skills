# DirtyClone - CVE-2026-43503 (TEE + ESP-in-UDP)

Page-cache write reached through `__pskb_copy_fclone()` losing a shared-fragment flag when the `TEE` netfilter target clones an skb for ESP-in-UDP. The ESP path then decrypts in place into file-backed pages that were supposed to be read-only. Same surface and same mitigation as Dirty Frag / Fragnesia (block `esp4`, `esp6`, `rxrpc`), so the module blacklist covers all three.

## Shape

- Unprivileged user namespaces required for the public chain (`user.max_user_namespaces > 0`).
- Public PoC overwrites `/etc/passwd` (adds a uid=0 entry) rather than a setuid binary - any readable file page works.
- CVSS 3.1 8.8; CVE record 2026-05-23, JFrog research 2026-06-25, first Ubuntu fixes 2026-06-02.
- Fix commit given by the Python port: `48f6a5356a33`.

## Version caveat

Vendor statements (Ubuntu) list all releases back to 14.04 as affected/fixed, while the independent Python port's README claims "7.1-rc1 to rc4". Trust the vendor version table for a target and treat the port's claim as specific to the path it implements; verify against the CVE record before relying on either.

## PoC

- <https://github.com/ASkyeye/DirtyClone> (pure-Python, overwrites `/etc/passwd`, spawns root shell)
- <https://github.com/mooder1/dirtyclone-CVE-2026-43503>
- JFrog writeup: <https://research.jfrog.com/post/dissecting-and-exploiting-linux-lpe-variant-dirtyclone-cve-2026-43503>

Cleanup matters here: a poisoned `/etc/passwd` in cache means every login path sees the extra root user until eviction (`drop_caches`) or reboot.
