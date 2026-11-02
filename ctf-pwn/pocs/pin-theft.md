# PinTheft - CVE-2026-43494 (RDS zerocopy + io_uring)

Reference-count bug in the RDS zerocopy send path (`rds_message_zcopy_from_user`): when a page pin fails, the page is `put_page()` twice, so the attacker can steal `FOLL_PIN` references from a page. Combined with an io_uring registered (fixed) buffer, the stale buffer metadata keeps writing to a page that has been freed back to the page allocator, and that page is then reclaimed as **page-cache data of a setuid binary**. Write the ELF stub through the stale fixed buffer, `execve` the setuid binary, root.

## Chain

1. Pin to CPU 0; find a readable SUID binary (`su`, `mount`, `passwd`, ...).
2. `mmap` an anonymous page and register it as an io_uring fixed buffer (`FOLL_PIN` bias ~1024).
3. Clone the buffer table to a second ring (needs `IORING_REGISTER_CLONE_BUFFERS`, kernel >= 6.13) so the stale metadata survives.
4. Fire ~1024 **failing** RDS zerocopy sends: each failure can drop an extra reference on the first pinned page, draining the bias.
5. `munmap` - the page is freed, but io_uring still holds the fixed-buffer slot.
6. Reopen/read the SUID target so page-cache reclaim gives that physical page to the binary; the stale fixed buffer now maps file cache.
7. Write a small x86_64 ELF stub into it, `execve` the SUID binary.

## Requirements

- `CONFIG_RDS=y`, `CONFIG_RDS_TCP=y` (or autoloadable by unprivileged users), `rds`/`rds_tcp` loaded.
- `CONFIG_IO_URING=y`, `kernel.io_uring_disabled=0`.
- Kernel >= 6.13 for the clone-buffers API; x86_64 for the embedded payload.
- Fix: `e174929793195e0cd6a4adb0cad731b39f9019b4`.

## Check exposure

```bash
grep CONFIG_RDS /boot/config-$(uname -r); lsmod | grep -E '^rds'
cat /proc/sys/kernel/io_uring_disabled    # expect 0 on vulnerable
```

Mitigation: patch, `rmmod rds rds_tcp` and block autoload, `kernel.io_uring_disabled=1`.

PoC: <https://github.com/letsr00t/CVE-2026-43494-PinTheft-PoC> (single-file C, "SLEY"); original research V12 / Aaron Esau; oss-security <https://www.openwall.com/lists/oss-security/2026/05/21/2>.
