---
name: ctf-pwn
description: Provides binary exploitation techniques for CTF challenges. Use when you already have a vulnerable native target or service and need to turn memory corruption or low-level primitives into code execution or privilege escalation, such as buffer overflows, format strings, heap bugs, ROP, ret2libc, shellcode, kernel exploitation, seccomp bypass, sandbox escape, or Windows/Linux exploit chains. Do not use it when the main blocker is understanding what the binary does; use reverse engineering first. Do not use it for pure web bugs, disk or packet forensics, or standalone crypto/math challenges.
license: MIT
compatibility: Requires filesystem-based agent (Claude Code or similar) with bash, Python 3, and internet access for tool installation.
allowed-tools: Bash Read Write Edit Glob Grep Task WebFetch WebSearch
metadata:
  user-invocable: "false"
  author: Lukasz Jagiello
---

# CTF Binary Exploitation (Pwn)

Quick reference for binary exploitation (pwn) CTF challenges. Each technique has a one-liner here; see supporting files for full details.

## Prerequisites

**Python packages (all platforms):**
```bash
pip install "pwntools==4.15.0" "ROPgadget==7.7" "ropper==1.13.13"
# or via script: bash scripts/install_ctf_tools.sh python
```

**uv alternative:**
```bash
uv venv && uv pip install "pwntools==4.15.0" "ROPgadget==7.7" "ropper==1.13.13"
```

**Linux (apt):**
```bash
apt install gdb binutils strace ltrace qemu-system-x86
```

**Optional cross-arch (ARM/MIPS — Debian/Ubuntu):**
```bash
apt install qemu-user qemu-user-static gdb-multiarch binutils-multiarch libc6-armhf-cross libc6-arm64-cross libc6-mips-cross
```

**macOS (Homebrew):**
```bash
brew install gdb binutils qemu
```

**Ruby gems (all platforms):**
```bash
gem install one_gadget seccomp-tools
```

**Manual install:**
- pwndbg — Linux: [GitHub](https://github.com/pwndbg/pwndbg), macOS: `brew install pwndbg/tap/pwndbg-gdb`
- checksec — included with pwntools (`checksec --file=binary`)

**MCP servers (optional):** WinDbg MCP ([svnscha/mcp-windbg](https://github.com/svnscha/mcp-windbg)) for Windows crash dumps, live breakpoint-driven exploitation, and kernel/driver debugging; IDA Pro MCP / Ghidra MCP for decompiling the vulnerable function — see [tools-mcp.md](tools-mcp.md).

## Additional Resources

**Userland memory corruption**
- [overflow-basics.md](overflow-basics.md) - stack/global overflow, ret2win, canary leaks (incl. fork brute force), scanf quirks, parser memcpy overflow, struct-pointer overwrite
- [rop-and-shellcode.md](rop-and-shellcode.md) - ret2libc, ret2csu, syscall ROP, rdx control, bad-char XOR, exotic gadgets, stack pivots
- [rop-advanced.md](rop-advanced.md) - SROP, seccomp bypass, RETF to x32, `.fini_array`, ret2vdso, magic-gadget GOT patching, one-shot string synthesis
- [format-string.md](format-string.md) - leaks, GOT/`.fini_array` writes, blind pwn, `__free_hook`, ROT13-transformed input
- [advanced.md](advanced.md) - ret2dlresolve, JIT/UAF patterns, heap overlap, pthread-cancellation takeover

**Heap and FILE structures**
- [heap-techniques.md](heap-techniques.md) - House of Apple 2 / Einherjar / Orange / Spirit / Lore / Force, unlink, tcache stash, largebin, allocator ordering rules
- [heap-techniques-2.md](heap-techniques-2.md) - writeup variants: UAF vtable/pointer encoding, residue leaks, cross-bin, custom allocators
- [heap-fsop.md](heap-fsop.md) - `_IO_FILE` exploitation, vtable bypass, House of Some (+ SomeofHouse)
- [glibc-versions.md](glibc-versions.md) - 2.41-2.43 allocator changes, dead/alive matrix, fingerprinting

**Challenge case files** (per-challenge notes, not first-line reference)
- [advanced-exploits.md](advanced-exploits.md), [advanced-exploits-2.md](advanced-exploits-2.md), [advanced-exploits-3.md](advanced-exploits-3.md), [advanced-exploits-4.md](advanced-exploits-4.md), [advanced-exploits-5.md](advanced-exploits-5.md) - parts 1-5: VM/JIT/type confusion, FSOP/TLS/shadow-stack, environment/format/canary cases, Windows/ARM/Forth/Game-of-Life, data-interpretation cases

**Kernel**
- [kernel.md](kernel.md) - QEMU setup, stack overflow/canary, ret2usr/kROP, modprobe_path, core_pattern, kmalloc mismatch, io_uring CVE-2024-0582
- [kernel-objects.md](kernel-objects.md) - spray/leak/hijack catalogue, `kmalloc-cg` isolation, pahole sizing
- [kernel-techniques.md](kernel-techniques.md) - tty kROP, AAW via ioctl, userfaultfd, SLUB internals, DiceCTF 2026 cross-cache/PTE, ret2hbp
- [kernel-bypass.md](kernel-bypass.md) - KASLR/FGKASLR, EntryBleed, KPTI, CET, CFI vs USMA, SMEP/SMAP, exploit templates
- [kernel-usma.md](kernel-usma.md) - USMA: map kernel text into userspace and patch a branch (CFI bypass)
- [kernel-cves.md](kernel-cves.md) - 2026 LPEs: Copy Fail family, pedit COW, Januscape, September quartet
- [pocs/README.md](pocs/README.md) - offline PoC/exp notes for those CVEs (no network needed)

**Routing and tooling**
- [attack-playbook.md](attack-playbook.md) - recon, leak selection by mitigation, primitive ranking
- [static-signals.md](static-signals.md) - evidence table for exploitability assessment
- [sandbox-escape.md](sandbox-escape.md) - VM/FUSE/busybox/shell/pipe bypasses
- [tools-mcp.md](tools-mcp.md) - WinDbg / IDA / Ghidra MCP workflows

**Archive** - the 43 pwnable.tw writeups moved to the sibling `ctf-pwn-writeups` skill; load it to compare against a known challenge, not as a technique reference.

---

## When to Pivot

- If you do not yet understand what the binary does, switch to `/ctf-reverse` before trying to exploit it.
- If the service is really a restricted shell, encoding puzzle, or sandbox language challenge, switch to `/ctf-misc`.
- If the exploit path depends on a web endpoint, session bug, or upload primitive more than memory corruption, switch to `/ctf-web`.
- If the vulnerability requires breaking a cryptographic primitive before exploitation, switch to `/ctf-crypto`.

## Quick Start Commands

```bash
# Binary analysis
checksec --file=binary
file binary
readelf -h binary

# Find gadgets
ROPgadget --binary binary | grep "pop rdi"
ropper -f binary --search "pop rdi"
one_gadget /lib/x86_64-linux-gnu/libc.so.6

# Debug
gdb -q binary -ex 'start' -ex 'checksec'

# Pattern for offset finding
python3 -c "from pwn import *; print(cyclic(200))"
python3 -c "from pwn import *; print(cyclic_find(0x61616168))"

# libc identification
./libc-database/find puts <leaked_addr_last_3_nibbles>
```

## Source Code Red Flags

- Threading/`pthread` -> race conditions
- `usleep()`/`sleep()` -> timing windows
- Global variables in multiple threads -> TOCTOU

## Race Condition Exploitation

```bash
bash -c '{ echo "cmd1"; echo "cmd2"; sleep 1; } | nc host port'
```

## Common Vulnerabilities

- Buffer overflow: `gets()`, `scanf("%s")`, `strcpy()`
- Format string: `printf(user_input)`
- Integer overflow, UAF, race conditions

## Protection Implications for Exploit Strategy

| Protection | Status | Implication |
|-----------|--------|-------------|
| PIE | Disabled | All addresses (GOT, PLT, functions) are fixed - direct overwrites work |
| RELRO | Partial | GOT is writable - GOT overwrite attacks possible |
| RELRO | Full | GOT is read-only - need alternative targets (hooks, vtables, return addr) |
| NX | Enabled | Can't execute shellcode on stack/heap - use ROP or ret2win |
| Canary | Present | Stack smash detected - need leak or avoid stack overflow (use heap) |

**Quick decision tree:**
- Partial RELRO + No PIE -> GOT overwrite (easiest, use fixed addresses)
- Full RELRO -> target `__free_hook`, `__malloc_hook` (glibc < 2.34), or return addresses
- Stack canary present -> prefer heap-based attacks or leak canary first

## Stack Buffer Overflow (quick loop)

1. Offset: `cyclic 200` then `cyclic -l <value>`; return address is at `rbp + 8`.
2. `checksec --file=binary` before writing any exploit code.
3. No PIE + no canary -> direct ROP or ret2win (add a `ret` for 16-byte alignment).
4. Canary present -> leak it (format string, partial overwrite, or byte-by-byte brute force on a forking server, 256 tries per byte).
5. Filtered bytes -> XOR-encode the payload or pick gadgets whose addresses survive the filter.

## Pattern Triggers

| What the target shows | Read |
|---|---|
| `gets`/`strcpy` with the saved RIP in reach | [overflow-basics.md](overflow-basics.md) |
| canary present, forking server or partial overwrite possible | [overflow-basics.md](overflow-basics.md) (canary sections) |
| parser copies a record length into a fixed stack buffer before validating | [overflow-basics.md](overflow-basics.md#parser-stack-overflow-via-unchecked-memcpy-length-metactf-flash-2026) |
| menu app with a struct holding a data pointer | [overflow-basics.md](overflow-basics.md) (struct pointer overwrite) |
| signed `scanf` value used as a size or price | [overflow-basics.md](overflow-basics.md) (signed bypass) |
| `scanf` loop fills an array that holds the canary | [overflow-basics.md](overflow-basics.md) (scanf quirks) |
| overflow reaches a flag between buffer and canary | [overflow-basics.md](overflow-basics.md) / [advanced.md](advanced.md) |
| adjacent globals, overflow via CSV/token count | [advanced.md](advanced.md) (CSV injection) |
| libc leak, but `rdx`/`rsi` need control | [rop-and-shellcode.md](rop-and-shellcode.md) (ret2csu, rdx control) |
| shellcode stage too small for the full payload | [rop-and-shellcode.md](rop-and-shellcode.md) (read stub) |
| `system`/`execve` crash under CET/IBT | [rop-and-shellcode.md](rop-and-shellcode.md) (raw syscall ROP) |
| filtered bytes (NUL, newline) | [rop-and-shellcode.md](rop-and-shellcode.md) (XOR encoding) / [format-string.md](format-string.md) |
| canary check epilogue reachable, no `pop rdx` | [rop-and-shellcode.md](rop-and-shellcode.md) (rdx zeroing) |
| no `pop rax` for `execve` | [rop-and-shellcode.md](rop-and-shellcode.md) (stub_execveat) |
| `printf(user_input)` | [format-string.md](format-string.md) |
| `printf` after ROT13 / input transform | [format-string.md](format-string.md) (ROT13) |
| seccomp on, need file read but no `execve` | [rop-advanced.md](rop-advanced.md) / [advanced.md](advanced.md) |
| no return address to hijack (CET + full RELRO) | [advanced.md](advanced.md) (pthread cancellation) |
| kernel target | [kernel.md](kernel.md), then objects/bypass/techniques |
| restricted shell, VM, emulator or jail | [sandbox-escape.md](sandbox-escape.md) (`ctf-misc` for pyjails) |
