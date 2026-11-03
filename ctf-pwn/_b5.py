import io

D = "/root/ctf-skills/ctf-pwn/"

def splice(fn, start, end, new):
    p = D + fn
    s = io.open(p, encoding="utf-8").read()
    i = s.index(start)
    j = s.index(end, i + len(start))
    io.open(p, "w", encoding="utf-8").write(s[:i] + new.rstrip("\n") + "\n\n" + s[j:])
    print("spliced %-24s %d -> %d chars" % (fn, j - i, len(new)))

ROP = '''## ROP Chain Building

```python
from pwn import *
elf, libc = ELF('./binary'), ELF('./libc.so.6')
rop = ROP(elf)
pop_rdi, ret = rop.find_gadget(['pop rdi', 'ret'])[0], rop.find_gadget(['ret'])[0]
payload = flat(b'A' * offset, pop_rdi, elf.got['puts'], elf.plt['puts'], RET2)
```

**The return target after the leak decides whether stage 2 survives.** Return to the `call vuln` instruction inside `main`: the CALL pushes a valid return address and rebuilds the frame exactly as on the first pass. `main`'s entry re-runs init/`check_status` and can reset state the exploit already consumed; entering `vuln` directly leaves `rsp` misaligned for the next libc call.

**Leak without a trailing newline.** `printf` with no `\n` puts the leaked bytes straight after the text, so `recvline` reads them glued to the prefix - take a fixed width instead:

```python
io.recvuntil(b'Laundry complete')
leak = u64(io.recv(6).ljust(8, b'\x00'))
```

### Raw Syscall ROP (When system() Fails)

When a libc call crashes under CET/IBT or bad alignment, end the chain through the `syscall` instruction: `pop rax` = 59, `pop rdi` = `"/bin/sh"`, `pop rsi` = 0, `pop rdx; pop rbx; ret` (plain `pop rdx; ret` is rare in modern libc), then `syscall; ret`. It skips every libc prologue and is the most reliable ending.

### rdx Control in ROP Chains

`puts` and friends clobber `rdx` to a small value, breaking a following `read(fd, buf, rdx)`. Three fixes: a `pop rdx; pop rbx; ret` gadget from libc; re-entering the binary's own `read` setup (`lea rax,[rbp-0x40]; mov edx,0x100; mov rsi,rax; ...`) after setting `rbp` with `pop rbp; ret` - the `leave;ret` after that read pivots `rsp` to `rbp`, so put the next chain at `rbp+8`; or use that `leave;ret` as a deliberate pivot.

### Shell Interaction After execve

The shell inherits stdin, so commands sent immediately can be eaten by a pending `read`. Sleep ~1s after the payload, then `sendline` one command at a time and `recv` with a timeout - do not batch-pipe.

## ret2csu — `__libc_csu_init` Gadgets

Two gadgets: the pop chain (`pop rbx; pop rbp; pop r12; pop r13; pop r14; pop r15; ret`) and the mover (`mov rdx, r15; mov rsi, r14; mov edi, r13d; call [r12 + rbx*8]; add rbx,1; cmp rbp,rbx; jne`). Set `rbx = 0`, `rbp = 1`, and `r12` to a *memory* slot holding the target address (a GOT entry, or a pointer array in `.bss`) - `r12` is dereferenced, never called directly.

Two traps decide the payload:

- **`edi` is 32-bit.** `mov edi, r13d` zero-extends, so a libc address as the first argument needs a real `pop rdi; ret`.
- **The call returns into the pop chain**, so the seven qwords after `call` are consumed as `rbx/rbp/r12-r15` plus a return - pad 56 bytes before the next gadget.
'''

OVF = '''## Stack Buffer Overflow

`cyclic 200` then `cyclic -l <value>` gives the offset; `checksec` then routes to one of the branches in this file.

- **ret2win with a magic argument**: `p64(ret)` for 16-byte alignment, then `pop rdi; ret` + magic + `win`; the offset is `rbp - buffer + 8`.
- **Hidden gadgets**: `cmp`/`mov`/`test` with large immediates encode usable bytes (`81 7d fc 5f 41 5e c3` is `pop rdi; pop r14; ret` at `+3`). `ROP(elf)` finds these; grep `objdump -d` only when the binary is tiny and pwntools comes up empty.
- **Substring filters** (`memmem`, "badge"/"token" checks) are beaten by splitting the constant across the payload, not by avoiding it.
'''

FMT = '''## Format String Basics

Primitives: `%p`/`%s` to read, `%n`/`%hn`/`%hhn`/`%lln` to write 4/2/1/8 bytes; `fmtstr_payload(offset, {addr: value})` automates the write.

**The three things that actually break:**

- **`%n` writes 4 bytes.** x86-64 GOT entries are 8, so `%n` leaves the upper half holding an old libc address and the next indirect call jumps into garbage. Use `%lln` (writes 8 bytes; the cost is output volume) or four `%hn`.
- **The address slot is `6 + pad/8`** when the format string starts at the usual stack slot: bare buffer 6, 16 bytes of padding 8, 32 bytes 10, 64 bytes 14. Confirm with `%<n>$p` before writing, never assume.
- **Output volume**: a value like `0x7f...` means that many characters. Split into 2-byte `%hn` writes and order them ascending so each field only prints the delta.

Read primitive: put the target address at slot `n` and use `%<n>$s`; it returns bytes up to the first NUL.
'''

PWN = '''## pwntools Template

`from pwn import *`, `context.binary = elf`, and an `args.REMOTE` switch are boilerplate worth rewriting each time. The part worth remembering is the automatic offset - it skips gdb entirely:

```python
p = process(exe, level='warn')
p.sendlineafter(b'>', cyclic(500))
p.wait()
offset = cyclic_find(p.corefile.read(p.corefile.sp, 8))   # x64: saved RIP sits at rsp
```

pwntools writes a corefile from the crash; on x86 read `corefile.pc` instead.
'''

DL = '''## ret2dlresolve

Forging `Elf64_Rela`/`Elf64_Sym`/dynstr so the linker resolves `system` - the 64-bit VERSYM-NULL step, the link_map `l_info` route, and the Full RELRO variant - is in [rop-advanced.md](rop-advanced.md#ret2dl_resolve-64-bit-codegate-2018). Use `Ret2dlresolvePayload` unless its gadget search fails; then build the chain by hand.
'''

KERN = '''## Kernel Exploitation

See [kernel.md](kernel.md) for setup/recon, object sprays and privilege-escalation primitives, and [kernel-bypass.md](kernel-bypass.md) for KASLR / SMEP / SMAP / KPTI.
'''

SEC = '''## Seccomp Bypass

Alternative syscalls (`openat` 257, `openat2` 437, `sendfile` 40, `readv`/`writev`) and the argument-restriction bypasses are in [advanced.md](advanced.md#seccomp-advanced-techniques).
'''

splice("rop-and-shellcode.md", "## ROP Chain Building", "## Bad Character Bypass via XOR Encoding in ROP (Crypto-Cat)", ROP)
splice("overflow-basics.md", "## Stack Buffer Overflow", "## Struct Pointer Overwrite (Heap Menu Challenges)", OVF)
splice("format-string.md", "## Format String Basics", "## Argument Retargeting (Non-Positional %n Trick)", FMT)
splice("rop-advanced.md", "## pwntools Template", "## ret2vdso — Using Kernel vDSO Gadgets (HTB Nowhere to go)", PWN)
splice("advanced.md", "## ret2dlresolve", "## Control Transfer Without a Return Address (pthread Cancellation)", DL)
splice("advanced.md", "## Kernel Exploitation", "## 9-Byte test+je Timing Leak (hxp 2018)", KERN)
splice("rop-advanced.md", "## Seccomp Bypass", "## RETF Architecture Switch for Seccomp Bypass (Midnightflag 2026)", SEC)

p = D + "rop-advanced.md"
s = io.open(p, encoding="utf-8").read()
i = s.index("## Useful Commands")
io.open(p, "w", encoding="utf-8").write(s[:i].rstrip("\n") + "\n")
print("trimmed rop-advanced tail")
