# Fragnesia - CVE-2026-46300 (XFRM ESP-in-TCP)

Arbitrary-byte write into the page cache of a read-only file, **without a race**. Member of the Dirty Frag class but a separate bug (`skb_try_coalesce()` drops `SKBFL_SHARED_FRAG`, so the ESP-in-TCP path decrypts in place into a splice-mapped file page). Affected: kernels before the 2026-05-13 patch; mitigation is the Dirty Frag module blacklist (`esp4`, `esp6`, `rxrpc`).

## Model

- Per invocation, exactly **one byte** of the cached file is XORed with one AES-GCM keystream byte (counter block position 2, byte 0).
- The keystream byte is chosen by the IV nonce: build a 256-entry table nonce -> stream byte once, using `AF_ALG`.
- The write happens when a TCP socket switches to `espintcp` ULP **after** data was already spliced from the file into the receive queue: the queued file pages are then processed as ESP ciphertext.

## Steps (as implemented in the public PoC)

1. `unshare(CLONE_NEWUSER | CLONE_NEWNET)` to hold `CAP_NET_ADMIN` in a private netns.
2. Install a transport-mode ESP-in-TCP SA via `NETLINK_XFRM`: AES-128-GCM, known key, SPI `0x100`.
3. Build the keystream table: encrypt counter block `[salt || IV || 00000002]` under the known key; vary the low 32 bits of the IV until every byte value appears (all 256 within the first 65536 nonces).
4. For each byte to change: fork a sender/receiver. Sender splices 4096 bytes starting at the target offset into the TCP stream, prefixed with the ESP-in-TCP length word and an ESP header carrying the chosen IV; receiver installs `TCP_ULP espintcp` only after the data is queued, which triggers the in-place decrypt.
5. Bytes that already match are skipped; each hit increments the ESP sequence number.
6. `execve("/usr/bin/su")` - the cached binary is now the injected stub (`setresuid(0,0,0)`, `setresgid(0,0,0)`, `execve("/bin/sh")`), still unmodified on disk.

## Build

```bash
git clone https://github.com/v12-security/pocs.git && cd pocs/fragnesia
gcc -o exp fragnesia.c && ./exp
# Ubuntu: AppArmor restricts unprivileged userns by default
sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0
```

Afterwards `/usr/bin/su` is poisoned for the lifetime of the cache - every later `su` re-spawns a shell. `echo 1 > /proc/sys/vm/drop_caches` or reboot.

## Detection / mitigation

Blacklist the modules (same as Dirty Frag):

```bash
rmmod esp4 esp6 rxrpc
printf 'install esp4 /bin/false\ninstall esp6 /bin/false\ninstall rxrpc /bin/false\n' > /etc/modprobe.d/dirtyfrag.conf
```

Affected: any kernel without the 2026-05-13 netdev patch; confirmed on 6.8.0-111-generic. Upstream PoC: <https://github.com/v12-security/pocs/tree/main/fragnesia>; credit William Bowling / V12.
