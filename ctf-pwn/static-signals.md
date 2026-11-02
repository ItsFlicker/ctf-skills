# Exploit-Relevant Static Signals

Use this reference only when the task asks for exploitability or security impact. State the primitive supported by evidence and the additional runtime condition required. Never turn absence of a static artifact into a proof of absence.

| Observed evidence | Security-relevant meaning |
| --- | --- |
| Libc version/build | Narrows offsets, gadget set, heap implementation, and known hardening behavior; confirm the mapped libc at runtime when possible. |
| Seccomp filter or policy evidence | May restrict available syscalls; derive actual allowed/blocked syscalls from the filter or observed behavior, not from presence alone. |
| `GNU_STACK RWE` | An executable stack is requested; shellcode feasibility still depends on runtime enforcement, input placement, and control-flow primitive. |
| `GNU_STACK` missing | Stack executability is unknown and depends on ABI/kernel policy. |
| NX disabled, when runtime evidence confirms it | Shellcode becomes more feasible, but still requires a way to redirect execution into attacker-controlled memory. |
| Non-PIE plus partial RELRO | Fixed ELF base and writable GOT make GOT overwrite a stronger candidate, subject to a write primitive and layout constraints. |
| PIE candidate confirmed as PIE | Exploits generally need an ELF base leak or another way to bridge to known absolute locations. |
| Full RELRO evidence | GOT is intended to be read-only after relocation; seek another target rather than assuming GOT overwrite. |
| Statically linked | Conventional external libc is not mapped separately; use the embedded libc/symbols and assess GOT/PLT differently. |
| Stripped | Named logic and boundaries are missing, requiring reconstruction from dynamic symbols, strings, code, and xrefs. |
| Canary instrumentation observed | Selected code has canary checks; coverage must be checked function by function. |
| No canary artifact observed | Canary status is not established, especially in stripped/static/inlined code; inspect the relevant write paths before claiming a stack overflow route. |
| Canary absence proven for a reachable function | Stack overflow, return-address overwrite, or stack pivot may be viable if an attacker-controlled overflow reaches that frame. |
| `GNU_PROPERTY_X86_FEATURE_1_AND` carries SHSTK/IBT | The binary *requests* CET. Enforcement needs a CET-capable CPU (QEMU `kvm64`/`qemu64` does not expose it), kernel support (`CONFIG_X86_USER_SHADOW_STACK`), and the loader enabling it. Confirm at runtime before designing around shadow stack/IBT; otherwise assume off. |
| `checksec` prints SHSTK/IBT | Same request bit - builds commonly set it, targets commonly do not enforce it. Treat it as a hint to verify, not as evidence of a CET-protected process. |

## Verifying CET at runtime

Static properties only say the binary was built with `-fcf-protection`. Three ways to get the real state, cheapest first:

```c
/* 6.6+; returns -EINVAL without CONFIG_X86_USER_SHADOW_STACK */
unsigned long st = 0;
if (arch_prctl(ARCH_SHSTK_STATUS /* 0x5005 */, &st) == 0) {
    int shstk = st & 1;   /* SHSTK_ENABLED */
    int ibt   = st & 2;   /* IBT_ENABLED   */
}
```

```bash
grep x86_Thread_features /proc/self/status   # fields appear only when a feature is active
grep -m1 flags /proc/cpuinfo | grep -o 'user_shstk\|ibt'   # CPU side
```

- Behavioural: fire a `ret`-based chain. Real SHSTK kills it at the first `ret` with `SIGSEGV` / `si_code = SEGV_CPERR`; if the chain executes, CET is not enforced for this process.
- QEMU `-cpu kvm64`/`qemu64`: no CET CPUID, so the guest can never enable it; `host`/`max` can pass it through, but the guest kernel and glibc still have to opt in.
- glibc can also be told to opt out (`GLIBC_TUNABLES=glibc.cpu.x86_shstk=off` where supported), which is one more reason the static bit does not decide the exploit shape.
