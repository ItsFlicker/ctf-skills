# CTF Pwn - Modern glibc Changes (2.38 to 2.43)

The allocator was stable from 2.38 through 2.40; the breakage starts in 2.41 and accelerates in 2.42/2.43 (Ubuntu 26.04 ships 2.43). This file is the "what died, what still works" map; per-technique detail lives in [heap-techniques.md](heap-techniques.md) and [heap-fsop.md](heap-fsop.md).

## Release map

| glibc | First shipped in | Allocator change |
|---|---|---|
| 2.35 | Ubuntu 22.04 | - |
| 2.38 - 2.39 | Ubuntu 24.04 | none in ptmalloc vs 2.37 (safe-linking since 2.32, malloc hooks gone since 2.34); see [heap-techniques.md](heap-techniques.md#tcache-239-changes--key-count-and-calloc) |
| 2.40 | Ubuntu 24.10 | no malloc changes |
| 2.41 | Ubuntu 25.04 | small chunks freed while tcache is full go straight to the smallbin; `calloc` starts using tcache |
| 2.42 | Ubuntu 25.10 | fastbin to tcache size check; largebin `nextsize` unlink check; `realloc` frees bypass tcache; double-free scan across all bins; `counts` renamed to `num_slots`; **tcache large chunks**; lazy tcache init |
| 2.43 | Ubuntu 26.04 | **fastbin removed**; tcache cap 7 to 16; tcache-large pop needs an exact size; mmap chunk size is 0x10 smaller; lazy init moved to the first free |
| 2.44 (future) | - | unsorted-bin tcache fill removed (`ea4c36c3`), which kills tcache-relative-write |

2.42 is a transition release no distro ships for long - current CTFs tend to jump from 2.39 straight to 2.43, so plan for both.

## 2.41 - smallbin-direct free, calloc joins tcache

**Small chunks freed while tcache is full now go directly to the smallbin** (`e2436d6f`):

```c
if (!in_smallbin_range (size))
  { /* unsorted bin, fd_nextsize = bk_nextsize = NULL */ }
else
  { /* bin_at (smallbin_index (size)), mark_bin, check fwd->bk == bck */ }
```

Consequences: the "free an 8th chunk, it lands in unsorted, read `main_arena`" recipe still works for **large** sizes, but a small chunk no longer passes through unsorted - free-to-leak timing shifts, and a forged `bk` now trips `free(): chunks in smallbin corrupted`. House of Orange follows the same rule: `sysmalloc` frees the old top with `_int_free`, so a top shrunk below `0x400` now lands in a smallbin (or in tcache, which comes first), and only the `>= 0x400` variants still reach the unsorted bin.

**`calloc` now pops tcache** (`226e3b0a`, `tcache_try_malloc`): the 2.39 property "calloc is tcache-neutral, so it grooms without touching counts" is gone. Chains that relied on it (House of Tangerine style) must be re-planned, and a `calloc` that lands on a poisoned chunk zero-fills it.

## 2.42 - the big hardening release

### fastbin to tcache size check (`d10176c0`)

When `_int_malloc` stashes the remainder of a fastbin into tcache it now verifies the victim maps to the same tcache index:

```
malloc(): chunk size mismatch in fastbin
```

**Dead:** *fastbin reverse into tcache*. **Alive:** classic fastbin dup and fake-chunk targets, as long as every chunk's size stays consistent with the bin.

### largebin unlink `nextsize` check (`4cf2d869`)

Before inserting into a largebin it asserts the skip list is circular:

```
if (fwd->fd->bk_nextsize->fd_nextsize != fwd->fd)
  malloc_printerr ("malloc(): largebin double linked list corrupted (nextsize)");
```

**Dead:** the one-shot *largebin attack* that writes a target pointer through a corrupted `bk_nextsize`. Variants that keep the `fd_nextsize/bk_nextsize` loop consistent, or that attack `fd/bk` through another bin, are unaffected.

### `realloc` frees bypass tcache (`cd335350`)

`__libc_realloc` now calls `_int_free_chunk` instead of `_int_free`, so chunks released by grow/shrink go to the bins, never to tcache.

**New primitive:** `realloc` can push a chunk into smallbin/unsorted/largebin even while the matching tcache bin is full - useful for leaks and for escaping tcache saturation.

### tcache double-free scan covers all bins (`eff1f680`)

`tcache_double_free_verify (tcache_entry *e)` now walks **every** tcache bin for `e`, not just the bin implied by its current size:

```c
for (size_t tc_idx = 0; tc_idx < TCACHE_MAX_BINS; ++tc_idx)
  { ... if (tmp == e) malloc_printerr ("free(): double free detected in tcache 2"); }
```

**Dead:** "flip the chunk size, then free again" tcache dup. **Alive:** clearing `e->key` before the second free, or any route where the chunk is not in a tcache list at all.

### `counts[]` becomes `num_slots[]` (`7e10e30e`)

`tcache_perthread_struct` now stores *remaining* capacity instead of a used count:

```c
typedef struct tcache_perthread_struct
{
  uint16_t num_slots[TCACHE_MAX_BINS];   /* 7 on 2.42, 16 on 2.43 - counts DOWN */
  tcache_entry *entries[TCACHE_MAX_BINS];
} tcache_perthread_struct;
```

Consequences for metadata corruption: zeroing a slot **disables that bin** (frees fall through to bins) instead of overflowing it, and `num_slots` never exceeds the fill count, so "set the count to 0xff" tricks that worked on `counts` need re-thinking. Layout: 2.41 still has 64 bins (`counts[64]`), so `entries[]` is at `+0x80`; 2.42+ has 76 bins (64 small + 12 large), so `entries[]` is at `+0x98` and the struct's chunk grows from ~0x290 to ~0x300.

### tcache large chunks (`cbfd7988`)

Chunks above `mp_.tcache_max_bytes` (default 0x410) can live in 12 extra per-thread bins:

```
tidx = 64 + clz(0x400) - clz(size)      # python: 64 - (0x400).bit_length() + size.bit_length()
```

so 0x420-0x800 maps to bin 64, 0x800-0x1000 to 65, 0x1000-0x2000 to 66 (ranges left-closed, right-open). Each bin holds up to 16 chunks, kept sorted ascending by size behind the (still safe-linked) `fd`. Enable with `GLIBC_TUNABLES=malloc.tcache.tcache_max_bytes=131072` (up to 4 MiB) or by writing `mp_.tcache_max_bytes` once you have a libc write.

Why it matters: tcache poisoning gets 12 more bins, but a pop returns any chunk >= the request size on 2.42 (2.43 requires an exact match), so track sizes.

### Lazy `tcache_perthread_struct` init (`cbfd7988`)

The per-thread tcache is no longer created on the first `malloc`; it appears on the first **tcache-sized** request (`tcache_malloc_init`).

**New surface:** until that moment there is no tcache chunk on the heap, so a heap overflow can pre-fill or steer the `tcache_perthread_struct` memory - how2heap's `glibc_2.42/tcache_metadata_hijacking.c`. 2.43 moves the init point again (first free, below).

## 2.43 - fastbin gone, 16 slots

- **fastbin removed** - the string `fastbin` no longer appears in `malloc/malloc.c` on master. Every fastbin technique is dead: fastbin dup, fastbin reverse into tcache, `__malloc_hook`-adjacent fake sizes, fastbin consolidation tricks. Small chunks that overflow tcache go to the smallbin instead.
- **tcache cap 7 to 16** (`TCACHE_FILL_COUNT 16`, `0b9210bd`): saturating a bin takes 16 frees, and "free 8 chunks to force smallbin/unsorted" becomes "free 17".
- **tcache-large pop requires an exact size match** (`b2b4b46a`): 2.42 returned any greater-or-equal chunk, 2.43 requires equality.
- **mmap chunk size is 0x10 smaller** (`614cfd0f`): an mmap allocation of `n` now reports `n - 0x10`, matching regular chunk accounting; arithmetic that assumed the old size breaks.
- **lazy init moved to the first free** (`2bf2188f`, `tcache_free_init`, gated by `tcache_inactive()`): a program that only allocates tcache-sized chunks still has no tcache chunk on the heap.

## Dead / alive matrix

| technique | 2.39 | 2.41 | 2.42 | 2.43 |
|---|---|---|---|---|
| tcache poisoning (safe-linked) | yes | yes | yes | yes - 16 slots, 76 bins |
| tcache dup via size flip | yes | yes | **no** (all-bin scan) | **no** |
| tcache dup via `key` patch | yes | yes | yes | yes |
| fastbin dup | yes | yes | yes (size must match) | **no** (fastbin gone) |
| fastbin reverse into tcache | yes | yes | **no** (size check) | **no** |
| largebin attack via `bk_nextsize` | yes | yes | **no** (nextsize check) | **no** |
| unsorted-bin `main_arena` leak | yes | yes (large sizes) | yes | yes |
| `realloc`-driven bin placement | no | no | **yes** (new) | yes |
| House of Orange (old top released by `sysmalloc`) | yes | yes | yes | yes - destination by size: tcache / smallbin / unsorted |
| House of Tangerine (calloc grooming) | yes | **no** | **no** | **no** |
| tcache relative write (`mp_.tcache_bins`) | no | yes | hard | hard; removed in 2.44 |
| `__free_hook` / `__malloc_hook` | **no** (gone in 2.34) | no | no | no |
| FSOP / `_IO_FILE` | yes | yes | yes | yes - untouched by these patches |

## Fingerprinting the target

```bash
ldd --version   # or: ./libc.so.6 | head -1
strings -a libc.so.6 | grep -m1 'GNU C Library'
python3 -c "d=open('libc.so.6','rb').read(); print('fastbin' in d)"   # False on 2.43+
```

Runtime probes, when a heap read is already available:

- the `tcache_perthread_struct` chunk is normally the first heap chunk (chunk size ~0x290 up to 2.41, ~0x300 on 2.42+); its `+0x80` (+0x98 on 2.42+) area is `counts`/`num_slots` - free one chunk and watch it go **up** (2.39-2.41) vs **down** (2.42+).
- free 8 chunks of size 0x40: 2.42 keeps the 8th in a smallbin, 2.43 puts it in tcache (16 slots), so the smallbin stays empty.
- `malloc_info(0, stdout)` and a recent pwndbg (`heap` command) understand the large-tcache layout.

## Working on 2.42 / 2.43

- Leaks: unsorted/smallbin and largebin `fd/bk` still expose `main_arena`.
- Writes: tcache poisoning is still the cheapest - patch `key`, respect `num_slots`, and use `mp_.tcache_max_bytes` to reach the large bins.
- New primitives: `realloc`-forced bin placement (2.42+), lazy-tcache metadata control (2.42/2.43), tcache large as an extra playground.
- Do not build on `__free_hook`/`__malloc_hook` (gone since 2.34) or on pre-2.42 `counts` semantics; FSOP itself is still fine.

**References:** [Ubuntu 24.04 to 26.04 heap changes](https://rocketma.dev/2026/03/31/glibc2.42/); glibc `malloc/malloc.c` at tags `glibc-2.41`, `glibc-2.42`, `master` (2.43); how2heap `glibc_2.42/` and `glibc_2.43/`.

Commits: `e2436d6f` (2.41 smallbin direct), `226e3b0a` (2.41 calloc/tcache), `d10176c0` (2.42 fastbin size check), `4cf2d869` (2.42 largebin nextsize), `cd335350` (2.42 realloc), `eff1f680` (2.42 all-bin dup scan), `7e10e30e` (2.42 num_slots), `cbfd7988` (2.42 tcache large + lazy init), `614cfd0f` (2.43 mmap -0x10), `2bf2188f` (2.43 lazy init on free), `0b9210bd` (2.43 16 slots), `b2b4b46a` (2.43 exact size), `ea4c36c3` (2.44 tcache fill removal).
