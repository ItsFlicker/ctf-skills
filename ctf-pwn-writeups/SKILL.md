---
name: ctf-pwn-writeups
description: Writeup archive for the 43 pwnable.tw binary exploitation challenges (mostly glibc 2.23, some 2.24/2.27/2.29). Use it when a target is literally a pwnable.tw challenge, when you need a complete worked heap layout from the pre-2.34 hook era, or when comparing the exploit paths other people chose. Do not use it as a technique reference for current targets - load ctf-pwn instead, whose glibc-versions.md tracks what still works on 2.41-2.43.
license: MIT
metadata:
  user-invocable: "false"
  author: Lukasz Jagiello
---

# pwnable.tw Writeup Archive

43 writeups, one file per challenge, indexed by [pwnable-tw/README.md](pwnable-tw/README.md)
(protections, root cause, exploitation paths, remote offsets for each challenge).

## Read the era before you read the exploit

These targets ship glibc 2.23 (most), 2.24, 2.27 or 2.29, so the techniques in
them are the ones that existed then:

- `__malloc_hook` / `__free_hook` exist (removed in 2.34) - a large share of the
  heap chains end in a fastbin dup onto `__malloc_hook - 0x23` plus a one-gadget.
- tcache has no double-free `key` check before 2.29 and safe-linking does not
  exist before 2.32 - the tcache writeups free the same chunk twice without any
  mangle arithmetic.
- fastbins exist (removed on 2.43) and the unsorted-bin `bk` write works
  (blocked on 2.29+).

So never lift an offset or a completion step from here into a modern target.
Take instead:

- the **layout** - how a chunk overlap became a leak and then a write;
- the **interface** - which menu operations produced the alloc/free pattern;
- the **failure** - where the obvious path breaks and what the author did instead.

For anything that has to work on a current libc, use ctf-pwn: `heap-techniques.md`
for the allocator, `heap-fsop.md` for FILE structures, `glibc-versions.md` for the
dead/alive matrix.

## Shape of a file

Environment and points, protections, the root-cause defect with the offending
code, the exploitation paths (often several, roughly ordered by reliability),
key offsets for the remote libc, and a table of community solutions. Open the
index row, then the single challenge you need - the archive is 12k lines.
