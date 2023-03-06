# ret2libc

## 检查程序

使用 checksec 查看程序安全属性, 注意到此程序为 i386-32 的程序，依赖 glibc-32，同时其并没有开启PIE, 因此ELF地址就是加载之后的地址

```
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH     Symbols          FORTIFY Fortified       Fortifiable     FILE
No RELRO        No canary found   NX enabled    No PIE          No RPATH   No RUNPATH   No Symbols        No    0               1               ropasaurusrex
```
执行程序发现其接收输入，并返回`WIN`字样，而当输入字符超过一定长度时(73), 程序会崩溃

## 漏洞检测

使用 ida64 反汇编，发现在 `sub_80483F4()` 函数处存在漏洞(256 > 136)，其中 0 为标准输入

```
int sub_80483F4()
{
  char v1[136]; // [esp+10h] [ebp-88h] BYREF

  return read(0, v1, 256);
}
```

由于程序中既没有 libc.so 又没有 syscall, 但是存在 read，write 函数，因此可以通过 write@plt 将 read@got 内容打印出来，从而获得 libc, system 等函数的地址，最后再通过 gadget 指令重新跳转至 sub_80483F4 再次溢出，且将返回地址覆盖为 system, 并且参数为 `/bin/sh` 从而 getshell

注意，使用PLT地址跳转，跳转目标函数的下一层应该放该函数的返回地址（因为jmp与call的差异，产生一层栈偏移），参数放在其下

## 攻击策略

1. 确定程序的.test段的起始地址(用于保险)与.bss段的起始地址(保存数据)
2. 通过read处的漏洞构造leak函数，从而构造DynELF以获取system，read函数的地址
3. 再通过read构造getshell read栈布局，传入`/bin/sh`并跳转system来getshell


leak write栈布局
```
arg3
agr2
arg1
start func
write plt
```

getshell read栈布局
```
arg3
arg2
arg1
system
read plt
```