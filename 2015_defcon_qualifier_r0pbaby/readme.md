# ret2text

## 检查程序

使用 checksec 查看程序，发现程序开启了 PIE, 不能直接使用ELF中的函数地址

```
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      Symbols         FORTIFY Fortified       Fortifiable     FILE
No RELRO        No canary found   NX enabled    PIE enabled     No RPATH   No RUNPATH   No Symbols        Yes   1               2               r0pbaby
```

## 漏洞检测

反汇编二进制文件
- 首先，程序中引用了动态链接库 `libc.so.6`, 动态库中存在 `system` 函数，其会fork一个子进程来执行传入的命令，同时动态库中还有 `/bin/sh` 字符串，两者的组合可以实现 pwn
- 然后找到危险函数 `memcpy`，同时发现用来把保存数据的dest地址就是 rbp, 因此只需超过 8byte 就可以覆盖到 return address

## 攻击策略


1. 计算 `libc.so.6` 中， system函数的相对偏移，`/bin/sh` 的相对偏移，并找到一个PPC的地址
2. 通过 `r0baby` 提供的功能，获得动态链接后的 `libc` 地址，与偏移组合得到实际的 `system` 函数，`/bin/sh` 的地址
3. 依据上述信息组合得到 payload，利用栈溢出漏洞修改 main 函数的执行栈顶，使用 padding 覆盖栈中的fbp, 再用ppc地址替换main的返回地址
4. 当从main返回时，便会执行ppc来准备的system的参数，进而调用 system 从而进入shell