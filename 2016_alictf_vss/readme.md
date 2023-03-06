# ret2syscall

## 检查程序

查看文件属性, `No PIE` 意味着没有启用ASLR，故可以直接使用elf文件中的函数地址

```
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      Symbols         FORTIFY Fortified       Fortifiable     FILE
Partial RELRO   No canary found   NX enabled    No PIE          No RPATH   No RUNPATH   No Symbols        No    0               0               vss
```

任意输入一串字符, 程序崩溃, 通过 gdb 确定崩溃发生的位置

## 漏洞检测

利用 ida 反汇编得到如下伪码, 崩溃发生在循环中，原因来自对 v2 遍历访问到了只读字段

但是可以发现，如果输入字符串的开头字符为 'p', 'y', 时，程序会直接返回，避免崩溃

同时注意到函数 `sub_400330()`, 通过 gdb 观察函数栈时，发现函数执行后，a1 地址指向的数据被拷贝到了 v2 指向的地址处，猜测函数为 `strncpy(ptr, ptr, num)`, 是一个危险函数

```C
{
  int v2[4]; // [rsp+10h] [rbp-40h] BYREF
  __int64 v3[5]; // [rsp+20h] [rbp-30h] BYREF
  unsigned int v4; // [rsp+48h] [rbp-8h]
  int v5; // [rsp+4Ch] [rbp-4h]

  memset(v3, 0, sizeof(v3));
  v2[0] = 0;
  sub_400330(v2, a1, 80LL);
  if ( LOWORD(v2[0]) == 31088 )
    return 1LL;
  v5 = sub_419550(v2);
  for ( dword_6C7A98 = 0; dword_6C7A98 < v5; ++dword_6C7A98 )
    *((_BYTE *)v2 + dword_6C7A98) ^= 0x66u;
  v4 = sub_437E40("pass.enc", 0LL);
  if ( v4 == -1 )
    sub_407700(0xFFFFFFFFLL);
  sub_437EA0(v4, v3, 40LL);
  return (unsigned int)sub_400360(v2, v3) == 0;
}
```

然而观察栈布局，发现最大溢出为 0x10 byte (0x50 - 0x40), 恰好能够覆盖 return address，但不足以进行 ROP; 但是在 main 函数中，足足申请了0x400 byte, 因此可进行 stack pivot, 修改 rsp 从而使用 main 函数的栈;考虑程序中没有使用libc库，但是存在[syscall](https://www.cnblogs.com/tcctw/p/11450449.html)函数调用, 能够通过 `sys_execve` 系统调用来 getshell;需要注意的是，main函数中0x400 byte也是stdin的缓冲区，因此输入会首先保存在main函数中，然后再传入函数 `sub_400330()` 中

## 攻击策略

使用ROPgadget工具获得修改rsp的gadget `add rsp 58h;ret`，以及构造 shellcode 的 ropchain，然后通过以上内容来构造payload，payload会保存在main中，同时前0x50在 `sub_400330()` 中进行 cpy, `add rsp 58h;ret` 会将栈向上移动 0x58, 因此需要补足 0x58 以保证 ropchain 的正常执行

```
main:    rochain
         0x8* A
         arr
         0x40 *A
         py + 0x6 *A
400330:  arr
         0x40 *A
         py + 0x6 *A
```


代码中没有使用libc, 但是存在 syscall 函数的调用，而 `sys_execve` id 为 59，需要传入3个参数，故需要使用 rax, rdi, rsi, rdx 三个寄存器，其中 rax 保存系统调用编号，rdi 为目标可执行文件名称的地址，因此
- 需要将 `/bin/sh` 添加到进程中
- 需要设置好各个参数
而以上操作都可以通过 ROPgadget 来进行构造