# double free

## 检查程序

查看程序信息, 发现除了stack canary以外，其他的保护均已开启

```
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      Symbols         FORTIFY Fortified       Fortifiable     FILE
Partial RELRO   No canary found   NX enabled    PIE enabled     No RPATH   No RUNPATH   84 Symbols        No    0               3               fheap
```

尝试fheap, 发现其本身为交互式命令行软件，提供 create, delete, quit 三个功能选项，其中 create 允许用户创建一个note, 要求设置文本最大长度并传入一份文本，delete 则可以按id删除某一个note

## 漏洞检测

使用 ida 逆向二进制文件，分析可得，note的主体结构为:

```c
struct {
    // base
    union {
        char *dest
        char array [16]
    }
    // base + 16
    uint
    // base + 24
    free()
}
```

create 的主体逻辑为:
1. 先申请 0x20 byte 的堆上空间，用来存放 note 的堆上数据
2. 如果 传入的字符串长度小于 0xf, 则会将字符串存储在 char array 处，否则则会申请一片新的堆上内存，并将地址保存在 dest 处，uint 为字符串长度
3. 随后会根据数据长度的不同把一个 free() 函数保存在高 8 byte 中

delete 依据输入的下标来删除对于的note，将当前 note 指针作为参数传入 free 函数来完成，但是程序中的两个 `freelong`, `freeshort` 函数，虽然将内存空间进行来释放，但却没有把对应的指针置空，因而存在UAF，Double free漏洞，可以用来攻击

## 攻击策略

1. 首先 malloc 两个较小(小于 0xf)的堆上内存 note0, note1，然后再free
2. 然后再 malloc 一个较大(大于 0x20)的堆上内存 note2, 此时会首先malloc 0x20 用来保存 note2, 再 malloc 0x20 用来保存字符串
3. 考虑 fastbin, note2 *dest 恰好指向的就是 note1
4. 覆盖 note1 的 free 函数为其他函数以实现劫持


考虑到PIE会对内存进行随机化，故不能直接使用elf中的函数指针来进行覆盖，但由于PIE只能对单个内存页进行随机化，因此页内偏移不会改变，故可以在 free 函数所在页内寻找合适的函数

考虑到要覆盖的函数形式为 `f(ptr)`, 因此可以使用 `system("/bin/sh")` 来 getshell, 而为实现这一目标，需要确定 `system` 的地址，由于程序中并没有直接链接libc库，因此需通过DynELF来获得`system`的地址，而对于开启PIE的程序，需要为DynELF传入一个程序基地址，因此主要思路为
1. 首先替换free函数为put, 由于put函数会将传入其中的字符串全部打印出来，应此可以泄漏put地址，与elf中的put地址计算就能得到程序的基础地址
2. 通过基础地址可以得到printf的地址，由此可以构造内存泄漏的DynELF来获取 system 地址
3. 替换 free 为 system， 并设置传入参数为 "/bin/sh" ，完成 getshell

printf泄漏布局

```
8byte target addr
8byte yes.xxxx
8byte note ptr
8byte return addr
```
