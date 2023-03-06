# pwn

## 术语

pwn: own(`o` is aside of `p` on  keyboard)

gadgets: Gadgets are computer programs or pieces of hardware that provide a specific function or set of functions. Gadgets often combine functionality with novelty, and there is some overlap between gadgets and widgets in the broader sense of each term. 

## linux程序保护机制

ASLR: Address space layout randomization，is a technique that is used to increase the difficulty of performing a buffer overflow attack that requires the attacker to know the location of an executable in memory

PIE: Position Independent Executable, 指的是可与内存地址无关的可执行文件。这意味着，在运行时它可以放置在内存中的任何位置而不会导致错误或崩溃

由于内存的页载入机制，PIE的随机化只能影响到单个内存页。通常来说，一个内存页大小为0x1000，这就意味着不管地址怎么变，某条指令的后12位，3个十六进制数的地址是始终不变的

[保护机制](https://www.jianshu.com/p/91fae054f922)

## 工具

ida-free(Interactive Disassembler): 交互式反汇编工具，能够从可执行文件(机器码)生成汇编代码以及对应的伪代码，[ida-wiki](https://en.wikipedia.org/wiki/Interactive_Disassembler)

ROPgadget(Return-oriented programming gadget): 在二进制文件中搜索gadget，以协助多种文件格式和体系结构的ROP开发

checksec: 用于测试正在使用的标准Linux OS和PaX安全特性的工具，[checksec-doc](https://www.trapkit.de/tools/checksec/)

python(ver3)
- pwntools: 一个CTF框架和开发库。它是用Python编写的，专为快速原型设计和开发而设计，旨在使开发编写尽可能简单，[pwn-doc](http://docs.pwntools.com/en/latest/index.html)
- DynELF：pwntools中一个重要的库，用来获取目标系统的libc并计算任意libc函数的地址，而使用DynELF需要提供一个函数，这个函数能够将内存中指定地址的数据取出，因而必然包括打印函数如 write,puts,printf

### 环境准备

```
# on archlinux 
yay -S ida-free

sudo pacman -S ropgadget checksec

# recommand in venv
pip install pwn
```

### 快速入门

**checksec**

checksec本身是一个 shell 脚本，依赖 readelf 等工具来完成各项功能，通常情况下，用来初步对目标二进制文件保护程度进行了解

```shell
checksec --file=<bin>
```

**ida**

在图形界面中，对二进制代码进行分析，找到漏洞
- `f5` 可将汇编代码以伪代码的形式展示
- `alt + T` 用以搜索二进制文件中的特殊文本
- `ctrl + F` 在函数窗口处检索特定函数

```shell
ida-64 <bin>
```

**ROPgadget**

在目标二进制中进行检索
- 以下命令可检索目标二进制文件中的 PPC(pop rax, pop rdi, call rax)

```shell
ROPgadget.py --binary <bin> --only "pop|call"
```

## 资料

[ctf-wiki](https://ctf-wiki.org/)
[pwn-教程](https://bbs.kanxue.com/thread-256946.htm)
[checksec-知乎](https://zhuanlan.zhihu.com/p/584502713)

## 常见漏洞

### 格式化字符串

[格式化字符串漏洞](https://ctf-wiki.org/pwn/linux/user-mode/fmtstr/fmtstr-intro/)

## PWN基础

### Stack Overflow

1. 寻找危险函数
2. 确定填充长度