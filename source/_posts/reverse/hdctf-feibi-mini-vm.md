---
title: "菲比的破碎解释器：迷你 VM 校验"
date: "2026-09-12"
categories: "Reverse"
tags: ["VM", "状态机", "哈希校验"]
excerpt: "重建逐字节 VM 状态链，枚举候选，再用整串哈希筛出唯一输入。"
slug: "hdctf-feibi-mini-vm"
source_event: "HDCTF"
---

> 复现材料：`main.exe`。赛题附件未随文章打包。本文日期取自原始题解文件的修改日期。

题面：`main.exe` 拒绝所有密钥，只认一个。校验藏在 `0x140001560`——一个 6 字节 VM 程序，对输入的每个位置执行同一段逻辑。

## 校验逻辑

反汇编 `0x140001560`，主循环固定执行程序 `a7 31 e2 5c 93 46`，配合三张表（都在 `.rdata`）：

- `PROG`（`0x1400040b6`）：`a7 31 e2 5c 93 46`
- `IDX`（`0x1400040bd`）：0..28 的置换
- `EXPECTED`（`0x1400040da`）：29 字节密文

每个位置 i 的语义，state 初值 `0xc0dec0de`、跨位置连续：

```
b = key[IDX[i]]
state = (state + b + i*0x37 + 0xa5) & 0xffffffff
state = ((state >> 11) ^ rol32(state, 5)) & 0xffffffff
b ^= (state >> 8) & 0xff
b ^= state & 0xff
b = (b + ((state >> 16) & 0xff)) & 0xff
要求 b == EXPECTED[i]
```

29 位全部通过后还有第二个门槛，对整串输入算哈希：

```
h = 0x13579bdf
h = rol32(h ^ c, 7) + 0x6d2b79f5     # c 按顺序取每个字节
要求 h == 0xeab2f255
```

## 求解

`IDX` 是双射，第 i 个位置只约束 `key[IDX[i]]` 这一个字节。正向枚举 256 个值、沿 state 链推进，满足逐位约束的路径共 8 条，哈希门槛再筛，只剩一条。

解题脚本（仅标准库，直接运行）：

```python
MASK = 0xFFFFFFFF

# 三张表来自 main.exe 的 .rdata（校验函数 0x140001560 反汇编确认）
PROG = bytes.fromhex('a731e25c9346')
IDX = bytes.fromhex('1103180800150e1b060c01131a0a04170f071c0b160512021909100d14')
EXPECTED = bytes.fromhex('ece085a03741b6c2309ffe1e965a5e46a983c544113a2a9ecb3d989edc')


def rol32(x, n):
    return ((x << n) | (x >> (32 - n))) & MASK


def next_state(state, b, i):
    state = (state + b + (i * 0x37 + 0xA5)) & MASK
    state = ((state >> 11) ^ rol32(state, 5)) & MASK
    return state


def enc(state, b):
    b ^= (state >> 8) & 0xFF
    b ^= state & 0xFF
    return (b + ((state >> 16) & 0xFF)) & 0xFF


def final_hash(key):
    h = 0x13579BDF
    for c in key:
        h = (rol32(h ^ c, 7) + 0x6D2B79F5) & MASK
    return h


solutions = []

def dfs(i, state, chosen):
    if i == len(IDX):
        solutions.append(chosen[:])
        return
    for b in range(256):
        s = next_state(state, b, i)
        if enc(s, b) == EXPECTED[i]:
            chosen.append(b)
            dfs(i + 1, s, chosen)
            chosen.pop()

dfs(0, 0xC0DEC0DE, [])

for chosen in solutions:
    key = bytearray(29)
    for i, b in enumerate(chosen):
        key[IDX[i]] = b
    if final_hash(key) == 0xEAB2F255:
        key = bytes(key)
        # 完整重放校验自检
        state = 0xC0DEC0DE
        ok = True
        for i in range(29):
            s = next_state(state, key[IDX[i]], i)
            if enc(s, key[IDX[i]]) != EXPECTED[i]:
                ok = False
            state = s
        assert ok and final_hash(key) == 0xEAB2F255
        print('flag:', key.decode())
```

运行输出：

```
flag: HDCTF{feibi_feibijiubi_miao!}
```

解出的字符串语义也对得上（"飞比飞比就必喵"），29 位逐位比对和 `eab2f255` 哈希全部通过。flag：

```
HDCTF{feibi_feibijiubi_miao!}
```

根因：VM 每个位置只消费 `key` 的一个字节，`IDX` 又是 0..28 的双射，逐位约束直接定死全部字节，最后那道哈希只是给解加唯一性。
