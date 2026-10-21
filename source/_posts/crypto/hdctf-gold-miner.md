---
title: "黄金矿工：compress 是方程不是黑盒"
date: "2026-09-12"
categories: "Crypto"
tags: ["PoW", "GF(2)", "自制哈希"]
excerpt: "把旋转异或关系化为线性方程，反推压缩状态并构造满足 PoW 的 nonce。"
slug: "hdctf-gold-miner"
source_event: "HDCTF"
---

> 复现材料：`hash/fasthash.go`、`题目交互服务`。赛题附件未随文章打包。本文日期取自原始题解文件的修改日期。

题面要一个 nonce，让 `FastHash(prev_hash,merkle_root,timestamp,nonce)` 的前 8 字节全零。64 位目标硬挖要 2^64 次，但 `compress` 在消息块已知时可逆，挖矿直接变成解方程。

## 漏洞

`hash/fasthash.go` 的压缩函数：

```go
func compress(s0, s1, m0, m1 uint64) (uint64, uint64) {
	s0Prime := (s0 ^ m0) * C1
	s1Prime := (s1 ^ m1) * C2

	s0New := s0Prime ^ bits.RotateLeft64(s1Prime, 17)
	s1New := s1Prime ^ bits.RotateLeft64(s0Prime, 41)

	return s0New, s1New
}
```

`C1 = 0x5851F42D4C957F2D`、`C2 = 0x14057B7EF767814F` 都是奇数，乘法 mod 2^64 可逆。记 `u = (s0^m0)*C1`、`v = (s1^m1)*C2`，输出满足：

```
u ^ R17(v) = s0New
v ^ R41(u) = s1New
```

消去 v 得 `u ^ R58(u) = s0New ^ R17(s1New)`，64 个 GF(2) 线性方程，高斯消元直接解。所以知道输出状态和消息块，就能反推前驱状态。可解概率 1/4，不行就换个终态重试。

中间相遇构造 nonce。消息固定前缀 141 字节，nonce 取 35 字节，总长 176 恰好 16 对齐，padding 块 `[0x80,0...]` 和长度块 `(0,176)` 都是定值：

1. 向前：算完前缀和前 3 字节 nonce（第 8 块），得状态 S9；
2. 向后：取终态 `(s0=0, s1=t)`，反解长度块、padding 块，得到第 10 块之后应有的状态 R；
3. 第 9 块随便填，第 10 块解线性方程把 S10 接到 R。

## 解题脚本

```python
import struct

C1 = 0x5851F42D4C957F2D
C2 = 0x14057B7EF767814F
IV0 = 0x6A09E667F3BCC908
IV1 = 0xBB67AE8584CAA73B
MASK = (1 << 64) - 1
INV_C1 = pow(C1, -1, 1 << 64)
INV_C2 = pow(C2, -1, 1 << 64)
PREFIX = ("0" * 64 + ","
          + "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"
          + ",1772880000,").encode()


def rotl(x, k):
    return ((x << k) | (x >> (64 - k))) & MASK


def compress(s0, s1, m0, m1):
    u = ((s0 ^ m0) * C1) & MASK
    v = ((s1 ^ m1) * C2) & MASK
    return u ^ rotl(v, 17), v ^ rotl(u, 41)


def solve_u(c):
    # 解 (I + R58)u = c，返回一个解；无解返回 None
    rows = [((1 << i) | (1 << ((i - 58) % 64)), (c >> i) & 1) for i in range(64)]
    pivot = [-1] * 64
    row = 0
    for col in range(64):
        sel = next((r for r in range(row, 64) if (rows[r][0] >> col) & 1), None)
        if sel is None:
            continue
        rows[row], rows[sel] = rows[sel], rows[row]
        for r in range(64):
            if r != row and ((rows[r][0] >> col) & 1):
                rows[r] = (rows[r][0] ^ rows[row][0], rows[r][1] ^ rows[row][1])
        pivot[row] = col
        row += 1
    if any(mask == 0 and val for mask, val in rows):
        return None
    return sum((1 << pivot[r]) for r in range(64) if pivot[r] != -1 and rows[r][1])


def invert_compress(n0, n1, m0, m1):
    # 求 (s0, s1) 使 compress(s0, s1, m0, m1) == (n0, n1)
    u = solve_u(n0 ^ rotl(n1, 17))
    if u is None:
        return None
    v = n1 ^ rotl(u, 41)
    return ((u * INV_C1) & MASK) ^ m0, ((v * INV_C2) & MASK) ^ m1


def state_after(msg, nblocks):
    s0, s1 = IV0, IV1
    for i in range(nblocks):
        m0, m1 = struct.unpack(">QQ", msg[16 * i:16 * i + 16])
        s0, s1 = compress(s0, s1, m0, m1)
    return s0, s1


# nonce = A(3字节，补完第8块) + B(第9块，随意填) + B2(第10块，待解)
A = b"\x00\x00\x00"
B = b"\x11" * 16
S9 = state_after(PREFIX + A, 9)
S10 = compress(S9[0], S9[1], *struct.unpack(">QQ", B))

PAD_M0, PAD_M1 = struct.unpack(">QQ", b"\x80" + b"\x00" * 15)
for t in range(2000):
    X = invert_compress(0, t, 0, 176)                # 反解长度块 (0, 176)
    if X is None:
        continue
    R = invert_compress(X[0], X[1], PAD_M0, PAD_M1)  # 反解 padding 块
    if R is None:
        continue
    u = solve_u(R[0] ^ rotl(R[1], 17))
    if u is None:
        continue
    v = R[1] ^ rotl(u, 41)
    b2m0 = ((u * INV_C1) & MASK) ^ S10[0]
    b2m1 = ((v * INV_C2) & MASK) ^ S10[1]
    B2 = struct.pack(">QQ", b2m0, b2m1)
    break
else:
    raise SystemExit("no solution")

nonce = A + B + B2
assert len(nonce) == 35
payload = PREFIX + nonce
print("nonce hex:", nonce.hex())

# 完整过一遍 FastHash 自校验
padded = payload + b"\x80" + b"\x00" * 15 + struct.pack(">QQ", 0, len(payload))
s0, s1 = IV0, IV1
for i in range(0, len(padded), 16):
    s0, s1 = compress(s0, s1, *struct.unpack(">QQ", padded[i:i + 16]))
assert s0 == 0
print("hash:", struct.pack(">QQQQ", s0, s1, s0 ^ s1, (s0 + s1) & MASK).hex())
```

脚本自带 FastHash 全流程校验，`s0 == 0` 通过。nonce 提交到远程，服务端返回：

```
[*] Hash result: 0000000000000000000000000000001e000000000000001e000000000000001e
[+] Accepted! Here is your reward: HDCTF{e220342e-f2e9-850d-e3ea-2ad191cebdd8}
```

flag：

```
HDCTF{e220342e-f2e9-850d-e3ea-2ad191cebdd8}
```

根因：压缩函数在消息块已知时可逆，64 位的 PoW 目标敌不过一个可自由构造的 128 位消息块，FastHash 从设计上就赢不了挖矿。
