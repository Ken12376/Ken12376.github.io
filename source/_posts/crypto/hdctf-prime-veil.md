---
title: "Prime Veil：格权重与小未知数"
date: "2026-09-12"
categories: "Crypto"
tags: ["LLL", "Babai", "格"]
excerpt: "为五个小乘积项建立加权格，经 LLL 与 Babai 求解，再用 gcd 还原四个素数。"
slug: "hdctf-prime-veil"
source_event: "HDCTF"
---

> 复现材料：`prime_veil.py`、`output`、`mpmath`。赛题附件未随文章打包。本文日期取自原始题解文件的修改日期。

`prime_veil.py` 把 flag 塞在 `0x01` 加 80 字节随机数后面，整体当整数 `m`，再乘上四个 58 位素数乘积 `S` 的模逆存进 output。masked 值人人可见，卡点只有那四个小素数。

## 方程

```python
a4 = (a[1]*a[2] + a[3]) % p
c = (a[0]*s[2]*s[3] + a[1]*s[0]**2*s[1] + a[2]*s[1]**3*s[2]**3
     + a[3]*s[0]*s[2]**2 + a4*s[0]*s[1]*s[3]) % p
masked_flag = (m * pow(S, -1, p)) % p
```

把 `a4` 展开，`c` 是五个乘积项的模线性组合：

| 项 | 值 | 位数 |
|---|---|---|
| t0 | s2·s3 | 116 |
| t1 | s0²·s1 | 174 |
| t2 | s1³·s2³ | 348 |
| t3 | s0·s2² | 174 |
| t4 | s0·s1·s3 | 174 |

`c ≡ Σ a_i·t_i (mod p)`，`t_i` 全远小于 p，就是个小未知数的模线性方程。

## 格

格基取 `(W_i·e_i, K·a_i)`，再补一行 `(0,…,0,K·p)`，权重 `W = (2²³², 2¹⁷⁴, 1, 2¹⁷⁴, 2¹⁷⁴)` 把五个 `t_i` 拉到同一量级，目标向量 `(0,0,0,0,0,K·c)`，LLL 归约后跑最近平面（Babai）。

末坐标那个 `K` 不能省。`K=1` 时最近向量不是真解：格子里有大量 `t` 很小的向量，末坐标碰巧落在 c 附近就比真解更近。`K=2³²⁰` 把它们压下去，真解才是唯一最近向量。解出的 `t_i` 要过 `Σ a_i·t_i ≡ c (mod p)` 校验。

## 还原

`t0` 和 `t3` 共享因子 `s2`，gcd 一下四个素数全出来：

```python
from math import gcd

s2 = gcd(t0, t3)
s3 = t0 // s2
s0 = t3 // (s2 * s2)
s1 = t1 // (s0 * s0)
```

然后 `m = masked * S % p`，转字节，丢掉开头的 `0x01` 和 80 字节随机前缀。

## 脚本

```python
import ast
from fractions import Fraction
from math import gcd
import mpmath as mp

mp.mp.dps = 2000

def gso_mpf(B):
    n, m = len(B), len(B[0])
    Bs = [None]*n
    mu = [[mp.mpf(0)]*n for _ in range(n)]
    for i in range(n):
        v = B[i][:]
        for j in range(i):
            num = mp.fdot(v, Bs[j]); den = mp.fdot(Bs[j], Bs[j])
            mu[i][j] = num/den
            v = [v[t] - mu[i][j]*Bs[j][t] for t in range(m)]
        Bs[i] = v
    return Bs, mu

def lll_mpf(rows, delta=0.75):
    B = [list(map(mp.mpf, row)) for row in rows]
    n, m = len(B), len(B[0])
    k = 1
    while k < n:
        for j in range(k-1, -1, -1):
            Bs, mu = gso_mpf(B)
            if abs(mu[k][j]) > 0.5:
                q = int(mp.nint(mu[k][j]))
                B[k] = [B[k][t] - q*B[j][t] for t in range(m)]
        Bs, mu = gso_mpf(B)
        b1 = mp.fdot(Bs[k], Bs[k]); b0 = mp.fdot(Bs[k-1], Bs[k-1])
        if b1 >= (delta - mu[k][k-1]**2) * b0:
            k += 1
        else:
            B[k-1], B[k] = B[k], B[k-1]
            k = max(k-1, 1)
    return B

def gso_exact(rows):
    n, m = len(rows), len(rows[0])
    Bs = [None]*n
    mu = [[Fraction(0)]*n for _ in range(n)]
    for i in range(n):
        v = [Fraction(x) for x in rows[i]]
        for j in range(i):
            num = sum(v[t]*Bs[j][t] for t in range(m))
            den = sum(Bs[j][t]*Bs[j][t] for t in range(m))
            mu[i][j] = num/den
            for t in range(m):
                v[t] -= mu[i][j]*Bs[j][t]
        Bs[i] = v
    return Bs, mu

def babai_exact(rows, target):
    n, m = len(rows), len(rows[0])
    Bs, mu = gso_exact(rows)
    w = [Fraction(x) for x in target]
    for i in range(n-1, -1, -1):
        num = sum(w[t]*Bs[i][t] for t in range(m))
        den = sum(Bs[i][t]*Bs[i][t] for t in range(m))
        q = (2*num + den) // (2*den)
        for t in range(m):
            w[t] -= q*rows[i][t]
    return [target[t] - w[t] for t in range(m)]

# 读 output：c / masked / a / p
with open("output", encoding="utf-8") as f:
    c = int(f.readline())
    masked = int(f.readline())
    a = ast.literal_eval(f.readline())
    p = int(f.readline())

a4 = (a[1]*a[2] + a[3]) % p
coeffs = [a[i] % p for i in range(4)] + [a4]

# 格：(W_i·e_i, K·a_i) + (0,...,0,K·p)，目标 (0,...,0,K·c)
K = 1 << 320
W = [1 << (348-116), 1 << (348-174), 1, 1 << (348-174), 1 << (348-174)]
rows = []
for i in range(5):
    row = [mp.mpf(0)]*6
    row[i] = mp.mpf(W[i])/p
    row[5] = mp.mpf(K)*coeffs[i]/p
    rows.append(row)
rows.append([mp.mpf(0)]*5 + [mp.mpf(K)])

reduced = lll_mpf(rows)
basis = [[int(mp.nint(x*p)) for x in row] for row in reduced]
v = babai_exact(basis, [0,0,0,0,0,K*c])
assert v[5] == K*c  # 校验 Σ a_i·t_i ≡ c (mod p)
t = [round(Fraction(v[i], W[i])) for i in range(5)]

# t 里解出四个素数
s2 = gcd(t[0], t[3])
s3 = t[0] // s2
s0 = t[3] // (s2*s2)
s1 = t[1] // (s0*s0)
assert s1**3 * s2**3 == t[2] and s0*s1*s3 == t[4]

S = s0*s1*s2*s3
m = masked * S % p
padded = m.to_bytes((m.bit_length()+7)//8, "big")
flag = padded[81:]  # 去掉 0x01 + 80 字节随机数
print(flag.decode())
```

## Flag

```text
HDCTF{567d06d4-b9da-4cd7-91f3-e67e34c90c00}
```

坑全在格的权重上：`t_i` 大小不一靠 W 拉平；末坐标不加重，干扰向量会比真解更近。
