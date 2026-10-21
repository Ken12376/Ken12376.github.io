---
title: "Fermat's eyes：一步之遥"
date: "2026-09-12"
categories: "Crypto"
tags: ["RSA", "Fermat", "矩阵"]
excerpt: "先用 Fermat 分解近素数 RSA，再从矩阵对角差恢复另一组素数。"
slug: "hdctf-fermat-eyes"
source_event: "HDCTF"
---

> 复现材料：`chall.py`、`output.txt`。赛题附件未随文章打包。本文日期取自原始题解文件的修改日期。

chall.py 出了两道 RSA：第一道 `q1 = nextprime(p1 + gap)`，两个素数只差 2^264 量级；第二道把 `p2²`、`q2²` 藏进一个 2×2 矩阵，对角差一减就把因子抖出来。

## 第一扇门：Fermat

```python
p1 = getPrime(512)
gap = getRandomNBitInteger(264)
q1 = int(nextprime(p1 + gap))
```

`q1 - p1 ≈ 2^264`，比 n1 的四次方根（约 2^256）稍大，普通 Fermat 仍然够用。从 `ceil(√n1)` 起每次加 1，直到 `x² - n1` 为完全平方，步数约 `(q-p)²/(8√n) ≈ 2^13`。解出的 `STAGE1 = b"look_at_my_eigs"` 经 `shake_256` 生成 `r`，是第二扇门的钥匙之一。

## 第二扇门：矩阵里的因子

```python
S = Matrix([[3, 5], [7, 12]])
D = diag(p2**2, q2**2)
A = S * D * S.inv()
M = A + r * eye(2)
```

`S` 行列式为 1，展开 `M` 的对角元：

- `M00 = 36p² - 35q² + r`
- `M11 = 36q² - 35p² + r`

`r` 在对角线上各加一份，相减正好消掉：`M00 - M11 = 71(p² - q²)`。又已知 `p²q² = n2²`，所以 `p² + q² = √((p²-q²)² + 4n2²)`，解出 `p² = (s+d)/2`、`q² = (s-d)/2`，开方后验证 `p2 * q2 == n2` 即可。

## 脚本

```python
import ast
from hashlib import shake_256
from math import isqrt

e = 65537

# 读 output.txt，跳过空行和 M 行
with open("output.txt") as f:
    text = f.read()
vals = {}
for line in text.splitlines():
    if line.startswith("M") or " = " not in line:
        continue
    key, value = line.split(" = ", 1)
    vals[key] = int(value)
M = ast.literal_eval(text.split("M = ", 1)[1].strip())
n1, c1, n2, c2 = vals["n1"], vals["c1"], vals["n2"], vals["c2"]

# 第一扇门：Fermat 分解
x = isqrt(n1)
if x * x < n1:
    x += 1
while True:
    y2 = x * x - n1
    y = isqrt(y2)
    if y * y == y2:
        p1, q1 = x - y, x + y
        break
    x += 1

d1 = pow(e, -1, (p1 - 1) * (q1 - 1))
m1 = pow(c1, d1, n1)
stage1 = m1.to_bytes((m1.bit_length() + 7) // 8, "big")
r = int.from_bytes(shake_256(stage1).digest(96), "big")

# 第二扇门：M00 - M11 = 71 * (p2^2 - q2^2)，结合 p2^2 * q2^2 = n2^2
d = (M[0][0] - M[1][1]) // 71
s = isqrt(d * d + 4 * n2 * n2)
p2 = isqrt((s + d) // 2)
q2 = isqrt((s - d) // 2)
assert p2 * q2 == n2

d2 = pow(e, -1, (p2 - 1) * (q2 - 1))
m2 = pow(c2, d2, n2)
flag = m2.to_bytes((m2.bit_length() + 7) // 8, "big")
print(flag.decode())
```

## Flag

```text
HDCTF{70u_Kn0w_ferm@t_R1ght?yeh1}
```

两道门都没做防护：第一道输在素数差太小，Fermat 几步就拆掉；第二道输在 `S` 行列式为 1，相似变换后的矩阵对角差直接把 `p² - q²` 暴露出来。
