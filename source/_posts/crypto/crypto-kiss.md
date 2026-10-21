---
title: "契约之吻：LLL 与 Ring-LWE"
date: "2026-10-07"
categories: "Crypto"
tags: ["LLL", "Ring-LWE", "格"]
excerpt: "先从短向量恢复隐藏多项式，再通过 Kannan embedding 求回小明文，并代回公开方程验证。"
slug: "crypto-kiss"
source_event: "0xGame"
---

> 复现材料：`契约.sage`、`output.txt`。赛题附件未随文章打包。

## 思路概览

题目把多项式 `F` 的系数藏进一个 64 维格的短向量里；`new_mt` 的那些随机行变换只是上三角幺模变换，不改变格本身。先用 LLL 从 `H` 中恢复短向量得到 `F = x^24 + 2x^3 + 2x + 4`，再把 `B = A*s + e (mod p)` 看成带小误差的 Ring-LWE 样本，用 Kannan embedding/LLL 找回明文系数 `s`。

## 解题过程

### Step 1: LLL 恢复隐藏多项式

`契约.sage` 中：

- `mt[0]` 被替换成 `secret = (f_coeffs, 1, 0, ..., 0)`。
- `new_mt` 是上三角、对角线全为 1 的整数矩阵乘上 `mt`，因此是幺模变换，`H` 与 `mt` 生成同一个格。
- 其他基向量来自 `scale = 2^44` 量级的随机数，而 `secret` 极短，所以直接对 `H` 做 LLL。

LLL 的最短向量为：

```text
[-4, -2, 0, -2, 0, ..., 0, -1, 0, ..., 0]
```

按第 24 项应为首一系数 `+1` 取反，得到：

```text
f_coeffs = [4, 2, 0, 2, 0, ..., 0]
F = x^24 + 2*x^3 + 2*x + 4
```

### Step 2: Kannan embedding 解小误差方程

已知 `F` 后可重建乘法矩阵 `M_A`，题目给出：

```text
B = M_A * s + e (mod p),  |e_i| <= 3
```

构造 49 维嵌入格，基向量为：

```text
(p*I_n, 0, 0)
(M_A[:,j], e_j, 0)
(B, 0, K)
```

其中取 `K = 20`。如果存在小明文 `s` 和小误差 `e`，LLL 会给出短向量：

```text
[e, -s, K]
```

解出的 `s` 为：

```text
[48, 120, 71, 97, 109, 101, 123, 107, 105, 115, 115, 32,
 116, 104, 101, 110, 32, 107, 105, 108, 108, 125, 0, 0]
```

转成字节并去掉末尾 `\x00` padding：

```text
0xGame{kiss then kill}
```

完整求解脚本如下，放在题目目录运行即可：

```python
from pathlib import Path
import ast
import re
from sympy import Matrix

OUT = Path("output.txt")
EMBED_K = 20


def parse_vector(text, name):
    match = re.search(rf"{name} = vector\(ZZ, \[(.*?)\]\)", text, re.S)
    if not match:
        raise ValueError(f"missing vector {name}")
    return ast.literal_eval("[" + match.group(1) + "]")


def parse_matrix_h(text):
    start = text.index("H = Matrix(ZZ, [") + len("H = Matrix(ZZ, [")
    end = text.index("\n])", start)
    return ast.literal_eval("[" + text[start:end] + "]")


def poly_mul_xj_mod(poly, shift, modulus_coeffs):
    n = len(modulus_coeffs)
    coeffs = [0] * (len(poly) + shift)
    for index, value in enumerate(poly):
        coeffs[index + shift] = value

    # F = x^n + sum(f_i*x^i), so x^n = -sum(f_i*x^i).
    while len(coeffs) > n:
        value = coeffs.pop()
        base = len(coeffs) - n
        if value:
            for index, mod_coeff in enumerate(modulus_coeffs):
                coeffs[base + index] -= value * mod_coeff
    return coeffs + [0] * (n - len(coeffs))


def multiplication_matrix(poly, modulus_coeffs):
    n = len(modulus_coeffs)
    columns = [poly_mul_xj_mod(poly, shift, modulus_coeffs) for shift in range(n)]
    return [[columns[col][row] for col in range(n)] for row in range(n)]


def recover_modulus_coeffs(H, n):
    reduced = Matrix(H).lll(delta=0.99)
    shortest = min((list(map(int, reduced.row(i))) for i in range(reduced.rows)),
                   key=lambda row: sum(value * value for value in row))
    if shortest[n] < 0:
        shortest = [-value for value in shortest]
    if shortest[n] != 1:
        raise ValueError(f"unexpected monic coefficient: {shortest[n]}")
    return shortest[:n]


def recover_secret(M, B, p):
    n = len(B)
    rows = []

    for index in range(n):
        row = [0] * (2 * n + 1)
        row[index] = p
        rows.append(row)

    for col in range(n):
        row = [0] * (2 * n + 1)
        for row_index in range(n):
            row[row_index] = M[row_index][col]
        row[n + col] = 1
        rows.append(row)

    rows.append(B + [0] * n + [EMBED_K])
    reduced = Matrix(rows).lll(delta=0.99)

    for row_index in range(reduced.rows):
        row = list(map(int, reduced.row(row_index)))
        if abs(row[-1]) != EMBED_K:
            continue
        sign = 1 if row[-1] > 0 else -1
        error = [value // sign for value in row[:n]]
        secret = [-value // sign for value in row[n:2 * n]]
        if max(abs(value) for value in error) <= 3:
            return secret, error
    raise ValueError("embedded LLL did not find a valid short error vector")


def main():
    text = OUT.read_text(encoding="utf-8")
    H = parse_matrix_h(text)
    A = parse_vector(text, "A")
    B = parse_vector(text, "B")
    n = int(re.search(r"\nn = (\d+)", text).group(1))
    p = int(re.search(r"\np = (\d+)", text).group(1))

    f_coeffs = recover_modulus_coeffs(H, n)
    M = multiplication_matrix(A, f_coeffs)
    secret, error = recover_secret(M, B, p)

    # Optional consistency check against the public equation.
    for row_index in range(n):
        value = sum(M[row_index][col] * secret[col] for col in range(n)) + error[row_index]
        assert value % p == B[row_index]

    flag = bytes(secret).rstrip(b"\x00").decode()
    print(flag)


if __name__ == "__main__":
    main()
```

### Step 3: 本地验证

```powershell
PS> py -3.11 solve.py
0xGame{kiss then kill}
```

并且代回验证满足 `M_A*s + e == B (mod p)`，恢复出的误差每一项都在 `[-3, 3]` 内。

## 最终结果

```text
0xGame{kiss then kill}
```
