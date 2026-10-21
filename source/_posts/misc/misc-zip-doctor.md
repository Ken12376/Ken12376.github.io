---
title: "zip 医生：ZipCrypto 已知明文攻击"
date: "2026-10-07"
categories: "Misc"
tags: ["ZipCrypto", "已知明文", "RSA"]
excerpt: "从 Store 模式下的 pyc 固定头恢复 ZIP 内部状态，解出脚本后继续处理 RSA。"
slug: "misc-zip-doctor"
source_event: "0xGame"
---

> 复现材料：`secret.zip`、`bkcrack`。赛题附件未随文章打包。

## 思路概览

题目给了一个传统 ZipCrypto 加密的 ZIP。关键点是两个条目都使用 `Store`（压缩方法 0），所以文件明文不会再经过 Deflate 变换；可以直接利用 `.pyc` 固定头部做 ZipCrypto 已知明文攻击，恢复内部 key 后解出 `locked.py`，最后分解 RSA 模数得到 flag。

## 解题过程

### Step 1: 观察 ZIP 结构

`secret.zip` 中两个条目均被传统 ZipCrypto 加密，并且压缩方法都是 `Store`：

```text
locked.cpython-313.pyc  encrypted  method=0  csize=666  usize=654  crc=0x222b4190
locked.py               encrypted  method=0  csize=500  usize=488  crc=0xa9339b01
```

这正好对应提示里的“ZipCrypto 松弛”和“Store”：如果是 Deflate，猜到的原始文件头还要先被压缩；但 Store 下 ZIP 加密的就是原始字节。

### Step 2: 用 `.pyc` 已知明文恢复 ZipCrypto key

`locked.cpython-313.pyc` 是 CPython 3.13 的 pyc。可以利用这些已知字节：

- offset `0`: `f3 0d 0d 0a 00 00 00 00`，即 Python 3.13 magic + timestamp pyc flags。
- offset `12`: `e8 01 00 00 e3 00...`，`0x1e8=488` 来自 `locked.py` 的明文长度；随后 `e3` 是 marshal code object 类型，模块级 code object 的前几个计数字段为 0。

使用 `bkcrack`：

```powershell
[IO.File]::WriteAllBytes("$PWD\work\pyc_magic_flags8.bin", [byte[]](0xf3,0x0d,0x0d,0x0a,0,0,0,0))
.\tools\bkcrack-1.8.1-win64\bkcrack-1.8.1-win64\bkcrack.exe `
  -C .\secret.zip `
  -c locked.cpython-313.pyc `
  -p .\work\pyc_magic_flags8.bin `
  -x 12 e8010000e3000000000000000000000000
```

输出：

```text
Keys: 64917537 61b24fcf b564419c
```

然后解密 ZIP：

```powershell
.\tools\bkcrack-1.8.1-win64\bkcrack-1.8.1-win64\bkcrack.exe `
  -C .\secret.zip `
  -k 64917537 61b24fcf b564419c `
  -D .\work\decrypted.zip
```

解出的 `locked.py` 给出 RSA 参数：

```python
n = 115792089237316195423570985008687907853269984665640564039457584007913129639937
c = 19411058501260029511744403653712197844299720287315419561082722362568892501402
```

### Step 3: 分解 RSA 模数并解密

`n = 2^256 + 1`，即 Fermat 数 `F8`，其已知分解为：

```text
p = 1238926361552897
q = 93461639715357977769163558199606896584051237541638188580280321
```

完整脚本见同目录 `solve.py`，核心解密如下：

```python
n = 115792089237316195423570985008687907853269984665640564039457584007913129639937
c = 19411058501260029511744403653712197844299720287315419561082722362568892501402
e = 65537
p = 1238926361552897
q = n // p
phi = (p - 1) * (q - 1)
d = pow(e, -1, phi)
m = pow(c, d, n)
print(m.to_bytes((m.bit_length() + 7) // 8, "big").decode())
```

运行验证：

```powershell
py -3 .\solve.py
```

输出：

```text
0xGame{pyc_1s_n0t_s0_s3cur3}
```

## 最终结果

```text
0xGame{pyc_1s_n0t_s0_s3cur3}
```
