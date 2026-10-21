---
title: "shadow-code：两层自解密与动态调试"
date: "2026-10-07"
categories: "Reverse"
tags: ["PE", "自解密", "GDB"]
excerpt: "在两层解密结束后下断点捕获真实校验逻辑，反解输入并回到原程序验证。"
slug: "re-shadow-code"
source_event: "0xGame"
---

> 整理自原有本地题解，保留原始结论，未在此次归档中重新运行赛题。复现材料：`shadow-code.exe`。赛题附件未随文章打包。

## 思路概览

这题是一个 Windows x64 PE 动态解密题。程序先用 `VirtualProtect` 把 `.text` 中的加密代码段改成可写，再用带有 `expand 32-byte k` 常量的流加密例程把代码原地解密；真正的密码校验逻辑只有在运行时才出现。

最终密码为：

```text
8qFcjsMm
```

输入后得到 flag：

```text
0xGame{525ca739-1677-49e6-8c45-6065c57ead1a}
```

## 题目信息

- File: `shadow-code.exe`
- Type: PE32+ executable, x86-64, MinGW-w64/GCC 16.2.0
- Size: 20,992 bytes
- MD5: `0362a354c896dd8803bf1ea26f4ddf51`
- SHA1: `0be78a1fdde885938b5f900e4d4f242ddd8264f4`
- SHA256: `044f6c72aa68486c2ddb21420e5ae2cb61fccc2344e556a90b60265c4b6ebe52`

## 解题过程

### Step 1: 先跑起来，看自解密层

`strings` 能看到 `password: `、`wrong password`、`expand 32-byte k`。这说明程序不是单纯字符串比较，而是运行时解密代码或数据。

用 GDB 运行程序，先在 `main` 调用解密函数 `0x23a0` 之后断下。因为 PE 开启 ASLR，需要用入口点反推出运行时基址：

```gdb
set pagination off
starti < gdb_input.txt
python
import gdb, re
s = gdb.execute('info files', to_string=True)
entry = int(re.search(r'Entry point:\s*(0x[0-9a-fA-F]+)', s).group(1), 16)
base = entry - 0x1440
gdb.execute('set $base = 0x%x' % base)
gdb.execute('break *0x%x' % (base + 0x2386))
end
continue
x/40i $base+0x2480
```

此时 `0x2480` 已经从乱码变成第一层 stub。该 stub 又解密 `0x24f0` 开始的第二层真实校验函数。

### Step 2: 继续动调，抓真实校验逻辑

在第一层 stub 的第二次解密调用之后断下：

```gdb
break *($base+0x24c8)
continue
x/80i $base+0x24f0
```

解密后的关键逻辑如下：

```asm
; read at most 8 bytes as a big-endian 64-bit word
x = 0
for i in range(8):
    if password[i] == 0: break
    x = (x << 8) | password[i]

; require exactly 8 bytes
if i != 8 or password[8] != 0:
    wrong

; 64-bit reversible transform and compare
x ^= 0x819173b095485d69
x = rol64(x, 0x15)
x += 0xe1d88535c1c4d1dd
x ^= 0xf216c53d78b72357
if x == 0x6e4ea9aabaeb2eb4:
    success
else:
    wrong
```

成功分支会再调用同一个解密函数，把 `.data` 中 45 字节的密文解成 flag 并打印。

### Step 3: 反推密码并运行程序拿 flag

64-bit 变换是可逆的，倒推即可得到 8 字节密码。下面脚本放在 `shadow-code.exe` 同目录运行即可直接打印密码和 flag：

```python
from pathlib import Path
import subprocess

MASK64 = (1 << 64) - 1
CONST_XOR_1 = 0x819173B095485D69
CONST_ADD = 0xE1D88535C1C4D1DD
CONST_XOR_2 = 0xF216C53D78B72357
TARGET = 0x6E4EA9AABAEB2EB4
ROTATE_BITS = 0x15
WORD_BYTES = 8


def ror64(value: int, bits: int) -> int:
    return ((value >> bits) | ((value << (64 - bits)) & MASK64)) & MASK64


def recover_password() -> str:
    after_rotate = ((TARGET ^ CONST_XOR_2) - CONST_ADD) & MASK64
    original_word = ror64(after_rotate, ROTATE_BITS) ^ CONST_XOR_1
    return original_word.to_bytes(WORD_BYTES, "big").decode("ascii")


if __name__ == "__main__":
    password = recover_password()
    print(f"password = {password}")

    exe = Path(__file__).with_name("shadow-code.exe")
    result = subprocess.run(
        [str(exe)],
        input=password + "\n",
        text=True,
        capture_output=True,
        check=True,
    )
    print(result.stdout.strip())
```

本机验证输出：

```text
password = 8qFcjsMm
password: 0xGame{525ca739-1677-49e6-8c45-6065c57ead1a}
```

## 最终结果

```text
0xGame{525ca739-1677-49e6-8c45-6065c57ead1a}
```

## 补充说明

- 这题的核心不是静态硬拆所有密文，而是把程序执行到自解密之后再看真实代码。
- 断点选择比反编译更重要：第一处断在 `main` 调用解密函数之后，第二处断在第一层 stub 解密第二层之后。
- 校验函数只处理 8 字节密码，`password[8]` 必须是字符串结尾。
