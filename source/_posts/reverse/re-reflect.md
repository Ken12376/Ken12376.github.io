---
title: "Reflect：反射加载器里的校验逻辑"
date: "2026-10-07"
categories: "Reverse"
tags: ["PE", "反射加载", "DLL"]
excerpt: "从 PE 中解密内存 DLL，沿 VerifyNode 还原输入变换，并回到原程序验证结果。"
slug: "re-reflect"
source_event: "0xGame"
---

> 复现材料：`Reflect.exe`。赛题附件未随文章打包。

## 思路概览

`Reflect.exe` 是一个 x64 PE reflective loader。主程序先从 `.rdata` 解密出内存 DLL，再按导出名 `VerifyNode` 反射加载并调用它验证输入；真正的 flag 校验逻辑在解密出的 DLL 中。

## 解题过程

### Step 1: 解密反射模块

`strings` 能看到 `VerifyNode`、`Reflect-2026-x64!` 和 `Correct! The reflective module accepted your flag.`。在 `objdump -d -Mintel` 中，主程序用 `Reflect-2026-x64!` 生成 17 字节 key，然后对 `.rdata` 中 RVA `0x50c0`、长度 `0x1400` 的数据逐字节执行：

```text
plain[i] = ror8(cipher[i], i & 7) ^ key[i % 17]
key[j]   = "Reflect-2026-x64!"[j] ^ ((j * 13) & 0xff)
```

解密结果是一个 x64 DLL，导出函数为 `VerifyNode`。

### Step 2: 逆向 `VerifyNode`

DLL 的 `VerifyNode(char *input)` 要求输入长度为 `0x29`。它先从 `.rdata+0x2000` 还原 17 字节尾部 key：

```text
key[i] = seed[i] ^ ((0xea + 0x2b * i) & 0xff)
```

随后要求：

- `input[24:41] == key`
- 对前 24 字节做交错变换：
  - `mixed[2*j] = input[j] + 0x0c`
  - `mixed[2*j+1] = input[12+j] - 0x0c`
- 再满足：`mixed[i] ^ key[i % 17] == target[i]`

完整求解脚本已保存为 `solve.py`，核心逻辑如下：

```python
from pathlib import Path
import struct
import sys

HOST_PAYLOAD_RVA = 0x50C0
HOST_PAYLOAD_SIZE = 0x1400
HOST_KEY_SEED = b"Reflect-2026-x64!"
PAYLOAD_SEED_RVA = 0x2000
PAYLOAD_TARGET_RVA = 0x2020
KEY_LEN = 17
MIXED_LEN = 24


def u16(data, off):
    return struct.unpack_from("<H", data, off)[0]


def u32(data, off):
    return struct.unpack_from("<I", data, off)[0]


def rva_to_off(pe, rva):
    pe_off = u32(pe, 0x3C)
    sections = u16(pe, pe_off + 6)
    opt_size = u16(pe, pe_off + 20)
    sec_off = pe_off + 24 + opt_size
    for i in range(sections):
        off = sec_off + i * 40
        virt_size = u32(pe, off + 8)
        virt_addr = u32(pe, off + 12)
        raw_size = u32(pe, off + 16)
        raw_ptr = u32(pe, off + 20)
        span = max(virt_size, raw_size)
        if virt_addr <= rva < virt_addr + span:
            return raw_ptr + (rva - virt_addr)
    raise ValueError(f"RVA 0x{rva:x} is not inside any section")


def ror8(value, count):
    count &= 7
    return value if count == 0 else ((value >> count) | (value << (8 - count))) & 0xFF


def decode_payload(host):
    key = bytes(b ^ ((i * 13) & 0xFF) for i, b in enumerate(HOST_KEY_SEED))
    start = rva_to_off(host, HOST_PAYLOAD_RVA)
    enc = host[start:start + HOST_PAYLOAD_SIZE]
    return bytes(ror8(b, i) ^ key[i % len(key)] for i, b in enumerate(enc))


def recover_flag(payload):
    seed_off = rva_to_off(payload, PAYLOAD_SEED_RVA)
    target_off = rva_to_off(payload, PAYLOAD_TARGET_RVA)
    seed = payload[seed_off:seed_off + KEY_LEN]
    target = payload[target_off:target_off + MIXED_LEN]

    key = bytes(b ^ ((0xEA + 0x2B * i) & 0xFF) for i, b in enumerate(seed))
    mixed = bytes(target[i] ^ key[i % KEY_LEN] for i in range(MIXED_LEN))

    prefix = bytearray(MIXED_LEN)
    for j in range(12):
        prefix[j] = (mixed[2 * j] - 0x0C) & 0xFF
        prefix[12 + j] = (mixed[2 * j + 1] + 0x0C) & 0xFF
    return (bytes(prefix) + key).decode("ascii")


def main():
    exe_path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("Reflect.exe")
    payload = decode_payload(exe_path.read_bytes())
    print(recover_flag(payload))


if __name__ == "__main__":
    main()
```

运行：

```powershell
py -3 solve.py Reflect.exe
# 0xGame{OvO_A_MaSt3r_of_RRR3f1ec7_1o@der!}
```

### Step 3: 验证

```powershell
'0xGame{OvO_A_MaSt3r_of_RRR3f1ec7_1o@der!}' | .\Reflect.exe
# Input flag: Correct! The reflective module accepted your flag.
```

## 最终结果

```text
0xGame{OvO_A_MaSt3r_of_RRR3f1ec7_1o@der!}
```
