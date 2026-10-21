---
title: "小伊卡：PNG 宽高与 CRC 修复"
date: "2026-10-07"
categories: "Misc"
tags: ["PNG", "CRC32", "文件修复"]
excerpt: "结合 IDAT 解压长度与原有 IHDR CRC，唯一恢复被清零的图像宽高。"
slug: "misc-png-repair"
source_event: "0xGame"
---

> 复现材料：`fat_Y1k@_ERROR*.png`。赛题附件未随文章打包。

## 思路概览

题目给了一张打不开的 PNG。核心点是：`IHDR` 里的宽高被改成了 `0`，但 `IHDR` 的 CRC 仍保留了原图宽高对应的值；结合 `IDAT` 解压后的扫描线长度，可以唯一恢复出正确宽高 `640 x 640`。

## 解题过程

### Step 1: 定位损坏点

查看 PNG 头部可以看到 `IHDR` 宽高字段全为 0：

```text
89 50 4E 47 0D 0A 1A 0A  ... PNG signature
00 00 00 0D 49 48 44 52  ... IHDR
00 00 00 00 00 00 00 00  ... width=0, height=0
08 02 00 00 00           ... 8-bit RGB, no interlace
83 AF 5E 74              ... stored IHDR CRC
```

但 PNG 每行扫描线长度为：

```text
1 byte filter + width * 3 bytes RGB
```

因此先解压所有 `IDAT` 得到原始扫描线总长度，再枚举所有可能的行长度；最后用原文件里保存的 `IHDR` CRC 校验候选宽高。只有 `640 x 640` 能让 CRC 等于 `0x83af5e74`。

### Step 2: 恢复图片并读取 flag

完整解题脚本如下，只依赖 Python 标准库：

```python
from pathlib import Path
import struct
import zlib

src = next(Path(".").glob("fat_Y1k@_ERROR*.png"))
data = bytearray(src.read_bytes())
assert data[:8] == b"\x89PNG\r\n\x1a\n"

pos = 8
ihdr = None
stored_ihdr_crc = None
idat = bytearray()
while pos < len(data):
    length = int.from_bytes(data[pos:pos + 4], "big")
    chunk_type = bytes(data[pos + 4:pos + 8])
    chunk_data = bytes(data[pos + 8:pos + 8 + length])
    chunk_crc = int.from_bytes(data[pos + 8 + length:pos + 12 + length], "big")

    if chunk_type == b"IHDR":
        ihdr = chunk_data
        stored_ihdr_crc = chunk_crc
    elif chunk_type == b"IDAT":
        idat.extend(chunk_data)
    elif chunk_type == b"IEND":
        break

    pos += 12 + length

assert ihdr is not None
bit_depth, color_type = ihdr[8], ihdr[9]
assert (bit_depth, color_type) == (8, 2)  # RGB888
bytes_per_pixel = 3
raw_len = len(zlib.decompress(idat))

row_lengths = set()
for factor in range(1, int(raw_len ** 0.5) + 1):
    if raw_len % factor == 0:
        row_lengths.add(factor)
        row_lengths.add(raw_len // factor)

hits = []
for row_len in sorted(row_lengths):
    if row_len <= 1 or (row_len - 1) % bytes_per_pixel:
        continue
    width = (row_len - 1) // bytes_per_pixel
    height = raw_len // row_len
    trial_ihdr = struct.pack(">II", width, height) + ihdr[8:]
    trial_crc = zlib.crc32(b"IHDR" + trial_ihdr) & 0xffffffff
    if trial_crc == stored_ihdr_crc:
        hits.append((width, height))

assert hits == [(640, 640)]
width, height = hits[0]

# Patch width/height back into IHDR. The old CRC is already correct for 640x640,
# but recompute it anyway to make the repaired PNG self-contained.
data[16:20] = struct.pack(">I", width)
data[20:24] = struct.pack(">I", height)
data[29:33] = struct.pack(">I", zlib.crc32(data[12:29]) & 0xffffffff)
Path("fixed_640x640.png").write_bytes(data)

image_flag = "0xGame{d0_y0u_truly_underst@nd_(Rc?}"
print(image_flag[:-1] + f"_{width}_{height}" + "}")
```

运行后生成 `fixed_640x640.png`，打开修复后的图片可读到图片上的 flag；注意这里是数字 `0`、字母 `l` 和 `(`，不要误读成字母 `O`、数字 `1` 或字母 `C`：

```text
0xGame{d0_y0u_truly_underst@nd_(Rc?}
```

题目要求把图片 flag 和正确宽高用 `_` 连接，所以把 `640_640` 追加到右花括号前。

## 最终结果

```text
0xGame{d0_y0u_truly_underst@nd_(Rc?_640_640}
```
