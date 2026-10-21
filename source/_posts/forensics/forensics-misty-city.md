---
title: "雾都的秘密：ICMP、DNS 与图像隐写"
date: "2026-09-12"
categories: "Forensics"
tags: ["PCAP", "DNS", "LSB", "Hilbert"]
excerpt: "从 ICMP 重组 PNG，用只出现一次的 DNS 查询恢复参数，再沿 Hilbert 曲线提取 LSB。"
slug: "forensics-misty-city"
source_event: "HDCTF"
---

> 复现材料：`secret.pcapng`。赛题附件未随文章打包。 本文日期取自原始题解文件的修改日期。

抓包里有 1050 个 ICMP 回声请求、208 条 DNS 查询和少量 TCP。题面提示"图片乘着回声走，字藏在没人问第二遍的问题里"：PNG 从 ICMP 里重组，隐写参数全在只查询过一次的 DNS 记录里。

## 还原图片

id=0x1337 的 475 个 echo request，数据段前 20 字节是自定义头：

```text
IGPK & | 序号(4B BE) | 总数(4B) | 块长(2B) | CRC32(4B) | 数据
```

按序号拼起来得到 645791 字节 PNG（960×432，RGB），SHA256 为 `7639b9fc1c719db4aa614039dad08c38a7d1f9ad33657643c39d20dd62963cc3`，与 DNS TXT 记录一致。

DNS 里三条只出现一次的查询给出了隐写参数：

```text
02.x0-44-dx-13-y0-32-dy-9-grid-32x32-ch-b-mode-lsb-n-1024
03.hilbert-o-5-origin-tl-first-d-y-down-op-read
```

配套 TXT 记录定义了载荷格式：`PAYLOAD=LEN1|FLAG|CRC16CCITT2|PAD-A55A`，`BITS=MSB`，`CRC=1021-FFFF-BE`。

## 提取

从 (44, 32) 起按横向间距 13、纵向间距 9 布 32×32 个采样点，沿 5 阶 Hilbert 曲线（左上起点、首步向下，标准曲线转置一下就是）逐点读 B 通道 LSB，凑 1024 bit，按 MSB 位序打包成 128 字节。

字节 0 是 flag 长度 47，随后 47 字节是 flag，末尾 2 字节是 CRC-16/CCITT（poly `0x1021`、init `0xFFFF`、大端输出）。对 flag 重算 CRC 得到 `0x82D6`，与载荷一致，提取无误。

## 解题脚本

```python
import struct, zlib, hashlib

PCAP = "secret.pcapng"
ICMP_ID = 0x1337
X0, DX, Y0, DY, GRID = 44, 13, 32, 9, 32


def icmp_payloads(path):
    """pcapng 里所有 id=0x1337 的 ICMP echo request 数据段。"""
    data = open(path, "rb").read()
    out = []
    pos = 0
    while pos + 12 <= len(data):
        btype = struct.unpack_from("<I", data, pos)[0]
        if btype == 0x0A0D0D0A:  # section header，决定字节序
            magic = struct.unpack_from("<I", data, pos + 8)[0]
            endian = "<" if magic == 0x1A2B3C4D else ">"
        blen = struct.unpack_from(endian + "I", data, pos + 4)[0]
        if struct.unpack_from(endian + "I", data, pos)[0] == 6:  # enhanced packet
            caplen = struct.unpack_from(endian + "I", data, pos + 24)[0]
            payload = parse_icmp(data[pos + 28 : pos + 28 + caplen])
            if payload:
                out.append(payload)
        pos += blen
    return out


def parse_icmp(pkt):
    if len(pkt) < 34 or pkt[12:14] != b"\x08\x00":
        return None  # 非 Ethernet/IPv4
    ihl = (pkt[14] & 0x0F) * 4
    if pkt[14 + 9] != 1:
        return None
    icmp = pkt[14 + ihl :]
    if len(icmp) < 8 or icmp[0] != 8:
        return None
    if struct.unpack_from(">H", icmp, 4)[0] != ICMP_ID:
        return None
    return icmp[8:]


def reassemble(payloads):
    chunks = {}
    for payload in payloads:
        if not payload.startswith(b"IGPK &"):
            continue
        seq = struct.unpack_from(">I", payload, 6)[0]
        size = struct.unpack_from(">H", payload, 14)[0]
        chunks[seq] = payload[20 : 20 + size]
    return b"".join(chunks[i] for i in sorted(chunks))


def png_pixels(png):
    """解码 8-bit RGB PNG，返回逐行像素字节。"""
    pos = 8
    idat = b""
    while pos < len(png):
        length = struct.unpack_from(">I", png, pos)[0]
        ctype = png[pos + 4 : pos + 8]
        body = png[pos + 8 : pos + 8 + length]
        if ctype == b"IHDR":
            width, height, depth, color = struct.unpack_from(">IIBB", body, 0)
            assert (depth, color) == (8, 2)
        elif ctype == b"IDAT":
            idat += body
        pos += 12 + length
    raw = zlib.decompress(idat)
    stride = width * 3
    pixels = []
    prev = bytearray(stride)
    p = 0
    for _ in range(height):
        ftype = raw[p]
        p += 1
        row = bytearray(raw[p : p + stride])
        p += stride
        for i in range(stride):
            left = row[i - 3] if i >= 3 else 0
            above = prev[i]
            if ftype == 1:
                row[i] = (row[i] + left) & 0xFF
            elif ftype == 2:
                row[i] = (row[i] + above) & 0xFF
            elif ftype == 3:
                row[i] = (row[i] + ((left + above) >> 1)) & 0xFF
            elif ftype == 4:
                upper_left = prev[i - 3] if i >= 3 else 0
                pa = abs(above - upper_left)
                pb = abs(left - upper_left)
                pc = abs(left + above - 2 * upper_left)
                predictor = left if pa <= pb and pa <= pc else (above if pb <= pc else upper_left)
                row[i] = (row[i] + predictor) & 0xFF
        pixels.append(bytes(row))
        prev = row
    return width, height, pixels


def hilbert(order):
    """order 阶 Hilbert 曲线坐标序列，左上起点、首步向下。"""
    if order == 0:
        return [(0, 0)]
    sub = hilbert(order - 1)
    size = 1 << (order - 1)
    out = []
    for x, y in sub:
        out.append((y, x))
    for x, y in sub:
        out.append((x + size, y))
    for x, y in sub:
        out.append((x + size, y + size))
    for x, y in sub:
        out.append((size - 1 - y, 2 * size - 1 - x))
    return out


def crc16_ccitt(data):
    crc = 0xFFFF
    for byte in data:
        crc ^= byte << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
    return crc


def main():
    png = reassemble(icmp_payloads(PCAP))
    print(f"png: {len(png)} bytes, sha256={hashlib.sha256(png).hexdigest()}")
    _, _, pixels = png_pixels(png)
    points = {(col, row): (X0 + col * DX, Y0 + row * DY) for row in range(GRID) for col in range(GRID)}
    order = [(y, x) for x, y in hilbert(5)]  # 转置：首步向下
    bits = [pixels[points[cell][1]][points[cell][0] * 3 + 2] & 1 for cell in order]
    data = bytearray()
    for i in range(0, 1024, 8):
        value = 0
        for bit in bits[i : i + 8]:
            value = (value << 1) | bit
        data.append(value)
    data = bytes(data)
    length = data[0]
    flag = data[1 : 1 + length]
    crc_stored = struct.unpack(">H", data[1 + length : 3 + length])[0]
    print("flag:", flag.decode())
    print("crc ok:", crc_stored == crc16_ccitt(flag))


main()
```

## 最终结果

```text
HDCTF{wh0_w1ll_f1nd_h1lb3rt_wh3n_th3_f0g_l1fts}
```

说穿了就一句话：ICMP 回声的载荷平时没人看，DNS 查询内容解析完就丢，把图和参数拆进这两条通道，隐写就成立了。
