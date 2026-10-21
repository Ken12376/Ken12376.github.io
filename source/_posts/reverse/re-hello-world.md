---
title: "HelloWorld：ISO-TP 与两层字符协议"
date: "2026-10-07"
categories: "Reverse"
tags: ["ELF", "ISO-TP", "协议逆向"]
excerpt: "还原固定 CAN 记录与第二层字符表，把 Hello World 编码成两帧请求并解析服务响应。"
slug: "re-hello-world"
source_event: "0xGame"
---

> 整理自原有本地题解，保留原始结论，未在此次归档中重新运行赛题。复现材料：`hello-world-server`。赛题附件未随文章打包。

## 思路概览

`hello-world-server` 是一个 x64 Linux PIE ELF。程序从 `stdin` 读取 9 字节记录，先按简化版 CAN ISO-TP 重组消息，再按题目自定义字符编码解码；只有第二层明文等于 `Hello World` 时，才会把运行环境变量 `FLAG` 通过第一层协议发回。

## 解题过程

### Step 1: 定位主逻辑和第一层协议

`readelf` 可见样本只导入 `read`、`fwrite`、`memcmp`、`getenv`、`strlen` 等 libc 函数。主函数附近的关键分支是：

- `0x1d83`: `getenv("FLAG")`，为空则输出 `[server] FLAG is not set` 后退出。
- `0x1e00`: 读取一条第一层消息。
- `0x1e37`: 调用第二层解码。
- `0x1e73`: 要求第二层解码长度为 `0x0b`。
- `0x1e8c`: 与 `.rodata:0x2020` 的 `Hello World` 做 `memcmp`。
- `0x1eb4`: 校验通过后发送 `FLAG` 环境变量；否则发送 `ERROR`。

`0x1269` / `0x1863` 的分片格式对应 ISO-TP / ISO 15765-2：

```text
外层记录: 08 || 8-byte CAN data   # 题目固定 DLC=8

Single Frame:      0L <L bytes data> <padding>         # 1 <= L <= 7
First Frame:       1H LL <6 bytes data>                # total = (H << 8) | LL
Consecutive Frame: 2S <7 bytes data>                   # S 为 1..15 循环序号
```

这和 ISO-TP 的 Single Frame / First Frame / Consecutive Frame 分片方式一致；题目省掉了 CAN ID 和 Flow Control，只保留固定 9 字节输入输出记录。参考资料：Linux kernel ISO-TP 文档 https://cdn.kernel.org/doc/html/latest/networking/iso15765-2.html 。

### Step 2: 还原第二层字符协议

`.rodata` 中有四组字符表：

```text
0: ABCDEFGHIJKLMNOPQRSTUVWXYZ
1: abcdefghijklmnopqrstuvwxyz
2: 0123456789
3:  !?.,:;()[]{}<>+-*/=_|\@#$%^&~`"'
```

第二层包格式为：

```text
<count> <encoded-char-1> ... <encoded-char-count>
```

每个字符编码 1 字节，高 2 位选择字符组，低 6 位是组内 1-based 下标；下标为 0 或查到空字符都会失败。例如：

```text
H -> 0x08          # uppercase, 第 8 个
e -> 0x45          # lowercase, 0x40 | 5
space -> 0xc1      # symbol, 0xc0 | 1
```

因此 `Hello World` 的第二层 payload 是：

```text
0b 08 45 4c 4c 4f c1 17 4f 52 4c 44
```

长度为 12，超过 Single Frame 上限 7，所以第一层应拆成一个 First Frame 和一个 Consecutive Frame：

```text
08 10 0c 0b 08 45 4c 4c 4f
08 21 c1 17 4f 52 4c 44 00
```

### Step 3: 发送请求拿 flag

完整解题脚本如下。无参数运行时输出二进制请求包；传入 `HOST PORT` 时会连接远端、发送请求并解析 ISO-TP 响应中的 flag。

```python
#!/usr/bin/env python3
import socket
import sys

SYMBOLS = " !?.,:;()[]{}<>+-*/=_|\\@#$%^&~`\"'"
TARGET_TEXT = "Hello World"


def encode_text(text: str) -> bytes:
    out = bytearray([len(text)])
    for char in text:
        code = ord(char)
        if "A" <= char <= "Z":
            out.append(code - 0x40)
        elif "a" <= char <= "z":
            out.append(0x40 | (code - 0x60))
        elif "0" <= char <= "9":
            out.append(0x80 | (code - 0x2F))
        else:
            out.append(0xC0 | (SYMBOLS.index(char) + 1))
    return bytes(out)


def pack_isotp(payload: bytes) -> bytes:
    if len(payload) <= 7:
        return bytes([0x08, len(payload)]) + payload + b"\0" * (7 - len(payload))
    frames = [bytes([0x08, 0x10 | (len(payload) >> 8), len(payload) & 0xFF]) + payload[:6]]
    seq = 1
    for offset in range(6, len(payload), 7):
        chunk = payload[offset : offset + 7]
        frames.append(bytes([0x08, 0x20 | seq]) + chunk + b"\0" * (7 - len(chunk)))
        seq = (seq + 1) & 0xF or 1
    return b"".join(frames)


def read_exact(sock: socket.socket, size: int) -> bytes:
    data = bytearray()
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            break
        data.extend(chunk)
    return bytes(data)


def unpack_isotp_from_socket(sock: socket.socket) -> bytes:
    record = read_exact(sock, 9)
    if len(record) != 9 or record[0] != 0x08:
        raise ValueError("missing 9-byte DLC=8 frame")
    frame = record[1:]
    kind = frame[0] & 0xF0
    if kind == 0x00:
        return frame[1 : 1 + (frame[0] & 0x0F)]
    if kind != 0x10:
        raise ValueError("expected ISO-TP first frame")
    total = ((frame[0] & 0x0F) << 8) | frame[1]
    out = bytearray(frame[2:8])
    seq = 1
    while len(out) < total:
        record = read_exact(sock, 9)
        frame = record[1:]
        if record[0] != 0x08 or (frame[0] & 0xF0) != 0x20 or (frame[0] & 0x0F) != seq:
            raise ValueError("bad ISO-TP continuation frame")
        out.extend(frame[1:8])
        seq = (seq + 1) & 0xF or 1
    return bytes(out[:total])


request = pack_isotp(encode_text(TARGET_TEXT))
if len(sys.argv) == 3:
    with socket.create_connection((sys.argv[1], int(sys.argv[2]))) as sock:
        sock.sendall(request)
        print(unpack_isotp_from_socket(sock).decode(errors="replace"))
else:
    sys.stdout.buffer.write(request)
```

已保存同等脚本到本目录的 `solve.py`。请求包校验：

```bash
python3 solve.py | xxd -p -c 9
# 08100c0b08454c4c4f
# 0821c1174f524c4400
```



## 最终结果

获取真实 flag 的条件是：服务端 `FLAG` 环境变量非空，并且输入经过第一层 ISO-TP 重组、第二层字符表解码后严格等于：

```text
Hello World
```

对容器 `challenge.example.invalid:18455` 发送上面的两帧请求，响应的第一层 ISO-TP payload 解出：

```text
0xGame{0835d591-dee5-4c2f-aa56-16fd8069d321}
```
