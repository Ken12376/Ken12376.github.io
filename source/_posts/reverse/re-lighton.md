---
title: "LightOn：VM 逆向与 GF(2) 方程"
date: "2026-10-07"
categories: "Reverse"
tags: ["VM", "GF(2)", "Lights Out"]
excerpt: "还原自定义 VM，将 10×10 Lights Out 转换成 GF(2) 方程，求出唯一的最少操作序列。"
slug: "re-lighton"
source_event: "0xGame"
---

> 复现材料：`Lightson.exe`、`Light.bin`。赛题附件未随文章打包。

## 思路概览

`Lightson.exe` 读取 `Light.bin` 并执行自定义 VM 字节码。题目实际是 10×10 的 Lights Out：每次输入一个灯格编号，会翻转该格及上下左右相邻格；目标是把所有灯点亮。

关键纠正：题目提示里的“节点值”不是操作节点编号列表，而是按升序输入最少操作节点后，VM 打印出的最后一个 16 字节哈希节点值。

## 解题过程

### Step 1: 还原 VM 字节码

`fetch8` 对 `Light.bin` 按文件偏移解密：

```python
plain[i] = raw[i] ^ ((i * 0x3d - 0x59) & 0xff)
```

字节码开头用 `0x22` 写入初始灯光状态；后面是 0 到 99 的输入分支。每个分支只执行若干条 `0x23 addr 1`，即翻转灯格。

初始 10×10 状态：

```text
1010010011
1011111000
0100000010
0000010010
0001111000
1100010110
0010000010
1100011101
1010010100
1100100011
```

### Step 2: 建 GF(2) 线性方程

第 `n` 个输入翻转 `n` 自身及上下左右相邻格，例如：

```text
0  -> 0, 1, 10
1  -> 1, 0, 2, 11
11 -> 11, 10, 12, 1, 21
99 -> 99, 98, 89
```

构造：

```text
A * x = all_ones XOR initial
```

矩阵秩为 100，因此解唯一，也就是最少操作解。

最少操作次数为 `30`，升序输入节点为：

```text
0 3 7 10 12 18 21 22 27 30 34 35 39 41 44 48 50 53 59 60 64 66 70 73 75 81 85 88 92 97
```

### Step 3: 计算节点值

VM 每次输入后会把当前输入历史拼成十进制字符串，再追加内置字符串 `0xGame_Lights_on`，做 MD5 后与该字符串逐字节异或并打印十六进制。

对上面的升序最少操作序列：

```text
node_value = 42adba60bc2d635b139bbb0b33dea757
```

因此 flag 内容是满足“最少操作次数、并且操作格子从小到大输入”时程序打印出的节点值；次数 `30` 只是求解条件，不拼进 flag。

```text
42adba60bc2d635b139bbb0b33dea757
```

## 求解脚本

完整脚本已保存为 `solve.py`：

```python
from pathlib import Path
import hashlib
import struct

BOARD_SIZE = 100
MEMORY_SIZE = 0x2000
DECODE_MULTIPLIER = 0x3D
DECODE_OFFSET = 0x59
HASH_SUFFIX_ADDR = 300
HASH_SUFFIX_LEN = 16
FLAG_PREFIX = "0xGame"

OP_STORE_IMM8 = 0x22
OP_XOR_IMM8 = 0x23
OP_MOV_IMM8 = 0x10
OP_CMP = 0x40
OP_JE = 0x42
OP_JMP = 0x41
OP_LEN = {
    0x00: 0, 0x10: 2, 0x11: 2, 0x12: 3, 0x20: 2, 0x21: 2,
    0x22: 3, 0x23: 3, 0x24: 3, 0x25: 2, 0x30: 3, 0x31: 3,
    0x32: 3, 0x33: 3, 0x34: 1, 0x40: 2, 0x41: 2, 0x42: 2,
    0x43: 2, 0x44: 2, 0x45: 2, 0x50: 1, 0x60: 3, 0x61: 4,
    0x62: 2,
}


def decode_bytecode(path: Path) -> bytes:
    raw = path.read_bytes()
    return bytes(
        byte ^ ((offset * DECODE_MULTIPLIER - DECODE_OFFSET) & 0xFF)
        for offset, byte in enumerate(raw)
    )


def parse_instructions(code: bytes):
    pc = 0
    instructions = {}
    while pc < len(code):
        start = pc
        opcode = code[pc]
        pc += 1
        arg_len = OP_LEN[opcode]
        args = code[pc:pc + arg_len]
        pc += arg_len
        instructions[start] = (opcode, bytes(args), pc)
    return instructions


def u16(args: bytes) -> int:
    return args[0] | (args[1] << 8)


def jump_target(pc_after: int, args: bytes) -> int:
    return pc_after + struct.unpack("<h", args)[0]


def extract_initial_memory(instructions) -> list[int]:
    memory = [0] * MEMORY_SIZE
    pc = 0
    while True:
        opcode, args, next_pc = instructions[pc]
        if opcode != OP_STORE_IMM8:
            break
        memory[u16(args)] = args[2]
        pc = next_pc
    return memory


def extract_case_targets(instructions) -> dict[int, int]:
    targets = {}
    for pc, (opcode, args, next_pc) in instructions.items():
        if opcode != OP_MOV_IMM8 or (args[0] & 0x0F) != 1:
            continue
        value = args[1]
        if value >= BOARD_SIZE:
            continue
        cmp_inst = instructions.get(next_pc)
        je_inst = instructions.get(cmp_inst[2]) if cmp_inst else None
        if not cmp_inst or not je_inst:
            continue
        if cmp_inst[0] == OP_CMP and je_inst[0] == OP_JE:
            targets[value] = jump_target(je_inst[2], je_inst[1])
    if len(targets) != BOARD_SIZE:
        raise ValueError(f"expected {BOARD_SIZE} input cases, got {len(targets)}")
    return targets


def extract_toggles(instructions, case_targets: dict[int, int]) -> dict[int, list[int]]:
    toggles = {}
    for value, pc in case_targets.items():
        changed = []
        while True:
            opcode, args, next_pc = instructions[pc]
            if opcode == OP_XOR_IMM8:
                if args[2] != 1:
                    raise ValueError(f"unexpected xor immediate at 0x{pc:x}")
                changed.append(u16(args))
                pc = next_pc
                continue
            if opcode == OP_JMP:
                break
            raise ValueError(f"unexpected opcode 0x{opcode:02x} at 0x{pc:x}")
        toggles[value] = changed
    return toggles


def solve_gf2(initial: list[int], toggles: dict[int, list[int]]) -> list[int]:
    rhs = [1 ^ bit for bit in initial]
    rows = []
    for cell in range(BOARD_SIZE):
        row = 0
        for node, changed in toggles.items():
            if cell in changed:
                row ^= 1 << node
        if rhs[cell]:
            row ^= 1 << BOARD_SIZE
        rows.append(row)

    pivot_columns = []
    pivot_row = 0
    for column in range(BOARD_SIZE):
        pivot = next((i for i in range(pivot_row, BOARD_SIZE) if (rows[i] >> column) & 1), None)
        if pivot is None:
            continue
        rows[pivot_row], rows[pivot] = rows[pivot], rows[pivot_row]
        for i in range(BOARD_SIZE):
            if i != pivot_row and ((rows[i] >> column) & 1):
                rows[i] ^= rows[pivot_row]
        pivot_columns.append(column)
        pivot_row += 1

    if pivot_row != BOARD_SIZE:
        raise ValueError(f"matrix rank is {pivot_row}, expected a unique full-rank solve")

    solution = []
    for row_index, column in enumerate(pivot_columns):
        if (rows[row_index] >> BOARD_SIZE) & 1:
            solution.append(column)
    return solution


def verify_solution(initial: list[int], toggles: dict[int, list[int]], solution: list[int]) -> None:
    state = initial[:]
    for node in solution:
        for cell in toggles[node]:
            state[cell] ^= 1
    if state != [1] * BOARD_SIZE:
        raise ValueError("solution does not turn every light on")


def calc_node_value(solution: list[int], suffix: bytes) -> str:
    input_history = "".join(map(str, solution)).encode()
    digest = hashlib.md5(input_history + suffix).digest()
    return bytes(byte ^ suffix[i] for i, byte in enumerate(digest)).hex()


def main() -> None:
    code = decode_bytecode(Path(__file__).with_name("Light.bin"))
    instructions = parse_instructions(code)
    memory = extract_initial_memory(instructions)
    initial = memory[:BOARD_SIZE]
    suffix = bytes(memory[HASH_SUFFIX_ADDR:HASH_SUFFIX_ADDR + HASH_SUFFIX_LEN])
    toggles = extract_toggles(instructions, extract_case_targets(instructions))
    solution = solve_gf2(initial, toggles)
    verify_solution(initial, toggles, solution)

    node_value = calc_node_value(solution, suffix)
    inner = node_value
    print(f"operation_count = {len(solution)}")
    print("nodes =", " ".join(map(str, solution)))
    print(f"node_value = {node_value}")
    print(f"flag_inner = {inner}")
    print(f"flag = {FLAG_PREFIX}{{{inner}}}")


if __name__ == "__main__":
    main()
```

运行：

```powershell
py -3 solve.py
```

输出：

```text
operation_count = 30
nodes = 0 3 7 10 12 18 21 22 27 30 34 35 39 41 44 48 50 53 59 60 64 66 70 73 75 81 85 88 92 97
node_value = 42adba60bc2d635b139bbb0b33dea757
flag_inner = 42adba60bc2d635b139bbb0b33dea757
flag = 0xGame{42adba60bc2d635b139bbb0b33dea757}
```

### 原程序验证

```powershell
$seq = @(0,3,7,10,12,18,21,22,27,30,34,35,39,41,44,48,50,53,59,60,64,66,70,73,75,81,85,88,92,97)
(($seq -join "`n") + "`n") | .\Lightson.exe .\Light.bin
```

最后一次输出：

```text
>42adba60bc2d635b139bbb0b33dea757
```

随后程序退出，说明所有灯已点亮。

## 最终结果

```text
0xGame{42adba60bc2d635b139bbb0b33dea757}
```
