---
title: "Rainbow Sour：剥开输出仿射掩码"
date: "2026-09-12"
categories: "Crypto"
tags: ["Rainbow", "签名伪造", "有限域"]
excerpt: "利用公钥附带的仿射掩码恢复中心映射，通过两层线性求解伪造目标消息签名。"
slug: "hdctf-rainbow-sour"
source_event: "HDCTF"
---

> 复现材料：`题目交互服务`。赛题附件未随文章打包。本文日期取自原始题解文件的修改日期。

服务要求提交 `unlock-the-rainbow` 的有效签名。`SIGN` 拒绝签目标消息，但 `KEY` 直接返回了带输出仿射掩码的完整公钥。

## 服务与数据结构

```text
KEY
SIGN <message_hex>
SUBMIT <signature_hex>
QUIT
```

参数固定为 GF(31)：10 个变量、6 个方程，两层结构是 4 个 vinegar + 3 个 oil，再叠 3 个 oil。`KEY` 返回 `map` 和 `trace`，公钥结构是

```text
public(x) = B · central(x) + b
```

`trace.codomain_basis` 是 6×6 的 `B`，`trace.codomain_shift` 是 `b`。公钥只是给中心映射套了个可逆线性变换，掩码参数没藏起来，等于把中心映射也公开了。

## 攻击思路

Rainbow 能签名靠的是 oil 变量只以一次方出现：每层方程里 oil-oil 二次项为 0，固定 vinegar 后方程组对 oil 是线性的。伪造步骤：

1. 用 `central = B⁻¹·(public − b)` 剥掉输出掩码。
2. 目标中心向量 `t = B⁻¹·(hash − b)`，其中 `hash` 是 `sha256("unlock-the-rainbow")` 前 6 字节模 31，即 `[12,18,10,4,21,1]`，与 `KEY` 返回的 `target_vector` 一致。
3. 枚举 4 个 vinegar（31⁴ = 923521 个点），固定后第一层解 3×3 线性系统得到 oil₁。
4. 连同 oil₁ 固定前 7 个变量，第二层再解一个 3×3 系统得到 oil₂，最后整点代入验证 `central(x) == t`。

每层矩阵可逆的概率约 97%，两层同时可逆约 93%，从 `(0,0,0,0)` 开始枚举通常第一个点就命中，整个伪造只有几次小矩阵求逆的开销。

## 解题脚本

`python solve.py <host> <port>` 一步完成取 KEY、伪造、提交：

```python
#!/usr/bin/env python3
"""Forge a signature for unlock-the-rainbow from the public Rainbow map."""

from __future__ import annotations

import argparse
import hashlib
import json
import socket
from typing import Any, Iterable


P = 31
VINEGAR = 4
OIL_LAYER_1 = 3
OIL_LAYER_2 = 3
VARIABLES = VINEGAR + OIL_LAYER_1 + OIL_LAYER_2
EQUATIONS = OIL_LAYER_1 + OIL_LAYER_2
TARGET = b"unlock-the-rainbow"


def inverse(value: int) -> int:
    value %= P
    if value == 0:
        raise ValueError("singular matrix")
    return pow(value, P - 2, P)


def matrix_inverse(matrix: list[list[int]]) -> list[list[int]]:
    size = len(matrix)
    augmented = [
        [value % P for value in row] + [int(row_index == col) for col in range(size)]
        for row_index, row in enumerate(matrix)
    ]

    for col in range(size):
        pivot = next(
            (row for row in range(col, size) if augmented[row][col] % P), None
        )
        if pivot is None:
            raise ValueError("singular matrix")
        augmented[col], augmented[pivot] = augmented[pivot], augmented[col]

        scale = inverse(augmented[col][col])
        augmented[col] = [(value * scale) % P for value in augmented[col]]
        for row in range(size):
            if row == col or augmented[row][col] % P == 0:
                continue
            scale = augmented[row][col]
            augmented[row] = [
                (left - scale * right) % P
                for left, right in zip(augmented[row], augmented[col])
            ]

    return [row[size:] for row in augmented]


def solve_square(matrix: list[list[int]], rhs: list[int]) -> list[int] | None:
    size = len(rhs)
    augmented = [
        [matrix[row][col] % P for col in range(size)] + [rhs[row] % P]
        for row in range(size)
    ]

    pivot_row = 0
    for col in range(size):
        pivot = next(
            (row for row in range(pivot_row, size) if augmented[row][col]), None
        )
        if pivot is None:
            continue
        augmented[pivot_row], augmented[pivot] = (
            augmented[pivot],
            augmented[pivot_row],
        )
        scale = inverse(augmented[pivot_row][col])
        augmented[pivot_row] = [
            (value * scale) % P for value in augmented[pivot_row]
        ]
        for row in range(size):
            if row == pivot_row or augmented[row][col] == 0:
                continue
            scale = augmented[row][col]
            augmented[row] = [
                (left - scale * right) % P
                for left, right in zip(augmented[row], augmented[pivot_row])
            ]
        pivot_row += 1

    if pivot_row != size:
        return None
    return [augmented[row][-1] for row in range(size)]


def message_vector(message: bytes) -> list[int]:
    return [value % P for value in hashlib.sha256(message).digest()[:EQUATIONS]]


def public_to_central(public_map: dict[str, Any], basis: list[list[int]], shift: list[int]) -> dict[str, Any]:
    basis_inverse = matrix_inverse(basis)
    central = {
        "quadratic": [
            [[0] * VARIABLES for _ in range(VARIABLES)]
            for _ in range(EQUATIONS)
        ],
        "linear": [[0] * VARIABLES for _ in range(EQUATIONS)],
        "constant": [0] * EQUATIONS,
    }

    for output in range(EQUATIONS):
        for public_output in range(EQUATIONS):
            scale = basis_inverse[output][public_output]
            for row in range(VARIABLES):
                for col in range(VARIABLES):
                    central["quadratic"][output][row][col] += (
                        scale * public_map["quadratic"][public_output][row][col]
                    )
            for col in range(VARIABLES):
                central["linear"][output][col] += (
                    scale * public_map["linear"][public_output][col]
                )
            central["constant"][output] += scale * (
                public_map["constant"][public_output] - shift[public_output]
            )

    for output in range(EQUATIONS):
        central["constant"][output] %= P
        central["linear"][output] = [
            value % P for value in central["linear"][output]
        ]
        for row in range(VARIABLES):
            for col in range(VARIABLES):
                central["quadratic"][output][row][col] %= P
    return central


def evaluate_prefix(central: dict[str, Any], point: list[int], limit: int) -> list[int]:
    values = []
    for output in range(EQUATIONS):
        value = central["constant"][output]
        for col in range(limit):
            value += central["linear"][output][col] * point[col]
            for row in range(col, limit):
                value += (
                    central["quadratic"][output][col][row]
                    * point[col]
                    * point[row]
                )
        values.append(value % P)
    return values


def oil_matrix(
    central: dict[str, Any], point: list[int], unknowns: Iterable[int], equations: Iterable[int], known_limit: int
) -> list[list[int]]:
    matrix = []
    for output in equations:
        row = []
        for unknown in unknowns:
            coefficient = (
                central["linear"][output][unknown]
                + central["quadratic"][output][unknown][unknown]
            )
            for known in range(known_limit):
                coefficient += central["quadratic"][output][min(known, unknown)][max(known, unknown)] * point[known]
            row.append(coefficient % P)
        matrix.append(row)
    return matrix


def forge_signature(document: dict[str, Any]) -> bytes:
    public_map = document["map"]
    trace = document["trace"]
    central = public_to_central(
        public_map,
        trace["codomain_basis"],
        trace["codomain_shift"],
    )
    basis_inverse = matrix_inverse(trace["codomain_basis"])
    public_target = message_vector(TARGET)
    target = [
        sum(
            basis_inverse[row][col]
            * (public_target[col] - trace["codomain_shift"][col])
            for col in range(EQUATIONS)
        )
        % P
        for row in range(EQUATIONS)
    ]

    for vinegar in _vinegar_points():
        point = list(vinegar) + [0] * (VARIABLES - VINEGAR)
        first_base = evaluate_prefix(central, point, VINEGAR)
        first_matrix = oil_matrix(
            central,
            point,
            range(VINEGAR, VINEGAR + OIL_LAYER_1),
            range(OIL_LAYER_1),
            VINEGAR,
        )
        first_rhs = [
            (target[row] - first_base[row]) % P for row in range(OIL_LAYER_1)
        ]
        first_oils = solve_square(first_matrix, first_rhs)
        if first_oils is None:
            continue
        point[VINEGAR : VINEGAR + OIL_LAYER_1] = first_oils

        second_base = evaluate_prefix(central, point, VINEGAR + OIL_LAYER_1)
        second_matrix = oil_matrix(
            central,
            point,
            range(VINEGAR + OIL_LAYER_1, VARIABLES),
            range(OIL_LAYER_1, EQUATIONS),
            VINEGAR + OIL_LAYER_1,
        )
        second_rhs = [
            (target[row] - second_base[row]) % P
            for row in range(OIL_LAYER_1, EQUATIONS)
        ]
        second_oils = solve_square(second_matrix, second_rhs)
        if second_oils is None:
            continue
        point[VINEGAR + OIL_LAYER_1 :] = second_oils

        if evaluate_prefix(central, point, VARIABLES) == target:
            return bytes(point)

    raise RuntimeError("no preimage found")


def _vinegar_points():
    for first in range(P):
        for second in range(P):
            for third in range(P):
                for fourth in range(P):
                    yield (first, second, third, fourth)


def parse_json_response(raw: bytes) -> dict[str, Any]:
    text = raw.decode("utf-8", errors="replace").strip()
    start, end = text.find("{"), text.rfind("}")
    if start < 0 or end < start:
        raise ValueError(f"KEY response is not JSON: {text!r}")
    return json.loads(text[start : end + 1])


def fetch_key(host: str, port: int) -> dict[str, Any]:
    with socket.create_connection((host, port), timeout=15) as connection:
        connection.sendall(b"KEY\n")
        response = bytearray()
        while True:
            chunk = connection.recv(65536)
            if not chunk:
                break
            response.extend(chunk)
            try:
                return parse_json_response(bytes(response))
            except ValueError:
                continue
        raise ValueError(f"KEY response has no JSON: {bytes(response)!r}")


def read_until_quiet(connection: socket.socket) -> bytes:
    response = bytearray()
    while True:
        try:
            chunk = connection.recv(65536)
            if not chunk:
                break
            response.extend(chunk)
        except socket.timeout:
            break
    return bytes(response)


def submit(host: str, port: int, signature: bytes) -> str:
    with socket.create_connection((host, port), timeout=15) as connection:
        connection.sendall(f"SUBMIT {signature.hex()}\n".encode())
        connection.settimeout(2.0)
        return read_until_quiet(connection).decode("utf-8", errors="replace").strip()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("host")
    parser.add_argument("port", type=int)
    args = parser.parse_args()

    document = fetch_key(args.host, args.port)
    signature = forge_signature(document)
    print(f"signature = {signature.hex()}")
    print(submit(args.host, args.port, signature))


if __name__ == "__main__":
    main()
```

## 运行结果

对 `challenge.example.invalid` 运行：

```text
signature = 000000010c1302001a00
```

`000000010c1302001a00` 是 10 字节原像，逐项对应 10 个变量，每个取值都在 0..30。把签名代入公钥求值得到 `[12,18,10,4,21,1]`，与目标哈希向量一致。`SUBMIT` 后服务端返回 `OK` 并给出 flag。

## 根因

签名 oracle 没有泄露私钥。问题出在 `KEY` 把输出仿射掩码 `B`、`b` 一起公开了：掩码可逆，剥掉之后中心映射完全可见，两层 oil-vinegar 结构把签名退化成枚举 vinegar 后解两个 3×3 线性系统，公钥在这里等价于私钥。

```text
HDCTF{67fc0cae-8328-de72-34ab-98e9a804463f}
```
