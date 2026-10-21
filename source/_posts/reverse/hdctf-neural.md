---
title: "neural：神经网络的真相"
date: "2026-09-12"
categories: "Reverse"
tags: ["状态机", "numpy", "约束搜索"]
excerpt: "将独立 word 变换拆成四个子问题，合并快照和最终状态约束搜索，再经 mode1 恢复输出。"
slug: "hdctf-neural"
source_event: "HDCTF"
---

> 复现材料：`neural.exe`、`numpy`。赛题附件未随文章打包。本文日期取自原始题解文件的修改日期。

16 个 [0,95] 的整数喂给一个"神经网络"，通过后输出的 48 字节才是 flag。校验分三关，全藏在 mode0 的 54 轮状态变换里。

## 校验路径

主函数读 16 个数（`scanf("%u")`，每个必须 ≤ 0x5f），调用 `0x1400016a0` 做变换。mode0 跑 54 轮，抽出三个结果：

- 第 20 轮快照 4 个散布字节：`out1[0]=0x4e, out1[5]=0xf5, out1[10]=0x6d, out1[15]=0x5f`
- 第 42 轮快照 4 个散布字节：`out1[17]=0x4b, out1[22]=0xc1, out1[27]=0x9f, out1[30]=0x93`
- 最终 16 字节状态 `out2` 与 `.rdata+0xd0d0` 的常量表全等

第三关最容易被漏掉。主函数里先调 memcmp，再查 out1 的字节：

```asm
mov r8d, 0x10
mov rcx, rdi              ; out2
lea rdx, [rip+0x1d09]     ; 0x14000d0d0
call memcmp
test eax, eax
jne wrong
```

把 memcmp 失败跳转 NOP 掉跑真二进制，候选输入直接 `converged`。这说明前两关早过了，唯一缺的是 out2 全等。目标表：

```
0b3accb2dfbe9a9e40b8132f251217f6
```

## 变换结构

mode0 的 54 轮作用在 4 个 4 字节 word 上，word 之间完全独立，每个只依赖 `in[4w..4w+3]`。五类操作：

- `0x2B` / `0xE7`：异或 keystream `k1`，由 `in[4w]`、`in[4w+1]` 经 64 位混合生成
- `0xA3`：异或固定矩阵 `k2`
- `0x51`：字节替换表（前缀和构造）
- `0x6D`：置换
- `0x87`：GF(2^8) 4×4 矩阵乘

初始状态是把 16 字节输入按固定顺序重排后逐字节加 `PADDB_M0`。word 独立意味着 96^4 的搜索能拆开：对 `(a,b)=(in[4w], in[4w+1])` 全扫，内层用 numpy 一次算 96×96 的 `(c,d)` 网格，命中条件三个：第 20 轮字节、第 42 轮字节、最终 4 字节等于目标表对应 word。

四组解：

| word | a b c d |
|---|---|
| 0 | 12 7 31 4 |
| 1 | 88 19 63 42 |
| 2 | 5 27 74 9 |
| 3 | 55 23 81 16 |

## 出 flag

通过后 mode1 再跑一遍变换，最终 16 字节按 `perm48` 重排、异或 `key48`，逐字节打出 48 个字符：

```python
out = bytes(o2[perm48[i]] ^ key48[i] for i in range(48))
```

## 脚本

下面脚本自包含：所有表（`TBL_A`、`PREFIX_SRC`、GF 矩阵、`PADDB`、`key48`、`perm48`）都从 `neural.exe` 的 `.rdata` 按 RVA 读取，64 位种子常量来自反汇编。解出 4 个 word 后验证全部三关，再走 mode1 输出 flag。

```python
#!/usr/bin/env python3
# HDCTF RE2: 还原 54 轮状态机 -> 解 16 个 [0,95] 整数 -> mode1 输出解出 flag
import pathlib
import numpy as np

M64 = (1 << 64) - 1
M32 = (1 << 32) - 1
DELTA = 0x9E3779B97F4A7C15
DELTA2 = 0x3C6EF372FE94F82A
CTR_DELTA = 0xA24BAED5
MODE_XOR = 0xC6BC279692B5CC83
K1_SEED = (DELTA, 0xA24BAED4963EE407)
K2_SEED = (0xD1B54A32D192ED03, 0xC6BC279692B5CC83)
BD_SEED = (0xC6BC279692B5CC83, 0xD1B54A32D192ED03)

# .rdata: vaddr 0x14000d000，文件偏移 0xAC00
RVA = {
    "PADDB_M1": (0x14000d340, 16), "PADDB_M0": (0x14000d350, 16),
    "TBL_A_M1": (0x14000d120, 42), "TBL_A_M0": (0x14000d160, 108),
    "M1_TBL": (0x14000d1e0, 32), "M0_TBL": (0x14000d200, 32),
    "M1_TBL2": (0x14000d220, 64), "M0_TBL2": (0x14000d230, 64),
    "PREFIX_SRC": (0x14000d240, 256),
    "KEY48": (0x14000d0a0, 48), "PERM48": (0x14000d0e0, 48),
}
OUT2_TARGET = bytes.fromhex("0b3accb2dfbe9a9e40b8132f251217f6")
EXE = pathlib.Path(__file__).resolve().parent / "neural.exe"
RDATA = 0xAC00
RDATA_VA = 0x14000d000

# 每个 word 的 (s20 字节, 值, s42 字节, 值)，字节位置是 word 内偏移
CONSTRAINTS = [(0, 0x4E, 1, 0x4B), (1, 0xF5, 2, 0xC1),
               (2, 0x6D, 3, 0x9F), (3, 0x5F, 2, 0x93)]
ORDERS = {0: (1, 0, 2, 3), 1: (2, 3, 0, 1), 2: (3, 0, 1, 2), 3: (3, 2, 0, 1)}


def rol64(x, n):
    return ((x << n) | (x >> (64 - n))) & M64


def mix64(x):
    y = (x ^ (x >> 0x1D)) & M64
    return (y ^ (y << 0xB)) & M64


def gf_mul(a, b):
    r = 0
    for _ in range(8):
        if a & 1:
            r ^= b
        carry = b & 0x80
        b = (b << 1) & 0xFF
        if carry:
            b ^= 0x1D
        a >>= 1
    return r


def prefix_table(src):
    out = bytearray(256)
    cl = 0
    for i in range(256):
        cl = (cl + src[i]) & 0xFF
        out[i] = cl
    return bytes(out)


def bd_seq(mode, tbl_a):
    rounds = 0x6C if mode == 0 else 0x2A
    r8 = BD_SEED[mode]
    seq = []
    for r in range(rounds >> 1):
        m1 = mix64(r8)
        b = ((tbl_a[2 * r] ^ (m1 & M32)) ^ ((m1 >> 0x11) & M32)) & 0xFF
        m2 = mix64((r8 + DELTA) & M64)
        d = ((tbl_a[2 * r + 1] ^ (m2 & M32)) ^ ((m2 >> 0x11) & M32)) & 0xFF
        seq.append((b, d))
        r8 = (r8 + DELTA2) & M64
    return seq


def keystream_gen(seed, count):
    out = bytearray()
    state = seed & M64
    ctr = 0
    for _ in range(count):
        u = ((state << 13) ^ state) & M64
        u = (u ^ (u >> 7)) & M64
        state = (u ^ (u << 17)) & M64
        v = (rol64(state, 17) ^ (state >> 23) ^ state) & M64
        v = (v ^ (ctr & M32)) & M64
        out.append(v & 0xFF)
        ctr = (ctr + 0x3D) & 0xFFFFFFFF
    return bytes(out)


def seed_mix(in0, in1, counter, r8seed):
    rcx = ((in0 + 0x31) * 0x9E3779B1) & M64
    rcx ^= (r8seed ^ counter) & M64
    rcx ^= ((in1 + 0x97) * 0xD1B54A33) & M64
    rcx ^= rol64(rcx, 0x17)
    rcx ^= MODE_XOR
    rax = ((rcx << 0xD) ^ rcx) & M64
    rax = (rax ^ (rax >> 0x7)) & M64
    return (rax ^ (rax << 0x11)) & M64


def load_tables(exe_path):
    raw = exe_path.read_bytes()

    def rd(rva, n):
        off = RDATA + (rva - RDATA_VA)
        return raw[off:off + n]

    t = {name: rd(rva, n) for name, (rva, n) in RVA.items()}
    t["PREFIX"] = prefix_table(t["PREFIX_SRC"])
    return t


def word_op(word, b, d, w, mode, ctx):
    out = bytearray(word)
    if b in (0x2B, 0xE7):
        k = ctx["k1"][w][d * 4:d * 4 + 4]
        for i in range(4):
            out[i] ^= k[i]
    elif b == 0xA3:
        k = ctx["k2"][d % ctx["init"]][w * 4:w * 4 + 4]
        for i in range(4):
            out[i] ^= k[i]
    elif b == 0x51:
        for i in range(4):
            out[i] = ctx["prefix"][out[i]]
    elif b == 0x6D:
        q = ((d * 0xAB) & 0xFFFF) >> 9
        dp = (d - 3 * q) & 0xFF
        perm = ctx["tbl2"][dp * 4:dp * 4 + 4]
        saved = bytes(out)
        for i in range(4):
            out[i] = saved[perm[i]]
    elif b == 0x87:
        saved = bytes(out)
        m = ctx["tbl"][(d & 1) * 16:(d & 1) * 16 + 16]
        for p in range(4):
            acc = 0
            for e in range(4):
                acc ^= gf_mul(saved[e], m[4 * p + e])
            out[p] = acc
    return bytes(out)


def transform(inp, mode, t):
    if mode == 0:
        k0 = bytes([inp[1], inp[0], inp[2], inp[3], inp[6], inp[7], inp[4], inp[5]])
        k1 = bytes([inp[11], inp[8], inp[9], inp[10], inp[15], inp[14], inp[12], inp[13]])
    else:
        k0 = bytes([inp[1], inp[2], inp[3], inp[0], inp[5], inp[7], inp[4], inp[6]])
        k1 = bytes([inp[9], inp[8], inp[10], inp[11], inp[14], inp[15], inp[12], inp[13]])
    paddb = t["PADDB_M0"] if mode == 0 else t["PADDB_M1"]
    state = bytearray((k0[i] + paddb[i]) & 0xFF for i in range(8))
    state += bytearray((k1[i] + paddb[8 + i]) & 0xFF for i in range(8))
    k1buf = []
    counter = 0
    k1count = 44 if mode == 0 else 20
    for w in range(4):
        counter = (counter + CTR_DELTA) & M64
        seed = seed_mix(inp[4 * w], inp[4 * w + 1], counter, K1_SEED[mode])
        k1buf.append(keystream_gen(seed, k1count))
    init = 10 if mode == 0 else 4
    k2raw = keystream_gen(K2_SEED[mode], init * 16)
    k2mat = bytearray(init * 16)
    for i in range(init * 16):
        k2mat[(i >> 4) * 16 + (i & 0xF)] = k2raw[i]
    ctx = {"k1": k1buf, "k2": [bytes(k2mat[r * 16:r * 16 + 16]) for r in range(init)],
           "init": init, "prefix": t["PREFIX"],
           "tbl2": t["M0_TBL2"] if mode == 0 else t["M1_TBL2"],
           "tbl": t["M0_TBL"] if mode == 0 else t["M1_TBL"]}
    out1 = bytearray(32)
    tbl_a = t["TBL_A_M0"] if mode == 0 else t["TBL_A_M1"]
    for r, (b, d) in enumerate(bd_seq(mode, tbl_a)):
        for w in range(4):
            state[w * 4:w * 4 + 4] = word_op(state[w * 4:w * 4 + 4], b, d, w, mode, ctx)
        if mode == 0 and r == 20:
            out1[0:16] = bytes(state)
        if mode == 0 and r == 42:
            out1[16:32] = bytes(state)
    return bytes(out1), bytes(state)


def forward_snap(state, w, keys, ctx):
    s20 = s42 = None
    for r in range(54):
        b, d = ctx["bd"][r]
        if b in (0x2B, 0xE7):
            k = np.frombuffer(keys, dtype=np.uint8, count=4, offset=d * 4)
            state = state ^ k
        elif b == 0xA3:
            state = state ^ ctx["k2np"][d % 10, w * 4:w * 4 + 4]
        elif b == 0x51:
            state = ctx["prefix_np"][state]
        elif b == 0x6D:
            q = ((d * 0xAB) & 0xFFFF) >> 9
            dp = (d - 3 * q) & 0xFF
            state = state[:, list(ctx["tbl2np"][dp * 4:dp * 4 + 4])]
        elif b == 0x87:
            base = (d & 1) * 16
            new = np.zeros_like(state)
            for p in range(4):
                acc = np.zeros(state.shape[0], dtype=np.uint8)
                for e in range(4):
                    acc ^= ctx["gf"][ctx["tblnp"][base + 4 * p + e]][state[:, e]]
                new[:, p] = acc
            state = new
        if r == 20:
            s20 = state.copy()
        if r == 42:
            s42 = state.copy()
    return s20, s42, state


def solve_word(w, t):
    c20pos, c20v, c42pos, c42v = CONSTRAINTS[w]
    target = OUT2_TARGET[4 * w:4 * w + 4]
    P = t["PADDB_M0"][w * 4:w * 4 + 4]
    o = ORDERS[w]
    rng = np.arange(96, dtype=np.uint8)
    cs, ds = np.meshgrid(rng, rng, indexing="ij")
    cs = cs.ravel()
    ds = ds.ravel()
    gf = {c: np.array([gf_mul(v, c) for v in range(256)], dtype=np.uint8) for c in set(t["M0_TBL"])}
    k2raw = keystream_gen(K2_SEED[0], 10 * 16)
    k2np = np.zeros((10, 16), dtype=np.uint8)
    for i in range(10 * 16):
        k2np[i >> 4, i & 0xF] = k2raw[i]
    ctx = {"bd": bd_seq(0, t["TBL_A_M0"]), "k2np": k2np,
           "prefix_np": np.frombuffer(t["PREFIX"], dtype=np.uint8),
           "tbl2np": np.frombuffer(t["M0_TBL2"], dtype=np.uint8),
           "tblnp": np.frombuffer(t["M0_TBL"], dtype=np.uint8), "gf": gf}
    for a in range(96):
        for b in range(96):
            st = np.empty((9216, 4), dtype=np.uint8)
            vals = (a, b, cs, ds)
            for i in range(4):
                st[:, i] = (vals[o[i]] + P[i]) & 0xFF
            keys = keystream_gen(seed_mix(a, b, ((w + 1) * CTR_DELTA) & M64, K1_SEED[0]), 44)
            s20, s42, fin = forward_snap(st, w, keys, ctx)
            hit = ((s20[:, c20pos] == c20v) & (s42[:, c42pos] == c42v)
                   & (fin[:, 0] == target[0]) & (fin[:, 1] == target[1])
                   & (fin[:, 2] == target[2]) & (fin[:, 3] == target[3]))
            if hit.any():
                idx = int(np.nonzero(hit)[0][0])
                return a, b, int(cs[idx]), int(ds[idx])
    return None


def main():
    t = load_tables(EXE)
    inp = []
    for w in range(4):
        sol = solve_word(w, t)
        assert sol is not None, f"word {w} no solution"
        inp += list(sol)
        print(f"word {w}: {sol}")
    print("input:", " ".join(map(str, inp)))
    o1, o2 = transform(bytes(inp), 0, t)
    assert o2 == OUT2_TARGET, o2.hex()
    assert o1[0] == 0x4E and o1[5] == 0xF5 and o1[10] == 0x6D and o1[15] == 0x5F
    assert o1[17] == 0x4B and o1[22] == 0xC1 and o1[27] == 0x9F and o1[30] == 0x93
    print("mode0 checks passed")
    _, o2m = transform(bytes(inp), 1, t)
    flag = bytes(o2m[t["PERM48"][i]] ^ t["KEY48"][i] for i in range(48))
    print("flag:", flag.decode("latin-1"))


if __name__ == "__main__":
    main()
```

## Flag

```
HDCTF{7h3_w31gh75_0f_7ru7h_4r3_n07_4lw4y5_3qu4l}
```

根因一句话：三关合并是 24 字节约束，直接爆 96^16 不可能，靠 word 相互独立拆成四个 4 字节子问题，每个只扫 96^4，几分钟解完。
