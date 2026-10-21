---
title: "Tide Relay：潮汐迷宫"
date: "2026-09-12"
categories: "Reverse"
tags: ["APK", "迷宫", "状态校验"]
excerpt: "还原 APK 的迷宫与状态校验，找到 33 步路线，并用固定常量恢复明文。"
slug: "hdctf-tide-relay"
source_event: "HDCTF"
---

> 复现材料：`attachment_1.apk`。赛题附件未随文章打包。本文日期取自原始题解文件的修改日期。

题面给的 `attachment_1.apk`（包名 `com.jusy.threethingstoday`）里藏着一个 9×9 迷宫：输入一条 33 步路线，走对了应用就把密钥解出来给你看。

## 校验逻辑

反编译后核心在 `TideRelayActivity`，迷宫和校验常量：

```java
private final String[] grid = {"S..#...#.", ".##.#..#.", ".A..#....", "##.#.###.", "~.+#~..B.", ".###.#~#.", "...#+#...", ".#~C.+.#.", "...##..E#"};
private final long expectedDigest = 2726682773L;
private final long expectedGate = 1939975347;
```

规则：从 `S(0,0)` 走到 `E(7,8)`，按序踩 `A→B→C`；`+` 让 pulse -1，`~` 让 pulse +2；pulse 初始 5，结束时必须是 9。每走一步更新 32 位 `digest`：

```java
jRol = ((rol(((jRol ^ (((long) cCharAt) + (((long) i3) * 17))) ^ ((long) (i5 << 8))) ^ ((long) i4), 5) * 73244475) + 40993409) & 4294967295L;
```

`cCharAt` 是 U/D/L/R，`i3` 是步数，`i5/i4` 是走完这一步后的坐标。校验要求 `digest == 2726682773`、`pulse == 9`、信标掩码 `i7 == 7`，再经 `RiftGate.calculate(digest, 9, 33, 7)` 核对 gate，最后 `decrypt` 输出明文。

`decrypt` 的三个入参全是固定常量，迷宫和 digest 只是绕路，直接还原即可。

## 路线

用 DFS 枚举 33 步路径，剪枝用两个条件：剩余步数内能否到达剩余信标和终点（预计算全图最短路）、pulse 在 ± 极限下能否回到 9。唯一解：

```text
DDRRDDLLDDRRDRRUUURRRLDDDLLLRRRDR
```

轨迹：第 3 步踩 `A`，第 21 步踩 `B`，第 28 步踩 `C`（第 14 步路过 `C` 时还没到 `B`，不算收集），pulse 5→9，digest 正好等于 `2726682773`。

## 脚本

```python
MASK = 0xFFFFFFFF


def rol(x, n):
    return (((x >> (32 - n)) | (x << n)) & MASK)


encrypted = [21, 13, 76, 57, 109, 37, 188, 176, 74, 161, 5, 215, 237, 255,
             106, 234, 76, 45, 186, 133, 213, 185, 169, 189, 89, 178, 91, 34, 183]


def decrypt(digest, pulse, gate):
    j2 = (digest ^ 1831565813) & MASK
    jr = (pulse ^ 2712847316) & MASK
    j3 = (gate ^ 826366246) & MASK
    out = bytearray()
    for i in range(len(encrypted)):
        j4 = (j2 * 1664525 + 1013904223) & MASK
        jr = (jr + rol(j4, 11) + i) & MASK
        j3 ^= jr >> 7
        out.append((((rol(j3, 3) ^ (j4 ^ jr)) & 0xFF) ^ encrypted[i]) ^ ((i * 29 + 83) & 0xFF))
        j2 = j4
    return bytes(out)


print(decrypt(2726682773, 9, 1939975347))
```

输出：

```text
b'HDCTF{Zh3n_Sh1_zako_zako_!!!}'
```

`RiftGate.calculate(2726682773, 9, 33, 7)` 的结果是 `1939975347`，与 `expectedGate` 一致，还原无误。

## Flag

```text
HDCTF{Zh3n_Sh1_zako_zako_!!!}
```

密钥只依赖固定常量，迷宫校验是障眼法；找到 `decrypt` 调用点就结束了。
