---
title: "群友群友群？：猪圈密码变体"
date: "2026-10-07"
categories: "Crypto"
tags: ["猪圈密码", "编码"]
excerpt: "以格形和黑点所在行建立字符索引，转写图中符号并恢复原文。"
slug: "crypto-pigpen"
source_event: "0xGame"
---

> 整理自原有本地题解，保留原始结论，未在此次归档中重新运行赛题。复现材料：`题目图片`。赛题附件未随文章打包。

## 思路概览

`hint.jpg` 中的猪和题干里的“小圈/栅栏/划痕”指向猪圈密码（Pigpen cipher）。`ciphertext.jpg` 不是标准“有点/无点”的猪圈密码，而是把 9 种猪圈格形和点所在的 1/2/3 行组合成 27 个字符。

## 解题过程

### Step 1: 确定编码表

按标准猪圈 3×3 方格给 9 种格形编号：

```text
1 = 右+下        2 = 左+右+下      3 = 左+下
4 = 上+右+下      5 = 方框          6 = 上+左+下
7 = 上+右        8 = 上+左+右      9 = 上+左
```

图中每个符号里的黑点落在标注的第 `1/2/3` 行。于是一个字符可写成 `(格形编号, 点所在行)`，并按：

```text
index = (格形编号 - 1) * 3 + 点所在行 - 1
alphabet = ABCDEFGHIJKLMNOPQRSTUVWXYZ_
```

查表。

### Step 2: 转写并解码

从图中按三行读出：

```text
(8,2) (2,2) (4,3) (1,3) (5,3) (5,1) (2,2)
(7,2) (5,3)
(7,1) (3,3) (3,1) (5,2) (7,3) (6,1)
```

完整解码脚本如下：

```python
alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ_"
pairs = [
    (8, 2), (2, 2), (4, 3), (1, 3), (5, 3), (5, 1), (2, 2),
    None,
    (7, 2), (5, 3),
    None,
    (7, 1), (3, 3), (3, 1), (5, 2), (7, 3), (6, 1),
]

message = "".join(
    " " if pair is None else alphabet[(pair[0] - 1) * 3 + pair[1] - 1]
    for pair in pairs
)
flag = f"0xGame{{{message}}}"

print(message)
print(flag)
```

运行结果：

```text
WELCOME TO SIGNUP
0xGame{WELCOME TO SIGNUP}
```

## 最终结果

```text
0xGame{WELCOME TO SIGNUP}
```
