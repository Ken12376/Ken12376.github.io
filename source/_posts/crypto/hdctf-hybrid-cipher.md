---
title: "Hybrid Cipher：摩斯码与凯撒"
date: "2026-09-12"
categories: "Crypto"
tags: ["摩斯码", "凯撒密码"]
excerpt: "先解摩斯码，再执行凯撒位移，组合得到最终短语。"
slug: "hdctf-hybrid-cipher"
source_event: "HDCTF"
---

> 复现材料：`题面密文`。赛题附件未随文章打包。本文日期取自原始题解文件的修改日期。

密文是一段摩斯码：

```text
.--. .-. ..- ...- .... / ..-. -.. .... ...- -.. ..-
```

解出 `PRUVH FDHVDU`，再凯撒平移 3 位得到 `MORSE CAESAR`。两个词转大写、用下划线连接就是 flag。

## Flag

```text
HDCTF{MORSE_CAESAR}
```
