---
title: "Lucky_D0g：Base64 解码"
date: "2026-10-18"
categories: "Misc"
tags: ["Base64", "签到"]
excerpt: "识别并解码 Base64 字符串，得到签到题的最终结果。"
slug: "misc-lucky-dog"
source_event: "散题"
---

> 复现材料：`题面密文`。赛题附件未随文章打包。本文日期取自原始题解文件的修改日期。

## 第一步：判断 Base64

密文 `SERDVEZ7VzNsYzBtZV90MF9IRENURl8yMDI2X0x1Y2t5X0QwZyEhIX0=` 末尾有 `=` ，Base64。

## 第二步：解密

```text
HDCTF{W3lc0me_t0_HDCTF_2026_Lucky_D0g!!!}
```
