---
title: "你真的懂 Word 吗：隐藏段落与 txtMoji"
date: "2026-09-12"
categories: "Forensics"
tags: ["DOCX", "隐藏文本", "txtMoji"]
excerpt: "从 DOCX 隐藏段落提取 emoji，识别 txtMoji 格式，按题目口令解密 AES 密文。"
slug: "hdctf-word-txtmoji"
source_event: "HDCTF"
---

> 复现材料：`hnusec_team_introduction.docx`。赛题附件未随文章打包。本文日期取自原始题解文件的修改日期。

题面是一份 HnuSec 战队介绍 docx，要找出成员埋的彩蛋。提示只给两条线索：成员最近在"拿来主义"，借来的东西要留署名。

## 定位

`docProps/core.xml` 的 `lastModifiedBy` 是 `Deepankar`，这个人就是 txtmoji.com 的作者。txtmoji 的加密流程：CryptoJS AES 加密明文，得到 OpenSSL 格式的 Base64，删掉开头 `U2FsdGVkX1`，再把剩余字节逐个映射成 emoji。

`word/document.xml` 里有一段白色且带 `<w:vanish/>` 的隐藏段落，共 78 个 emoji。解码时取每个 emoji 码点的低字节，还原出被删掉的 Base64：

```text
U2FsdGVkX1+HBM7pD98RtQv2Qtgtx7yioKxIm285j1C15zpipSnESYNs4TzM+2io8PGQHnF164xDYiP7Qve+ZA==
```

Base64 解出来是 64 字节：`Salted__` + 8 字节盐 + 48 字节 AES-CBC 密文。密码就是战队名 `HnuSec`，key/iv 按 OpenSSL `EVP_BytesToKey`（MD5）派生。

## 解题脚本

```python
import base64, hashlib, html, re, zipfile
from Crypto.Cipher import AES

doc = zipfile.ZipFile('hnusec_team_introduction.docx').read('word/document.xml').decode('utf-8')
emoji = ''.join(
    html.unescape(t)
    for run in re.findall(r'<w:r\b.*?</w:r>', doc, re.S)
    if '<w:vanish' in run
    for t in re.findall(r'<w:t(?:\s[^>]*)?>(.*?)</w:t>', run, re.S)
)
b64 = 'U2FsdGVkX1' + ''.join(chr(ord(c) & 0x7f) for c in emoji)
blob = base64.b64decode(b64)
salt, ct = blob[8:16], blob[16:]

pw = b'HnuSec'
d0 = hashlib.md5(pw + salt).digest()
d1 = hashlib.md5(d0 + pw + salt).digest()
d2 = hashlib.md5(d1 + pw + salt).digest()
plain = AES.new(d0 + d1, AES.MODE_CBC, d2).decrypt(ct)
plain = plain[:-plain[-1]]
print(plain.decode())
```

## Flag

```text
HDCTF{w0rd_Rev1sion_1s_dangerous}
```

根因一句话：`vanish` 隐藏段在 Word 渲染时不可见，但 XML 里原样保留；txtmoji 作者的署名暴露了工具，剩下的就是按它的加密格式还原。
