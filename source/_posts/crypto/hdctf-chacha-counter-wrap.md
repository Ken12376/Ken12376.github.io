---
title: "不老春：ChaCha20 计数器回绕"
date: "2026-09-12"
categories: "Crypto"
tags: ["ChaCha20", "已知明文", "密钥流复用"]
excerpt: "利用 8 位计数器回绕造成的密钥流复用，以已知小说正文恢复追加内容。"
slug: "hdctf-chacha-counter-wrap"
source_event: "HDCTF"
---

> 复现材料：`novel.txt`、`novel.enc`、`main.c`。赛题附件未随文章打包。本文日期取自原始题解文件的修改日期。

小说末尾鹭鸶剪在笔记本上写了一行字，这行字被加密藏了起来。`novel.txt` 是小说正文，结尾停在“歪歪扭扭写了一行字：”；`novel.enc` 比正文多 23 字节，追加内容就是 flag。

## 加密实现

加密用的 ChaCha20，key 被挖掉，nonce 已知。真正的问题在 `main.c`：

```c
#define CHUNK_SIZE 4096

uint8_t counter = 0;

while ((bytes_read = fread(plain, 1, sizeof(plain), fin)) > 0) {
    chacha20_crypt(key, nonce, counter, plain, cipher, bytes_read);
    fwrite(cipher, 1, bytes_read, fout);
    counter += (bytes_read + 63) / 64;
}
```

`counter` 是 `uint8_t`，最大 255。一个 4096 字节分块消耗 64 个 block，四个分块用掉 0..255，处理完第四块后 counter 从 256 回绕成 0，第五块重新生成第一段密钥流。密钥流被完整复用，和 key 无关。

## 数据对齐

```text
novel.txt: 16760 字节
novel.enc: 16783 字节
```

前四个分块占 16384 字节，第五块 `16783 - 16384 = 399` 字节。第五块复用第一块密钥流，而第一块明文是小说开头，已知。因此：

```text
第五块明文 = 第五块密文 XOR 第一块密文 XOR 第一块明文
```

## 解题脚本

```python
from pathlib import Path

ROOT = Path("cry/3")
CHUNK = 4096

plain = (ROOT / "novel.txt").read_bytes()
cipher = (ROOT / "novel.enc").read_bytes()

tail_len = len(cipher) - 4 * CHUNK
tail_plain = bytes(a ^ b ^ c for a, b, c in zip(cipher[-tail_len:], cipher[:tail_len], plain[:tail_len]))

assert tail_plain[: len(plain) - 4 * CHUNK] == plain[4 * CHUNK:]
secret = tail_plain[-(len(cipher) - len(plain)):]
print("secret =", secret.decode())
print("flag   =", "HDCTF{" + secret.decode().replace(" ", "_") + "}")
```

运行结果：

```text
secret = Gui Hua Gao Shi Tian De
flag   = HDCTF{Gui_Hua_Gao_Shi_Tian_De}
```

解出的第五块正文与 `novel.txt` 第 16384 字节之后完全一致，密钥流复用关系成立。追加的 23 字节是“桂花糕是甜的”的拼音，空格换成下划线后即：

```text
HDCTF{Gui_Hua_Gao_Shi_Tian_De}
```

根因是计数器类型过窄导致回绕，第五块和第一块共享同一段 ChaCha20 密钥流，已知明文直接异或即可恢复。
