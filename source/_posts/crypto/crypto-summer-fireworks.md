---
title: "夏天仍未结束：GCM nonce 复用与音频恢复"
date: "2026-10-07"
categories: "Crypto"
tags: ["AES-GCM", "GF(2)", "FLAC"]
excerpt: "从 Simon 型测量恢复周期向量，利用两条记录复用 nonce 的缺陷解出目标 FLAC。"
slug: "crypto-summer-fireworks"
source_event: "0xGame"
---

> 整理自原有本地题解，保留原始结论，未在此次归档中重新运行赛题。复现材料：`记忆的宝藏.json`、`quantum_echo1.qflac`、`quantum_echo2.qflac`。赛题附件未随文章打包。

## 思路概览

题目给出 Simon 型测量记录和自定义 `QFLAC2` 音频容器。核心是先从 GF(2) 正交测量中恢复 8 个 10-bit 周期向量，得到公开辅助载荷的明文，再利用两条 AES-GCM 记录复用同一 nonce 导致的 CTR keystream reuse 解出目标 FLAC。

## 解题过程

### Step 1: 恢复测量材料并解析容器

`记忆的宝藏.json` 中每条 10-bit 测量向量都满足 `y·s=0 (mod 2)`。每个实例只有一个非零 nullspace 向量，按实例顺序拼接后 LSB-first 打包，得到：

```text
packed_measurements = de970acad204c1714017
```

`QFLAC2` 容器需要先把 `quantum_echo1.qflac` 和 `quantum_echo2.qflac` 原样拼接。布局为 `QFLAC2\x00\x00 || manifest_len || manifest || metadata_len || FLAC metadata || payload/tag...`。

### Step 2: 利用 GCM nonce reuse 解目标音频

第一条 `auxiliary` 载荷的明文由 `SHA256(label || packed_measurements || uint32be(counter))` 扩展得到。两条载荷属于同一个 AES-GCM 会话并复用 nonce，所以 CTR keystream 相同：

```text
stream = C_auxiliary XOR P_auxiliary
P_target = C_target XOR stream
```

完整解题脚本如下，会生成 `recovered.flac` 并打印 flag：

```python
from pathlib import Path
import hashlib
import json
import struct

MAGIC = b"QFLAC2\x00\x00"
UINT32_LEN = 4
BITS_PER_BYTE = 8
VORBIS_COMMENT = 4


def dot_gf2(left, right):
    return sum(a & b for a, b in zip(left, right)) & 1


def recover_secret(rows, width):
    for value in range(1, 1 << width):
        secret = [(value >> (width - 1 - bit)) & 1 for bit in range(width)]
        if all(dot_gf2([int(ch) for ch in row], secret) == 0 for row in rows):
            return secret
    raise ValueError("no non-zero Simon period vector found")


def pack_lsb_first(bits):
    packed = bytearray()
    for offset in range(0, len(bits), BITS_PER_BYTE):
        byte = 0
        for bit_index, bit in enumerate(bits[offset:offset + BITS_PER_BYTE]):
            byte |= bit << bit_index
        packed.append(byte)
    return bytes(packed)


def sha256_counter(label, source, size):
    output = bytearray()
    counter = 0
    label_bytes = label.encode()
    while len(output) < size:
        output += hashlib.sha256(
            label_bytes + source + struct.pack(">I", counter)
        ).digest()
        counter += 1
    return bytes(output[:size])


def parse_qflac(parts):
    blob = b"".join(path.read_bytes() for path in parts)
    if not blob.startswith(MAGIC):
        raise ValueError("bad QFLAC2 magic")

    offset = len(MAGIC)
    manifest_len = struct.unpack_from("<I", blob, offset)[0]
    offset += UINT32_LEN
    manifest = json.loads(blob[offset:offset + manifest_len])
    offset += manifest_len

    metadata_len = struct.unpack_from("<I", blob, offset)[0]
    offset += UINT32_LEN
    metadata = blob[offset:offset + metadata_len]
    offset += metadata_len

    records = []
    tag_len = manifest["tag_len"]
    for payload_len in manifest["payload_lengths"]:
        ciphertext = blob[offset:offset + payload_len]
        offset += payload_len
        tag = blob[offset:offset + tag_len]
        offset += tag_len
        records.append((ciphertext, tag))

    if offset != len(blob):
        raise ValueError("QFLAC2 parser did not consume the full concatenated blob")
    return manifest, metadata, records


def extract_title(flac_bytes):
    if flac_bytes[:4] != b"fLaC":
        raise ValueError("decrypted target is not FLAC")

    offset = 4
    while True:
        header = flac_bytes[offset]
        offset += 1
        is_last = bool(header & 0x80)
        block_type = header & 0x7F
        block_len = int.from_bytes(flac_bytes[offset:offset + 3], "big")
        offset += 3
        block = flac_bytes[offset:offset + block_len]
        offset += block_len

        if block_type == VORBIS_COMMENT:
            pos = UINT32_LEN + int.from_bytes(block[:UINT32_LEN], "little")
            comment_count = int.from_bytes(block[pos:pos + UINT32_LEN], "little")
            pos += UINT32_LEN
            for _ in range(comment_count):
                size = int.from_bytes(block[pos:pos + UINT32_LEN], "little")
                pos += UINT32_LEN
                comment = block[pos:pos + size].decode("utf-8", "replace")
                pos += size
                if comment.lower().startswith("title="):
                    return comment.split("=", 1)[1]
        if is_last:
            break
    raise ValueError("missing FLAC Title tag")


def main():
    base = Path(__file__).resolve().parent
    measurement = json.loads((base / "记忆的宝藏.json").read_text(encoding="utf-8"))

    bits = []
    secrets = []
    for index in range(measurement["instance_count"]):
        secret = recover_secret(
            measurement["samples"][str(index)],
            measurement["secret_bits"],
        )
        secrets.append("".join(str(bit) for bit in secret))
        bits.extend(secret)

    packed = pack_lsb_first(bits)
    manifest, metadata, records = parse_qflac([
        base / "quantum_echo1.qflac",
        base / "quantum_echo2.qflac",
    ])

    auxiliary_plain = sha256_counter(
        manifest["auxiliary"]["label"],
        packed,
        manifest["payload_lengths"][0],
    )
    stream = bytes(a ^ b for a, b in zip(records[0][0], auxiliary_plain))
    target_plain = bytes(a ^ b for a, b in zip(records[1][0], stream))

    recovered = metadata + target_plain
    (base / "recovered.flac").write_bytes(recovered)
    title = extract_title(recovered)

    print("Simon secrets:", ",".join(secrets))
    print("packed_measurements:", packed.hex())
    print("title:", title)
    print(f"flag: 0xGame{{{title}}}")
    print("wrote: recovered.flac")


if __name__ == "__main__":
    main()

```

运行结果：

```text
Simon secrets: 0111101111,1010010101,0000010100,1101001011,0010000010,0000111000,1110000000,1011101000
packed_measurements: de970acad204c1714017
title: 打上花火
flag: 0xGame{打上花火}
wrote: recovered.flac
```

### Step 3: 识别解密结果

解出的 FLAC 的 Vorbis Comment 中包含：

```text
Title=打上花火
Artist=Daoko (ダヲコ)/米津玄師 (よねづ けんし)
```

题目提示要求“解密后识别直接包裹 `0xGame{}`”，因此取标题作为 flag 内容。

## 最终结果

```text
0xGame{打上花火}
```
