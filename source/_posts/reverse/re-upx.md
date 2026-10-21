---
title: "UPX：从标准壳到字符串校验"
date: "2026-10-17"
categories: "Reverse"
tags: ["PE", "UPX", "脱壳"]
excerpt: "识别标准 UPX 壳，脱壳后定位 strcmp 目标字符串，再运行程序验证输入。"
slug: "re-upx"
source_event: "散题"
source_author: "海鸥"
---

> 整理自原有本地题解，保留原始结论，未在此次归档中重新运行赛题。复现材料：`upx.exe`、`UPX 工具`。赛题附件未随文章打包。

## 思路概览

题目是一个被 UPX 3.96 压缩的 Windows x64 PE。脱壳后可以看到 `main` 直接使用 `strcmp` 比较输入和硬编码字符串，因此拿到目标串即可得到 flag。

## 解题过程

### Step 1: 识别 UPX 壳

PE 节区名为 `UPX0`、`UPX1`、`UPX2`，导入表中出现 `VirtualProtect`，文件内还能看到 `UPX!` 与版本号 `3.96`，可以确认是标准 UPX 壳。

原始文件 SHA-256：

```text
8580794CE50D7743BD723C4289AF49FD8385D68AB3F2B7ACE70C03E8C54B6BF5
```

### Step 2: 脱壳

使用 UPX 5.0.2 脱壳：

```powershell
upx.exe -d -o upx_unpacked.exe upx.exe
```

输出显示文件从 `73163` 字节恢复为 `112075` 字节。脱壳后的 `.rdata` 中直接出现了目标字符串。

### Step 3: 确认校验逻辑并恢复 flag

在 `0x1400014f2` 处的 `main` 中，程序先调用 `scanf` 读取输入，再调用 `strcmp`：

```asm
14000151f  call scanf
140001524  lea  rax,[rbp-0x40]
140001528  lea  rdx,[rip+0xeae9]   ; 140010018, 目标字符串
14000152f  mov  rcx,rax
140001532  call strcmp
140001537  test eax,eax
140001539  jne  main+0x5a
```

目标字符串位于文件偏移 `0xe618`，内容为：

```text
NSSCTF{UPX_c4n_3as1ly_5h3ll_pr0gr4m!}
```

完整复现脚本：

```python
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


challenge = Path(__file__).with_name("upx.exe")
upx = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("upx")

with tempfile.TemporaryDirectory() as temp_dir:
    packed = Path(temp_dir) / "packed.exe"
    unpacked = Path(temp_dir) / "unpacked.exe"
    shutil.copy2(challenge, packed)
    subprocess.run(
        [str(upx), "-d", "-o", str(unpacked), str(packed)],
        check=True,
    )

    match = re.search(rb"NSSCTF\{[^}\r\n]+\}", unpacked.read_bytes())
    if not match:
        raise SystemExit("未找到 NSSCTF flag")

    flag = match.group().decode()
    print(flag)

    result = subprocess.run(
        [str(unpacked)],
        input=f"{flag}\n".encode(),
        capture_output=True,
        check=True,
    )
    if b"Right! Congratulation!" not in result.stdout:
        raise SystemExit("程序校验失败")
    print("校验通过")
```

运行：

```powershell
py -3.11 solve.py .\upx.exe
```

实际输出：

```text
NSSCTF{UPX_c4n_3as1ly_5h3ll_pr0gr4m!}
校验通过
```

## 最终结果

```text
NSSCTF{UPX_c4n_3as1ly_5h3ll_pr0gr4m!}
```
