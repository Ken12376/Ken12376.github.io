---
title: "命运石之门：AES-CBC 明文伪造"
date: "2026-10-07"
categories: "Crypto"
tags: ["AES-CBC", "明文伪造"]
excerpt: "检查点只有明文的九个固定字节；利用赛题公开材料构造满足条件的明文，再重新加密。"
slug: "crypto-steins-gate"
source_event: "0xGame"
---

> 复现材料：`时间线.py`。赛题附件未随文章打包。 认证材料已改为环境变量，复现时从自己的赛题环境注入。

## 思路概览

题目给出的 `时间线.py` 会解密用户提交的 `c2`，只检查解密后 256 字节明文中 9 个固定偏移是否等于指定字符。源码同时暴露了 AES-CBC 的 `KEY` 和 `IV`，因此不需要恢复原文，只要伪造一个满足条件的明文并重新加密即可触发 `get_flag`。

## 解题过程

### Step 1: 伪造满足检查的明文

`时间线.py` 的关键逻辑如下：

- `c2 = b64decode(input(...), validate=True)`，要求解码后长度为 256。
- `m2 = AES.new(KEY, AES.MODE_CBC, IV).decrypt(c2)`。
- 只检查 `m2[8] == 'U'`、`m2[30] == 'l'` 等 9 个字节。
- AES-CBC 没有 MAC，也没有检查明文语义；已知 `KEY` / `IV` 后可以选择任意 256 字节 `m2`，填上这 9 个条件字节，再加密成合法 `c2`。

完整脚本如下，使用 Windows/PowerShell 自带的 .NET AES，无需额外 Python 依赖：

```powershell
param(
    [string]$HostName = $env:CTF_HOST,
    [int]$Port = 38497
)

$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [Text.Encoding]::UTF8

function ConvertFrom-Hex([string]$Hex) {
    $bytes = [byte[]]::new($Hex.Length / 2)
    for ($i = 0; $i -lt $bytes.Length; $i++) {
        $bytes[$i] = [Convert]::ToByte($Hex.Substring($i * 2, 2), 16)
    }
    return $bytes
}

$key = ConvertFrom-Hex $env:CTF_AES_KEY_HEX
$iv = ConvertFrom-Hex $env:CTF_AES_IV_HEX
$conditions = @{8=85; 30=108; 41=50; 63=122; 67=115; 91=75; 104=103; 122=90; 143=52}

$m2 = [byte[]]::new(256)
foreach ($position in $conditions.Keys) {
    $m2[[int]$position] = [byte]$conditions[$position]
}

$aes = [Security.Cryptography.Aes]::Create()
$aes.Mode = [Security.Cryptography.CipherMode]::CBC
$aes.Padding = [Security.Cryptography.PaddingMode]::None
$aes.Key = $key
$aes.IV = $iv
$c2 = $aes.CreateEncryptor().TransformFinalBlock($m2, 0, $m2.Length)
$payload = [Convert]::ToBase64String($c2) + "`n"

$client = [Net.Sockets.TcpClient]::new($HostName, $Port)
try {
    $client.ReceiveTimeout = 5000
    $stream = $client.GetStream()
    $payloadBytes = [Text.Encoding]::ASCII.GetBytes($payload)
    Start-Sleep -Milliseconds 300
    $stream.Write($payloadBytes, 0, $payloadBytes.Length)

    $buffer = [byte[]]::new(4096)
    Start-Sleep -Milliseconds 500
    while (($count = $stream.Read($buffer, 0, $buffer.Length)) -gt 0) {
        [Text.Encoding]::UTF8.GetString($buffer, 0, $count)
        if (-not $stream.DataAvailable) {
            Start-Sleep -Milliseconds 300
            if (-not $stream.DataAvailable) { break }
        }
    }
}
finally {
    $client.Close()
}
```

### Step 2: 运行结果

```powershell
PS> .\solve.ps1
c2.encode('base64')=0xGame{th15 15 my v1ct0ry}
```

## 最终结果

```text
0xGame{th15 15 my v1ct0ry}
```
