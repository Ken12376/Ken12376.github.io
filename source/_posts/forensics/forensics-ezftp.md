---
title: "ezftp：FTP 断点续传与备份恢复"
date: "2026-10-07"
categories: "Forensics"
tags: ["PCAP", "FTP", "ZIP", "Office"]
excerpt: "从流量中重组中断后续传的 ZIP，沿加密说明和花名册规则恢复备份内容。"
slug: "forensics-ezftp"
source_event: "0xGame"
---

> 整理自原有本地题解，保留原始结论，未在此次归档中重新运行赛题。复现材料：`ftp_incident.pcap`。赛题附件未随文章打包。 日期取自原始题解文件的修改日期。 实例地址已替换；认证材料以环境变量表示，个人信息已隐去。

## 结论

- 目标服务器：`192.0.2.1`，服务横幅为 `FileZilla Server 1.8.2` / `backup.example.invalid`。
- 真正的数据下载会话来自 `192.0.2.2`，使用 FTP 明文凭据 `$CTF_FTP_USER / $CTF_FTP_PASSWORD`。
- `backup.zip` 第一次下载到 7300 字节后中断，随后使用 `REST 7300` 断点续传，需要拼接两段 FTP data stream。
- Flag：`0xGame{e2717ba6-a1dc-4171-a741-bc89be5d7b2e}`

## 1. 流量初筛

题目只给了一个流量包：

```text
ftp_incident.pcap
SHA256: 6BE196DBA8DDB37D22B4AB4280C09F86BB3D9FA46EE4FDF48FDF4815F48B63D1
```

PCAP 的链路层类型是 `LINKTYPE_IPV4`，包内容从 IPv4 头开始。按 `192.0.2.3` 过滤后，可以看到多次 FTP 登录尝试：

```text
192.0.2.4 -> 192.0.2.1  多次弱口令尝试，均失败
192.0.2.5 -> 192.0.2.1  guest / $CTF_GUEST_PASSWORD public/brochure.pdf
192.0.2.2 -> 192.0.2.1  $CTF_FTP_USER / $CTF_FTP_PASSWORD，下载 readme.zip、roster.xlsx、backup.zip
```

关键控制流如下：

```text
USER $CTF_FTP_USER
PASS $CTF_FTP_PASSWORD
230 Logged on
TYPE I
SIZE readme.zip      -> 213 565
EPSV                 -> 40501
RETR readme.zip

SIZE roster.xlsx     -> 213 15360
EPSV                 -> 40502
RETR roster.xlsx

SIZE backup.zip      -> 213 14673
EPSV                 -> 40503
RETR backup.zip
426 Connection closed; transfer aborted.

# 后续断点续传
SIZE backup.zip      -> 213 14673
EPSV                 -> 40510
REST 7300
RETR backup.zip
226 Successfully transferred "/backup.zip"
```

## 2. 恢复 FTP 文件

FTP 使用被动模式，文件内容在独立 TCP data stream 中传输：

| 文件 | 数据连接 | 恢复长度 | 说明 |
|---|---:|---:|---|
| `readme.zip` | `192.0.2.6 -> 192.0.2.7` | 565 | 完整 |
| `roster.xlsx` | `192.0.2.8 -> 192.0.2.9` | 15360 | 完整，Office 加密 |
| `backup_part0.bin` | `192.0.2.10 -> 192.0.2.11` | 7300 | 第一次下载前半段 |
| `backup_part1.bin` | `192.0.2.12 -> 192.0.2.13` | 7373 | `REST 7300` 后续传内容 |

拼接方式：

```python
backup = backup_part0 + backup_part1
assert len(backup) == 14673
open("backup.zip", "wb").write(backup)
```

恢复出的关键文件校验：

```text
readme.zip   size=565    sha256=fdc01ac52bb7c5ee450e8b147b0ff08ccd834e6dac22baef6358adab695323e6
roster.xlsx  size=15360  sha256=1f7048c4c17bdcb7c5a9f12fa0518842fa8e649bc05d238703f7dd19daeb2cc0
backup.zip   size=14673  sha256=2dae83947b02785ec9fd85a68ed238afc102331c1c2a4b18ef91976501c0eacf
```

## 3. 解密线索

`readme.zip` 是传统 Zip 加密。用流量中出现过的弱口令列表测试，`$CTF_README_PASSWORD` 可以解开 `README.md`。

`README.md` 给出关键规则：

```text
backup.zip 密码规则：维护人的工号(大写) + 入职年月(YYYYMM)
roster.xlsx 加密口令与运维 FTP 登录口令相同
```

因此先使用 FTP 明文口令 `$CTF_FTP_PASSWORD` 解密 `roster.xlsx`：

```python
import msoffcrypto
import os

with open("roster.xlsx", "rb") as f, open("roster_decrypted.xlsx", "wb") as out:
    office = msoffcrypto.OfficeFile(f)
    office.load_key(password=os.environ["CTF_FTP_PASSWORD"])
    office.decrypt(out)
```

读取花名册后，按规则尝试 `工号 + 入职年月`。命中运维部员工：

```text
工号：$CTF_EMPLOYEE_ID
姓名：[个人信息已隐去]
部门：运维部
入职年月：$CTF_HIRE_MONTH
backup.zip 密码：$CTF_ARCHIVE_PASSWORD
```

## 4. 获取 Flag

用 `$CTF_ARCHIVE_PASSWORD` 解开拼接后的 `backup.zip`：

```python
import zipfile
import os

with zipfile.ZipFile("backup.zip") as z:
    data = z.read("flag.txt", pwd=os.environ["CTF_ARCHIVE_PASSWORD"].encode())
    print(data.decode())
```

输出：

```text
本次例行备份的校验信息如下：
0xGame{e2717ba6-a1dc-4171-a741-bc89be5d7b2e}
请勿泄露。
```

## 5. 本地验证结果

```text
backup.zip testzip: None
flag.txt size=107 sha256=f9f1343ae7db94ec4f11027355aa76b6470eb974f624dd754760de6ec921aef7
```

最终答案：

```text
0xGame{e2717ba6-a1dc-4171-a741-bc89be5d7b2e}
```
