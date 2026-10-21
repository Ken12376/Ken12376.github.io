---
title: "静默行动：HTTP 请求头检查链"
date: "2026-09-12"
categories: "Web"
tags: ["HTTP", "请求头", "访问控制"]
excerpt: "逐步完成方法、来源头、User-Agent、Referer、JSON 与 Cookie 的六段检查。"
slug: "web-silent-operation"
source_event: "HDCTF"
---

> 复现材料：`题目 HTTP 服务`。赛题附件未随文章打包。 本文日期取自原始题解文件的修改日期。 认证材料已改为环境变量，复现时从自己的赛题环境注入。

入口给了行动代号 `operation-blue`，要求 POST 到 `/hdctf_archive`，form 参数 `codename`。之后每页解锁一段提示，共六步，全是 HTTP 方法 / 请求头检查。

## 流程

1. `POST /hdctf_archive`，form `codename=operation-blue`。档案页提示内网接口只认回环地址，要靠请求头声明来源。
2. `GET /hdctf_internal`，带 `X-Forwarded-For: 127.0.0.1`（`X-Real-IP` 同理）。过白名单后提示客户端必须是 PRTS 官方终端。
3. `GET /hdctf_terminal`，`User-Agent: PRTS`。之后要求从任务列表页 `/intel/list` 跳转进入。
4. `GET /hdctf_mission`，`Referer: https://challenge.example.invalid/intel/list`。拿到归档要求：JSON POST 到 `/hdctf_report`。
5. `POST /hdctf_report`，`Content-Type: application/json`，body `{"operator":"doctor","task":"operation-blue","priority":3}`。归档成功给出令牌 `$CTF_COOKIE_TOKEN`，提示夹进 Cookie。
6. `GET /hdctf_classified`，`Cookie: token=$CTF_COOKIE_TOKEN`，返回 flag。

每一步失败时页面都会明说缺什么：`/hdctf_internal` 用 POST 会回 `405` 并带 `Allow: GET`；JSON 没发对会回 `400`，把收到的内容原样打印出来，等于把正确答案写脸上。

## 解题脚本

```python
import json
import os
import re
import urllib.request

HOST = 'https://challenge.example.invalid'


def req(method, path, headers=None, data=None):
    request = urllib.request.Request(
        HOST + path, method=method, headers=headers or {}, data=data)
    with urllib.request.urlopen(request, timeout=30) as resp:
        return resp.read().decode()


req('POST', '/hdctf_archive',
    headers={'Content-Type': 'application/x-www-form-urlencoded'},
    data=b'codename=operation-blue')
req('GET', '/hdctf_internal',
    headers={'X-Forwarded-For': '127.0.0.1', 'X-Real-IP': '127.0.0.1'})
req('GET', '/hdctf_terminal', headers={'User-Agent': 'PRTS'})
req('GET', '/hdctf_mission', headers={'Referer': HOST + '/intel/list'})
req('POST', '/hdctf_report',
    headers={'Content-Type': 'application/json'},
    data=json.dumps({"operator": "doctor",
                     "task": "operation-blue",
                     "priority": 3}).encode())
flag_page = req('GET', '/hdctf_classified',
                headers={"Cookie": "token=" + os.environ["CTF_COOKIE_TOKEN"]})
print(re.search(r'HDCTF\{[^}]+\}', flag_page).group())
```

## 最终结果

```text
HDCTF{f6487474-247d-eeb9-74c8-6b572fd990b5}
```

根因小结：这题没有漏洞，考点是把 HTTP 的基础元素逐个过一遍——方法、form、来源伪造头、UA、Referer、JSON、Cookie。反面教材是：拿可伪造的请求头做访问控制等于没有，内网校验得绑定真实链路信息。
