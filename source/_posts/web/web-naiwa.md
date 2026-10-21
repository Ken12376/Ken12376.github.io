---
title: "奶娃：从 502 故障到后台恢复"
date: "2026-10-07"
categories: "Web"
tags: ["PHP-FPM", "nginx", "配置修复"]
excerpt: "沿 nginx 日志定位 PHP-FPM 配置问题，恢复后端服务，再访问后台读取题目结果。"
slug: "web-naiwa"
source_event: "0xGame"
---

> 整理自原有本地题解，保留原始结论，未在此次归档中重新运行赛题。复现材料：`题目 HTTP/SSH 服务`。赛题附件未随文章打包。 实例地址已替换；认证材料以环境变量表示，个人信息已隐去。

## 思路概览

题面给了临时 SSH 值班账号。站点外部表现为 `502 Bad Gateway`，根因不是漏洞利用入口，而是博客的 PHP-FPM 被服务守护脚本按配置拒绝启动：`service.ini` 仍处于 recovery/maintenance 状态。修复配置并重启 PHP-FPM 后，登录后台即可读取 flag。

## 解题过程

### Step 1: 先看日志定位 502 根因

访问首页时返回 nginx 502：

```bash
curl -i https://challenge.example.invalid/
```

SSH 登录题面给的值班账号：

```bash
ssh -p 22146 $CTF_SSH_USER@challenge.example.invalid
# password: $CTF_SSH_PASSWORD
```

日志直接说明 nginx 转发到 PHP-FPM socket 失败：

```bash
tail -n 80 /srv/naiwa/logs/error.log
```

关键报错：

```text
connect() to unix:/run/php/php-fpm.sock failed (2: No such file or directory) while connecting to upstream
```

继续看配置和服务脚本：

```bash
cat /srv/naiwa/config/service.ini
cat /usr/local/sbin/php-fpm-service
sudo /usr/local/sbin/service php-fpm status
```

原始配置是：

```ini
[service]
mode = recovery
maintenance = on
listen = 127.0.0.1:8088
secret_backend = disabled
```

而 `/usr/local/sbin/php-fpm-service` 只有在以下条件同时满足时才会启动 PHP-FPM 并写入 `ready` 状态：

```text
mode=production
maintenance=off
listen=0.0.0.0:80
secret_backend=enabled
```

### Step 2: 修复服务配置并重启 PHP-FPM

只需要改配置，不需要改业务代码：

```bash
cp /srv/naiwa/config/service.ini /srv/naiwa/config/service.ini.bak.$(date +%Y%m%d%H%M%S)
cat > /srv/naiwa/config/service.ini <<'EOF'
[service]
mode = production
maintenance = off
listen = 0.0.0.0:80
secret_backend = enabled

[notes]
owner = naiwa
last_incident = archive worker lost its public route after a sleepy restart
EOF

sudo /usr/local/sbin/service php-fpm restart
sudo /usr/local/sbin/service php-fpm status
```

修复后状态：

```text
php-fpm is running
mode=production
maintenance=off
listen=0.0.0.0:80
secret_backend=enabled
runtime=ready
```

外部验证：

```bash
curl -s https://challenge.example.invalid/api/status.php
```

返回：

```json
{
  "runtime": "ready",
  "ready": true,
  "gateway": "alive",
  "archive_backend": "online",
  "operator_note": "archive route restored"
}
```

### Step 3: 登录后台读取秘密抽屉

源码里可以看到后台口令：

```bash
grep -n "adminPassword" /var/www/html/login.php
```

```php
$adminPassword = getenv('CTF_ADMIN_PASSWORD');
```

使用 `admin / $CTF_ADMIN_PASSWORD` 登录 `/login.php`，再访问 `/admin.php`：

```bash
BASE='https://challenge.example.invalid'
COOKIE=/tmp/naiwa_cookie.txt
curl -s -c "$COOKIE" -b "$COOKIE" -X POST "$BASE/login.php" \
  --data "username=admin&password=$CTF_ADMIN_PASSWORD" -i | grep -E 'HTTP/|Location|Set-Cookie'
curl -s -b "$COOKIE" "$BASE/admin.php" | grep -o '0xGame{[^<]*}'
```

输出：

```text
0xGame{82151eab-f3eb-49fb-98bc-142f01c23619}
```

## 最终结果

```text
0xGame{82151eab-f3eb-49fb-98bc-142f01c23619}
```
