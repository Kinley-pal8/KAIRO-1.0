---
title: Password Attack
published: 2022-08-01
description: Study Material
tags: [Example, Notes]
category: Examples
draft: false
---

# Password Attack

## Theory of Protection and Authentication

### 1. Core Principles of Information Security (Infosec)

- **Confidentiality, Integrity, Availability (CIA Triad):**
    - These are the foundation of an Infosec practitioner's role.
    - Balance is maintained through:
        - **Accounting:** Auditing and tracking files, objects, and hosts.
        - **Authorization:** Ensuring users have correct permissions.
        - **Authentication:** Validating user identity before granting access.
    - Breaches often result from failing to uphold one of these tenets.

### 2. Focus: Authentication

- **Definition:** Validation of identity using a combination of factors.
- **Three Main Authentication Factors:**
    1. **Something You Know:** Password, PIN, passphrase.
    2. **Something You Have:** ID card, security key, multi-factor authentication (MFA) tools.
    3. **Something You Are:** Biometrics (fingerprint, facial recognition), username, email.
- **Examples:**
    - Doctors: Common Access Card (CAC) + PIN/password + authenticator app (all 3 factors).
    - Email: Email address + password + 2FA (e.g., phone or biometrics).
- **Process:**
    - Correct authentication (e.g., password) → Authorization (permissions granted).

### 3. Passwords: The Most Common Authentication Method

- **Definition:** A string of letters, numbers, and symbols for identity validation (e.g., "TreeDogEvilElephant").
- **Complexity Example:**
    - 8-digit password with uppercase letters + numbers = 36 characters → 208,827,084,576 combinations.
- **Key Considerations:**
    - Must meet organizational security standards.
    - Balance between security and convenience is critical (complexity can frustrate users).
- **User Experience (UX):**
    - Simple authentication (e.g., username + password) speeds up processes like online shopping.

### 4. Password Statistics (PardaSecurity & Google)

- **Common Weak Passwords:**
    - 24% of Americans use "password," "Qwerty," or "123456."
    - 22% use their name.
    - 35% use pet or children’s names.
- **Password Reuse:**
    - 66% reuse passwords across multiple accounts → If one password is compromised, others are vulnerable.
- **Post-Breach Behavior:**
    - Only 45% change passwords after a breach; 55% keep compromised passwords.
- **Implication for Attackers:**
    - Guess common passwords + user IDs (often easy to find) → High success rate due to reuse.

### 5. Checking Breaches

- **Tool:** HaveIBeenPwned (website)
    - Enter email → See list of breaches involving that email.

### 6. Next Steps (from Document)

- Explore how passwords/credentials are stored and how attackers bypass authentication.

---

### Key Takeaways

- Authentication is critical to security but often the weakest link due to poor password practices.
- Use strong, unique passwords and enable MFA to reduce risks.
- Password reuse and weak choices (e.g., "123456") make systems vulnerable.
- Regularly check for breaches (e.g., via HaveIBeenPwned) and update passwords.

---

## Credential Storage and Authentication Mechanisms in Linux and Windows

## Overview

Credential storage and authentication mechanisms are critical components of system security. This note summarizes how credentials are stored, managed, and authenticated in Linux and Windows systems, along with potential vulnerabilities.

## **Credential Storage in Linux**

1. **Password Storage:**
    - Linux stores user passwords in an encrypted format using a file called the **shadow file** (`/etc/shadow`).
    - The shadow file is part of the Linux user management system and contains information such as:
        - **Username**
        - **Encrypted password (hash)**
        - **Day of last password change**
        - **Password expiration details**
2. **Shadow File Format Example:**
    
    `texthtb-student:$y$j9T$3QSBB6CbHEu...SNIP...f8Ms:18955:0:99999:7:::`
    
    - `$<id>$<salt>$<hashed>` represents the cryptographic hash method, salt, and hashed password.
3. **Common Hash Algorithms Used:**
    - `$1$` → MD5
    - `$5$` → SHA-256
    - `$6$` → SHA-512
    - `$y$` → Yescrypt (modern systems)
4. **Other Files in Linux User Management:**
    - `/etc/passwd`: Contains user account information but no passwords (replaced by shadow file for security).
    - `/etc/group`: Manages group memberships.
5. **Security Concerns:**
    - If the shadow file permissions are misconfigured, attackers can manipulate it to bypass authentication.
    - Storing passwords in plain text (e.g., as seen in historical cases like RockYou) is a critical vulnerability.

## **Credential Storage in Windows**

1. **Authentication Process Overview:**
    - Windows authentication involves multiple components, including:
        - **WinLogon**: Manages user logins and launches LogonUI for password entry.
        - **LSASS (Local Security Authority Subsystem Service)**: Handles security policies, user authentication, and audit logs.
        - **SAM Database**: Stores local user credentials in hashed format.
2. **Key Components of Windows Authentication:**
    - **LSASS Modules**:
        - `Msv1_0.dll`: Handles local logins.
        - `Kerberos.dll`: Used for Kerberos-based authentication.
        - `Samsrv.dll`: Manages the SAM database.
    - **SAM Database**:
        - Located at `%SystemRoot%/system32/config/SAM`.
        - Stores passwords as LM or NTLM hashes.
        - Requires SYSTEM-level permissions to access.
    - **Domain Authentication**:
        - For domain-joined systems, credentials are validated against the Active Directory database (`ntds.dit`).
3. **Credential Manager:**
    - Allows users to save credentials for network resources and websites.
    - Credentials are encrypted and stored in:
        
        `textC:\Users\[Username]\AppData\Local\Microsoft\[Vault/Credentials]\`
        
4. **NTDS.dit File:**
    - Found on Domain Controllers; stores Active Directory data, including:
        - User accounts (username & password hash)
        - Group accounts
        - Group policies
    - This file is synchronized across Domain Controllers for centralized management.
5. **Security Features:**
    - SYSKEY encryption helps protect the SAM database from offline attacks by encrypting password hashes.

## Common Vulnerabilities

1. **Linux Vulnerabilities:**
    - SQL injection attacks on web applications can expose plaintext credentials if databases are not properly secured.
    - Misconfigured permissions on `/etc/shadow` can allow unauthorized access or manipulation.
2. **Windows Vulnerabilities:**
    - LSASS memory dumps can be exploited to extract credentials during attacks.
    - Improper handling of SAM or NTDS.dit files can lead to credential theft.

## Key Takeaways

- Always store passwords in hashed and salted formats using secure algorithms like SHA-512 or Yescrypt.
- Ensure proper permission settings for sensitive files like `/etc/shadow` (Linux) or `SAM`/`NTDS.dit` (Windows).
- Use additional security measures like SYSKEY encryption (Windows) to prevent offline attacks.
- Regularly audit systems to detect misconfigurations or vulnerabilities that could expose credentials.

---

## John the Ripper (JTR)

### Overview

- **Definition**: John the Ripper (JTR or "John") is an open-source password cracking tool used to test password strength and recover encrypted/hashed passwords.
- **Purpose**: Primarily used by security professionals for penetration testing ("pentesting").
- **Initial Release**: 1996, originally developed for UNIX-based systems.
- **Recommended Variant**: "Jumbo" version – includes performance optimizations, multilingual wordlists, and 64-bit architecture support for faster and more accurate cracking.

### Key Features

- **Attack Methods**:
    1. **Dictionary Attacks**: Uses pre-generated wordlists (e.g., from public dictionaries or leaked passwords) to match hashed passwords.
    2. **Brute Force Attacks**: Tries every possible character combination; slow but exhaustive.
    3. **Rainbow Table Attacks**: Uses pre-computed hash tables for faster cracking, limited by table size and hash coverage.
- **Supported Hash Formats**: Extensive list including UNIX crypt(3), DES, MD5, Blowfish, SHA-crypt, Windows LM, Kerberos, and more.
- **File Conversion**: Tools like `pdf2john`, `rar2john`, etc., convert various file types into crackable hash formats.
- **Regular Updates**: Continuously updated to adapt to modern security trends.

### Encryption Technologies Supported

| Encryption Type | Description | Key Size |
| --- | --- | --- |
| UNIX crypt(3) | Traditional UNIX encryption | 56-bit |
| DES-based | Data Encryption Standard algorithm | 56-bit |
| bigcrypt | Extended DES-based | 128-bit |
| BSDI extended DES | Extension of DES | 168-bit |
| FreeBSD MD5-based | MD5 algorithm | 128-bit |
| OpenBSD Blowfish-based | Blowfish algorithm | 448-bit |
| Windows LM | LAN Manager hash | 56-bit |
| SHA-crypt | SHA-based (Fedora, Ubuntu) | 256-bit |
| SHA-crypt + SUNMD5 (Solaris) | Combines SHA and MD5 | 256-bit |

### Cracking Modes

1. **Single Crack Mode**:
    - **Type**: Brute-force using a single password list.
    - **Syntax**: `john --format=<hash_type> <hash_file>`
    - **Example**: `john --format=sha256 hashes_to_crack.txt`
    - **Pros**: Simple and straightforward.
    - **Cons**: Slow for complex passwords; depends on list quality.
2. **Wordlist Mode**:
    - **Type**: Dictionary attack with multiple wordlists.
    - **Syntax**: `john --wordlist=<wordlist_file> --rules <hash_file>`
    - **Features**: Applies rules (e.g., appending numbers, capitalizing) to generate variations.
    - **Pros**: Faster than brute force with good wordlists.
    - **Cons**: Limited by wordlist comprehensiveness.
3. **Incremental Mode**:
    - **Type**: Hybrid attack generating combinations from a character set.
    - **Syntax**: `john --incremental <hash_file>`
    - **Features**: Starts with short combinations, incrementally increases length; customizable character sets.
    - **Pros**: Highly effective for weak passwords.
    - **Cons**: Resource-intensive; slow for complex passwords.

### Cracking Files

- **Process**: Use auxiliary tools to extract hashes from encrypted files, then crack with John.
- **Syntax Example**:
    
    ```
    pdf2john server_doc.pdf > server_doc.hash
    john --wordlist=wordlist.txt server_doc.hash
    
    ```
    
- **Supported Tools**:
    - `pdf2john`: PDFs
    - `ssh2john`: SSH keys
    - `rar2john`: RAR archives
    - `zip2john`: ZIP files
    - `office2john`: MS Office documents
    - Full list via: `locate *2john*`

### Practical Usage

- **Command Breakdown**:
    - `john`: Runs the program.
    - `-format=<hash_type>`: Specifies hash type (e.g., sha256, md5).
    - `<hash_file>`: File containing hashes to crack.
- **Output**: Cracked passwords saved to `~/john/john.pot`; progress checked with `john --show`.
- **Tips**:
    - Use comprehensive, updated wordlists and rules.
    - Adjust character sets in Incremental Mode for special characters.

### Password Security Recommendations

- Use complex, unique passwords (min. 8 characters, mix of letters/numbers/symbols).
- Change passwords regularly.
- Enable two-factor authentication (2FA).

### Key Takeaways

- **Strengths**: Versatile, supports numerous hash types, customizable attack modes.
- **Limitations**: Success depends on password complexity, wordlist quality, and computational resources.
- **Applications**: Essential for security audits and understanding encryption vulnerabilities.

---

## Network Services and Penetration Testing Tools

### Overview of Network Services

- **Definition**: Services installed on computer networks to manage, edit, or create content, each assigned specific permissions and users.
- **Common Services**: Include FTP, IMAP/POP3, RDP, SMB, SSH, WinRM, SMTP, NFS, MySQL/MSSQL, VNC, LDAP, and more.
- **Purpose**: Facilitate remote access, command execution, and content management (GUI or terminal).
- **Authentication**: Typically username/password-based; can be configured for key-based access.

### Key Services for Remote Management

1. **Windows Systems**:
    - **RDP (Remote Desktop Protocol)**: Common for GUI access.
    - **WinRM (Windows Remote Management)**: For remote management via command-line.
    - **SSH**: Less common on Windows, but available.
2. **Linux Systems**:
    - **SSH**: Primary service for secure remote access.

### Windows Remote Management (WinRM)

- **Definition**: Microsoft’s implementation of WS-Management protocol using SOAP over HTTP/HTTPS.
- **Function**: Manages communication between WBEM and WMI, interfacing with DCOM.
- **Ports**: TCP 5985 (HTTP), 5986 (HTTPS).
- **Security**: Requires manual activation/configuration in Windows 10; supports certificates and specific authentication methods.
- **Tool**: CrackMapExec for password attacks and protocol interaction.

### CrackMapExec (CME)

- **Purpose**: A versatile pentesting tool for network protocols (MSSQL, SMB, SSH, WinRM).
- **Installation**:
    - Via `apt` on Parrot OS: `sudo apt-get -y install crackmapexec`
    - Alternative: `sudo apt-get -y install netexec` or clone from GitHub.
- **Usage**:
    - General: `crackmapexec <protocol> <target-IP> -u <user/userlist> -p <password/passwordlist>`
    - Example: `crackmapexec winrm 10.129.42.197 -u user.list -p password.list`
    - SMB Shares: `crackmapexec smb 10.129.42.197 -u "user" -p "password" --shares`
- **Options**:
    - `h`: Help menu.
    - `t THREADS`: Set concurrent threads (default: 100).
    - `-verbose`: Enable detailed output.
    - Protocol-specific help: `crackmapexec <protocol> -h` (e.g., `crackmapexec smb -h`).
- **Output**: Successful logins initiate a PowerShell Remoting Protocol (MS-PSRP) session.

### Secure Shell (SSH)

- **Purpose**: Securely connect to remote hosts for command execution or file transfer.
- **Port**: TCP 22 (default).
- **Cryptography**:
    1. **Symmetric Encryption**: Uses a single key (e.g., AES, Blowfish, 3DES) with Diffie-Hellman key exchange.
    2. **Asymmetric Encryption**: Public/private key pair; private key decrypts messages encrypted by the public key.
    3. **Hashing**: Ensures message authenticity (one-way mathematical function).
- **Brute Force Tool**: Hydra.
    - Command: `hydra -L user.list -P password.list ssh://10.129.42.197`
    - Notes: Limited parallel tasks recommended due to SSH configurations.
- **Client**: OpenSSH (default on Linux).
    - Command: `ssh user@10.129.42.197`

### Remote Desktop Protocol (RDP)

- **Purpose**: Remote access to Windows systems via GUI.
- **Port**: TCP 3389 (default).
- **Functionality**: Supports image/sound transfer, keyboard/mouse input, printing, and storage access.
- **Protocol**: Application layer; uses TCP/UDP.
- **Brute Force Tool**: Hydra.
    - Command: `hydra -L user.list -P password.list rdp://10.129.42.197`
    - Notes: Experimental module; reduce tasks (e.g., `t 4`) to avoid connection issues.
- **Client**: XFreeRDP (Linux).
    - Command: `xfreerdp /v:10.129.42.197 /u:user /p:password`
    - Certificate prompt requires confirmation.

### Server Message Block (SMB)

- **Purpose**: File sharing and resource access on Windows networks.
- **Port**: TCP 445 (default).
- **Brute Force Tools**:
    1. **Hydra**:
        - Command: `hydra -L user.list -P password.list smb://10.129.42.197`
        - Issue: Older versions may fail with SMBv3; update or use alternatives.
    2. **Metasploit Framework**:
        - Command: `msfconsole -q`
        - Setup:
            
            ```
            use auxiliary/scanner/smb/smb_login
            set user_file user.list
            set pass_file password.list
            set rhosts 10.129.42.197
            run
            
            ```
            
        - Output: Success indicated by valid credentials.
- **Client**: smbclient.
    - Command: `smbclient -U user \\\\\\\\10.129.42.197\\\\SHARENAME`
    - Functionality: List contents (`ls`), upload/download files based on privileges.

### Tools Summary

| Tool | Protocols Supported | Key Command Example | Notes |
| --- | --- | --- | --- |
| CrackMapExec | MSSQL, SMB, SSH, WinRM | `crackmapexec smb 10.129.42.197 -u user -p pass` | Multi-protocol, versatile |
| Hydra | SSH, RDP, SMB, etc. | `hydra -L user.list -P pass.list ssh://10.129.42.197` | Brute forcing; update for SMBv3 |
| Metasploit | SMB, others via modules | `use auxiliary/scanner/smb/smb_login; run` | Framework with extensive modules |
| smbclient | SMB | `smbclient -U user \\\\\\\\10.129.42.197\\\\SHARENAME` | File share interaction |
| XFreeRDP | RDP | `xfreerdp /v:10.129.42.197 /u:user /p:pass` | Linux RDP client |
| OpenSSH | SSH | `ssh user@10.129.42.197` | Default Linux SSH client |

### Key Takeaways

- **Service Selection**: Choose based on OS (e.g., SSH for Linux, RDP/WinRM for Windows).
- **Security**: Default configs are vulnerable; enhance with keys/certificates.
- **Pentesting**: Tools like CrackMapExec, Hydra, and Metasploit are essential for credential testing and exploitation.
- **Practical Use**: Combine brute forcing with client tools for access and interaction.

---

[Untitled](Password%20Attack%201bad813d6e428096a333f24fc9d7fefb/Untitled%201bad813d6e4281a8b438dbbb0b810fc7.csv)