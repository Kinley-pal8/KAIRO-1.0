---
title: Foot Printing
published: 2025-03-30
description: For My Reference
tags: [Notes]
category: Notes
author: Me
draft: false
---


# 2 - Footprinting

### 1. Enumeration Principles.pdf

**Overview**: This document establishes enumeration as a foundational cybersecurity process, distinct yet complementary to OSINT (Open-Source Intelligence). Enumeration involves gathering information about a target using both active methods (e.g., network scans) and passive methods (e.g., leveraging third-party data), forming a continuous loop where each discovery fuels further investigation.

**Key Concepts**:

- **Definition and Scope**: Enumeration targets domains, IP addresses, accessible services, and other infrastructure components. It’s a dynamic process that builds on itself, unlike OSINT, which is strictly passive and independent.
- **Avoiding Noise**: The document warns against brute-force attacks (e.g., targeting SSH, RDP, or WinRM with common passwords), as they are loud, detectable, and likely to trigger defensive measures like blacklisting. This can halt further testing if the target’s security posture is unknown.
- **Strategic Analogy**: Enumeration is likened to a treasure hunter preparing for an expedition. Rather than digging randomly (akin to brute-forcing), the hunter studies maps, gathers tools, and plans based on terrain knowledge. Similarly, enumeration requires understanding a company’s infrastructure—its services, vendors, and security measures—before acting.

**Guiding Questions**:

- These questions form the backbone of enumeration, encouraging a deeper, reflective approach:
    1. **What can we see?** Identify visible assets (e.g., open ports, subdomains).
    2. **What reasons can we have for seeing it?** Consider why these assets are exposed (e.g., misconfiguration, necessity).
    3. **What image does what we see create for us?** Build a mental model of the infrastructure.
    4. **What do we gain from it?** Assess the value of the information (e.g., potential entry points).
    5. **How can we use it?** Plan exploitation or further enumeration.
    6. **What can we not see?** Hypothesize hidden components (e.g., internal services).
    7. **What reasons can there be that we do not see?** Analyze potential obfuscation or security measures.
    8. **What image results for us from what we do not see?** Infer the unseen structure.

**Practical Application**:

- Imagine enumerating a company’s SSH service. Instead of brute-forcing, you’d first check if it’s publicly accessible, why (e.g., remote admin access), and what it implies (e.g., weak authentication policies). If it’s not visible, consider VPNs or internal networks as reasons, guiding your next steps.

**Takeaway**: Effective enumeration prioritizes comprehension over hasty exploitation. Keep these questions visible (e.g., on a notepad) during testing to maintain focus and uncover both obvious and subtle vulnerabilities.

---

### 2. Enumeration Methodology.pdf

**Overview**: This document introduces a structured yet flexible six-layer methodology for enumeration, applicable to external and internal penetration tests. It addresses the unpredictability of target systems by providing a standardized framework that adapts to diverse environments.

**The Six Layers**:

1. **Internet Presence**: Identify the company’s online footprint (e.g., domains, subdomains, netblocks). Crucial for black-box tests with broad scopes.
2. **Gateway**: Analyze network interfaces, protections (e.g., firewalls), and their locations. More detail is promised in other modules.
3. **Accessible Services**: Examine services (e.g., HTTP, SSH) for their purpose and functionality—central to this module.
4. **Processes**: Investigate how data is processed, identifying sources and targets of tasks.
5. **Privileges**: Assess user permissions and overlooked privileges, especially in complex setups like Active Directory.
6. **OS Setup**: Collect internal OS details (e.g., configurations, security settings) post-access, reflecting admin capabilities.

**Key Insights**:

- **Labyrinth Metaphor**: Penetration testing is like navigating a labyrinth. Each layer is a wall with gaps (vulnerabilities) to find. Some gaps lead nowhere, requiring efficient prioritization within time limits.
- **Dynamic Process**: While the layers are static, their exploration is dynamic, adapting to findings. Tools and commands (e.g., `nmap`, `dig`) are cheat-sheet aids, not the methodology itself.
- **Time Constraints**: Even a four-week test can’t guarantee full coverage. The SolarWinds attack exemplifies how prolonged analysis outstrips short-term assessments.

**Practical Application**:

- **Black-Box Example**: Start with Layer 1 by finding subdomains (e.g., via [crt.sh](http://crt.sh/)). Move to Layer 3 to probe services (e.g., nginx on port 80), then Layer 4 to analyze process interactions (e.g., web app workflows). Adjust based on findings, avoiding rigid steps.

**Takeaway**: Use this methodology as a roadmap, not a checklist. Begin with Internet Presence for external tests, adapt as you progress, and supplement with tool-specific knowledge from cheat sheets.

---

### 3. Domain Information.pdf

**Overview**: This document details passive enumeration of domain-related data to map a company’s online presence, emphasizing stealth to avoid detection.

**Techniques**:

- **Main Website Analysis**: Scrutinize content for technologies (e.g., hosting, IoT) and required infrastructure. Example: An IT firm offering app development likely uses specific frameworks.
- **SSL Certificates**: Extract subdomains from certificates (e.g., `inlanefreight.htb`, `support.inlanefreight.htb`) using tools like [crt.sh](http://crt.sh/). JSON output from `curl -s <https://crt.sh/?q=inlanefreight.com&output=json`> reveals historical subdomains (e.g., `matomo.inlanefreight.com`).
- **Shodan**: Query IPs for open ports and services (e.g., 10.129.27.33 runs OpenSSH on 22, nginx on 80/443). Note SSL versions and Diffie-Hellman parameters for potential weaknesses.
- **DNS Records**: Use `dig any inlanefreight.com` to retrieve:
    - **A Records**: IPs (e.g., 10.129.27.33).
    - **MX Records**: Mail servers (e.g., Google’s, skippable for now).
    - **NS Records**: Name servers, hinting at hosting providers.
    - **TXT Records**: Security configs (e.g., SPF, DMARC).

**Practical Application**:

- For “[inlanefreight.com](http://inlanefreight.com/)”:
    1. Check the website for service clues (e.g., hosting).
    2. Use [crt.sh](http://crt.sh/) to find subdomains like “[smartfactory.inlanefreight.com](http://smartfactory.inlanefreight.com/).”
    3. Query Shodan for 10.129.27.22, noting port 22 (SSH) for later active testing.
    4. Run `dig` to confirm IPs and third-party dependencies (e.g., Google mail).

**Takeaway**: Build a stealthy, comprehensive picture of domain infrastructure using passive tools. Save active probes (e.g., SSH testing) for later, informed by this data.

---

### 4. Cloud Resources.pdf

**Overview**: This document focuses on enumerating cloud resources (AWS, Azure, GCP), highlighting vulnerabilities from misconfigurations despite provider security.

**Techniques**:

- **DNS Lookups**: Identify cloud-hosted IPs (e.g., `s3-website-us-west-2.amazonaws.com` at 10.129.95.250) using `host` commands on subdomain lists.
- **Google Dorks**: Search for exposed files with `inurl:*.amazonaws.com` or `inurl:*.blob.core.windows.net`. Results include PDFs, code, etc.
- **Source Code Analysis**: Inspect website HTML for cloud storage links (e.g., `<link href="s3.amazonaws.com/...">`), offloading content from the main server.
- **GrayHatWarfare**: Filter cloud storage for files (e.g., SSH keys) after initial discovery via Google or DNS.

**Practical Application**:

- For “[inlanefreight.com](http://inlanefreight.com/)”:
    1. Run `for i in $(cat subdomainlist); do host $i | grep "has address"; done` to find `s3-website-us-west-2.amazonaws.com`.
    2. Google `inurl:inlanefreight.amazonaws.com` for PDFs or configs.
    3. Check the site’s source code for S3 references.
    4. Use GrayHatWarfare to explore bucket contents if public.

**Key Insight**: Misconfigured cloud storage (e.g., unauthenticated S3 buckets) is a common weak point, often added to DNS for admin convenience.

**Takeaway**: Combine passive searches (Google, DNS) with specialized tools (GrayHatWarfare) to uncover sensitive cloud assets. Focus on misconfigurations over provider flaws.

---

### 5. Staff.pdf

**Overview**: This document explores enumerating staff data from social media and job postings to infer technologies, infrastructure, and security measures indirectly.

**Techniques**:

- **LinkedIn/Xing**:
    - **Job Posts**: Reveal tech stacks (e.g., Java, Python, Django, SQL databases, Atlassian Suite) and security requirements (e.g., CompTIA Security+).
    - **Profiles**: Skills (e.g., React, Flask) and projects (e.g., CRM apps with Java, Elastic, Kafka) indicate tools in use.
- **GitHub**: Public repos (e.g., OWASP Top 10 for Django) expose coding practices, file naming, and vulnerabilities (e.g., misconfigured JWT secrets).
- **Search Strategy**: Filter LinkedIn by technical roles (e.g., developers, security engineers) to deduce infrastructure and defenses.

**Practical Application**:

- For a target company:
    1. Find a LinkedIn job post requiring Django and Jira. Infer internal web apps and Atlassian tools.
    2. Check an employee’s profile mentioning React and Kafka. Target related systems.
    3. Search GitHub for “companyname django” to find repos with security flaws (e.g., hardcoded secrets).

**Key Insight**: Employees’ public data reflects company tech and priorities. Security-focused staff hint at implemented defenses.

**Takeaway**: Use staff enumeration to build a tech profile passively. Cross-reference with technical findings (e.g., from Domain Info) for a fuller picture.

---

### Practical Guide for Implementation

**Step-by-Step Approach**:

1. **Start with Principles**: Write down the eight guiding questions. Apply them at each stage to maintain focus.
2. **Follow the Methodology**:
    - **Layer 1**: Use Domain Info techniques ([crt.sh](http://crt.sh/), Shodan) to map the Internet Presence.
    - **Layer 3**: Probe services (e.g., nginx, SSH) identified in Shodan or DNS records.
    - Progress deeper as access allows.
3. **Incorporate Cloud and Staff Data**:
    - Check for cloud assets (DNS, Google Dorks) early.
    - Research staff on LinkedIn/GitHub to infer tech stacks and vulnerabilities.
4. **Adapt Dynamically**: Adjust based on findings (e.g., skip brute-forcing if defenses are strong; prioritize misconfigured cloud storage).

**Tool Cheat Sheet**:

- `dig any domain.com`: DNS records.
- `curl -s <https://crt.sh/?q=domain.com&output=json> | jq .`: Subdomains.
- `shodan host IP`: Service details.
- Google Dorks: `inurl:*.amazonaws.com`.
- LinkedIn search: Filter by “software engineer” + company.

---

### Strategic Considerations

- **Stealth**: Prioritize passive methods (OSINT, staff research) to avoid detection initially.
- **Time Management**: Focus on high-value gaps (e.g., public cloud storage) within limited test windows.
- **Holistic View**: Combine technical (domains, cloud) and human (staff) intelligence for comprehensive enumeration.

---

## FTP

### 1. Overview of FTP

- **Definition**: File Transfer Protocol (FTP) is an old Internet protocol for transferring files between a client and a server.
- **Layer**: Operates at the application layer of the TCP/IP stack, alongside HTTP and POP.
- **Tools**: Works with browsers, email clients, or dedicated FTP programs.

### 2. FTP Connection Basics

- **Channels**:
    - **Control Channel**: Established via TCP port 21 for sending commands and receiving status codes.
    - **Data Channel**: Uses TCP port 20 for transferring files, with error checking and resumable transfers.
- **Modes**:
    - **Active FTP**: Client opens control channel (port 21) and specifies a port for the server to send data. Blocked by firewalls if client-side ports are restricted.
    - **Passive FTP**: Server provides a port for the client to initiate the data channel, bypassing firewall issues.

### 3. FTP Commands and Security

- **Commands**: Upload/download files, manage directories, delete files (implementation varies by server).
- **Status Codes**: Server responses indicating command success/failure (e.g., 200, 226).
- **Credentials**: Typically requires username/password; FTP is clear-text (sniffable unless encrypted).
- **Anonymous FTP**: Allows public access without passwords, but with limited permissions due to security risks.

### 4. TFTP (Trivial File Transfer Protocol)

- **Overview**: Simpler than FTP, no authentication, uses UDP (unreliable) instead of TCP.
- **Limitations**: No directory listing, restricted to globally readable/writable files, best for local/protected networks.
- **Commands**: `connect`, `get`, `put`, `quit`, `status`.

### 5. vsftpd (FTP Server on Linux)

- **Installation**: `sudo apt install vsftpd`.
- **Config File**: `/etc/vsftpd.conf` (key settings below; uncomment/edit as needed).
    - `anonymous_enable=NO`: Disables anonymous login.
    - `local_enable=YES`: Allows local users to log in.
    - `write_enable=YES`: Permits file uploads.
    - `chroot_local_user=YES`: Restricts users to their home directories.
    - `hide_ids=YES`: Masks user/group IDs in listings as "ftp" for security.
- **ftpusers File**: `/etc/ftpusers` lists users denied access (e.g., `guest`, `john`).

### 6. Dangerous Settings (Security Risks)

- **Anonymous Access**:
    - `anonymous_enable=YES`: Enables anonymous logins.
    - `anon_upload_enable=YES`: Allows uploads by anonymous users.
    - `no_anon_password=YES`: No password required for anonymous.
- **Risks**: Public access increases vulnerability; use cautiously in controlled environments.

### 7. FTP Interaction Examples

- **Login as Anonymous**:
    
    ```
    ftp> open 10.129.14.136
    Name: anonymous
    230 Login successful.
    
    ```
    
- **List Files**: `ls` (shows files like `Calendar.pptx`, `Clients`).
- **Download**: `get Important Notes.txt`.
- **Upload**: `put testupload.txt`.
- **Recursive Listing**: `ls -R` (shows directory structure).
- **Download All**: `wget -m --no-passive <ftp://anonymous:anonymous@10.129.14.136`>.

### 8. Footprinting with Nmap

- **Basic Scan**: `sudo nmap -sV -p21 -sC -A 10.129.14.136`
    - Detects vsftpd version, anonymous access, and directory contents.
- **Scripts**: Update with `sudo nmap --script-updatedb`.
    - Examples: `ftp-anon.nse` (checks anonymous access), `ftp-syst.nse` (server status).
- **Trace**: `-script-trace` shows detailed command/response flow.

### 9. Secure FTP (TLS/SSL)

- **Check Certificate**: `openssl s_client -connect 10.129.14.136:21 -starttls ftp`.
- **Use Case**: Reveals server details (e.g., organization, location) via SSL certificate.

### 10. Practical Tips

- **Enumeration**: Use FTP logs/files for potential vulnerabilities (e.g., RCE).
- **Security**: Avoid anonymous access on public networks; harden internal servers.
- **Testing**: Set up vsftpd on a VM to experiment with configurations.

---

### Quick Reference

- **Ports**: Control (21), Data (20).
- **Active vs. Passive**: Use passive for firewall compatibility.
- **Config File**: `/etc/vsftpd.conf` for vsftpd settings.
- **Nmap**: `sV -sC -A` for service detection and scripting.
- **Commands**: `ls`, `get`, `put`, `status` for FTP interaction.

---

## SMB

### 1. Overview of SMB

- **Definition**: Server Message Block (SMB) is a client-server protocol for accessing files, directories, printers, and other network resources.
- **Layer**: Application layer protocol in TCP/IP, used primarily in Windows but supported cross-platform via Samba.
- **Purpose**: Enables file/service sharing and inter-process communication over a network.
- **History**: Originated with OS/2 (LAN Manager/Server), evolved with Windows, and extended to Unix/Linux via Samba.

### 2. SMB Connection Basics

- **Protocol**: Uses TCP with a three-way handshake for connection establishment.
- **Ports**:
    - **NetBIOS**: 137-139 (older SMB versions, e.g., SMB 1/CIFS).
    - **Direct SMB**: 445 (modern versions, e.g., SMB 2/3).
- **Shares**: Server exposes parts of its file system as shares, independent of local structure, controlled by Access Control Lists (ACLs).

### 3. SMB Versions

- **CIFS**: Dialect of SMB 1, tied to NetBIOS (ports 137-139), Windows NT 4.0, considered outdated.
- **SMB 1.0**: Windows 2000, direct TCP (port 445).
- **SMB 2.0**: Windows Vista/Server 2008, improved performance.
- **SMB 3.0**: Windows 8/Server 2012, enhanced security/performance, supports encryption.

### 4. Samba (SMB for Unix/Linux)

- **Purpose**: Implements SMB/CIFS for cross-platform compatibility.
- **Features**:
    - Samba v3: Full Active Directory (AD) member.
    - Samba v4: AD domain controller.
- **Daemons**: `smbd` (SMB server), `nmbd` (NetBIOS naming).
- **Config File**: `/etc/samba/smb.conf`.
    - **Global Settings**: Apply to all shares (e.g., `workgroup`, `server role`).
    - **Share Settings**: Override globals (e.g., `path`, `browseable`).

### 5. Default Samba Config Example

- **Global**:
    - `workgroup = DEV.INFREIGHT.HTB`
    - `server role = standalone server`
    - `map to guest = bad user` (unknown users treated as guests).
    - `usershare allow guests = yes`
- **Shares**:
    - `[printers]`: `/var/spool/samba`, not browseable, read-only.
    - `[print$]`: `/var/lib/samba/printers`, browseable, read-only.

### 6. Dangerous Settings (Security Risks)

- **browseable = yes**: Lists shares, exposing structure to attackers.
- **read only = no / writable = yes**: Allows file modification.
- **guest ok = yes**: Permits anonymous access.
- **create mask = 0777 / directory mask = 0777**: Full permissions on new files/directories.
- **enable privileges = yes**: Honors specific security privileges, risky if misconfigured.

### 7. Example Share Config

- `[notes]`:
    - `path = /mnt/notes/`
    - `browseable = yes`
    - `read only = no`
    - `writable = yes`
    - `guest ok = yes`
    - `create mask = 0777`
- **Restart**: `sudo systemctl restart smbd`.

### 8. SMB Enumeration Tools

- **smbclient**:
    - List shares: `smbclient -N -L //10.129.14.128` (anonymous).
    - Connect: `smbclient //10.129.14.128/notes`.
    - Commands: `ls` (list), `get <file>` (download), `!cat <file>` (local command).
- **Nmap**:
    - Scan: `sudo nmap 10.129.14.128 -sV -sC -p139,445`.
    - Output: Version (e.g., Samba 4.6.2), NetBIOS name, security mode.
- **rpcclient**:
    - Connect: `rpcclient -U "" 10.129.14.128`.
    - Queries: `srvinfo` (server info), `enumdomains` (domains), `netshareenumall` (shares), `queryuser <RID>` (user info).
- [**samrdump.py](http://samrdump.py/) (Impacket)**:
    - Usage: `samrdump.py 10.129.14.128`.
    - Output: Domains, users, details (e.g., UID, password last set).
- **smbmap**: `smbmap -H 10.129.14.128` (lists shares, permissions).
- **CrackMapExec**: `crackmapexec smb 10.129.14.128 --shares -u '' -p ''`.
- **enum4linux-ng**:
    - Install: `git clone <repo>; pip3 install -r requirements.txt`.
    - Run: `./enum4linux-ng.py 10.129.14.128 -A` (detailed enumeration).

### 9. Enumeration Examples

- **Shares**: `print$`, `home`, `dev`, `notes`, `IPC$`.
- **Files**: `prep-prod.txt` (downloadable with `get`).
- **Users**: `mrb3n` (RID 0x3e8), `cry011t3` (RID 0x3e9).
- **Brute Force RIDs**: `for i in $(seq 500 1100); do rpcclient -N -U "" 10.129.14.128 -c "queryuser 0x$i"; done`.

### 10. Security Considerations

- **Anonymous Access**: Risks exposure of shares/users, brute-force opportunities.
- **Weak Configs**: Overly permissive settings (e.g., `guest ok`, `0777`) increase attack surface.
- **Monitoring**: Use `smbstatus` to track connections (PID, user, share).

### 11. Practical Tips

- **Testing**: Experiment with Samba configs in a VM.
- **Enumeration**: Combine tools (Nmap for quick scans, smbclient/rpcclient for manual depth).
- **Hardening**: Disable guest access, enforce authentication, limit permissions.

---

### Quick Reference

- **Ports**: 137-139 (NetBIOS), 445 (direct SMB).
- **Config**: `/etc/samba/smb.conf`.
- **Commands**: `ls`, `get`, `queryuser`, `netshareenumall`.
- **Tools**: smbclient, Nmap, rpcclient, smbmap, CrackMapExec, enum4linux-ng.Below are concise notes based on the provided "8 - NFS.pdf" document, designed as a quick reference guide for understanding and working with NFS (Network File System). These notes are organized by key topics for easy guidance, similar to the SMB notes provided earlier.

---

## NFS

### 1. Overview of NFS

- **Definition**: Network File System (NFS) is a distributed file system protocol developed by Sun Microsystems for accessing files over a network as if they were local.
- **Purpose**: Similar to SMB but uses a different protocol, primarily for Linux/Unix systems.
- **Compatibility**: NFS clients cannot directly communicate with SMB servers.
- **Standard**: Internet standard for distributed file systems.
- **Authentication**:
    - **NFS v3**: Authenticates the client computer.
    - **NFS v4**: Requires user authentication, similar to SMB.

### 2. NFS Versions

- **NFS v3**: Long-standing version, client-based authentication.
- **NFS v4**: Enhanced security with user authentication (e.g., Kerberos via `gss/krb5i`).

### 3. NFS Configuration

- **Config File**: Typically `/etc/exports` on the NFS server.
- **Syntax**: Specifies folder, permissions, hosts/subnets, and options.
- **Example**:
    - `/srv/nfs4 gss/krb5i(rw,sync,fsid=0,crossmnt,no_subtree_check)`
    - `/srv/nfs4/homes gss/krb5i(rw,sync,no_subtree_check)`
- **Key Options**:
    - `rw`: Read/write permissions.
    - `ro`: Read-only permissions.
    - `sync`: Synchronous data transfer (safer, slower).
    - `async`: Asynchronous data transfer (faster, riskier).
    - `secure`: Restricts to ports below 1024 (root-only).
    - `insecure`: Allows ports above 1024 (user-accessible, risky).
    - `no_subtree_check`: Disables subtree checking for performance.
    - `root_squash`: Maps root to an unprivileged user (e.g., UID 65534).

### 4. Security Considerations

- **Insecure Option**: Allows ports >1024, enabling non-root users to interact with NFS (dangerous).
- **Root Squash**: Prevents root on the client from having root privileges on the server.
- **Permissions**: Overly permissive settings (e.g., `rw` for all) increase risk.

### 5. Footprinting NFS

- **Ports**:
    - 111 (RPCbind), 2049 (NFS).
- **Tools**:
    - **Nmap**:
        - Basic scan: `sudo nmap 10.129.14.128 -p111,2049 -sV -sC`.
        - Output: RPC services (e.g., `rpcbind`, `nfs`, `nlockmgr`), versions, ports.
        - NFS-specific scan: `sudo nmap --script nfs* 10.129.14.128 -sV -p111,2049`.
        - Output: Share details (e.g., `/mnt/nfs`), permissions, file listings.
- **RPC**: Provides service info (e.g., `rpcbind 2-4`, `nfs 3-4`).

### 6. Mounting NFS Shares

- **Command**: `sudo mount -t nfs 10.129.14.128:/ ./target-NFS/ -o nolock`.
- **Access**: Mounted directory (e.g., `./target-NFS/mnt/nfs`) shows files.
- **Example Output**:
    - Files: `id_rsa`, `id_rsa.pub`, `nfs.share`.
- **Unmounting**: `sudo umount ../target-NFS`.

### 7. File Permissions and Enumeration

- **List with Names**: `ls -l mnt/nfs/` (e.g., `cry0lit3:cry0lit3`, `root:root`).
- **List with IDs**: `ls -n mnt/nfs/` (e.g., UID/GID `1000:1000`, `0:0`).
- **Example**:
    - `rw-r--r-- 1 1000 1000 1872 Sep 25 00:55 cry0lit3.priv`
    - `rw-r--r-- 1 0 0 1872 Sep 19 17:27 id_rsa`
- **Note**: With `root_squash`, root cannot edit files owned by root on the server.

### 8. Privilege Escalation with NFS

- **Scenario**: Access via SSH, need to read files from another user’s directory.
- **Method**: Upload a shell to the NFS share with the target user’s UID, then execute it via SSH.
- **Steps**:
    1. Identify UID/GID from NFS share.
    2. Create matching user locally.
    3. Modify/access files accordingly.

### 9. Practical Tips

- **Enumeration**: Use Nmap to identify shares and permissions, then mount for deeper inspection.
- **Testing**: Experiment with NFS in a controlled environment (e.g., VM).
- **Hardening**: Use `secure`, `root_squash`, and restrict `rw` access to trusted hosts.

### 10. Quick Reference

- **Ports**: 111 (RPC), 2049 (NFS).
- **Config**: `/etc/exports`.
- **Commands**: `mount -t nfs`, `ls -l`, `ls -n`, `umount`.
- **Tools**: Nmap (with `nfs*` scripts).

---

## DNS

### 1. Overview of DNS

- **Definition**: Domain Name System (DNS) translates human-readable domain names (e.g., `www.hackthebox.com`) into IP addresses.
- **Purpose**: Acts like a distributed "phone book" for the Internet, resolving names to IPs without a central database.
- **Structure**: Information is spread across globally distributed DNS servers, handling name resolution hierarchically.

### 2. Types of DNS Servers

- **DNS Root Server**: Manages top-level domains (TLDs) like `.com`, `.org`. Queried as a last resort if other servers fail.
- **Authoritative Name Server**: Holds definitive records for a domain, providing answers to queries about it.
- **Non-Authoritative Name Server**: Responds with cached or forwarded data, not the primary source.
- **Caching Server**: Stores query results temporarily to speed up future requests.
- **Forwarding Server**: Passes queries to other servers instead of resolving them directly.
- **Resolver**: Client-side component that initiates DNS queries (e.g., on your device).

### 3. DNS Configuration (BIND9 Example)

- **Config File**: `/etc/bind/db.domain.com` (zone file for a domain).
- **Zone File Purpose**: Defines a DNS zone (delegation point in the DNS tree) using the BIND format.
- **Key Records**:
    - **SOA (Start of Authority)**: Marks the zone’s start, includes serial, refresh, retry, expire, and TTL (e.g., `86400` = 1 day).
    - **NS (Name Server)**: Lists servers authoritative for the domain (e.g., `ns1.domain.com`).
    - **MX (Mail Exchange)**: Specifies mail servers (e.g., `mx.domain.com` with priority `10`).
    - **A (Address)**: Maps hostname to IPv4 address (e.g., `server1 IN A 10.129.14.5`).
    - **CNAME (Canonical Name)**: Aliases one name to another (e.g., `www IN CNAME server2`).
- **Syntax**: Errors render the zone unusable, resulting in `SERVFAIL` responses.
- **Example**:
    
    ```
    $ORIGIN domain.com
    $TTL 86400
    @ IN SOA dns1.domain.com. hostmaster.domain.com. (2001062501 21600 3600 604800 86400)
    IN NS ns1.domain.com.
    IN A 10.129.14.5
    server1 IN A 10.129.14.5
    www IN CNAME server1
    
    ```
    

### 4. Reverse DNS (PTR Records)

- **Purpose**: Resolves IP addresses to fully qualified domain names (FQDNs).
- **File**: Separate reverse lookup zone file (not fully provided in the PDF).
- **Record**: `PTR` links an IP’s last octet to a hostname (e.g., `5.14.129.10.in-addr.arpa IN PTR server1.domain.com`).

### 5. Footprinting DNS

- **Tools**: `dig` (DNS lookup utility).
- **Queries**:
    - **NS Query**: Lists name servers.
        - Command: `dig ns inlanefreight.htb @10.129.14.128`.
        - Output: `ns.inlanefreight.htb IN A 10.129.34.156`.
    - **Version Query**: Retrieves DNS server version (if configured).
        - Command: `dig CH TXT version.bind @10.129.120.85`.
        - Output: `version.bind CH TXT "9.10.6-P1"`.
    - **ANY Query**: Shows all available records.
        - Command: `dig any inlanefreight.htb @10.129.14.128`.
        - Output: TXT records (e.g., SPF, domain verification), NS, etc.
    - **AXFR (Zone Transfer)**: Dumps entire zone file if allowed.
        - Command: `dig axfr inlanefreight.htb @10.129.14.128`.
        - Output: Full records (e.g., `app.inlanefreight.htb IN A 10.129.18.15`).
        - Internal Example: `dig axfr internal.inlanefreight.htb @10.129.14.128` reveals internal IPs/hostnames.
- **Security Note**: Misconfigured `allow-transfer` (e.g., set to `any`) exposes all zone data.

### 6. Subdomain Enumeration

- **Brute Force**:
    - **Manual**: Loop through a wordlist.
        - Command: `for sub in $(cat subdomains.txt); do dig $sub.inlanefreight.htb @10.129.14.128; done`.
        - Output: Valid subdomains (e.g., `mail.inlanefreight.htb IN A 10.129.18.201`).
    - **Tool**: `dnsenum`.
        - Command: `dnsenum --dnsserver 10.129.14.128 -f subdomains.txt`.
        - Output: Subdomains, NS records, and failed AXFR attempts if restricted.
- **Wordlists**: Use `SecLists` (e.g., `subdomains-top1million-110000.txt`).

### 7. Security Considerations

- **Zone Transfers**: Restrict `allow-transfer` to trusted IPs to prevent data leaks.
- **Internal Records**: Exposed internal IPs (e.g., `10.129.18.x`) indicate poor segmentation.
- **Version Exposure**: Hide `version.bind` to reduce attack surface.

### 8. Practical Tips

- **Enumeration**: Start with NS, ANY, and AXFR queries, then brute-force subdomains.
- **Testing**: Use tools like `dig` or `dnsenum` in a lab to understand responses.
- **Hardening**: Limit zone transfers, obscure server versions, and audit records.

### 9. Quick Reference

- **Port**: 53 (UDP/TCP).
- **Files**: `/etc/bind/db.domain.com` (forward), reverse zone files.
- **Commands**: `dig ns`, `dig any`, `dig axfr`, `dnsenum`.
- **Records**: SOA, NS, A, MX, CNAME, TXT, PTR.

---

## SMTP

### 1. Overview of SMTP

- **Definition**: Simple Mail Transfer Protocol (SMTP) is used to send emails over IP networks.
- **Usage**: Operates between email clients and outgoing mail servers or between SMTP servers.
- **Complementary Protocols**: Often paired with IMAP or POP3 for fetching emails.
- **Model**: Client-server protocol; servers can act as clients when relaying emails.
- **Default Port**: 25 (TCP); newer servers may use 587 for authenticated submissions with STARTTLS.

### 2. SMTP Workflow

- **Process**:
    1. Client (Mail User Agent, MUA) connects to SMTP server.
    2. Authentication (if required) via username/password.
    3. Client sends sender/recipient addresses and email content.
    4. Server (Mail Transfer Agent, MTA) forwards email to recipient’s SMTP server via DNS lookup.
    5. Mail Delivery Agent (MDA) delivers email to recipient’s mailbox.
- **Flow**: MUA → MSA (Mail Submission Agent) → MTA → MDA → Mailbox (POP3/IMAP).
- **Encryption**: Unencrypted by default; uses SSL/TLS (e.g., STARTTLS) for security.

### 3. Key Components

- **MUA**: Mail User Agent (email client).
- **MTA**: Mail Transfer Agent (handles sending/receiving emails).
- **MSA**: Mail Submission Agent (validates email origin, optional relay).
- **MDA**: Mail Delivery Agent (delivers to mailbox).
- **Open Relay**: Misconfigured MTA allowing unauthorized email relaying.

### 4. ESMTP (Extended SMTP)

- **Purpose**: Extends SMTP with features like TLS encryption and authentication.
- **Commands**:
    - `EHLO`: Initiates ESMTP session, lists supported extensions.
    - `STARTTLS`: Upgrades connection to encrypted TLS.
    - `AUTH PLAIN`: Secure authentication method.
- **Common Use**: Referred to as SMTP in modern contexts.

### 5. SMTP Configuration (Postfix Example)

- **Config File**: `/etc/postfix/main.cf`.
- **Key Settings**:
    - `smtpd_banner = ESMTP Server`: Server greeting.
    - `mynetworks = 0.0.0.0/0`: Allows all IPs (risky, enables open relay).
- **Dangerous Setting**: Open relay (`mynetworks = 0.0.0.0/0`) permits spoofing and spam.

### 6. Security Features

- **Authentication**: Prevents unauthorized use (e.g., via `AUTH`).
- **Spam Prevention**:
    - **DomainKeys (DKIM)**: Verifies sender domain.
    - **Sender Policy Framework (SPF)**: Validates sender IP.
    - Suspicious emails quarantined or rejected.
- **TLS**: Encrypts communication post-`STARTTLS`.

### 7. SMTP Disadvantages

- **No Delivery Confirmation**: Protocol supports notifications, but format isn’t standardized (often just error messages).
- **Sender Spoofing**: Lack of default authentication allows fake sender addresses, exploited in open relays.

### 8. Footprinting SMTP

- **Tools**:
    - **Telnet**:
        - Command: `telnet 10.129.14.128 25`.
        - Example: `HELO mail.inlanefreight.htb` → `250 mail.inlanefreight.htb`.
        - `EHLO` lists extensions (e.g., `PIPELINING`, `VRFY`).
        - `VRFY username`: Enumerates users (e.g., `252 2.0.0 root`), though unreliable if misconfigured.
    - **Nmap**:
        - Basic Scan: `sudo nmap 10.129.14.128 -sC -sV -p25`.
            - Output: `25/tcp open smtp Postfix smtpd`, lists commands (e.g., `VRFY`).
        - Open Relay Test: `sudo nmap 10.129.14.128 -p25 --script smtp-open-relay -v`.
            - Output: Confirms open relay (e.g., `16/16 tests` succeeded).
- **Goal**: Identify server version, supported commands, and relay status.

### 9. Open Relay Attack

- **Definition**: Misconfigured SMTP server relays emails from any source.
- **Impact**: Enables spam, spoofing, and phishing.
- **Detection**: Nmap’s `smtp-open-relay` script runs 16 tests (e.g., `MAIL FROM` → `RCPT TO` combinations).
- **Fix**: Restrict `mynetworks` to trusted IPs.

### 10. Email Header

- **Content**: Sender, recipient, timestamps, relay path (per RFC 5322).
- **Access**: Visible to sender/recipient, not required for delivery.
- **Use**: Analyze for spoofing or tracing.

### 11. Practical Tips

- **Enumeration**: Use `telnet` for manual checks, `nmap` for automation.
- **Testing**: Verify `VRFY`, relay status, and encryption support.
- **Hardening**: Enable TLS, restrict relays, disable `VRFY` if unused.

### 12. Quick Reference

- **Ports**: 25 (SMTP), 587 (submission with TLS).
- **Commands**: `HELO`, `EHLO`, `STARTTLS`, `VRFY`, `MAIL FROM`, `RCPT TO`, `QUIT`.
- **Tools**: `telnet`, `nmap` (`smtp-commands`, `smtp-open-relay`).
- **Risks**: Open relays, spoofing, unencrypted data.

---