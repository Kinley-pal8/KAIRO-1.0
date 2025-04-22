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

### 1. Enumeration Principles

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

### 2. Enumeration Methodology

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

### 3. Domain Information

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

### 4. Cloud Resources

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

### 5. Staff

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

## IMAP (Internet Message Access Protocol)

- **Purpose**: Enables online management of emails directly on a mail server.
- **Key Features**:
    - Supports folder structures and hierarchical mailboxes.
    - Allows synchronization across multiple clients, acting like a network file system for emails.
    - Emails remain on the server until explicitly deleted.
    - Text-based protocol using ASCII commands over port 143 (unencrypted) or 993 (SSL/TLS).
- **Functionality**:
    - Clients can create local copies and synchronize changes.
    - Supports offline mode in some clients, syncing changes upon reconnection.
    - Multiple users can access the server simultaneously.
- **Security**:
    - Unencrypted by default, transmitting data in plain text.
    - SSL/TLS encryption recommended, using ports 143 or 993.
- **Commands**:
    - `LOGIN username password`: Authenticate user.
    - `LIST "" *`: List all directories.
    - `CREATE "INBOX"`: Create a mailbox.
    - `DELETE "INBOX"`: Delete a mailbox.
    - `RENAME "ToRead" "Important"`: Rename a mailbox.
    - `LSUB "" *`: List subscribed mailboxes.
    - `SELECT INBOX`: Select a mailbox for access.
    - `UNSELECT INBOX`: Exit selected mailbox.
    - `FETCH <ID> all`: Retrieve message data.
    - `CLOSE`: Remove messages marked as deleted.
    - `LOGOUT`: Close connection.
- **Integration**:
    - SMTP used for sending emails, with sent emails stored in IMAP folders for universal access.
- **Footprinting**:
    - Default ports: 143 (IMAP), 993 (IMAPS).
    - Nmap scan example: `sudo nmap 10.129.14.128 -sV -p143,993 -sC`.
    - Curl for IMAP interaction: `curl -k 'imaps://10.129.14.128' --user user:p4ssw0rd`.
    - OpenSSL for encrypted interaction: `openssl s_client -connect 10.129.14.128:imaps`.

## POP3 (Post Office Protocol 3)

- **Purpose**: Retrieves emails from a mail server, typically deleting them after download.
- **Key Features**:
    - Limited functionality compared to IMAP: lists, retrieves, and deletes emails.
    - Does not support folder structures or server-side management.
- **Security**:
    - Default ports: 110 (unencrypted), 995 (SSL/TLS).
    - Unencrypted by default; SSL/TLS recommended.
- **Commands**:
    - `USER username`: Specify username.
    - `PASS password`: Authenticate with password.
    - `STAT`: Display mailbox status.
    - `LIST`: List messages.
    - `RETR <message>`: Retrieve a message.
    - `DELE <message>`: Delete a message.
    - `QUIT`: Close connection.
- **Footprinting**:
    - Nmap scan example: `sudo nmap 10.129.14.128 -sV -p110,995 -sC`.
    - OpenSSL for encrypted interaction: `openssl s_client -connect 10.129.14.128:pop3s`.

## SNMP (Simple Network Management Protocol)

- **Purpose**: Monitors and manages network devices (routers, switches, servers, IoT devices).
- **Key Features**:
    - Operates over UDP ports 161 (queries) and 162 (traps).
    - Supports configuration tasks and remote setting changes.
    - Uses traps for unsolicited event notifications from devices.
- **Versions**:
    - **SNMPv1**: Basic, no encryption, plain text community strings.
    - **SNMPv2c**: Community-based, no encryption, extended functionality.
    - **SNMPv3**: Enhanced security with authentication and encryption.
- **MIB (Management Information Base)**:
    - Standardized text file listing queryable SNMP objects in a tree hierarchy.
    - Written in ASN.1 ASCII format, contains OIDs (Object Identifiers).
- **OID (Object Identifier)**:
    - Unique numerical address for SNMP objects in a hierarchical namespace.
    - Example: `.1.3.6.1.2.1.1.5.0` for system name.
- **Community Strings**:
    - Act as passwords for access control.
    - Transmitted in plain text in SNMPv1/v2c, vulnerable to interception.
- **Default Configuration**:
    - Example: `/etc/snmp/snmpd.conf` with settings like `rocommunity public default`.
    - Dangerous settings:
        - `rwuser noauth`: Full OID access without authentication.
        - `rocommunity <string> <IPv4>`: Full OID access from specific IP.
- **Footprinting**:
    - Tools:
        - `snmpwalk`: Query OIDs (`snmpwalk -v2c -c public 10.129.14.128`).
        - `onesixtyone`: Brute-force community strings (`onesixtyone -c /path/to/snmp.txt 10.129.14.128`).
        - `braa`: Enumerate OIDs with known community string (`braa public@10.129.14.128:.1.3.6.*`).
    - Example output reveals system details like OS, installed packages, and location.

## Recommendations

- **IMAP/POP3**:
    - Always use SSL/TLS to encrypt connections.
    - Experiment with Dovecot on a VM to understand configurations.
- **SNMP**:
    - Transition to SNMPv3 for enhanced security.
    - Avoid default or weak community strings.
    - Set up a VM to test SNMP configurations and explore MIBs/OIDs.

---

## MySQL

### Overview

- **Definition**: Open-source SQL relational database management system (RDBMS) developed by Oracle.
- **Structure**: Organized collection of data stored in tables with columns, rows, and specific data types.
- **Operation**: Uses SQL for data manipulation; operates on a client-server model.
- **File Extension**: Databases often stored in `.sql` files (e.g., `my_wargress.sql`).
- **MariaDB**: A fork of MySQL created by its original developer post-Oracle acquisition.

### MySQL Clients

- **Function**: Clients interact with the database using SQL queries for inserting, deleting, modifying, and retrieving data.
- **Access**: Possible via internal networks or the public internet.
- **Example Use Case**: WordPress CMS stores posts, usernames, and passwords in a MySQL database, typically accessible only from localhost.

### MySQL Databases

- **Applications**: Ideal for dynamic websites requiring efficient syntax and high response speed.
- **LAMP/LEMP Stack**:
    - **LAMP**: Linux, Apache, MySQL, PHP.
    - **LEMP**: Linux, Nginx, MySQL, PHP.
- **Storage**: Stores content like headers, texts, user information, permissions, and encrypted passwords (using PHP one-way encryption).
- **Security**: Passwords can be stored in plain text but are typically encrypted.

### MySQL Commands

- **Purpose**: SQL commands manage data and database structure (e.g., display, modify, add, delete rows; manage relationships, indexes, users).
- **Error Handling**: Errors from SQL injections may reveal sensitive information about database interactions.

### Default Configuration

- **Installation**:
    
    ```bash
    sudo apt install mysql-server -y
    
    ```
    
- **Config File**: `/etc/mysql/mysql.conf.d/mysqld.cnf`
- **Key Settings**:
    - **Port**: 3306
    - **Socket**: `/var/run/mysqld/mysqld.sock`
    - **User**: `mysql`
    - **Data Directory**: `/var/lib/mysql`
    - **Security-Relevant Settings**:
        - `user`: Defines the MySQL service user.
        - `password`: Sets the MySQL user password (stored in plain text).
        - `admin_address`: IP for administrative connections.
        - `debug`: Debugging settings.
    - **Risks**: Misconfigured permissions on config files can expose credentials, allowing unauthorized access to sensitive data.

### Dangerous Settings

- **Plain Text Credentials**: User, password, and admin_address in config files.
- **Verbose Errors**: Settings like `delay` and `set_warnings` may expose sensitive error details exploitable via SQL injections.
- **External Access**: MySQL servers on TCP port 3306 exposed externally (often temporary or due to misconfiguration).

### Footprinting MySQL

- **Nmap Scan**:
    
    ```bash
    sudo nmap 10.129.14.128 -sV -sC -p3306 --script mysql*
    
    ```
    
    - **Output**: Reveals version, credentials (e.g., `root:<empty>`), and valid usernames.
    - **Caution**: Results (e.g., empty passwords) may be false positives; verify manually.
- **Manual Verification**:
    
    ```bash
    mysql -u root -h 10.129.14.132  # Fails if no password
    mysql -u root -pP4SSw0rd -h 10.129.14.128  # Succeeds with correct password
    
    ```
    
    - **Commands**:
        
        ```sql
        show databases;
        select version();
        
        ```
        

### Key Commands

| Command | Description |
| --- | --- |
| `mysql -u <user> -p<password> -h <ip>` | Connect to MySQL server (no space between `-p` and password). |
| `show databases;` | List all databases. |
| `use <database>;` | Select a database. |
| `show tables;` | List tables in the selected database. |
| `select version();` | Display MySQL version. |

### System Schemas

- **Information Schema**: Contains metadata about databases, per ANSI/ISO standards.
- **System Schema**: Microsoft-specific catalog with extensive system information.

## MSSQL

### Overview

- **Definition**: Microsoft’s closed-source SQL-based RDBMS.
- **Platform**: Primarily for Windows, with versions for Linux and macOS.
- **Integration**: Strong support for .NET framework, popular for Windows-based applications.

### MSSQL Clients

- **SQL Server Management Studio (SSMS)**:
    - Client-side tool for database configuration and management.
    - Can be installed on the server or remote systems.
    - Risk: Systems with SSMS may store saved credentials, exploitable if compromised.

### MSSQL Databases

- **Default System Databases**:
    
    
    | Database | Description |
    | --- | --- |
    | `master` | Stores system information for the SQL Server instance. |
    | `model` | Template for new databases; changes apply to new databases. |
    | `msdb` | Used by SQL Server Agent for job scheduling and alerts. |
    | `tempdb` | Temporary storage for query processing. |

### Dangerous Settings

- **Unencrypted Connections**: Clients not using encryption to connect to the server.
- **Self-Signed Certificates**: Can be spoofed if used for encryption.
- **Named Pipes**: Vulnerable to exploitation.
- **Weak/Default Credentials**: Default `sa` account may be left enabled with weak passwords.
- **Windows Authentication**: Uses OS credentials (SAM or Active Directory), risking privilege escalation if compromised.

### Footprinting MSSQL

- **Nmap Scan**:
    
    ```bash
    sudo nmap --script ms-sql-info,ms-sql-empty-password,ms-sql-xp-cmdshell,ms-sql-config -p1433 10.129.201.248
    
    ```
    
    - **Output**: Reveals instance name, version (e.g., Microsoft SQL Server 2019), named pipes, and port (1433).
- **Metasploit MSSQL Ping**:
    
    ```bash
    msf6 auxiliary(scanner/mssql/mssql_ping) > set rhosts 10.129.201.248
    msf6 auxiliary(scanner/mssql/mssql_ping) > run
    
    ```
    
    - **Output**: Confirms server name, instance, version, and port.

### Connecting to MSSQL

- **Tool**: `mssqlclient.py` from Impacket.
- **Command**:
    
    ```bash
    python3 mssqlclient.py Administrator@10.129.201.248 -windows-auth
    
    ```
    
    - **Output**: Lists databases (e.g., `master`, `tempdb`, `model`, `msdb`, `Transactions`).
- **T-SQL Interaction**: Use Transact-SQL for querying databases.

### Notes

- **Authentication**: Windows Authentication uses OS credentials, which can be audited but risks escalation if accounts are compromised.
- **Best Practice**: Set up MSSQL in a VM to explore default configurations and potential misconfigurations.

## General Security Considerations

- **SQL Injections**: Can exploit verbose error messages or misconfigured settings to execute system commands.
- **Credential Management**: Avoid plain-text storage; use encryption and strong passwords.
- **Network Exposure**: Limit external access to database ports (3306 for MySQL, 1433 for MSSQL).
- **Configuration Files**: Secure permissions to prevent unauthorized access to sensitive settings.
- **Footprinting**: Use tools like Nmap and Metasploit to identify vulnerabilities, but verify results to avoid false positives.

---

## Intelligent Platform Management Interface (IPMI)

### Overview

- **Definition**: Standardized specifications for hardware-based system management, operating independently of the host’s BIOS, CPU, firmware, and OS.
- **Functionality**: Enables remote management and monitoring (e.g., system temperature, voltage, fan status, power supplies) even when the system is powered off or unresponsive.
- **Use Cases**:
    - Modify BIOS settings before OS boot.
    - Manage systems when powered down.
    - Access hosts post-system failure.
- **Operation**: Uses a direct network connection to hardware, not requiring OS login.
- **Components**:
    - **Baseboard Management Controller (BMC)**: Core microcontroller.
    - **Intelligent Chassis Management Bus (ICMB)**: Inter-chassis communication interface.
    - **Intelligent Platform Management Bus (IPMB)**: Extends BMC functionality.
    - **IPMI Memory**: Stores system event logs and repository data.
    - **Communication Interfaces**: Local, serial, LAN, ICMB, and PCI Management Bus.
- **Vendors**: Supported by over 200 vendors (e.g., Cisco, Dell, HP, Supermicro, Intel).
- **IPMI v2.0**: Supports serial over LAN for viewing console output.

### Footprinting

- **Port**: Communicates over UDP/623.
- **BMC Implementation**: Embedded ARM systems running Linux, connected to the motherboard or added via PCI card.
- **Common BMCs**: HP iLO, Dell DRAC, Supermicro IPMI.
- **Risk**: BMC access grants near-physical control (monitor, reboot, power off, reinstall OS).
- **Nmap Scan**:
    
    ```bash
    sudo nmap -sU --script ipmi-version -p 623 ilo.inlanefreight.local
    
    ```
    
    - **Output**: Identifies IPMI v2.0, user authentication methods, and MAC address.
- **Metasploit**:
    
    ```bash
    msf6 > use auxiliary/scanner/ipmi/ipmi_version
    msf6 auxiliary(scanner/ipmi/ipmi_version) > set rhosts 10.129.42.195
    msf6 auxiliary(scanner/ipmi/ipmi_version) > run
    
    ```
    
    - **Output**: Confirms version and settings.

### Security Risks

- **Hash Dumping**:
    - Metasploit module: `auxiliary/scanner/ipmi/ipmi_dumphashes`.
    - Command:
        
        ```bash
        msf6 > use auxiliary/scanner/ipmi/ipmi_dumphashes
        msf6 auxiliary(scanner/ipmi/ipmi_dumphashes) > set rhosts 10.129.42.195
        msf6 auxiliary(scanner/ipmi/ipmi_dumphashes) > run
        
        ```
        
    - Hashes can be cracked offline using Hashcat (mode 7300).
    - HP iLO default password attack:
        
        ```bash
        hashcat -m 7300 <hash> -a 3 ?u?u?u?u?u?u?u?u
        
        ```
        
- **Vulnerabilities**:
    - Weak/default passwords (e.g., factory defaults).
    - Password reuse across systems (e.g., BMC password reused for SSH or web consoles).
    - No direct fix for hash exposure (IPMI specification flaw).
- **Mitigation**:
    - Use long, complex passwords.
    - Implement network segmentation to restrict BMC access.

## Oracle Transparent Network Substrate (TNS)

### Overview

- **Definition**: Communication protocol for Oracle databases and applications, part of Oracle Net Services.
- **Supported Protocols**: TCP/IP, IPX/SPX, with SSL/TLS encryption.
- **Industries**: Healthcare, finance, retail.
- **Features**:
    - Name resolution, connection management, load balancing, security.
    - Encrypts client-server communication over TCP/IP.
    - Provides performance monitoring, error logging, workload management, and fault tolerance.

### Default Configuration

- **Listener Port**: TCP/1521 (configurable).
- **Supported Protocols**: TCP/IP, UDP, IPX/SPX, AppleTalk.
- **Configuration Files**:
    - **tnsnames.ora**: Client-side, resolves service names to network addresses.
        
        ```
        ORCL =
          (DESCRIPTION =
            (ADDRESS_LIST =
              (ADDRESS = (PROTOCOL = TCP)(HOST = 10.129.11.102)(PORT = 1521))
            )
            (CONNECT_DATA =
              (SERVER = DEDICATED)
              (SERVICE_NAME = orcl)
            )
          )
        
        ```
        
    - **listener.ora**: Server-side, defines listener process properties.
        
        ```
        SID_LIST_LISTENER =
          (SID_LIST =
            (SID_DESC =
              (SID_NAME = PDB1)
              (ORACLE_HOME = C:\oracle\product\19.0.0\dbhome_1)
              (GLOBAL_DBNAME = PDB1)
            )
          )
        LISTENER =
          (DESCRIPTION_LIST =
            (DESCRIPTION =
              (ADDRESS = (PROTOCOL = TCP)(HOST = orcl.inlanefreight.htb)(PORT = 1521))
              (ADDRESS = (PROTOCOL = IPC)(KEY = EXTPROC1521))
            )
          )
        
        ```
        
- **Security Features**:
    - Accepts connections from authorized hosts.
    - Basic authentication (hostname, IP, username/password).
    - Encrypts communication via Oracle Net Services.
- **Default Passwords**:
    - Oracle 9i: `CHANGE_ON_INSTALL`.
    - Oracle DbSNMP: `dbmsnp`.
- **PLS/SQL Exclusion List**: Blacklists packages/types from execution, stored in `$ORACLE_HOME/sqldevelop`.

### Footprinting and Enumeration

- **Setup Tools**:
    
    ```bash
    #!/bin/bash
    sudo apt-get install libaio1 python3-dev alien -y
    git clone https://github.com/quentinhardy/odat.git
    cd odat/
    git submodule init
    git submodule update
    wget https://download.oracle.com/otn_software/linux/instantclient/2112000/instantclient-basic-linux.x64-21.12.0.0.0dbru.zip
    unzip instantclient-basic-linux.x64-21.12.0.0.0dbru.zip
    wget https://download.oracle.com/otn_software/linux/instantclient/2112000/instantclient-sqlplus-linux.x64-21.12.0.0.0dbru.zip
    unzip instantclient-sqlplus-linux.x64-21.12.0.0.0dbru.zip
    export LD_LIBRARY_PATH=instantclient_21_12:$LD_LIBRARY_PATH
    export PATH=$LD_LIBRARY_PATH:$PATH
    pip3 install cx_Oracle
    sudo apt-get install python3-scapy -y
    sudo pip3 install colorlog termcolor passlib python-libnmap
    sudo apt-get install build-essential libgmp-dev -y
    pip3 install pycryptodome
    
    ```
    
- **Test ODAT**:
    
    ```bash
    ./odat.py -h
    
    ```
    
- **SID Brute-Forcing**:
    
    ```bash
    sudo nmap -p 1521 --script oracle-sid-brute 10.129.204.235
    
    ```
    
- **SQLplus Login**:
    
    ```bash
    sqlplus scott/tiger@10.129.204.235/XE
    
    ```
    
    - **Error Fix** (if `libclntsh.so` missing):
        
        ```bash
        sudo sh -c "echo /usr/lib/oracle/12.2/client64/lib > /etc/ld.so.conf.d/oracle-instantclient.conf"
        
        ```
        
- **Enumeration Commands**:
    
    ```sql
    select table_name from all_tables;
    select * from user_role_privs;
    
    ```
    
- **Sysdba Login**:
    
    ```bash
    sqlplus scott/tiger@10.129.204.235/XE as sysdba
    
    ```
    

### Exploitation

- **File Upload**:
    
    ```bash
    ./odat.py utlfile -s 10.129.204.235 -d XE -U scott -P tiger --sysdba --putFile C:\\inetpub\\wwwroot testing.txt
    
    ```
    
    - **Verify**:
        
        ```bash
        curl -X GET http://10.129.204.235/testing.txt
        
        ```
        
- **Risks**:
    - Default/weak passwords (e.g., `scott/tiger`).
    - Misconfigured listener exposing services.
    - Unpatched vulnerabilities in older Oracle versions.

## Linux Remote Management Protocols

### Secure Shell (SSH)

### Overview

- **Definition**: Encrypted protocol for secure remote connections over TCP/22.
- **Compatibility**: Native on Linux, macOS; available on Windows with tools.
- **Versions**:
    - **SSH-1**: Vulnerable to MITM attacks.
    - **SSH-2**: Improved encryption, speed, stability, security.
- **Authentication Methods**:
    - Password, public-key, host-based, keyboard, challenge-response, GSSAPI.
- **Public-Key Authentication**:
    - **Process**: Server sends certificate; client uses private key to solve cryptographic challenge.
    - **Keys**:
        - Private key: Stored locally, secured with passphrase.
        - Public key: Stored on server.
    - **Benefit**: Single passphrase for multiple server connections per session.

### Default Configuration

- **File**: `/etc/ssh/sshd_config`.
- **Settings**:
    
    ```bash
    Include /etc/ssh/sshd_config.d/*.conf
    ChallengeResponseAuthentication no
    UsePAM yes
    X11Forwarding yes
    PrintMotd no
    AcceptEnv LANG LC_*
    Subsystem sftp /usr/lib/openssh/sftp-server
    
    ```
    
- **Note**: Most settings commented out, requiring manual configuration.

### Dangerous Settings

| Setting | Description |
| --- | --- |
| `PasswordAuthentication yes` | Enables brute-forcing passwords. |
| `PermitEmptyPasswords yes` | Allows empty passwords. |
| `PermitRootLogin yes` | Permits root login. |
| `Protocol 1` | Uses outdated encryption. |
| `X11Forwarding yes` | Enables GUI forwarding (past vulnerabilities). |
| `AllowTcpForwarding yes` | Allows TCP port forwarding. |
| `DebianBanner yes` | Displays login banner. |

### Footprinting

- **Tool**: `ssh-audit`.
    
    ```bash
    git clone https://github.com/jtesta/ssh-audit.git
    cd ssh-audit
    ./ssh-audit.py 10.129.14.132
    
    ```
    
    - **Output**: Banner, software version (e.g., OpenSSH 8.2p1), encryption algorithms.
- **Verbose SSH**:
    
    ```bash
    ssh -v cry0l1t3@10.129.14.132
    
    ```
    
    - **Output**: Shows authentication methods (e.g., publickey, password, keyboard-interactive).
- **Force Password Authentication**:
    
    ```bash
    ssh -v cry0l1t3@10.129.14.132 -o PreferredAuthentications=password
    
    ```
    

### Rsync

### Overview

- **Definition**: Tool for efficient file copying, locally or remotely, over TCP/873.
- **Features**:
    - Delta-transfer algorithm: Sends only file differences.
    - Used for backups and mirroring.
    - Can use SSH for secure transfers.
- **Risk**: Misconfigured shares may allow unauthorized access.

### Footprinting

- **Nmap Scan**:
    
    ```bash
    sudo nmap -sV -p 873 127.0.0.1
    
    ```
    
    - **Output**: Confirms Rsync protocol version (e.g., 31).
- **Probe Shares**:
    
    ```bash
    nc -nv 127.0.0.1 873
    
    ```
    
    - **Output**: Lists shares (e.g., `dev`).
- **Enumerate Share**:
    
    ```bash
    rsync -av --list-only rsync://127.0.0.1/dev
    
    ```
    
    - **Output**: Lists files (e.g., `build.sh`, `secrets.yaml`, `.ssh` directory).
- **Sync Files**:
    
    ```bash
    rsync rsync://127.0.0.1/dev .
    
    ```
    
    - **With SSH**:
        
        ```bash
        rsync -e ssh rsync://127.0.0.1/dev .
        
        ```
        

### R-Services

### Overview

- **Definition**: Suite of insecure remote access services for Unix, replaced by SSH.
- **Ports**: TCP/512 (rexec), TCP/513 (rlogin), TCP/514 (rsh).
- **Commands**:
    
    
    | Command | Daemon | Port | Description |
    | --- | --- | --- | --- |
    | `rcp` | `rshd` | 514 | Remote file copy. |
    | `rsh` | `rshd` | 514 | Remote shell access. |
    | `rexec` | `rexecd` | 512 | Remote command execution. |
    | `rlogin` | `rlogind` | 513 | Remote login. |
    | `rwho` | `rwhod` | 513/UDP | Lists logged-in users. |
    | `rusers` | `rusersd` | 513/UDP | Detailed user information. |
- **Security Flaw**: Unencrypted communication, vulnerable to MITM attacks.

### Configuration Files

- **/etc/hosts.equiv**:
    
    ```
    pwnbox cry0l1t3
    
    ```
    
    - Lists trusted hosts/users for automatic access.
- **.rhosts**:
    
    ```
    htb-student 10.0.17.5
    htb-student 10.0.17.10
    htb-student +
    
    ```
    
    - Wildcard (`+`) allows any external user to access as `htb-student`.

### Footprinting

- **Nmap Scan**:
    
    ```bash
    sudo nmap -sV -p 512,513,514 10.0.17.2
    
    ```
    
    - **Output**: Identifies open ports/services (e.g., `exec`, `login`, `tcpwrapped`).
- **Rlogin**:
    
    ```bash
    rlogin 10.0.17.2 -l htb-student
    
    ```
    
    - Exploits misconfigured `.rhosts` for unauthenticated access.
- **Rwho**:
    
    ```bash
    rwho
    
    ```
    
    - Lists authenticated users (e.g., `htb-student` on `workstn01`).
- **Rusers**:
    
    ```bash
    rusers -al 10.0.17.5
    
    ```
    
    - Provides detailed user information (e.g., login time, TTY).

### General Security Considerations

- **IPMI**:
    - Restrict BMC access via network segmentation.
    - Avoid default/weak passwords; monitor for password reuse.
- **Oracle TNS**:
    - Use strong passwords and SSL/TLS encryption.
    - Regularly update Oracle software to patch vulnerabilities.
    - Restrict listener access to authorized hosts.
- **SSH**:
    - Disable `PasswordAuthentication` and use public-key authentication.
    - Disable `PermitRootLogin` and `PermitEmptyPasswords`.
    - Use SSH-2 and strong encryption algorithms.
- **Rsync**:
    - Require authentication for shares.
    - Use SSH for secure transfers.
- **R-Services**:
    - Avoid use due to inherent insecurities.
    - If necessary, restrict access via `hosts.equiv` and `.rhosts` with specific IPs/users.
- **General**:
    - Regularly audit configurations and credentials.
    - Use network monitoring to detect unauthorized access.
    - Apply least privilege principles for all services.

---

## Windows Remote Management Protocols Notes

Windows servers can be managed locally or remotely using tools like Server Manager. Remote management, enabled by default since Windows Server 2016, is part of Windows hardware management features, including WS-Management protocol, hardware diagnostics, and baseboard management controllers. A COM API and script objects allow remote communication via WS-Management.

**Main Components**:

- Remote Desktop Protocol (RDP)
- Windows Remote Management (WinRM)
- Windows Management Instrumentation (WMI)

## Remote Desktop Protocol (RDP)

### Overview

- **Definition**: Microsoft-developed protocol for remote access to Windows systems, transmitting GUI display and control commands over IP networks.
- **Layer**: Operates at the application layer of the TCP/IP model.
- **Ports**: Typically uses TCP/3389; UDP/3389 for connectionless remote administration.
- **Encryption**: Supports Transport Layer Security (TLS) since Windows Vista, but some systems allow weaker RDP Security.
- **Certificates**: Uses self-signed certificates by default, which may trigger warnings as clients cannot verify authenticity.
- **Requirements**:
    - Network and server firewalls must allow external connections.
    - For NAT environments, port forwarding and the server’s public IP are needed.
- **Default Configuration**: Installed on Windows servers, activated via Server Manager, and set to allow connections only with Network Level Authentication (NLA).

### Footprinting

- **Purpose**: Identifies NLA status, product version, and hostname.
- **Nmap Scan**:
    
    ```bash
    nmap -sV -sC 10.129.201.248 -p3389 --script rdp*
    
    ```
    
    - **Output**:
        - Confirms Microsoft Terminal Services on port 3389.
        - Security layers: CredSSP (NLA), CredSSP with Early User Auth, RDSTLS.
        - NTLM info: Target Name, NetBIOS/DNS names (ILF-SQL-01), Product Version (10.0.17763), System Time.
        - OS: Windows; CPE: cpe:/o:microsoft:windows.
- **Packet Trace**:
    
    ```bash
    nmap -sV -sC 10.129.201.248 -p3389 --packet-trace --disable-arp-ping -n
    
    ```
    
    - **Output**: Tracks packets, showing probes like TerminalServerCookie. Note: RDP cookies may be detected by EDR systems, potentially blocking scans.
- **RDP Security Check**:
    
    ```bash
    ./rdp-sec-check.pl 10.129.201.248
    
    ```
    
    - **Output**:
        - Protocols: PROTOCOL_HYBRID (CredSSP with NLA) supported; PROTOCOL_RDP and PROTOCOL_SSL not supported (HYBRID_REQUIRED_BY_SERVER).
        - Encryption: No support for ENCRYPTION_METHOD_NONE, 40BIT, 56BIT, 128BIT, or FIPS.

### Connection

- **Tools** (Linux): xfreerdp, rdesktop, Remmina for GUI interaction.
- **Command**:
    
    ```bash
    xfreerdp /u:cry0l1t3 /p:"P455w0rD!" /v:10.129.201.248
    
    ```
    
    - **Output**: Loads channels (rdpsdr, rdpsnd, cliprdr), establishes connection, and creates crypto directories for certificates.

### Security Risks

- Weak encryption if TLS is not enforced.
- Self-signed certificates enable man-in-the-middle (MITM) attacks.
- Exposed RDP services vulnerable to brute-force attacks if NLA is disabled.

### Mitigation

- Enforce NLA and TLS for all connections.
- Use strong, unique credentials.
- Restrict RDP access via firewall rules or VPN.
- Monitor for unusual login attempts.

## Windows Remote Management (WinRM)

### Overview

- **Definition**: Protocol for remote management of Windows systems using HTTP/HTTPS.
- **Ports**: TCP/5985 (HTTP), TCP/5986 (HTTPS); typically HTTP used.
- **Purpose**: Executes commands and manages configurations remotely.

### Footprinting

- **Nmap Scan**:
    
    ```bash
    nmap -sV -sC 10.129.201.248 -p5985,5986 --disable-arp-ping -n
    
    ```
    
    - **Output**:
        - Port 5985 open, running Microsoft HTTPAPI/2.0 (SSDP/UPnP).
        - HTTP title: "Not found"; server header: Microsoft-HTTPAPI/2.0.
        - OS: Windows; CPE: cpe:/o:microsoft:windows.
- **PowerShell**:
    
    ```powershell
    Test-WSMan -ComputerName 10.129.201.248
    
    ```
    
    - Verifies WinRM accessibility.
- **Evil-WinRM** (Linux):
    
    ```bash
    evil-winrm -i 10.129.201.248 -u cry0l1t3 -p P455w0rD!
    
    ```
    
    - **Output**: Establishes a PowerShell session, landing in the user’s Documents directory.

### Security Risks

- Unencrypted HTTP (5985) exposes credentials and commands.
- Weak or reused credentials vulnerable to brute-forcing.
- Misconfigured WinRM may allow unauthorized access.

### Mitigation

- Use HTTPS (5986) with strong certificates.
- Restrict WinRM access to specific IPs or via VPN.
- Implement strong authentication and monitor logs.

## Windows Management Instrumentation (WMI)

### Overview

- **Definition**: Microsoft’s implementation of the Common Information Model (CIM), part of Web-Based Enterprise Management (WBEM).
- **Functionality**: Provides read/write access to most Windows settings, critical for administration and remote maintenance.
- **Access**: Via PowerShell, VBScript, or Windows Management Instrumentation Console (WMIC).
- **Components**: Multiple programs and databases (repositories).

### Footprinting

- **Port**: Initializes on TCP/135, then switches to a random port.
- **Tool**: wm.exec.py (Impacket):
    
    ```bash
    /usr/share/doc/python3-impacket/examples/wm.exec.py cry0l1t3:"P455w0rD!"@10.129.201.248
    
    ```
    
    - **Output**: Uses SMBv3.0, connects to ILF-SQL-01, confirming WMI access.

### Security Risks

- Exposed WMI services allow extensive system control if credentials are compromised.
- Random port usage complicates firewall rules.
- Weak credentials increase risk of unauthorized access.

### Mitigation

- Restrict WMI access to authorized IPs.
- Use strong credentials and enable auditing.
- Limit WMI permissions to least privilege.

## General Security Considerations

- **Experimentation**: Set up a Windows Server VM to test configurations and scan results for hands-on experience.
- **Common Mitigations**:
    - Enforce strong encryption (TLS, HTTPS) for all protocols.
    - Use complex, unique credentials and avoid reuse.
    - Implement network segmentation and firewall rules to limit access.
    - Regularly audit configurations and monitor for suspicious activity.
- **Tool Usage**:
    - Nmap for service enumeration and vulnerability scanning.
    - Evil-WinRM and Impacket for exploitation and testing.
    - PowerShell for native Windows management and verification.
- **Risks**:
    - Exposed services (RDP, WinRM, WMI) are prime targets for attackers.
    - Default or weak configurations increase vulnerability to brute-force and MITM attacks.