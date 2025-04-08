---
title: Nmap
published: 2025-03-26
description: For My Reference
tags: [Notes]
category: Notes
author: Me
draft: false
---

# 1 - Nmap

### **Nmap Cheat Sheet**

### **1. Overview of Nmap**

- **What is Nmap?**: Network Mapper, an open-source tool for network discovery, port scanning, and security auditing.
- **Purpose**: Identify live hosts, open ports, services, operating systems, and vulnerabilities.
- **Basic Syntax**: `nmap [scan types] [options] [target]`
  - Example: `nmap -sS 192.168.1.1`
- **Privilege Note**: Many scans (e.g., SYN, UDP) require root privileges (`sudo`).

---

### **2. Target Specification**

- **Single IP**: `nmap 192.168.1.1`
- **Multiple IPs**: `nmap 192.168.1.1 192.168.1.2`
- **IP Range**: `nmap 192.168.1.1-10`
- **CIDR Notation**: `nmap 192.168.1.0/24`
- **From File**: `nmap -iL targets.txt`
  - File format: One IP or hostname per line (e.g., `192.168.1.1`, `10.10.10.10`).
- **Random Targets**: `nmap -iR 10` (scans 10 random hosts).
- **Exclude Targets**: `nmap 192.168.1.0/24 --exclude 192.168.1.1`
- **Exclude from File**: `nmap 192.168.1.0/24 --excludefile exclude.txt`

**Tip**: Use `nmap -sL <targets>` to list targets without scanning (dry run).

---

### **3. Host Discovery Options**

- **Purpose**: Identify live hosts before port scanning.
- **Disable Port Scanning**: `sn` (ping scan only).
  - Example: `sudo nmap -sn 192.168.1.0/24`
- **ICMP Echo Request**: `PE` (ping with ICMP echo).
  - Example: `sudo nmap -PE 192.168.1.1`
- **ICMP Timestamp**: `PP` (checks if host responds to timestamp requests).
- **ICMP Netmask**: `PM` (requests subnet mask).
- **TCP SYN Ping**: `PS<ports>` (sends SYN to specified ports).
  - Example: `sudo nmap -PS22,80 192.168.1.1`
- **TCP ACK Ping**: `PA<ports>` (sends ACK to specified ports).
- **UDP Ping**: `PU<ports>` (sends UDP packets).
  - Example: `sudo nmap -PU53 192.168.1.1`
- **ARP Ping**: Default for local networks; disable with `-disable-arp-ping`.
- **No Ping**: `Pn` (assumes all hosts are up; skips discovery).
  - Example: `nmap -Pn 192.168.1.1`

**Tip**: Combine methods (e.g., `-PE -PS22`) if firewalls block ICMP.

---

### **4. Port Scanning Techniques**

- **TCP SYN Scan**: `sS` (stealthy, default for root users).
  - SYN → SYN-ACK (open), RST (closed), no reply (filtered).
  - Example: `sudo nmap -sS 192.168.1.1`
- **TCP Connect Scan**: `sT` (full handshake; default for non-root).
  - Example: `nmap -sT 192.168.1.1`
- **UDP Scan**: `sU` (slower, checks UDP ports).
  - Reply (open), ICMP unreachable (closed), no reply (open|filtered).
  - Example: `sudo nmap -sU 192.168.1.1`
- **TCP Null Scan**: `sN` (no flags set).
  - No reply (open/filtered), RST (closed).
- **TCP FIN Scan**: `sF` (FIN flag set).
- **TCP Xmas Scan**: `sX` (FIN, PSH, URG flags set).
- **TCP ACK Scan**: `sA` (checks firewall rules; unfiltered if RST received).
- **TCP Window Scan**: `sW` (analyzes TCP window size in RST packets).
- **TCP Maimon Scan**: `sM` (FIN/ACK combo; rare use).
- **Idle Scan**: `sI <zombie host>` (uses a “zombie” to hide source IP).
  - Example: `sudo nmap -sI 192.168.1.2 192.168.1.1`
- **IP Protocol Scan**: `sO` (checks supported protocols like ICMP, TCP).
- **FTP Bounce Scan**: `b <FTP relay host>` (uses FTP server to scan).

**Tip**: Use `-sS` for stealth, `-sU` for UDP services (e.g., DNS, DHCP).

---

### **5. Port Specification**

- **All Ports**: `p-` (scans 0-65535).
  - Example: `sudo nmap -p- 192.168.1.1`
- **Specific Ports**: `p <port>` or `p <port1,port2>`.
  - Example: `nmap -p 22,80,443 192.168.1.1`
- **Port Range**: `p <start-end>`.
  - Example: `nmap -p 1-100 192.168.1.1`
- **Top Ports**: `-top-ports=<n>` (scans most common ports).
  - Example: `nmap --top-ports=10 192.168.1.1`
- **Fast Scan**: `F` (top 100 ports).
  - Example: `nmap -F 192.168.1.1`

**Tip**: Start with `-F` for speed, then `-p-` for thoroughness.

---

### **6. Service and Version Detection**

- **Service Detection**: `sV` (identifies service names and versions).
  - Example: `sudo nmap -sV 192.168.1.1`
    - Output: `445/tcp open microsoft-ds Samba smbd 3.X-4.X`.
- **Intensity Level**: `-version-intensity <0-9>` (0=light, 9=try all probes).
  - Example: `sudo nmap -sV --version-intensity 9 192.168.1.1`
- **All Probes**: `A` (includes -sV, OS detection, traceroute, scripts).
  - Example: `sudo nmap -A 192.168.1.1`
- **Service Debugging**: `-version-trace` (shows service detection steps).

**Tip**: Use `-sV` to pinpoint exploitable software versions.

---

### **7. OS Detection**

- **OS Fingerprinting**: `O` (guesses OS and version via TCP/IP stack).
  - Example: `sudo nmap -O 192.168.1.1`
    - Output: `Running: Linux 4.X`.
- **Aggressive OS Guess**: `-osscan-guess` (more speculative guesses).
- **Limit OS Guesses**: `-osscan-limit` (only if ports are favorable).

**Tip**: Combine `-O -sV` for a full system profile.

---

### **8. Timing and Performance**

- **Timing Templates**: `T<0-5>` (0=paranoid, 5=insane).
  - `T0`: Very slow, stealthy.
  - `T3`: Default.
  - `T5`: Fast, noisy.
  - Example: `nmap -T4 192.168.1.1` (aggressive but balanced).
- **Parallel Scans**: `-min-parallelism <n>` (minimum threads).
  - Example: `-min-parallelism 100`.
- **Host Timeout**: `-host-timeout <time>` (e.g., `10m`, `30s`).
- **RTT Timeout**: `-max-rtt-timeout <time>` (adjusts for slow networks).
- **Scan Delay**: `-scan-delay < - Example:` nmap --scan-delay 1s 192.168.1.1` (1-second delay between packets).
- **Retries**: `-max-retries <n>` (default 10 for filtered ports).
  - Example: `nmap --max-retries 2 192.168.1.1`.

**Tip**: Use `-T4` for most scans; tweak `--scan-delay` for IDS evasion.

---

### **9. Output Options**

- **Normal Output**: `oN <file>.nmap` (human-readable).
  - Example: `nmap -oN scan.nmap 192.168.1.1`.
- **Greppable Output**: `oG <file>.gnmap` (parseable).
- **XML Output**: `oX <file>.xml` (structured).
- **All Formats**: `oA <basename>` (saves .nmap, .gnmap, .xml).
  - Example: `sudo nmap -oA target 192.168.1.1`.
- **Verbose**: `v` (more details; `vv` for extra verbosity).
- **Debugging**: `d` (shows internal details; `dd` for more).
- **Packet Trace**: `-packet-trace` (displays sent/received packets).
  - Example: `sudo nmap --packet-trace 192.168.1.1`.
- **Reason**: `-reason` (explains port states).
- **HTML Report**: Convert XML: `xsltproc target.xml -o target.html`.

**Tip**: Always use `-oA` to keep all output options available.

---

### **10. Firewall and IDS Evasion**

- **Fragment Packets**: `f` (splits packets into fragments).
  - Example: `nmap -f 192.168.1.1`.
- **MTU**: `-mtu <size>` (sets fragment size, multiple of 8).
- **Decoy Scan**: `D <decoy1,decoy2>` (spoofs source IPs).
  - Example: `nmap -D 1.1.1.1,2.2.2.2 192.168.1.1`.
- **Source IP Spoof**: `S <IP>` (fakes source IP).
- **Source Port**: `-source-port <port>` (bypasses some firewalls).
  - Example: `nmap --source-port 53 192.168.1.1`.
- **Randomize Hosts**: `-randomize-hosts` (shuffles target order).
- **Bad Checksum**: `-badsum` (sends invalid checksums).

**Tip**: Combine `-f` and `--scan-delay` for stealth.

---

### **11. Nmap Scripting Engine (NSE)**

- **Run Scripts**: `-script <script/category>` (executes NSE scripts).
  - Example: `nmap --script vuln 192.168.1.1` (vulnerability scan).
- **Categories**: `auth`, `broadcast`, `brute`, `default`, `discovery`, `dos`, `exploit`, `fuzzer`, `intrusive`, `malware`, `safe`, `version`, `vuln`.
- **Specific Script**: `-script <name>` (e.g., `http-enum`).
- **Script Args**: `-script-args <key=value>` (customizes script behavior).
  - Example: `nmap --script http-enum --script-args http-enum.basepath=/admin 192.168.1.1`.
- **Update Database**: `nmap --script-updatedb` (refreshes script DB).

**Tip**: Use `--script default` with `-A` for a broad scan.

---

### **12. Practical Examples**

- **Quick Scan**: `nmap -F 192.168.1.1`
- **Stealth Scan**: `sudo nmap -sS -T4 192.168.1.1`
- **Full Scan**: `sudo nmap -sS -p- -sV -O -oA fullscan 192.168.1.1`
- **UDP Scan**: `sudo nmap -sU -F 192.168.1.1`
- **Host Discovery**: `sudo nmap -sn 192.168.1.0/24`
- **Firewall Test**: `sudo nmap -sA 192.168.1.1`
- **Verbose Output**: `sudo nmap -sS -v --reason 192.168.1.1`
- **Scripted Scan**: `sudo nmap -sV --script vuln 192.168.1.1`

**Tip**: Test on `scanme.nmap.org` (with permission) to practice.

---

### **13. Troubleshooting and Debugging**

- **No Response**: Increase `-max-rtt-timeout` or use `Pn`.
- **Ports Filtered**: Use `-packet-trace` to see packet flow.
- **Slow Scan**: Adjust `T` or `-min-parallelism`.
- **False Negatives**: Verify with manual tools (e.g., `nc -v <IP> <port>`).
- **Errors**: Use `d` for detailed logs.

**Tip**: Cross-check with Wireshark if results seem off.

---

### **14. Additional Resources**

- **Official Docs**: [https://nmap.org/book/man.html](https://nmap.org/book/man.html)
- **Port Scanning**: [https://nmap.org/book/man-port-scanning-techniques.html](https://nmap.org/book/man-port-scanning-techniques.html)
- **Host Discovery**: [https://nmap.org/book/host-discovery-strategies.html](https://nmap.org/book/host-discovery-strategies.html)
- **NSE Scripts**: [https://nmap.org/nsedoc/](https://nmap.org/nsedoc/)

---

# NOTEZ

## **1. Enumeration: The Foundation of Penetration Testing**

- **Definition**: Enumeration is the process of systematically gathering detailed information about a target system or network to identify potential attack vectors. It’s not just about gaining access but understanding all possible entry points.
- **Why It’s Critical**:
  - Often considered the most important phase of a penetration test because it lays the groundwork for exploitation.
  - The goal isn’t to breach the system immediately but to map out every detail—ports, services, misconfigurations—that could lead to a successful attack.
  - The more data collected, the higher the likelihood of finding exploitable weaknesses.
- **Core Concept**: Tools are secondary; the real skill lies in knowing how to interpret and act on the information they provide. Tools like Nmap are aids, not replacements for human judgment and expertise.
- **Key Objectives**:
  - Identify **functions and resources** that allow interaction with the target (e.g., open ports, accessible APIs).
  - Collect **information that leads to more information** (e.g., service versions revealing vulnerabilities).
- **Process**:
  - Actively interact with services to extract data (e.g., querying a web server for headers or a database for schema info).
  - Understand service syntax and protocols (e.g., HTTP GET vs. POST, SMB dialects).
  - Adapt to new findings by integrating them with existing knowledge.
- **Analogy**:
  - Imagine losing your car keys and calling your partner:
    - Vague response: “In the living room” → Time-consuming search.
    - Precise response: “In the living room, on the white shelf, next to the TV, in the third drawer” → Quick retrieval.
  - Enumeration is about getting that precise, actionable intel.
- **Common Sources of Information**:
  - **Misconfigurations**: Poorly secured services (e.g., default credentials, exposed admin panels).
  - **Neglect**: Outdated software or ignored security practices.
  - Example: An admin relying solely on firewalls and updates might miss deeper vulnerabilities like open ports or weak permissions.
- **Challenges**:
  - Over-reliance on automated tools can miss subtle details (e.g., a service responding slowly might be marked “closed”).
  - Lack of service knowledge stalls progress—spending hours on a tool without understanding the target wastes time.
- **Manual Enumeration**:
  - Critical when tools fail (e.g., bypassing timeouts or custom configurations).
  - Example: A tool might timeout on a slow-responding port, but manual probing (e.g., `nc -v <IP> <port>`) could reveal it’s open.

**Reference Tip**: Always research the services you encounter (e.g., SSH, SMB) to understand their defaults, quirks, and vulnerabilities.

---

## **2. Introduction to Nmap: The Network Exploration Tool**

- **Overview**: Nmap (Network Mapper) is an open-source tool written in C, C++, Python, and Lua, widely used for network discovery and security auditing.
- **Purpose**:
  - Scans networks to identify live hosts, open ports, running services, and operating systems.
  - Detects packet filters, firewalls, and intrusion detection systems (IDS).
  - Provides raw packet-level insights for detailed analysis.
- **Use Cases**:
  - **Security Audits**: Check network defenses for weaknesses.
  - **Penetration Testing**: Simulate attacks to find exploitable points.
  - **Firewall/IDS Testing**: Verify configurations and rules.
  - **Network Mapping**: Build a topology of connected devices.
  - **Vulnerability Assessment**: Identify outdated software or misconfigured services.
- **Architecture**:
  - **Host Discovery**: Finds live systems (e.g., ping sweeps).
  - **Port Scanning**: Checks port states (open, closed, filtered).
  - **Service Enumeration**: Identifies services and versions (e.g., Apache 2.4.7).
  - **OS Detection**: Guesses OS and version based on TCP/IP stack behavior.
  - **Nmap Scripting Engine (NSE)**: Extends functionality with scripts for advanced tasks (e.g., vuln scanning).
- **Syntax**: `nmap <scan types> <options> <target>`
  - Example: `nmap -sS 192.168.1.1` (TCP SYN scan on a single IP).

**Reference Tip**: Familiarize yourself with Nmap’s help (`nmap --help`) for a full list of options.

---

## **3. Nmap Scan Techniques: Detailed Breakdown**

- **TCP SYN Scan (-sS)**:
  - Default scan type; stealthy because it doesn’t complete the TCP three-way handshake (SYN → SYN-ACK → RST).
  - Fast: Can scan thousands of ports per second.
  - Responses:
    - SYN-ACK: Port is **open**.
    - RST: Port is **closed**.
    - No response: Port is **filtered** (firewall likely dropping packets).
  - Example: `sudo nmap -sS localhost`
    - Output: Open ports like 22/tcp (ssh), 80/tcp (http).
- **TCP Connect Scan (-sT)**:
  - Completes the full TCP handshake (SYN → SYN-ACK → ACK); noisier but useful when SYN scans are blocked.
  - Example: `sudo nmap -sT 10.129.2.28 -p 443`
    - Output: 443/tcp open https.
- **UDP Scan (-sU)**:
  - Scans UDP ports; slower due to no handshake and longer timeouts.
  - Responses:
    - Reply: Port is **open**.
    - No reply: Port is **open|filtered** (can’t confirm without app response).
    - ICMP “port unreachable”: Port is **closed**.
  - Example: `sudo nmap -sU 10.129.2.28 -F`
    - Output: 137/udp open netbios-ns.
- **Other Scans**:
  - **Null (-sN)**: No flags set; closed ports send RST, open/filtered don’t.
  - **FIN (-sF)**: FIN flag set; similar to Null.
  - **Xmas (-sX)**: FIN, PSH, URG flags set; same logic.
  - **Idle Scan (-sI)**: Uses a “zombie” host to hide the scanner’s IP.
  - **IP Protocol Scan (-sO)**: Checks supported IP protocols (e.g., ICMP, TCP).
- **Port States**:
  - **Open**: Accepts connections (TCP, UDP, SCTP).
  - **Closed**: Sends RST (TCP) or ICMP unreachable (UDP).
  - **Filtered**: No response or error; firewall likely present.
  - **Unfiltered**: Accessible but status unclear (TCP-ACK scan only).
  - **Open|Filtered**: UDP-specific; no response to empty packet.

**Reference Tip**: Use `--packet-trace` and `--reason` to debug scan results (e.g., why a port is filtered).

---

## **4. Saving and Managing Nmap Results**

- **Why Save?**:
  - Compare scans over time.
  - Document findings for reports.
  - Analyze differences between scan types.
- **Output Formats**:
  - **Normal (-oN)**: `.nmap` file; human-readable text.
    - Example: `cat target.nmap`
  - **Greppable (-oG)**: `.gnmap` file; easy to parse with tools like `grep`.
    - Example: `cat target.gnmap`
  - **XML (-oX)**: `.xml` file; structured data for processing.
    - Example: `cat target.xml`
  - **All (-oA)**: Saves in all three formats with a base name (e.g., `target`).
- **Command Example**:
  - `sudo nmap 10.129.2.28 -p- -oA target`
    - Scans all ports, saves as `target.nmap`, `target.gnmap`, `target.xml`.
    - Output: Open ports 22/ssh, 25/smtp, 80/http.
- **HTML Reports**:
  - Convert XML to HTML: `xsltproc target.xml -o target.html`
  - Benefit: Readable format for non-technical stakeholders.
- **File Listing**:
  - `ls`: Shows `target.nmap`, `target.gnmap`, `target.xml`.

**Reference Tip**: Use `-oA` for every scan to keep all options open for later analysis.

---

## **5. Host Discovery: Finding Live Systems**

- **Purpose**: Confirm which hosts are online before deeper scanning.
- **Techniques**:
  - **ICMP Echo Request (-PE)**: Sends ping; expects reply if host is alive.
    - Blocked by firewalls often; adjust with alternatives.
  - **ARP Ping**: Default for local networks; fast and reliable.
    - Disabled with `-disable-arp-ping`.
  - **No Port Scan (-sn)**: Focuses solely on host discovery.
- **Examples**:
  - **Network Range**: `sudo nmap 10.129.2.0/24 -sn -oA tnet`
    - Lists live IPs (e.g., 10.129.2.4, 10.129.2.28).
  - **IP List**: `sudo nmap -iL hosts.lst -sn`
    - Reads from `hosts.lst` (e.g., 10.129.2.4, 10.129.2.10).
  - **Multiple IPs**: `sudo nmap 10.129.2.18 10.129.2.19 10.129.2.20 -sn`
    - Or range: `10.129.2.18-20`.
  - **Single IP**: `sudo nmap 10.129.2.18 -sn -PE --packet-trace`
    - Output: Host is up (ARP or ICMP reply).
- **Advanced Options**:
  - `-packet-trace`: Shows packets (e.g., ARP request/reply).
  - `-reason`: Explains why a host is “up” (e.g., arp-response).
  - `-disable-arp-ping`: Forces ICMP or other methods.

**Reference Tip**: Start with `-sn` to map the network, then drill down with port scans.

---

## **6. Host and Port Scanning: Digging Deeper**

- **Goals**:
  - Identify open ports, services, versions, and OS.
  - Gather actionable data for exploitation.
- **Key Options**:
  - `p <port>`: Specific ports (e.g., `p 80,443`).
  - `-top-ports=<n>`: Scans most frequent ports (e.g., `-top-ports=10`).
  - `sV`: Detects service versions (e.g., Samba 3.X-4.X).
  - `F`: Fast scan (top 100 ports).
- **Examples**:
  - Top Ports: `sudo nmap 10.129.2.28 --top-ports=10`
    - Output: 22/open, 445/filtered, etc.
  - Packet Trace: `sudo nmap 10.129.2.28 -p 21 --packet-trace -Pn -n --disable-arp-ping`
    - Shows SYN → RST (closed).
  - Version Scan: `sudo nmap 10.129.2.28 -p 445 -sV`
    - Output: 445/tcp open netbios-ssn Samba smbd 3.X-4.X.
- **Filtered Ports**:
  - **Dropped**: No response; firewall drops packet.
    - Example: `sudo nmap 10.129.2.28 -p 139` → 2-second delay, filtered.
  - **Rejected**: ICMP error (e.g., “port unreachable”).
    - Example: `sudo nmap 10.129.2.28 -p 445` → Quick ICMP reply.
- **UDP Scanning**:
  - Slower due to no handshake; use `sU`.
  - Example: `sudo nmap 10.129.2.28 -F -sU`
    - Output: 137/udp open, 138/udp open|filtered.
  - Packet Trace: `sudo nmap 10.129.2.28 -sU -p 137 --packet-trace`
    - Shows UDP response if open.

**Reference Tip**: Use `-sV` to fingerprint services; combine with `--reason` to troubleshoot.

---

## 7. Service Enumeration

### Key Concepts:

1. **Service Enumeration**:
   - Goal: Identify applications and their versions on a target to find vulnerabilities or exploits.
   - Steps: Perform a quick port scan, followed by a detailed version scan.
2. **Port Scanning**:
   - Quick scan: Use `nmap <target> -p-` to identify open ports with minimal traffic.
   - Version scan: Use `sV` to detect service versions on specific ports (e.g., `sudo nmap 10.129.2.28 -p- -sV`).
   - Full scan takes time; check status with `[Space Bar]` or set periodic updates with `-stats-every <time>` (e.g., `-stats-every 5s`).
3. **Verbosity**:
   - Increase output detail with `v` or `vv` to see open ports as they’re detected.
4. **Banner Grabbing**:
   - After scanning, services may reveal banners (e.g., `220 inlane ESMTP Postfix (Ubuntu)` on port 25).
   - Use `nc` (netcat) to manually grab banners: `nc -nv 10.129.2.28 25`.
   - Combine with `tcpdump` to capture traffic and analyze banners Nmap might miss.
5. **Example Output**:
   - Scan: `sudo nmap 10.129.2.28 -p- -sV`
   - Results: Open ports (e.g., 22/ssh OpenSSH 7.6p1, 80/http Apache 2.4.29), filtered ports (e.g., 445/microsoft-ds).
6. **TCP Handshake**:
   - Three-way handshake: SYN → SYN-ACK → ACK.
   - PSH-ACK: Server sends data (e.g., banner) and confirms transmission.

### Notes:

- Start with a lightweight scan to avoid detection, then refine with version detection.
- Use tools like `tcpdump` and `nc` for deeper analysis of service responses.Performance

---

## 7. Performance

### Key Concepts:

1. **Performance Tuning**:
   - Optimize Nmap scans for speed or accuracy depending on network size and bandwidth.
2. **Timeouts**:
   - Default RTT timeout: 100ms.
   - Optimize: --initial-rtt-timeout 50ms --max-rtt-timeout 100ms.
   - Example: sudo nmap 10.129.2.0/24 -F (39.44s) vs. optimized (12.29s), but may miss hosts if too aggressive.
3. **Max Retries**:
   - Default: 10 retries.
   - Reduce: --max-retries 0 speeds up scans but risks missing ports.
   - Example: Default found 23 ports, reduced retries found 21.
4. **Packet Rates**:
   - Set minimum packet rate with --min-rate <number> (e.g., --min-rate 300).
   - Example: Default (29.83s) vs. optimized (8.67s), both found 23 ports.
5. **Timing Templates**:
   - Predefined options: -T0 (paranoid) to -T5 (insane).
   - Default: -T3 (normal).
   - Example: -T5 reduced scan time from 32.44s to 18.07s, same results (23 ports).

### Notes:

- Balance speed and accuracy: Aggressive settings (low timeouts, fewer retries, high rates) save time but may miss data.
- Use -oN <filename> to save results for comparison.

---

## 8.Nmap Scripting Engine (NSE)

### Key Concepts:

1. **NSE Overview**:
   - Uses Lua scripts to interact with services, categorized into 14 types (e.g., `auth`, `brute`, `vuln`).
2. **Specifying Scripts**:
   - Example: `sudo nmap 10.129.2.28 -p 25 --script banner,smtp-commands`.
   - Output: Banner (`220 inlane ESMTP Postfix (Ubuntu)`), SMTP commands (e.g., `STARTTLS`).
3. **Aggressive Scan**:
   - Use `A` for service detection (`sV`), OS detection (`O`), traceroute, and default scripts.
   - Example: `sudo nmap 10.129.2.28 -p 80 -A` revealed Apache 2.4.29, WordPress 5.3.4, and OS guesses (Linux 68%).
4. **Vulnerability Assessment**:
   - Use `-script vuln` to check for known vulnerabilities.
   - Example: `sudo nmap 10.129.2.28 -p 80 -sV --script vuln`.
   - Output: WordPress version, admin folder (`/wp-login.php`), CVEs (e.g., CVE-2019-0211, score 7.2).

### Notes:

- NSE enhances Nmap’s capabilities—use specific scripts for targeted info or `A` for broad scans.
- Check NSE documentation for script details: `https://nmap.org/nsedoc/index.html`.

---

## 9. Firewall and IDS/IPS Evasion

### Key Concepts:

1. **Firewalls**:
   - Filter traffic based on rules; ports may appear “filtered” (dropped or rejected with RST/ICMP errors).
2. **IDS/IPS**:
   - IDS detects attacks via pattern matching; IPS blocks them.
   - Harder to detect as they passively monitor traffic.
3. **ACK Scan**:
   - Use `sA` to send ACK-only packets, bypassing SYN filters.
   - Example: SYN scan (`sS`) vs. ACK scan (`sA`) showed different responses for port 25 (dropped vs. RST).
4. **Detecting IDS/IPS**:
   - Use multiple VPS IPs; if one is blocked, IDS/IPS is likely present.
   - Aggressive scans (e.g., single port) can trigger detection.
5. **Decoys**:
   - Use `D RND:<number>` to spoof source IPs and hide origin.
   - Example: `sudo nmap 10.129.2.28 -p 80 -sS -D RND:5` mixed real IP (10.10.14.2) with decoys.
6. **Source IP Spoofing**:
   - Use `S <IP>` to test firewall rules.
   - Example: `sudo nmap 10.129.2.28 -p 445 -O -S 10.129.2.200` changed port 445 from filtered to open.
7. **DNS Proxying**:
   - Use `-source-port 53` to mimic DNS traffic, often trusted.
   - Example: `sudo nmap 10.129.2.28 -p 50000 -sS --source-port 53` opened a filtered port.

### Notes:

- Evasion requires subtlety—ACK scans, decoys, and spoofed IPs help bypass filters.
- Test with `ncat` to confirm connectivity (e.g., `ncat -nv --source-port 53 10.129.2.28 50000`).

---

### General Tips:

- **Commands**: Always use `sudo` for full functionality; specify targets (e.g., `10.129.2.28`) and ports (e.g., `p-` or `p 80`).
- **Output**: Use `oN` to save results, `-packet-trace` for debugging.
- **Caution**: Aggressive scans (`T5`, `A`) may trigger security systems—adjust based on context.
