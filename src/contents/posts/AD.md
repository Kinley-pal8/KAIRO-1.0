---
title: Active Directory
published: 2025-04-29
description: For My Reference
tags: [Notes]
category: Notes
author: Me
draft: false
---

# 13 - Active Directory

# Active Directory Basics - TryHackMe Room Notes

## Overview

- **Room Objective**: Understand the fundamental concepts and functionality of Active Directory (AD), a Microsoft directory service for managing users, computers, and resources in Windows Domain Networks.
- **Prerequisites**: Basic knowledge of Windows, networking, PowerShell, and remote desktop tools.
- **Key Topics**: AD structure, domain controllers, users, groups, organizational units (OUs), group policies (GPOs), authentication protocols, and trust relationships.

---

## 1. Introduction to Active Directory

- **What is Active Directory?**
    - A directory service that acts as a centralized database/server storing user credentials (usernames, passwords, emails, phone numbers, etc.) and network resources.
    - Hosted on a **Domain Controller (DC)** running **Active Directory Domain Services (AD DS)**, which manages the domain’s objects.
    - Enables centralized management of users, computers, and policies in a Windows domain.
- **Purpose**:
    - **Centralized Identity Management**: Allows users to log into any domain-joined computer with one set of credentials, eliminating the need for local accounts on each machine.
    - **Security Policy Management**: Enforces consistent policies (e.g., password complexity, restricted access) across the network.
    - **Delegation of Control**: Grants specific users permissions to manage certain AD objects without full admin rights.
- **Real-World Example**:
    - In a school or workplace, you use a single username/password to access any computer on the network. AD verifies your credentials and applies policies (e.g., restricting control panel access) centrally.
- **Why Use a Windows Domain?**
    - Overcomes limitations of manual administration, such as:
        - Creating user accounts on each computer individually.
        - Applying policies or fixing issues on a per-machine basis.
        - Defining user boundaries manually.
    - A domain groups users and computers under one administrative boundary (e.g., `thm.local`), managed via AD.

---

## 2. Windows Domains (Task 2)

- **Key Components**:
    - **Credentials Repository**: Active Directory (specifically, the `NTDS.dit` database on the DC).
        - **Answer**: Active Directory.
    - **Server Role**: The server running AD services is called a **Domain Controller**.
        - **Answer**: Domain Controller.
- **Advantages of a Windows Domain**:
    - Simplifies administration by centralizing user and resource management.
    - Enables scalable policy deployment across the network.
    - Supports single sign-on (SSO) for seamless access to domain resources.

---

## 3. Active Directory Core Components (Task 3)

- **Active Directory Domain Services (AD DS)**:
    - The core service that catalogs all network objects, including:
        - **Users**: Accounts for people (employees) or services (e.g., MSSQL, IIS).
        - **Groups**: Collections of users or machines for assigning permissions.
        - **Machines**: Computers joined to the domain.
        - **Printers, Shares, etc.**: Other network resources.
- **Users**:
    - **Types**:
        - **People**: Represent employees or individuals accessing the network.
        - **Service Accounts**: Used by applications/services (e.g., SQL Server). These have limited privileges tailored to the service and can run continuously, even without a logged-in user.
    - Users are **security principals**, meaning they can authenticate and be assigned permissions to resources.
- **Machines**:
    - Each computer in the domain has a **machine account**, also a security principal.
    - Naming: Machine accounts are named `<computer_name>$` (e.g., `TOM-PC$` for a computer named `TOM-PC`).
        - **Answer**: `TOM-PC$`.
    - Machine accounts have local admin rights on their respective computers and use auto-rotated 120-character passwords for security.
- **Security Groups**:
    - Used to assign permissions to resources (e.g., shared folders, printers) for multiple users/machines.
    - Unlike OUs, users can belong to multiple groups to inherit various permissions.
    - **Default Groups**:
        - **Domain Admins**: Administrative control over the entire domain, including DCs.
            - **Answer**: Domain Admins (group that administrates all computers/resources).
        - **Server Operators**: Can administer DCs but cannot modify admin group memberships.
        - **Backup Operators**: Can access files regardless of permissions for backups.
        - **Account Operators**: Can create/modify user accounts.
        - **Domain Users**: All user accounts in the domain.
        - **Domain Computers**: All computers in the domain.
        - **Domain Controllers**: All DCs in the domain.
- **Organizational Units (OUs)**:
    - Containers for grouping users, computers, or other OUs to apply consistent policies.
    - Example: Create an OU for the **Quality Assurance** department to enforce department-specific policies.
        - **Answer**: Organizational Unit.
    - Users can only belong to one OU at a time to avoid policy conflicts.
    - OUs often reflect the business structure (e.g., OUs for IT, Sales, Marketing).
- **Default Containers**:
    - **Builtin**: Default groups for Windows hosts.
    - **Computers**: Default location for new machine accounts.
    - **Domain Controllers**: Contains all DCs.
    - **Users**: Default users and groups for domain-wide context.
    - **Managed Service Accounts**: Service accounts for domain services.
- **Security Groups vs. OUs**:
    - **OUs**: Apply policies/configurations to users or computers based on their role.
    - **Groups**: Grant permissions to resources; users can belong to multiple groups.

**Practical**:

- Use **Active Directory Users and Computers** (on the DC) to manage users, groups, and OUs.
    - Access via Start Menu on the DC.
    - View and modify the hierarchy (e.g., create an OU called `Students` under `THM`).
    - Example: Reset a user’s password or move a computer to a different OU.

---

## 4. Managing Users in AD (Task 4)

- **Scenario**: As a domain admin, update AD to match an organizational chart by managing OUs and users.
- **Tasks**:
    - **Delete Extra OUs**:
        - Identify and remove outdated OUs (e.g., a closed department).
        - OUs are protected against accidental deletion by default.
        - Enable **Advanced Features** in Active Directory Users and Computers (View menu).
        - Uncheck “Protect object from accidental deletion” in the OU’s Properties (Object tab).
        - Delete the OU, which also removes its child objects (users, groups, OUs).
    - **Create/Delete Users**:
        - Add or remove users to match the organizational chart.
    - **Delegation**:
        - Grant specific users (e.g., IT support) privileges over OUs without full admin rights.
        - Example: Allow Phillip (IT support) to reset passwords for Sales, Marketing, and Management OUs.
        - **Answer**: Delegation (process of granting privileges over an OU or AD object).
- **Practical Example: Resetting Sophie’s Password**:
    - Connect to the domain (`thm.local`) via **Remmina** (RDP client) using:
        - Username: `Administrator`, Password: `Password321`.
        - Or: Username: `phillip`, Password: `Claire2008` (for delegation tasks).
    - Open Command Prompt, switch to PowerShell:
        
        ```powershell
        powershell
        
        ```
        
    - Reset Sophie’s password:
        
        ```powershell
        Set-ADAccountPassword sophie -Reset -NewPassword (Read-Host -AsSecureString -Prompt 'New Password') -Verbose
        
        ```
        
        - Example password: `abcD12345*`.
    - Log into Sophie’s account to find a flag on her desktop:
        - **Answer**: `THM{thanks_for_contacting_support}`.
    - Force Sophie to reset her password at next logon:
        
        ```powershell
        Set-ADUser -ChangePasswordAtLogon $true -Identity sophie -Verbose
        
        ```
        
        - This ensures Sophie cannot use the temporary password and must reset it.

---

## 5. Managing Computers in AD (Task 5)

- **Objective**: Organize computers into appropriate OUs (e.g., Workstations, Servers).
- **Tasks**:
    - Move computers to OUs based on their role.
    - After organizing, count computers in the **Workstations** OU.
        - **Answer**: 7.
    - Question: Is it recommendable to create separate OUs for Servers and Workstations?
        - **Answer**: Yay (separating OUs allows tailored policies for each device type).
- **Why Separate OUs?**
    - Servers and workstations have different security and configuration needs.
    - Example: Servers may require stricter access controls, while workstations need user-focused policies.

---

## 6. Group Policies (Task 6)

- **What are Group Policies (GPOs)?**
    - Rules applied to users or computers to enforce settings (e.g., password policies, software restrictions).
    - Distributed via a network share called **SYSVOL**.
        - **Answer**: SYSVOL.
- **GPO Capabilities**:
    - Can apply settings to both users and computers.
        - **Answer**: Yay.
- **How GPOs Work**:
    - Stored in the SYSVOL share on DCs, replicated across the domain.
    - Linked to OUs to apply policies to specific groups of users or computers.

---

## 7. Authentication Methods (Task 7)

- **Authentication Protocols**:
    - **Kerberos**: Default protocol in modern Windows domains (used by current versions).
        - **Answer**: Nay (Windows does not prefer NetNTLM by default).
    - **NetNTLM**: Legacy protocol for compatibility with older systems.
- **Kerberos Process**:
    1. User sends username and encrypted timestamp to the **Key Distribution Center (KDC)** on the DC.
    2. KDC issues a **Ticket Granting Ticket (TGT)** and a Session Key.
        - TGT allows requesting service tickets; encrypted with the `krbtgt` account’s hash.
        - **Answer**: Ticket Granting Ticket (ticket that allows requesting TGS).
    3. To access a service, the user sends the TGT, username, timestamp, and **Service Principal Name (SPN)** to the KDC.
    4. KDC issues a **Ticket Granting Service (TGS)** and Service Session Key, encrypted with the service owner’s hash.
    5. User presents the TGS to the service for authentication.
- **NetNTLM Process**:
    - Uses a challenge-response mechanism:
        1. Client sends username and domain to the server.
        2. Server sends a random challenge.
        3. Client generates a response using the NTLM hash and challenge.
        4. Server forwards the response to the DC for verification.
        5. DC verifies the response and authenticates the user.
    - User’s password/hash is never sent over the network.
        - **Answer**: Nay.
    - For local accounts, the server verifies the response using the local **SAM** database.
- **Security Note**:
    - Kerberos is more secure and efficient; NetNTLM is vulnerable to attacks like pass-the-hash (relevant to your prior interest in password cracking tools like John the Ripper).

---

## 8. Trees, Forests, and Trusts (Task 8)

- **Trees**:
    - A group of domains sharing the same namespace (e.g., `thm.local`, `uk.thm.local`, `us.thm.local`).
        - **Answer**: Tree.
    - Allows independent management of resources (e.g., UK IT manages `uk.thm.local` only).
    - **Enterprise Admins**: A group with admin privileges over all domains in the tree.
- **Forests**:
    - A collection of trees with different namespaces (e.g., `thm.local` and `mht.local`).
    - Used when companies merge, each maintaining separate IT management.
- **Trust Relationships**to allow users in one domain to access resources in another.
    - **One-Way Trust**: Domain A trusts Domain B, allowing B’s users to access A’s resources.
    - **Two-Way Trust**: Mutual access between domains; default in trees/forests.
    - Required for cross-domain resource access (e.g., a user in `uk.thm.local` accessing a server in `mht.asia`).
        - **Answer**: 2 trust relationship (for Domain A to access Domain B).
    - Trusts enable authorization but do not automatically grant full access; permissions must be configured.

---

## 9. Practical Setup and Tools

- **Lab Access**:
    - Connect to the domain (`thm.local`) using **Remmina** (RDP client on Kali):
        - RDP port: 3389.
        - Credentials:
            - Administrator: `Password321`.
            - Phillip: `Claire2008` (for delegation tasks).
    - Use TryHackMe’s AttackBox or VPN for network access.
- **PowerShell Commands**:
    - Manage users:
        
        ```powershell
        Set-ADAccountPassword <username> -Reset -NewPassword (Read-Host -AsSecureString -Prompt 'New Password') -Verbose
        Set-ADUser -ChangePasswordAtLogon $true -Identity <username> -Verbose
        
        ```
        
    - Create OUs:
        
        ```powershell
        New-ADOrganizationalUnit -Name "Students" -Path "OU=THM,DC=thm,DC=local"
        
        ```
        
    - View user details:
        
        ```powershell
        Get-NetUser -Username <username> | select pwdlastset
        
        ```
        
- **Active Directory Users and Computers**:
    - GUI tool on the DC for managing OUs, users, and groups.
    - Enable Advanced Features to modify protected objects.

---

## 10. Key Takeaways

- **AD’s Role**: Centralizes network management, making it a critical target for attackers (relevant to your penetration testing interests, e.g., Nmap, CrackMapExec).
- **Security Implications**:
    - Misconfigured OUs, groups, or trusts can lead to privilege escalation.
    - Weak authentication protocols (e.g., NetNTLM) are exploitable.
- **Real-World Application**:
    - AD is used in most corporate environments, essential for IT and cybersecurity roles.
    - Understanding AD helps in both administration and attacking/defending networks.
- **Next Steps**:
    - Explore TryHackMe rooms like “Attacking AD” or “Persisting Active Directory.”
    - Practice PowerShell scripting for AD management.
    - Study AD attack techniques (e.g., Kerberoasting, NTLM relay) to complement your security knowledge.

---

## 11. Additional Resources

- **TryHackMe Path**: Continue with “Jr Penetration Tester” or “Active Directory” learning paths.
- **Write-Ups**:
    - Kevinovitz’s guide: [https://kevinovitz.github.io/TryHackMe_Writeups/winadbasics/winadbasics/](https://kevinovitz.github.io/TryHackMe_Writeups/winadbasics/winadbasics/)
    - Kawsar Uddin’s Medium post: [https://medium.com/@kawsaruddin/active-directory-basics-tryhackme-8b0b0e0f0b0](https://medium.com/@kawsaruddin/active-directory-basics-tryhackme-8b0b0e0f0b0)
- **YouTube Walkthroughs**:
    - Search for “TryHackMe Active Directory Basics” for task-specific videos.
- **PowerShell Documentation**:
    - Microsoft’s AD PowerShell module: [https://docs.microsoft.com/en-us/powershell/module/activedirectory/](https://docs.microsoft.com/en-us/powershell/module/activedirectory/)

---

Notez

## 1. What is Active Directory?

**Definition**: Active Directory (AD) is a **directory service** developed by Microsoft for Windows-based networks. It acts as a centralized database and management system for organizing and securing network resources, including users, computers, groups, printers, and policies. AD handles **authentication** (verifying who you are) and **authorization** (determining what you can do).

**Core Purpose**:

- **Centralized Management**: Simplifies administration of users, devices, and policies across a network.
- **Security**: Ensures only authorized users access resources using protocols like Kerberos and LDAP.
- **Scalability**: Supports millions of objects, making it suitable for small businesses to global enterprises.
- **Accessibility**: Provides a searchable database of network resources, accessible to all domain users.

**Real-World Analogy**: Think of AD as a digital phonebook for a company. It lists all employees (users), their devices (computers), and their roles (groups), with rules (policies) about who can access what. Just as a phonebook is searchable, AD allows administrators and users to find resources easily.

**Why Critical?**

- **Prevalence**: ~95% of Fortune 500 companies use AD, making it a cornerstone of enterprise IT.
- **Attack Surface**: Its centrality and complexity make it a prime target for attackers. Misconfigurations or vulnerabilities can lead to unauthorized access or full network compromise.

**Key Features**:

- **Hierarchical Structure**: Organizes resources in a tree-like structure (forests, domains, OUs).
- **Authentication/Authorization**: Uses Kerberos for secure logins and Access Control Lists (ACLs) for permissions.
- **Group Policies**: Applies settings (e.g., password requirements) to users and computers.
- **Trust Relationships**: Enables resource sharing between domains or forests.

**Security Challenges**:

- **Backward Compatibility**: Older features (e.g., from Windows 2000) may lack modern security, creating vulnerabilities.
- **Enumeration**: Any domain user, even with minimal privileges, can query most AD objects (users, groups, policies), exposing potential attack paths.
- **Misconfigurations**: Improper settings (e.g., weak ACLs, overly permissive trusts) can be exploited.
- **Notable Attacks**:
    - **noPac (2021)**: Exploits misconfigurations to gain domain admin access.
    - **PrintNightmare (CVE-2021-34527)**: Escalates privileges via the print spooler.
    - **Zerologon (CVE-2020-1472)**: Compromises Domain Controllers (DCs) by exploiting Netlogon flaws.
    - **Kerberoasting**: Targets service accounts to crack passwords.

**Example**: A phishing attack grants an attacker a standard user account in AD. With this access, they can enumerate users, groups, and policies, identify misconfigurations (e.g., an outdated trust), and escalate privileges to control the entire network.

---

## 2. AD Structure

AD uses a **hierarchical tree structure** to organize resources, making it intuitive for management and scalable for large networks.

### Key Components

1. **Forest**:
    - The top-level container in AD, encompassing all objects (domains, users, groups, etc.).
    - Defines the **security boundary**: Objects within a forest are under unified administrative control.
    - Can contain one or more domains and trees.
    - Example: `inlanefreight.local`.
2. **Domain**:
    - A logical group of objects (users, computers, groups) within a forest.
    - Each domain has its own database (stored in NTDS.DIT) and policies (e.g., password length).
    - Example: `corp.inlanefreight.local`.
3. **Tree**:
    - A collection of domains sharing a common root domain and namespace (e.g., `inlanefreight.local` as root with `corp.inlanefreight.local` as a child).
    - Domains in a tree are linked by **parent-child trusts**.
4. **Organizational Units (OUs)**:
    - Containers within a domain to organize objects for easier administration.
    - Used to apply **Group Policy Objects (GPOs)** (e.g., enforce screen lock timeout) and delegate tasks (e.g., allow HR to reset passwords).
    - Example: OU “Employees” with sub-OUs for “HR,” “IT.”
5. **Domain Controllers (DCs)**:
    - Servers that host the AD database, handle authentication, and enforce policies.
    - Store the NTDS.DIT file (AD’s core database) and replicate changes to other DCs.
    - Example: `DC01.inlanefreight.local`.
6. **Sites**:
    - Groups of computers in high-speed network subnets, used to optimize replication between DCs.

### Diagram: AD Structure

```
[Forest: inlanefreight.local]
    |
    +-- [Domain: inlanefreight.local]
    |       |
    |       +-- [DC: DC01]
    |       +-- [OU: Employees]
    |       |       |
    |       |       +-- [OU: HR]
    |       |       |       |
    |       |       |       +-- [User: barbara.jones]
    |       |       |       +-- [Group: HR Staff]
    |       |       |
    |       |       +-- [OU: IT]
    |       |               |
    |       |               +-- [User: john.doe]
    |       |
    |       +-- [OU: Computers]
    |               |
    |               +-- [Computer: FILE01]
    |               +-- [Computer: WS01]
    |
    +-- [Domain: corp.inlanefreight.local]
    |       |
    |       +-- [DC: DC02]
    |       +-- [OU: Dev]
    |               |
    |               +-- [User: dev.user]
    |
    +-- [Domain: dev.inlanefreight.local]
            |
            +-- [DC: DC03]
            +-- [OU: Admin]
                    |
                    +-- [Group: Admins]

```

**Explanation**:

- **Forest**: `inlanefreight.local` is the top-level container, holding all domains.
- **Domains**: `inlanefreight.local`, `corp.inlanefreight.local`, and `dev.inlanefreight.local` are separate domains with their own DCs and OUs.
- **OUs**: Organize objects (e.g., “HR” OU contains users and groups).
- **DCs**: Manage authentication and store AD data for their domain.
- **Trusts**: Parent-child trusts link domains within the same forest (e.g., `inlanefreight.local` to `corp.inlanefreight.local`).

**Practical Example**: A company with offices in New York and London might have a forest (`company.local`) with domains for each region (`ny.company.local`, `london.company.local`). OUs within `ny.company.local` could include “Sales” and “Engineering,” each containing relevant users and computers.

---

## 3. AD Terminology

Understanding AD requires mastering its terminology, which describes its components and operations.

### Key Terms

1. **Object**: Any resource in AD, such as users, computers, OUs, printers, or groups.
2. **Attributes**: Properties of an object (e.g., a user’s email, a computer’s hostname).
3. **Schema**: The blueprint defining object types (e.g., “user,” “computer”) and their possible attributes.
4. **Security Principal**: Objects that can be authenticated (e.g., users, computers) and assigned permissions. Identified by a **Security Identifier (SID)**.
5. **Global Unique Identifier (GUID)**: A unique 128-bit value assigned to every AD object (e.g., stored in `objectGUID` attribute).
6. **Distinguished Name (DN)**: The full path to an object in AD (e.g., `CN=BJones,OU=Managers,OU=Sales,DC=inlanefreight,DC=local`).
7. **Relative Distinguished Name (RDN)**: The object’s unique name within its parent container (e.g., `CN=BJones`).
8. **Container**: Objects that hold other objects (e.g., domains, OUs, groups).
9. **Leaf**: Objects that cannot contain others (e.g., users, computers, printers).
10. **Service Principal Name (SPN)**: Identifies a service instance for Kerberos authentication (e.g., `HTTP/webserver.inlanefreight.local`).
11. **Group Policy Object (GPO)**: A set of policy settings (e.g., disable USB drives) applied to users or computers.
12. **Access Control List (ACL)**: Lists permissions (Access Control Entries, or ACEs) for an object.
13. **NTDS.DIT**: The AD database file on DCs, storing object data and password hashes.
14. **SYSVOL**: A shared folder on DCs storing GPOs, scripts, and policies, replicated across DCs.
15. **AdminSDHolder**: A container managing ACLs for privileged groups (e.g., Domain Admins).
16. **AD Recycle Bin**: Facilitates recovery of deleted objects, preserving attributes (introduced in Server 2008 R2).
17. **Tombstone**: Holds deleted objects for a set period (default: 60 or 180 days) before permanent deletion.

### Diagram: Distinguished Name

```
[Domain: inlanefreight.local]
    |
    +-- [OU: Users]
            |
            +-- [OU: Sales]
                    |
                    +-- [OU: Managers]
                            |
                            +-- [User: BJones]
DN: CN=BJones,OU=Managers,OU=Sales,OU=Users,DC=inlanefreight,DC=local
RDN: CN=BJones

```

**Explanation**:

- **DN**: Traces the object’s location from the domain root to the object (like a file path).
- **RDN**: Ensures uniqueness within the parent container (e.g., no two “BJones” in the same OU).
- **Practical Use**: When querying AD (e.g., via PowerShell), the DN or GUID ensures precise identification.

**Example**: To find Barbara Jones in AD, you could query her DN or GUID (`objectGUID`) using PowerShell:

```powershell
Get-ADUser -Identity "CN=BJones,OU=Managers,OU=Sales,OU=Users,DC=inlanefreight,DC=local"

```

---

## 4. AD Objects

AD objects represent network resources and are classified as **container** (can hold other objects) or **leaf** (cannot hold others).

### Types of Objects

1. **Users**:
    - Represent individuals in the organization (e.g., employees).
    - **Leaf objects**, **security principals** (have SID and GUID).
    - Attributes: `displayName`, `mail`, `lastLogon`, `passwordLastSet`, etc.
    - **Security Note**: Even low-privileged users can enumerate AD, making them a starting point for attacks.
2. **Computers**:
    - Represent devices joined to the domain (e.g., workstations, servers).
    - **Leaf objects**, **security principals**.
    - Attributes: `dNSHostName`, `operatingSystem`, `servicePrincipalName`.
    - **Security Note**: Compromising a computer grants `NT AUTHORITY\SYSTEM` access, equivalent to a standard user for enumeration.
3. **Groups**:
    - **Container objects** holding users, computers, or other groups.
    - **Security principals** used to manage permissions.
    - Example: Adding “HelpDesk” group to “Remote Management Users” grants all members access.
    - **Security Note**: Nested groups can lead to unintended permissions (e.g., a user in a nested group gaining admin rights).
4. **Organizational Units (OUs)**:
    - **Container objects** for organizing objects.
    - Used for **GPOs** (e.g., enforce password policies) and **delegation** (e.g., allow IT to manage user accounts).
    - Attributes: `name`, `gPLink` (linked GPOs), `managedBy`.
5. **Domain Controllers**:
    - Servers hosting the AD database and handling authentication.
    - **Container objects** (contain AD data).
    - **Security Note**: Compromising a DC grants access to NTDS.DIT, exposing all password hashes.
6. **Printers**:
    - Represent network printers.
    - **Leaf objects**, **not security principals** (only GUID).
    - Attributes: `printerName`, `portName`, `driverName`.
7. **Shared Folders**:
    - Represent shared directories on a computer.
    - **Leaf objects**, **not security principals**.
    - Attributes: `shareName`, `path`, `permissions`.
    - **Security Note**: Misconfigured shares (e.g., open to “Everyone”) can expose sensitive data.
8. **Contacts**:
    - Represent external individuals (e.g., vendors).
    - **Leaf objects**, **not security principals**.
    - Attributes: `givenName`, `sn`, `mail`.
9. **Foreign Security Principals (FSPs)**:
    - Placeholders for objects from trusted external forests.
    - Stored in `ForeignSecurityPrincipals` container.
    - **Security Note**: Misconfigured trusts can allow FSPs to gain unintended access.

### Diagram: Object Hierarchy

```
[Domain: inlanefreight.local]
    |
    +-- [OU: Employees]
    |       |
    |       +-- [Group: HQ Staff]
    |       |       |
    |       |       +-- [User: barbara.jones]
    |       |       +-- [User: john.doe]
    |       |
    |       +-- [OU: Managers]
    |               |
    |               +-- [User: alice.smith]
    |
    +-- [OU: Resources]
    |       |
    |       +-- [Printer: Printer01]
    |       +-- [Shared Folder: DataShare]
    |
    +-- [OU: Computers]
            |
            +-- [Computer: FILE01]
            +-- [Computer: WS01]

```

**Explanation**:

- **OUs** organize objects for management (e.g., “Employees” for users, “Resources” for printers).
- **Groups** simplify permission assignment (e.g., “HQ Staff” grants access to shared resources).
- **Leaf Objects** (users, computers, printers) are endpoints in the hierarchy.

**Practical Example**: To enforce a strict password policy for IT staff, create an OU “IT,” place IT users in it, and link a GPO with settings like “Minimum Password Length: 12.”

---

## 5. AD Functionality

AD’s functionality is driven by roles, functional levels, trusts, and replication.

### Flexible Single Master Operation (FSMO) Roles

Five roles handle specific AD tasks, typically assigned to DCs:

1. **Schema Master**:
    - Manages the AD schema (defines object types/attributes).
    - Only one per forest.
2. **Domain Naming Master**:
    - Ensures unique domain names in the forest.
    - Only one per forest.
3. **Relative ID (RID) Master**:
    - Allocates RIDs for SIDs to ensure uniqueness.
    - One per domain.
4. **PDC Emulator**:
    - Handles password changes, time synchronization, and legacy client compatibility.
    - One per domain.
5. **Infrastructure Master**:
    - Manages cross-domain object references (e.g., group memberships).
    - One per domain.

**Security Note**: FSMO role holders are critical; their compromise can disrupt AD operations.

**Example**: If the PDC Emulator fails, users may experience login delays due to unsynchronized time or unprocessed password changes.

### Domain and Forest Functional Levels

- **Functional Levels**: Determine available features and supported DC operating systems.
- **Domain Functional Levels**:
    - **Windows 2000 Native**: Supports universal groups, SID history.
    - **Windows Server 2003**: Adds domain rename, lastLogon replication.
    - **Windows Server 2016**: Enhances Kerberos, credential protection.
- **Forest Functional Levels**:
    - **Windows Server 2003**: Introduces forest trusts, read-only DCs (RODCs).
    - **Windows Server 2008 R2**: Adds AD Recycle Bin.
    - **Windows Server 2016**: Supports Privileged Access Management (PAM).

**Example**: Upgrading to Windows Server 2016 functional level enables stronger Kerberos security but requires all DCs to run Server 2016 or later.

### Trusts

Trusts allow resource sharing between domains or forests.

**Types**:

1. **Parent-Child**: Automatic, transitive trust between domains in the same forest.
2. **Cross-Link**: Speeds up authentication between child domains.
3. **External**: Connects domains in different forests (non-transitive).
4. **Tree-Root**: Links root domains in a forest.
5. **Forest**: Transitive trust between forest root domains.

**Properties**:

- **Transitive**: Trust extends to domains trusted by the trusted domain.
- **Non-Transitive**: Trust is limited to the specified domains.
- **One-Way**: Only the trusted domain accesses resources.
- **Two-Way**: Both domains access each other’s resources.

**Security Note**: Misconfigured trusts (e.g., unnecessary bidirectional trusts from mergers) can create attack paths, such as Kerberoasting across domains.

### Diagram: Trusts

```
[Forest: inlanefreight.local] <--> [Forest: freightlogistics.local]
    |                                  |
    +-- [Domain: inlanefreight.local]      +-- [Domain: freightlogistics.local]
    |       |                              |       |
    |       +-- [OU: Employees]            |       +-- [OU: Staff]
    |       |       |                      |       |       |
    |       |       +-- [User: BJones]     |       |       +-- [User: JSmith]
    |       |                              |       |
    |       +-- [DC: DC01]                 |       +-- [DC: DC04]
    |                                      |
    +-- [Domain: corp.inlanefreight.local]  +-- [Domain: corp.freightlogistics.local]
            |                                      |
            +-- [DC: DC02]                        +-- [DC: DC05]

```

**Explanation**:

- A **bidirectional forest trust** allows users in `inlanefreight.local` to access resources in `freightlogistics.local` and vice versa.
- Child domains (`corp.inlanefreight.local`) inherit trusts within their forest but need explicit trusts to access other forests’ child domains.

**Practical Example**: After a merger, `inlanefreight.local` establishes a forest trust with `freightlogistics.local`. A user in `inlanefreight.local` can access a shared folder in `freightlogistics.local` if permissions allow.

### Replication

- **Purpose**: Ensures all DCs have consistent AD data.
- **Mechanism**: The Knowledge Consistency Checker (KCC) creates connection objects to manage replication between DCs.
- **Types**:
    - **Intra-site**: Fast replication within the same site.
    - **Inter-site**: Slower, optimized replication across sites.
- **Security Note**: Replication includes SYSVOL (GPOs, scripts), which, if misconfigured, can expose sensitive data.

**Example**: A user password change on `DC01` is replicated to `DC02` to ensure consistent authentication across the domain.

---

## 6. Security Considerations

AD’s centrality makes it a prime target for attackers. Understanding its vulnerabilities and mitigations is crucial.

### Common Vulnerabilities

1. **Misconfigurations**:
    - Weak ACLs granting excessive permissions.
    - Unnecessary trusts (e.g., bidirectional trusts from acquisitions).
    - Outdated functional levels retaining insecure features.
2. **Enumeration**:
    - Any domain user can query objects (users, groups, GPOs, trusts) using tools like PowerShell or BloodHound.
    - Example: Enumerating groups reveals nested memberships that may grant unintended access.
3. **Privilege Escalation**:
    - Exploits like Kerberoasting, noPac, PrintNightmare, or Zerologon escalate from user to admin privileges.
4. **Password Hashes**:
    - Stored in NTDS.DIT, extractable after DC compromise.
    - If “Store password with reversible encryption” is enabled, cleartext passwords are stored (rare but dangerous).
5. **Legacy Protocols**:
    - Older protocols (e.g., NTLM) are less secure than Kerberos.

### Attack Examples

1. **Kerberoasting**:
    - Targets SPNs of service accounts to request and crack Kerberos tickets offline.
    - Mitigation: Use strong passwords, enable gMSA.
2. **noPac (2021)**:
    - Exploits SAM RPC vulnerabilities to gain domain admin access.
    - Mitigation: Apply patches, monitor for suspicious activity.
3. **PrintNightmare (CVE-2021-34527)**:
    - Exploits print spooler to execute code with SYSTEM privileges.
    - Mitigation: Disable print spooler on DCs, apply patches.
4. **Zerologon (CVE-2020-1472)**:
    - Bypasses Netlogon authentication to compromise DCs.
    - Mitigation: Update DCs, enforce secure Netlogon settings.

### Mitigation Strategies

1. **Least Privilege**:
    - Restrict user permissions to only what’s needed.
    - Example: Don’t grant “Domain Admins” to regular users.
2. **Network Segmentation**:
    - Isolate DCs and critical systems from general access.
    - Example: Place DCs in a separate VLAN.
3. **Patching**:
    - Regularly update Windows Server to fix vulnerabilities.
4. **Group Managed Service Accounts (gMSA)**:
    - Automate password management for service accounts to prevent Kerberoasting.
5. **AD Recycle Bin**:
    - Enable to recover deleted objects with attributes intact.
6. **Monitor adminCount**:
    - Accounts with `adminCount=1` are privileged; audit them regularly.
7. **Secure Trusts**:
    - Limit trust scope, prefer one-way trusts, and review after mergers.
8. **Logging and Monitoring**:
    - Use System Access Control Lists (SACLs) to log access attempts.
    - Monitor for unusual activity (e.g., mass enumeration).
9. **Harden SYSVOL**:
    - Restrict access to scripts and policies in SYSVOL.
10. **Disable Legacy Features**:
    - Avoid NTLM, enforce Kerberos, and update functional levels.

**Practical Example**: To prevent Kerberoasting, configure service accounts with random, 25+ character passwords and use gMSA for automated tasks. Regularly audit SPNs with PowerShell:

```powershell
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName

```

---

## 7. Tools and Administration

AD administration and security testing rely on specialized tools.

### Management Tools

1. **Active Directory Users and Computers (ADUC)**:
    - GUI for managing users, groups, computers, and OUs.
    - Example: Create a new user or reset a password.
2. **ADSI Edit**:
    - Advanced GUI for editing AD objects and attributes.
    - **Caution**: Incorrect changes can break AD.
    - Example: Modify `dsHeuristics` to exclude groups from AdminSDHolder protection.
3. **PowerShell**:
    - Automates AD tasks (e.g., user creation, group membership queries).
    - Example: `Get-ADGroupMember -Identity "Domain Admins"`

### Penetration Testing Tools

1. **BloodHound**:
    - Maps AD attack paths by analyzing group memberships and permissions.
    - Example: Identifies a user with a path to Domain Admin via nested groups.
2. **Hashcat**:
    - Cracks password hashes extracted from NTDS.DIT.
    - Example: Cracks NTLM hashes to reveal weak passwords.
3. **Impacket**:
    - Performs attacks like Kerberoasting or pass-the-hash.
4. **PowerView**:
    - PowerShell tool for AD enumeration.
    - Example: `Get-NetUser` lists all users and their attributes.

### Key Files/Folders

1. **NTDS.DIT**:
    - Located at `C:\Windows\NTDS` on DCs.
    - Stores AD data, including password hashes.
    - **Security Note**: Protect DCs to prevent hash extraction.
2. **SYSVOL**:
    - Located at `C:\Windows\SYSVOL`.
    - Stores GPOs, scripts, and policies, replicated across DCs.
    - **Security Note**: Misconfigured permissions can expose sensitive scripts.
3. **AdminSDHolder**:
    - Container managing ACLs for privileged groups.
    - SDProp process (runs hourly) ensures correct ACLs.
    - **Security Note**: Attackers may target AdminSDHolder to persist access.

**Practical Example**: To audit privileged accounts, use PowerShell to find users with `adminCount=1`:

```powershell
Get-ADUser -Filter {adminCount -eq 1} -Properties adminCount,SamAccountName

```

---

## 8. History of AD

AD evolved from early directory services to a robust enterprise solution:

- **1971**: LDAP introduced via RFCs, laying the foundation for AD.
- **1990**: Windows NT 3.0 offers basic directory services with LAN Manager and OS/2 features.
- **1993**: Novell Directory Services (NDS) introduces hierarchical directory concepts.
- **1997**: First AD beta release.
- **2000**: AD debuts in Windows Server 2000, integrating LDAP and Kerberos.
- **2003**: Adds forest trusts, domain renaming, and read-only DCs.
- **2008**: Introduces AD Federation Services (ADFS) for Single Sign-On (SSO).
- **2016**: Enhances cloud integration with Azure AD Connect and adds gMSA for security.

**Security Note**: Legacy features (e.g., NTLM from NT 3.0) persist in modern AD, creating vulnerabilities if not disabled.

---

## 9. Practical Examples

### Example 1: Setting Up an OU and GPO

**Scenario**: Enforce a 15-minute screen lock for IT users.

1. Create an OU “IT” in `inlanefreight.local` using ADUC.
2. Move IT users (e.g., `john.doe`) to the OU.
3. Create a GPO “IT Screen Lock” with settings:
    - Computer Configuration > Policies > Administrative Templates > Control Panel > Personalization > Screen saver timeout: 900 seconds.
4. Link the GPO to the “IT” OU.
5. Verify enforcement with `gpupdate /force` on an IT user’s computer.

### Example 2: Enumerating AD as an Attacker

**Scenario**: An attacker with a standard user account enumerates AD.

1. Use PowerView to list all users:
    
    ```powershell
    Get-NetUser | Select-Object SamAccountName,displayName
    
    ```
    
2. Identify privileged groups:
    
    ```powershell
    Get-NetGroupMember -GroupName "Domain Admins"
    
    ```
    
3. Check for misconfigured shares in SYSVOL:
    
    ```powershell
    Get-NetShare
    
    ```
    
4. Use BloodHound to map attack paths, revealing a user with indirect admin access via nested groups.

### Example 3: Securing Against Kerberoasting

**Scenario**: Protect service accounts from Kerberoasting.

1. Identify accounts with SPNs:
    
    ```powershell
    Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName
    
    ```
    
2. Set strong passwords (25+ characters, random).
3. Convert eligible accounts to gMSA:
    
    ```powershell
    New-ADServiceAccount -Name "MyService" -DNSHostName "server.inlanefreight.local"
    
    ```
    
4. Monitor for Kerberos ticket requests using event logs.

---

## 10. Key Takeaways

- **AD is Central**: Manages authentication, authorization, and resource access in Windows networks.
- **Hierarchical Structure**: Forests > Domains > OUs > Objects, with DCs as the backbone.
- **Security is Paramount**: Misconfigurations and vulnerabilities (e.g., Kerberoasting, Zerologon) make AD a target.
- **Enumeration Power**: Even low-privileged users can map AD, necessitating strong defenses.
- **Defense-in-Depth**: Combine least privilege, segmentation, patching, and monitoring.
- **Practical Skills**: Master ADUC, PowerShell, and tools like BloodHound for administration and testing.
- **Continuous Learning**: Stay updated on vulnerabilities and best practices to secure AD.

---

## 11. Comprehensive Diagram: AD Ecosystem

```
[Forest: inlanefreight.local]
    |
    +-- [Domain: inlanefreight.local]
    |       |
    |       +-- [DC: DC01]
    |       |       |
    |       |       +-- [NTDS.DIT: Stores AD data, hashes]
    |       |       +-- [SYSVOL: GPOs, scripts]
    |       |
    |       +-- [OU: Employees]
    |       |       |
    |       |       +-- [OU: HR]
    |       |       |       |
    |       |       |       +-- [User: barbara.jones]
    |       |       |       +-- [Group: HR Staff]
    |       |       |
    |       |       +-- [OU: IT]
    |       |               |
    |       |               +-- [User: john.doe]
    |       |               +-- [GPO: IT Screen Lock]
    |       |
    |       +-- [OU: Resources]
    |       |       |
    |       |       +-- [Printer: Printer01]
    |       |       +-- [Shared Folder: DataShare]
    |       |
    |       +-- [OU: Computers]
    |               |
    |               +-- [Computer: FILE01]
    |               +-- [Computer: WS01]
    |
    +-- [Domain: corp.inlanefreight.local]
    |       |
    |       +-- [DC: DC02]
    |       +-- [OU: Dev]
    |               |
    |               +-- [User: dev.user]
    |               +-- [Group: Dev Team]
    |
    +-- [Forest Trust] <--> [Forest: freightlogistics.local]
                            |
                            +-- [Domain: freightlogistics.local]
                                    |
                                    +-- [DC: DC04]
                                    +-- [OU: Staff]
                                            |
                                            +-- [User: jsmith]

```

**Explanation**:

- **Forest**: Unifies all domains under `inlanefreight.local`.
- **DCs**: Store NTDS.DIT and SYSVOL, critical for AD operations.
- **OUs**: Organize objects and apply GPOs (e.g., “IT Screen Lock”).
- **Trusts**: Enable cross-forest access (e.g., `inlanefreight.local` to `freightlogistics.local`).
- **Objects**: Users, groups, computers, and resources form the AD ecosystem.

---

# Active Directory Comprehensive Notes

These notes summarize key Active Directory (AD) concepts from the provided documents, covering **User & Machine Accounts**, **AD Groups**, **AD Rights and Privileges**, **NTLM Authentication**, and **Kerberos, DNS, LDAP, MSRPC**. They are designed for beginners and professionals, offering clear explanations, practical examples, and security insights. Text-based diagrams illustrate relationships where applicable.

---

## 1. User & Machine Accounts

**Purpose**: User and machine accounts in AD enable authentication and resource access in Windows networks. User accounts represent individuals or services, while machine accounts represent domain-joined computers.

### User Accounts

- **Definition**: Security principals (with a Security Identifier, SID) created for people (employees, contractors) or programs (services) to log in and access resources.
- **Functionality**:
    - **Authentication**: Verifying identity via password, creating an **access token** containing the user’s SID and group memberships.
    - **Authorization**: The access token determines permissions for processes or resources (e.g., file shares, applications).
- **Types**:
    - **Standard Users**: Basic accounts with read-only access to most AD objects (default for Domain Users).
    - **Admin Accounts**: Elevated accounts (e.g., IT admins) with additional privileges.
    - **Service Accounts**: Run applications or services (e.g., SQL Server). Vulnerable to attacks like **Kerberoasting** if misconfigured.
- **Management**:
    - Provisioned per employee, sometimes multiple per user (e.g., standard and admin accounts for IT staff).
    - Disabled accounts (e.g., in “Former Employees” OU) are retained for audits but should have privileges removed.
- **Security Risks**:
    - **Misconfigurations**: Overly permissive rights (e.g., granting Domain Admin to a standard user).
    - **Human Error**: Weak passwords, shared credentials, or unauthorized software installation.
    - **Enumeration**: Standard users can query AD, exposing objects and potential attack paths.
- **Example**: An organization with 1,000 employees might have 1,200+ accounts (1 per employee, plus service accounts and disabled accounts).

### Machine Accounts

- **Definition**: Accounts for domain-joined computers, treated as security principals with SIDs.
- **Functionality**:
    - Authenticate computers to the domain, allowing access to resources like file servers.
    - Run under **NT AUTHORITY\SYSTEM** context, equivalent to a standard domain user for AD enumeration.
- **Security Note**: Compromising a machine account (e.g., via remote code execution) grants **SYSTEM**level access, enabling AD enumeration and further attacks.

### Local vs. Domain Accounts

- **Local Accounts**:
    - Stored on a single host (in the SAM database).
    - Rights are limited to that host; no domain-wide access.
    - **Default Accounts**:
        - **Administrator** (SID: S-1-5-domain-500): Full control, disabled by default on Windows 10/Server 2016.
        - **Guest**: Disabled by default, allows limited anonymous access (security risk if enabled).
        - **SYSTEM**: Runs OS services, has full control, not visible in User Manager.
        - **Network Service**: Runs services, presents credentials to remote systems.
        - **Local Service**: Runs services with minimal privileges, presents anonymous credentials.
- **Domain Accounts**:
    - Stored in AD’s NTDS.DIT database, accessible across the domain.
    - Managed centrally via Domain Controllers (DCs).
    - Example: **KRBTGT** account, a service account for Kerberos authentication, is a prime target for **Golden Ticket** attacks.

### User Naming Attributes

- **UserPrincipalName (UPN)**: Primary logon name, typically the user’s email (e.g., `htb-student@INLANEFREIGHT.LOCAL`).
- **SAMAccountName**: Legacy logon name for older Windows versions (e.g., `htb-student`).
- **ObjectGUID**: Unique 128-bit identifier (e.g., `aa799587-c641-4c23-a2f7-75850b4dd7e3`).
- **SID**: Security Identifier for authentication and group membership (e.g., `S-1-5-21-3842939050-3880317879-2865463114-1111`).
- **sIDHistory**: Tracks SIDs from previous domains (e.g., after migration), can be exploited for privilege escalation.

**Example Output**:

```powershell
Get-ADUser -Identity htb-student
DistinguishedName : CN=htb-student,CN=Users,DC=INLANEFREIGHT,DC=LOCAL
Enabled           : True
GivenName         : htb
ObjectGUID        : aa799587-c641-4c23-a2f7-75850b4dd7e3
SamAccountName    : htb-student
SID               : S-1-5-21-3842939050-3880317879-2865463114-1111
UserPrincipalName : htb-student@INLANEFREIGHT.LOCAL

```

### Domain-Joined vs. Non-Domain-Joined Machines

- **Domain-Joined**:
    - Managed by AD, receive Group Policy Objects (GPOs) for configurations.
    - Users can log in to any domain-joined host, accessing domain resources (e.g., file servers).
    - **Advantage**: Centralized management, seamless resource sharing.
- **Non-Domain-Joined (Workgroup)**:
    - Managed locally, no GPO application.
    - Resource sharing is complex; accounts are host-specific.
    - **Advantage**: User control over local changes, suitable for home or small networks.

**Security Note**: SYSTEM access on a domain-joined machine allows AD enumeration, equivalent to a standard user, making it a foothold for attacks.

---

## 2. AD Groups

**Purpose**: Groups simplify permission management by assigning rights and access to multiple users or computers at once, reducing administrative overhead.

### Group Types

- **Security Groups**:
    - Assign permissions to resources (e.g., file shares, printers).
    - All members inherit the group’s permissions.
    - Example: Granting “HR Staff” group read/write access to an HR folder.
- **Distribution Groups**:
    - Used for email distribution (e.g., Microsoft Exchange mailing lists).
    - Cannot assign permissions to resources.

### Group Scopes

- **Domain Local**:
    - Manages permissions within the same domain.
    - Can include users from other domains but not global groups.
    - Example: `Print Operators` (DomainLocal) manages printer access in one domain.
- **Global**:
    - Grants access across domains, contains only accounts from its domain.
    - Can be nested in other global or local groups.
    - Example: `Domain Admins` (Global) for domain-wide admin tasks.
- **Universal**:
    - Manages resources across multiple domains in a forest.
    - Stored in the Global Catalog, triggering forest-wide replication on changes.
    - Best practice: Include global groups as members to minimize replication.
    - Example: `Enterprise Admins` (Universal) for forest-wide administration.

**Scope Conversion Rules**:

- Global → Universal: Allowed if not nested in another global group.
- Domain Local → Universal: Allowed if no other domain local groups are members.
- Universal → Domain Local: No restrictions.
- Universal → Global: Allowed if no other universal groups are members.

**Example Output**:

```powershell
Get-ADGroup -Filter * | Select samaccountname,groupscope
samaccountname            groupscope
Administrators            DomainLocal
Print Operators           DomainLocal
Domain Admins             Global
Enterprise Admins          Universal
Schema Admins             Universal

```

### Built-in vs. Custom Groups

- **Built-in Groups**:
    - Created automatically with AD (e.g., `Domain Admins`, `Administrators`).
    - Domain Local groups (e.g., `Print Operators`) don’t allow group nesting.
    - Example: Add a user from another domain to `Administrators` (DomainLocal) for DC admin rights.
- **Custom Groups**:
    - Created for specific organizational needs (e.g., “Finance Team”).
    - Example: Microsoft Exchange adds privileged groups, which, if misconfigured, can be exploited.

### Nested Group Membership

- **Definition**: A group within another group, leading to inherited privileges.
- **Security Risk**: Unintended privileges via nesting (e.g., a user in “Help Desk” gains admin rights through a nested group).
- **Tool**: **BloodHound** visualizes nested memberships to identify attack paths.
- **Example**: User `oconner` in “Help Desk” inherits `Helpdesk Level 1` privileges, allowing them to add members to `Tier 1 Admins` (potentially granting local admin access).

### Important Group Attributes

- **cn**: Common Name (e.g., `Domain Admins`).
- **member**: Lists members (users, groups, contacts).
- **groupType**: Specifies type and scope (e.g., security, DomainLocal).
- **memberOf**: Lists groups this group is nested in.
- **objectSid**: Unique SID for the group.

**Diagram: Nested Group Membership**

```
[Group: Help Desk]
    |
    +-- [User: oconner]
    +-- [Group: Helpdesk Level 1]
            |
            +-- [Privilege: Add member to Tier 1 Admins]
                    |
                    +-- [Potential: Local admin access]

```

**Security Note**: Regularly audit group memberships and scopes to prevent excessive privileges. Tools like BloodHound are critical for uncovering hidden risks.

---

## 3. AD Rights and Privileges

**Purpose**: Rights and privileges govern what users and groups can access or do in AD, forming the backbone of security and administration.

### Rights vs. Privileges

- **Rights**: Permissions to access objects (e.g., read a file, modify a GPO).
- **Privileges**: Permissions to perform actions (e.g., shut down a system, debug a process).
- **User Rights Assignment**: Windows term for privileges assigned via GPOs or group membership.

### Built-in Security Groups

- **Purpose**: Grant specific rights and privileges, some highly privileged (e.g., `Domain Admins`).
- **Examples**:
    - **Administrators** (DomainLocal): Full control on a host or domain (if on a DC).
    - **Domain Admins** (Global): Full domain control, members include service accounts and admins.
    - **Enterprise Admins** (Universal): Full forest control.
    - **Server Operators** (DomainLocal): Manage services, SMB shares, and backups on DCs (no members by default).
    - **Group Policy Creator Owners**: Create/edit GPOs.
    - **Protected Users**: Enhanced security against credential theft (e.g., Kerberos attacks).
    - **Remote Desktop Users**: Grants RDP access.
    - **Backup Operators**: Create backups, can access sensitive files (e.g., NTDS.DIT).

**Example Output: Server Operators**:

```powershell
Get-ADGroup -Identity "Server Operators" -Properties *
CanonicalName    : INLANEFREIGHT.LOCAL/Builtin/Server Operators
GroupScope       : DomainLocal
Members          : {}
Description      : Members can administer domain servers
ObjectGUID       : 8887487b-7b07-4d85-82ad-40d25526ec17
SID              : S-1-5-32-549

```

**Example Output: Domain Admins**:

```powershell
Get-ADGroup -Identity "Domain Admins" -Properties *
DistinguishedName : CN=Domain Admins,CN=Users,DC=INLANEFREIGHT,DC=LOCAL
GroupScope        : Global
Members           : {htb-student_adm, sharepoint_admin, FREIGHTLOGISTICSUSER, PROXYAGENT}

```

**Security Note**: Overly permissive group membership (e.g., adding a standard user to `Domain Admins`) is a common flaw exploitable for privilege escalation.

### User Rights Assignment

- **Purpose**: Assign privileges via GPOs or group membership, impacting security.
- **Dangerous Privileges**:
    - **SeRemoteInteractiveLogonRight**: Allows RDP access, potentially exposing sensitive data.
    - **SeBackupPrivilege**: Creates backups, can access SAM, SYSTEM, or NTDS.DIT files.
    - **SeDebugPrivilege**: Debugs processes, can read LSASS memory (e.g., using Mimikatz) for credentials.
    - **SeImpersonatePrivilege**: Impersonates privileged accounts (e.g., SYSTEM) using tools like JuicyPotato.
    - **SeLoadDriverPrivilege**: Loads/unloads drivers, potentially for privilege escalation.
    - **SeTakeOwnershipPrivilege**: Takes ownership of objects (e.g., file shares).

**Example**: Gaining write access to a GPO allows assigning `SeDebugPrivilege` to a user, enabling credential theft via LSASS.

### Viewing Privileges

- **Command**: `whoami /priv` lists a user’s privileges.
- **Standard User** (limited rights):
    
    ```powershell
    whoami /priv
    Privilege Name                Description                    State
    SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
    SeIncreaseWorkingSetPrivilege Increase a process working set Disabled
    
    ```
    
- **Domain Admin (Non-Elevated)**:
    
    ```powershell
    whoami /priv
    Privilege Name                Description                    State
    SeShutdownPrivilege           Shut down the system           Disabled
    SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
    SeUndockPrivilege             Remove computer from docking   Disabled
    SeIncreaseWorkingSetPrivilege Increase a process working set Disabled
    
    ```
    
- **Backup Operator**:
    
    ```powershell
    whoami /priv
    Privilege Name                Description                    State
    SeShutdownPrivilege           Shut down the system           Disabled
    SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
    SeIncreaseWorkingSetPrivilege Increase a process working set Disabled
    
    ```
    
    - Note: `SeBackupPrivilege` is available but disabled by default (requires elevated context).

**Security Note**: **User Account Control (UAC)** restricts privileges in non-elevated sessions, requiring elevated CMD/PowerShell for full access. Misassigned privileges (e.g., `SeBackupPrivilege`) can lead to system compromise.

**Mitigation**:

- Keep privileged groups empty unless needed.
- Use separate accounts for admin tasks (not daily use).
- Assign strong passwords to privileged accounts.
- Monitor group membership and privilege assignments.

---

## 4. NTLM Authentication

**Purpose**: NTLM (NT LAN Manager) is a challenge-response authentication protocol used in AD alongside Kerberos and LDAP, primarily for legacy or non-Kerberos scenarios.

### Hash Types

- **LM (LAN Manager)**:
    - **Introduced**: 1987 (OS/2).
    - **Storage**: SAM (local) or NTDS.DIT (DC).
    - **Weaknesses**:
        - Limited to 14 characters, uppercase only (69-character keyspace).
        - Splits passwords into two 7-character chunks, encrypted with DES and “KGS!@#$%”.
        - Easily cracked with tools like **Hashcat** (second half predictable for <7-character passwords).
    - **Status**: Disabled by default since Windows Vista/Server 2008 but persists in legacy systems.
    - **Example**: `299bd128c1101fd6`.
    - **Mitigation**: Disable via GPO.
- **NT (NTHash)**:
    - **Algorithm**: MD4 hash of little-endian UTF-16 password.
    - **Storage**: SAM or NTDS.DIT.
    - **Strength**: Stronger than LM, supports longer passwords and case sensitivity.
    - **Example**: `88dcbe4446168966a153a0064958dac6`.

### Authentication Protocols

- **NTLM Process**:
    1. Client sends **NEGOTIATE_MESSAGE** to the server.
    2. Server responds with **CHALLENGE_MESSAGE** (random number).
    3. Client sends **AUTHENTICATE_MESSAGE** using LM or NT hash.
- **NTLMv1**:
    - Uses both LM and NT hashes.
    - **Algorithm**: `response = DES(K1,C) | DES(K2,C) | DES(K3,C)` (C = 8-byte challenge).
    - **Weakness**: Captured hashes (e.g., via Responder) can be cracked offline; not suitable for pass-the-hash.
    - **Example**: `u4-netntlm::kNS:338d08f8e26de933...:5c7830315c783031...`.
- **NTLMv2**:
    - Improved security with a more complex challenge-response.
    - **Algorithm**: Uses NT hash, adds client nonce and timestamp.
    - **Example**: `admin::N46iSNekpT:08ca45b7d7ea58ee:88dcbe4446168966...`.
    - **Strength**: Harder to crack, still vulnerable to relay attacks.

**Comparison**:

| Protocol | Crypto | Mutual Auth | Message Type | Trusted Third Party |
| --- | --- | --- | --- | --- |
| NTLM | Symmetric | No | Random number | DC |
| NTLMv1 | Symmetric | No | LM/NT hash, random | DC |
| NTLMv2 | Symmetric | No | NT hash, random, nonce | DC |
| Kerberos | Symmetric & Asymmetric | Yes | Encrypted ticket | DC/KDC |

**Security Risks**:

- **Cracking**: LM and NTLMv1 hashes are easily cracked.
- **Relay Attacks**: NTLMv2 hashes can be relayed to other systems.
- **Pass-the-Hash**: NT hashes can be used directly for authentication (unlike Net-NTLM hashes).
- **Mitigation**: Prefer Kerberos, disable LM/NTLMv1, enforce signing.

### Domain Cached Credentials (MSCache2)

- **Purpose**: Allows authentication when a DC is unavailable (e.g., network outage).
- **Storage**: Local host, cached after domain login.
- **Strength**: Very slow to crack (even with GPUs), requires targeted attacks or weak passwords.
- **Weakness**: Extractable with local admin access, not suitable for pass-the-hash.
- **Example**: Requires admin access to extract via tools like Mimikatz.

**Security Note**: NTLM’s lack of mutual authentication and reliance on hashes make it less secure than Kerberos. Legacy systems using LM/NTLMv1 are prime targets.

---

## 5. Kerberos, DNS, LDAP, MSRPC

**Purpose**: These protocols underpin AD’s authentication, communication, and directory services, critical for both functionality and security.

### Kerberos

- **Definition**: Default authentication protocol since Windows 2000, using tickets for secure, stateless authentication.
- **Components**:
    - **Key Distribution Center (KDC)**: Runs on DCs, issues tickets (uses **KRBTGT** account).
    - **Ticket Granting Ticket (TGT)**: Proves user identity, requested via **AS-REQ** and returned in **AS-REP**.
    - **Ticket Granting Service (TGS)**: Grants access to specific services, requested via **TGS-REQ** and returned in **TGS-REP**.
- **Process**:
    1. User’s password is hashed (NTLM) to encrypt an **AS-REQ** for a TGT.
    2. KDC decrypts AS-REQ, verifies user, and sends TGT (AS-REP).
    3. User presents TGT to request a TGS for a service (TGS-REQ).
    4. KDC validates TGT, encrypts TGS with the service’s NTLM hash, and sends it (TGS-REP).
    5. User presents TGS to the service (AP-REQ), which decrypts it and grants access.
- **Port**: 88 (TCP/UDP).
- **Security Risks**:
    - **Golden Ticket**: Forging a TGT using KRBTGT’s hash grants unlimited access.
    - **Kerberoasting**: Requests TGS tickets for service accounts to crack offline.
- **Mitigation**: Use strong service account passwords, enable **Protected Users** group, monitor ticket requests.

**Diagram: Kerberos Authentication**

```
[Client]
   | 1. AS-REQ (password-hashed)
   v
[DC/KDC]
   | 2. AS-REP (TGT)
   | 3. TGS-REQ (present TGT)
   | 4. TGS-REP (TGS encrypted with service hash)
   v
[Service]
   | 5. AP-REQ (present TGS)
   | Access granted

```

### DNS

- **Purpose**: Resolves hostnames to IP addresses, enabling clients to locate DCs and services via **Service Records (SRV)**.
- **Dynamic DNS**: Automatically updates IP changes, reducing manual errors.
- **Ports**: 53 (UDP default, TCP for large messages).
- **Process**:
    1. Client queries DNS for a DC’s SRV record.
    2. DNS returns the DC’s hostname.
    3. Client resolves the hostname to an IP address.
- **Example**:
    
    ```powershell
    nslookup INLANEFREIGHT.LOCAL
    Name: INLANEFREIGHT.LOCAL
    Address: 172.16.6.5
    
    ```
    
- **Security Note**: Incorrect DNS records can disrupt AD communication; attackers may target DNS for spoofing.

### LDAP

- **Definition**: Lightweight Directory Access Protocol for directory lookups and authentication in AD.
- **Ports**: 389 (LDAP), 636 (LDAPS for SSL).
- **Functionality**:
    - Stores and shares user/security information (e.g., passwords, attributes).
    - Applications query AD via LDAP (e.g., for authentication).
- **Authentication Types**:
    - **Simple**: Uses username/password for BIND (sent in cleartext unless encrypted).
    - **SASL**: Uses Kerberos for BIND, adding security via challenge-response.
- **Security Risks**:
    - Cleartext LDAP messages can be sniffed; use LDAPS.
    - Misconfigured LDAP permissions can expose sensitive attributes.
- **Analogy**: AD is a directory server (like Apache for HTTP), and LDAP is the protocol it uses.

### MSRPC

- **Definition**: Microsoft’s Remote Procedure Call for client-server communication in AD.
- **Interfaces**:
    - **lsarpc**: Manages security policies and accounts.
    - **samr**: Handles user/group management.
    - **drsuapi**: Manages directory replication.
    - **netlogon**: Manages domain authentication and trusts.
- **Security Note**: Vulnerabilities like **Zerologon** (CVE-2020-1472) exploit MSRPC (Netlogon), allowing DC compromise.

**Security Note**: Kerberos is preferred for its mutual authentication and ticket-based security. LDAP and MSRPC require encryption and monitoring to prevent sniffing or exploitation.

---

## 6. Security Considerations

### Common Vulnerabilities

- **User Accounts**:
    - Weak passwords, shared credentials, or misconfigured rights (e.g., granting `SeDebugPrivilege`).
    - Standard users can enumerate AD, exposing objects and relationships.
- **Groups**:
    - Nested memberships granting unintended privileges.
    - Overpopulated privileged groups (e.g., `Domain Admins` with standard users).
- **Privileges**:
    - Dangerous privileges (e.g., `SeBackupPrivilege`, `SeImpersonatePrivilege`) enable escalation.
    - Misconfigured GPOs assigning excessive rights.
- **Authentication**:
    - **NTLM**: Vulnerable to cracking, relaying, and pass-the-hash.
    - **Kerberos**: Golden Ticket and Kerberoasting attacks target KRBTGT and service accounts.
    - **LDAP**: Cleartext messages expose credentials if not encrypted.
- **Legacy Systems**: LM/NTLMv1 usage in older systems increases attack surface.

### Mitigation Strategies

1. **User & Machine Accounts**:
    - Enforce strong passwords, disable unnecessary accounts (e.g., Guest).
    - Regularly audit disabled accounts and remove privileges.
    - Use **group Managed Service Accounts (gMSA)** for services to prevent Kerberoasting.
2. **Groups**:
    - Audit memberships with BloodHound to detect nested privilege issues.
    - Keep privileged groups (e.g., `Domain Admins`) empty unless needed.
    - Use Domain Local groups for specific permissions, Global/Universal for broader access.
3. **Rights & Privileges**:
    - Restrict dangerous privileges (e.g., `SeDebugPrivilege`) to essential users.
    - Use UAC to limit privilege exposure in non-elevated sessions.
    - Monitor GPO assignments for unintended rights.
4. **Authentication**:
    - **NTLM**: Disable LM/NTLMv1, enforce NTLMv2 or Kerberos.
    - **Kerberos**: Protect KRBTGT account, use long passwords for service accounts.
    - **LDAP**: Enable LDAPS, restrict LDAP query permissions.
    - **MSRPC**: Patch vulnerabilities (e.g., Zerologon), monitor RPC traffic.
5. **General**:
    - Segment networks to isolate DCs.
    - Apply patches for known exploits (e.g., PrintNightmare, noPac).
    - Enable logging (e.g., SACLs) to detect enumeration or privilege abuse.

**Example: Auditing Privileged Groups**:

```powershell
Get-ADGroupMember -Identity "Domain Admins" | Select Name,SamAccountName

```

**Example: Disabling LM Hashes**:

- GPO: Computer Configuration > Policies > Windows Settings > Security Settings > Local Policies > Security Options > Network security: Do not store LAN Manager hash value on next password change.

---

## 7. Practical Examples

### Example 1: Creating a Security Group

**Scenario**: Grant HR staff access to a shared folder.

1. Create a security group “HR Staff” (Global scope) in ADUC.
2. Add HR users (e.g., `barbara.jones`) to the group.
3. Assign read/write permissions to “HR Staff” on the folder’s ACL.
4. Verify access by logging in as `barbara.jones`.

### Example 2: Enumerating AD as an Attacker

**Scenario**: A standard user enumerates AD.

1. List all users:
    
    ```powershell
    Get-ADUser -Filter * | Select SamAccountName,UserPrincipalName
    
    ```
    
2. Check privileged group membership:
    
    ```powershell
    Get-ADGroupMember -Identity "Domain Admins"
    
    ```
    
3. Use BloodHound to map nested memberships and identify escalation paths.

### Example 3: Securing Kerberos

**Scenario**: Protect against Kerberoasting.

1. Identify service accounts with SPNs:
    
    ```powershell
    Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName
    
    ```
    
2. Set random, 25+ character passwords or convert to gMSA:
    
    ```powershell
    New-ADServiceAccount -Name "MyService" -DNSHostName "server.inlanefreight.local"
    
    ```
    
3. Add critical accounts to **Protected Users** group to block NTLM and weak Kerberos encryption.

### Example 4: Checking User Privileges

**Scenario**: Verify a user’s privileges.

1. Log in as the user and run:
    
    ```powershell
    whoami /priv
    
    ```
    
2. Elevate to admin context (if applicable) and rerun to see additional privileges.
3. Audit for dangerous privileges (e.g., `SeBackupPrivilege`) and remove if unnecessary.

---

## 8. Key Takeaways

- **User & Machine Accounts**: Central to AD authentication; misconfigurations (e.g., weak passwords, excessive rights) are exploitable.
- **Groups**: Simplify permission management but require careful scoping and auditing to prevent unintended privileges.
- **Rights & Privileges**: Critical for security; dangerous privileges (e.g., `SeDebugPrivilege`) enable escalation if misassigned.
- **NTLM Authentication**: Legacy protocol, vulnerable to cracking and relaying; prefer Kerberos.
- **Kerberos, DNS, LDAP, MSRPC**: Core AD protocols; secure configurations (e.g., LDAPS, strong KRBTGT passwords) are essential.
- **Security**: Regular audits, strong passwords, minimal privileges, and modern protocols (Kerberos over NTLM) reduce attack surface.
- **Tools**: Use PowerShell, BloodHound, and monitoring to manage and secure AD.

---

## 9. Comprehensive Diagram: AD Authentication Flow

```
[Client]
   | 1. Kerberos: AS-REQ (NTLM hash of password)
   | 2. NTLM: NEGOTIATE_MESSAGE
   v
[DC/KDC]
   | Kerberos: AS-REP (TGT)
   | NTLM: CHALLENGE_MESSAGE
   | LDAP: BIND (Simple/SASL)
   | DNS: SRV record for DC
   | MSRPC: Policy/account management
   | 3. Kerberos: TGS-REQ (present TGT)
   | 4. NTLM: AUTHENTICATE_MESSAGE
   v
[Service]
   | Kerberos: AP-REQ (TGS encrypted with service hash)
   | NTLM: Validates response
   | Access granted

```

**Explanation**:

- **Kerberos**: Ticket-based, secure, uses ports 88 and KRBTGT account.
- **NTLM**: Challenge-response, less secure, used for legacy systems.
- **LDAP**: Queries AD, requires encryption (LDAPS) to prevent sniffing.
- **DNS**: Resolves DC/services, critical for AD functionality.
- **MSRPC**: Manages policies and replication, vulnerable if unpatched.

---

# Active Directory Security and Group Policy Notes

## 1. Active Directory Security Overview

**Purpose**: Active Directory (AD) is designed for centralized management and rapid information sharing, prioritizing **Availability** and **Confidentiality** in the CIA Triad (Confidentiality, Integrity, Availability). However, its default configuration is insecure, requiring hardening to balance **Integrity** and reduce vulnerabilities.

### CIA Triad in AD Context

- **Confidentiality**: Protecting sensitive data (e.g., user credentials, AD objects).
- **Integrity**: Ensuring AD data and configurations remain unaltered by unauthorized entities.
- **Availability**: Ensuring AD services are accessible for legitimate users.
- **Challenge**: AD’s focus on availability (e.g., allowing standard users to enumerate objects) can compromise confidentiality and integrity without proper hardening.

**Security Note**: A default AD installation lacks many security measures, making it vulnerable to attacks like **password spraying**, **Kerberoasting**, or **privilege escalation**. Hardening requires enabling built-in features, applying best practices, and maintaining a defense-in-depth strategy (e.g., asset inventories, patching, endpoint protection, network segmentation).

---

## 2. General AD Hardening Measures

**Purpose**: Harden AD to mitigate common attack vectors, ensuring a secure environment while maintaining functionality.

### Microsoft Local Administrator Password Solution (LAPS)

- **Function**: Randomizes and rotates local administrator passwords on Windows hosts to prevent lateral movement.
- **Configuration**: Passwords rotate at fixed intervals (e.g., every 12 or 24 hours).
- **Benefits**:
    - Reduces impact of a compromised host by ensuring unique local admin passwords.
    - Centralized management via AD.
- **Limitations**: Not a standalone solution; must be combined with other security measures.
- **Example**: A compromised workstation’s local admin password is useless on other hosts due to LAPS rotation.

### Audit Policy Settings (Logging and Monitoring)

- **Purpose**: Detect and respond to unauthorized activities or attacks.
- **Capabilities**:
    - Monitor user/computer additions, object modifications, password changes, or unauthorized access.
    - Detect attacks like **password spraying** (multiple login attempts) or **Kerberoasting** (TGS ticket extraction).
- **Implementation**:
    - Enable logging via GPOs or Advanced Audit Policy Configuration.
    - Use Security Information and Event Management (SIEM) tools for real-time analysis.
- **Example**: Log failed logins to detect password spraying:
    
    ```powershell
    Get-WinEvent -LogName "Security" | Where-Object {$_.Id -eq 4625}
    
    ```
    
- **Security Note**: Robust logging is critical for identifying AD enumeration or privilege abuse.

### Group Managed Service Accounts (gMSA)

- **Function**: Secure service accounts for non-interactive applications, services, or tasks.
- **Features**:
    - Automatic password management with 120-character passwords generated by the Domain Controller (DC).
    - Passwords rotate regularly (no user interaction required).
    - Credentials usable across multiple hosts.
- **Benefits**:
    - Reduces risk of **Kerberoasting** by using strong, managed passwords.
    - Eliminates manual password management for service accounts.
- **Example**: A SQL Server service uses a gMSA (`svc-sql`) with an auto-rotating password, preventing credential theft.

### Security Groups

- **Purpose**: Assign granular permissions to groups rather than individual users, simplifying access control.
- **Types**:
    - **Default Groups**: Created during AD installation (e.g., `Domain Admins`, `Administrators`, `Backup Operators`, `Domain Users`).
    - **Custom Groups**: Created for specific needs (e.g., “HR Staff” for file share access).
- **Usage**:
    - Assign rights to perform actions (e.g., RDP access).
    - Grant resource access (e.g., folders, printers).
- **Example**: Grant “HR Staff” group read/write access to an HR folder:
    
    ```powershell
    $acl = Get-Acl "\\server\HRShare"
    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule("HR Staff","Modify","Allow")
    $acl.AddAccessRule($rule)
    Set-Acl "\\server\HRShare" $acl
    
    ```
    

### Account Separation

- **Practice**: Administrators use two accounts:
    - **Standard Account**: For daily tasks (e.g., email, browsing).
    - **Admin Account**: For administrative tasks (e.g., managing AD objects).
- **Benefits**:
    - Limits exposure of privileged credentials if a standard account is compromised (e.g., via phishing).
    - Prevents admin credentials from residing in memory on non-secure hosts.
- **Example**: User `jdoe` uses `jdoe` for email and `jdoe_adm` for DC management, with distinct passwords.
- **Security Note**: Enforce different passwords to mitigate password reuse attacks.

### Password Complexity Policies, Passphrases, and MFA

- **Challenges**:
    - Default complexity (e.g., 7-8 characters, 3 of 4 categories: uppercase, lowercase, numbers, special) is insufficient.
    - Weak passwords (e.g., `Welcome1`) meet complexity but are easily cracked via **Hashcat** or guessed in **password spraying**.
- **Recommendations**:
    - **Minimum Length**: 12+ characters for standard users, longer for admins/service accounts.
    - **Passphrases**: Use random, long phrases (e.g., `BlueSky$RainyDay2025!`) or password managers.
    - **Password Filters**: Block common words (e.g., “password”, company name, seasons).
    - **Multi-Factor Authentication (MFA)**: Require for Remote Desktop (RDP) to limit lateral movement.
- **Example**: Password policy GPO:
    
    ```powershell
    Set-GPRegistryValue -Name "Default Domain Policy" -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\PasswordComplexity" -ValueName "MinimumPasswordLength" -Type DWord -Value 12
    
    ```
    
- **Security Note**: Short passwords are vulnerable to offline cracking; MFA significantly reduces RDP-based attacks.

### Limiting Domain Admin Account Usage

- **Practice**: Restrict `Domain Admins` logins to Domain Controllers only.
- **Benefits**:
    - Prevents admin credentials from being stored in memory on workstations or servers.
    - Reduces attack paths (e.g., credential theft via Mimikatz).
- **Example**: Configure GPO to deny `Domain Admins` login on non-DC hosts:
    
    ```powershell
    Set-GPRegistryValue -Name "Restrict DA Login" -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" -ValueName "DenyLogonLocally" -Type MultiString -Value "Domain Admins"
    
    ```
    

### Auditing and Removing Stale Users/Objects

- **Purpose**: Disable or remove unused accounts/objects to reduce attack surface.
- **Risks**:
    - Stale accounts (e.g., old service accounts with weak passwords) are targets for **password spraying** or **privilege escalation**.
- **Process**:
    - Identify inactive accounts:
        
        ```powershell
        Get-ADUser -Filter {Enabled -eq $true -and LastLogonDate -lt (Get-Date).AddDays(-90)} | Select SamAccountName,LastLogonDate
        
        ```
        
    - Disable or delete as needed:
        
        ```powershell
        Disable-ADAccount -Identity "stale_user"
        
        ```
        
- **Example**: An 8-year-old service account with a weak password is disabled to prevent exploitation.

### Auditing Permissions and Access

- **Purpose**: Ensure users have least-privilege access.
- **Focus Areas**:
    - Local admin rights (avoid granting to `Domain Users`).
    - Number of `Domain Admins` (minimize, e.g., <5 in a small organization).
    - File share access and privileged group memberships.
- **Example**: Audit `Domain Admins` membership:
    
    ```powershell
    Get-ADGroupMember -Identity "Domain Admins" | Select Name,SamAccountName
    
    ```
    

### Using Restricted Groups

- **Function**: Control group memberships via GPOs.
- **Use Cases**:
    - Restrict local `Administrators` group to `Local Administrator` and `Domain Admins`.
    - Control membership in `Enterprise Admins` or `Schema Admins`.
- **Example**: GPO to restrict local `Administrators`:
    
    ```powershell
    Set-GPRegistryValue -Name "Restricted Groups" -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\GroupPolicy\RestrictedGroups" -ValueName "Administrators" -Type MultiString -Value "Domain Admins,Administrator"
    
    ```
    

### Limiting Server Roles

- **Practice**: Avoid installing unnecessary roles on sensitive hosts (e.g., no IIS on DCs).
- **Benefits**:
    - Reduces attack surface by limiting exposed services.
    - Isolates critical functions (e.g., separate web and database servers).
- **Example**: Install IIS on a dedicated web server, not a DC or Exchange server.

### Limiting Local Admin and RDP Rights

- **Risks**:
    - Granting `Domain Users` local admin rights allows attackers to escalate privileges.
    - Broad RDP access increases risk of credential theft or lateral movement.
- **Mitigation**:
    - Use Restricted Groups to limit local admin rights.
    - Restrict RDP access via GPO:
        
        ```powershell
        Set-GPRegistryValue -Name "Restrict RDP" -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -ValueName "DenyLogon" -Type MultiString -Value "Domain Users"
        
        ```
        
- **Example**: Only IT staff have RDP access to servers, enforced via a security group.

**Security Note**: These measures are the bare minimum. Combine with general security practices (e.g., vulnerability management, security awareness training) for a robust defense-in-depth strategy.

---

## 3. Group Policy Overview

**Purpose**: Group Policy is a Windows feature for managing and securing user and computer settings in AD, critical for both administration and security.

### Group Policy Objects (GPOs)

- **Definition**: Virtual collections of policy settings applied to users, computers, or groups at the OU, domain, or site level.
- **Attributes**:
    - **Unique Name**: Human-readable (e.g., “Password Policy”).
    - **GUID**: Unique identifier (e.g., `6b3e5f2a-8c9d-4e1b-9f3c-7d2a1b8c4e5f`).
- **Scope**:
    - Linked to OUs, domains, or sites.
    - Multiple GPOs can apply to one container; one GPO can link to multiple containers.
- **Settings**:
    - **Computer Configuration**: Applies to hosts (e.g., disable USB ports).
    - **User Configuration**: Applies to users (e.g., screen lock timeout).
- **Examples**:
    - Enforce password complexity.
    - Disable removable media.
    - Restrict applications (e.g., block `cmd.exe` for standard users).
    - Deploy software or scripts.
    - Set audit/logging policies.

**Example GPO Settings**:

- Password policy (Windows Server 2008 default):
    - Minimum 7 characters.
    - 3 of 4 categories (uppercase, lowercase, numbers, special).
- RDP settings:
    - Require Network Level Authentication.
    - Limit session duration.

### GPO Management

- **Tools**:
    - **Group Policy Management Console (GPMC)**: GUI for creating/editing GPOs.
    - **PowerShell GroupPolicy Module**: Command-line management.
        
        ```powershell
        Get-GPO -All | Select DisplayName,Id
        
        ```
        
- **Default GPOs**:
    - **Default Domain Policy**: Applies domain-wide settings (e.g., password policy).
    - **Default Domain Controllers Policy**: Sets security/auditing for DCs.
- **Best Practice**: Use `Default Domain Policy` for broad settings; create custom GPOs for specific OUs.

### GPO Processing and Precedence

- **Order of Precedence**:
    
    
    | Level | Description | Priority |
    | --- | --- | --- |
    | Local Group Policy | Local host settings | Lowest (overridden by higher levels) |
    | Site Policy | Applies to AD sites | Higher than local |
    | Domain-wide Policy | Applies to entire domain | Higher than site |
    | Organizational Unit (OU) | Applies to specific OUs | Higher than domain |
    | Nested OU Policies | Applies to child OUs | Highest (processed last) |
- **Rules**:
    - GPOs are processed top-down (domain → OU → nested OU).
    - Settings in a lower-level GPO (e.g., OU) override higher-level GPOs (e.g., domain).
    - **Computer Configuration** settings take precedence over **User Configuration** for the same setting.
    - **Link Order**: For multiple GPOs on one OU, the lowest link order (e.g., 1) is processed last (highest precedence).
- **Special Options**:
    - **Enforced**: Prevents lower-level GPOs from overriding settings.
        - Example: An enforced domain-level GPO (e.g., “Logon Banner”) applies to all OUs.
    - **Block Inheritance**: Prevents higher-level GPOs from applying to an OU (except enforced GPOs).
    - **Default Domain Policy**: Always takes precedence if enforced.
- **Refresh Interval**:
    - Default: Every 90 minutes (±30 minutes random offset) to avoid DC overload.
    - Manual refresh: `gpupdate /force`.
    - Configurable via GPO:
        
        ```powershell
        Set-GPRegistryValue -Name "GPO Refresh" -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" -ValueName "GroupPolicyRefreshTime" -Type DWord -Value 60
        
        ```
        
    - **Caution**: Frequent refreshes can cause network congestion.

**Diagram: GPO Precedence**

```
[Domain]
   | GPO: Default Domain Policy (Enforced)
   | GPO: Logon Banner (Link Order 2)
   v
[OU: Corp]
   | GPO: Disabled Forced Restarts (Link Order 1, processed last)
   | GPO: Password Policy (Link Order 3)
   v
[OU: Computers] (Block Inheritance)
   | GPO: Restrict CMD Access

```

**Example**: In the above, `Disabled Forced Restarts` overrides `Logon Banner` for the Corp OU due to link order. `Default Domain Policy` (enforced) applies to all OUs, and `Computers` OU blocks inheritance from `Corp` (except enforced GPOs).

---

## 4. GPO Security Settings

**Purpose**: GPOs enforce security policies to harden AD and reduce attack surface.

### Account Policies

- **Settings**:
    - **Password Policy**: Minimum length, complexity, history.
    - **Account Lockout Policy**: Threshold for failed logins, lockout duration.
    - **Kerberos Policy**: Ticket lifetime, renewal settings.
- **Example**: Set minimum password length to 12:
    
    ```powershell
    Set-GPRegistryValue -Name "Default Domain Policy" -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\PasswordComplexity" -ValueName "MinimumPasswordLength" -Type DWord -Value 12
    
    ```
    

### Local Policies

- **Settings**:
    - **Audit Policy**: Log security events (e.g., logon failures).
    - **User Rights Assignment**: Assign privileges (e.g., `SeRemoteInteractiveLogonRight` for RDP).
    - **Security Options**: Disable Guest account, rename Administrator, block removable media.
- **Example**: Disable Guest account:
    
    ```powershell
    Set-GPRegistryValue -Name "Security Settings" -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\Guest" -ValueName "Enabled" -Type DWord -Value 0
    
    ```
    

### Software Restriction Policies

- **Function**: Control executable software on hosts.
- **Example**: Block `cmd.exe` for standard users:
    
    ```powershell
    Set-GPRegistryValue -Name "Software Restriction" -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers" -ValueName "Disallowed" -Type String -Value "cmd.exe"
    
    ```
    

### Application Control Policies (AppLocker)

- **Function**: Restrict applications by user/group.
- **Use Cases**:
    - Block executables, scripts, or Windows Installer files for non-admins.
    - Prevent standard users from running `PowerShell`.
- **Limitations**: Can be bypassed (e.g., via alternate execution methods).
- **Example**: Block `PowerShell` for `Domain Users`:
    
    ```powershell
    New-AppLockerPolicy -RuleType Publisher -User "Domain Users" -Deny -FilePath "powershell.exe"
    
    ```
    

### Advanced Audit Policy Configuration

- **Settings**:
    - Audit file access/modification, account logon/logoff, policy changes, or privilege usage.
- **Example**: Audit privilege use:
    
    ```powershell
    Set-GPRegistryValue -Name "Audit Policy" -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\Audit" -ValueName "AuditPrivilegeUse" -Type DWord -Value 1
    
    ```
    

**Security Note**: GPOs are critical for enforcing security but require careful configuration to avoid misconfigurations that attackers can exploit.

---

## 5. Security Risks and Attack Vectors

### AD Security Risks

- **Weak Passwords**: Short or predictable passwords (e.g., `Welcome1`) are vulnerable to **password spraying** or offline cracking.
- **Excessive Privileges**: Overpopulated `Domain Admins` or broad local admin rights increase attack surface.
- **Stale Accounts**: Unused accounts with weak passwords are easy targets.
- **Unsecured Protocols**: Cleartext LDAP or NTLMv1 enable credential sniffing.
- **Misconfigured GPOs**: Granting excessive rights (e.g., `SeDebugPrivilege`) via GPOs can lead to escalation.

### GPO-Specific Attack Vectors

- **GPO Modification**:
    - Attackers with GPO edit rights can:
        - Add privileges to a controlled user (e.g., `SeImpersonatePrivilege`).
        - Grant local admin rights to a host.
        - Create scheduled tasks for malicious commands (e.g., reverse shells, malware deployment).
    - **Example Attack Path** (via BloodHound):
        
        ```
        [Domain Users]
           | Member of
           v
        [Group: IT Support]
           | Can modify
           v
        [GPO: Disconnect Idle RDP]
           | Applies to
           v
        [OU: Servers]
           | Contains
           v
        [Computer: DC01]
        
        ```
        
        - **Impact**: Compromising an `IT Support` member allows GPO modification, granting admin rights on `DC01`.
- **Persistence**:
    - Attackers use GPOs to maintain access (e.g., scheduled tasks running malicious scripts).
- **Privilege Escalation**:
    - Misconfigured GPOs granting excessive rights (e.g., local admin to `Domain Users`) enable escalation.
- **Lateral Movement**:
    - GPOs applying to multiple OUs can be leveraged to access additional hosts.

**Security Note**: Tools like **BloodHound** identify GPO-related attack paths by mapping permissions and OU relationships.

---

## 6. Mitigation Strategies

### General AD Security

1. **Implement LAPS**: Randomize local admin passwords.
2. **Enable Robust Logging**: Monitor for unauthorized changes or attacks.
3. **Use gMSAs**: Secure service accounts with auto-rotating passwords.
4. **Enforce Account Separation**: Separate standard and admin accounts with unique passwords.
5. **Strengthen Password Policies**:
    - Minimum 12 characters, use passphrases.
    - Implement password filters and MFA for RDP.
6. **Limit Domain Admin Usage**: Restrict to DCs only.
7. **Audit Regularly**:
    - Disable stale accounts.
    - Review privileged group memberships and permissions.
8. **Use Restricted Groups**: Control local admin and privileged group memberships.
9. **Separate Server Roles**: Avoid unnecessary roles on DCs or critical hosts.
10. **Restrict RDP/Local Admin Rights**: Limit to essential users.

### GPO-Specific Mitigations

1. **Restrict GPO Edit Permissions**:
    - Only trusted admins (e.g., `Domain Admins`) should modify GPOs.
    - Audit GPO permissions:
        
        ```powershell
        Get-GPPermission -Name "Disconnect Idle RDP" -All | Select Trustee,Permission
        
        ```
        
2. **Use Enforced GPOs Sparingly**: Reserve for critical settings to avoid overriding legitimate OU policies.
3. **Enable Block Inheritance Judiciously**: Ensure critical domain policies (e.g., password policy) are enforced.
4. **Monitor GPO Changes**:
    - Log GPO modifications via Advanced Audit Policy.
    - Example: Audit GPO changes:
        
        ```powershell
        Set-GPRegistryValue -Name "Audit Policy" -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\Audit" -ValueName "AuditObjectAccess" -Type DWord -Value 1
        
        ```
        
5. **Test GPOs in a Lab**: Validate settings before domain-wide deployment to avoid misconfigurations.
6. **Limit GPO Scope**:
    - Apply GPOs to specific OUs rather than domain-wide.
    - Use security filtering to target specific groups.
        
        ```powershell
        Set-GPPermissions -Name "Restrict CMD" -TargetName "Standard Users" -TargetType Group -PermissionLevel GpoApply
        
        ```
        

**Security Note**: Regular audits with tools like BloodHound and PowerShell, combined with least-privilege principles, significantly reduce GPO-related risks.

---

## 7. Practical Examples

### Example 1: Implementing LAPS

**Scenario**: Randomize local admin passwords.

1. Install LAPS on a DC.
2. Configure GPO to enable LAPS:
    
    ```powershell
    Set-GPRegistryValue -Name "LAPS Policy" -Key "HKLM\SOFTWARE\Policies\Microsoft Services\AdmPwd" -ValueName "AdmPwdEnabled" -Type DWord -Value 1
    
    ```
    
3. Set password rotation interval (e.g., 24 hours).
4. Verify password storage in AD:
    
    ```powershell
    Get-ADComputer -Filter * -Properties ms-Mcs-AdmPwd
    
    ```
    

### Example 2: Creating a Secure GPO

**Scenario**: Restrict `cmd.exe` for standard users in the “Staff” OU.

1. Create GPO in GPMC named “Restrict CMD”.
2. Navigate to Computer Configuration → Policies → Software Restriction Policies.
3. Add rule to disallow `cmd.exe`.
4. Link GPO to “Staff” OU with security filtering for `Domain Users`.
5. Verify application:
    
    ```powershell
    gpresult /r /scope computer
    
    ```
    

### Example 3: Auditing GPO Permissions

**Scenario**: Check who can modify a GPO.

1. Run:
    
    ```powershell
    Get-GPPermission -Name "Disconnect Idle RDP" -All | Where-Object {$_.Permission -eq "GpoEditDeleteModifySecurity"}
    
    ```
    
2. Remove unauthorized users:
    
    ```powershell
    Set-GPPermissions -Name "Disconnect Idle RDP" -TargetName "IT Support" -TargetType Group -PermissionLevel None
    
    ```
    

### Example 4: Detecting Password Spraying

**Scenario**: Monitor for multiple failed logins.

1. Enable audit policy for failed logons:
    
    ```powershell
    Set-GPRegistryValue -Name "Audit Policy" -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\Audit" -ValueName "AuditLogon" -Type DWord -Value 1
    
    ```
    
2. Query Security event log:
    
    ```powershell
    Get-WinEvent -LogName "Security" | Where-Object {$_.Id -eq 4625} | Select TimeCreated,@{Name="Account";Expression={$_.Properties[5].Value}}
    
    ```
    

---

## 8. Key Takeaways

- **AD Security**:
    - AD is insecure by default, prioritizing availability over integrity.
    - Hardening measures (LAPS, gMSAs, logging, account separation, MFA) are essential for security.
    - Regular audits and least-privilege principles reduce attack surface.
- **Group Policy**:
    - GPOs are powerful for managing and securing AD but vulnerable to misuse.
    - Proper precedence (domain → OU, enforced settings) and permissions are critical.
    - Misconfigured GPOs can enable **lateral movement**, **privilege escalation**, or **persistence**.
- **Security Practices**:
    - Use tools like BloodHound to identify attack paths.
    - Combine GPOs with general security measures (e.g., patching, network segmentation).
    - Test and monitor GPO changes to prevent unintended consequences.

---

## 9. Comprehensive Diagram: AD Security and GPO Workflow

```
[Domain Controller]
   | Manages
   v
[GPOs]
   | Default Domain Policy (Enforced: Password Policy, MFA)
   | Security GPO (LAPS, Restrict CMD, Audit Logging)
   | Linked to
   v
[OU: Staff]
   | Contains
   v
[Users: jdoe]
   | Applies settings
   | - 12-character password
   | - No cmd.exe access
   | - MFA for RDP
   v
[Computers: WORKSTATION01]
   | Applies settings
   | - LAPS-enabled admin password
   | - Restricted RDP access
   | - Audit logon events
   v
[Monitoring]
   | Logs to SIEM
   | Detects: Password spraying, GPO changes, Kerberoasting

```

**Explanation**:

- **GPOs**: Enforce security settings (e.g., password policy, application restrictions).
- **Users/Computers**: Receive settings based on OU and security filtering.
- **Monitoring**: Detects anomalies via audit policies and SIEM integration.
- **Security Measures**: LAPS, MFA, and restricted groups reduce attack vectors.

---