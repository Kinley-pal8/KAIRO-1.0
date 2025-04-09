---
title: Titanic
published: 2025-03-24
description: Easy-rated Linux machine on Hack The Box. 
tags: [HTB, Labs]
category: HTB
draft: false
---

# Week 2 Machine: Titanic

# Intoduction

The HackTheBox platform presents Titanic as a Linux-based Capture the Flag (CTF) scenario that recreates an entire simulated server environment. The challenge enables testers to demonstrate multiple cybersecurity competencies through its design which requires people to use technical expertise to solve problems while they perform research effectively. This report outlines my solution process for the Titanic challenge along with all methods and tools and logical reasoning behind it that resulted in successful completion.

# Objective

The essential goal of the Titanic challenge requires exploitation of system vulnerabilities to achieve access authentication and finally obtain hidden flag(s). The task demands successful directory traversal alongside service analysis and utilization of Gitea tools to accomplish the mission while demonstrating outstanding research capabilities.

# **Network Topology & Scope**

The target IP address: 10.10.11.55

Discovered two website:

- titanic.htb/
- dev.titanic.htb/

# Phase 1 : Recon

Every CTF challenge requires an initial reconnaissance phase at the beginning of analysis. The first step started with running Nmap on the target system to detect active open ports with running services. The scan results showed multiple services including a web server.


### Two ports discovered:

- 22/tcp ssh
- 80/tcp http

I had  perform reconnaissance scan using **WhatWeb** and **Metasploit** on the IP address `10.10.11.55`, which is returning a `200 OK` status with a **Meta-Refresh-Redirect** pointing to `http://titanic.htb/`. 


So, after doing this phase, we found out that the target is running Apache/2.4.52 (Ubuntu)

## **Phase 2: Web Exploitation**

As we have one open port 80 so we start with exploring the website.

While performing the Recon phase, we knew that the target is redirecting to the http://titanic.htb. However, the system cannot resolve titanic.htb due to it being an internal hostname, likely part of a target network.

As it is part of a CTF or a test environment, titanic.htb is probably meant to resolve to 10.10.11.55. I manually add this mapping to your /etc/hosts file. Used the following command:

```bash
echo "10.10.11.55 titanic.htb" | sudo tee -a /etc/hosts
```

This way, titanic.htb will point to 10.10.11.55 , and it will access the redirected URL correctly.


So this the home page of the website.

With the help of Wappalyzer, to see what technologies used on the website.


The web application on port 80 appeared to be a simple static site with limited functionality. However, directory enumeration using ffuf revealed hidden paths that were not immediately visible. After that, i had try running ffuf on the webiste titanic.htb/ to see if there are hidden directories or files:


I didn’t find notable domain but with all status 301 but they have one thing common which it has 20 words. Therefore, we used a Filter functional/option to exclude responses with a specific number of words.  


I found a new domain called dev with status 200 and i did the same thing to access the website with manually add this mapping to your /etc/hosts file. 


This was the page for dev.titanic.htb/ .

So, back the titanic.htb/ , i used Brupsuite to play around the website and in the website it has only one functionality that is when we book tickets we get a .json file.


I found one vulnerability called Path Traversal.

Path Traversal (also known as Directory Traversal) functions as a web security bug that enables attackers to navigate beyond web root directory boundaries and access files and directories. Path Traversal occurs when applications let users specify file paths through unvalidated inputs. The vulnerability permits unauthorized users to access important files which may include application configuration details and passwords in addition to the application source code itself.

**How Path Traversal Works**
User-supplied input leads to the development of Path Traversal vulnerabilities because applications build their file paths through client-sourced data. The web application enables users to download files through its URL parameter which requires filename input.

```bash
http://example.com/download?file=report.pdf
```

If the application does not properly validate the `file` parameter, an attacker could manipulate it to access files outside the intended directory:

```bash
http://example.com/download?file=../../../../etc/passwd
```

This could result in the server returning the contents of the /etc/passwd , which it has the information of the user account. 

Again while i was exploring the other website dev.titanic.htb/

When i clicked the explore button it leads to me the GitHub platform where there were two repositories.



With the help of this source code, I put this to [claude.io](http://claude.io) and review or inspect on this code whether it had any vulnerabilities and it gave many but the Path Traversal I tired to keep eye on.


As this way, I download the content of the website.


I found out that developer can be used as a username to login as there was no /nologin

Next, I tired to read the documentation on the Gitea to find the configuration file in order to find the path or the password. 


/download?ticket=../../../home/developer/gitea/data/gitea/conf/app.ini

this was the path where we found a lot information.



I found the path for me to download the database where i can acquire the database can manipulate the data and can get any information.

I used the command as it was a powerful to  extract and format password hashes from a Gitea SQLite database (`gitea.db`) for further analysis or cracking.


Once the hashes are extracted and formatted, it can be cracked using tools like **hashcat** or **John the Ripper**.

```bash
hashcat gitea.hashes rockyou.txt --user
```


Thus, i found the password.

Next with the help of  ssh, i logged in.


First I found the user.txt and next step, I used the find command to locate all writable directories on the system:

```bash
find / -writable -type d 2>/dev/null
```

- This revealed `/opt/app/` as a writable directory.


A script named identify_images.sh exists as likely one in the /opt/scripts/ directory. I had  located the ImageMagick binary at `/usr/bin/magick` and checked its version:

```bash
/usr/bin/magick --version
```

- The version is `7.1.1–35`.


I discovered that it was CVE-2024-41817, which allows arbitrary code execution via malicious shared libraries loaded by ImageMagick.


Using gcc you generated a malicious shared library (libxcb.so.1) at /opt/app/static/assets/images/ directory.

```bash
gcc -x c -shared -fPIC -o ./libxcb.so.1 - << EOF
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

__attribute__((constructor)) void init(){
    system("cp /root/root.txt root.txt; chmod 754 root.txt");
    exit(0);
}
EOF
```

With this, when loaded by ImageMagick, will copy the `/root/root.txt` file to the current directory and change its permissions.

I found the root.txt.