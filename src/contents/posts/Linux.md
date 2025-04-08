---
title: Linux
published: 2025-03-25
description: For My Reference
tags: [Notes]
category: Notes
author: Me
draft: false
---

# 0 - Linux

# Daily-Useful Linux Notes

These notes are your go-to companion for navigating Linux, especially if you're working with the terminal daily. They cover the bash prompt, getting help, Linux distributions, its structure, and the shell—everything you need to feel confident and productive. Think of this as your personal Linux cheat sheet, built from real-world concepts you'll encounter often.

---

## 1. Mastering the Bash Prompt

The bash prompt is that line of text staring at you in the terminal—it’s your gateway to knowing where you are and who you are in the system. It’s simple but insanely customizable, and tweaking it can save you time every day.

- **What It Shows by Default**:
    - Format: `<username>@<hostname>:<current_directory>$`
    - Example: `john@my-laptop:~/Documents$`
    - The `~` (tilde) means you're in your home directory (e.g., `/home/john`).
    - `$` = regular user; `#` = root (superuser). If you see `#`, you’ve got full power—use it wisely!
- **Why Customize It?**:
    - Default is fine, but adding info like time, date, or full paths can make your life easier, especially when juggling multiple tasks or servers.
    - Example: During a project, I set my prompt to show the time and full path so I could track when I ran commands and exactly where I was—super handy for debugging.
- **How to Customize (PS1 Variable)**:
    - Edit your `.bashrc` file in your home directory (`nano ~/.bashrc`).
    - PS1 controls the prompt. Here’s a starter:
        
        ```bash
        PS1='\\u@\\h:\\w\\$ '
        
        ```
        
        - `\\u` = username, `\\h` = hostname, `\\w` = full current directory, `\\$` = `$` or `#`.
    - Fancy Example with Time and Colors:
        
        ```bash
        PS1='\\[\\e[32m\\]\\t \\u@\\h:\\[\\e[33m\\]\\w\\[\\e[0m\\]\\$ '
        
        ```
        
        - `\\t` = time (HH:MM:SS), `\\e[32m` = green text, `\\e[33m` = yellow directory, `\\e[0m` = reset color.
    - After editing, run `source ~/.bashrc` to apply changes instantly.
- **Daily Use Cases**:
    - **Quick Location Check**: If you’re hopping between directories, `\\w` ensures you always know your full path (e.g., `/var/www/html` instead of just `html`).
    - **Time Tracking**: Add `\\t` or `\\d` to log when you ran commands—great for scripting or noting when something broke.
    - **Server ID**: On multiple machines? Include `\\h` to avoid confusing `server1` with `server2`.
- **Special Characters I Use Often**:
    - `\\d`: Date (e.g., "Tue Apr 08").
    - `\\t`: 24-hour time (e.g., "14:35:22").
    - `\\u`: My username—reassuring when I’m root!
    - `\\w`: Full path—saves me from typing `pwd` constantly.
- **Pro Tip**: If your prompt looks weird (e.g., no username), the PS1 variable might not be set. Fix it with: `export PS1='\\u@\\h:\\w\\$ '`.

---

## 2. Getting Help When You’re Stuck

Linux has a million commands, and no one remembers them all. These help tools are your lifeline—use them daily to figure out what’s what without Googling every five minutes.

- **The Big Three**:
    1. **`man <command>`**:
        - Full manual for any tool. Example: `man ls` explains how to list files.
        - Daily Use: I check `man cp` when I forget if `r` or `R` copies directories (it’s both!).
    2. **`<command> --help`**:
        - Quick summary of options. Example: `ls --help` shows `a` (all files) and `l` (long format).
        - Daily Use: Perfect when I need a fast reminder without wading through `man`.
    3. **`<command> -h`**:
        - Short help for some tools (e.g., `curl -h`). Not all commands support it, but it’s snappy when they do.
- **Real-World Examples**:
    - Forgot how to list hidden files? `ls --help` → `a` does it.
    - Need to download a file with `curl`? `curl -h` → `-cacert <file>` for SSL stuff.
    - Curious about `sudo` options? `man sudo` → detailed breakdown.
- **Bonus Tools**:
    - **`apropos <keyword>`**: Searches man pages by keyword. Example: `apropos password` finds `passwd` for user management.
        - Daily Use: When I vaguely remember a tool but not its name—saves me tons of time.
    - [**explainshell.com**](http://explainshell.com/): Paste a complex command online, and it explains each part. Example: `ls -la | grep txt` → breaks it down step-by-step.
- **Why It Matters Daily**:
    - You’ll hit unknown commands constantly (e.g., `netstat`, `chmod`). These tools let you learn on the fly without breaking your workflow.
    - Tip: Press `q` to exit `man` pages—don’t just sit there staring!

---

## 3. Linux Distros: Picking Your Daily Driver

Linux comes in flavors (distros), and knowing which one fits your day-to-day needs is key. Here’s the rundown.

- **What’s a Distro?**:
    - A version of Linux with its own tools and vibe. All use the Linux kernel but differ in packages and purpose.
    - Examples: Ubuntu (beginner-friendly), Debian (stable), Kali (cybersecurity).
- **Daily Choices**:
    - **Ubuntu**: My go-to for desktop stuff—easy setup, tons of support online. Great for coding or browsing.
    - **Debian**: Rock-solid for servers or long-term projects. I use it when I need something that won’t crash mid-task.
    - **Kali Linux**: Cybersecurity goldmine—preloaded with tools like `nmap` and `metasploit`. I boot it up for pentesting days.
- **Debian Deep Dive (My Server Fav)**:
    - **Stability**: Updates roll out slow but steady—perfect for a machine I don’t want to babysit.
    - **APT**: Package manager (`apt update && apt upgrade`) keeps it secure with minimal effort.
    - **Customization**: Takes more work to set up, but I can tweak it exactly how I want (e.g., lightweight for an old PC).
    - Daily Use: I run a Debian server for hosting files—`apt install nginx` and I’m live in minutes.
- **Why Linux Over Windows?**:
    - Free, open-source, and secure. I can peek at the code if I’m paranoid (rarely do, though).
    - Updates are frequent—less worry about viruses sneaking in.
- **Daily Tip**: Dual-boot Ubuntu for casual use and Kali for hacking practice—covers all my bases.

---

## 4. Linux Structure: Knowing Your Way Around

Linux’s layout and guts are worth understanding—it’s like knowing where the kitchen is in your house. You’ll use this daily without even thinking.

- **Core Bits**:
    - **Kernel**: The brain—talks to hardware (CPU, RAM). You won’t touch it much, but it’s always working.
    - **Shell**: Your command-line buddy (usually Bash). Type stuff here to get things done.
    - **File System**: Everything’s a file, organized in a tree starting at `/`.
- **Key Directories I Visit Daily**:
    - `/home/john`: My stuff—documents, downloads, scripts.
    - `/etc`: Config files (e.g., `/etc/passwd` for users, `/etc/hosts` for network tweaks).
    - `/var`: Logs (`/var/log/syslog`)—check here when something’s fishy.
    - `/tmp`: Temp files—great for quick tests; clears on reboot.
    - `/bin`: Commands like `ls` and `cp` live here.
- **Philosophy I Live By**:
    - **Everything’s a File**: Even hardware (`/dev/sda` = my hard drive). Edit a text file, control the system.
    - **Small Tools**: `cat`, `grep`, `awk`—chain them together for big wins (e.g., `cat log.txt | grep error`).
    - **Shell Power**: GUI’s fine, but the shell’s faster. `cd /var/www && ls` beats clicking around.
- **Daily Workflow**:
    - Check my location: `pwd` → `/home/john/projects`.
    - List files: `ls -la` (shows hidden stuff too).
    - Edit config: `sudo nano /etc/ssh/sshd_config` to tweak my server’s SSH.
- **History Tip**: Linux grew from Unix (1970s) to Torvalds’ kernel (1991). It’s battle-tested—trust it.

---

## 5. Shell: Your Daily Superpower

The shell is where the magic happens. It’s text-based, but once you get it, you’ll never go back to clicking buttons.

- **What’s a Shell?**:
    - A program (usually Bash) that takes your commands and runs them. Think of it as texting the OS what to do.
    - Example: `whoami` → `john` (tells me who I am).
- **Terminal vs. Shell**:
    - Terminal = the window you type in (e.g., GNOME Terminal).
    - Shell = the engine inside (Bash, Zsh, etc.).
    - Daily Analogy: Terminal’s the phone; shell’s the person answering.
- **Why It’s Awesome**:
    - Faster than GUI: `rm -rf junk/` deletes a folder instantly—no dragging to trash.
    - Automatable: Write a script (e.g., `backup.sh`) to save time on repetitive tasks.
    - Example: I made a script to update my system daily:
        
        ```bash
        #!/bin/bash
        apt update && apt upgrade -y
        
        ```
        
- **Terminal Emulators**:
    - Tools like Tmux split your screen—great for monitoring logs in one pane while working in another.
    - Daily Use: `tmux split-window -h` → two side-by-side terminals.
- **Other Shells**:
    - Bash is king, but Zsh (fancy prompts) or Fish (auto-suggestions) are worth a try if you’re bored.
- **Daily Commands**:
    - `cd /var/log`: Go to logs.
    - `cat syslog | grep fail`: Find failures.
    - `sudo systemctl restart nginx`: Restart my web server.

---

## 6. Navigating Like a Pro

Navigating the Linux filesystem is a daily necessity—whether you're hopping between directories or digging into files, these commands are your bread and butter. The PDF’s “Navigation” section (pages 1-4) lays out the essentials, and I’ll break it down into practical, note-style tips you’ll use constantly.

- **Where Am I?**:
    - **`pwd`**: Prints your current directory. Example: `/home/cry011t3`.
        - Daily Use: I run this when I’ve `cd`’d too many times and lost track—keeps me grounded.
    - **Why It Matters**: Knowing your location is step one before doing anything else.
- **What’s Here?**:
    - **`ls`**: Lists directory contents. Example: `Desktop Documents Downloads`.
        - Barebones but fast—great for a quick peek.
    - **`ls -l`**: Long format—shows permissions, owner, size, date. Example:
        
        ```
        drwxr-xr-x 2 cry011t3 htbacademy 4096 Nov 13 17:37 Desktop
        
        ```
        
        - Daily Use: I check file sizes or who owns what—4096 bytes is typical for empty dirs.
    - **`ls -la`**: Shows hidden files too (starting with `.`). Example: `.bash_history`.
        - Pro Tip: Hidden files are goldmines—`.bashrc` tweaks your shell, `.bash_history` spills past commands.
    - **`ls /path/`**: Peek anywhere28 anywhere without moving. Example: `ls -l /var/`.
        - Daily Use: I scout system dirs like `/etc` or `/usr` to troubleshoot configs.
- **Moving Around**:
    - **`cd /path/`**: Change directory. Example: `cd /dev/shm`.
        - Daily Use: Jump to project dirs (`cd ~/code`) or system spots (`cd /var/log`).
    - **`cd -`**: Back to the last directory.
        - Lifesaver when I’m bouncing between two spots—e.g., `/home` to `/tmp` and back.
    - **`cd ..`**: Up one level. Example: `/dev/shm` → `/dev`.
        - Daily Use: Climb out of deep folder nests fast.
    - **Dots Rule**:
        - `.` = current dir (e.g., `ls .` = list here).
        - `..` = parent dir (e.g., `cd ..` = go up).
- **Auto-Complete Magic**:
    - Hit `[TAB]` twice after partial input. Example: `cd /dev/s[TAB][TAB]` → `shm/ snd/`.
    - Add a letter: `cd /dev/sh[TAB]` → auto-fills `shm/`.
    - Daily Use: Saves typing—especially for long paths like `/usr/share`.
- **Clean the Slate**:
    - **`clear`**: Wipes the terminal screen.
        - Daily Use: When my shell’s a mess after tons of output—fresh start!
    - **Shortcut**: `[CTRL + L]` does the same—quicker.
    - Example: `cd /dev/shm && clear` = move and clean in one shot.
- **Command History**:
    - **Up/Down Arrows**: Scroll past commands.
    - **`[CTRL + R]`**: Search history. Type a bit (e.g., “ls”), hit enter to reuse.
    - Daily Use: I rerun `ls -la` or old `grep` searches without retyping.
- **Why It’s Daily Gold**:
    - Speed: `cd`, `ls`, and `[TAB]` cut navigation time in half.
    - Recovery: `cd -` or history saves me when I’m lost or forget what I ran.

---

## 7. Finding Files and Folders Fast

The “Find Files and Directories” section (pages 1-3) is your treasure map for locating stuff on Linux. These tools—`which`, `find`, `locate`—are my daily go-tos for hunting down files, configs, or tools.

- **`which`**:
    - Finds a program’s path. Example: `which python` → `/usr/bin/python`.
    - If nothing shows, it’s not installed—blank output = “not found.”
    - Daily Use: Check if `curl` or `nc` (netcat) is on a system before scripting.
- **`find`**:
    - Searches with filters. Syntax: `find <location> <options>`.
    - Example: `find / -type f -name "*.conf" -user root -size +20k -newermt 2020-03-03`.
        - Breakdown:
            - `/`: Start at root (whole system).
            - `type f`: Files only (not dirs).
            - `name "*.conf"`: Config files.
            - `user root`: Owned by root.
            - `size +20k`: Bigger than 20KB.
            - `newermt 2020-03-03`: Modified after March 3, 2020.
        - Output: Lists matching files (e.g., `/etc/dnsmasq.conf`).
    - Daily Use: I hunt big config files (`find /etc -name "*.conf"`) or recent changes (`find ~ -newermt 2025-04-01`).
    - Noise Filter: Add `2>/dev/null` to hide “permission denied” errors.
- **`locate`**:
    - Faster search via database. Example: `locate *.conf` → `/etc/GeoIP.conf`, etc.
    - Update DB: `sudo updatedb` (run first if results seem stale).
    - Daily Use: Quick checks for common files—beats `find` when I don’t need filters.
- **Which vs. Find vs. Locate**:
    - `which`: “Where’s this tool?” (e.g., `which gcc`).
    - `find`: Deep, customizable search—slow but precise.
    - `locate`: Fast, broad sweep—less control, needs fresh DB.
- **Daily Workflow**:
    - Need `netcat`? `which nc`.
    - Hunting logs? `find /var/log -name "*.log"`.
    - Config scan? `locate *.conf`.
- **Exercise Idea**: Try `which nc`, `find / -name "*nc*"`, and `locate nc`—see what each digs up!

---

## 8. Managing Files and Dirs Like a Boss

The “Working with Files and Directories” section (pages 1-6) is your toolkit for creating, moving, and organizing. These commands are my daily muscle memory for keeping systems tidy.

- **Creating Stuff**:
    - **`touch <name>`**: Makes an empty file. Example: `touch info.txt`.
        - Daily Use: Placeholder files or quick timestamps (`touch log.txt`).
    - **`mkdir <name>`**: Makes a directory. Example: `mkdir Storage`.
    - **`mkdir -p <path>`**: Creates nested dirs. Example: `mkdir -p Storage/local/user/docs`.
        - Daily Use: Set up project trees fast—no manual steps.
- **Seeing the Structure**:
    - **`tree`**: Shows dir layout. Example:
        
        ```
        .
        ├── info.txt
        └── Storage
            └── local
                └── user
                    └── docs
        
        ```
        
    - Daily Use: Visualize my mess before cleaning it up.
- **Moving and Renaming**:
    - **`mv <source> <dest>`**: Moves or renames.
        - Rename: `mv info.txt information.txt`.
        - Move: `mv information.txt Storage/`.
    - Daily Use: Rename backups (`mv data.bak data_2025.bak`) or shift files (`mv *.txt logs/`).
- **Copying**:
    - **`cp <source> <dest>`**: Copies files. Example: `cp Storage/readme.txt Storage/local/`.
    - Daily Use: Duplicate configs for testing (`cp sshd_config sshd_config.test`).
- **Deleting (Figure It Out)**:
    - Hint: `rm <file>` (files), `rm -r <dir>` (dirs, recursive).
    - Daily Use: `rm junk.txt`, `rm -r old_project/`—keeps my space clean.
    - Safety: `rm -i` asks first—saved me from disasters.
- **Daily Flow**:
    - New project? `mkdir -p proj/docs && touch proj/notes.txt`.
    - Organize? `mv *.log logs/ && tree`.
    - Backup? `cp config.conf config.conf.bak`.
- **Pro Tip**: Chain commands: `mkdir logs && mv *.log logs/`—one-liner efficiency.

---

## 9. System Intel Gathering

The “System Information” section (pages 1-5) is your spy kit for understanding any Linux box. These commands are my daily recon tools—whether I’m troubleshooting or pentesting.

- **Who and Where**:
    - **`whoami`**: Current user. Example: `cry011t3`.
    - **`id`**: User and group IDs. Example: `uid=1000(cry011t3) groups=1000,1337(hackthebox),4(adm)`.
        - Daily Use: Check privileges—`sudo` group = jackpot.
    - **`hostname`**: Machine name. Example: `nixfund`.
    - **`pwd`**: Current dir (yep, again—`/home/cry011t3`).
- **System Specs**:
    - **`uname -a`**: All system info. Example: `Linux box 4.15.0-99-generic ... x86_64`.
        - Breakdown: Kernel, hostname, release, hardware.
    - **`uname -r`**: Kernel release only. Example: `4.15.0-99-generic`.
        - Daily Use: Grab this for exploit hunting (e.g., “4.15.0-99 exploit”).
- **Network and Processes**:
    - **`ifconfig`**: Old-school network info (IP, MAC).
    - **`ip a`**: Modern alt—shows interfaces. Example: `eth0: 192.168.1.10`.
    - **`netstat`**: Network status (ports, connections).
    - **`ss`**: Socket stats—faster than `netstat`.
    - **`ps`**: Running processes. Example: `ps aux` = everything.
    - Daily Use: `ip a` for my IP, `ps aux | grep nginx` to check my web server.
- **Hardware and Users**:
    - **`lsblk`**: Disks (e.g., `sda`).
    - **`lsusb`**: USB devices.
    - **`lspci`**: PCI devices (e.g., GPU).
    - **`who`**: Logged-in users.
    - **`env`**: Environment vars (e.g., `PATH`).
    - Daily Use: `lsblk` to check free space, `who` to see if I’m alone.
- **Daily Recon**:
    - New box? `whoami; id; uname -a; ip a`.
    - Trouble? `ps aux` + `netstat -tulnp` (listening ports).
    - Learn More? `man <cmd>` (e.g., `man ps`).

---

## 10. Editing Files with Ease

The “Editing Files” section (pages 1-5) covers tweaking files via `nano` and `vim`. These are my daily text wranglers—simple or surgical, depending on the job.

- **`nano`**:
    - Easy editor. Example: `nano notes.txt`.
    - Interface: Type away, `[CTRL + O]` to save, `[CTRL + X]` to exit.
    - Search: `[CTRL + W]`, type “notes”, `[ENTER]` jumps to it.
    - Daily Use: Quick edits—`nano /etc/hosts` to block a site.
- **Nano Shortcuts**:
    - Save: `[CTRL + O]`, confirm with `[ENTER]`.
    - Exit: `[CTRL + X]`.
    - Search Next: `[CTRL + W]`, `[ENTER]`.
    - Daily Use: Jot notes (`nano todo.txt`)—no fuss.
- **Viewing Files**:
    - **`cat <file>`**: Dumps contents. Example: `cat notes.txt`.
    - Daily Use: Peek at logs (`cat /var/log/syslog`).
- **Key Files**:
    - `/etc/passwd`: User list (e.g., `cry011t3:x:1000:1000`).
    - `/etc/shadow`: Password hashes (needs root).
    - Daily Use: `cat /etc/passwd` to scout users—pentest recon.
- **`vim`**:
    - Power editor. Example: `vim notes.txt`.
    - Modes:
        - Normal: Commands (start here).
        - Insert: Type text (`i` to enter).
        - Visual: Highlight text (`v`).
        - Command: Run stuff (`:`), e.g., `:q` to quit.
    - Exit: `:q` or `:q!` (force quit).
    - Daily Use: Precise edits—`vim script.sh` to fix a loop.
- **VimTutor**:
    - Learn it: `vimtutor` (~30 mins).
    - Daily Use: Practice moves (`hjkl`)—worth the grind.
- **Daily Pick**:
    - `nano`: Fast fixes (e.g., config tweaks).
    - `vim`: Heavy lifting (e.g., regex replaces).
    - Check: `cat` to confirm changes.

---

## 11. User Management: Controlling the Crew

User management is about creating, tweaking, and securing accounts—daily admin stuff. Here’s what I use from the “User Management” section (pages 1-2).

- **Why It Matters**: Keeps the system secure—right users, right access. Think new hire Alex needing a dev account.
- **Root vs. Regular**:
    - `cat /etc/shadow` → “Permission denied” (regular user).
    - `sudo cat /etc/shadow` → Hashes galore (root access).
    - Daily Use: Check `/etc/shadow` for audits—needs `sudo`.
- **Key Commands**:
    - `sudo <cmd>`: Run as another user (usually root). Ex: `sudo whoami` → `root`.
    - `su`: Switch user (default root). Ex: `su -` → root shell.
    - `useradd <name>`: New user. Ex: `sudo useradd -m alex` (home dir too).
    - `userdel <name>`: Delete user. Ex: `sudo userdel alex`.
    - `usermod`: Tweak user. Ex: `sudo usermod -aG devs alex` (add to group).
    - `addgroup <name>`: New group. Ex: `sudo addgroup devs`.
    - `delgroup <name>`: Drop group. Ex: `sudo delgroup devs`.
    - `passwd <name>`: Set password. Ex: `sudo passwd alex`.
- **Daily Flow**:
    - New user? `sudo useradd -m alex && sudo passwd alex && sudo usermod -aG devs alex`.
    - Cleanup? `sudo userdel alex && sudo delgroup oldteam`.
- **Pro Tip**: Practice in a VM—mess up, reset, repeat.

---

## 12. Permission Management: Locking It Down

Permissions are your security keys—control who does what. From “Permission Management” (pages 1-6), here’s my daily toolkit.

- **Basics**:
    - Every file/dir has an owner and group.
    - Ex: `ls -l scripts` → `drw-rw-r-- 3 cry0l1t3 cry0l1t3`.
    - Read (`r` = 4), Write (`w` = 2), Execute (`x` = 1).
    - Octal: `754` = `rwxr-xr--` (owner: 7, group: 5, others: 4).
- **Traversal**:
    - Need `x` on a dir to `cd` in. No `x`? “Permission denied.”
    - Ex: `ls -l mydirectory/` → errors if no `x`.
- **Change Owner**:
    - `chown <user>:<group> <file>`: Shift ownership.
    - Ex: `sudo chown root:root shell` → `ls -l shell` shows `root root`.
- **SUID/SGID**:
    - `s` in perms = run as owner/group. Ex: `rwsr-xr-x` (SUID).
    - Risk: `sudo chmod u+s journalctl` → shell as root (check GTFObins).
    - Daily Use: Spot `s` with `find / -perm -u=s`.
- **Sticky Bit**:
    - `t` in perms = only owner/root can delete in shared dir.
    - Ex: `drwxrwxr-t` (lowercase `t` = `x` on), `drwxrwxr-T` (uppercase = no `x`).
    - Daily Use: `chmod +t scripts` for shared dirs.
- **Daily Flow**:
    - Secure file? `sudo chown root:root file && chmod 600 file`.
    - Shared dir? `chmod 1777 temp` (sticky + full access).

---

## 13. Regular Expressions: Pattern Ninja

RegEx is my text-search superpower—grep and sed love it. From “Regular Expressions” (pages 1-2).

- **Why It’s Gold**: Find patterns fast—logs, configs, you name it.
- **Grouping**:
    - `()`: Group patterns. Ex: `(my|false)` = “my” or “false”.
    - `[]`: Character class. Ex: `[a-z]` = any lowercase.
    - `{}`: Quantifiers. Ex: `a{2}` = “aa”.
    - `|`: OR. Ex: `grep -E "(my|false)" /etc/passwd`.
    - `.*`: AND-ish (sequence). Ex: `grep -E "(my.*false)" /etc/passwd`.
- **Examples**:
    - OR: `grep -E "(my|false)" /etc/passwd` → lines with “my” or “false”.
    - AND: `grep -E "(my.*false)" /etc/passwd` → “my” then “false”.
    - Double grep: `grep -E "my" /etc/passwd | grep -E "false"`.
- **Practice Tasks** (on `/etc/ssh/sshd_config`):
    1. No `#`: `grep -v "^#"`.
    2. Starts with “Permit”: `grep "^Permit"`.
    3. Ends with “Authentication”: `grep "Authentication$"`.
    4. Has “Key”: `grep "Key"`.
    5. Starts “Password” + “yes”: `grep "^Password.*yes"`.
    6. Ends “yes”: `grep "yes$"`.
- **Daily Use**: Debug configs—`grep -E "Port.*22" sshd_config`.

---

## 14. Filter Contents: Sifting Through Noise

Filtering tools are my data wranglers—cut, sort, grep, etc. From “Filter Contents” (pages 1-8).

- **Pagers**:
    - `more`: Scroll down, `[Q]` to quit, output stays.
    - `less`: Scroll both ways, `[Q]` to quit, screen clears.
    - Ex: `cat /etc/passwd | more` or `less /etc/passwd`.
- **Head/Tail**:
    - `head`: First 10 lines. Ex: `head /etc/passwd`.
    - `tail`: Last 10. Ex: `tail /etc/passwd`.
    - Tweak: `head -n 5` (first 5).
- **Sort**:
    - `sort`: Alphabetize. Ex: `cat /etc/passwd | sort`.
- **Grep**:
    - Filter: `grep "/bin/bash" /etc/passwd`.
    - Exclude: `grep -v "false\\|nologin" /etc/passwd`.
- **Cut**:
    - Slice: `cut -d':' -f1 /etc/passwd` → usernames.
- **Tr**:
    - Replace: `tr ':' ' ' < /etc/passwd` → spaces instead of colons.
- **Column**:
    - Table it: `cat /etc/passwd | tr ':' ' ' | column -t`.
- **Awk**:
    - Pick fields: `awk '{print $1 " " $NF}' /etc/passwd` → username + shell.
- **Sed**:
    - Swap: `sed 's/bin/HTB/g' /etc/passwd` → “bin” to “HTB”.
- **Wc**:
    - Count: `grep "/bin/bash" /etc/passwd | wc -l` → bash users.
- **Daily Chain**: `cat /etc/passwd | grep -v "nologin" | cut -d':' -f1 | sort | wc -l`.

---

## 15. Find Files and Directories: Treasure Hunt

Finding stuff fast is clutch—configs, scripts, tools. From “Find Files and Directories” (pages 1-3).

- **`which`**:
    - Path to tool. Ex: `which python` → `/usr/bin/python`.
    - Daily Use: `which nc`—is netcat here?
- **`find`**:
    - Deep search. Ex: `find / -type f -name "*.conf" -user root -size +20k`.
    - Filters: `type d` (dirs), `newermt "2025-04-01"`, `exec ls -l {} \\;`.
    - Quiet: `2>/dev/null`.
- **`locate`**:
    - Fast DB search. Ex: `locate *.conf`.
    - Refresh: `sudo updatedb`.
- **Daily Flow**:
    - Tool check: `which gcc`.
    - Config hunt: `find /etc -name "*.conf" 2>/dev/null`.
    - Quick scan: `locate shadow`.
- **Exercise**: `which nc`, `find / -name "*nc*" 2>/dev/null`, `locate nc`.

---

## 16. File Descriptors and Redirections: Output Wizardry

Redirections manage I/O like a pro—STDIN, STDOUT, STDERR. From “File Descriptors and Redirections” (pages 1-6).

- **File Descriptors**:
    - `0` = STDIN (input).
    - `1` = STDOUT (output).
    - `2` = STDERR (errors).
- **Examples**:
    - STDIN: `cat` → type “Hack”, get “Hack” back.
    - STDOUT/STDERR: `find /etc -name shadow` → files (1), errors (2).
- **Redirect**:
    - Errors off: `find /etc -name shadow 2>/dev/null`.
    - STDOUT to file: `> results.txt`.
    - Both: `2> stderr.txt 1> stdout.txt`.
    - Append: `>> stdout.txt`.
    - STDIN stream: `cat << EOF > stream.txt` → type, end with “EOF”.
- **Pipes**:
    - Chain: `find /etc -name "*.conf" 2>/dev/null | grep systemd | wc -l`.
- **Daily Use**:
    - Clean output: `ls dir 2>/dev/null > list.txt`.
    - Log results: `grep "error" log.txt >> errors.txt`.

---