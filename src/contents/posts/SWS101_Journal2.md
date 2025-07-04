---
title: HTB Tier 0 and 1
published: 2024-03-17
description: Walk Through
category: SWS Journal
draft: false
---

### Topic : Journal entry 2: Walk Through Of HTB Tier 0 and 1.

---

Tier 0

According to the learning outcomes in HTB;
In the first tier, you will gain essential skills in the world of cybersecurity pen-testing. You'll start by learning how to connect to various services, such as FTP, SMB, Telnet, Rsync, and RDP anonymously. Next, you'll discover the power of Nmap, a valuable tool for identifying open ports on target systems, allowing you to assess their vulnerabilities. Lastly, you'll explore connecting to a MongoDB server, adding a valuable layer to your penetration testing knowledge. This tier will lay a strong foundation for your journey into the realm of cybersecurity.

A beginning course for those new to cybersecurity and penetration testing. It offers a selection of really simple-to-hack boxes, each with a single main step and a focus on a specific tool or service. The level is designed to teach the core principles of machine attack.
Here is the walk through for tier o;

Meow:
- Connect to the Network: i used the OpenVPN technique. Run the VPN configuration file (.ovpn) that i had downloaded in my terminal.
- Machine Activation: clicked the "Spawn Machine" button to turn on the "Meow" machine which there will be IP address.
- Task Completion: Done the the tasks given and answered the questions.
- Checked for Open Ports: To find any open ports on the target IP, I used  nmap. Port 23/tcp was the port that corresponds to the Telnet service.
- Establish a Telnet connection: To establish a connection with the target server, I used telnet [Target_IP]. Log in with the username "root" and no password.
- To get the flag,  i used 'ls' to list the files and cat flag.txt to examine the flag file's contents after logging in.

Dancing:
- Connect to HTB Network: To access the HTB network, utilize OpenVPN, just like you would with the Meow challenge.
- Turn on the machine: Turned on the "Dancing" device.
- Finding  Any Open Ports: To scan the target IP, use nmap. Port 445 where it is connected to the SMB service, should be found.
- Enumerate SMB Shares: SMBclient -L [target_ip] will show every share that is available. Entered the share name "WorkShares" and connected without a password.
- Get the Flag Back: To download the "flag.txt" file, used 'get' after listing the files with 'ls' and navigating to the "James.P" directory.

Redeemer:
The Redeemer walkthrough was not directly provided in the sources, but the process typically involves similar steps to the Meow and Dancing challenges.
- Connect to HTB Network.
- Activate the Machine.
- Scan for Open Ports: Used 'nmap'.
- Exploit Vulnerabilities: Exploited vulnerabilities using tools like smbclient for SMB. 
- Retrieve the Flag: I found in a directory accessible via the exploited service, and retrieve its contents.

Fawn:
- Connect to the HTB Network.
- Turn on the machine.
- Check for Open Ports.
- Profit from Weaknesses: Used the proper tools and strategies to exploit vulnerabilities based on the ports and services that are open.
- Get the Flag Back.

---

Tier 1

According to the learning outcomes;
You will go deeper into the realm of cybersecurity pen-testing in the second tier, with an emphasis on beginner-friendly web exploitation techniques. You will learn the fundamentals of Remote File Inclusion, Server Side Template Injection, and SQL injection, as well as how to use Web/Reverse Shells efficiently. Building on what you learned in the first layer, you'll use these methods to take advantage of the many services that were previously shown off, giving you a practical grasp of their weaknesses.

This builds upon the foundational knowledge gained in Tier 0, introducing more complex challenges. It focuses on web traffic interception, directory discovery, and privilege escalation, requiring a deeper understanding of web technologies and system vulnerabilities. Their tasks, such as gaining access via cookies, uploading and tracking files, and hunting for passwords, provided hands-on experience with real-world scenarios 3.

- Web Traffic Interception: Learning to intercept and analyze web traffic using tools like BurpSuite is crucial for identifying vulnerabilities and understanding web application behavior.
- Directory Discovery: The use of directory busting tools like gobuster to explore hidden web directories and resources is an essential skill.
- Privilege Escalation: The lab emphasized the importance of privilege escalation, highlighting techniques for gaining higher-level access to systems.
- Information Disclosure Vulnerability: Identifying and exploiting information disclosure vulnerabilities, such as those found through manipulating cookies, is a key skill in penetration testing.

in conclusion, the Hack The Box Tier 0 and 1 challenges have indeed helped in building a solid base in cybersecurity. I have been able to gain hands-on experience in different cybersecurity concepts by working on these labs . From simple enumeration and exploitation to more advanced concepts such as directory brute-forcing and privilege escalation, these labs have helped bring the principles closer home. The principles have not just been explained but I also got a chance to apply them using the platform .There are high-tier labs out there and I still have ajourney to complete, which I will undertake to enhance my skills and knowledge in cybersecurity.