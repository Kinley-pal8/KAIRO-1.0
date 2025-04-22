---
title: Web Information Gathering
published: 2025-04-23
description: For My Reference
tags: [Notes]
category: Notes
author: Me
draft: false
---

# 3 - Web Information Gathering

### Web Reconnaissance Notes

### 1. Introduction to Web Reconnaissance

- **Definition**: Web reconnaissance is the initial phase of a security assessment, involving systematic collection of information about a target website or web application.
- **Primary Goals**:
    - **Identify Assets**: Discover public components like web pages, subdomains, IP addresses, and technologies.
    - **Discover Hidden Information**: Find exposed sensitive data (e.g., backup files, configs).
    - **Analyze Attack Surface**: Identify vulnerabilities, misconfigurations, and entry points.
    - **Gather Intelligence**: Collect data for social engineering or exploitation (e.g., key personnel, email addresses).
- **Importance**:
    - Attackers use recon to tailor attacks and bypass defenses.
    - Defenders use it to identify and patch vulnerabilities proactively.
- **Types of Reconnaissance**:
    - **Active Reconnaissance**:
        - Direct interaction with the target (e.g., port scanning, vulnerability scanning).
        - Techniques: Port scanning, vulnerability scanning, network mapping, banner grabbing, OS fingerprinting, service enumeration, web spidering.
        - Tools: Nmap, Nessus, Nikto, Burp Suite Spider, curl.
        - Risk: High detection risk due to direct interaction triggering IDS/firewalls.
    - **Passive Reconnaissance**:
        - No direct interaction; uses publicly available data.
        - Techniques: Search engine queries, WHOIS lookups, DNS analysis, web archive analysis, social media analysis, code repository analysis.
        - Tools: Google, WHOIS command-line tool, dig, Wayback Machine, LinkedIn, GitHub.
        - Risk: Very low detection risk, as it mimics normal internet activity.

---

### 2. WHOIS

- **Definition**: A query/response protocol to access databases storing registered internet resource details (domains, IP addresses, autonomous systems).
- **Purpose**: Acts as an internet "phonebook" to identify ownership and technical details of online assets.
- **Key WHOIS Record Components**:
    - **Domain Name**: e.g., [inlanefreight.com](http://inlanefreight.com/).
    - **Registrar**: Company where domain is registered (e.g., Amazon Registrar).
    - **Registrant Contact**: Person/organization owning the domain.
    - **Administrative Contact**: Manages domain operations.
    - **Technical Contact**: Handles technical issues.
    - **Creation/Expiration Dates**: When domain was registered and when it expires.
    - **Name Servers**: Translate domain to IP addresses.
- **History**:
    - Originated in the 1970s by Elizabeth Feinler at Stanford’s NIC for ARPANET.
    - WHOIS directory tracked network users, hostnames, and domains.
- **Importance for Web Recon**:
    - **Key Personnel**: Reveals names, emails, phone numbers for social engineering/phishing.
    - **Network Infrastructure**: Name servers/IPs indicate hosting providers or misconfigurations.
    - **Historical Data**: Tools like WhoisFreaks show changes in ownership or technical details.
- **Practical Scenarios**:
    - **Phishing Investigation**:
        - Suspicious email domain WHOIS shows recent registration, hidden registrant, and bulletproof hosting → likely phishing.
        - Action: Block domain, warn employees, investigate hosting provider.
    - **Malware Analysis**:
        - Malware C2 server WHOIS shows anonymous email, high-cybercrime country, lax registrar → likely compromised server.
        - Action: Notify hosting provider, investigate further.
    - **Threat Intelligence**:
        - WHOIS data on threat actor domains reveals patterns (clustered registrations, shared name servers, fake identities).
        - Action: Build TTP profiles, share IOCs for blocking future attacks.
- **Using WHOIS**:
    - **Installation**: `sudo apt update && sudo apt install whois -y` (Linux).
    - **Command**: `whois domain.com` (e.g., `whois facebook.com`).
    - **Example Output ([facebook.com](http://facebook.com/))**:
        - **Registrar**: RegistrarSafe, LLC.
        - **Creation Date**: 1997-03-29.
        - **Expiry Date**: 2033-03-30.
        - **Registrant**: Meta Platforms, Inc., Domain Admin.
        - **Domain Status**: Multiple protections (client/server Delete/Transfer/Update Prohibited).
        - **Name Servers**: [a.ns.facebook.com](http://a.ns.facebook.com/), [b.ns.facebook.com](http://b.ns.facebook.com/), etc.
        - **Insight**: Long-standing, secure domain with Meta-managed DNS.
    - **Limitations**: May not reveal individual employees or specific vulnerabilities; combine with other recon techniques.

---

### 3. DNS (Domain Name System)

- **Definition**: Translates human-readable domain names (e.g., [www.example.com](http://www.example.com/)) to IP addresses (e.g., 192.0.2.1), acting as the internet’s GPS.
- **How DNS Works**:
    1. **DNS Query**: Computer checks cache, then queries DNS resolver (e.g., ISP’s server).
    2. **Recursive Lookup**: Resolver queries root name server.
    3. **Root Name Server**: Directs to TLD name server (e.g., .com).
    4. **TLD Name Server**: Points to authoritative name server.
    5. **Authoritative Name Server**: Provides IP address.
    6. **Resolver Response**: Returns IP to computer, caches it.
    7. **Connection**: Computer connects to web server.
- **Hosts File**:
    - Location: `C:\\Windows\\System32\\drivers\\etc\\hosts` (Windows), `/etc/hosts` (Linux/MacOS).
    - Format: `<IP Address> <Hostname> [<Alias>]` (e.g., `127.0.0.1 localhost`).
    - Uses: Local development, testing, blocking sites (e.g., `0.0.0.0 unwanted-site.com`).
    - Edit: Requires admin/root privileges; changes apply instantly.
- **Key DNS Concepts**:
    - **Zone**: Managed portion of domain namespace (e.g., [example.com](http://example.com/) and subdomains).
    - **Zone File**: Stores resource records for a zone (e.g., NS, MX, A records).
    - **DNS Record Types**:
        - **A**: Maps hostname to IPv4 (e.g., `www.example.com IN A 192.0.2.1`).
        - **AAAA**: Maps hostname to IPv6.
        - **CNAME**: Aliases one hostname to another (e.g., `blog.example.com IN CNAME webserver.example.net`).
        - **MX**: Specifies mail servers (e.g., `example.com IN MX 10 mail.example.com`).
        - **NS**: Lists authoritative name servers.
        - **TXT**: Stores text data (e.g., SPF records).
        - **SOA**: Defines zone authority (e.g., serial number, refresh intervals).
        - **SRV**: Specifies service locations.
        - **PTR**: Maps IP to hostname for reverse lookups.
    - **IN**: Indicates Internet protocol in DNS records.
- **Importance for Web Recon**:
    - **Uncover Assets**: Subdomains, mail servers, and name servers reveal infrastructure.
    - **Map Infrastructure**: NS/A records identify hosting providers, load balancers, etc.
    - **Monitor Changes**: New subdomains (e.g., [vpn.example.com](http://vpn.example.com/)) or TXT records (e.g., 1Password usage) indicate new entry points or tools.
- **Example Zone File**:
    
    ```
    $TTL 3600
    @ IN SOA ns1.example.com. admin.example.com. (2024060401 3600 900 604800 86400)
    @ IN NS ns1.example.com.
    @ IN NS ns2.example.com.
    @ IN MX 10 mail.example.com.
    www IN A 192.0.2.1
    mail IN A 198.51.100.1
    ftp IN CNAME www.example.com.
    
    ```
    

---

### 4. Digging DNS

- **Purpose**: Practical DNS reconnaissance to extract infrastructure details using specialized tools.
- **DNS Tools**:
    - **dig**: Versatile, detailed DNS query tool.
    - **nslookup**: Basic DNS lookup.
    - **host**: Streamlined for quick A/AAAA/MX lookups.
    - **dnsenum**, **fierce**, **dnsrecon**: Subdomain enumeration and zone transfer attempts.
    - **theHarvester**: OSINT tool for emails, subdomains, and hosts.
    - **Online Services**: User-friendly DNS lookup interfaces.
- **dig (Domain Information Groper)**:
    - **Key Commands**:
        - `dig domain.com`: Default A record lookup.
        - `dig domain.com MX`: Mail servers.
        - `dig domain.com NS`: Name servers.
        - `dig domain.com TXT`: Text records.
        - `dig domain.com CNAME`: Canonical names.
        - `dig domain.com SOA`: Start of authority.
        - `dig @1.1.1.1 domain.com`: Query specific server.
        - `dig +trace domain.com`: Full resolution path.
        - `dig -x 192.168.1.1`: Reverse lookup.
        - `dig +short domain.com`: Concise output.
        - `dig +noall +answer domain.com`: Answer section only.
        - `dig domain.com ANY`: All records (may be blocked per RFC 8482).
    - **Caution**: Excessive queries may be detected/blocked; respect rate limits and obtain permission.
- **Example dig Output ([google.com](http://google.com/))**:
    
    ```
    dig google.com
    ; <<>> DiG 9.18.24-0ubuntu0.22.04.1-Ubuntu <<>> google.com
    ; Got answer:
    ; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 16449
    ; QUESTION SECTION:
    ;google.com. IN A
    ; ANSWER SECTION:
    google.com. 0 IN A 142.251.47.142
    ; Query time: 0 msec
    ; SERVER: 172.23.176.1#53(172.23.176.1) (UDP)
    ; WHEN: Thu Jun 13 10:45:58 SAST 2024
    
    ```
    
    - **Breakdown**:
        - **Header**: Query status (NOERROR), ID.
        - **Question**: Asked for A record of [google.com](http://google.com/).
        - **Answer**: IP 142.251.47.142.
        - **Additional**: Query time, server used.

---

### Web Reconnaissance: Subdomains, Zone Transfers, Virtual Hosts, and Certificate Transparency Notes

### 1. Subdomains

- **Definition**: Extensions of a main domain (e.g., `blog.example.com` for `example.com`) used to organize website sections or services (e.g., `mail.example.com`, `shop.example.com`).
- **Importance for Web Recon**:
    - **Development/Staging Environments**: Often less secure, may expose vulnerabilities or sensitive data (e.g., `dev.example.com`).
    - **Hidden Login Portals**: Administrative panels or internal tools (e.g., `admin.example.com`) may be accessible.
    - **Legacy Applications**: Old subdomains may run outdated, vulnerable software.
    - **Sensitive Information**: May expose configs, internal docs, or data inadvertently.
- **Subdomain Enumeration**:
    - **Active Enumeration**:
        - Interacts directly with DNS servers.
        - Techniques:
            - **DNS Zone Transfer**: Requests full zone file (rarely successful due to security).
            - **Brute-Force Enumeration**: Tests potential subdomain names using wordlists.
        - Tools: `dnsenum`, `fierce`, `gobuster`.
        - Risk: Detectable by target’s security systems.
    - **Passive Enumeration**:
        - Uses external data without querying target DNS.
        - Techniques:
            - **Certificate Transparency (CT) Logs**: Public SSL/TLS certificate records reveal subdomains.
            - **Search Engines**: Use operators (e.g., `site:*.example.com`) to find subdomains.
            - **Online Databases**: Aggregate DNS data from multiple sources.
        - Risk: Stealthy, low detection risk.
    - **Best Practice**: Combine active and passive methods for comprehensive discovery.

---

### 2. Subdomain Brute-Forcing

- **Definition**: Active technique using wordlists to systematically test potential subdomain names against a target domain to identify valid ones.
- **Process**:
    1. **Wordlist Selection**:
        - **General-Purpose**: Common names (e.g., `dev`, `staging`, `admin`).
        - **Targeted**: Industry-specific or based on naming patterns.
        - **Custom**: Built from recon data or keywords.
    2. **Iteration and Querying**: Tool appends wordlist entries to domain (e.g., `dev.example.com`).
    3. **DNS Lookup**: Checks A/AAAA records to confirm resolution to an IP.
    4. **Filtering/Validation**: Validates subdomains, optionally tests accessibility.
- **Tools**:
    - **dnsenum**: Comprehensive DNS recon, supports brute-forcing, zone transfers, Google scraping, WHOIS, reverse lookups.
    - **fierce**: User-friendly, detects wildcards, recursive discovery.
    - **dnsrecon**, **amass**, **assetfinder**, **puredns**: Specialized for subdomain discovery, varying in features and data sources.
- **Example (dnsenum)**:
    
    ```bash
    dnsenum --enum inlanefreight.com -f /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
    
    ```
    
    - Output: Discovered `www.inlanefreight.com`, `support.inlanefreight.com` (both resolve to `134.209.24.248`).
    - Features: Uses SecLists wordlist, recursive brute-forcing, DNS record enumeration.
- **Considerations**:
    - Generates significant DNS traffic; may be detected.
    - Use targeted wordlists to reduce noise and false positives.

---

### 3. DNS Zone Transfers

- **Definition**: Mechanism to replicate DNS records (zone file) from primary to secondary name server for consistency/redundancy.
- **Process**:
    1. **AXFR Request**: Secondary server requests full zone transfer (AXFR).
    2. **SOA Record**: Primary sends Start of Authority record (includes serial number).
    3. **DNS Records**: Transfers all records (A, AAAA, MX, CNAME, NS, etc.).
    4. **Completion**: Primary signals end of transfer.
    5. **Acknowledgment**: Secondary confirms receipt.
- **Vulnerability**:
    - Misconfigured servers allow unauthorized AXFR requests, leaking full zone data.
    - Reveals: Subdomains, IPs, name servers, hosting providers, potential misconfigurations.
    - Historical Context: Common in early internet; now secured but misconfigurations persist.
- **Exploitation**:
    - Tool: `dig`.
    - Command:
        
        ```bash
        dig axfr @nsztm1.digi.ninja zonetransfer.me
        
        ```
        
    - Output Example ([zonetransfer.me](http://zonetransfer.me/)):
        
        ```
        zonetransfer.me. 7200 IN SOA nsztm1.digi.ninja. robin.digi.ninja. ...
        zonetransfer.me. 7200 IN A 5.196.105.14
        zonetransfer.me. 7200 IN MX 0 ASPMX.L.GOOGLE.COM.
        www.zonetransfer.me. 7200 IN A 5.196.105.14
        asfdbbox.zonetransfer.me. 7200 IN A 127.0.0.1
        ...
        
        ```
        
    - Insight: Reveals subdomains (`asfdbbox.zonetransfer.me`), IPs, MX records, etc.
    - Note: `zonetransfer.me` is a test domain for demonstrating risks.
- **Remediation**:
    - Restrict zone transfers to trusted secondary servers.
    - Regularly audit DNS server configurations.
- **Recon Value**:
    - Comprehensive DNS infrastructure map.
    - Identifies hidden subdomains (e.g., dev/staging servers).
    - Even failed attempts reveal server configuration details.

---

### 4. Virtual Hosts (VHosts)

- **Definition**: Web server configurations allowing multiple websites/domains to share one server/IP, distinguished by HTTP Host header.
- **VHosts vs. Subdomains**:
    - **Subdomains**: DNS-based extensions (e.g., `blog.example.com`) with own DNS records.
    - **VHosts**: Server-side configs for domains/subdomains, may lack DNS records.
    - Example (Apache):
        
        ```
        <VirtualHost *:80>
            ServerName www.example1.com
            DocumentRoot /var/www/example1
        </VirtualHost>
        <VirtualHost *:80>
            ServerName www.example2.org
            DocumentRoot /var/www/example2
        </VirtualHost>
        
        ```
        
- **How VHosts Work**:
    1. Browser sends HTTP request with Host header (e.g., `www.inlanefreight.com`).
    2. Web server checks Host header against VHost configs.
    3. Serves content from matching VHost’s document root.
- **Accessing Non-DNS VHosts**:
    - Modify local hosts file (e.g., `/etc/hosts` or `C:\\Windows\\System32\\drivers\\etc\\hosts`).
    - Example: `192.168.1.1 hidden.example.com` to bypass DNS.
- **Types of Virtual Hosting**:
    - **Name-Based**: Uses Host header; most common, no extra IPs needed. Limited for some protocols (e.g., SSL/TLS).
    - **IP-Based**: Unique IP per site; protocol-agnostic but IP-intensive.
    - **Port-Based**: Different ports per site (e.g., `:80`, `:8080`); less user-friendly.
- **VHost Discovery (Fuzzing)**:
    - Technique: Test various hostnames against a server’s IP to find public/non-public VHosts.
    - Tool: **Gobuster**.
    - Command:
        
        ```bash
        gobuster vhost -u <http://inlanefreight.htb:81> -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt --append-domain
        
        ```
        
    - Output: Discovered `forum.inlanefreight.htb:81` (Status: 200).
    - Flags:
        - `u`: Target URL/IP.
        - `w`: Wordlist (e.g., SecLists).
        - `-append-domain`: Appends base domain (required in newer Gobuster versions).
        - `t`: Increase threads for speed.
        - `k`: Ignore SSL errors.
        - `o`: Save output to file.
- **Considerations**:
    - Generates significant traffic; may trigger IDS/WAF.
    - Requires authorization to avoid legal issues.
    - Analyze results for unusual VHosts (e.g., internal portals).

---

### 5. Certificate Transparency (CT) Logs

- **Definition**: Public, append-only ledgers recording SSL/TLS certificate issuances, maintained by independent organizations.
- **Purpose**:
    - **Detect Rogue Certificates**: Identify unauthorized/misissued certificates.
    - **CA Accountability**: Expose improper certificate issuance.
    - **Strengthen Web PKI**: Enhance trust in secure communications.
- **Recon Value**:
    - Lists subdomains in certificate Subject Alternative Name (SAN) fields.
    - Reveals historical/expired subdomains (e.g., outdated dev servers).
    - More reliable than brute-forcing; no dependency on wordlist quality.
- **Tools**:
    - [**crt.sh**](http://crt.sh/):
        - Web interface and API for domain searches.
        - Pros: Free, no registration, user-friendly.
        - Cons: Limited filtering.
    - **Censys**:
        - Advanced search for certificates/devices.
        - Pros: Extensive data, API access.
        - Cons: Requires registration (free tier available).
- **Example ([crt.sh](http://crt.sh/))**:
    
    ```bash
    curl -s "<https://crt.sh/?q=facebook.com&output=json>" | jq -r '.[] | select(.name_value | contains("dev")) | .name_value' | sort -u
    
    ```
    
    - Output: `.dev.facebook.com`, `dev.facebook.com`, `secure.dev.facebook.com`, etc.
    - Breakdown:
        - `curl`: Fetches JSON from [crt.sh](http://crt.sh/) for `facebook.com`.
        - `jq`: Filters for “dev” in `name_value` (subdomains), outputs unique results.
        - `sort -u`: Alphabetizes, removes duplicates.
- **Advantages**:
    - Passive, stealthy; no direct target interaction.
    - Comprehensive subdomain discovery, including obscure/historical ones.

---

### Practical Tips for Recon

- **Holistic Approach**:
    - Combine **zone transfers** (if misconfigured) for full DNS data, **brute-forcing** for active discovery, **CT logs** for passive subdomain enumeration, and **VHost fuzzing** for server-side configs.
- **Stealth**:
    - Prioritize passive methods (CT logs, search engines) to minimize detection.
    - Use targeted wordlists and rate-limited queries for active techniques.
- **Tool Synergy**:
    - Use `dig` for zone transfers, `dnsenum`/`gobuster` for brute-forcing, `crt.sh` for CT logs.
    - Automate with scripts (e.g., `curl` + `jq` for CT logs).
- **Validation**:
    - Confirm discovered subdomains/VHosts via HTTP requests or manual checks.
    - Investigate unusual findings (e.g., dev servers, internal portals).
- **Ethics**:
    - Obtain explicit authorization before active recon (brute-forcing, VHost fuzzing, zone transfer attempts).
    - Respect rate limits to avoid disrupting target servers.
- **Monitoring**:
    - Regularly check CT logs for new subdomains.
    - Monitor historical DNS changes (e.g., via zone transfer history if accessible).

---

### Key Tools and Commands

- **dig (Zone Transfer)**:
    
    ```bash
    dig axfr @<nameserver> <domain>
    
    ```
    
- **dnsenum (Subdomain Brute-Forcing)**:
    
    ```bash
    dnsenum --enum <domain> -f <wordlist>
    
    ```
    
- **gobuster (VHost Fuzzing)**:
    
    ```bash
    gobuster vhost -u http://<IP> -w <wordlist> --append-domain
    
    ```
    
- [**crt.sh](http://crt.sh/) (CT Logs)**:
    
    ```bash
    curl -s "<https://crt.sh/?q=><domain>&output=json" | jq -r '.[] | .name_value' | sort -u
    
    ```
    

---

### Web Reconnaissance: Crawling, Fingerprinting, robots.txt, and Well-Known URIs Notes

### 1. Fingerprinting

- **Definition**: Identifying technical details (e.g., web server, OS, software) of a website to uncover its technology stack and potential vulnerabilities.
- **Importance for Web Recon**:
    - **Targeted Attacks**: Enables exploits tailored to specific software versions.
    - **Misconfigurations**: Reveals outdated software or insecure settings.
    - **Prioritization**: Helps focus on vulnerable systems.
    - **Comprehensive Profile**: Builds a holistic view of the target’s infrastructure.
- **Techniques**:
    - **Banner Grabbing**: Analyzes server banners for software/version details.
    - **HTTP Headers**: Examines `Server`, `X-Powered-By` headers for tech clues.
    - **Probing Responses**: Sends crafted requests to elicit unique responses.
    - **Page Content Analysis**: Inspects page structure, scripts, or copyright headers.
- **Tools**:
    - **Wappalyzer**: Browser extension for CMS, framework detection.
    - **BuiltWith**: Detailed tech stack reports (free/paid).
    - **WhatWeb**: Command-line tool for tech fingerprinting.
    - **Nmap**: Network scanner with OS/service fingerprinting via NSE scripts.
    - **Netcraft**: Reports tech, hosting, and security posture.
    - **wafw00f**: Detects Web Application Firewalls (WAFs).
- **Example ([inlanefreight.com](http://inlanefreight.com/))**:
    - **Banner Grabbing (curl)**:
        
        ```bash
        curl -I inlanefreight.com
        
        ```
        
        - Output: `Server: Apache/2.4.41 (Ubuntu)`, redirects to HTTPS.
        - HTTPS: `X-Redirect-By: WordPress`, confirms WordPress usage.
        - Final: `Link: <.../wp-json/>`, WordPress API endpoints.
    - **wafw00f**:
        
        ```bash
        pip3 install git+https://github.com/EnableSecurity/wafw00f
        wafw00f inlanefreight.com
        
        ```
        
        - Output: Wordfence WAF (Defiant) detected.
        - Implication: Extra security layer; adapt recon to avoid blocking.
    - **Nikto**:
        
        ```bash
        sudo apt install perl
        git clone <https://github.com/sullo/nikto>
        cd nikto/program
        chmod +x ./nikto.pl
        nikto -h inlanefreight.com -Tuning b
        
        ```
        
        - Output:
            - IPs: `134.209.24.248`, IPv6 `2a03:b0c0:1:e0::32c:b001`.
            - Server: Apache/2.4.41 (Ubuntu, outdated).
            - WordPress: `/wp-login.php`, `license.txt` found.
            - Headers: Missing `Strict-Transport-Security`, `X-Content-Type-Options`.
            - Issues: Potential WordPress exploits, insecure headers.
- **Considerations**:
    - WAFs may block probes; use stealthy techniques.
    - Combine with other recon (e.g., crawling) for context.

---

### 2. Crawling

- **Definition**: Automated process (spidering) of systematically browsing websites by following links to collect data (e.g., pages, links, files).
- **How It Works**:
    1. Start with a **seed URL** (e.g., homepage).
    2. Fetch page, parse content, extract links.
    3. Queue links, crawl iteratively.
- **Crawling Strategies**:
    - **Breadth-First**: Explores all links on a page before deeper links; good for broad site structure overview.
    - **Depth-First**: Follows one link path deeply before backtracking; useful for specific content or deep pages.
- **Extracted Data**:
    - **Links**: Internal (site structure), external (relationships).
    - **Comments**: May reveal sensitive details (e.g., software versions, processes).
    - **Metadata**: Titles, descriptions, keywords, authors, dates.
    - **Sensitive Files**: Backup (`.bak`), config (`web.config`), logs (`error_log`), credentials, or API keys.
- **Importance for Recon**:
    - Maps site structure, uncovers hidden pages.
    - Identifies sensitive files or comments for exploitation.
    - Contextual analysis (e.g., combining comments with metadata) reveals vulnerabilities.
- **Example**:
    - Crawling finds `/files/` directory with enabled browsing, exposing backups or internal docs.
    - Comment about “file server” + `/files/` discovery suggests public access to sensitive data.
- **Considerations**:
    - Holistic analysis: Connect data points (e.g., comments + files) for insights.
    - Avoid overloading servers with excessive requests.

---

### 3. Creepy Crawlies (Web Crawling Tools)

- **Purpose**: Automate crawling for efficiency, allowing focus on data analysis.
- **Popular Tools**:
    - **Burp Suite Spider**: Active crawler for mapping web apps, finding hidden content/vulnerabilities.
    - **OWASP ZAP**: Free, open-source scanner with spider for vuln discovery (manual/automated).
    - **Scrapy**: Python framework for custom crawlers, ideal for tailored recon.
    - **Apache Nutch**: Scalable Java crawler for large-scale or focused crawls; requires setup expertise.
- **Scrapy Example ([inlanefreight.com](http://inlanefreight.com/))**:
    - **Installation**:
        
        ```bash
        pip3 install scrapy
        
        ```
        
    - **ReconSpider**:
        
        ```bash
        wget -O ReconSpider.zip <https://academy.hackthebox.com/storage/modules/>...
        unzip ReconSpider.zip
        python3 ReconSpider.py <http://inlanefreight.com>
        
        ```
        
    - **Output**: `results.json` with:
        - `emails`: `lily.floid@inlanefreight.com`, `cvs@inlanefreight.com`.
        - `links`: Internal (`/offices`), external (`themeansar.com`).
        - `external_files`: PDFs (`goals.pdf`).
        - `js_files`: JavaScript (`jquery-migrate.min.js`).
        - `form_fields`, `images`, `videos`, `audio`, `comments` (e.g., `<!-- masthead -->`).
    - **JSON Structure**:
        
        
        | Key | Description |
        | --- | --- |
        | emails | Email addresses found on site |
        | links | Internal/external URLs |
        | external_files | Downloadable files (e.g., PDFs) |
        | js_files | JavaScript files |
        | form_fields | Input fields in forms |
        | images | Image URLs |
        | videos | Video URLs |
        | audio | Audio URLs |
        | comments | HTML comments |
- **Ethical Considerations**:
    - Obtain permission before crawling.
    - Respect server resources; avoid excessive requests.
- **Recon Value**:
    - Extracts structured data for architecture mapping.
    - Identifies potential entry points (e.g., forms, sensitive files).

---

### 4. robots.txt

- **Definition**: Text file in a website’s root (e.g., `www.example.com/robots.txt`) following the Robots Exclusion Standard, guiding crawlers on accessible/forbidden areas.
- **Structure**:
    - **User-agent**: Targets specific bots (e.g.,  for all, `Googlebot` for Google).
    - **Directives**:
        - `Disallow`: Blocks paths (e.g., `/admin/`).
        - `Allow`: Permits paths (e.g., `/public/`).
        - `Crawl-delay`: Sets request delay (e.g., `Crawl-delay: 10`).
        - `Sitemap`: Points to sitemap URL (e.g., `Sitemap: <https://example.com/sitemap.xml`>).
- **Example**:
    
    ```
    User-agent: *
    Disallow: /admin/
    Disallow: /private/
    Allow: /public/
    User-agent: Googlebot
    Crawl-delay: 10
    Sitemap: <https://www.example.com/sitemap.xml>
    
    ```
    
    - Insight: Suggests `/admin/` and `/private/` may contain sensitive content.
- **Why Respect robots.txt**:
    - Prevents server overload.
    - Protects sensitive data from indexing.
    - Ensures legal/ethical compliance (ignoring may violate terms of service).
- **Recon Value**:
    - **Hidden Directories**: `Disallow` paths (e.g., `/admin/`) may indicate sensitive areas.
    - **Site Structure**: Allowed/disallowed paths map site layout.
    - **Crawler Traps**: Honeypot paths reveal security awareness.
- **Considerations**:
    - Respect directives during ethical recon.
    - Analyze `Disallow` paths manually for sensitive content.

---

### 5. Well-Known URIs

- **Definition**: Standardized directory (`/.well-known/`) for metadata, configs, and service info, defined by RFC 8615, maintained by IANA.
- **Examples**:
    - `security.txt` (RFC 9116): Security contact info.
    - `change-password`: Password change page URL.
    - `openid-configuration`: OpenID Connect metadata.
    - `assetlinks.json`: Verifies digital asset ownership.
    - `mta-sts.txt`: Email security policy (MTA-STS).
- **OpenID Connect (openid-configuration)**:
    - URL: `https://example.com/.well-known/openid-configuration`.
    - JSON Output:
        - Endpoints: Authorization, token, userinfo.
        - `jwks_uri`: Cryptographic key set.
        - Scopes, response types, algorithms.
    - Recon Value:
        - Maps authentication endpoints.
        - Reveals security mechanisms (e.g., signing algorithms).
- **Recon Value**:
    - Discover endpoints, configs, and security policies.
    - Structured metadata aids in mapping site functionality.
- **Approach**:
    - Check IANA registry for URIs.
    - Test `/.well-known/` paths (e.g., `curl <https://example.com/.well-known/security.txt`>).
- **Considerations**:
    - Passive recon; low detection risk.
    - Combine with crawling for comprehensive mapping.

---

### Practical Tips for Recon

- **Integrated Workflow**:
    - **Fingerprinting**: Identify tech stack (e.g., Apache, WordPress) to guide vuln targeting.
    - **Crawling**: Map site structure, extract links/files/comments (use Scrapy for automation).
    - **robots.txt**: Check for hidden paths (e.g., `/admin/`) to investigate manually.
    - **Well-Known URIs**: Probe `/.well-known/` for configs (e.g., `openid-configuration`).
- **Stealth**:
    - Use passive methods (e.g., robots.txt, well-known URIs) to avoid detection.
    - Limit crawl intensity; respect `Crawl-delay` in robots.txt.
- **Tool Synergy**:
    - **curl**: Quick header grabbing (`curl -I`).
    - **wafw00f/Nikto**: Detect WAFs, fingerprint tech/vulns.
    - **Scrapy**: Custom crawling for structured data.
- **Validation**:
    - Manually verify `Disallow` paths or sensitive files from robots.txt/crawling.
    - Test well-known URIs for active endpoints.
- **Ethics**:
    - Obtain explicit authorization for active recon (crawling, fingerprinting).
    - Avoid overloading servers; use rate-limiting.
- **Contextual Analysis**:
    - Combine findings (e.g., WordPress from fingerprinting + `/files/` from crawling + `/admin/` from robots.txt) for deeper insights.

---

### Key Tools and Commands

- **curl (Banner Grabbing)**:
    
    ```bash
    curl -I <https://inlanefreight.com>
    
    ```
    
- **wafw00f (WAF Detection)**:
    
    ```bash
    wafw00f inlanefreight.com
    
    ```
    
- **Nikto (Fingerprinting)**:
    
    ```bash
    nikto -h inlanefreight.com -Tuning b
    
    ```
    
- **Scrapy (Crawling)**:
    
    ```bash
    python3 ReconSpider.py <http://inlanefreight.com>
    
    ```
    
- **robots.txt Check**:
    
    ```bash
    curl <https://inlanefreight.com/robots.txt>
    
    ```
    
- **Well-Known URIs**:
    
    ```bash
    curl <https://inlanefreight.com/.well-known/security.txt>
    
    ```
    

---

### Web Reconnaissance: Search Engine Discovery, Web Archives, and Automation Notes

### 1. Search Engine Discovery

- **Definition**: Leveraging search engines for OSINT (Open Source Intelligence) to gather data about targets (e.g., websites, organizations, individuals) using specialized queries.
- **Importance for Web Recon**:
    - **Open Source**: Publicly accessible, legal, and ethical.
    - **Breadth**: Indexes vast web content.
    - **Ease of Use**: No advanced skills required.
    - **Cost-Effective**: Free resource.
- **Applications**:
    - **Security Assessment**: Identify vulnerabilities, exposed data, attack vectors.
    - **Competitive Intelligence**: Gather competitor insights (products, strategies).
    - **Investigative Journalism**: Uncover hidden connections or practices.
    - **Threat Intelligence**: Track malicious actors, predict attacks.
- **Limitations**:
    - Not all data is indexed.
    - Hidden/protected data may be inaccessible.
- **Search Operators**:
    
    
    | Operator | Description | Example | Use Case |
    | --- | --- | --- | --- |
    | `site:` | Limits to a domain | `site:example.com` | Find all pages on `example.com` |
    | `inurl:` | Term in URL | `inurl:login` | Locate login pages |
    | `filetype:` | Specific file type | `filetype:pdf` | Find PDFs |
    | `intitle:` | Term in title | `intitle:"confidential report"` | Find titled documents |
    | `intext:` | Term in body | `intext:"password reset"` | Find pages with specific text |
    | `cache:` | Cached page | `cache:example.com` | View past content |
    | `link:` | Pages linking to URL | `link:example.com` | Find external links |
    | `related:` | Similar websites | `related:example.com` | Discover similar sites |
    | `info:` | Page summary | `info:example.com` | Get basic site details |
    | `numrange:` | Number range | `site:example.com numrange:1000-2000` | Find pages with numbers |
    | `allintext:` | All terms in body | `allintext:admin password reset` | Pages with multiple terms |
    | `allinurl:` | All terms in URL | `allinurl:admin panel` | URLs with multiple terms |
    | `AND`, `OR`, `NOT` | Logical operations | `site:bank.com NOT inurl:login` | Refine searches |
    | `*` | Wildcard | `site:socialnetwork.com filetype:pdf user*manual` | Match variations |
    | `..` | Range search | `site:ecommerce.com "price" 100..500` | Find price ranges |
    | `""` | Exact phrase | `"information security policy"` | Precise matches |
    | `-` | Exclude term | `site:news.com -inurl:sports` | Exclude topics |
- **Google Dorking (Google Hacking)**:
    - Technique using operators to find sensitive data or vulnerabilities.
    - Examples:
        - Login Pages: `site:example.com inurl:(login | admin)`
        - Exposed Files: `site:example.com filetype:(pdf | xls | doc)`
        - Config Files: `site:example.com inurl:config.php`
        - Database Backups: `site:example.com filetype:sql`
    - Resource: Google Hacking Database for advanced dorks.
- **Considerations**:
    - Passive recon; low detection risk.
    - Combine with other methods (e.g., web archives) for comprehensive insights.
    - Verify findings manually to avoid false positives.

---

### 2. Web Archives

- **Definition**: Digital archives (e.g., Internet Archive’s Wayback Machine) storing historical snapshots of websites, capturing content, design, and functionality.
- **How Wayback Machine Works**:
    1. **Crawling**: Bots download webpages and resources (HTML, CSS, JS, images).
    2. **Archiving**: Stores snapshots with timestamps, creating historical records.
    3. **Accessing**: Users view snapshots via URL and date selection.
- **Archiving Frequency**:
    - Varies by site popularity, update frequency, and archive resources.
    - Popular sites: Multiple daily snapshots.
    - Less popular: Sparse snapshots over years.
- **Limitations**:
    - Not all pages are captured.
    - Owners can request exclusion (not guaranteed).
- **Recon Value**:
    - **Hidden Assets/Vulnerabilities**: Reveals old pages, directories, files, or subdomains.
    - **Change Tracking**: Shows site evolution (structure, tech, vulnerabilities).
    - **OSINT**: Provides insights into past activities, strategies, employees, tech.
    - **Stealth**: Passive; no direct target interaction.
- **Example (HackTheBox)**:
    - Access: Enter `hackthebox.com` in Wayback Machine, select earliest snapshot (2017-06-10).
    - Insight: View historical design, content, or exposed resources.
- **Considerations**:
    - Analyze snapshots for discontinued subdomains or sensitive files.
    - Compare versions to detect tech upgrades or security improvements.
    - Cross-reference with current site data for anomalies.

---

### 3. Automating Recon

- **Definition**: Using tools/frameworks to automate repetitive recon tasks for efficiency, scalability, and consistency.
- **Why Automate**:
    - **Efficiency**: Faster than manual recon.
    - **Scalability**: Handles multiple targets/domains.
    - **Consistency**: Reduces human error.
    - **Coverage**: Performs diverse tasks (DNS, subdomains, crawling, scanning).
    - **Integration**: Combines with other tools for seamless workflows.
- **Recon Frameworks**:
    - **FinalRecon**: Python tool for headers, WHOIS, SSL, crawling, DNS, subdomains, directories, Wayback Machine.
    - **Recon-ng**: Modular Python framework for DNS, subdomains, crawling, port scanning, exploits.
    - **theHarvester**: Gathers emails, subdomains, hosts, employee names from public sources.
    - **SpiderFoot**: OSINT tool for domains, emails, social media, DNS, crawling, scanning.
    - **OSINT Framework**: Collection of tools for social media, search engines, public records.
- **FinalRecon Example ([inlanefreight.com](http://inlanefreight.com/))**:
    - **Installation**:
        
        ```bash
        git clone <https://github.com/thewhiteh4t/FinalRecon.git>
        cd FinalRecon
        pip3 install -r requirements.txt
        chmod +x ./finalrecon.py
        ./finalrecon.py --help
        
        ```
        
    - **Command**:
        
        ```bash
        ./finalrecon.py --headers --whois --url <http://inlanefreight.com>
        
        ```
        
    - **Output**:
        - Headers: `Server: Apache/2.4.41`, `X-Redirect-By: WordPress`, `Content-Type: text/html; charset=UTF-8`.
        - WHOIS:
            - Domain: `inlanefreight.com`
            - Registrar: Amazon Registrar
            - Creation: 2019-08-05
            - Expiry: 2024-08-05
            - Name Servers: `ns-1303.awsdns-34.org`, etc.
        - Export: Saved to `~/.local/share/finalrecon/dumps/`.
    - **Options**:
        - `-headers`: Header info.
        - `-whois`: WHOIS lookup.
        - `-sslinfo`: SSL certificate details.
        - `-crawl`: Crawl site.
        - `-dns`: DNS enumeration.
        - `-sub`: Subdomain enumeration.
        - `-dir`: Directory search.
        - `-wayback`: Wayback Machine URLs.
        - `-ps`: Port scan.
        - `-full`: All modules.
        - Extra: `w` (wordlist), `e` (file extensions), `o` (export format).
- **Considerations**:
    - Active recon (e.g., crawling, scanning) may trigger detection; use with caution.
    - Obtain authorization for legal/ethical compliance.
    - Customize modules for target-specific recon.

---

### Practical Tips for Recon

- **Integrated Workflow**:
    - **Search Engine Discovery**: Use Google Dorks to find login pages, configs, or exposed files; verify with manual checks.
    - **Web Archives**: Check Wayback Machine for historical subdomains, files, or tech stacks; compare with current site.
    - **Automation**: Use FinalRecon for quick, broad recon; supplement with targeted tools (e.g., Scrapy, Nikto).
- **Stealth**:
    - Prioritize passive methods (search engines, Wayback Machine) to avoid detection.
    - Rate-limit automated scans to respect server resources.
- **Tool Synergy**:
    - **Google**: `site:inlanefreight.com filetype:pdf` for documents.
    - **Wayback Machine**: Access via `archive.org` for historical data.
    - **FinalRecon**: Combine `-sub`, `-crawl`, `-wayback` for comprehensive recon.
- **Validation**:
    - Manually verify dork results (e.g., login pages, backups).
    - Cross-check Wayback findings with current site for relevance.
    - Analyze automated outputs for actionable insights (e.g., outdated software).
- **Ethics**:
    - Obtain explicit authorization for active recon (e.g., FinalRecon scans).
    - Respect robots.txt and site terms during crawling.
- **Contextual Analysis**:
    - Combine dork findings (e.g., `/admin/` from `inurl:admin`) with Wayback data (e.g., old admin panel) and FinalRecon headers (e.g., WordPress) for deeper insights.

---
