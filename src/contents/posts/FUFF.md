---
title: FUFF
published: 2025-04-28
description: For My Reference
tags: [Notes]
category: Notes
author: Me
draft: false
---

# 4 - FUFF

## Web Fuzzing Notes

## 1. Introduction

- **Module Overview**: The "Attacking Web Applications with Ffuf" module teaches the use of `ffuf`, a powerful open-source tool for web fuzzing, to identify hidden directories, files, subdomains, virtual hosts (vhosts), and GET parameters. This is a critical skill in penetration testing and web application security assessments.
- **Ffuf Tool**: A fast, customizable tool designed for fuzzing web applications, automating the discovery of resources by sending requests and analyzing HTTP responses. It’s widely used for its speed and flexibility.
- **Key Objectives**:
    - Uncover hidden directories and files to map a web application's structure.
    - Identify file extensions (e.g., `.php`, `.html`) to understand the technology stack.
    - Discover public and non-public subdomains and vhosts to expand attack surfaces.
    - Fuzz GET parameters to find hidden or vulnerable endpoints.
- **Fuzzing Concept**: Fuzzing involves sending automated, systematic inputs (e.g., directory names, subdomain names) to a web server and analyzing responses (e.g., HTTP 200 OK) to confirm the existence of resources. It’s like guessing possible paths or parameters using predefined wordlists.
- **Why Ffuf?**: Manual enumeration is time-consuming and error-prone. `ffuf` automates the process, supports large wordlists, and allows filtering to reduce noise, making it ideal for large-scale testing.
- **Topics Covered**:
    - Directory and page fuzzing to explore file structures.
    - Subdomain fuzzing to find public subdomains via DNS.
    - Vhost fuzzing to discover non-public subdomains on a known IP.
    - Filtering techniques to refine results.
    - GET parameter fuzzing to uncover hidden functionality or vulnerabilities.
    - DNS record management for testing non-public websites.
- **Practical Use**: Fuzzing helps testers identify misconfigured or hidden resources that developers may not have secured, revealing potential vulnerabilities like exposed admin panels or sensitive files.

## 2. Web Fuzzing Basics

- **Definition**: Fuzzing is a testing technique that sends varied inputs to a system to observe its behavior. In web fuzzing, inputs are URLs, headers, or parameters, and the goal is to identify valid resources by analyzing HTTP response codes.
- **Types of Fuzzing**:
    - **SQL Injection**: Sending special characters (e.g., `' OR 1=1`) to exploit database queries.
    - **Buffer Overflow**: Sending oversized inputs to crash or exploit software.
    - **Web Fuzzing**: Sending requests for common directory, file, or subdomain names to discover hidden resources.
- **HTTP Response Codes**:
    - **200 OK**: Resource exists and is accessible (e.g., a login page).
    - **404 Not Found**: Resource does not exist (e.g., `https://example.com/doesnotexist`).
    - **301/302 Redirect**: Resource moved, often indicating a valid directory or subdomain.
    - **403 Forbidden**: Resource exists but access is restricted, potentially interesting for further testing.
    - **500 Internal Server Error**: May indicate a misconfiguration or vulnerability when unexpected inputs are sent.
- **Why Automate?**: Websites can have thousands of potential paths or subdomains. Manual testing is impractical, while `ffuf` can send hundreds of requests per second, efficiently identifying valid resources.
- **Wordlists**:
    - Lists of common terms for directories, files, subdomains, or parameters.
    - Source: SecLists repository (`/opt/useful/seclists` on PwnBox), a popular collection of security-focused wordlists.
    - Examples:
        - `directory-list-2.3-small`: For directory and page fuzzing.
        - `subdomains-top1million-5000.txt`: For subdomain fuzzing.
        - `burp-parameter-names.txt`: For parameter fuzzing.
    - **Tip**: Wordlists may include metadata (e.g., copyright comments). Use `ffuf`’s `fw` (filter words) option to exclude irrelevant entries and clean results.
- **Success Rate**: Wordlist-based fuzzing can uncover ~90% of a website’s resources, but unique or randomly named resources (e.g., `/secret-xyz123`) may require custom wordlists or alternative techniques.
- **Ethical Considerations**: Fuzzing can generate significant traffic. Avoid aggressive scans (e.g., high threads, unlimited recursion) on production servers to prevent accidental denial-of-service (DoS).

## 3. Directory Fuzzing

- **Objective**: Identify accessible directories on a web server to understand its structure and find potential entry points.
- **Tool**: `ffuf`, pre-installed on PwnBox. Install via `apt install ffuf` or download from GitHub for other systems.
- **Getting Started**:
    - Run `ffuf -h` to view options, including HTTP settings, matchers, filters, and input configurations.
    - Key options:
        - `w <wordlist:keyword>`: Specify wordlist and keyword (e.g., `FUZZ` for placeholder).
        - `u <URL>`: Target URL with `FUZZ` (e.g., `http://SERVER_IP:PORT/FUZZ`).
        - `mc <codes>`: Match HTTP status codes (default: 200, 204, 301, 302, 307, 401, 403).
        - `t <threads>`: Number of threads (e.g., 40 default, 200 for speed, but high values risk DoS).
- **Example Command**:
    
    ```bash
    ffuf -w /opt/useful/seclists/Discovery/Web-Content/directory-list-2.3-small:FUZZ -u http://SERVER_IP:PORT/FUZZ
    
    ```
    
- **Performance**: Scans ~90,000 URLs in <10 seconds, depending on network speed and server responsiveness.
- **Sample Output**:
    - Found `/blog` directory (HTTP 200, empty page, no 404/403 errors).
    - Indicates an accessible directory, but it may lack a default page (e.g., `index.html`).
- **Best Practices**:
    - Verify findings manually by visiting URLs (e.g., `http://SERVER_IP:PORT/blog`) to confirm content or explore further.
    - Use moderate thread counts (e.g., 40–100) on remote servers to avoid overwhelming the target.
    - Save results with `o <file>` for later analysis.

## 4. Page Fuzzing

- **Objective**: Discover files within identified directories (e.g., `/blog`) and determine their file extensions to understand the application’s technology.
- **Extension Fuzzing**:
    - **Goal**: Identify file types used by the website (e.g., `.php`, `.aspx`, `.html`).
    - **Challenge**: Directories like `/blog` may return empty pages, requiring fuzzing to find hidden files.
    - **Method**: Fuzz extensions on a common file (e.g., `index`) using `/opt/useful/seclists/Discovery/Web-Content/web-extensions.txt`.
    - **Command**:
        
        ```bash
        ffuf -w /opt/useful/seclists/Discovery/Web-Content/web-extensions.txt:FUZZ -u http://SERVER_IP:PORT/blog/indexFUZZ
        
        ```
        
    - **Output**:
        - `.php`: HTTP 200 (valid extension).
        - `.phps`: HTTP 403 (forbidden, not useful).
    - **Note**: The wordlist includes the dot (`.`), so no need to add it after `index`.
- **Page Fuzzing**:
    - **Goal**: Find specific PHP files within a directory using the confirmed `.php` extension.
    - **Method**: Use the same directory wordlist, placing `FUZZ` in the filename position.
    - **Command**:
        
        ```bash
        ffuf -w /opt/useful/seclists/Discovery/Web-Content/directory-list-2.3-small:FUZZ -u http://SERVER_IP:PORT/blog/FUZZ.php
        
        ```
        
    - **Output**:
        - `index.php`: HTTP 200, size 0 (empty page).
        - `[REDACTED].php`: HTTP 200, size 465 (contains content).
    - **Verification**: Manually visit pages (e.g., `http://SERVER_IP:PORT/blog/[REDACTED].php`) to inspect content, which may reveal sensitive information or functionality.
- **Tips**:
    - HTTP response headers may hint at server type (e.g., Apache → `.php`, IIS → `.asp`/`.aspx`), but fuzzing is more reliable for confirmation.
    - Combine multiple wordlists (e.g., for different extensions) for broader coverage if initial scans yield limited results.
    - Look for unusual responses (e.g., 500 errors) that might indicate misconfigurations.

## 5. Recursive Fuzzing

- **Objective**: Automate fuzzing across directories, subdirectories, and files to efficiently explore complex website structures.
- **Why Recursive?**: Manually fuzzing each subdirectory (e.g., `/login/user/content`) is time-consuming, especially for websites with deep or nested directory trees.
- **Recursive Flags**:
    - `recursion`: Automatically scans newly discovered directories.
    - `recursion-depth <n>`: Limits scan depth (e.g., `recursion-depth 1` scans main directories and their immediate subdirectories, avoiding deeper paths like `/login/user`).
    - `e <extension>`: Specifies file extension (e.g., `e .php`).
    - `v`: Outputs full URLs for clarity (e.g., `http://SERVER_IP:PORT/forum/index.php`).
- **Example Command**:
    
    ```bash
    ffuf -w /opt/useful/seclists/Discovery/Web-Content/directory-list-2.3-small:FUZZ -u http://SERVER_IP:PORT/FUZZ -recursion -recursion-depth 1 -e .php -v
    
    ```
    
- **Sample Output**:
    - Directories: `/forum`, `/blog` (HTTP 301/200).
    - Files: `index.php` (HTTP 200, size 0 or 986).
    - New job queued: `http://SERVER_IP:PORT/forum/FUZZ` for recursive scanning.
- **Performance**:
    - Generates ~6x more requests than single-level fuzzing due to scanning subdirectories.
    - Wordlist size doubles (tests with/without `.php`).
    - Comprehensive results include all previously identified resources plus new findings.
- **Best Practices**:
    - Always set `recursion-depth` to avoid excessive scanning of deep directory structures (e.g., `/login/user/content/uploads`).
    - Focus recursive scans on interesting directories (e.g., `/forum`) for targeted follow-up.
    - Use `v` to track which files belong to which directories, aiding manual verification.
    - Monitor scan duration and server response to avoid overwhelming the target.

## 6. DNS Records

- **Context**: Attempting to access `http://academy.htb:PORT` fails because `academy.htb` is a non-public, local website used in Hack The Box (HTB) exercises, not listed in public DNS or the local `/etc/hosts` file.
- **Issue**: Browsers resolve URLs to IPs by checking:
    1. Local `/etc/hosts` file.
    2. Public DNS (e.g., Google’s 8.8.8.8).Without an entry for `academy.htb`, the browser cannot connect, resulting in a "can’t connect to the server" error.
- **Solution**: Manually add the target IP and domain to `/etc/hosts` to enable resolution.
    - **Command**:
        
        ```bash
        sudo sh -c 'echo "SERVER_IP academy.htb" >> /etc/hosts'
        
        ```
        
    - **Result**: Visiting `http://academy.htb:PORT` now resolves, displaying the HTB Academy page.
- **Verification**:
    - Accessing `http://academy.htb:PORT/blog/index.php` confirms it’s the same site as scans performed directly on the IP.
    - Previous recursive scans on the IP found no admin or panel-related resources, suggesting the need to explore subdomains or vhosts.
- **Key Insight**: Non-public websites, like those in HTB, require manual `/etc/hosts` configuration. Public domains (e.g., `google.com`) resolve automatically via DNS, but local or private domains do not.
- **Troubleshooting**:
    - Ensure the correct `SERVER_IP` and `PORT` are used, especially if the exercise environment restarts.
    - Check for firewall or network issues if connections still fail after updating `/etc/hosts`.

## 7. Sub-domain Fuzzing

- **Objective**: Identify subdomains (e.g., `photos.google.com` under `google.com`) by checking for public DNS records that resolve to working server IPs.
- **Mechanism**: `ffuf` sends requests to potential subdomains (e.g., `support.example.com`) and checks for valid HTTP responses (e.g., 200, 301), indicating a DNS record exists.
- **Requirements**:
    - **Wordlist**: `/opt/useful/seclists/Discovery/DNS/subdomains-top1million-5000.txt`, containing common subdomain names (e.g., `www`, `mail`, `blog`). Larger lists (e.g., `top1million-20000.txt`) can be used for more thorough scans.
    - **Target**: Example target: `inlanefreight.com`.
- **Command**:
    
    ```bash
    ffuf -w /opt/useful/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u https://FUZZ.inlanefreight.com/
    
    ```
    
- **Sample Output**:
    - Subdomains found:
        - `support`: HTTP 301, size 0.
        - `ns3`: HTTP 301, size 0.
        - `blog`: HTTP 301, size 0.
        - `my`: HTTP 301, size 0.
        - `www`: HTTP 200, size 22266 (likely the main site).
- **Testing Another Target**:
    - Target: `academy.htb`.
    - Command:
        
        ```bash
        ffuf -w /opt/useful/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u https://FUZZ.academy.htb/
        
        ```
        
    - **Result**: No hits after scanning 4997 subdomains, indicating no public subdomains for `academy.htb`.
- **Why No Hits?**:
    - `academy.htb` subdomains lack public DNS records, as it’s a local HTB domain.
    - Only the main domain (`academy.htb`) was added to `/etc/hosts`. When `ffuf` tests subdomains (e.g., `support.academy.htb`), it queries public DNS, which finds no records.
- **Key Insight**: Subdomain fuzzing relies on public DNS, making it ineffective for non-public or internal subdomains. For such cases, vhost fuzzing is required.
- **Tips**:
    - Use `mc all` to capture all status codes for broader analysis.
    - Manually verify hits (e.g., visit `https://support.inlanefreight.com`) to confirm functionality.
    - Larger wordlists increase scan time but improve coverage.

## 8. Vhost Fuzzing

- **Objective**: Discover virtual hosts (vhosts) and non-public subdomains on a known IP, bypassing the limitations of public DNS-based subdomain fuzzing.
- **Vhosts vs. Subdomains**:
    - **Vhosts**: Multiple websites (e.g., `admin.academy.htb`, `www.academy.htb`) served on the same IP, distinguished by the `Host` header in HTTP requests. They may or may not have public DNS records.
    - **Subdomains**: May resolve to different IPs and typically rely on public DNS records.
- **Challenge**: Non-public subdomains (e.g., internal vhosts) won’t resolve via public DNS or standard subdomain fuzzing, as seen with `academy.htb`.
- **Method**: Fuzz the `Host` HTTP header to test for vhosts on the target IP, effectively asking the server if it hosts specific domains.
- **Command**:
    
    ```bash
    ffuf -w /opt/useful/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u http://academy.htb:PORT/ -H "Host: FUZZ.academy.htb"
    
    ```
    
- **Issue**: All requests return HTTP 200 because the server responds with the default `academy.htb` page, regardless of the `Host` header’s value.
- **Solution**: Filter results by response size to identify unique vhost pages, as valid vhosts typically return different content (see Filtering Requests).
- **Key Insight**: Vhost fuzzing targets the server’s configuration directly, not DNS, making it ideal for discovering non-public or internal subdomains on a known IP.
- **Tips**:
    - Use the same subdomain wordlist (`subdomains-top1million-5000.txt`) for consistency.
    - Test with and without `https://` to account for protocol differences.
    - Be prepared to update `/etc/hosts` for manual verification of discovered vhosts.

## 9. Filtering Requests

- **Objective**: Refine `ffuf` results by filtering out irrelevant or repetitive responses to focus on meaningful findings.
- **Default Behavior**: `ffuf` filters out HTTP 404 (Not Found) by default but retains 200, 301, 403, etc., which can result in noisy output, especially in vhost fuzzing where all requests may return 200.
- **Filtering Options** (`ffuf -h`):
    - **Matchers**:
        - `mc`: Match HTTP status codes (e.g., `mc 200,301`).
        - `ms`: Match response size.
        - `mw`: Match word count in response.
        - `ml`: Match line count.
        - `mr`: Match regex.
    - **Filters**:
        - `fc`: Filter HTTP status codes (e.g., `fc 404`).
        - `fs`: Filter response size (e.g., `fs 900`).
        - `fw`: Filter word count.
        - `fl`: Filter line count.
        - `fr`: Filter regex.
- **Vhost Fuzzing Example**:
    - **Problem**: Vhost scan (`Host: FUZZ.academy.htb`) returns HTTP 200, size 900 for all requests, corresponding to the default `academy.htb` page.
    - **Solution**: Filter out responses with size 900 to isolate unique vhost responses.
    - **Command**:
        
        ```bash
        ffuf -w /opt/useful/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u http://academy.htb:PORT/ -H "Host: FUZZ.academy.htb" -fs 900
        
        ```
        
    - **Output**: Found `admin` vhost (HTTP 200, size 0, words 1, lines 1), indicating an empty but distinct page.
- **Verification**:
    - Add `admin.academy.htb` to `/etc/hosts`:
        
        ```bash
        sudo sh -c 'echo "SERVER_IP admin.academy.htb" >> /etc/hosts'
        
        ```
        
    - Visit `http://admin.academy.htb:PORT/`: Displays an empty page, unlike `academy.htb`.
    - Test `http://admin.academy.htb:PORT/blog/index.php`: Returns 404, confirming a different vhost with a distinct file structure.
- **Next Steps**: Perform a recursive scan on `admin.academy.htb` to identify pages or directories.
- **Tips**:
    - Determine the default response size by running a test request with an invalid `Host` header (e.g., `Host: invalid.academy.htb`).
    - Use multiple filters (e.g., `fs 900 -fc 404`) for complex scans.
    - Save filtered results with `o <file>` for easier analysis.

## 10. GET Parameter Fuzzing

- **Context**: A recursive scan on `admin.academy.htb` reveals `http://admin.academy.htb:PORT/admin/admin.php`, which returns "You don't have access to read the flag!"
- **Hypothesis**: The page may require a specific GET parameter (e.g., `?key=value`) to bypass access restrictions, as no login or cookies are present.
- **Objective**: Fuzz GET parameter names to identify valid ones accepted by `admin.php`, potentially granting access to the flag or revealing vulnerabilities.
- **Method**:
    - Use wordlist: `/opt/useful/seclists/Discovery/Web-Content/burp-parameter-names.txt`, containing common parameter names (e.g., `id`, `key`, `token`).
    - Place `FUZZ` in the parameter name position (e.g., `?FUZZ=key`).
- **Command**:
    
    ```bash
    ffuf -w /opt/useful/seclists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u http://admin.academy.htb:PORT/admin/admin.php?FUZZ=key
    
    ```
    
- **Filtering**: Many parameters will return the same error page ("You don't have access"). Filter out the default response size (e.g., `fs <error_page_size>`) to isolate unique responses indicating valid parameters.
- **Importance**:
    - Fuzzing parameters can uncover unpublished or poorly secured endpoints, such as debug or admin parameters.
    - These are often less tested and vulnerable to exploits like SQL injection, cross-site scripting (XSS), or privilege escalation.
- **Next Steps**:
    - If a valid parameter is found (e.g., `?token=key`), fuzz its values using a wordlist (e.g., `common.txt`) to test for access:
        
        ```bash
        ffuf -w /opt/useful/seclists/Discovery/Web-Content/common.txt:FUZZ -u http://admin.academy.htb:PORT/admin/admin.php?token=FUZZ
        
        ```
        
    - Manually test identified parameters for vulnerabilities (e.g., injecting payloads like `<script>alert(1)</script>` for XSS).
- **Tips**:
    - Use `v` to see full URLs and responses for clarity.
    - Test both GET and POST parameters if the page supports forms (POST fuzzing requires `d` for data).
    - Look for unusual responses (e.g., 500 errors, different sizes) that might indicate a misconfiguration.

## 11. POST Parameter Fuzzing

- **Objective**: Identify valid POST parameters for admin.php, as GET parameters may not suffice.
- **GET vs. POST**:
    - GET: Parameters in URL (e.g., ?param=value).
    - POST: Parameters in the HTTP request body, not visible in the URL.
- **Context**: GET fuzzing may have identified some parameters, but POST parameters are common for sensitive actions (e.g., form submissions).
- **Method**:
    - Use -X POST to send POST requests.
    - Use -d to specify data with FUZZ in the parameter name.
    - Set Content-Type for PHP compatibility: application/x-www-form-urlencoded.
    - Wordlist: /opt/useful/seclists/Discovery/Web-Content/burp-parameter-names.txt.
- **Command**:
    
    ```bash
    ffuf -w /opt/useful/seclists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u http://admin.academy.htb:PORT/admin/admin.php -X POST -H "Content-Type: application/x-www-form-urlencoded" -d "FUZZ=key"
    
    ```
    
- **Output**:
    - Found parameters, including id (and possibly others from GET fuzzing).
- **Verification**:
    - Test with curl:
        
        ```bash
        curl -X POST -d "id=key" -H "Content-Type: application/x-www-form-urlencoded" http://admin.academy.htb:PORT/admin/admin.php
        
        ```
        
    - Response: "Invalid id!", indicating id is a valid parameter expecting a specific value.
- **Importance**:
    - POST parameters are often used for critical actions (e.g., authentication, data submission).
    - Unsecured POST parameters may allow bypassing restrictions or injecting malicious payloads.
- **Next Steps**: Fuzz the id parameter’s value to find the correct input (see Value Fuzzing).
- **Tips**:
    - Use -v to inspect full requests/responses.
    - Test multiple parameters in a single request (e.g., -d "param1=value1&FUZZ=key") if the page accepts multiple inputs.
    - Ensure the correct Content-Type header to avoid server rejection.

## 12. Value Fuzzing

- **Objective**: Fuzz the value of the id parameter (identified via POST fuzzing) to find the correct input that grants access to the flag.
- **Context**: Sending id=key via POST returned "Invalid id!", suggesting id expects a specific value (e.g., a number, token, or username).
- **Custom Wordlist**:
    - Pre-made wordlists (e.g., /opt/useful/seclists/Usernames/) work for common parameters like usernames, but custom parameters like id may require tailored lists.
    - Hypothesis: id may accept a numeric value, possibly sequential (e.g., 1–1000).
    - Create a wordlist of numbers 1–1000 using Bash:
        
        bash
        
        ```bash
        for i in $(seq 1 1000); do echo $i >> ids.txt; done
        
        ```
        
    - Verify:
        
        bash
        
        ```bash
        cat ids.txt
        
        ```
        
        Output:
        
        plain
        
        ```
        1
        2
        3
        4
        ...
        
        ```
        
- **Method**:
    - Fuzz the id parameter’s value using the ids.txt wordlist.
    - Use POST request, as id was identified via POST fuzzing.
- **Command**:
    
    bash
    
    ```bash
    ffuf -w ids.txt:FUZZ -u http://admin.academy.htb:PORT/admin/admin.php -X POST -H "Content-Type: application/x-www-form-urlencoded" -d "id=FUZZ"
    
    ```
    
- **Output**:
    - A hit is found (e.g., id=<value>, with a unique HTTP status, size, or content), indicating the correct value.
- **Verification**:
    - Use curl to send the identified value:
        
        bash
        
        ```bash
        curl -X POST -d "id=<found_value>" -H "Content-Type: application/x-www-form-urlencoded" http://admin.academy.htb:PORT/admin/admin.php
        
        ```
        
    - Expected result: The flag or protected content is returned.
- **Importance**:
    - Value fuzzing is critical for bypassing access controls when a parameter is known but its valid value is not.
    - Incorrect or untested values may reveal vulnerabilities (e.g., enumeration, injection).
- **Tips**:
    - If numeric values fail, try other formats (e.g., UUIDs, hashes, or keywords like admin, true).
    - Use larger ranges (e.g., 1–10000) or different wordlists if initial scans yield no results.
    - Filter responses (e.g., -fs <error_size>) to isolate the correct value’s response.
    - Save results with -o <file> to review hits.

## Additional Tips

- **Wordlist Selection**:
    - Use small wordlists for quick scans, larger ones for thorough testing.
    - Customize wordlists for specific parameters (e.g., numeric IDs, usernames, tokens).
    - Combine SecLists wordlists with custom lists for targeted fuzzing.
- **Filtering**:
    - Use -fs, -fc, or -fw to reduce noise.
    - Test filter values with a small scan to identify default responses (e.g., error pages).
- **Output Management**:
    - Save results with -o <file> (e.g., -o results.json -of json).
    - Use -v for verbose output to understand response patterns.
- **Ethical Considerations**:
    - Obtain permission for production servers.
    - Limit threads (e.g., -t 40) and avoid unlimited recursion.
    - Monitor server responses for overload signs.
- **Environment Notes**:
    - Update /etc/hosts for new vhosts (e.g., admin.academy.htb).
    - Verify ports if HTB exercises restart.
    - Recursive scans on vhosts can reveal new resources.
- **Troubleshooting**:
    - Check wordlist paths, URL syntax, and connectivity if scans fail.
    - Test both HTTP/HTTPS for vhost/parameter fuzzing.
    - Adjust filters if valid results are excluded.
- **Next Steps**:
    - Manually inspect discovered resources for vulnerabilities (e.g., injection, XSS).
    - Use tools like Burp Suite for dynamic page analysis.
    - Combine fuzzing with brute-forcing or spidering for comprehensive testing.