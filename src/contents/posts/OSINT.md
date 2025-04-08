---
title: OSINT
published: 2025-03-20
description: Passive Attack
category: Assignment
draft: false
---

# Assignment 2

# Final OSINT Report

## Executive Summary

A detailed study of domain [dhi.bt](http://dhi.bt/) belongs to Druk Holding and Investments (DHI) which serves as the commercial division of the Royal Government of Bhutan. DHI started its operation in 2007 through a Royal Charter to function as the governing body responsible for managing public investments for Bhutan's citizen benefit. The research uses open-source intelligence techniques to collect data which presents an extensive organizational profile.

## Domain Information

- **Domain Name**: dhi.bt
- **TLD**: .bt (Bhutan's country code TLD)
- **Registration Status**: Active
- **Website Type**: Government-owned investment company website

## Organization Profile

- **Organization Name**: Druk Holding and Investments (DHI)
- **Establishment**: 2007, by Royal Charter
- **Industry**: State investment company (Bhutan's sovereign wealth fund)
- **Location**: Thimphu, Bhutan
- **Ownership**: 100% owned by the Ministry of Finance, Royal Government of Bhutan
- **Function**: DHI is Bhutan's largest and only government-owned holding company that manages state-owned enterprises and investments

## Organizational Vision and Mission

- **Vision**: "To be the leading wealth management and creation organization that helps transform Bhutan into a globally competitive economy guided by the principles of GNH"
- **Mission**: "Safeguard and enhance national wealth for all generations of Bhutanese through prudent investments."
- **Core Values**: Integrity, Honesty, Excellence, Prudence, Teamwork, Responsibility

## Investment Portfolio

- **Total Portfolio Companies**: 20 companies across multiple sectors
- **Ownership Structure**:
    - 11 fully owned companies (DHI-Owned Companies)
    - 3 controlled companies (DHI-Controlled Companies - 51% and above)yes yesyeyenchd bvhu iindc
    - 6 linked companies (DHI-Linked Companies - below 51%)
- **Industry Sectors**: Manufacturing, Energy, Natural Resources, Financial, Communication, Aviation, Trading, and Real Estate

![Screenshot From 2025-03-17 10-53-31.png](/public/images/Assignment%202%201c7d813d6e4280b78449ff449943e949/Screenshot_From_2025-03-17_10-53-31.png)

## Website Analysis

- **Primary Purpose**: Official portal for DHI information, projects, and services
- **Content Focus**: Investment information, corporate governance, portfolio companies
- **Key Sections**: About, Portfolio Companies, Board & Management, News & Media
- **Documentation**: Contains multiple annual reports and corporate documents in PDF format

## Technical Information

- **Hosting Information**: Hosted in Bhutan
- **CMS Platform**: Likely custom or standard CMS
- **Security Features**: Basic HTTPS implementation
- **Mobile Responsiveness**: Website appears to be responsive for mobile devices

## Digital Footprint

- **Social Media Presence**: Limited presence on platforms like LinkedIn
- **Related Domains**: May be connected to other Bhutanese government domains (.gov.bt)
- **External Links**: Connected to various Bhutanese government and company websites

## Information Collection Methodology

The following OSINT techniques were used to gather information:

- **WHOIS Lookup and Domain Analysis**
    - Domain registration information
    
    ![Screenshot From 2025-03-16 13-34-44.png](/public/images/Assignment%202%201c7d813d6e4280b78449ff449943e949/Screenshot_From_2025-03-16_13-34-44.png)
    
    The website was hosted in this IP: 54.179.217.168
    
    ![Screenshot From 2025-03-16 13-42-56.png](/public/images/Assignment%202%201c7d813d6e4280b78449ff449943e949/Screenshot_From_2025-03-16_13-42-56.png)
    
    ![Screenshot From 2025-03-16 13-43-17.png](/public/images/Assignment%202%201c7d813d6e4280b78449ff449943e949/Screenshot_From_2025-03-16_13-43-17.png)
    
    ![Screenshot From 2025-03-16 13-43-37.png](/public/images/Assignment%202%201c7d813d6e4280b78449ff449943e949/Screenshot_From_2025-03-16_13-43-37.png)
    
    - DNS records analysis

![image.png](/public/images/Assignment%202%201c7d813d6e4280b78449ff449943e949/image.png)

- **Website Content Analysis**

-Using the dnsdumper.

![Screenshot From 2025-03-16 14-00-46.png](/public/images/Assignment%202%201c7d813d6e4280b78449ff449943e949/Screenshot_From_2025-03-16_14-00-46.png)

-An interactive world map presents Singapore while showing its national flag.

-The website utilizes Amazon AWS facilities based in Singapore as confirmed by this information.

-Multiple DNS A records contain the identical IP value which is 54.179.217.168.

-The open services display an nginx web server currently operates from the system.

-The responses from HTTP and HTTPS protocols produce "301 Moved Permanently" status codes.

-This system contains three operational services according to Reverse IP lookup results.

![Screenshot From 2025-03-16 14-00-57.png](/public/images/Assignment%202%201c7d813d6e4280b78449ff449943e949/Screenshot_From_2025-03-16_14-00-57.png)

-Website domain [www.dhi.bt](http://www.dhi.bt/) connects its users to DNS as well as MX records.

-The domain points to IP address 54.179.217.168 through an A record.

-The network location of this domain is an Amazon AWS server platform based in [ec2-54-179-217-168.ap-southeast-1.compute.amazonaws.com](http://ec2-54-179-217-168.ap-southeast-1.compute.amazonaws.com/).

-The network information demonstrates that this subnet has the address range 54.179.192.0/18.

- Historical versions via Wayback Machine

These images below show data from the Internet Archive's Wayback Machine for the website [www.dhi.bt](http://www.dhi.bt/). The Wayback Machine is a digital archive that captures and stores snapshots of websites over time.

![Screenshot From 2025-03-16 14-05-57.png](/public/images/Assignment%202%201c7d813d6e4280b78449ff449943e949/Screenshot_From_2025-03-16_14-05-57.png)

It shows the Wayback Machine interface itself, with the domain [www.dhi.bt](http://www.dhi.bt/) being searched. It indicates this site has been saved 276 times between March 22, 2009, and March 6, 2025, with the most recent indexing on August 22, 2024. The pie chart shows text/html files (14,514 captures) dominate the archived content, followed by image/png (1,752) and application/pdf (1,301).

![Screenshot From 2025-03-16 14-06-20.png](/public/images/Assignment%202%201c7d813d6e4280b78449ff449943e949/Screenshot_From_2025-03-16_14-06-20.png)

It shows more detailed MIME-type statistics and a "Keys Summary" graph displaying capture activity from 2009 to 2025. There's a significant spike in activity around 2018-2021, with specific counts for 2018 showing 2,734 captures, 869 URLs, and 671 new URLs.

![Screenshot From 2025-03-16 14-06-28.png](/public/images/Assignment%202%201c7d813d6e4280b78449ff449943e949/Screenshot_From_2025-03-16_14-06-28.png)

It displays a "Top Level MIME-types Summary" graph showing the distribution of file types captured from the website. Text files are the most common (over 10,000 captures), followed by image, application, and font files. Below that is a table of the 10 most recent captures, mostly from March 6, 2025, with HTTP status codes and file sizes.

- **Subdomain Enumeration**
    - Used Sublist3r to discover 6 subdomains
    
    ![Screenshot From 2025-03-17 10-33-53.png](/public/images/Assignment%202%201c7d813d6e4280b78449ff449943e949/Screenshot_From_2025-03-17_10-33-53.png)
    
    - Identified potential functions of each subdomain
    
    -www.dhi.bt
    
    ![Screenshot From 2025-03-17 10-35-43.png](/public/images/Assignment%202%201c7d813d6e4280b78449ff449943e949/Screenshot_From_2025-03-17_10-35-43.png)
    
    -compact.dhi.bt
    
    ![Screenshot From 2025-03-17 10-36-05.png](/public/images/Assignment%202%201c7d813d6e4280b78449ff449943e949/Screenshot_From_2025-03-17_10-36-05.png)
    
    -dashboard.dhi.bt
    
    ![Screenshot From 2025-03-17 10-36-19.png](/public/images/Assignment%202%201c7d813d6e4280b78449ff449943e949/Screenshot_From_2025-03-17_10-36-19.png)
    
    -innotech.dhi.bt
    
    ![Screenshot From 2025-03-17 10-36-33.png](/public/images/Assignment%202%201c7d813d6e4280b78449ff449943e949/Screenshot_From_2025-03-17_10-36-33.png)
    
    -www.innotech.dhi.bt
    
    ![Screenshot From 2025-03-17 10-36-42.png](/public/images/Assignment%202%201c7d813d6e4280b78449ff449943e949/Screenshot_From_2025-03-17_10-36-42.png)
    
    -rise.dhi.bt
    
    ![Screenshot From 2025-03-17 10-36-51.png](/public/images/Assignment%202%201c7d813d6e4280b78449ff449943e949/Screenshot_From_2025-03-17_10-36-51.png)
    
- **Google Dorking**
    - `site:dhi.bt filetype:pdf` (Found annual reports)
    
    ![Screenshot From 2025-03-16 14-09-58.png](/public/images/Assignment%202%201c7d813d6e4280b78449ff449943e949/Screenshot_From_2025-03-16_14-09-58.png)
    
    - `"Druk Holding and Investments" + "contact"`
    
    ![Screenshot From 2025-03-16 14-28-22.png](/public/images/Assignment%202%201c7d813d6e4280b78449ff449943e949/Screenshot_From_2025-03-16_14-28-22.png)
    
    ![Screenshot From 2025-03-17 21-18-45.png](/public/images/Assignment%202%201c7d813d6e4280b78449ff449943e949/Screenshot_From_2025-03-17_21-18-45.png)
    
    -This appeared to be part of a job description or terms of employment document for recruiting a CEO for this Bhutanese natural resources company.
    
    ![Screenshot From 2025-03-17 21-19-37.png](/public/images/Assignment%202%201c7d813d6e4280b78449ff449943e949/Screenshot_From_2025-03-17_21-19-37.png)
    

-This image shows instructions for using the DHI eRecruitment System in Bhutan. It appears to be part of job application instructions and also  shows their online recruitment system where candidates can apply for positions like the CEO role described in the previous document.

- **Social Media**

![Screenshot From 2025-03-16 14-29-20.png](/public/images/Assignment%202%201c7d813d6e4280b78449ff449943e949/Screenshot_From_2025-03-16_14-29-20.png)

-LinkedIn

![Screenshot From 2025-03-16 14-30-15.png](/public/images/Assignment%202%201c7d813d6e4280b78449ff449943e949/Screenshot_From_2025-03-16_14-30-15.png)

-Facebook

![image.png](/public/images/Assignment%202%201c7d813d6e4280b78449ff449943e949/image%201.png)

-Instagram

![image.png](/public/images/Assignment%202%201c7d813d6e4280b78449ff449943e949/image%202.png)

-YouTube

![image3.png](/public/images/Assignment%202%201c7d813d6e4280b78449ff449943e949/image3.png)

## Conclusion

Druk Holding and Investments (DHI) represents a significant economic entity in Bhutan, managing state investments across multiple sectors. The organization maintains a professional web presence with the domain dhi.bt, providing substantial information about its operations, values, and portfolio companies. The discovery of multiple subdomains indicates a complex digital infrastructure that warrants further investigation. The information gathered through OSINT techniques provides valuable insights into this important Bhutanese institution and its role in the country's economic development strategy.