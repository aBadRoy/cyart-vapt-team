# Week 2: VAPT Training - Complete Penetration Testing Cycle


**Submission Date:** January 2, 2026  
**Target:** Metasploitable2 (192.168.111.129)  
**Attacker Machine:** Kali Linux (192.168.111.128)

---

## 📋 Executive Summary

This repository contains comprehensive documentation for Week 2 VAPT (Vulnerability Assessment and Penetration Testing) training. All activities followed the PTES (Penetration Testing Execution Standard) methodology and industry best practices.

**Key Achievements:**
- ✅ Identified 76 vulnerabilities (10 Critical, 8 High, 58 Medium)
- ✅ Successfully exploited 4 critical vulnerabilities with proof-of-concept
- ✅ Conducted OSINT reconnaissance on testphp.vulnweb.com
- ✅ Performed post-exploitation activities including privilege escalation
- ✅ Completed full VAPT cycle on DVWA application
- ✅ Generated professional security reports for management

---

## 📁 Repository Structure

```
cyart-vapt-team/
└── Week 2/
    ├── README.md                          # This file
    ├── Documentation/
    │   ├── 01_Vulnerability_Scanning_Report.pdf
    │   ├── 02_Reconnaissance_Report.pdf
    │   ├── 03_Exploitation_Report.pdf
    │   ├── 04_Post_Exploitation_Report.pdf
    │   ├── 05_Capstone_VAPT_Report.pdf
    │   └── 06_Executive_Summary.pdf
    ├── Screenshots/
    │   ├── 01_nmap_scan.png
    │   ├── 02_openvas_results.png
    │   ├── 03_nikto_scan.png
    │   ├── 04_shodan_recon.png
    │   ├── 05_wappalyzer_tech.png
    │   ├── 06_metasploit_exploit.png
    │   ├── 07_sqlmap_injection.png
    │   ├── 08_privilege_escalation.png
    │   └── 09_evidence_collection.png
    ├── Scan_Results/
    │   ├── nmap_comprehensive_scan.xml
    │   ├── openvas_report.pdf
    │   ├── nikto_results.html
    │   ├── sqlmap_output.txt
    │   └── burpsuite_findings.xml
    └── Scripts/
        ├── exploitation_commands.txt
        ├── post_exploitation_steps.txt
        └── remediation_code_samples.txt
```

---

## 🎯 Completed Activities

### 1. Vulnerability Scanning Lab ✅
**Tools Used:** Nmap, OpenVAS, Nikto

**Objective:** Identify and prioritize vulnerabilities on Metasploitable2

**Key Results:**
- **Total Vulnerabilities:** 76
- **Critical (CVSS 9.0+):** 10
- **High (CVSS 7.0-8.9):** 8
- **Medium (CVSS 4.0-6.9):** 58

**Top Critical Findings:**
1. UnrealIRCd Backdoor (CVE-2010-2075) - CVSS 10.0
2. vsftpd Backdoor (CVE-2011-2523) - CVSS 10.0
3. Tomcat Manager Default Credentials - CVSS 9.1
4. MySQL Root No Password - CVSS 9.8
5. PHP CGI Argument Injection - CVSS 9.8

**Documentation:** `Documentation/01_Vulnerability_Scanning_Report.pdf`

---

### 2. Reconnaissance Practice ✅
**Tools Used:** Shodan, Wappalyzer, Sublist3r, Google Dorking, Maltego

**Target:** testphp.vulnweb.com (Legal testing platform)

**Key Findings:**
- **IP Address:** 176.120.75.145
- **Hosting:** WEISS HOSTING GROUP S.R.L.
- **Technology Stack:** 
  - Web Server: Nginx 1.19.0, Apache 2.4.52
  - Programming: PHP 5.6.40 (EOL - Critical Risk)
  - OS: Ubuntu Linux
- **Subdomains Discovered:** 4 active test applications
- **Exposed Services:** HTTP (80), HTTPS (443)

**Risk Assessment:**
- PHP 5.6.40 is End-of-Life since 2019 (High Risk)
- Server version information disclosed (Medium Risk)
- Adobe Flash detected (deprecated, High Risk)

**Documentation:** `Documentation/02_Reconnaissance_Report.pdf`

---

### 3. Exploitation Lab ✅
**Tools Used:** Metasploit Framework, Burp Suite, sqlmap

**Successful Exploits:**

| Exploit ID | Vulnerability | Target Port | Status | Access Level | CVSS |
|------------|---------------|-------------|--------|--------------|------|
| EXP-001 | Tomcat Manager RCE | 8180 | ✅ Success | tomcat55 | 9.1 |
| EXP-002 | vsftpd Backdoor | 21 | ✅ Success | root | 10.0 |
| EXP-003 | SQL Injection (DVWA) | 80 | ✅ Success | database | 9.8 |
| EXP-004 | UnrealIRCd Backdoor | 6667 | ✅ Success | root | 10.0 |

**Proof of Concept:**
- All exploits validated against Exploit-DB entries
- Metasploit sessions established with remote code execution
- Database completely dumped via SQL injection
- Root-level access achieved through multiple vectors

**Documentation:** `Documentation/03_Exploitation_Report.pdf`

---

### 4. Post-Exploitation Practice ✅
**Tools Used:** Meterpreter, sha256sum, MySQL client

**Activities Completed:**

**Privilege Escalation:**
- Initial access: tomcat55 (unprivileged user)
- Escalation method: Kernel exploit (udev_netlink)
- Final access: root (complete system control)

**Evidence Collection:**
- 8 critical files collected and hashed
- Chain of custody maintained with SHA256 checksums
- Database dump: 2.4 MB (1,200+ user records)
- Log files: Auth logs, Apache access logs, MySQL logs

**Persistence Mechanisms Established:**
1. Backdoor user account with sudo privileges
2. SSH authorized_keys modification
3. Cron job for periodic callback
4. PHP web shell in hidden location

**Lateral Movement Assessment:**
- 6 hosts discovered on local network
- 2 additional systems vulnerable to credential reuse
- Complete network diagram created

**Documentation:** `Documentation/04_Post_Exploitation_Report.pdf`

---

### 5. Capstone Project: Full VAPT Cycle ✅
**Target:** DVWA (Damn Vulnerable Web Application)  
**Methodology:** Complete PTES 7-Phase Process

**PTES Phases Completed:**

1. **Pre-Engagement** - Scope definition, rules of engagement
2. **Intelligence Gathering** - Reconnaissance and information gathering
3. **Threat Modeling** - Attack vector identification
4. **Vulnerability Analysis** - Comprehensive scanning with OpenVAS, Nmap, Nikto
5. **Exploitation** - SQL Injection, XSS, Command Injection, File Upload
6. **Post-Exploitation** - Privilege escalation, data exfiltration, persistence
7. **Reporting** - Technical and executive reports generated

**Critical Findings (DVWA):**
1. SQL Injection - Database access (CVSS 9.8)
2. Stored XSS - Session hijacking (CVSS 9.0)
3. Command Injection - RCE (CVSS 9.8)
4. Unrestricted File Upload - Web shell (CVSS 9.1)

**Impact:**
- Complete application compromise
- All user credentials extracted
- Remote code execution achieved
- Administrative access obtained

**Documentation:** `Documentation/05_Capstone_VAPT_Report.pdf`

---

## 🔧 Tools & Technologies

### Scanning Tools
- **Nmap 7.94** - Network and port scanning
- **OpenVAS 22.4** - Comprehensive vulnerability assessment
- **Nikto 2.5.0** - Web server vulnerability scanner

### Exploitation Tools
- **Metasploit Framework** - Exploitation and post-exploitation
- **Burp Suite** - Web application security testing
- **sqlmap** - Automated SQL injection exploitation

### Reconnaissance Tools
- **Shodan** - Internet-wide device search
- **Wappalyzer** - Technology stack identification
- **Sublist3r** - Subdomain enumeration
- **Maltego** - OSINT and relationship mapping

### Post-Exploitation Tools
- **Meterpreter** - Advanced payload and session management
- **sha256sum** - File integrity verification
- **John the Ripper** - Password cracking

---

## 📊 Key Statistics

| Metric | Count |
|--------|-------|
| Total Vulnerabilities Found | 76 |
| Critical Severity | 10 |
| High Severity | 8 |
| Medium Severity | 58 |
| Successful Exploits | 4 |
| Root Access Achieved | Yes |
| Evidence Files Collected | 8 |
| Database Records Extracted | 1,200+ |
| Testing Duration | 24 hours |
| Reports Generated | 6 |

---

## 🎓 Learning Outcomes

### Technical Skills Developed
1. ✅ Vulnerability assessment using industry-standard tools
2. ✅ OSINT and passive reconnaissance techniques
3. ✅ Exploitation of critical web application vulnerabilities
4. ✅ Privilege escalation techniques (Linux kernel exploits)
5. ✅ Post-exploitation and evidence handling procedures
6. ✅ Professional security report writing

### Methodologies Mastered
- **PTES** (Penetration Testing Execution Standard)
- **OWASP Testing Guide** (Web application security)
- **CVSS v3.1** (Vulnerability severity scoring)
- **Chain of Custody** (Evidence handling)

### Compliance & Frameworks
- OWASP Top 10 vulnerabilities
- NIST SP 800-115 (Technical Guide to Information Security Testing)
- PCI-DSS penetration testing requirements

---

## 🔐 Security & Ethics

**Important Notes:**
- All testing was conducted on authorized lab environments
- Metasploitable2 is intentionally vulnerable for training purposes
- DVWA is a legal testing platform
- testphp.vulnweb.com explicitly allows security testing
- No production systems were targeted
- All findings documented for educational purposes only

**Ethical Guidelines Followed:**
- ✅ Written authorization obtained
- ✅ Defined scope adhered to strictly
- ✅ Testing conducted in isolated lab network
- ✅ All changes documented and reverted
- ✅ Confidentiality maintained

---

## 📝 Report Highlights

### For Management (Executive Summary)
A comprehensive security assessment identified critical vulnerabilities enabling complete system compromise. Ten critical-severity issues require immediate remediation within 24-48 hours. The assessment demonstrates significant risk of data breach, unauthorized access, and potential regulatory non-compliance. Estimated remediation cost: $5,000-$15,000. Full details in `Documentation/06_Executive_Summary.pdf`.

### For Technical Teams
Detailed technical reports provide step-by-step exploitation procedures, proof-of-concept code, remediation guidance, and validation steps. Each vulnerability includes CVSS scores, impact analysis, and prioritized remediation timelines. Complete scan outputs and evidence files available in `Scan_Results/` directory.

---

## 🚀 Remediation Priorities

### P0 - Critical (0-24 hours)
1. Disable vsftpd and UnrealIRCd services immediately
2. Change all default credentials (Tomcat, MySQL, PostgreSQL)
3. Set strong passwords on database root accounts
4. Disable anonymous FTP access

### P1 - High (24-48 hours)
1. Update all services to latest versions
2. Implement SSL/TLS with strong cipher suites
3. Configure server header obfuscation
4. Enable fail2ban for brute force protection

### P2 - Medium (1-2 weeks)
1. Add security headers (X-Frame-Options, CSP, HSTS)
2. Disable directory listing
3. Remove phpinfo() and test files
4. Implement Web Application Firewall (WAF)

---

## 🏆 Certification & Validation

All findings have been:
- ✅ Validated with proof-of-concept exploits
- ✅ Cross-referenced with CVE databases
- ✅ Scored using CVSS v3.1 methodology
- ✅ Documented with forensic evidence and hashes
- ✅ Reviewed for accuracy and completeness

**Quality Assurance:**
- Screenshots captured for all critical findings
- Command outputs preserved in text format
- Evidence files cryptographically hashed (SHA256)
- Reports peer-reviewed for technical accuracy

---

## 📚 References

- PTES Technical Guidelines: http://www.pentest-standard.org/
- OWASP Testing Guide: https://owasp.org/www-project-web-security-testing-guide/
- NIST SP 800-115: https://csrc.nist.gov/publications/detail/sp/800-115/final
- CVE Database: https://cve.mitre.org/
- Exploit-DB: https://www.exploit-db.com/

---

## ⚖️ Legal Disclaimer

This penetration testing report and all associated materials are provided for educational and authorized security testing purposes only. All testing was conducted on:
- Intentionally vulnerable lab systems (Metasploitable2, DVWA)
- Authorized testing platforms (testphp.vulnweb.com)
- Isolated network environment with no production impact

Unauthorized access to computer systems is illegal. The techniques described should only be used with explicit written permission from system owners.
