# CYART VAPT Team - Week 4 Capstone Project

## 📋 Project Overview

This repository contains comprehensive documentation for the **Week 4 Capstone Project** - a full-scale Vulnerability Assessment and Penetration Testing (VAPT) engagement conducted as part of the CYART VAPT internship program.

**Project Details:**
- **Project Name:** Full VAPT Engagement Simulation
- **Target Environment:** HackTheBox Lab (Lame VM) + Custom Test Infrastructure
- **Duration:** January 20, 2026 (Full Day Engagement)
- **Team:** VAPT Security Team
- **Submission Deadline:** January 20, 2026 - 5:30 PM

---

## 🎯 Engagement Objectives

The capstone project demonstrates proficiency in:

1. **Advanced Exploitation Techniques** - Multi-stage attack chains and custom exploit development
2. **API Security Testing** - OWASP API Top 10 vulnerability assessment
3. **Privilege Escalation** - Linux/Windows privilege escalation and persistence mechanisms
4. **Network Protocol Attacks** - Man-in-the-Middle, SMB relay, and protocol exploitation
5. **Mobile Application Security** - Static/dynamic analysis of Android applications
6. **Professional Reporting** - PTES-compliant documentation and stakeholder communication

---

## 🏗️ Repository Structure

```
cyart-vapt-team/
│
├── Week 4/
│   ├── README.md                          
│   ├── VAPT_Full_Report.pdf               
│   │
│   ├── 01_Reconnaissance/
│   │   ├── nmap_scan_results.txt          
│   │   ├── openvas_scan_report.xml        
│   │   └── reconnaissance_notes.md        
│   │
│   ├── 02_Exploitation/
│   │   ├── exploit_logs.md                
│   │   ├── metasploit_sessions.txt        
│   │   ├── screenshots/                   
│   │   │   ├── vsftpd_root_shell.png
│   │   │   ├── wordpress_rce.png
│   │   │   └── api_bola_exploit.png
│   │   └── custom_exploits/               
│   │       └── api_bola_test.py
│   │
│   ├── 03_Privilege_Escalation/
│   │   ├── linpeas_output.txt             
│   │   ├── privilege_escalation_notes.md  
│   │   ├── persistence_methods.md         
│   │   └── screenshots/
│   │       └── suid_exploit_root.png
│   │
│   ├── 04_API_Testing/
│   │   ├── api_test_results.md            
│   │   ├── burp_suite_logs/               
│   │   ├── postman_collection.json        
│   │   └── screenshots/
│   │       ├── bola_exploitation.png
│   │       └── graphql_injection.png
│   │
│   ├── 05_Network_Attacks/
│   │   ├── responder_logs.txt             
│   │   ├── ettercap_mitm_results.md       
│   │   ├── wireshark_captures/            
│   │   │   └── smb_ntlm_capture.pcap
│   │   └── screenshots/
│   │       └── ntlm_hash_capture.png
│   │
│   ├── 06_Mobile_Testing/
│   │   ├── mobsf_analysis_report.html     
│   │   ├── frida_scripts/                 
│   │   │   └── auth_bypass.js
│   │   ├── mobile_vulnerabilities.md      
│   │   └── screenshots/
│   │       ├── insecure_storage.png
│   │       └── frida_hook_success.png
│   │
│   ├── 07_Remediation/
│   │   ├── remediation_plan.md            
│   │   ├── openvas_rescan_results.xml     
│   │   └── compliance_checklist.md        
│   │
│   └── 08_Reporting/
│       ├── Executive_Summary.pdf          
│       ├── Technical_Report.pdf           
│       ├── Attack_Timeline.xlsx           
│       └── presentation_slides.pptx       
```

---

## 🔬 Methodology & Framework

This engagement followed the **Penetration Testing Execution Standard (PTES)** framework:

**Phase 1: Pre-Engagement (10%)**
- Scope definition and rules of engagement
- Target identification and authorization verification
- Testing environment setup

**Phase 2: Intelligence Gathering (15%)**
- Active reconnaissance (Nmap, Netdiscover)
- Service enumeration and version detection
- OSINT and information gathering

**Phase 3: Threat Modeling (10%)**
- Attack vector identification
- Vulnerability prioritization
- Attack plan development

**Phase 4: Vulnerability Analysis (20%)**
- Automated scanning (OpenVAS, Nikto)
- Manual vulnerability validation
- False positive elimination

**Phase 5: Exploitation (25%)**
- Exploit development and execution
- Multi-stage attack chaining
- Initial access and foothold establishment

**Phase 6: Post-Exploitation (15%)**
- Privilege escalation
- Persistence mechanism deployment
- Lateral movement assessment

**Phase 7: Reporting (5%)**
- Technical documentation
- Executive summary creation
- Remediation guidance

---

## 🛠️ Tools and Technologies Used

**Reconnaissance & Scanning**
- **Nmap** - Network mapping and service enumeration
- **OpenVAS** - Comprehensive vulnerability scanning
- **Netdiscover** - ARP-based network discovery
- **Nikto** - Web server vulnerability assessment

**Exploitation Frameworks**
- **Metasploit Framework** - Primary exploitation platform
- **Exploit-DB** - Public exploit repository
- **Custom Python Scripts** - Tailored exploit development

**Web & API Testing**
- **Burp Suite Professional** - Web application security testing
- **Postman** - API endpoint testing and fuzzing
- **sqlmap** - Automated SQL injection exploitation
- **OWASP ZAP** - Automated web vulnerability scanning

**Privilege Escalation**
- **LinPEAS** - Linux enumeration and privilege escalation
- **WinPEAS** - Windows privilege escalation automation
- **PowerSploit** - PowerShell exploitation framework
- **GTFOBins** - UNIX binary privilege escalation reference

**Network Attacks**
- **Responder** - LLMNR/NBT-NS/MDNS poisoner
- **Ettercap** - Network sniffer and MITM framework
- **Wireshark** - Network protocol analyzer
- **Bettercap** - Network attack and monitoring tool

**Mobile Testing**
- **MobSF** - Mobile Security Framework (static/dynamic analysis)
- **Frida** - Dynamic instrumentation toolkit
- **Drozer** - Android security assessment framework
- **APKTool** - Reverse engineering Android apps

**Reporting & Documentation**
- **Google Docs** - Collaborative report writing
- **Markdown** - Technical documentation
- **Draw.io** - Network diagrams and attack flow visualization
- **Screenshot Tools** - Evidence capture (Flameshot, Shutter)

---

## 🎯 Key Findings Summary

**Critical Vulnerabilities Identified: 3**

**1. VSFTPD 2.3.4 Backdoor RCE (CVE-2011-2523)**
- **CVSS:** 10.0 (Critical)
- **Impact:** Unauthenticated remote root access
- **Status:** Successfully exploited

**2. Broken Object Level Authorization (BOLA) - API**
- **CVSS:** 9.1 (Critical)
- **Impact:** Unauthorized access to user PII
- **Status:** Successfully exploited

**3. WordPress Plugin Remote Code Execution Chain**
- **CVSS:** 9.8 (Critical)
- **Impact:** Web server compromise via XSS → RCE
- **Status:** Successfully exploited

**High-Severity Vulnerabilities: 2**
- SUID Binary Privilege Escalation (CVSS 7.8)
- GraphQL Query Injection (CVSS 7.5)

**Medium-Severity Vulnerabilities: 1**
- SMB NTLM Hash Capture via Relay (CVSS 6.5)

**Overall Compromise Rate:** 100% (Full administrative access achieved)

---

## 📊 Exploitation Timeline

| **Timestamp** | **Target IP** | **Vulnerability** | **PTES Phase** | **Status** | **Outcome** |
|---------------|---------------|-------------------|----------------|------------|-------------|
| 2026-01-20 09:15:00 | 192.168.1.0/24 | Network Recon | Intelligence | Success | 3 hosts found |
| 2026-01-20 11:00:00 | 192.168.1.200 | SMB Relay | Exploitation | Success | NTLM Hash |
| 2026-01-20 11:30:00 | 192.168.1.100 | WordPress XSS→RCE | Exploitation | Success | Meterpreter |
| 2026-01-20 12:00:00 | 192.168.1.200 | VSFTPD RCE | Exploitation | Success | Root Shell |
| 2026-01-20 13:30:00 | 192.168.1.150 | SUID Exploit | Post-Exploit | Success | Root Shell |
| 2026-01-20 14:45:00 | API Endpoint | BOLA | Exploitation | Success | Data Access |
| 2026-01-20 15:00:00 | GraphQL API | Injection | Exploitation | Success | Schema Dump |
| 2026-01-20 16:00:00 | test.apk | Auth Bypass | Mobile Test | Success | Full Access |

---

## 🔐 Attack Chains Demonstrated

**Chain 1: Web Application to System Compromise**
```
1. XSS Injection (WordPress Comment) 
   → 2. Session Hijacking (Admin Cookie Theft)
   → 3. Plugin Upload (Malicious PHP)
   → 4. Web Shell Execution
   → 5. Reverse Shell (Meterpreter)
   → 6. Local Privilege Escalation (SUID)
   → 7. Root Access Achieved
```

**Chain 2: Network-Based Attack Path**
```
1. ARP Spoofing (Ettercap)
   → 2. MITM Position Established
   → 3. SMB Authentication Capture (Responder)
   → 4. NTLM Hash Relay
   → 5. Lateral Movement to Domain Controller
   → 6. Domain Admin Compromise
```

**Chain 3: API Exploitation Chain**
```
1. API Endpoint Enumeration
   → 2. BOLA Vulnerability Discovery
   → 3. Parameter Manipulation
   → 4. Unauthorized Data Access
   → 5. Privilege Escalation (Admin Token)
   → 6. Full Database Extraction
```

---

## 📝 Lab Activities Completed

**✅ Lab 1: Advanced Exploitation**
- [x] Metasploit exploit chaining on VulnHub VM
- [x] Custom Python PoC modification (buffer overflow)
- [x] ROP-based ASLR bypass demonstration
- [x] Multi-stage payload deployment

**✅ Lab 2: API Security Testing**
- [x] OWASP API Top 10 vulnerability testing
- [x] Burp Suite manual API manipulation
- [x] GraphQL introspection and injection
- [x] Rate limiting bypass techniques

**✅ Lab 3: Privilege Escalation & Persistence**
- [x] LinPEAS enumeration and SUID exploitation
- [x] Cron job persistence mechanism
- [x] SSH key installation for backdoor access
- [x] Living-off-the-Land techniques (PowerShell)

**✅ Lab 4: Network Protocol Attacks**
- [x] SMB relay attack execution (Responder)
- [x] ARP spoofing and MITM (Ettercap)
- [x] DNS poisoning demonstration
- [x] Network traffic analysis (Wireshark)

**✅ Lab 5: Mobile Application Testing**
- [x] MobSF static analysis (insecure storage)
- [x] Frida runtime hooking (authentication bypass)
- [x] Drozer IPC testing
- [x] APK decompilation and code review

**✅ Lab 6: Capstone Full Engagement**
- [x] Complete PTES methodology execution
- [x] Multi-vector attack simulation
- [x] Comprehensive VAPT report generation
- [x] Remediation validation (OpenVAS rescan)

---

## 📈 Skills Demonstrated

**Technical Competencies**
- ✅ Advanced Linux/Windows exploitation
- ✅ Multi-stage attack chain development
- ✅ API security assessment (REST/GraphQL)
- ✅ Mobile application penetration testing
- ✅ Network protocol manipulation
- ✅ Custom exploit script development (Python)
- ✅ Defense evasion techniques (ASLR, DEP, WAF bypass)

**Professional Competencies**
- ✅ PTES framework adherence
- ✅ Technical report writing
- ✅ Executive communication (non-technical summaries)
- ✅ Remediation planning and validation
- ✅ CVSS/DREAD risk scoring
- ✅ Compliance awareness (GDPR, PCI DSS)

---

## 🚀 Remediation Highlights

**Immediate Actions Taken (24 Hours)**
1. ✅ VSFTPD service disabled on 192.168.1.200
2. ✅ Emergency API authorization hotfix deployed
3. ✅ All compromised systems isolated and credential rotation initiated
4. ✅ WordPress core and plugins updated to latest versions

**Short-Term Fixes (1-7 Days)**
1. ✅ SUID permissions removed from unnecessary binaries
2. ✅ GraphQL query complexity limits implemented
3. ✅ Mobile app updated with encrypted storage (v2.0)
4. ✅ WAF deployed with OWASP Core Rule Set

**Long-Term Improvements (1-3 Months)**
1. 🔄 Zero Trust architecture implementation (In Progress)
2. 🔄 SIEM deployment for continuous monitoring (Planned)
3. 🔄 Quarterly penetration testing program establishment (Planned)
4. 🔄 Security awareness training rollout (Scheduled)

**Validation Results**
- **Post-Remediation OpenVAS Scan:** 0 Critical, 0 High vulnerabilities
- **Manual Retest:** All previous exploits successfully mitigated
- **Compliance Status:** OWASP ASVS Level 2 achieved

---

## 📚 Documentation Included

**Main Deliverables**
1. **Complete VAPT Report (300+ pages)** - Full technical documentation following PTES standard
2. **Executive Summary (5 pages)** - Non-technical brief for C-level stakeholders
3. **Attack Timeline Spreadsheet** - Detailed chronological exploitation log
4. **Remediation Plan** - Prioritized fix recommendations with timelines
5. **Evidence Package** - Screenshots, logs, and proof-of-concept code

**Supporting Materials**
- Network diagrams and attack flow visualizations
- Tool configuration files and custom scripts
- Checklist templates for each testing phase
- CVSS scoring methodology and risk matrix
- Compliance mapping (OWASP, NIST, PCI DSS)

---

## 🎓 Learning Outcomes

This capstone project enhanced proficiency in:

**1. Offensive Security Techniques**
- Mastered multi-stage exploitation and attack chaining
- Developed custom exploits for specific environments
- Learned advanced evasion techniques for modern defenses

**2. Security Assessment Methodologies**
- Applied PTES framework in real-world simulation
- Integrated multiple testing disciplines (network, web, API, mobile)
- Understood holistic security posture evaluation

**3. Professional Communication**
- Translated technical findings for diverse audiences
- Created actionable remediation roadmaps
- Balanced security rigor with business practicality

**4. Defensive Perspectives**
- Understood attacker mindset and common pitfalls
- Learned secure architecture design principles
- Recognized importance of defense-in-depth strategies

---

**Last Updated:** January 20, 2026  
**Version:** 1.0  
**Report Reference:** VAPT-2026-W4-CAPSTONE
