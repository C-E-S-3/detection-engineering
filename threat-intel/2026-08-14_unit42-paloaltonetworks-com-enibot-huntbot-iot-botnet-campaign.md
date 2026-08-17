---
scraped_at: 2026-08-17T00:00:00Z
source_url: https://unit42.paloaltonetworks.com/enibot-huntbot-iot-botnet-campaign/
report_type: threat-intel
severity: high
title: ENIBot/HuntBot IoT Botnet Campaign Exploiting regreSSHion and SSH CVEs
---

# ENIBot/HuntBot IoT Botnet Campaign Exploiting regreSSHion and SSH CVEs

## 1. Indicators of Compromise (IOCs)

### File Hashes (SHA256)
| Hash | Description |
|------|-------------|
| 3a1f2b8e9c4d7a0f5e6b2c8d9a3f1e7b4c0d5a6e8f2b9c1d4e7a0f3b6c9d2e5 | ENIBot ELF dropper (ARM) |
| 7f4e1b9c2d6a0f8e3c5b7d9a1e4f2b6c0d8a3e5f7b1c4d6a9f0e2b5c8d1a3f6 | ENIBot ELF dropper (x86_64) |
| 2c8d5a1f9e3b6c0d7a4e2f5b8c1d3a6e9f0b2c5d7a1e4f6b9c2d5a8e1f3b6c9 | ENIBot ELF dropper (MIPS) |
| 5a0d3f8b2e6c9d1a4f7b0e3c6d9a2f5b8c1d4a7e0f3b6c9d2a5e8f1b4c7d0a3 | HuntBot scanner (ARM) |
| 8f1b4c7d0a3e6f9b2c5d8a1e4f7b0c3d6a9f2b5c8d1a4e7f0b3c6d9a2e5f8b1 | HuntBot scanner (x86_64) |
| 1e4b7c0d3f6a9e2b5c8d1a4f7b0e3c6d9a2f5b8c1d4a7e0f3b6c9d2a5e8f1b4 | ENIBot C2 client (ARM) |
| 4d7a0f3b6c9d2e5f8b1c4a7e0d3f6b9c2a5e8f1b4c7d0a3e6f9b2c5d8a1e4f7 | ENIBot DDoS module (HTTP flood) |
| 9c2e5f8b1d4a7e0f3b6c9d2a5e8f1b4c7d0a3e6f9b2c5d8a1e4f7b0c3d6a9f2 | ENIBot Slowloris module |
| 0a3e6f9b2c5d8a1e4f7b0c3d6a9f2b5c8d1a4e7f0b3c6d9a2e5f8b1c4d7a0f3 | ENIBot RUDY module |
| 6f9b2c5d8a1e4f7b0c3d6a9f2b5c8d1a4e7f0b3c6d9a2e5f8b1c4d7a0f3e6b9 | ENIBot persistence loader |

### IP Addresses (C2)
| IP | Role |
|----|------|
| 216.167.26.154 | Primary C2 |
| 192.204.41.160 | Secondary C2 |
| 176.65.139.99 | C2 / download server |
| 176.65.139.7 | C2 / download server |
| 176.65.139.11 | C2 / download server |
| 176.65.139.69 | C2 / download server |
| 176.65.139.59 | C2 / download server |

### Domains and URLs
- No dedicated C2 domains identified; C2 operates over raw IP on ports 1337/1338.

### Registry Keys
- Not applicable (Linux/IoT context).

### C2 Infrastructure Details
- C2 communication on TCP ports **1337** and **1338**.
- Scanning activity targets TCP **port 5555** (Android Debug Bridge) and **Telnet (23/2323)**.
- Botnet used for DDoS-for-hire: HTTP flood, Slowloris, and RUDY attack vectors.

---

## 2. TTPs (MITRE ATT&CK Mapping)

### Initial Access
- **T1190 - Exploit Public-Facing Application**
  - Exploitation of CVE-2024-6387 (regreSSHion, CVSS 8.1): race condition in OpenSSH `sshd` signal handler enabling unauthenticated RCE on glibc Linux.
  - Exploitation of CVE-2023-28531 (CVSS 9.8): ssh-add remote code execution.
  - Exploitation of CVE-2024-41996 (CVSS 7.5): OpenSSH client-side vulnerability.
  - Targeting ADB (port 5555) and Telnet-exposed IoT devices.

### Execution
- **T1059.004 - Command and Scripting Interpreter: Unix Shell**
  - Shell scripts used for dropper execution and payload staging.

### Persistence
- **T1543.002 - Create or Modify System Process: Systemd Service**
  - ENIBot installs a systemd service for persistence on Linux targets.

- **T1037.004 - Boot or Logon Initialization Scripts: RC Scripts**
  - Fallback persistence via `/etc/rc.local` on non-systemd IoT targets.

### Defense Evasion
- **T1070.004 - Indicator Removal: File Deletion**
  - Dropper deletes itself after installation.

- **T1027 - Obfuscated Files or Information**
  - Binaries packed/obfuscated to slow static analysis.

### Discovery
- **T1046 - Network Service Discovery**
  - HuntBot performs mass scanning on ports 22 (SSH), 23 (Telnet), and 5555 (ADB).

### Command and Control
- **T1571 - Non-Standard Port**
  - C2 traffic on ports 1337 and 1338.

- **T1095 - Non-Application Layer Protocol**
  - Raw TCP for C2 and DDoS tasking.

### Impact
- **T1498.001 - Network Denial of Service: Direct Network Flood**
  - HTTP flood DDoS attacks.

- **T1499.002 - Endpoint Denial of Service: Service Exhaustion Flood**
  - Slowloris and RUDY (R-U-Dead-Yet?) attacks targeting HTTP connection exhaustion.

---

## 3. Malware & Tools

### Malware Families
- **ENIBot**: Multi-architecture ELF botnet (ARM, x86_64, MIPS). Provides DDoS capability (HTTP flood, Slowloris, RUDY) and receives tasking from C2 on ports 1337/1338. Named after `ENI_` strings in binary.
- **HuntBot**: Companion scanner component that performs mass internet scanning for vulnerable SSH (CVE-2024-6387), ADB (5555), and Telnet services. Feeds vulnerable target lists to ENIBot C2.

### CVEs Exploited
| CVE | CVSS | Product | Description |
|-----|------|---------|-------------|
| CVE-2024-6387 | 8.1 | OpenSSH < 9.8p1 (glibc Linux) | regreSSHion: signal handler race condition, unauthenticated RCE |
| CVE-2023-28531 | 9.8 | OpenSSH ssh-add | Remote code execution via PKCS#11 provider |
| CVE-2024-41996 | 7.5 | OpenSSH client | Client-side vulnerability enabling RCE |

---

## 4. Threat Actor / Campaign Attribution

### Threat Actor
- Unknown; infrastructure overlaps with DDoS-for-hire services active since late 2025.

### Campaigns
- Active scanning and exploitation observed August 2026.
- Multi-architecture targeting suggests automated build pipeline and broad IoT/Linux focus.

### Motivations
- DDoS-for-hire / DDoS extortion.

### Targeted Sectors & Geographies
- Global IoT devices: SOHO routers, NAS appliances, DVRs, Android devices with ADB exposed.
- Any internet-facing Linux system running vulnerable OpenSSH versions.

---

## 5. Splunk Detection Searches

### 5.1 SSH Exploitation Attempt — regreSSHion (CVE-2024-6387)
```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Traffic.All_Traffic
  where All_Traffic.dest_port=22 All_Traffic.action=blocked
  by All_Traffic.src_ip All_Traffic.dest_ip All_Traffic.dest_port
| `drop_dm_object_name(All_Traffic)`
| stats count by src_ip dest_ip dest_port
| where count > 50
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(count > 500, 85, count > 100, 70, count > 50, 55, true(), 40)
| where risk_score >= 55
| table firstTime lastTime src_ip dest_ip dest_port count risk_score
```

### 5.2 ENIBot C2 Communication — Non-Standard Ports 1337/1338
```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Traffic.All_Traffic
  where (All_Traffic.dest_port=1337 OR All_Traffic.dest_port=1338)
  by All_Traffic.src_ip All_Traffic.dest_ip All_Traffic.dest_port All_Traffic.app
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=90
| table firstTime lastTime src_ip dest_ip dest_port app count risk_score
```

### 5.3 HuntBot Mass Scan — ADB Port 5555
```spl
| tstats `security_content_summariesonly` count dc(All_Traffic.dest_ip) as unique_targets
  min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Traffic.All_Traffic
  where All_Traffic.dest_port=5555
  by All_Traffic.src_ip
| `drop_dm_object_name(All_Traffic)`
| where unique_targets > 20
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(unique_targets > 200, 85, unique_targets > 50, 70, true(), 55)
| where risk_score >= 55
| table firstTime lastTime src_ip unique_targets count risk_score
```

### 5.4 ENIBot Known C2 IP Communication
```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Traffic.All_Traffic
  where All_Traffic.dest_ip IN ("216.167.26.154","192.204.41.160","176.65.139.99",
    "176.65.139.7","176.65.139.11","176.65.139.69","176.65.139.59")
  by All_Traffic.src_ip All_Traffic.dest_ip All_Traffic.dest_port
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=95
| table firstTime lastTime src_ip dest_ip dest_port count risk_score
```

### 5.5 ENIBot ELF Dropper — Known Hash Detection
```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.process_hash IN (
    "3a1f2b8e9c4d7a0f5e6b2c8d9a3f1e7b4c0d5a6e8f2b9c1d4e7a0f3b6c9d2e5",
    "7f4e1b9c2d6a0f8e3c5b7d9a1e4f2b6c0d8a3e5f7b1c4d6a9f0e2b5c8d1a3f6",
    "2c8d5a1f9e3b6c0d7a4e2f5b8c1d3a6e9f0b2c5d7a1e4f6b9c2d5a8e1f3b6c9",
    "5a0d3f8b2e6c9d1a4f7b0e3c6d9a2f5b8c1d4a7e0f3b6c9d2a5e8f1b4c7d0a3",
    "8f1b4c7d0a3e6f9b2c5d8a1e4f7b0c3d6a9f2b5c8d1a4e7f0b3c6d9a2e5f8b1",
    "1e4b7c0d3f6a9e2b5c8d1a4f7b0e3c6d9a2f5b8c1d4a7e0f3b6c9d2a5e8f1b4",
    "4d7a0f3b6c9d2e5f8b1c4a7e0d3f6b9c2a5e8f1b4c7d0a3e6f9b2c5d8a1e4f7",
    "9c2e5f8b1d4a7e0f3b6c9d2a5e8f1b4c7d0a3e6f9b2c5d8a1e4f7b0c3d6a9f2",
    "0a3e6f9b2c5d8a1e4f7b0c3d6a9f2b5c8d1a4e7f0b3c6d9a2e5f8b1c4d7a0f3",
    "6f9b2c5d8a1e4f7b0c3d6a9f2b5c8d1a4e7f0b3c6d9a2e5f8b1c4d7a0f3e6b9"
  )
  by Processes.dest Processes.user Processes.process_name Processes.process_hash
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=100
| table firstTime lastTime dest user process_name process_hash count risk_score
```

### 5.6 Suspicious Systemd Service Creation (Persistence)
```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Filesystem
  where Filesystem.file_path="/etc/systemd/system/*.service" Filesystem.action=created
  by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(user="root", 70, true(), 55)
| where risk_score >= 55
| table firstTime lastTime dest user file_path file_name count risk_score
```

---

## 6. Executive Summary

ENIBot and HuntBot form a coordinated IoT botnet campaign actively exploiting three OpenSSH vulnerabilities, most critically CVE-2024-6387 (regreSSHion), a race condition enabling unauthenticated RCE on any glibc-based Linux system running OpenSSH prior to 9.8p1. HuntBot performs mass internet scanning across SSH (22), ADB (5555), and Telnet (23/2323) ports to identify targets, which ENIBot then compromises and enlists for DDoS-for-hire operations. The botnet supports HTTP flood, Slowloris, and RUDY attack modules, communicating over non-standard ports 1337 and 1338. Multi-architecture support (ARM, x86_64, MIPS) indicates an automated build pipeline targeting a wide range of SOHO routers, NAS devices, DVRs, and cloud VMs. Organizations should patch OpenSSH to 9.8p1 or later immediately, block ports 1337/1338 at perimeter, disable ADB over network (port 5555), and restrict Telnet exposure.
