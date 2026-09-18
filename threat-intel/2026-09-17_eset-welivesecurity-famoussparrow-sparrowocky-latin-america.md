---
scraped_at: "2026-09-18T00:00:00Z"
source_url: "https://www.welivesecurity.com/en/eset-research/beware-sparrowock-backdoor-bites-commands-catch/"
report_type: threat-intel
severity: high
title: "FamousSparrow SparroWocky — China-Aligned APT Deploys New Modular C++ Backdoor Against Latin American Governments; ESET September 17, 2026"
---

# FamousSparrow / SparroWocky — New Modular C++ Backdoor Targeting Latin American Governments

**Published:** September 17, 2026
**Authors:** ESET Research
**Campaign Reference:** FamousSparrow / SparroWocky

---

## 1. IOCs

### File Hashes (SHA256)

| Hash | Malware Family | Notes |
|------|---------------|-------|
| e0ff727c5feb3352f0bb6df91bcf2b3100203e5777c8b49b3913fcec0dbbd260 | SparroWocky | Backdoor or loader sample |
| 8dfaa1f579de14bca8bb27c54a57dd87646a835969766ca9ddb81ecd9329f4e4 | SparroWocky | Backdoor or loader sample |
| bc2b8196d8c966e84c255d0d1c7908541104446e3fc51f52318aac4239bbb4c4 | SparroWocky | Backdoor or loader sample |
| 03241adc63e5a204dcec26915f4df076a8121fa7827edfdc36b75e4803c2f019 | SparroWocky | Backdoor or loader sample |
| 1215584b4fa69130799f6cf5efe467f380dc68b14ed2c76f63ca6b461ad57246 | SparroWocky | Backdoor or loader sample |
| 222d68c03d96d230bc3829e86be8821f32960375b70388028a705a4986b8d9c6 | SparroWocky | Backdoor or loader sample |
| 773635768e738bec776dfd7504164b3596e5eee344757dd1ac9a1ad19b452c86 | SparroWocky | Backdoor or loader sample |
| 67d7962eaec2c785d7a6db8502c74e6ccd95445d366e370fa9fe6743d68cb42c | SparroWocky | Backdoor or loader sample |
| 90af57e976aea91030579b9761e5265251986b707550ca1b793191e2818bad92 | SparroWocky | Backdoor or loader sample |
| f61a113f6de19f2c821b89d934268621cf2410278155f173c8682e524b450f21 | SparroWocky | Backdoor or loader sample |
| f2434d7f2427ee2f3a1be4ab0922fb73ac2ceaa494c73790af71024453ce0c9c | SparroWocky | Backdoor or loader sample |
| c57fd715bcb6d5ece60745d036496ac37e0c13f14098776c9168c0381a01409f | SparroWocky | Backdoor or loader sample |
| dd5a6c162eff8103f6e06149faf1287feeb6dbbbb9bbca031145767fd69ce500 | SparroWocky | Backdoor or loader sample |
| 24dc94e01592a29c90fd875dcdfa095ed6e1dff6db4e517b48a2f89db467aa28 | SparroWocky | Backdoor or loader sample |
| edc3ab9bc87402a5e7de43b7b2e247fdd4e134b9220d91f84934362cce34b827 | SparroWocky | Backdoor or loader sample |
| dd3dffb09fd1df4ea2ae38023e5c256855dfc9bcf9913d775f65365e2acae166 | SparroWocky | Backdoor or loader sample |
| b68c8dff2ca0944c7e6c94d184d8219c08c020eb349ff9e0a7f49bc6a6effdaf | SparroWocky | Backdoor or loader sample |
| 973a692e6240bf4ce3c14e6ca13755c7e473c7722513d7a6e811a08cf2ae0e10 | SparroWocky | Backdoor or loader sample |
| 1cca1555b3ce3dbe37e17f32c91441886fb113a3d5e8da1c4ec5e523f8719fa5 | SparroWocky | Backdoor or loader sample |
| 63cf1e1e7ea20a69f8a6b9d16468673b92cfe2560ad1012422ec3001a7e837cf | SparroWocky | Backdoor or loader sample |
| 80a7ff01de553cb099452cb9fac5762caf96c0c3cd9c5ad229739da7f2a2ca72 | SparroWocky | Backdoor or loader sample |
| 41128b82fa12379034b3c42bdecf8e3b435089f19a5d57726a2a784c25e9d91f | SparroWocky | Backdoor or loader sample |
| 1ce7895cee6dfbc182486f7c2dff87281ba0b57a85febeb1a0196d480d032936 | SparroWocky | Backdoor or loader sample |
| abbf9c57ad3068c8aafaf443297e9448e8657b6ac16e1a8bdde5ba87254708e1 | SparroWocky | Backdoor or loader sample |
| d53346b5c8c6c76e7bc0407410a58328a1e214a4d359e558380963d29a35f71b | SparroWocky | Backdoor or loader sample |
| 5ad73e8bd5bde7808cfa39d3ada411a2e5a51278dcc7b543f2f5b5abb0c4ea27 | SparroWocky | Backdoor or loader sample |
| 0e74d57f572e384ad179ad8aa094cbdc92a6abbcc77eeb658fc05743ffd94e68 | SparroWocky | Backdoor or loader sample |
| d057034675befc1b4c2ae4132c4d169201c9abfbae79181185d45ca6721e43cc | SparroWocky | Backdoor or loader sample |
| 95dff799b2fffe128fb5e8f3bae0a0ec5bc5b181567165ac50860beac9230fcf | SparroWocky | Backdoor or loader sample |
| b87247a9ab8994e18486970c8c393593143b8775d75305b8b244c58a1294790c | SparroWocky | Backdoor or loader sample |
| e0b6f8535e19f0a4938e3317de0c4493ecea17aa906fd0454805ba2086cbf3a8 | SparroWocky | Backdoor or loader sample |
| 72677119b8bf3e2d23f22150c7b364fea9248819c36e97db015414586285591d | SparroWocky | Backdoor or loader sample |
| 3c771cf5f74a62a0c0d825f99dbe322ec261b4cc988006ada3a4b829b09ba43e | SparroWocky | Backdoor or loader sample |

*Source: ESET malware-ioc GitHub repository — github.com/eset/malware-ioc/blob/master/famoussparrow/samples.sha256*

### C2 IP Addresses

| IP | Port(s) | Notes |
|----|---------|-------|
| 38.54.57[.]17 | 443, 8080 | SparroWocky C2 server |
| 38.60.197[.]55 | 443, 8080 | SparroWocky C2 server |
| 38.60.209[.]106 | 443, 8080 | SparroWocky C2 server |
| 38.60.224[.]51 | 443, 8080 | SparroWocky C2 server |
| 38.60.224[.]235 | 443, 8080 | SparroWocky C2 server |
| 38.60.241[.]65 | 443, 8080 | SparroWocky C2 server |
| 38.60.241[.]127 | 443, 8080 | SparroWocky C2 server |
| 38.60.241[.]193 | 443, 8080 | SparroWocky C2 server |
| 77.111.101[.]40 | 443, 8080 | SparroWocky C2 server |
| 91.148.134[.]115 | 443, 8080 | SparroWocky C2 server |
| 130.94.101[.]82 | 443, 8080 | SparroWocky C2 server |
| 140.99.164[.]199 | 443, 8080 | SparroWocky C2 server |
| 149.104.87[.]228 | 443, 8080 | SparroWocky C2 server |
| 149.104.90[.]203 | 443, 8080 | SparroWocky C2 server |
| 216.238.92[.]2 | 443, 8080 | SparroWocky C2 server |
| 216.238.105[.]53 | 443, 8080 | SparroWocky C2 server |
| 216.238.106[.]150 | 443, 8080 | SparroWocky C2 server |
| 216.238.110[.]120 | 443, 8080 | SparroWocky C2 server |
| 216.238.121[.]164 | 443, 8080 | SparroWocky C2 server |
| 43.254.216[.]195 | 443, 8080 | SparroWocky C2 server |
| 103.85.25[.]166 | 443, 8080 | SparroWocky C2 server |
| 45.131.179[.]24 | 443, 8080 | SparroWocky C2 server |
| 27.102.113[.]240 | 443, 8080 | SparroWocky C2 server |

*Source: ESET GitHub repository README — at least 18 C2 addresses documented; traffic on port 443 or 8080 direct, or via HTTP/SOCKS5 proxy.*

### Domains

| Domain | Notes |
|--------|-------|
| amelicen[.]com | SparroWocky / FamousSparrow infrastructure domain |
| credits.offices-analytics[.]com | SparroWocky / FamousSparrow infrastructure domain |

---

## 2. TTPs (MITRE ATT&CK)

| Tactic | Technique ID | Technique Name | Usage |
|--------|-------------|----------------|-------|
| Initial Access (TA0001) | T1190 | Exploit Public-Facing Application | FamousSparrow gains initial access by exploiting publicly reachable Microsoft Exchange Server web services; historically uses N-day Exchange vulnerabilities for initial code execution |
| Execution (TA0002) | T1059.003 | Windows Command Shell | Command execution via shell after exploitation; BOF (Beacon Object Files) are executed in-process by SparroWocky to extend capabilities without dropping new executables |
| Persistence (TA0003) | T1543.003 | Create or Modify System Process: Windows Service | SparroWocky installs itself as a Windows service for persistence; service names not disclosed in public reporting |
| Defense Evasion (TA0005) | T1055 | Process Injection | SparroWocky uses process injection techniques to hide malicious code in legitimate processes |
| Defense Evasion (TA0005) | T1027 | Obfuscated Files or Information | Anti-analysis techniques and knowledge of Windows internals are embedded in SparroWocky |
| Credential Access (TA0006) | T1003.001 | OS Credential Dumping: LSASS Memory | Post-exploitation credential dumping from LSASS |
| Discovery (TA0007) | T1082 | System Information Discovery | SparroWocky collects host and network details as a core backdoor function |
| Collection (TA0009) | T1113 | Screen Capture | SparroWocky captures screenshots on a repeating cycle and exfiltrates them |
| Collection (TA0009) | T1005 | Data from Local System | File exfiltration capability in SparroWocky |
| Command and Control (TA0011) | T1071.001 | Application Layer Protocol: Web Protocols | C2 over TLS on port 443 or 8080; traffic encrypted via TLS at the transport layer plus RC4 for the payload |
| Command and Control (TA0011) | T1090 | Proxy | HTTP and SOCKS5 proxies used to relay traffic through intermediate nodes |
| Command and Control (TA0011) | T1573.001 | Encrypted Channel: Symmetric Cryptography | Command data additionally encrypted with RC4 inside the TLS tunnel |
| Exfiltration (TA0010) | T1041 | Exfiltration Over C2 Channel | Files and screenshots exfiltrated via the established C2 channel |

---

## 3. Malware & Tools

### SparroWocky

- **Type:** Modular C++ backdoor
- **Naming:** Named by ESET because early iterations contain the first stanza of *Jabberwocky* (Lewis Carroll) as an embedded string
- **Architecture:** Modular design; capability extensions loaded as Beacon Object Files (BOFs) without dropping new executables to disk
- **Core Capabilities:**
  - Execute arbitrary shell commands
  - Execute files
  - Act as TCP proxy
  - Collect host and network details
  - Exfiltrate files
  - Take screenshots on a repeating schedule
  - Load and execute Beacon Object Files (BOFs)
- **C2 Protocol:** TLS over port 443 or 8080 (direct or via HTTP/SOCKS5 proxy); payload additionally encrypted with RC4
- **C2 count:** At least 18 active C2 servers documented

### Related Malware Families (Historical FamousSparrow)
- **SparrowDoor** — Older FamousSparrow loader, replaced by SparroWocky
- **ShadowPad** — Shared tooling with other China-nexus groups; used in some FamousSparrow operations
- **SparkRAT** — Modified open-source Go RAT used in subset of intrusions
- **HemiGate** — Plugin-based variant observed in earlier campaigns

---

## 4. Threat Actor / Campaign Attribution

| Field | Value |
|-------|-------|
| Actor Name | FamousSparrow |
| Aliases | Unknown aliases; ESET tracking designation |
| Nexus | China-aligned (state-sponsored, likely China Ministry of State Security or PLA affiliate) |
| Targeting | Governmental entities in Argentina, Ecuador, Guatemala, Honduras, Panama, Peru, Puerto Rico, and Venezuela; 90% of ESET telemetry from mid-2025 into 2026 is Latin American targets |
| Sectors | Government, diplomatic entities |
| Campaign Timeline | SparroWocky: December 2025 – active into September 2026; FamousSparrow previously attributed to 2021 MS Exchange mass exploitation |
| Motivation | Cyber espionage |

---

## 5. Splunk Detection Searches

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Processes
where Processes.parent_process_name IN ("w3wp.exe", "httpd.exe", "tomcat.exe", "java.exe")
    AND Processes.process_name IN ("cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe",
                                    "certutil.exe", "bitsadmin.exe", "mshta.exe", "rundll32.exe",
                                    "regsvr32.exe", "schtasks.exe", "net.exe", "net1.exe",
                                    "whoami.exe", "ipconfig.exe", "nltest.exe", "ping.exe")
by Processes.dest Processes.user Processes.parent_process_name
   Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    process_name IN ("cmd.exe","powershell.exe"), 85,
    process_name IN ("certutil.exe","bitsadmin.exe","mshta.exe","regsvr32.exe"), 90,
    1=1, 75)
| where risk_score >= 75
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```
*Detects Exchange/IIS web server processes (w3wp.exe) spawning command-line tools — a hallmark of Exchange exploitation and SparroWocky post-compromise execution. FamousSparrow uses Exchange RCE as the initial access vector.*

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Network_Traffic.All_Traffic
where All_Traffic.dest_ip IN (
    "38.54.57.17","38.60.197.55","38.60.209.106","38.60.224.51","38.60.224.235",
    "38.60.241.65","38.60.241.127","38.60.241.193","77.111.101.40","91.148.134.115",
    "130.94.101.82","140.99.164.199","149.104.87.228","149.104.90.203","216.238.92.2",
    "216.238.105.53","216.238.106.150","216.238.110.120","216.238.121.164",
    "43.254.216.195","103.85.25.166","45.131.179.24","27.102.113.240")
    AND All_Traffic.dest_port IN ("443","8080")
by All_Traffic.src All_Traffic.dest All_Traffic.dest_ip All_Traffic.dest_port All_Traffic.app
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=90
| table firstTime lastTime src dest dest_ip dest_port app risk_score
```
*Detects direct outbound connections to known SparroWocky C2 server IP addresses on ports 443 or 8080. Requires network traffic data model with destination IP resolution.*

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Network_Resolution.DNS
where DNS.query IN ("amelicen.com","credits.offices-analytics.com")
by DNS.src DNS.query DNS.answer DNS.record_type
| `drop_dm_object_name(DNS)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=90
| table firstTime lastTime src query answer record_type risk_score
```
*Detects DNS resolution of known SparroWocky infrastructure domains. High-fidelity IOC — any hit warrants immediate investigation.*

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Services
where Services.start_type="auto start"
    AND Services.service_dll_path IN ("C:\\Users\\*","C:\\ProgramData\\*","C:\\Temp\\*","C:\\Windows\\Temp\\*")
by Services.dest Services.user Services.service_name Services.service_dll_path Services.process
| `drop_dm_object_name(Services)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=85
| where risk_score >= 85
| table firstTime lastTime dest user service_name service_dll_path process risk_score
```
*Detects Windows services with DLL paths in user-writable directories (T1543.003) — consistent with SparroWocky service-based persistence. Tune path exclusions for legitimate software installed to ProgramData.*

```spl
index=* (hash IN (
    "e0ff727c5feb3352f0bb6df91bcf2b3100203e5777c8b49b3913fcec0dbbd260",
    "8dfaa1f579de14bca8bb27c54a57dd87646a835969766ca9ddb81ecd9329f4e4",
    "bc2b8196d8c966e84c255d0d1c7908541104446e3fc51f52318aac4239bbb4c4",
    "03241adc63e5a204dcec26915f4df076a8121fa7827edfdc36b75e4803c2f019",
    "1215584b4fa69130799f6cf5efe467f380dc68b14ed2c76f63ca6b461ad57246",
    "222d68c03d96d230bc3829e86be8821f32960375b70388028a705a4986b8d9c6",
    "773635768e738bec776dfd7504164b3596e5eee344757dd1ac9a1ad19b452c86",
    "67d7962eaec2c785d7a6db8502c74e6ccd95445d366e370fa9fe6743d68cb42c",
    "90af57e976aea91030579b9761e5265251986b707550ca1b793191e2818bad92",
    "f61a113f6de19f2c821b89d934268621cf2410278155f173c8682e524b450f21",
    "f2434d7f2427ee2f3a1be4ab0922fb73ac2ceaa494c73790af71024453ce0c9c",
    "c57fd715bcb6d5ece60745d036496ac37e0c13f14098776c9168c0381a01409f",
    "dd5a6c162eff8103f6e06149faf1287feeb6dbbbb9bbca031145767fd69ce500",
    "24dc94e01592a29c90fd875dcdfa095ed6e1dff6db4e517b48a2f89db467aa28",
    "edc3ab9bc87402a5e7de43b7b2e247fdd4e134b9220d91f84934362cce34b827",
    "dd3dffb09fd1df4ea2ae38023e5c256855dfc9bcf9913d775f65365e2acae166",
    "b68c8dff2ca0944c7e6c94d184d8219c08c020eb349ff9e0a7f49bc6a6effdaf",
    "973a692e6240bf4ce3c14e6ca13755c7e473c7722513d7a6e811a08cf2ae0e10",
    "1cca1555b3ce3dbe37e17f32c91441886fb113a3d5e8da1c4ec5e523f8719fa5",
    "63cf1e1e7ea20a69f8a6b9d16468673b92cfe2560ad1012422ec3001a7e837cf",
    "80a7ff01de553cb099452cb9fac5762caf96c0c3cd9c5ad229739da7f2a2ca72",
    "41128b82fa12379034b3c42bdecf8e3b435089f19a5d57726a2a784c25e9d91f",
    "1ce7895cee6dfbc182486f7c2dff87281ba0b57a85febeb1a0196d480d032936",
    "abbf9c57ad3068c8aafaf443297e9448e8657b6ac16e1a8bdde5ba87254708e1",
    "d53346b5c8c6c76e7bc0407410a58328a1e214a4d359e558380963d29a35f71b",
    "5ad73e8bd5bde7808cfa39d3ada411a2e5a51278dcc7b543f2f5b5abb0c4ea27",
    "0e74d57f572e384ad179ad8aa094cbdc92a6abbcc77eeb658fc05743ffd94e68",
    "d057034675befc1b4c2ae4132c4d169201c9abfbae79181185d45ca6721e43cc",
    "95dff799b2fffe128fb5e8f3bae0a0ec5bc5b181567165ac50860beac9230fcf",
    "b87247a9ab8994e18486970c8c393593143b8775d75305b8b244c58a1294790c",
    "e0b6f8535e19f0a4938e3317de0c4493ecea17aa906fd0454805ba2086cbf3a8",
    "72677119b8bf3e2d23f22150c7b364fea9248819c36e97db015414586285591d",
    "3c771cf5f74a62a0c0d825f99dbe322ec261b4cc988006ada3a4b829b09ba43e"
) )
| stats count min(_time) as firstTime max(_time) as lastTime by host hash file_path
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=95
| table firstTime lastTime host hash file_path risk_score
```
*Detects execution or presence of files matching known SparroWocky SHA256 hashes. Adapt `hash` field name to your endpoint telemetry (e.g., `sha256`, `SHA256Hash`, `file_hash`). Any hit is critical.*

---

## 6. Executive Summary

ESET Research published a detailed analysis on September 17, 2026 of **SparroWocky**, a new modular C++ backdoor deployed by China-aligned espionage group **FamousSparrow** against government organizations across Latin America. The backdoor is named after embedded strings from Lewis Carroll's *Jabberwocky*.

**Targeting:** Government entities in Argentina, Ecuador, Guatemala, Honduras, Panama, Peru, Puerto Rico, and Venezuela. ESET telemetry shows 90% of FamousSparrow targets from mid-2025 into 2026 were in Latin America, a significant geographic pivot from FamousSparrow's historically broader global targeting.

**Initial Access:** FamousSparrow exploits publicly reachable Microsoft Exchange servers (T1190) to establish initial footholds, continuing a pattern first observed in the 2021 ProxyLogon wave.

**Malware Capabilities:** SparroWocky supports command execution, file exfiltration, TCP proxy, host discovery, repeating screenshot capture, and dynamic capability extension via Beacon Object Files (BOFs) — a technique borrowed from Cobalt Strike that extends backdoor functionality without writing new executables to disk.

**C2 Infrastructure:** At least 18 confirmed C2 servers communicate with SparroWocky on port 443 or 8080, with all traffic over TLS and payload additionally RC4-encrypted. SOCKS5 and HTTP proxies are used to relay traffic through intermediate nodes, complicating attribution and detection.

**Scale and Persistence:** SparroWocky is active December 2025 – present, representing an ongoing espionage campaign. Organizations with Exchange servers exposed to the internet in Latin American government sectors should treat this as a high-priority threat.

---

## References

- [ESET WeLiveSecurity — Beware the SparroWock (September 17, 2026)](https://www.welivesecurity.com/en/eset-research/beware-sparrowock-backdoor-bites-commands-catch/)
- [ESET GitHub malware-ioc — FamousSparrow](https://github.com/eset/malware-ioc/tree/master/famoussparrow)
- [ESET GlobeNewswire Press Release (September 17, 2026)](https://www.globenewswire.com/news-release/2026/09/17/3363770/0/en/eset-research-china-aligned-famoussparrow-expands-operations-in-latin-america-targets-governments-with-new-backdoor.html)
- [MITRE ATT&CK — FamousSparrow (G0093)](https://attack.mitre.org/groups/G0093/)
- [MITRE ATT&CK — T1190 Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
- [MITRE ATT&CK — T1543.003 Windows Service Persistence](https://attack.mitre.org/techniques/T1543/003/)
- [MITRE ATT&CK — T1055 Process Injection](https://attack.mitre.org/techniques/T1055/)
- [MITRE ATT&CK — T1071.001 Web Protocol C2](https://attack.mitre.org/techniques/T1071/001/)
