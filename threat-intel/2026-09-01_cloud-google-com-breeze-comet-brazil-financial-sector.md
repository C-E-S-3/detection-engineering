---
scraped_at: 2026-09-01T00:00:00Z
source_url: https://cloud.google.com/blog/topics/threat-intelligence/financially-motivated-threat-actor-breeze-comet-targets-brazil
report_type: threat-intel
severity: high
title: "BREEZE COMET: Financially Motivated Threat Actor Targets Brazilian Financial Infrastructure (Pix, STR, Boleto)"
---

# BREEZE COMET: Financially Motivated Threat Actor Targets Brazilian Financial Infrastructure

**Date Reported:** August 2026  
**Source:** Google Threat Intelligence Group (GTIG)  
**Severity:** High  
**Note:** New threat actor cluster targeting Brazilian interbank settlement systems. Custom toolset including Rust, Go, Nim, and Java implants. Not previously tracked.

## 1. IOCs

### File Hashes (SHA-256)

| Hash | Malware Family | Description |
|------|---------------|-------------|
| `3b22605244dbace8f0c07c2c599f88c4b831bb07e9998b869a5da2759d27ceec` | COBALTSPIN | Rust-based SOCKS5-over-WebSocket network tunneler |
| `2214907e696bad85bde1d90c943ef66e413d7a5c6d7596ced25b74441200439a` | REALBREEZE | Custom LDAP brute-force utility for Active Directory attacks |
| `c0db6ddd6222d02ad7490399d33c61ded0076f0037409dc8498924458646d78a` | MILDFROST | Java JAR passive backdoor with DNS tunneling C2 |
| `6d4012e0dd3b56a3e52857734fa0d582cdf3c56f0e5decc8005c882d1d1c6ceb` | BOATBEAM | Go-based backdoor masquerading as IIS HTTPS server |
| `f139b4ca15feffb7a6633ec1a431c5c604b397576b56b5c863ae8fe4fa14db4f` | KICKPLATE | Nim-based backdoor impersonating Windows Update Health Tools |
| `51fdd83b3737add7f3832bd0ad0b56863c0a8f7cf9bcc16fd787d1ae4b403ce6` | XWORM | Commercial backdoor; initial access and persistence |
| `d2aa40cc53b40c6e76ac0677c4a54387b3f27ee94c85d9b2c3a3d66aeef92a66` | XWORM | Commercial backdoor; alternate variant |
| `447e3a131e62bd33b1297739a7b959a92358a97f58554469044636a3c4f244e8` | XWORM | Commercial backdoor; alternate variant |

### Domains (Compromised Brazilian Government Staging Infrastructure)

All `.gov.br` domains are legitimate Brazilian government sites compromised by BREEZE COMET for payload staging. Treat these as time-limited indicators — remediation is expected. The critical pattern is staging via `*.gov.br` domains to evade geo-blocking and trust controls.

| Indicator | Type | Context |
|-----------|------|---------|
| `procon[.]go[.]gov[.]br` | Compromised staging | Hosted `ComprovantePDF.exe` (XWORM/KICKPLATE dropper) |
| `cmgovernadorluizrocha[.]ma[.]gov[.]br` | Compromised staging | Hosted `Comprovantepdf.exe` |
| `gcm[.]setelagoas[.]mg[.]gov[.]br` | Compromised staging | Hosted `ti.zip`, `notepadd.exe`, `tes.exe` |
| `minacu[.]go[.]gov[.]br` | Compromised staging | Hosted `ComprovantePDF.exe` |
| `conseg[.]ssp[.]go[.]gov[.]br` | Compromised staging | Hosted `COAF-POLICIAFEDERAL.exe`, `ComprovanteBBpix.exe` |
| `suporte[.]camaratunapolis[.]sc[.]gov[.]br` | Compromised staging | Hosted `attvpn.zip`, `1.exe` |
| `tisup[.]camaratunapolis[.]sc[.]gov[.]br` | Compromised staging | Hosted `SoftEther.exe` (VPN persistence via LIGHTPAINT) |
| `suporte[.]ourinhos[.]sp[.]gov[.]br` | Compromised staging | Hosted `s.zip`, `s.exe`, `a.exe` |
| `servicos[.]salto[.]sp[.]gov[.]br` | Compromised staging | Hosted `j.jar` (MILDFROST Java backdoor) |
| `mrtb[.]gov[.]ng` | Compromised staging | Hosted `attvpn.vip` |
| `credeb[.]gov[.]gn` | Compromised staging | Hosted `r.zip` |
| `sit[.]baer[.]gob[.]ve` | Compromised staging | Hosted `r.exe` |
| `jmcov[.]gov[.]py` | Compromised staging | Hosted `cxv.exe` |
| `dontpad[.]com` | Exfiltration | Legitimate public notepad site used for data exfiltration |

## 2. TTPs

| Tactic | Technique | Details |
|--------|-----------|---------|
| Initial Access | T1566 — Phishing | Voice phishing impersonating IT support; VEC-style targeting of financial sector employees |
| Initial Access | T1200 — Hardware Implants | Rogue hardware devices inserted into retail banking network points |
| Initial Access | T1190 — Exploit Public-Facing Application | JBoss AS vulnerability exploitation for initial foothold |
| Credential Access | T1110.004 — Brute Force: Credential Stuffing | REALBREEZE custom LDAP brute-force against Active Directory |
| Credential Access | T1003 — OS Credential Dumping | Theft of mTLS certificates, API keys, service account credentials |
| Privilege Escalation | T1199 — Trusted Relationship | Mining hard-coded credentials from CI/CD pipelines |
| Discovery | T1518 — Software Discovery | Impacket, ADRecon, ADVipscan for network and AD reconnaissance |
| Defense Evasion | T1027.005 — Indicator Removal: In-Memory Execution | PowerShell reconnaissance scripts executed in memory only |
| Defense Evasion | T1562.001 — Impair Defenses | PowerShell commands disabling Windows Defender |
| Lateral Movement | T1021.001 — Remote Services: RDP | Unauthorized RDP sessions using hijacked service accounts |
| Lateral Movement | T1021.002 — Remote Services: SMB | Command execution via SMB shares |
| Persistence | T1053.005 — Scheduled Task | SYSTEM-level persistence via schtasks.exe |
| Persistence | T1547.001 — Registry Run Keys / Startup Folder | Malicious `.lnk` in Startup folder; registry Run key modifications (KICKPLATE) |
| Persistence | T1037 — Boot or Logon Initialization Scripts | Registry startup key modifications for MILDFROST/KICKPLATE |
| Command & Control | T1090 — Proxy | COBALTSPIN SOCKS5 reverse proxy tunneled over WebSocket |
| Command & Control | T1071.004 — Application Layer Protocol: DNS | MILDFROST DNS tunneling via dynamic subdomain queries (DnsCommandBeacon.class) |
| Command & Control | T1071.001 — Web Protocols | BOATBEAM fake IIS HTTPS server on port 443 with session-cookie activation |
| Exfiltration | T1041 — Exfiltration Over C2 Channel | Data uploaded to `dontpad[.]com` public notepad site |
| Impact | T1491 — Defacement | Fraudulent Pix, STR, and Boleto interbank transactions |

**MITRE Tactics:** TA0001, TA0003, TA0005, TA0006, TA0008, TA0009, TA0011, TA0040  
**Kill Chain Phases:** Delivery, Exploitation, Installation, C2, Actions on Objectives

## 3. Malware & Tools

### COBALTSPIN (Rust)
Lightweight Rust-based network tunneler operating as a SOCKS5 proxy over WebSocket connections. Routes operator traffic between C2 infrastructure and internal network targets, enabling lateral movement and post-exploitation tooling through boundary firewalls.

### REALBREEZE (custom .NET LDAP brute-forcer)
Custom LDAP brute-forcing utility designed specifically for Brazilian Active Directory environments. Portuguese-language GUI (`SENHA`, `USUÁRIO`, `IP/REDE` strings). Attacks domain accounts to harvest credentials for lateral movement to financial systems.

### MILDFROST (Java JAR)
Passive Java backdoor hiding within JVM process space. Uses DNS tunneling via `DnsCommandBeacon.class` for covert C2 communication using dynamic subdomain queries. Serves as fallback/long-term persistence C2. Commands: `shell:`, `exec:`, `upload,`, `dl|`, `tc|`, `noop`, `wait:`.

### KICKPLATE (Nim)
Custom Nim-based backdoor masquerading as Windows Update Health Tools. Controls SOCKS5 tunnelers (COBALTSPIN), modifies registry startup keys, and manipulates Windows services. Primary orchestration layer for the BREEZE COMET toolkit.

### LIGHTPAINT (Java)
Java-based backdoor that installs and configures SoftEther VPN for automated network access. Provides persistent VPN-based access to victim networks independent of other C2 channels.

### BOATBEAM (Go)
Golang backdoor that initializes a fake IIS HTTPS server on port 443. Hides backdoor traffic within apparent web server responses; only activates C2 functionality when receiving HTTP requests with specific session cookie values.

### XWORM
Widely available commercial backdoor purchased from criminal forums. Used for initial access, persistence via startup shortcut modifications, and baseline RAT functionality. Three distinct variants observed (three different hashes).

## 4. Threat Actor

**BREEZE COMET** is a new, financially motivated threat actor cluster identified by Google Threat Intelligence Group in August 2026. The actor exclusively targets Brazilian financial infrastructure — specifically systems involved in Pix (instant payment), STR (reserve transfer), Boleto (payment slip), and CNAB (banking file) operations.

Distinctive characteristics:
- Deep knowledge of Brazilian financial system architecture and Portuguese language
- Staged payloads exclusively through compromised `.gov.br` government domains to abuse institutional trust
- Custom toolset across five programming languages (Rust, Go, Nim, Java, .NET) — unusual breadth for a financially-motivated actor
- Use of voice phishing and physical hardware implants alongside traditional cyber intrusion
- Data exfiltration via public legitimate services (`dontpad.com`) to avoid DLP controls

No attribution to a known nation-state or cybercriminal group has been made. The sophistication and Brazilian-specific targeting suggest either an insider threat with financial sector knowledge or a well-resourced criminal organization with domain expertise.

## 5. Splunk Detection Searches

### Detect LDAP brute force (REALBREEZE pattern — high volume failed LDAP auth)
```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Authentication
  where Authentication.action=failure
    AND Authentication.app IN ("ldap", "ldaps", "Active Directory")
  by Authentication.src Authentication.dest Authentication.user
| `drop_dm_object_name(Authentication)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| where count > 50
| eval risk_score=case(count > 500, 90, count > 100, 75, count > 50, 60, true(), 40)
| table firstTime lastTime src dest user count risk_score
```

### Detect DNS queries matching dynamic C2 subdomain pattern (MILDFROST)
```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Resolution.DNS
  where DNS.record_type="A" OR DNS.record_type="TXT"
  by DNS.src DNS.query DNS.answer
| `drop_dm_object_name(DNS)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval subdomain_count=mvcount(split(query, "."))
| where subdomain_count >= 4
| stats count dc(query) as unique_subdomains by src
| where unique_subdomains > 20
| eval risk_score=case(unique_subdomains > 100, 85, unique_subdomains > 50, 70, true(), 55)
| table src unique_subdomains count risk_score
```

### Detect BREEZE COMET IOC hash matches
```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.process_hash IN (
    "3b22605244dbace8f0c07c2c599f88c4b831bb07e9998b869a5da2759d27ceec",
    "2214907e696bad85bde1d90c943ef66e413d7a5c6d7596ced25b74441200439a",
    "c0db6ddd6222d02ad7490399d33c61ded0076f0037409dc8498924458646d78a",
    "6d4012e0dd3b56a3e52857734fa0d582cdf3c56f0e5decc8005c882d1d1c6ceb",
    "f139b4ca15feffb7a6633ec1a431c5c604b397576b56b5c863ae8fe4fa14db4f",
    "51fdd83b3737add7f3832bd0ad0b56863c0a8f7cf9bcc16fd787d1ae4b403ce6",
    "d2aa40cc53b40c6e76ac0677c4a54387b3f27ee94c85d9b2c3a3d66aeef92a66",
    "447e3a131e62bd33b1297739a7b959a92358a97f58554469044636a3c4f244e8"
  )
  by Processes.dest Processes.user Processes.process_name Processes.process_hash
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=95
| table firstTime lastTime dest user process_name process_hash risk_score
```

### Detect SoftEther VPN installed as service (LIGHTPAINT persistence)
```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Services
  where Services.process_name IN ("vpnserver.exe", "vpnclient.exe", "SoftEther.exe", "vpnbridge.exe")
    AND Services.start_mode=auto
  by Services.dest Services.user Services.process_name Services.service_path
| `drop_dm_object_name(Services)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=70
| table firstTime lastTime dest user process_name service_path risk_score
```

### Detect data exfiltration via dontpad[.]com (BREEZE COMET exfil pattern)
```spl
| tstats `security_content_summariesonly` count sum(All_Traffic.bytes_out) as bytes_out
  min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Traffic.All_Traffic
  where All_Traffic.dest_host="dontpad.com" OR All_Traffic.dest_host="*.dontpad.com"
  by All_Traffic.src All_Traffic.dest_host All_Traffic.dest_port
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| where bytes_out > 50000
| eval risk_score=75
| table firstTime lastTime src dest_host dest_port bytes_out risk_score
```

## 6. Executive Summary

BREEZE COMET is a newly identified financially motivated threat actor cluster targeting Brazilian interbank payment infrastructure (Pix, STR, Boleto, CNAB). Google GTIG disclosed the actor in August 2026 after observing intrusions into Brazilian financial institutions via a combination of voice phishing, physical hardware implants, and web application exploitation.

The actor employs a custom five-language toolset: XWORM (initial access), KICKPLATE (Nim orchestrator), COBALTSPIN (Rust SOCKS5 tunneler), BOATBEAM (Go fake-IIS backdoor), MILDFROST (Java DNS-tunnel fallback C2), LIGHTPAINT (Java VPN installer), and REALBREEZE (custom LDAP brute-forcer). All staging infrastructure used compromised Brazilian `.gov.br` government websites to abuse institutional trust and evade geographic controls.

Key detection priorities: monitor for high-volume LDAP authentication failures (REALBREEZE), unexpected SoftEther VPN service installation (LIGHTPAINT), large data uploads to `dontpad.com`, and DNS queries matching the MILDFROST dynamic subdomain C2 pattern. Hash-based detection covers all eight known malware samples.

## References

- [Google GTIG — BREEZE COMET Targets Brazil Financial Infrastructure](https://cloud.google.com/blog/topics/threat-intelligence/financially-motivated-threat-actor-breeze-comet-targets-brazil)
- [MITRE ATT&CK — T1110.004 Credential Stuffing / LDAP Brute Force](https://attack.mitre.org/techniques/T1110/004/)
- [MITRE ATT&CK — T1071.004 DNS Tunneling](https://attack.mitre.org/techniques/T1071/004/)
- [MITRE ATT&CK — T1090 Proxy (SOCKS5)](https://attack.mitre.org/techniques/T1090/)

## YARA Rules

```yara
rule M_Utility_REALBREEZE_2 {
    meta:
        author = "Google Threat Intelligence Group"
            
    strings:
        $s1 = "IP/REDE" wide
        $s2 = "SENHA" wide
        $s3 = "U\x00S\x00U\x00\xc1\x00R\x00I\x00O\x00:"
        $s4 = "Arquivo de Texto (*.txt)|*.txt" wide
        $s5 = "get_SamAccountName"
        $s6 = "get_txtHostname"

    condition:
      uint16(0) == 0x5A4D
      and all of them 
}
```

```yara
rule G_Tunneler_COBALTSPIN_1
{
  meta:
    author = "Google Threat Intelligence Group"
    
  strings:
    $p00_0 = {488985[4]72??4c8b47??4c8b6f??488985[4]eb??4989f04989c5488b85}
    $p00_1 = {4d8bae[4]4d85ed4c897d??897d??4c8975??89b5[4]74??498bbe[4]4d89ee}
  condition:
    uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 and
    (
      ($p00_0 in (560000..600000) and $p00_1 in (1500000..1600000))
    )
}
```

```yara
rule G_Backdoor_BOATBEAM_1
{
  meta:
    author = "Google Threat Intelligence Group"
    
  strings:
    $p00_0 = {4d89d84889ce488bbc24[4]e9[4]0f82[4]4c89ac24[4]4c89e74d29ec4c896424}
    $p00_1 = {e8[4]498903498973??498953??4d8943??488942??488957??4889f8488b4c24}
  condition:
    uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 and
    (
      ($p00_0 in (1500000..1600000) and $p00_1 in (2700000..2800000))
    )
}
```

```yara
rule G_Backdoor_MILDFROST_1 
{
  meta:
    author = "Google Threat Intelligence Group"
  
  strings:
    $s1 = "sc tcp ok" fullword
    $s2 = "fl comando vazio" fullword
    $s3 = "noop" fullword
    $s4 = "wait:" fullword
    $s5 = "shell:" fullword
    $s6 = "exec:" fullword 
    $s7 = "upload," fullword
    $s8 = "dl|" fullword 
    $s9 = "tc|" fullword
  condition:
    uint16(0)==0x5a4d and 7 of them
}
```
