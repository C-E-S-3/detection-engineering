---
scraped_at: "2026-11-01T00:00:00Z"
source_url: "https://blog.talosintelligence.com/uat-11473-keydrift/"
report_type: threat-intel
severity: critical
title: "UAT-11473 KeyDrift: State-Linked APT Deploys IPsec Key-Stealing Malware on Cisco SD-WAN Controllers via CVE-2026-20127"
---

## 1. IOCs

### CVEs / Vulnerabilities

| CVE | CVSS | Product | Description |
|-----|------|---------|-------------|
| CVE-2026-20127 | 10.0 | Cisco Catalyst SD-WAN Controller, Manager, Validator | Authentication bypass enabling unauthenticated API access and arbitrary command execution as root; affects on-premises and Cisco-hosted cloud deployments |

### File Artifacts (no hashes publicly confirmed in accessible secondary sources as of 2026-11-01)

| Filename | Role | Path (observed) |
|----------|------|-----------------|
| libcommon.so | LittleFilch — SSL_read hook injected into vdaemon; extracts 32-byte AES-256 IPsec key material from decrypted control-plane messages | SD-WAN controller library paths |
| libdssl.so | PolyFlame — in-memory backdoor; receives commands covertly via SD-WAN control-plane traffic; masquerades as SSL helper library | SD-WAN controller library paths |

### Detection Rules (Snort)

| Rule Set | SIDs | Covers |
|----------|------|--------|
| Snort v2 (CVE-2026-20127) | 65938, 65958 | Authentication bypass exploitation attempts |
| Snort v2 (KeyDrift) | 67387–67416 | KeyDrift implant traffic and behavior |
| Snort v3 (KeyDrift) | 7:44–7:73 | KeyDrift implant traffic and behavior |

> **Note:** No network IOC hashes, IP addresses, or C2 domains were available in accessible secondary sources at time of writing. For the full indicator set, consult the Talos blog post directly at https://blog.talosintelligence.com/uat-11473-keydrift/ and Cisco advisory `cisco-sa-sdwan-rpa-EHchtZk`.

---

## 2. TTPs (MITRE ATT&CK)

| Tactic | Technique ID | Technique Name | KeyDrift Usage |
|--------|-------------|----------------|---------------|
| Initial Access | T1190 | Exploit Public-Facing Application | CVE-2026-20127 (CVSS 10.0 auth bypass) used to gain root on Cisco Catalyst SD-WAN Controller, Manager, and Validator |
| Execution | T1059 | Command and Scripting Interpreter | Post-auth commands executed as root via CVE-2026-20127 to deploy LittleFilch and PolyFlame |
| Persistence | T1543.001 | Create or Modify System Process: Systemd Service / Init Daemon | Modified runit launcher scripts ensure KeyDrift components survive reboots on the appliance |
| Defense Evasion | T1036.005 | Masquerading: Match Legitimate Name or Location | libdssl.so and libcommon.so impersonate standard SSL and common library names used by SD-WAN vdaemon process |
| Defense Evasion | T1055 | Process Injection | LittleFilch injects SSL_read hook into the running vdaemon process without spawning a separate process |
| Collection | T1119 | Automated Collection | LittleFilch automatically extracts 32-byte AES-256 IPsec key material from each decrypted SD-WAN control-plane message processed by vdaemon |
| Command and Control | T1205 | Traffic Signaling | PolyFlame receives operator commands embedded inside legitimate SD-WAN control-plane traffic, avoiding separate C2 channel |

---

## 3. Malware & Tools

### KeyDrift Framework

| Component | Type | Description |
|-----------|------|-------------|
| LittleFilch | SSL_read hook / key extractor | Shared object injected into vdaemon; hooks SSL_read to intercept control-plane messages after TLS decryption and extracts a 32-byte field Talos assesses with high confidence to be AES-256 IPsec key material; key material is staged for exfiltration |
| PolyFlame | In-memory backdoor / covert C2 | Shared object acting as an in-memory backdoor; receives operator commands covertly encoded in SD-WAN control-plane traffic; executes commands on the appliance with root privileges without requiring a separate external C2 channel |

---

## 4. Threat Actor / Campaign Attribution

**Actor:** UAT-11473 (Cisco Talos designation)

**Summary:**
- Talos disclosed the KeyDrift campaign on October 28, 2026
- UAT-11473 infrastructure overlaps with high confidence with Volt Typhoon's "Silent Train" operational relay network (ORB) as characterized by Lumen Black Lotus Labs; Talos does not assess the two groups are identical
- Targets observed: space and satellite services, defense and aerospace technology, policy research organizations
- Motivation: Strategic intelligence gathering; IPsec key exfiltration enables passive decryption of captured enterprise WAN traffic
- Apparent state sponsorship: China-nexus assessed (based on Silent Train infrastructure overlap)
- Entry confirmed via CVE-2026-20127; Cisco disclosed the flaw in February 2026 and no workaround exists — only patching resolves it

---

## 5. Splunk Detection Searches

```spl
`cisco_sdwan` sourcetype=cisco:sdwan:audit
| search action=* (status=401 OR status=403 OR status=200)
    uri_path IN ("/dataservice/client/token", "/dataservice/j_security_check", 
                 "/dataservice/v1/token", "/dataservice/admin/*")
| bin _time span=5m
| stats count values(status) as statuses 
        values(src_ip) as src_ips 
        min(_time) as firstTime max(_time) as lastTime 
  by host uri_path
| where count > 5 AND mvcount(statuses) > 1
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=90
| table firstTime lastTime host uri_path src_ips statuses count risk_score
```
_Detects sequential auth-bypass probing against Cisco SD-WAN Manager REST API — CVE-2026-20127 exploitation precursor_

```spl
`cisco_sdwan` sourcetype=cisco:sdwan:syslog
| search (message="libcommon.so" OR message="libdssl.so" 
          OR message="vdaemon" OR message="runit"
          OR process_path IN ("*libcommon.so*","*libdssl.so*"))
| stats count min(_time) as firstTime max(_time) as lastTime 
        values(message) as messages 
  by host src_user
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=95
| table firstTime lastTime host src_user messages count risk_score
```
_Detects presence of KeyDrift malware artifact filenames (LittleFilch=libcommon.so, PolyFlame=libdssl.so) in SD-WAN controller syslog_

---

## 6. Executive Summary

Cisco Talos disclosed on October 28, 2026 that a threat actor cluster designated UAT-11473 — whose infrastructure overlaps significantly with Volt Typhoon's Silent Train relay network — has been actively deploying a novel malware framework called **KeyDrift** against Cisco Catalyst SD-WAN Controllers, Managers, and Validators. Entry is via CVE-2026-20127, a maximum-severity (CVSS 10.0) authentication bypass patched by Cisco in February 2026 but apparently still unpatched across victim environments.

The objective is IPsec encryption key theft: the LittleFilch component hooks into the vdaemon process SSL_read function to silently extract AES-256 IPsec key material from decrypted control-plane messages. The PolyFlame backdoor receives operator commands embedded inside legitimate SD-WAN control traffic, making the implant extremely difficult to detect without appliance-level forensics. Persistence is via modified runit launcher scripts.

Observed victims span space and satellite services, defense and aerospace, and policy research — consistent with strategic intelligence objectives aligned with Chinese state interests. Key rotation for SD-WAN IPsec tunnels is recommended alongside emergency patching of CVE-2026-20127 for all affected organizations.

**Immediate action:** Apply Cisco patch for CVE-2026-20127; rotate all SD-WAN IPsec tunnel keys on potentially affected controllers; audit runit scripts and shared library loadout on SD-WAN appliances for unexpected additions.
