# Kimsuky HttpTroy HTTP C2 Beaconing

## Description

Detects network and endpoint activity consistent with Kimsuky's **HttpTroy** backdoor and the broader PebbleDash malware cluster. HttpTroy is a DLL-based backdoor loaded in-memory by the MemLoad loader; it communicates with its C2 server via periodic HTTP POST requests. The PebbleDash cluster also includes **httpMalice** (uses compromised South Korean websites and Dropbox for C2) and JSE/SCR file droppers.

Detection covers:
1. HTTP POST connections from non-browser processes to known Kimsuky C2 domains
2. DNS resolution of known Kimsuky C2 infrastructure
3. SCR (screen saver) file execution from user-writable directories (dropper delivery)
4. WScript/CScript launching JSE (JavaScript Script Engine) files (dropper delivery)

**False positives:** Legitimate screen saver executables exist in `%SystemRoot%\System32\` — filter on process path. VS Code Remote Tunneling and `cloudflared` are often used legitimately by developers; correlate with other indicators.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Command and Control |
| Tactic ID | TA0011 |
| Technique | Application Layer Protocol: Web Protocols |
| Technique ID | T1071.001 |
| Secondary Tactic | Execution |
| Secondary Technique | User Execution: Malicious File |
| Secondary ID | T1204.002 |
| Tertiary Tactic | Defense Evasion |
| Tertiary Technique | Process Injection |
| Tertiary ID | T1055 |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Command & Control |
| Exploitation |

## Splunk Detection Query

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Network_Resolution.DNS
where DNS.query IN (
    "load.auraria.org",
    "opedromos1.r-e.kr",
    "morames.r-e.kr",
    "load.ssangyongcne.o-r.kr",
    "load.yju.o-r.kr",
    "attach.docucloud.o-r.kr",
    "load.supershop.o-r.kr",
    "load.erasecloud.n-e.kr",
    "pyrotech.co.kr",
    "newjo-imd.com",
    "yespp.co.kr"
    )
by DNS.src DNS.query DNS.answer
| `drop_dm_object_name(DNS)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=95
| table firstTime lastTime src query answer risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| DNS resolution of any known Kimsuky HttpTroy / httpMalice C2 domain | 95 | Direct IOC match — confirmed Kimsuky infrastructure |
| SCR file executed from `%APPDATA%`, `%TEMP%`, or `Downloads` | 85 | Dropper execution pattern; screen savers should not run from user directories |
| WScript/CScript executing `.jse` or `.vbe` from user directory | 90 | JSE dropper execution — high confidence malicious |
| HTTP POST from non-browser process to `.r-e.kr` / `.o-r.kr` / `.n-e.kr` subdomains | 80 | Matches httpMalice hacked Korean site C2 pattern |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| Kimsuky (Velvet Chollima, APT43, Thallium) | [MITRE ATT&CK — G0094 Kimsuky](https://attack.mitre.org/groups/G0094/) |
| Kimsuky — PebbleDash cluster | [Kaspersky Securelist — New PebbleDash-based tools by Kimsuky (2026-05-15)](https://securelist.com/kimsuky-appleseed-pebbledash-campaigns/119785/) |

## References

- [Kaspersky Securelist — Disclosing new PebbleDash-based tools by Kimsuky (2026-05-15)](https://securelist.com/kimsuky-appleseed-pebbledash-campaigns/119785/)
- [Gen Digital — DPRK's Playbook: Kimsuky's HttpTroy and Lazarus's New BLINDINGCAN Variant](https://www.gendigital.com/blog/insights/research/dprk-kimsuky-lazarus-analysis)
- [CISA — North Korean Threat Actor Kimsuky](https://www.cisa.gov/news-events/cybersecurity-advisories/aa20-301a)
- [MITRE ATT&CK — G0094 Kimsuky](https://attack.mitre.org/groups/G0094/)
- [MITRE ATT&CK — T1071.001 Application Layer Protocol: Web Protocols](https://attack.mitre.org/techniques/T1071/001/)
- [MITRE ATT&CK — T1055 Process Injection](https://attack.mitre.org/techniques/T1055/)
