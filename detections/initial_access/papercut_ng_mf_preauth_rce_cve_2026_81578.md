# PaperCut NG/MF Pre-Authentication RCE (CVE-2026-81578 / CVE-2026-82078)

## Description

Detects exploitation of the two-CVE pre-authentication RCE chain in PaperCut NG/MF print management software:

- **CVE-2026-81578** (CVSS 8.8): Authentication bypass in the PaperCut Application Server web management interface. An unauthenticated remote attacker can reach administrative functions on TCP 9191/9192 before access validation completes.
- **CVE-2026-82078** (CVSS 9.4): Unsafe dynamic Java class loading in database connection utilities. PaperCut loads DB driver classes from configurable names without allowlist enforcement; an attacker who can write configuration values (via the auth bypass) can supply a malicious Java class path to achieve arbitrary code execution.

Active exploitation was confirmed by PaperCut on August 27, 2026. Java-based reconnaissance payloads were observed executing as the PaperCut service user. Emergency patches were released August 28, 2026.

**Primary signal:** Child processes spawned by `pc-app` or `pcmf-app` (the PaperCut Application Server) — specifically shell interpreters, download tools, or scripting engines. This is a high-confidence exploitation indicator; PaperCut's application server does not legitimately spawn shells or `curl`/`wget` in normal operation.

**False positives:** PaperCut integrations that invoke Java sub-processes may generate low-confidence matches on the `java`/`javaw` branch. Filter by known PaperCut integration paths (e.g., `PaperCut-branded jar files`) to reduce noise. The HTTP POST detection may match internal administrative tooling polling PaperCut management ports from privileged subnets — tune with known-good source IP exclusions.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Initial Access |
| Tactic ID | TA0001 |
| Technique | Exploit Public-Facing Application |
| Technique ID | T1190 |

**Secondary techniques:** T1505.003 (Web Shell — expected post-exploitation pattern), T1082 (System Information Discovery — observed recon payloads), T1105 (Ingress Tool Transfer — expected dropper stage)

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Exploitation |

## Splunk Detection Query

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Processes
where Processes.parent_process_name IN ("pc-app", "pc-app.exe", "pcmf-app", "pcmf-app.exe")
  AND Processes.process_name IN (
    "sh", "bash", "dash", "zsh", "ksh", "ash",
    "cmd.exe", "powershell.exe", "pwsh.exe",
    "curl", "wget", "python", "python3", "perl", "ruby",
    "nc", "ncat", "netcat", "xmrig", "minerd",
    "java", "javaw", "javaw.exe")
by Processes.dest Processes.user Processes.parent_process_name
   Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    process_name IN ("nc", "ncat", "netcat", "xmrig", "minerd"), 95,
    process_name IN ("powershell.exe", "pwsh.exe", "cmd.exe") AND match(process, "(?i)iex|downloadstring|webclient|invoke|http|bypass"), 95,
    process_name IN ("curl", "wget") AND match(process, "http"), 90,
    process_name IN ("sh", "bash", "dash", "zsh", "ksh", "ash"), 85,
    process_name IN ("python", "python3", "perl", "ruby"), 80,
    process_name IN ("java", "javaw", "javaw.exe") AND NOT match(process, "(?i)papercut|pcmf"), 75,
    1=1, 70)
| where risk_score >= 70
| table firstTime lastTime dest user parent_process_name process_name process process_id risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| PaperCut spawning reverse-shell tools (`nc`, `ncat`, `netcat`) or miners (`xmrig`, `minerd`) | 95 | Near-certain exploitation; these processes have no legitimate PaperCut use |
| PaperCut spawning PowerShell/cmd with download or execution cradle keywords | 95 | Classic post-exploitation dropper invocation pattern |
| PaperCut spawning `curl` or `wget` making HTTP requests | 90 | Fetching secondary payload from attacker infrastructure |
| PaperCut spawning any Unix shell (`sh`, `bash`, `dash`, etc.) | 85 | Shell spawning from Java app server is abnormal; direct exploitation indicator |
| PaperCut spawning scripting interpreters (`python`, `perl`, `ruby`) | 80 | Scripting engines used for post-exploitation tooling |
| PaperCut spawning `java`/`javaw` not referencing PaperCut paths | 75 | Possible dynamic class loading exploitation (CVE-2026-82078); verify against known-good integration processes |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| Cl0p Ransomware | Exploited prior PaperCut RCE (CVE-2023-27350) within days of disclosure; [BleepingComputer 2023-04-27](https://www.bleepingcomputer.com/news/security/clop-ransomware-gang-begins-extorting-papercut-server-hack-victims/) |
| LockBit Ransomware | Exploited CVE-2023-27350; large-scale targeting of university and enterprise PaperCut instances; [MITRE ATT&CK G0032](https://attack.mitre.org/groups/G0032/) |
| Bl00dy Ransomware Gang | CISA advisory confirmed Bl00dy exploitation of CVE-2023-27350 against US K-12 schools; [CISA Alert AA23-131A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-131a) |
| Unknown (August 2026 campaign actors) | Active exploitation confirmed; no attribution yet; ransomware affiliates and IABs considered most likely based on prior targeting patterns |

## References

- [PaperCut Security Bulletin — August 2026](https://www.papercut.com/kb/Main/SecurityBulletinAugust2026)
- [BleepingComputer — PaperCut Patches Critical Pre-Auth RCE Flaws (2026-08-28)](https://www.bleepingcomputer.com/news/security/papercut-patches-critical-pre-authentication-rce-vulnerabilities/)
- [The Hacker News — Critical PaperCut Flaws Exploited (2026-08-28)](https://thehackernews.com/2026/08/critical-papercut-flaws-exploited-in-the-wild.html)
- [NVD — CVE-2026-81578](https://nvd.nist.gov/vuln/detail/CVE-2026-81578)
- [NVD — CVE-2026-82078](https://nvd.nist.gov/vuln/detail/CVE-2026-82078)
- [MITRE ATT&CK — T1190: Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
- [threat-intel/2026-08-28_papercut-ng-mf-cve-2026-81578-82078-preauth-rce.md](../../threat-intel/2026-08-28_papercut-ng-mf-cve-2026-81578-82078-preauth-rce.md)
- [CISA KEV Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [CISA Alert AA23-131A — Bl00dy Ransomware Gang Exploiting PaperCut](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-131a)
