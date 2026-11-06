# CWPdoor: Passive Linux Backdoor in Trojanized CWP (Control Web Panel) Server Binary

**Date Added:** 2026-11-05
**Source:** The Hacker News / CISA / Independent Research
**Severity:** High
**Status:** Active

---

## Summary

Researchers discovered a backdoored version of `cwpsrv`, the core web server binary of Control Web Panel
(CWP, formerly CentOS Web Panel), a widely deployed Linux server management panel with over 340,000 publicly
exposed instances. The backdoored binaries (versions 1.15.10 and 1.24.0) contain a passive implant dubbed
**CWPdoor** that remains dormant until it receives a specially crafted HTTP request. The backdoor implements
AES-256-CBC encrypted commands hidden in HTTP headers, suppresses its own log entries, and achieves zero
detections on VirusTotal at time of disclosure. Infrastructure overlaps with the Ebury SSH botnet ecosystem
suggest a sophisticated actor with prior Linux hosting-panel targeting experience.

---

## Threat Actor

**Name:** Unknown; infrastructure linked to Ebury botnet ecosystem
**Type:** Espionage / Persistent Access (suspected nation-state or sophisticated eCrime)
**Attribution confidence:** Low — Ebury infrastructure overlap noted; no confirmed group attribution
**Prior activity:** Ebury botnet has targeted hosting providers and Linux servers since ~2009

---

## Attack Chain

1. **Initial delivery:** Victim administrators are social-engineered or misled into downloading the backdoored
   `cwpsrv` binary from `136.0[.]141[.]71` via a fake updater script (`cwpsrv_update.sh`).
   - Fake updater SHA256 (MD5): `e505d4ffa21cf494a5dc2d7c8f4f1236`

2. **Installation:** The updater replaces the legitimate `cwpsrv` binary in-place. Backdoored versions
   confirmed:
   - cwpsrv 1.15.10 (MD5: `965aea67fb40de1bab5169ada993349f`)
   - cwpsrv 1.24.0 (MD5: `d3f4e95113d49ab3991b45e457bda75b`)

3. **Dormancy:** The backdoor remains completely passive — no outbound connections, no listening ports beyond
   normal CWP operations — until triggered.

4. **Activation:** A specially crafted HTTP request to any CWP endpoint activates the backdoor. Trigger
   criteria:
   - HTTP request must arrive within a 300-second timestamp window (replay protection)
   - Request must carry a valid cryptographic signature
   - Command payload is AES-256-CBC encrypted in an HTTP header field

5. **Log suppression:** CWPdoor patches the CWP access log handler to silently drop its own trigger requests,
   preventing forensic discovery via standard web server log review.

6. **C2 socket:** An internal Unix domain socket (`ngx_http_integrity_helper`) is created for the backdoor
   module to communicate with the main cwpsrv process, mirroring the naming convention of legitimate nginx
   helper sockets to blend in.

---

## MITRE ATT&CK Mapping

| Technique | ID | Description |
|-----------|----|-------------|
| Compromise Host Software Binary | T1554 | Legitimate cwpsrv binary replaced with backdoored version |
| Indicator Removal: Clear Command History | T1070.003 | Log suppression hides trigger requests from access logs |
| Masquerading | T1036 | Socket named `ngx_http_integrity_helper` mimics legitimate nginx internals |
| Deobfuscate/Decode Files or Information | T1140 | AES-256-CBC encrypted commands decoded at runtime |
| Ingress Tool Transfer | T1105 | cwpsrv_update.sh fetches backdoored binary from attacker server |
| Encrypted Channel | T1573 | AES-256-CBC command encryption in HTTP headers |

**Primary Tactic:** Defense Evasion (TA0005)
**Secondary Tactics:** Persistence (TA0003), Command and Control (TA0011)

---

## Kill Chain Phase

**Installation** → **C2** → **Actions on Objectives**

---

## Indicators of Compromise

### IP Addresses

| Indicator | Context |
|-----------|---------|
| `136.0[.]141[.]71` | CWPdoor download server — hosts `/static/cwpsrv_update.sh` and `/static/cwpsrv_1.15.10` |

### File Hashes (MD5)

| Hash | Description |
|------|-------------|
| `e505d4ffa21cf494a5dc2d7c8f4f1236` | cwpsrv_update.sh — fake updater / installer script |
| `965aea67fb40de1bab5169ada993349f` | cwpsrv 1.15.10 — backdoored binary |
| `d3f4e95113d49ab3991b45e457bda75b` | cwpsrv 1.24.0 — backdoored binary |

### Behavioral / Host Indicators

| Indicator | Type |
|-----------|------|
| String `X-Ngx-Integrity` present in cwpsrv binary | Static binary indicator |
| Unix socket `ngx_http_integrity_helper` present on filesystem | Runtime indicator |
| `cwpsrv` binary modified time newer than expected for installed CWP version | Integrity indicator |
| `cwpsrv` binary hash does not match vendor-signed package | Integrity indicator |
| Access logs missing entries for specific time ranges (log suppression) | Forensic indicator |

### Download URLs

| URL | Context |
|-----|---------|
| `hxxp://136.0[.]141[.]71/static/cwpsrv_update.sh` | Fake updater script |
| `hxxp://136.0[.]141[.]71/static/cwpsrv_1.15.10` | Backdoored cwpsrv 1.15.10 binary |

---

## Detection Opportunities

1. **File integrity:** Monitor `cwpsrv` binary hash against known-good vendor hashes; alert on unexpected
   modification time changes.
2. **Network:** Alert on outbound connections from CWP servers to `136.0.141.71`.
3. **Process:** Detect `wget` or `curl` downloading `cwpsrv_update.sh` from external IPs to CWP directories.
4. **Static:** Scan cwpsrv binary for the string `X-Ngx-Integrity` using YARA.
5. **Host:** Alert on creation of Unix socket `ngx_http_integrity_helper` on CWP servers.
6. **Log anomaly:** Alert when CWP access logs have unexpected time gaps or zero-byte entries.

See: `detections/defense_evasion/cwpdoor_trojanized_cwpsrv_binary.md`

---

## Affected Versions

- CWP (Control Web Panel) versions using cwpsrv 1.15.10 and 1.24.0
- 340,000+ publicly exposed CWP instances at risk
- Zero VirusTotal detections at time of initial disclosure (2026-11-05)

---

## References

- [The Hacker News — Hackers Hide Linux Backdoor in Control Web Panel cwpsrv Binary](https://thehackernews.com/2026/11/hackers-hide-linux-backdoor-in-control.html)
- [MITRE ATT&CK — T1554: Compromise Host Software Binary](https://attack.mitre.org/techniques/T1554/)
- [MITRE ATT&CK — T1070.003: Indicator Removal: Clear Command History](https://attack.mitre.org/techniques/T1070/003/)
- [Ebury Botnet — ESET Research](https://www.welivesecurity.com/en/eset-research/ebury-is-alive-but-unseen-400k-linux-servers-compromised-for-cryptocurrency-theft-and-financial-gain/)
