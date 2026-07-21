---
scraped_at: 2026-07-20T00:00:00Z
source_url: https://expel.com/blog/introducing-cylindricalcanine/
report_type: threat-intel
severity: critical
title: "CylindricalCanine / GoldenEyeDog: DigiCert Code-Signing Certificate Theft and Golden Gh0st RAT WebSocket C2"
---

## 1. IOCs

### Domains (C2)

| Indicator | Type | Description |
|-----------|------|-------------|
| `uu.goldeyeuu[.]io` | Domain | Golden Gh0st RAT C2; WebSocket (unencrypted channel) on TCP 5188; attributed to CylindricalCanine/GoldenEyeDog |
| `api.keensie[.]com` | Domain | Golden Gh0st RAT C2; encrypted channel on TCP 5198; attributed to CylindricalCanine/GoldenEyeDog |

### File Hashes

| Indicator | Type | Description |
|-----------|------|-------------|
| `81e276aaa3eb9b3f595663c316b3c6414cc3dde5e6cc3a82856b7276acabb7de` | SHA256 | Golden Gh0st implant observed in the wild; first seen April 12, 2026; signed with DigiCert-issued certificate stolen in the April 2026 DigiCert breach; per Expel analysis |

---

## 2. MITRE ATT&CK

| Field | Value |
|-------|-------|
| Tactic (Primary) | Command and Control (TA0011) |
| Technique | Application Layer Protocol: Web Protocols (T1071.001) |
| Sub-technique | WebSocket C2 |
| Additional Tactics | Defense Evasion (TA0005) |
| Additional Techniques | Code Signing (T1553.002), Supply Chain Compromise: Compromise Software Supply Chain (T1195.002) |
| Platform | Windows |

---

## 3. Summary

**CylindricalCanine** is a subgroup of the Chinese cybercrime collective **GoldenEyeDog** (also tracked as APT-Q-27, Dragon Breath, Miuuti Group). In **April 2026**, a DigiCert support employee ran a malicious file received through DigiCert's ticketing system, giving CylindricalCanine persistent access to DigiCert's internal certificate issuance infrastructure.

### DigiCert Breach Impact

- **60 code-signing certificates** were stolen.
- **27+ certificates** have been linked to malware specimens in the wild.
- DigiCert has revoked the compromised certificates; Expel's blog details the timeline.

The stolen certificates were used to sign **Golden Gh0st Loader** and **Golden Gh0st RAT** binaries, giving them a veneer of legitimacy and defeating signature-based AV detections at time of use.

### Malware: Golden Gh0st

| Component | Description |
|-----------|-------------|
| **Golden Gh0st Loader** | Initial-stage component; loads and executes the Golden Gh0st RAT; signed with stolen DigiCert certificate |
| **Golden Gh0st RAT** | Full-featured Windows RAT; C2 over WebSocket; two channels: unencrypted WebSocket on TCP 5188 and encrypted channel on TCP 5198 |

### C2 Architecture

Golden Gh0st RAT uses a dual-port WebSocket C2 design:
- **TCP 5188**: Unencrypted WebSocket — command channel
- **TCP 5198**: Encrypted WebSocket — data exfiltration channel

Both channels use domains registered under attacker-controlled infrastructure (`goldeyeuu[.]io` and `keensie[.]com`).

### Attribution

GoldenEyeDog (APT-Q-27 / Dragon Breath / Miuuti Group) is a Chinese-speaking cybercrime and espionage collective. The DigiCert breach was described by Expel as a targeted supply chain intrusion. The Golden Gh0st RAT toolset has previously been attributed to Dragon Breath campaigns targeting online gambling platforms and VPN service users in Southeast Asia.

---

## 4. Detection Notes

- **WebSocket to non-browser processes on ports 5188/5198**: The primary detection opportunity is a Windows process other than a browser establishing an outbound WebSocket connection to `uu.goldeyeuu[.]io` or `api.keensie[.]com` on these non-standard ports.
- **Revoked-certificate code signing**: Endpoint security products that verify certificate revocation should flag the stolen certificates. Ensure OCSP/CRL checking is enabled for code-signing trust chains.
- **Hash IOC**: Block and alert on SHA256 `81e276aaa3eb9b3f595663c316b3c6414cc3dde5e6cc3a82856b7276acabb7de` at endpoint and email gateway.
- **Domain IOCs**: Block `uu.goldeyeuu[.]io` and `api.keensie[.]com` at DNS and firewall.

---

## 5. References

- Expel (2026-07-20): https://expel.com/blog/introducing-cylindricalcanine/
- The Hacker News (2026-07): https://thehackernews.com/2026/07/goldeneyedog-subgroup-linked-to.html
- MITRE ATT&CK — Dragon Breath (APT-Q-27): https://attack.mitre.org/groups/G1071/
- MITRE ATT&CK T1553.002 — Code Signing: https://attack.mitre.org/techniques/T1553/002/
