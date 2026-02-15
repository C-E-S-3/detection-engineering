# Command and Control Detections

**MITRE ATT&CK Tactic:** [Command and Control (TA0011)](https://attack.mitre.org/tactics/TA0011/)
**Kill Chain Phase:** Command & Control (C2)

Detections for techniques adversaries use to communicate with compromised systems, including HTTPS beaconing, DNS-based C2, domain generation algorithms, and traffic to compromised infrastructure.

---

## Detections

| Detection | MITRE Technique | Description |
|-----------|----------------|-------------|
| [Gootloader HTTPS Beaconing](gootloader_https_beaconing.md) | T1071.001, T1573.002 | Low-jitter repeated outbound connections indicating C2 beaconing |
| [Gootloader Suspicious DNS](gootloader_suspicious_dns.md) | T1071.004 | DNS queries to domains with high entropy, excessive length, or digit patterns |
| [Gootloader WordPress C2](gootloader_wordpress_c2.md) | T1071.001 | HTTP POST requests to WordPress URI paths from non-browser processes |
| [Lazarus C2 Beaconing](lazarus_c2_beaconing.md) | T1071, T1573 | DNS-based beaconing with statistical anomaly detection |
| [Lazarus DGA Detection](lazarus_dga_detection.md) | T1568.002 | Domain generation algorithm detection via lexical analysis |
| [Lazarus Suspicious Outbound Traffic](lazarus_suspicious_outbound.md) | T1071, T1048 | High-volume outbound traffic to many unique destinations |

---

## Threat Actors

| Actor | Type | TTPs | References |
|-------|------|------|-----------|
| Gootloader / UNC2565 | Malware Loader | HTTPS C2 to compromised WordPress sites, beaconing patterns with low jitter | [MITRE - Gootloader (S1138)](https://attack.mitre.org/software/S1138/) |
| Lazarus Group (HIDDEN COBRA) | Nation-State APT (DPRK) | Custom C2 protocols, DGA domains, DNS tunneling, high-volume exfiltration | [MITRE - Lazarus Group (G0032)](https://attack.mitre.org/groups/G0032/), [Kaspersky - Lazarus Under the Hood](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2018/03/07180244/Lazarus_Under_The_Hood_PDF_final.pdf) |
