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
| [Godloader Legitimate Web Service Payload Delivery](godloader_webservice_payload_delivery.md) | T1102.002, T1105 | Non-browser payload downloads from Bitbucket, GitHub, and Pastebin |
| [CrystalRAT WebSocket C2 Communication](crystalrat_websocket_c2.md) | T1071.001, T1573 | High-volume WebSocket egress for keylogging/clipboard hijacking C2; ChaCha20-encrypted payloads |
| [Havoc C2 Framework Beaconing](havoc_c2_framework_beaconing.md) | T1071.001, T1055 | Havoc Demon agent HTTPS beaconing, default User-Agent/certificate fingerprints, TrueChaos UAC bypass |
| [Turla Kazuar P2P Botnet C2](turla_kazuar_p2p_botnet_c2.md) | T1090, T1071.001, T1071.003, T1008 | Secret Blizzard modular P2P botnet; Kernel leader election, Bridge EWS/HTTP exfiltration, Worker keylogging/screen capture; PowerShell profile persistence and AMSI/ETW bypass |
| [DNS TXT Record Data Exfiltration](dns_txt_record_data_exfiltration.md) | T1071.004, T1048 | High-entropy or high-volume DNS TXT queries indicating DNS tunneling; node-ipc supply chain attack exfil pattern (bt.node.js zone, xh/xd/xf label prefixes) |
| [Kimsuky HttpTroy HTTP C2 Beaconing](kimsuky_httptroy_http_c2_beaconing.md) | T1071.001, T1204.002, T1055 | Kimsuky PebbleDash cluster; HttpTroy DLL C2 via HTTP POST; httpMalice via compromised Korean websites; JSE/SCR dropper execution patterns |

---

## Threat Actors

| Actor | Type | TTPs | References |
|-------|------|------|-----------|
| Gootloader / UNC2565 | Malware Loader | HTTPS C2 to compromised WordPress sites, beaconing patterns with low jitter | [MITRE - Gootloader (S1138)](https://attack.mitre.org/software/S1138/) |
| Godloader / GodLoader (Stargazer Goblin) | Malware Loader | Payload delivery via Bitbucket repos, mining config from Pastebin, distribution via fake GitHub repos (Stargazers Ghost Network) | [Check Point - Gaming Engines: An Undetected Playground](https://research.checkpoint.com/2024/gaming-engines-an-undetected-playground-for-malware-loaders/), [Check Point - Stargazers Ghost Network](https://research.checkpoint.com/2024/stargazers-ghost-network/) |
| Lazarus Group (HIDDEN COBRA) | Nation-State APT (DPRK) | Custom C2 protocols, DGA domains, DNS tunneling, high-volume exfiltration | [MITRE - Lazarus Group (G0032)](https://attack.mitre.org/groups/G0032/), [Kaspersky - Lazarus Under the Hood](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2018/03/07180244/Lazarus_Under_The_Hood_PDF_final.pdf) |
| CrystalRAT (CrystalX RAT) | MaaS RAT | WebSocket C2 with ChaCha20 encryption; real-time keystroke streaming, clipboard hijacking (crypto wallet replacement), screen/audio capture | [BleepingComputer - CrystalRAT](https://www.bleepingcomputer.com/news/security/new-crystalrat-malware-adds-rat-stealer-and-prankware-features/) |
| Amaranth Dragon (TrueChaos) | Nation-State APT (China-nexus) | Havoc C2 framework via CVE-2026-3502 TrueConf exploitation; hosted on Alibaba Cloud/Tencent; targets SE Asian government entities | [BleepingComputer - TrueChaos](https://www.bleepingcomputer.com/news/security/hackers-exploit-trueconf-zero-day-to-push-malicious-software-updates/) |
| Secret Blizzard (Turla / VENOMOUS BEAR / Uroburos) | Nation-State APT (Russia FSB Center 16) | Kazuar modular P2P botnet: Kernel leader election reduces network footprint; Bridge module uses HTTP/WSS/EWS for C2; Worker module conducts keylogging, screen capture, file harvesting, MAPI email monitoring; Pelmeni dropper delivers host-bound encrypted payload | [MITRE ATT&CK G0010 — Turla](https://attack.mitre.org/groups/G0010/), [Microsoft — Kazuar Anatomy (2026-05-14)](https://www.microsoft.com/en-us/security/blog/2026/05/14/kazuar-anatomy-of-a-nation-state-botnet/) |
| Unknown (node-ipc supply chain actor, May 2026) | Supply Chain Threat Actor | Expired npm maintainer email domain hijack; DNS TXT tunneling exfiltration via bt.node.js zone; targets developer credentials, SSH keys, cloud tokens, and AI API keys at CI/CD pipeline scale | [Socket.dev — node-ipc Compromise](https://socket.dev/blog/node-ipc-package-compromised) |
| Kimsuky (Velvet Chollima, APT43) | Nation-State APT (DPRK) | PebbleDash cluster: httpMalice via compromised Korean websites + Dropbox C2; HttpTroy DLL via HTTP POST; MemLoad in-memory injector; JSE/SCR droppers via spearphishing; VS Code Tunnel and Cloudflare Tunnel for C2 evasion; targets South Korean defense and government | [MITRE ATT&CK G0094 — Kimsuky](https://attack.mitre.org/groups/G0094/), [Kaspersky Securelist — PebbleDash tools (2026-05-15)](https://securelist.com/kimsuky-appleseed-pebbledash-campaigns/119785/) |
