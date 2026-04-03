# Credential Access Detections

**MITRE ATT&CK Tactic:** [Credential Access (TA0006)](https://attack.mitre.org/tactics/TA0006/)
**Kill Chain Phase:** Actions on Objectives

Detections for techniques adversaries use to steal credentials, including Kerberos ticket abuse, credential dumping, brute force, and certificate exploitation. The Kerberos detections focus on identifying offensive tool fingerprints (Rubeus, Impacket, Mimikatz, Metasploit), encryption downgrades, and anomalous authentication patterns in Active Directory environments.

---

## Detections

| Detection | MITRE Technique | Description |
|-----------|----------------|-------------|
| [Suspicious TGT - Tool Fingerprint](kerberos_suspicious_tgt_tool_fingerprint.md) | T1558 | TGT requests with TicketOptions matching Rubeus, Impacket, Certipy, Whisker (missing Canonicalize flag) |
| [Suspicious TGT - Metasploit](kerberos_metasploit_tgt_fingerprint.md) | T1558 | TGT requests with Metasploit-specific TicketOptions (`0x50800000` with Proxiable flag) |
| [TGT Missing Canonicalize - Bitwise](kerberos_tgt_missing_canonicalize.md) | T1558 | Generic bitwise detection for any TGT missing the Canonicalize flag, catches novel tools |
| [Kerberoasting - RC4 TGS](kerberos_tgs_rc4_kerberoasting.md) | T1558.003 | TGS requests with RC4 encryption targeting service accounts with SPNs |
| [Kerberoasting - Anomalous Volume](kerberos_anomalous_tgs_volume.md) | T1558.003 | Statistical detection of unusual TGS request volume (3-sigma rule) |
| [AS-REP Roasting](kerberos_asrep_roasting.md) | T1558.004 | TGT requests for accounts without pre-authentication, especially with RC4/DES |
| [AS-REP Roasting - High Volume](kerberos_asrep_roasting_high_volume.md) | T1558.004 | Single source targeting multiple accounts without pre-auth in rapid succession |
| [OverPass-the-Hash](kerberos_overpass_the_hash.md) | T1550.002 | TGT requests using RC4 encryption indicating stolen NTLM hash usage |
| [Golden Ticket](kerberos_golden_ticket_weak_encryption.md) | T1558.001 | TGT requests with deprecated encryption (DES/RC4) indicating forged tickets |
| [Silver Ticket](kerberos_silver_ticket_no_tgt.md) | T1558.002 | TGS requests without a preceding TGT, indicating forged service tickets |
| [Pre-Auth Brute Force](kerberos_preauth_brute_force.md) | T1110.003 | High volume of Kerberos pre-authentication failures indicating password spraying |
| [ADCS Certificate Abuse](kerberos_adcs_certificate_abuse.md) | T1649 | Certificate-based TGT with tool-fingerprinted TicketOptions (Certipy/Certify) |
| [Rare TicketOptions Hunting](kerberos_rare_ticketoptions_hunting.md) | T1558 | Hunting query to discover novel tool signatures via rare TicketOptions values |
| [DES Encryption Downgrade](kerberos_des_encryption_downgrade.md) | T1558 | Any Kerberos request using deprecated DES encryption |
| [EvilTokens OAuth Device Code Phishing](eviltokens_oauth_device_code_phishing.md) | T1550.001 | OAuth 2.0 device authorization flow abuse for Microsoft account token theft; anomalous device code grants and token reuse |

---

## Threat Actors

| Actor | Type | TTPs | References |
|-------|------|------|-----------|
| Lazarus Group (HIDDEN COBRA) | Nation-State APT (DPRK) | Credential dumping, Mimikatz, pass-the-hash | [MITRE - Lazarus Group (G0032)](https://attack.mitre.org/groups/G0032/) |
| Medusa Ransomware | Ransomware Operator | comsvcs.dll MiniDump for LSASS credential extraction | [CISA - StopRansomware: Medusa](https://www.cisa.gov/news-events/cybersecurity-advisories/aa25-071a) |
| Any adversary using Rubeus | Offensive Tool | Kerberoasting, AS-REP Roasting, OverPass-the-Hash, Golden/Silver Ticket, ADCS abuse | [GhostPack - Rubeus](https://github.com/GhostPack/Rubeus) |
| Any adversary using Impacket | Offensive Tool | Kerberoasting (GetUserSPNs.py), AS-REP Roasting (GetNPUsers.py), ticket forging (ticketer.py) | [Impacket](https://github.com/fortra/impacket) |
| Any adversary using Mimikatz | Offensive Tool | Golden Ticket, Silver Ticket, OverPass-the-Hash, credential dumping | [Mimikatz](https://github.com/gentilkiwi/mimikatz) |
| Any adversary using Metasploit | Offensive Framework | Kerberos client module with unique TicketOptions fingerprint | [Metasploit Framework](https://www.metasploit.com/) |
| Any adversary using Certipy | Offensive Tool | ADCS exploitation (ESC1-ESC8), certificate-based TGT abuse | [Certipy](https://github.com/ly4k/Certipy) |
| EvilTokens (PhaaS) / Storm-237 / ShinyHunters | Cybercrime (PhaaS) | OAuth 2.0 device code phishing to steal Microsoft access/refresh tokens without credentials | [BleepingComputer - EvilTokens](https://www.bleepingcomputer.com/news/security/new-eviltokens-service-fuels-microsoft-device-code-phishing-attacks/) |

---

## Prerequisites

To use these Kerberos detections, the following audit policies must be enabled on **all Domain Controllers**:

1. **Audit Kerberos Authentication Service** (Success/Failure) - generates Event ID 4768 and 4771
2. **Audit Kerberos Service Ticket Operations** (Success/Failure) - generates Event ID 4769 and 4770

Configured under: `Computer Configuration > Policies > Windows Settings > Security Settings > Advanced Audit Policy Configuration > Account Logon`

## Data Source

All detections in this category use the `` `wineventlog_security` `` source macro for Windows Security Event Log data from Domain Controllers.
