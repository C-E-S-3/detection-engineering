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
| [Gremlin Stealer Credential Theft](gremlin_stealer_credential_theft.md) | T1539, T1555.003, T1528, T1115 | C#-based MaaS infostealer harvesting Chromium/Gecko browser credentials, Telegram session files, Steam data, VPN configs, and crypto wallet addresses (clipboard clipping); exfiltrates via Telegram Bot API to `207.244.199[.]46` |
| [UNC6671 AiTM MFA Device Registration Abuse](unc6671_aitm_mfa_device_registration_abuse.md) | T1111, T1556, T1557.002 | Detects attacker-controlled MFA device registration on Okta or Azure AD following vishing-facilitated AiTM credential capture; UNC6671/BlackFile post-access persistence |
| [Tycoon 2FA Post-Compromise Token Abuse](tycoon2fa_device_code_token_abuse.md) | T1550.001, T1528 | Node.js (`node`/`undici`) user-agent in Entra sign-in logs indicating Tycoon2FA operator token-replay automation after device code phishing; supplemental rules for known operator IPs (AS45102) and Trustifi redirect chain |
| [SonicWall SSL-VPN CLI Session Brute Force — CVE-2024-12802 MFA Bypass](sonicwall_vpn_upn_mfa_bypass_brute_force.md) | T1110.001, T1133, T1556 | Detects automated brute-force using `sess="CLI"` session type (no legitimate interactive session uses this value) against SonicWall Gen6 SSL-VPN; CVE-2024-12802 allows MFA bypass via UPN format on insufficiently patched appliances; attributed to Akira ransomware affiliates |
| [Linux /proc Filesystem and Shadow File Credential Dumping](linux_proc_filesystem_credential_dumping.md) | T1003.007, T1003.008 | Linux credential dumping via ptrace PEEK ops, process_vm_readv, /proc/kcore, and /etc/shadow reads by unprivileged users; Wazuh rules 100620-100626 |
| [FortiBleed VPN Credential Brute Force](fortibleed_vpn_credential_brute_force.md) | T1110.001, T1110.003 | SSH/VPN brute force and password spraying patterns consistent with FortiBleed campaign — Russian-speaking group leaked 73,932 FortiGate VPN credentials via 1.16B credential attempts in 194 countries (June 2026) |
| [Azure Entra ROPC Password Spray](azure_entra_ropc_password_spray.md) | T1110.003, T1550.001 | Azure CLI ROPC (legacy OAuth) authentication spray bypassing Conditional Access Policy MFA enforcement; LSHIY LLC campaign June 2026 |
| [FortiOS Diagnostic Sniffer Credential Capture](fortios_diagnostic_sniffer_credential_capture.md) | T1040 | FortiBleed operators abuse built-in `diagnose sniffer packet` CLI command to capture authentication traffic (VPN credentials, NTLM hashes) without dropping any binary; Golang FortigateSniffer tool automates multi-appliance capture; linked to Lynx/INC ransomware credential pipeline |
| [ADFS Token-Signing Key Extraction via Machine DPAPI](adfs_machine_dpapi_signing_key_extraction.md) | T1003, T1552.004, T1550.003 | SYSTEM-level attacker on ADFS host extracts active token-signing private key via Machine DPAPI (`SharpDPAPI /machine`), bypassing WID/DKM-based extraction; enables Golden SAML token forgery for any relying party trust (M365, Entra ID); prerequisite is ADFS "ghost certificate" condition (Event ID 385) |
| [CrashStealer macOS Keychain Credential Theft](crashstealer_macos_keychain_credential_theft.md) | T1555.001, T1005, T1547.011, T1553.002 | DNS/network connections to `werkbit[.]io` (delivery) or `endpoint-api-v1[.]com` (C2 exfil) (risk 95); `codesign` execution touching CrashReporter or LaunchAgents paths (risk 75); LaunchAgent plist creation by non-system processes, especially with CrashReporter in path (risk 90); native C++ macOS infostealer notarized with valid Apple Developer ID; PIN-gated delivery; AES-GCM encrypted Keychain and browser credential exfil via libcurl |
| [ClickLock macOS GUI Input Capture via Browser Kill-Loop](clicklock_macos_gui_input_capture_kill_loop.md) | T1056.002, T1543.001, T1489, T1555.001 | ClickFix-delivered macOS stealer; LaunchAgent (`com.authirity.plist`) kill-loop continuously terminates browsers until victim enters login password in fake auth dialog; Keychain and browser credentials exfiltrated via Telegram Bot API (`com.chromer.plist`); supplemental rules for browser kill-loop volume and non-Telegram `api.telegram.org` connections |

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
| Gremlin Stealer (MaaS — multiple buyers) | Cybercrime (MaaS Infostealer) | C# Windows infostealer sold via Telegram; harvests Chromium/Gecko credentials (Chrome Cookie V20 bypass), Telegram sessions, Steam tokens, VPN/FTP credentials, crypto wallet addresses; .NET resource-file XOR obfuscation; Telegram Bot API exfiltration | [Unit 42 — Gremlin Stealer Evolution (2026-05-15)](https://unit42.paloaltonetworks.com/gremlin-stealer-evolution/) |
| UNC6671 / BlackFile | Cybercrime (Vishing + AiTM Extortion) | Vishing calls impersonating IT helpdesk + real-time AiTM credential/MFA capture → immediate new MFA device registration → bulk M365 cloud data exfiltration → extortion; no malware, pure social engineering + scripting | [Google TI — BlackFile Vishing Operation (2026-05-15)](https://cloud.google.com/blog/topics/threat-intelligence/blackfile-vishing-extortion-operation) |
| Tycoon 2FA Operators (PhaaS) | Cybercrime (PhaaS) | Survived March 2026 coalition takedown; switched to OAuth device code phishing — Trustifi email tracking URL lure → Cloudflare Workers redirect → victim completes MFA on `microsoft.com/devicelogin` → attacker collects refresh tokens; post-compromise token replay via `node`/`undici` automation on Alibaba Cloud AS45102 | [BleepingComputer — Tycoon2FA Device Code (2026-05-17)](https://www.bleepingcomputer.com/news/security/tycoon2fa-hijacks-microsoft-365-accounts-via-device-code-phishing/) |
| Akira Ransomware Group | Ransomware (RaaS) | Exploited CVE-2024-12802 in SonicWall Gen6 SSL-VPN — UPN format authentication bypasses MFA enforcement on incompletely patched appliances; credential brute-force using automated tools fingerprinted by `sess="CLI"` session type; 30–60 minute network sweep and credential reuse playbook preceding ransomware staging | [BleepingComputer — SonicWall VPN MFA Bypass (2026-05-20)](https://www.bleepingcomputer.com/news/security/hackers-bypass-sonicwall-vpn-mfa-due-to-incomplete-patching/) |
| Kali365 (PhaaS operators) | Cybercrime (PhaaS) | Hybrid device code phishing + AiTM proxy platform targeting Microsoft 365; AI-generated lures impersonate Adobe Acrobat Sign, DocuSign, SharePoint; device code OAuth flow abuse silently captures M365 access/refresh tokens while victim completes MFA on legitimate Microsoft portal; AiTM proxy intercepts live session cookies; tokens replayed from Cloudflare Workers / Alibaba Cloud AS45102 infrastructure; FBI IC3 PSA260521 May 21 2026; IOC: kali365[.]xyz | [FBI IC3 — PSA260521 (2026-05-21)](https://www.ic3.gov/PSA/2026/PSA260521), [Security Boulevard — Kali365 Analysis (2026-06)](https://securityboulevard.com/2026/06/kali365-the-new-phishing-kit-hijacking-microsoft-365-tokens/) |
| LSHIY LLC (AS32167 / AS955) | Cybercrime (Credential Spray Infrastructure) | Operated 81M+ Azure CLI ROPC password spray attempts (June 12–26 2026) against 64+ organizations, compromising 78 accounts; exploited Conditional Access Policy gap — ROPC flow bypasses CAP MFA enforcement for interactive sign-ins; sourced from IPv6 CIDR `2a0a:d683::/32`; credential source: previously breached combo lists | [Huntress — LSHIY ROPC Password Spray (2026-07-01)](https://www.huntress.com/blog/lshiy-password-spray-attack) |
| FortiBleed Operators / Lynx Ransomware / INC Ransom | Cybercrime (Credential Supply Pipeline + Ransomware) | Russian-speaking ~20-person operation; weaponizes FortiOS built-in `diagnose sniffer packet` via Golang FortigateSniffer tool to harvest VPN credentials and NTLM hashes without binary deployment; cracks hashes with Hashtopolis/Hashcat GPU cluster; supplies credentials to Lynx and INC ransomware affiliates; active 07:00–18:00 MSK (UTC+3) | [BleepingComputer — FortiBleed Lynx Link (2026-07-02)](https://www.bleepingcomputer.com/news/security/fortibleed-credential-theft-campaign-linked-to-lynx-ransomware/) |
| COZY BEAR / APT29 (SVR) | Nation-State APT (Russia) | Pioneered Golden SAML in SolarWinds supply chain attack; used forged SAML tokens to access federated Microsoft 365 and cloud environments without credentials; ADFS Machine DPAPI technique extends this attack path | [MITRE ATT&CK G0016](https://attack.mitre.org/groups/G0016/), [T1550.003 — Golden SAML](https://attack.mitre.org/techniques/T1550/003/) |
| CrashStealer (Unknown Actor) | Cybercrime / Espionage (macOS Infostealer) | Native C++ macOS Keychain and browser credential stealer; notarized with Apple Developer ID Emil Grigorov (WWB7JA7AQV); PIN-gated delivery via `werkbit[.]io` indicates targeted distribution; copies self to CrashReporter-mimicking path, re-signs with `codesign`, persists via LaunchAgent; AES-GCM encrypted exfiltration via libcurl to `endpoint-api-v1[.]com`; RSA public key fetched from GitHub (`mgothiclove/pkeys`) for key encapsulation; first disclosed July 2026 | [Jamf Threat Labs — CrashStealer (2026-07-13)](https://www.jamf.com/blog/crashstealer-macos-infostealer/), [BleepingComputer (2026-07-13)](https://www.bleepingcomputer.com/news/security/new-crashstealer-macos-malware-steals-passwords-using-fake-crashreporter/) |
| ClickLock Operators (Unknown) | Cybercrime (macOS Infostealer) | ClickFix-delivered macOS infostealer; novel kill-loop LaunchAgent (`com.authirity.plist`) continuously terminates browsers until victim enters login password into spoofed dialog; harvests macOS Keychain and Chromium/Firefox credentials; exfiltrates via Telegram Bot API; distribution via compromised websites serving fake CAPTCHA pages; first disclosed July 2026 | [Group-IB — ClickLock macOS Stealer (2026-07-16)](https://www.group-ib.com/blog/clicklock-stealer-macos-malware/) |

---

## Prerequisites

To use these Kerberos detections, the following audit policies must be enabled on **all Domain Controllers**:

1. **Audit Kerberos Authentication Service** (Success/Failure) - generates Event ID 4768 and 4771
2. **Audit Kerberos Service Ticket Operations** (Success/Failure) - generates Event ID 4769 and 4770

Configured under: `Computer Configuration > Policies > Windows Settings > Security Settings > Advanced Audit Policy Configuration > Account Logon`

## Data Source

All detections in this category use the `` `wineventlog_security` `` source macro for Windows Security Event Log data from Domain Controllers.
