# Collection Detections

**MITRE ATT&CK Tactic:** [Collection (TA0009)](https://attack.mitre.org/tactics/TA0009/)
**Kill Chain Phase:** Actions on Objectives

Detections for techniques adversaries use to gather data of interest from target systems, including cryptocurrency wallet access, data staging, and automated collection.

---

## Detections

| Detection | MITRE Technique | Description |
|-----------|----------------|-------------|
| [Lazarus Cryptocurrency Access](lazarus_cryptocurrency_access.md) | T1005, T1119 | DNS queries and process activity targeting cryptocurrency wallets and exchanges |
| [Credential and Secrets Harvesting](credential_and_secrets_harvesting.md) | T1005, T1552.001, T1552.007 | Automated collection of SSH keys, cloud tokens (AWS/GCP/Azure), Kubernetes service account tokens, Docker credentials, and .env files by non-standard processes |
| [UNC6671 O365 SharePoint Bulk Scripting Exfiltration](unc6671_o365_sharepoint_bulk_scripting_exfil.md) | T1530, T1213.002, T1567.002 | High-volume SharePoint FileAccessed/FileDownloaded events via scripting user agents (python-requests, PowerShell) from unmanaged devices; spoofed MS Office ClientAppId with scripting UA indicates stolen session cookie reuse |
| [Silent Ransom Group Rclone and WinSCP Data Exfiltration](silent_ransom_group_rclone_winscp_data_theft.md) | T1074.001, T1048.002, T1219 | Rclone/WinSCP exfiltration and unauthorized remote access tool (Zoho Assist, AnyDesk, Splashtop, Syncro, Atera) installation; covers SRG/Luna Moth law firm targeting campaign (FBI Flash May 2026, 100+ intrusions) |
| [Windows USB LNK Crypto Clipper Worm with Tor-Based C2](windows_usb_lnk_crypto_clipper_worm_tor_c2.md) | T1115, T1091, T1090.003 | USB .lnk worm deploys bundled Tor client for C2; polls clipboard every 500ms to replace BTC/ETH wallet addresses and BIP39 seed phrases; worm propagates via USB; active since February 2026 (Microsoft, June 17 2026) |
| [Icarus / Supply Chain OAuth Token Abuse — Salesforce Bulk CRM Exfiltration](icarus_salesforce_oauth_bulk_api_exfil.md) | T1213, T1078.004 | Detects anomalous bulk Salesforce CRM exfiltration via OAuth tokens from compromised third-party integrations; Python scripting user-agents and >200 API queries per 15-minute window; matches Icarus/ShinyHunters Klue supply chain breach pattern (June 2026) |
| [GoSerpent ThumbcacheService File Collection Artifact](goserpent_thumbcacheservice_file_collection.md) | T1560.001, T1090, T1003 | ThumbcacheService DLL creates password-protected archive at `C:\Users\Public\thumbcache_605a.db`; high-specificity forensic indicator for GoSerpent intrusions targeting SEA government and diplomatic networks; companion detections for Mimikatz credential dumping and Stowaway SOCKS5 C2 routing |

---

## Threat Actors

| Actor | Type | TTPs | References |
|-------|------|------|-----------|
| Lazarus Group (HIDDEN COBRA) | Nation-State APT (DPRK) | Cryptocurrency theft from exchanges and individual wallets, AppleJeus campaign | [MITRE - Lazarus Group (G0032)](https://attack.mitre.org/groups/G0032/), [CISA - AppleJeus](https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-048a), [FBI - TraderTraitor](https://www.ic3.gov/Media/News/2022/220418.pdf) |
| UAT-10608 | Threat Cluster | NEXUS Listener framework exfiltrates SSH keys, cloud tokens, K8s secrets from CVE-2025-55182-compromised hosts | [Cisco Talos - UAT-10608](https://blog.talosintelligence.com/uat-10608-inside-a-large-scale-automated-credential-harvesting-operation-targeting-web-applications/) |
| TeamPCP | Supply Chain Threat Actor | Trivy/Telnyx/Axios supply chain attacks harvest CI/CD credentials from GitHub Actions runners | [CrowdStrike - Trivy Action Supply Chain](https://www.crowdstrike.com/en-us/blog/from-scanner-to-stealer-inside-the-trivy-action-supply-chain-compromise/) |
| UNC5221 | Nation-State APT (China-nexus) | SPAWN ecosystem targets Ivanti VPN appliances to harvest admin credentials and session tokens | [Mandiant - UNC5221 SPAWN](https://www.mandiant.com/resources/blog/suspected-apt-targets-ivanti-zero-day) |
| UNC6671 / BlackFile | Cybercrime (Vishing + AiTM Extortion) | After AiTM credential capture, uses python-requests and Microsoft Graph API to bulk-exfiltrate SharePoint/OneDrive data; pivots from FileDownloaded to FileAccessed events to evade DLP detection; exfiltrated 1M+ files per victim | [Google TI — BlackFile Vishing Operation (2026-05-15)](https://cloud.google.com/blog/topics/threat-intelligence/blackfile-vishing-extortion-operation) |
| Silent Ransom Group (SRG) / Luna Moth / Chatty Spider / UNC3753 | Financially Motivated Cybercrime | Vishing + physical intrusion campaign targeting law firms; uses only legitimate tools (Rclone, WinSCP, Zoho Assist, AnyDesk, Splashtop, Syncro, Atera) for data theft and extortion; 100+ intrusions in 2026; 38+ law firms with data leaked | [FBI Flash FLASH-20260526-01 (2026-05-26)](https://www.ic3.gov/CSA/2026/260526.pdf), [BleepingComputer (2026-05-27)](https://www.bleepingcomputer.com/news/security/fbi-warns-of-silent-ransom-group-in-person-data-theft-attacks/) |
| Icarus extortion group (possibly ShinyHunters / UNC6240) | Financially Motivated Cybercrime | Exploited dormant Klue OAuth integration credential to mass-exfiltrate Salesforce CRM data (Opportunity, Contact, Lead, Account) from hundreds of organizations; Python scripting + Salesforce REST API QueryMore bypass; victims include Huntress, Recorded Future, Tanium, Jamf; active April 2026+ | [Datadog Security Labs (2026-06-22)](https://securitylabs.datadoghq.com/articles/detecting-the-klue-supply-chain-attack-in-salesforce/), [Huntress (2026-06-22)](https://www.huntress.com/blog/klue-breach-investigation) |
| Unnamed China-nexus espionage actor (GoSerpent, 2021–2026) | Nation-State APT (China-nexus) | GoSerpent RAT + McMx + ThumbcacheService DLL + Stowaway SOCKS5 + TmcLoader intrusion framework; targets SEA government agencies, diplomatic missions, and intelligence orgs; active since 2021; C2 infrastructure on Alibaba Cloud and UCLOUD HK; deploys Mimikatz and QuarksDumpLocalHash for credential access; forensic artifact: `C:\Users\Public\thumbcache_605a.db` | [Kaspersky Securelist (2026-07-17)](https://securelist.com/goserpent-backdoor-in-southeast-asia/120687/) |
