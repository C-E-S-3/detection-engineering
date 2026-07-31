---
scraped_at: "2026-07-31T08:00:00Z"
source_url: https://www.bleepingcomputer.com/news/security/shinyhunters-claims-brinks-home-breach-threatens-to-leak-stolen-data/
report_type: threat-intel
severity: high
title: "ShinyHunters (UNC6661) Breaches Brinks Home via Entra Vishing and EY via Supply Chain; July 31 Extortion Deadline"
---

# ShinyHunters (UNC6661) Breaches Brinks Home via Entra Vishing and EY via ITSM Supply Chain

ShinyHunters (also tracked as UNC6661) is conducting an active extortion campaign targeting enterprises via voice phishing (vishing) attacks against Microsoft Entra/Azure AD and supply chain compromise of third-party ITSM platforms. July 2026 disclosures involve Brinks Home (1.1M+ Salesforce records) and Ernst & Young (client tax documents). The EY extortion deadline was July 31, 2026.

## 1. IOCs

### Campaign-Wide ShinyHunters IPs (Microsoft Security Blog, July 13, 2026)
IPs observed in connection with Salesforce exfiltration API calls across ShinyHunters victims:

| IP | Observed Activity | Date |
|----|------------------|------|
| `138.226.246.94` | Klue integration Salesforce API calls | June 11, 2026 |
| `212.86.125.24` | ShinyHunters campaign infrastructure | 2026 |
| `213.111.148.90` | ShinyHunters campaign infrastructure | 2026 |
| `94.154.32.160` | ShinyHunters campaign infrastructure | 2026 |

### Supply Chain Salesforce Access Vendors Compromised

| Date | Vendor | Access Gained |
|------|--------|--------------|
| August 2025 | Salesloft Drift | Salesforce connection secrets |
| November 2025 | Gainsight | Persistent Salesforce API access |
| June 2026 | Klue | Salesforce customer instance access |

## 2. Brinks Home Breach

### Timeline
- **July 13, 2026:** Breach via Microsoft Entra vishing
- **July 20, 2026:** Brinks Home detection of intrusion

### Attack Method — Microsoft Entra Vishing
1. ShinyHunters called a Brinks Home employee, impersonating IT support
2. Employee was convinced to complete a Microsoft Entra MFA authentication or device registration step
3. This granted the attacker persistent account access and downstream Salesforce access

### Data Exfiltrated
| Dataset | Volume |
|---------|--------|
| Salesforce "Contacts" object rows (customer data) | 1,100,000+ |
| Employee PII (names, email, job title, phone) | 4,000+ rows |
| Customer support chat logs (Brinks Care Cresta instance) | 3,800,000+ |

### Systems Targeted
- Microsoft Entra (initial access via vishing)
- Salesforce CRM (data exfiltration)
- Cresta (customer care/chat platform)

## 3. Ernst & Young (EY) Breach

### Timeline
- **March 28 to April 12, 2026:** Unauthorized access period (15 days)
- **April 23, 2026:** EY detection of anomalous activity
- **July 2026:** ShinyHunters dark web claim posted
- **July 31, 2026:** Extortion deadline — "release all data" if EY does not negotiate

### Attack Method — Third-Party ITSM Supply Chain
- Compromised unnamed third-party ITSM (IT Service Management) platform used by EY internal IT to support tax-related client work
- Support tickets on the platform contained attached client tax documents
- ShinyHunters claims stolen credentials were then used to pivot into EY's Jira, GitHub, and Azure environments (not confirmed by EY)

### Data Stolen
- Client tax documents with: names, addresses, SSNs, financial account information
- Volume unspecified; "numerous EY clients" affected

## 4. ShinyHunters Campaign-Wide TTPs

### Three Salesforce Attack Paths
1. **Vishing + OAuth consent:** Employee socially engineered to authorize malicious "Salesforce Data Loader" Connected App
2. **Supply chain connected app abuse:** Third-party vendor with pre-authorized Salesforce integration compromised (Salesloft, Gainsight, Klue pattern)
3. **Session hijacking:** Stolen SSO credentials or session tokens used directly

### Vishing Infrastructure
| Category | Tools |
|----------|-------|
| VoIP calling | Twilio, Google Voice, 3CX |
| AI voice automation | Vapi, Bland AI |
| Attribution evasion (VPN) | Mullvad, Oxylabs, NetNut, Infatica |

### MITRE ATT&CK Techniques

| Technique ID | Technique | Notes |
|-------------|-----------|-------|
| T1566.004 | Phishing: Vishing | Primary initial access method |
| T1621 | Multi-Factor Authentication Request Generation | MFA bypass via Entra device registration |
| T1098.005 | Account Manipulation: Device Registration | Registering attacker-controlled Entra device |
| T1528 | Steal Application Access Token | OAuth Connected App token theft |
| T1213.004 | Data from Information Repositories: CRM Software | Salesforce exfiltration |
| T1567 | Exfiltration Over Web Service | Salesforce API for exfil |
| T1195 | Supply Chain Compromise | ITSM vendor pivot (EY breach) |
| T1078 | Valid Accounts | Leveraging compromised employee credentials |

### Salesforce Detection Signatures (from Microsoft)
- "Salesforce detected a possibly hijacked user session"
- "Salesforce detected a successful credential stuffing attack"
- "Salesforce Connected App activity from a new IP address"
- "Suspicious Salesforce Aura Activity"

## 5. Threat Actor Profile

| Field | Value |
|-------|-------|
| Primary name | ShinyHunters |
| Mandiant/Google TI tracking | UNC6661 |
| Campaign C0059 (Salesforce) | MITRE ATT&CK |
| Prior affiliations | UNC6240 collaboration (Oracle PeopleSoft 2026) |
| Operational status | Active as of July 31, 2026 |
| Business model | Pay-or-leak extortion (no encryption) |
| Infrastructure | Decentralized affiliate ecosystem, shared infrastructure |

## 6. References

- [BleepingComputer — ShinyHunters claims Brinks Home breach](https://www.bleepingcomputer.com/news/security/shinyhunters-claims-brinks-home-breach-threatens-to-leak-stolen-data/)
- [BleepingComputer — Ernst and Young data breach claimed by ShinyHunters](https://www.bleepingcomputer.com/news/security/ernst-and-young-data-breach-claimed-by-shinyhunters-extortion-gang/)
- [Microsoft Security Blog — Defending SaaS apps against ShinyHunters OAuth abuse (July 13, 2026)](https://www.microsoft.com/en-us/security/blog/2026/07/13/defending-saas-based-applications-against-shinyhunters-oauth-abuse/)
- [SC World — Brinks Home confirms breach](https://www.scworld.com/brief/brinks-home-confirms-data-breach-after-ransomware-group-claims-attack)
- [SecurityWeek — ShinyHunters Claims Ernst Young Hack](https://www.securityweek.com/shinyhunters-claims-ernst-young-hack/)
- [ReliaQuest — ShinyHunters targets Salesforce, Scattered Spider collaboration](https://reliaquest.com/blog/threat-spotlight-shinyhunters-data-breach-targets-salesforce-amid-scattered-spider-collaboration/)
- [MITRE ATT&CK — Salesforce Data Exfiltration Campaign C0059](https://attack.mitre.org/campaigns/C0059/)
