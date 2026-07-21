# StealC Infostealer — Developer Credential and API Key Theft

## Description

Detects the credential-harvesting behavior of StealC, a MaaS (Malware-as-a-Service) infostealer delivered as SmartLoader's secondary payload in the FakeGit MCP server supply chain campaign. StealC targets high-value developer credentials in addition to standard browser credential stores:

- **Browser credentials**: Chrome/Chromium `Login Data`, Cookies, `Local State` (encryption key); Firefox `logins.json`, `key4.db`, `cookies.sqlite`; Edge, Brave, Opera, Vivaldi
- **API keys and cloud credentials**: `.env` files, AWS credentials (`~/.aws/credentials`), GCP service account JSON, Azure CLI tokens, `~/.config/gcloud/`
- **CI/CD tokens**: `.npmrc` (npm auth tokens), `.pypirc`, `~/.cargo/credentials.toml`, GitHub CLI tokens (`~/.config/gh/hosts.yml`)
- **Cryptocurrency wallets**: MetaMask extension storage, Exodus, Atomic, Coinbase Wallet, Ledger Live; browser-based wallet extension databases
- **Development secrets**: `.ssh/id_rsa`, `id_ed25519` (private keys); Docker registry credentials (`~/.docker/config.json`); kubeconfig files

StealC drops as a Windows PE executable loaded by SmartLoader and exfiltrates collected data via multipart POST to a bare-IP C2 server (resolved via Polygon blockchain, see companion detection). The StealC binary itself may be placed in `%LOCALAPPDATA%` and masquerade as a system component.

This detection focuses on the credential-access phase: unexpected processes accessing multiple high-value credential file paths in rapid succession. The combination of breadth (multiple credential types accessed within a short window) and the specific process ancestry (LuaJIT or unknown LOCALAPPDATA binary) distinguishes StealC from legitimate credential managers.

False positives: Password managers (1Password, Bitwarden, KeePass) may legitimately access browser credential databases. Backup tools, security scanners, and browser sync services may also access some of these paths. Filter with allowlisted process hashes or paths for known-legitimate credential managers.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Credential Access |
| Tactic ID | TA0006 |
| Technique | Credentials from Password Stores: Credentials from Web Browsers |
| Technique ID | T1555.003 |
| Secondary Technique | Unsecured Credentials: Credentials in Files |
| Secondary Technique ID | T1552.001 |
| Secondary Technique (2) | Credentials from Password Stores: Password Managers |
| Secondary Technique ID (2) | T1555.001 |
| Tertiary Tactic | Collection |
| Tertiary Technique | Data from Local System |
| Tertiary Technique ID | T1005 |
| Exfiltration | Exfiltration Over C2 Channel |
| Exfiltration ID | T1041 |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Actions on Objectives (credential and secret harvesting) |

## Splunk Detection Queries

### Query 1: Suspicious Process Accessing Browser Credential Database (Windows)

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Filesystem
where NOT Filesystem.process_name IN (
    "chrome.exe", "msedge.exe", "firefox.exe", "brave.exe",
    "chromium.exe", "opera.exe", "vivaldi.exe",
    "1password.exe", "bitwarden.exe", "keepass.exe",
    "1Password.exe", "Bitwarden.exe",
    "SearchIndexer.exe", "MsMpEng.exe")
  AND (Filesystem.file_path LIKE "%\\Chrome\\User Data\\Default\\Login Data%"
       OR Filesystem.file_path LIKE "%\\Chrome\\User Data\\Default\\Cookies%"
       OR Filesystem.file_path LIKE "%\\Chrome\\User Data\\Local State%"
       OR Filesystem.file_path LIKE "%\\Edge\\User Data\\Default\\Login Data%"
       OR Filesystem.file_path LIKE "%\\Brave-Browser\\User Data\\Default\\Login Data%"
       OR Filesystem.file_path LIKE "%\\Firefox\\Profiles\\%logins.json%"
       OR Filesystem.file_path LIKE "%\\Firefox\\Profiles\\%key4.db%"
       OR Filesystem.file_path LIKE "%\\Opera Software\\%Login Data%")
by Filesystem.dest Filesystem.user Filesystem.process_name Filesystem.file_path Filesystem.action
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(process_name, "(?i)lua\.exe|luajit\.exe|lua52|lua53|lua54|luajit"), 98,
    match(file_path, "(?i)Login Data.*AND.*key4\.db"), 90,
    match(process_name, "(?i)AppData.Local"), 90,
    1=1, 75)
| where risk_score >= 75
| table firstTime lastTime dest user process_name file_path action risk_score
```

### Query 2: Process Accessing Cloud/CI Credential Files (Linux/macOS)

```spl
index=auditd OR index=osquery
(action="open" OR action="read" OR syscall IN ("open","openat","read"))
(file_path IN (
    "/root/.aws/credentials", "/home/*/.aws/credentials",
    "/root/.config/gcloud/*", "/home/*/.config/gcloud/*",
    "/root/.azure/accessTokens.json", "/home/*/.azure/*",
    "/root/.npmrc", "/home/*/.npmrc",
    "/root/.pypirc", "/home/*/.pypirc",
    "/root/.cargo/credentials.toml", "/home/*/.cargo/credentials.toml",
    "/root/.config/gh/hosts.yml", "/home/*/.config/gh/hosts.yml",
    "/root/.docker/config.json", "/home/*/.docker/config.json",
    "/root/.kube/config", "/home/*/.kube/config",
    "/root/.ssh/id_rsa", "/home/*/.ssh/id_rsa",
    "/root/.ssh/id_ed25519", "/home/*/.ssh/id_ed25519"))
NOT (process_name IN ("git", "gh", "aws", "gcloud", "kubectl", "docker", "npm", "pip", "cargo", "ssh", "scp"))
| eval risk_score=case(
    match(process_name, "(?i)lua|luajit"), 98,
    match(file_path, ".aws.credentials.*AND.*.ssh.id_rsa"), 95,
    1=1, 80)
| table _time host process_name file_path risk_score
```

### Query 3: Breadth-Based Detection — Multiple Credential File Types Accessed by Same Process (5-Minute Window)

```spl
| tstats `security_content_summariesonly` count values(Filesystem.file_path) as accessed_paths
    dc(Filesystem.file_path) as path_count
    min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Filesystem
where (Filesystem.file_path LIKE "%Login Data%"
       OR Filesystem.file_path LIKE "%logins.json%"
       OR Filesystem.file_path LIKE "%.aws/credentials%"
       OR Filesystem.file_path LIKE "%.npmrc%"
       OR Filesystem.file_path LIKE "%id_rsa%"
       OR Filesystem.file_path LIKE "%id_ed25519%"
       OR Filesystem.file_path LIKE "%MetaMask%"
       OR Filesystem.file_path LIKE "%exodus%"
       OR Filesystem.file_path LIKE "%.docker/config.json%"
       OR Filesystem.file_path LIKE "%.kube/config%"
       OR Filesystem.file_path LIKE "%key4.db%"
       OR Filesystem.file_path LIKE "%Local State%")
by Filesystem.dest Filesystem.user Filesystem.process_name
    span=5m
| `drop_dm_object_name(Filesystem)`
| where path_count >= 3
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    path_count >= 6, 95,
    path_count >= 4, 85,
    path_count >= 3, 75,
    1=1, 65)
| table firstTime lastTime dest user process_name path_count accessed_paths risk_score
```

### Query 4: Cryptocurrency Wallet Enumeration by Non-Browser Process

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Filesystem
where NOT Filesystem.process_name IN (
    "chrome.exe", "firefox.exe", "msedge.exe", "brave.exe",
    "Exodus.exe", "Atomic.exe", "coinbase.exe")
  AND (Filesystem.file_path LIKE "%MetaMask%"
       OR Filesystem.file_path LIKE "%\\Exodus\\%"
       OR Filesystem.file_path LIKE "%\\Atomic\\%"
       OR Filesystem.file_path LIKE "%Coinbase Wallet%"
       OR Filesystem.file_path LIKE "%Ledger Live%"
       OR Filesystem.file_path LIKE "%\\nkbihfbeogaeaoehlefnkodbefgpgknn\\%"
       OR Filesystem.file_path LIKE "%wallet.dat%")
by Filesystem.dest Filesystem.user Filesystem.process_name Filesystem.file_path Filesystem.action
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=85
| table firstTime lastTime dest user process_name file_path action risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| LuaJIT accessing browser Login Data or logins.json | 98 | LuaJIT has no legitimate reason to read browser credential stores; near-certain StealC |
| Same process reads 6+ distinct credential file types in 5 min | 95 | StealC's breadth-first credential sweep is distinctive; no legitimate tool reads this many types simultaneously |
| Unknown LOCALAPPDATA binary accessing Chrome Login Data | 90 | Process ancestry indicates malware; Chrome Login Data is a high-value target |
| Same process reads 4+ distinct credential file types in 5 min | 85 | High-confidence credential sweep; investigate process ancestry |
| Crypto wallet database accessed by non-browser, non-wallet process | 85 | Crypto wallet theft is a primary StealC objective; few legitimate tools need wallet DB access |
| AWS/GCP/SSH credential files accessed by unknown process | 80 | Developer credential theft; high-value target for cloud infrastructure compromise |
| 3+ distinct credential file types in 5 min by same process | 75 | Suspicious breadth; may be security scanner — correlate with process hash and parent ancestry |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| SmartLoader Gang (FakeGit campaign, StealC delivery) | [The Hacker News (2026-02)](https://thehackernews.com/2026/02/smartloader-attack-uses-trojanized-oura.html) |
| StealC (MaaS infostealer, multiple buyers) | [Bitsight — StealC/Amadey Infrastructure](https://www.bitsight.com/blog/bitsight-aids-disruption-efforts-on-amadey-malware-and-stealc-malware), [SOC Prime SmartLoader Analysis](https://socprime.com/active-threats/smartloader-analysis/) |

## References

- [The Hacker News — SmartLoader Attack Uses Trojanized Oura MCP Server (2026-02)](https://thehackernews.com/2026/02/smartloader-attack-uses-trojanized-oura.html)
- [Bitsight — Bitsight Aids Disruption of StealC and Amadey Malware](https://www.bitsight.com/blog/bitsight-aids-disruption-efforts-on-amadey-malware-and-stealc-malware)
- [SOC Prime — SmartLoader / StealC Active Threats](https://socprime.com/active-threats/smartloader-analysis/)
- [Hexastrike — 109 Fake GitHub Repos Deliver SmartLoader and StealC](https://hexastrike.com/resources/blog/threat-intelligence/cloned-loaded-and-stolen-how-109-fake-github-repositories-delivered-smartloader-and-stealc/)
- [Straiker — SmartLoader Clones Oura Ring MCP](https://www.straiker.ai/blog/smartloader-clones-oura-ring-mcp-to-deploy-supply-chain-attack)
- [MITRE ATT&CK — T1555.003: Credentials from Web Browsers](https://attack.mitre.org/techniques/T1555/003/)
- [MITRE ATT&CK — T1552.001: Unsecured Credentials in Files](https://attack.mitre.org/techniques/T1552/001/)
- [MITRE ATT&CK — T1005: Data from Local System](https://attack.mitre.org/techniques/T1005/)
- [MITRE ATT&CK — T1041: Exfiltration Over C2 Channel](https://attack.mitre.org/techniques/T1041/)
