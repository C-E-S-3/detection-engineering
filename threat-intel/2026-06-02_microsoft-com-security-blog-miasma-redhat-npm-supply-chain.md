---
scraped_at: 2026-06-03T00:00:00Z
source_url: https://www.microsoft.com/en-us/security/blog/2026/06/02/preinstall-persistence-inside-red-hat-npm-miasma-credential-stealing-campaign/
report_type: threat-intel
severity: high
title: "Miasma: TeamPCP-Linked Credential-Stealing Worm Compromises 32 Red Hat @redhat-cloud-services npm Packages via CI/CD Pipeline Hijack"
---

## 1. IOCs

### File Hashes (SHA256) — Miasma payload variants from compromised @redhat-cloud-services packages

| Hash | Context |
|------|---------|
| 396cac9e457ec54ff6d3f6311cb5cc1da8054d019ce3ffa1de5741506c7a4ea4 | Miasma obfuscated preinstall payload — @redhat-cloud-services package variant |
| d8d170af3de17bb9b217c52aaaffdf9395f35ef015a57ef676e406c121e5e223 | Miasma obfuscated preinstall payload — @redhat-cloud-services package variant |
| f0641e053e81f0d01fa46db35a83e0a34494886503086866d956d14e81fd3e1c | Miasma obfuscated preinstall payload — @redhat-cloud-services package variant |
| d5a97614d5319ce9c8e01fa0b4eb06fb5b9e54fa13b23d718174a1546444123b | Miasma obfuscated preinstall payload — @redhat-cloud-services package variant |
| f88258e21592084a2f93a572ade8f9b91c0cd0e242f5cf6121ed7bad0f7bdd1f | Miasma obfuscated preinstall payload — @redhat-cloud-services package variant |
| 25e121e3b7d300c0d0075b33e5eca39a3e6a659fb9cfee52b70ef71686628f1b | Miasma obfuscated preinstall payload — @redhat-cloud-services package variant |

**Note:** The malware generates a uniquely encrypted payload per infection; these hashes cover specific compromised package versions. Hash-based detection alone is insufficient — behavioral detection is essential.

### C2 / Exfiltration Infrastructure

All three C2 channels reuse infrastructure previously identified in the Mini Shai-Hulud / TeamPCP Wave 3 campaign. These domains are already tracked in `iocs/domain.csv`:

| Indicator | Context |
|-----------|---------|
| filev2.getsession.org | TeamPCP/Miasma — Session Protocol file upload API for exfiltration (already tracked 2026-05-20) |
| api.masscan.cloud | TeamPCP/Miasma — HTTPS POST endpoint receiving stolen CI/CD credentials (already tracked 2026-05-20) |
| git-tanstack[.]com | TeamPCP — PyPI payload delivery and C2 exfiltration domain (already tracked 2026-05-17) |

**New C2 channel — GitHub dead-drop exfiltration (Wave 4 / Miasma):**
- Attacker uses a rotating pool of ~16 attacker-controlled GitHub accounts per session
- Stolen credentials are committed to private repositories under the victim's own GitHub account
- Repository description contains the campaign marker: `Miasma: The Spreading Blight`
- Commit messages prefixed with: `IfYouInvalidateThisTokenItWillNukeTheComputerOfTheOwner`
- Data stored in `_results/<timestamp>-<counter>.json` files via the Git Data API

### Behavioral IOCs

- `package.json` `preinstall` hook executing a 4.29 MB obfuscated JavaScript payload during `npm install`
- GitHub repository description matching `Miasma: The Spreading Blight`
- Commit message prefix: `IfYouInvalidateThisTokenItWillNukeTheComputerOfTheOwner`
- npm process (`node`, `npm`, `npx`) reading credential files: `~/.ssh/`, `~/.aws/`, `~/.kube/config`, `~/.docker/config.json`, `.env` files

### Compromised Packages (@redhat-cloud-services namespace)

Affected versions across at least 32 packages including:

| Package | Compromised Versions |
|---------|---------------------|
| @redhat-cloud-services/types | 3.6.1, 3.6.2, 3.6.4 |
| @redhat-cloud-services/frontend-components | 7.7.2, 7.7.3, 7.7.5 |
| @redhat-cloud-services/rbac-client | 9.0.3, 9.0.4, 9.0.6 |
| @redhat-cloud-services/chrome | 2.3.1, 2.3.2, 2.3.4 |
| 28 additional @redhat-cloud-services/* packages | Multiple versions per package (90+ total compromised versions) |

**Total exposure:** 96 compromised versions across 32 packages; ~116,991 combined weekly downloads.

**Compromise vector:** Attackers gained access to the RedHatInsights/javascript-clients CI/CD pipeline and abused the legitimate GitHub Actions OpenID Connect (OIDC) publishing workflow to push backdoored versions to npm with authentic provenance signatures.

## 2. TTPs (MITRE ATT&CK)

| Tactic | Technique ID | Technique Name | Usage |
|--------|-------------|----------------|-------|
| Initial Access | T1195.002 | Supply Chain Compromise: Compromise Software Supply Chain | GitHub Actions OIDC publishing workflow hijacked via compromised CI/CD pipeline credentials; backdoored npm versions published with valid provenance signatures |
| Execution | T1059.007 | Command and Scripting Interpreter: JavaScript | 4.29 MB obfuscated JavaScript payload executed via npm `preinstall` lifecycle hook before application code runs |
| Credential Access | T1552.001 | Unsecured Credentials: Credentials In Files | Sweeps for cloud provider credentials, CI/CD tokens, SSH keys, kubeconfig, .env files across the host filesystem |
| Credential Access | T1555 | Credentials from Password Stores | Collects browser-stored credentials and cloud identity tokens |
| Collection | T1005 | Data from Local System | Harvests cloud identities: GitHub Actions GITHUB_TOKEN, ACTIONS_RUNTIME_TOKEN; AWS access keys and session tokens; GCP application default credentials and service account key files; Azure SP credentials and managed identity tokens; HashiCorp Vault tokens; Kubernetes service account tokens; npm and PyPI publish tokens; SSH private keys; Docker registry credentials; GPG keys |
| Exfiltration | T1041 | Exfiltration Over C2 Channel | Exfiltrates to api.masscan.cloud and filev2.getsession.org via HTTPS POST |
| Exfiltration | T1567.001 | Exfiltration Over Web Service: Exfiltration to Code Repository | GitHub dead-drop: commits stolen credentials to attacker-controlled repos inside victim GitHub account using the Git Data API |
| Defense Evasion | T1140 | Deobfuscate/Decode Files or Information | Payload is heavily obfuscated; unique per-infection encryption prevents static hash matching |
| Persistence | T1547 | Boot or Logon Autostart Execution | npm `preinstall` hook ensures payload runs every time the package is installed |
| Impact | T1578 | Modify Cloud Compute Infrastructure | Collected cloud credentials (GCP, Azure, AWS) provide attacker access to cloud compute environments post-exfil |
| Defense Evasion | T1036.005 | Masquerading: Match Legitimate Name or Location | Backdoored packages carry authentic npm provenance signatures matching legitimate Red Hat releases |

## 3. Malware & Tools

| Malware | Platform | Description |
|---------|----------|-------------|
| Miasma Worm | Node.js (npm) | Credential-stealing worm embedded in @redhat-cloud-services npm packages via CI/CD pipeline compromise; direct descendant of Mini Shai-Hulud (TeamPCP); campaign marker "Miasma: The Spreading Blight"; generates uniquely encrypted payload per infection; sweeps 14 credential categories including new GCP and Azure identity collectors added in this wave |

## 4. Threat Actor / Campaign Attribution

| Attribute | Detail |
|-----------|--------|
| Campaign name | Miasma: The Spreading Blight |
| Associated actor | Consistent with TeamPCP (UNC6780 / Glassworm adjacency) — same C2 infrastructure and worm code as Mini Shai-Hulud; however, the Mini Shai-Hulud source was publicly released, making copycat attribution possible |
| Timeline | Compromise detected June 1, 2026; 3 waves of package pushes observed (96 versions across 32 packages at peak) |
| Compromise method | CI/CD pipeline account compromise → GitHub Actions OIDC token abuse → npm publish with authentic provenance |
| Prior waves | TeamPCP Wave 1 (March 2026): TanStack npm packages; Wave 2 (April): AntV/echarts; Wave 3 (May): durabletask + Nx Console; Wave 4 (June): @redhat-cloud-services (Miasma) |

## 5. Splunk Detection Searches

```spl
| comment "Search 1: Miasma GitHub dead-drop — npm process accessing credential files (preinstall hook execution)"
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Filesystem
  where Filesystem.process_name IN ("node","npm","npx","node.js")
    AND (Filesystem.file_path="*/.ssh/*"
         OR Filesystem.file_path="*/.aws/credentials*"
         OR Filesystem.file_path="*/.aws/config*"
         OR Filesystem.file_path="*/.kube/config*"
         OR Filesystem.file_path="*/.docker/config.json*"
         OR Filesystem.file_path="*/.config/gcloud/*"
         OR Filesystem.file_path="*/.vault-token*"
         OR Filesystem.file_path="*/.npmrc*"
         OR Filesystem.file_path="*/.pypirc*"
         OR Filesystem.file_path="*/.gnupg/*")
    AND Filesystem.action="read"
  by Filesystem.dest Filesystem.user Filesystem.process_name Filesystem.file_path
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(file_path, "/\.kube/config|service.account"), 95,
    match(file_path, "/\.aws/credentials|/\.aws/config"), 90,
    match(file_path, "/\.ssh/|/\.vault-token"), 88,
    match(file_path, "/\.config/gcloud/"), 87,
    match(file_path, "/\.docker/config|/\.npmrc|/\.pypirc"), 80,
    1=1, 70)
| where risk_score >= 80
| table firstTime lastTime dest user process_name file_path risk_score
```

```spl
| comment "Search 2: Miasma C2 exfiltration — npm process making outbound HTTPS connections to known TeamPCP exfil endpoints"
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Traffic.All_Traffic
  where All_Traffic.dest_domain IN ("api.masscan.cloud","filev2.getsession.org","git-tanstack.com")
    AND All_Traffic.app IN ("npm","node","npx","python","python3","bash","sh")
  by All_Traffic.src All_Traffic.dest All_Traffic.dest_domain All_Traffic.dest_port All_Traffic.app
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=95
| table firstTime lastTime src dest dest_domain dest_port app risk_score
```

```spl
| comment "Search 3: Miasma — large (>1 MB) JavaScript file written to node_modules with non-standard name, potential obfuscated payload indicator"
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Filesystem
  where Filesystem.file_path="*/node_modules/*"
    AND Filesystem.file_name="*.js"
    AND Filesystem.file_size > 1048576
    AND Filesystem.action="created"
    AND NOT Filesystem.process_name IN ("npm","node","npx","yarn","pnpm")
  by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.file_name Filesystem.file_size Filesystem.process_name
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=75
| where file_size > 4000000
| eval risk_score=85
| table firstTime lastTime dest user file_path file_name file_size process_name risk_score
```

```spl
| comment "Search 4: IOC match — known Miasma payload hashes (from Microsoft Security Blog, June 2 2026)"
`sysmon` EventCode=1
| search (MD5 IN ("396cac9e457ec54ff6d3f6311cb5cc1da8054d019ce3ffa1de5741506c7a4ea4","d8d170af3de17bb9b217c52aaaffdf9395f35ef015a57ef676e406c121e5e223","f0641e053e81f0d01fa46db35a83e0a34494886503086866d956d14e81fd3e1c","d5a97614d5319ce9c8e01fa0b4eb06fb5b9e54fa13b23d718174a1546444123b","f88258e21592084a2f93a572ade8f9b91c0cd0e242f5cf6121ed7bad0f7bdd1f","25e121e3b7d300c0d0075b33e5eca39a3e6a659fb9cfee52b70ef71686628f1b")
    OR SHA256 IN ("396cac9e457ec54ff6d3f6311cb5cc1da8054d019ce3ffa1de5741506c7a4ea4","d8d170af3de17bb9b217c52aaaffdf9395f35ef015a57ef676e406c121e5e223","f0641e053e81f0d01fa46db35a83e0a34494886503086866d956d14e81fd3e1c","d5a97614d5319ce9c8e01fa0b4eb06fb5b9e54fa13b23d718174a1546444123b","f88258e21592084a2f93a572ade8f9b91c0cd0e242f5cf6121ed7bad0f7bdd1f","25e121e3b7d300c0d0075b33e5eca39a3e6a659fb9cfee52b70ef71686628f1b"))
| eval risk_score=99
| table _time host user Image CommandLine risk_score
```

## 6. Executive Summary

On June 1, 2026, Wiz Research identified that 32 packages under the `@redhat-cloud-services` npm scope had been backdoored with a credential-stealing worm. By June 2, Microsoft published a detailed technical analysis. The campaign — dubbed **"Miasma: The Spreading Blight"** — represents the fourth wave of supply chain attacks attributed to, or modeled after, the **TeamPCP** (UNC6780) threat actor cluster responsible for the Mini Shai-Hulud worm.

**How it happened:** Attackers compromised credentials associated with the `RedHatInsights/javascript-clients` GitHub CI/CD pipeline and abused the repository's GitHub Actions OIDC publishing workflow to push 90+ backdoored package versions to npm with authentic provenance attestations — making the malicious packages indistinguishable from legitimate Red Hat releases on surface inspection.

**What the malware does:** An obfuscated 4.29 MB JavaScript payload executes via an npm `preinstall` lifecycle hook — before any application code runs — and performs a comprehensive credential sweep across 14+ categories: GitHub Actions tokens, AWS/GCP/Azure cloud credentials, Kubernetes service accounts, HashiCorp Vault tokens, npm/PyPI publish tokens, SSH keys, Docker credentials, and all `.env` files. It then exfiltrates via two channels: (1) HTTPS POST to previously identified TeamPCP endpoints (`api.masscan.cloud`, `filev2.getsession.org`); and (2) a new GitHub dead-drop channel that commits stolen credentials to attacker-controlled repositories within the victim's own GitHub account, using commit messages prefixed with `IfYouInvalidateThisTokenItWillNukeTheComputerOfTheOwner`.

**New in this wave:** GCP and Azure identity collectors were added that harvest all managed identity tokens accessible to the infected machine — a significant expansion from earlier waves focused primarily on AWS and GitHub credentials.

**Scale:** ~116,991 combined weekly downloads across the 32 affected packages. Red Hat revoked the CI/CD tokens and removed affected versions from npm on June 1; organizations that installed any @redhat-cloud-services packages between the compromise window and removal should treat all CI/CD secrets, cloud credentials, and SSH keys as compromised.

**Immediate actions:**
1. Audit your `node_modules/` and `package-lock.json` for any @redhat-cloud-services package versions listed above as compromised.
2. Rotate ALL secrets on any system that installed affected versions: GitHub tokens, AWS/GCP/Azure credentials, SSH keys, Vault tokens, npm publish tokens.
3. Deploy Search 1 to detect npm processes reading credential files (covers this wave and future variants).
4. Check your GitHub organization for new repositories with description containing "Miasma: The Spreading Blight" or unusual commits from unfamiliar committers in your organization's repositories.

## References

- [Microsoft Security Blog — Preinstall to persistence: Inside the Red Hat npm Miasma credential-stealing campaign (2026-06-02)](https://www.microsoft.com/en-us/security/blog/2026/06/02/preinstall-persistence-inside-red-hat-npm-miasma-credential-stealing-campaign/)
- [Wiz Research — Miasma: Supply Chain Attack Targeting RedHat npm Packages (2026-06-01)](https://www.wiz.io/blog/miasma-supply-chain-attack-targeting-redhat-npm-packages)
- [The Hacker News — Miasma Supply Chain Attack Compromises Red Hat npm Packages (2026-06-02)](https://thehackernews.com/2026/06/miasma-supply-chain-attack-compromises.html)
- [OX Security — New Shai-Hulud Hits npm: @redhat-cloud-services Compromised](https://www.ox.security/blog/new-npm-supply-chain-attack-redhat-cloud-services-compromised/)
- [JFrog Security Research — Shai-Hulud Miasma: RedHat Cloud Services](https://research.jfrog.com/post/shai-hulud-miasma-redhat-cloud-services/)
- [Snyk — Miasma Attack Hits Red Hat npm Packages](https://snyk.io/blog/miasma-supply-chain-attack-malicious-code-redhat-cloud-services-npm-packages/)
- [MITRE ATT&CK — T1195.002 Supply Chain Compromise](https://attack.mitre.org/techniques/T1195/002/)
- [MITRE ATT&CK — T1567.001 Exfiltration to Code Repository](https://attack.mitre.org/techniques/T1567/001/)
- [MITRE ATT&CK — T1578 Modify Cloud Compute Infrastructure](https://attack.mitre.org/techniques/T1578/)
