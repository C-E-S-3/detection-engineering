# ARMORY CASTLE BeyondTrust Remote Support Unauthenticated File Upload RCE (CVE-2026-102764)

## Description

Detects exploitation of CVE-2026-102764, an unauthenticated arbitrary file upload vulnerability in BeyondTrust Remote Support ≤ 26.2.3. ARMORY CASTLE (PRC-nexus espionage, formerly UNC5221) weaponized this vulnerability to deploy the SAWFLY PHP webshell (`mangoapi.php`) and the BARECLAW SOCKS5-over-WebSocket tunneler. Post-exploitation activity includes vault credential theft (`bt-secrets get vault`), SUID backdoor creation (`/usr/bin/dbus-authd`), and HAProxy configuration modification to externalize the BARECLAW tunnel.

False positives: Legitimate BeyondTrust Remote Support file operations will not match the specific filenames, paths, or WebSocket route patterns used by this actor. The SPL query filters for the known-malicious indicators documented by Google TI; tuning is not expected to be necessary for these IOC-based conditions.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Initial Access |
| Tactic ID | TA0001 |
| Technique | Exploit Public-Facing Application |
| Technique ID | T1190 |

**Secondary techniques (post-exploitation):**

| Tactic | Technique ID | Technique |
|--------|-------------|-----------|
| Persistence | T1505.003 | Web Shell (SAWFLY `mangoapi.php`) |
| Privilege Escalation | T1548.001 | Setuid and Setgid (SUID `/usr/bin/dbus-authd`) |
| Privilege Escalation | T1548.003 | Sudo and Sudo Caching (sudoers.template modification) |
| Credential Access | T1555 | Credentials from Password Stores (vault theft) |
| Defense Evasion | T1070.002 | Clear Linux or Mac System Logs |
| Defense Evasion | T1027 | Obfuscated Files or Information |
| Command and Control | T1572 | Protocol Tunneling (BARECLAW WebSocket SOCKS5) |
| Command and Control | T1090.001 | Internal Proxy (BARECLAW localhost:19800) |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Delivery |
| Exploitation |
| Installation |

## Splunk Detection Query

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Filesystem
  where (Filesystem.file_name="mangoapi.php"
      OR Filesystem.file_name="ingredi_ws"
      OR Filesystem.file_path="*/post_boot.d/zz-root-persist"
      OR Filesystem.file_path="*/usr/bin/dbus-authd")
  by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    file_name="mangoapi.php",                        90,
    file_name="ingredi_ws",                          85,
    like(file_path, "%post_boot.d/zz-root-persist"), 90,
    like(file_path, "%/usr/bin/dbus-authd"),         95,
    1=1, 75)
| where risk_score >= 75
| eval indicator_type=case(
    file_name="mangoapi.php",                        "SAWFLY PHP webshell",
    file_name="ingredi_ws",                          "BARECLAW SOCKS5 tunneler",
    like(file_path, "%post_boot.d/zz-root-persist"), "ARMORY CASTLE persistence script",
    like(file_path, "%/usr/bin/dbus-authd"),         "SUID backdoor")
| table firstTime lastTime dest user file_path file_name indicator_type risk_score
```

### Supplemental: HAProxy Backdoor Configuration (Keyword Search)

```spl
index=* sourcetype=haproxy* ("wswsws" OR "webskd3" OR "/uidchanarge")
| eval risk_score=95
| eval indicator_type="BARECLAW HAProxy routing indicator"
| table _time host sourcetype _raw risk_score indicator_type
```

### Supplemental: BARECLAW Network Traffic (Web Datamodel)

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Web.Web
  where Web.uri_path="/uidchanarge"
  by Web.dest Web.src Web.uri_path Web.http_method Web.status
| `drop_dm_object_name(Web)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=95
| eval indicator_type="BARECLAW WebSocket tunnel endpoint"
| table firstTime lastTime dest src uri_path http_method status risk_score indicator_type
```

### Supplemental: Vault Credential Theft (Process)

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.process="*bt-secrets*get*vault*"
  by Processes.dest Processes.user Processes.parent_process_name
     Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=95
| eval indicator_type="ARMORY CASTLE vault credential theft"
| table firstTime lastTime dest user parent_process_name process_name process risk_score indicator_type
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| `dbus-authd` SUID backdoor file creation | 95 | Near-certain malicious; legitimate `dbus-authd` does not exist in BeyondTrust appliance baseline |
| `mangoapi.php` / `zz-root-persist` file creation | 90 | ARMORY CASTLE-specific IOC; no legitimate BeyondTrust component uses these names |
| `ingredi_ws` file creation | 85 | BARECLAW IOC; unusual ELF binary name on a Remote Support appliance |
| HAProxy config containing `wswsws` / `webskd3` / `/uidchanarge` | 95 | IOC-specific; no known legitimate HAProxy configuration uses these strings |
| BARECLAW WebSocket endpoint `/uidchanarge` in web logs | 95 | IOC-specific network indicator |
| `bt-secrets get vault` process | 95 | Vault credential theft; no legitimate automated process uses this command sequence |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| ARMORY CASTLE (formerly UNC5221) | [Google TI — ARMORY CASTLE CVE-2026-102764](https://cloud.google.com/blog/topics/threat-intelligence/armory-castle-exploits-beyondtrust), [Google TI — UNC5221 Ivanti](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-exploiting-critical-ivanti-vulnerability) |

## References

- [Google Threat Intelligence — ARMORY CASTLE Exploits BeyondTrust (2026-10-15)](https://cloud.google.com/blog/topics/threat-intelligence/armory-castle-exploits-beyondtrust)
- [BeyondTrust Security Advisory BT26-05](https://beyondtrust.com/security-advisories/bt26-05)
- [MITRE ATT&CK — T1190: Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
- [MITRE ATT&CK — T1505.003: Web Shell](https://attack.mitre.org/techniques/T1505/003/)
- [MITRE ATT&CK — T1572: Protocol Tunneling](https://attack.mitre.org/techniques/T1572/)
