# OpenSSH SSHole Oversized Password Authentication Bypass (CVE-2026-123158)

## Description

Detects exploitation of CVE-2026-123158 ("SSHole"), an authentication bypass in OpenSSH builds compiled against musl libc (Alpine Linux default) with PAM disabled and PasswordAuthentication enabled. The musl libc `crypt()` function returns the literal string `"*"` for passwords longer than 256 bytes; OpenSSH then compares the returned value against the stored password hash, which also begins with `"*"`, resulting in a false equality match and authentication success without valid credentials.

Observed exploitation behavior: attacker sends a 257+ byte password string to bypass authentication, then immediately executes system discovery commands (`id`, `uname`, `hostname`) via a non-interactive SSH session. GreyNoise observed 16 successful exploitation chains within 48 hours of disclosure; active exploitation confirmed.

**False positives:** Legitimate administrative tools using `expect` or automated scripts sending long passwords; SSH honeypots; pen test activity. Tune the discovery-command detection by excluding known-good automation accounts.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Initial Access |
| Tactic ID | TA0001 |
| Technique | Exploit Public-Facing Application |
| Technique ID | T1190 |
| Secondary Tactic | Discovery (TA0007) |
| Secondary Technique | System Information Discovery — T1082; System Owner/User Discovery — T1033 |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Exploitation |

## Splunk Detection Query

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where (Processes.process_name IN ("id", "uname", "hostname", "whoami")
         OR Processes.process IN ("*/id", "*/uname", "*/hostname", "*/whoami"))
  AND Processes.parent_process_name IN ("sshd", "bash", "sh", "dash", "zsh")
  by Processes.dest Processes.user Processes.parent_process_name
     Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    process_name="id" AND parent_process_name="sshd", 80,
    process_name IN ("uname","hostname","whoami") AND parent_process_name="sshd", 70,
    process_name="id", 65,
    1=1, 55)
| where risk_score >= 55
| table firstTime lastTime dest user parent_process_name process_name process process_id risk_score
```

**Corroborating search — known attacker IP in authentication data model:**

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Authentication
  where Authentication.action="success"
  AND Authentication.app IN ("ssh", "openssh", "sshd")
  AND Authentication.src IN ("89.116.89.18")
  by Authentication.src Authentication.dest Authentication.user Authentication.action
| `drop_dm_object_name(Authentication)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=90
| table firstTime lastTime src dest user action count risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| `id` executed with `sshd` as direct parent | 80 | Strong indicator of post-SSH-auth discovery; `sshd` spawning `id` is unusual in legitimate sessions |
| `uname`/`hostname`/`whoami` with `sshd` parent | 70 | Same SSHole pattern; slightly less specific than `id` |
| `id` executed (any parent) | 65 | Anomalous discovery; needs correlation with SSH auth event |
| Known attacker IP (`89.116.89.18`) in SSH success | 90 | Direct IOC match from confirmed exploitation |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| GT10 (GreyNoise cluster, unattributed) | GreyNoise observed 16 exploitation chains tracking this cluster |
| Generic botnet operators / cryptominers | watchTowr links SSHole exploitation to botnet and cryptomining campaigns |

## References

- [Ethiack: SSHole CVE-2026-123158 Research](https://ethiack.com/info-hub/research/sshole-cve-2026-123158)
- [Help Net Security: OpenSSH exploited in the wild within hours of disclosure](https://www.helpnetsecurity.com/2026/11/06/openssh-sshole-cve-2026-123158-exploitation/)
- [The Hacker News: SSHole flaw exploited](https://thehackernews.com/2026/11/hackers-exploited-openssh-sshole-flaw.html)
- [CISA KEV: CVE-2026-123158](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [MITRE ATT&CK T1190](https://attack.mitre.org/techniques/T1190/)
