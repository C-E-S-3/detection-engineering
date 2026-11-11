# GPUStack Loopback IP Header Authentication Bypass (CVE-2026-102895)

## Description

Detects exploitation of CVE-2026-102895, a critical (CVSS 9.8) pre-authentication authorization bypass in GPUStack versions before 2.2.0. GPUStack trusts requests that appear to originate from the loopback address (`127.0.0.1`) as having automatic admin-level authorization. Attackers exploit this by setting the `X-GPUStack-Real-IP: 127.0.0.1` header on external HTTP requests, causing the server to grant admin access without authentication.

Post-exploitation behavior observed: attackers used admin API access to register malicious inference backends, which then executed reverse shells on GPU worker nodes. The technique gives attackers shell access to the underlying GPU compute infrastructure.

**False positives:** Legitimate reverse proxies or load balancers that set `X-GPUStack-Real-IP` for internal routing. After patching, existing legitimate proxy configurations should be validated and traffic from known-good proxy IPs excluded from alerting.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Initial Access |
| Tactic ID | TA0001 |
| Technique | Exploit Public-Facing Application |
| Technique ID | T1190 |
| Secondary Tactic | Execution (TA0002) |
| Secondary Technique | Command and Scripting Interpreter — T1059 |
| Secondary Tactic | Persistence (TA0003) |
| Secondary Technique | Account Manipulation — T1098 |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Exploitation |
| Installation |

## Splunk Detection Query

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Web.Web
  where Web.url IN ("*/api/v1/worker*", "*/api/v1/models*", "*/api/v1/admin*",
                    "*/api/v1/api-keys*", "*/api/v1/backends*", "*/api/v1/users*")
  AND Web.http_method IN ("POST", "PUT", "DELETE", "PATCH")
  AND Web.status IN ("200", "201", "204")
  by Web.src Web.dest Web.url Web.http_method Web.http_user_agent Web.status
| `drop_dm_object_name(Web)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| where NOT (src IN ("127.0.0.1", "::1", "0:0:0:0:0:0:0:1"))
| eval risk_score=case(
    match(url, "(?i)/api/v1/(api-keys|backends)") AND http_method IN ("POST","DELETE"), 90,
    match(url, "(?i)/api/v1/admin"), 85,
    match(url, "(?i)/api/v1/worker") AND http_method IN ("POST","DELETE"), 80,
    1=1, 70)
| where risk_score >= 70
| table firstTime lastTime src dest url http_method http_user_agent status count risk_score
```

**Reverse shell detection on GPU worker nodes:**

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where (Processes.process_name IN ("bash", "sh", "nc", "ncat", "python", "python3", "perl")
         AND (Processes.process IN ("*>/dev/tcp/*", "*-e /bin/bash*", "*-e /bin/sh*",
                                     "*socket*connect*", "*-c import socket*",
                                     "*mkfifo*", "*nc -e*", "*ncat -e*")))
  by Processes.dest Processes.user Processes.parent_process_name
     Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(process, "(?i)/dev/tcp/"), 95,
    match(process, "(?i)-e /bin/(bash|sh)"), 90,
    match(process, "(?i)import socket.*connect"), 85,
    1=1, 75)
| where risk_score >= 75
| table firstTime lastTime dest user parent_process_name process_name process process_id risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| POST/DELETE to `/api/v1/api-keys` or `/backends` from non-loopback | 90 | Direct exploitation path: creating API keys or registering backends are the primary post-auth actions |
| Any write to `/api/v1/admin` from non-loopback | 85 | Admin endpoint access from external IP — high confidence exploit attempt |
| Write to `/api/v1/worker` from non-loopback | 80 | Worker manipulation requires admin; external source is anomalous |
| Reverse shell via `/dev/tcp/` | 95 | Near-certain exploitation; bash TCP redirect reverse shell from GPU worker |
| Reverse shell with `-e /bin/bash` | 90 | Classic nc/ncat reverse shell; high confidence malicious |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| Unattributed — opportunistic actors targeting AI/ML infrastructure | CISA KEV Nov 2026; CSA Research Note |
| LLM Jacking operators (UNC6993 archetype) | GPU compute infrastructure is a high-value target for cryptomining and LLM API abuse |

## References

- [Cloud Security Alliance: CSA Research Note — GPUStack CVE-2026-102895](https://labs.cloudsecurityalliance.org/research/csa-research-note-gpustack-cve-2026-102895-kev-20261110-csa/)
- [Security Affairs: CISA adds IBM, SignalWire, OpenSSH, and GPUStack to KEV](https://securityaffairs.com/202813/hacking/u-s-cisa-adds-ibm-signalwire-freeswitch-openssh-and-gpustack-flaws-to-its-known-exploited-vulnerabilities-catalog.html)
- [CISA KEV: CVE-2026-102895](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [MITRE ATT&CK T1190](https://attack.mitre.org/techniques/T1190/)
