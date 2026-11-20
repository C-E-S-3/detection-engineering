# ARMORY CASTLE vSphere — Golden SAML Token Forgery via Stolen vCenter STS Signing Key

## Description

Detects Golden SAML token forgery enabled by ARMORY CASTLE's exploitation of CVE-2026-123890 (VMware vCenter `vmdird` unauthenticated SRP-6a session key disclosure). The attack chain is:

1. **CVE-2026-123890 exploitation** — BONESAW tool connects to `vmdird` RPC port 2012 and recovers the SRP-6a session key, then decrypts the vmdird LMDB database to extract the vCenter Security Token Service (STS) SAML signing certificate and private key.
2. **Golden SAML forging** — SAWSNAKE uses the stolen STS signing key to forge SAML assertions for any user, granting persistent authenticated access to any service trusting the vCenter IdP.

False positives for the SAML query: internal SSO testing or service account automation against vCenter SAML endpoints; tune by adding known automation source IPs to an allowlist. For the LAZYBONES process query, there should be essentially no false positives — `vmtoolscs` is not a legitimate VMware binary name. For BEARBONES port detection, DNS services legitimately use TCP 53, so context (destination host type) is required.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Credential Access |
| Tactic ID | TA0006 |
| Technique | Forge Web Credentials: SAML Tokens |
| Technique ID | T1606.002 |
| Secondary Techniques | T1190 (Exploit Public-Facing Application — CVE-2026-123890), T1098.004 (SSH Authorized Keys — BEARBONES), T1102.002 (Slack C2 — LAZYBONES), T1543.002 (Systemd Persistence), T1556 (Modify Authentication Process — BEARBONES SSH bypass) |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Actions on Objectives |
| Exploitation (CVE-2026-123890 initial access) |
| Installation (BEARBONES / LAZYBONES persistence) |
| Command & Control (LAZYBONES Slack C2) |

## Splunk Detection Query

### Rule 1 — vCenter SAML Authentication from External or Unexpected Source (Primary)

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Authentication.Authentication
where Authentication.app="VMware vCenter"
  AND Authentication.authentication_method="SAML"
  AND Authentication.action="success"
by Authentication.src Authentication.user Authentication.dest Authentication.app
   Authentication.authentication_method Authentication.action
| `drop_dm_object_name(Authentication)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    NOT match(src,"^(10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.)"), 95,
    1=1, 65)
| where risk_score >= 65
| table firstTime lastTime src user dest app authentication_method action risk_score
```

### Rule 2 — LAZYBONES Backdoor: vmtoolscs Outbound Network Activity

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Network_Traffic.All_Traffic
where All_Traffic.process="vmtoolscs"
  AND All_Traffic.direction="outbound"
by All_Traffic.src All_Traffic.dest All_Traffic.dest_port All_Traffic.process
   All_Traffic.app All_Traffic.user
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=100,
       note="vmtoolscs is not a legitimate VMware binary; any network activity is malicious"
| table firstTime lastTime src dest dest_port process app user risk_score note
```

### Rule 3 — BEARBONES: SSH Service Connections on Non-Standard Ports (53 or 33992)

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Network_Traffic.All_Traffic
where (All_Traffic.dest_port=33992 OR
       (All_Traffic.dest_port=53 AND All_Traffic.protocol="tcp"))
  AND All_Traffic.action="allowed"
by All_Traffic.src All_Traffic.dest All_Traffic.dest_port All_Traffic.protocol
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(dest_port=33992, 90, dest_port=53 AND protocol="tcp", 60)
| where risk_score >= 60
| table firstTime lastTime src dest dest_port protocol risk_score
```

### Rule 4 — CVE-2026-123890: vmdird RPC Port Connections from Non-vCenter Hosts

```spl
index=network_traffic dest_port=2012 protocol=tcp
| stats count min(_time) as firstTime max(_time) as lastTime by src dest dest_port
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=90,
       note="vmdird RPC port 2012 — CVE-2026-123890 exploitation vector; connections from non-vCenter hosts are highly suspicious"
| table firstTime lastTime src dest dest_port count risk_score note
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| vCenter SAML success from non-RFC1918 IP | 95 | SAWSNAKE-forged tokens will originate from attacker infrastructure; near-certain indicator |
| vCenter SAML success from RFC1918 IP | 65 | Lateral movement with forged token from internal pivot; still high severity |
| Any outbound network from `vmtoolscs` process | 100 | No legitimate VMware binary has this name; any execution is malicious |
| TCP connection to destination port 33992 | 90 | No legitimate services use this port; BEARBONES specific |
| TCP/53 (not UDP/53) inbound SSH-like session | 60 | BEARBONES non-standard port; TCP/53 may have FP from DNS-over-TCP; correlate with ESXi/vCenter dest |
| Connection to vmdird port 2012 from non-vCenter host | 90 | CVE-2026-123890 exploitation; this port should only be accessed intra-vCenter |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| ARMORY CASTLE (formerly UNC5221, PRC-nexus espionage) | [Google GTIG — ARMORY CASTLE vSphere (2026-11-19)](https://cloud.google.com/blog/topics/threat-intelligence/armory-castle-exploits-vsphere) |
| APT29 / COZY BEAR (pioneered Golden SAML in SolarWinds) | [MITRE ATT&CK G0016](https://attack.mitre.org/groups/G0016/), [T1606.002](https://attack.mitre.org/techniques/T1606/002/) |

## References

- [Google GTIG — ARMORY CASTLE Exploits vSphere (2026-11-19)](https://cloud.google.com/blog/topics/threat-intelligence/armory-castle-exploits-vsphere)
- [MITRE ATT&CK — T1606.002 Forge Web Credentials: SAML Tokens](https://attack.mitre.org/techniques/T1606/002/)
- [MITRE ATT&CK — T1190 Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
- [MITRE ATT&CK — T1098.004 Account Manipulation: SSH Authorized Keys](https://attack.mitre.org/techniques/T1098/004/)
- [MITRE ATT&CK — T1543.002 Create or Modify System Process: Systemd Service](https://attack.mitre.org/techniques/T1543/002/)
- [VMware vCenter CVE-2026-123890 — NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-123890)
