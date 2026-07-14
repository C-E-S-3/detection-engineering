# Microsoft SharePoint Server CVE-2026-56164: Missing Authentication EoP

## Description

Detects exploitation of CVE-2026-56164, a missing authentication for critical function vulnerability (CWE-306) in Microsoft SharePoint Server. An unauthenticated network attacker can call privileged SharePoint REST API endpoints — including `/_api/web/SiteGroups`, `/_api/web/RoleAssignments`, and `/_api/web/SiteAdministrators` — without credentials and receive success responses. This allows the attacker to add themselves to privileged site groups, assign Full Control role bindings, or grant site administrator access over the network with no prior authentication.

CISA added CVE-2026-56164 to the Known Exploited Vulnerabilities catalog on 2026-07-14 with a mandatory remediation deadline of 2026-07-17 — the shortest possible KEV window, indicating known active exploitation.

**Exploit sequence:**

1. Attacker sends an unauthenticated POST to `/_api/contextinfo` to obtain a SharePoint form digest value. The missing auth check allows this to succeed (HTTP 200).
2. Using the form digest, attacker sends an authenticated-looking POST to `/_api/web/SiteGroups(id)/Users` or `/_api/web/RoleAssignments/addroleassignment`, adding their account to the Owners group or granting Full Control.
3. Windows Security Event 4728 fires with the SharePoint IIS AppPool account as Subject, confirming the web process executed the privilege change.

**False positive sources:**

- SharePoint administrators legitimately call these REST endpoints from management tools, SharePoint Designer, and PowerShell PnP modules. Correlate with unexpected source IPs or non-admin user accounts.
- Windows Event 4728 fires for all SharePoint group membership changes including legitimate admin operations. The discriminating signal is the Subject account: changes by a service or AppPool account (not a human admin) are anomalous.
- Windows Event 4720 occurs during standard SharePoint user provisioning flows. Flag only when the creating Subject is an IIS AppPool or service account.

**Affected versions:** Microsoft SharePoint Server (all supported on-premises versions). Apply Microsoft security updates per MS advisory.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Initial Access |
| Tactic ID | TA0001 |
| Technique | Exploit Public-Facing Application |
| Technique ID | T1190 |

Secondary techniques:

- T1098 (Persistence/Privilege Escalation: Account Manipulation — unauthenticated group membership grant)
- T1548 (Privilege Escalation: Abuse Elevation Control Mechanism — auth bypass allowing EoP)
- T1136 (Persistence: Create Account — backdoor account provisioning via unprotected admin endpoint)

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Exploitation |
| Actions on Objectives |

## Known IOCs

No specific IOCs published at time of writing. Indicators are behavioral (unauthenticated REST API success, service-account-attributed Windows events). Monitor for:

| Type | Value | Description |
|------|-------|-------------|
| URL Pattern | `POST /_api/contextinfo` returning 200 from unexpected sources | Anonymous form digest token acquisition |
| URL Pattern | `POST /_api/web/SiteGroups(N)/Users` returning 201 | Unauthenticated group member addition |
| URL Pattern | `POST /_api/web/RoleAssignments/addroleassignment` returning 200 | Unauthenticated role assignment |
| Windows Event | EventID 4728, Subject=IIS APPPOOL\* | Group membership change by web process |
| Windows Event | EventID 4720, Subject=IIS APPPOOL\* | Account creation by web process |

## Wazuh Detection Rules

Rules 103925-103934 in `wazuh/rules/staged/sharepoint_cve_2026_56164_missing_auth_eop.xml`:

| Rule ID | Level | Description |
|---------|-------|-------------|
| 103925 | 9 | Base anchor: request to privileged SharePoint REST endpoint (info) |
| 103926 | 11 | POST to /_api/contextinfo returning 2xx (anon form digest obtained) |
| 103927 | 12 | 2xx response to SiteGroups or RoleAssignments endpoint |
| 103928 | 13 | POST to SiteGroups(n)/Users returning 2xx (group member addition) |
| 103929 | 14 | POST to SiteAdministrators or addroleassignment returning 2xx (critical) |
| 103930 | 0 | Base anchor: Windows EventID 4728 (member added to global group) |
| 103931 | 12 | EventID 4728 targeting SharePoint admin group name |
| 103932 | 13 | EventID 4728 with IIS/SharePoint service account as Subject |
| 103933 | 0 | Base anchor: Windows EventID 4720 (user account created) |
| 103934 | 12 | EventID 4720 with IIS/SharePoint service account as Subject |

## Splunk Detection Query

**HTTP: Unauthenticated success on SharePoint admin REST endpoints**

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Web.Web
  where Web.url IN ("*/_api/web/SiteGroups*", "*/_api/web/RoleAssignments*",
                    "*/_api/web/SiteAdministrators*", "*/_vti_bin/UserGroup.asmx*")
    AND Web.status IN ("200","201","204")
    AND Web.http_method IN ("POST","PUT","PATCH")
  by Web.src Web.dest Web.url Web.http_method Web.status Web.user
| `drop_dm_object_name(Web)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(url, "(?i)siteadministrators|addroleassignment|usergroup\.asmx"), 95,
    match(url, "(?i)sitegroups\(\d+\)/users"), 90,
    match(url, "(?i)roleassignments"), 80,
    1=1, 70)
| where risk_score >= 70
| table firstTime lastTime src dest url http_method status user risk_score
```

**Contextinfo: Anonymous form digest acquisition**

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Web.Web
  where Web.url="*/_api/contextinfo*"
    AND Web.http_method="POST"
    AND Web.status IN ("200","201")
  by Web.src Web.dest Web.url Web.http_method Web.status Web.user
| `drop_dm_object_name(Web)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=75
| table firstTime lastTime src dest url status user risk_score
```

**Windows: Group membership change initiated by IIS AppPool or SharePoint service account**

```spl
index=wineventlog EventCode=4728
(SubjectUserName="IIS APPPOOL*" OR SubjectUserName="spservice" OR SubjectUserName="sp_farm"
 OR SubjectUserName="sp_service" OR SubjectUserName="svc_sp" OR SubjectUserName="IUSR")
| eval risk_score=case(
    match(TargetUserName, "(?i)sharepoint|wss_admin|farm.admin|sp_admin"), 90,
    1=1, 75)
| `security_content_ctime(_time)`
| table _time host SubjectUserName TargetUserName MemberName risk_score
```

**Windows: Account creation by IIS AppPool or SharePoint service account**

```spl
index=wineventlog EventCode=4720
(SubjectUserName="IIS APPPOOL*" OR SubjectUserName="spservice" OR SubjectUserName="sp_farm"
 OR SubjectUserName="IUSR")
| `security_content_ctime(_time)`
| eval risk_score=85
| table _time host SubjectUserName TargetUserName risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| POST to SiteAdministrators/addroleassignment succeeds | 95 | Direct admin privilege grant via unauthenticated request |
| POST to SiteGroups(n)/Users succeeds | 90 | Group member addition confirmed; EoP in progress |
| 4728 Subject is IIS AppPool, group is SharePoint admin | 90 | Web process executed privilege change; exploit confirmed |
| 4720 Subject is IIS AppPool or service account | 85 | Account created by web process; possible backdoor |
| POST to contextinfo succeeds from unexpected source | 75 | Anonymous form digest obtained; exploit prerequisite |
| 2xx to SiteGroups or RoleAssignments endpoint | 80 | Privilege manipulation at REST layer succeeded |
| 4728 targeting SharePoint admin group name | 70 | Group membership change in sensitive group; investigate Subject |

## Associated Threat Actors

CVE-2026-56164 was added to CISA KEV on 2026-07-14 with a three-day remediation window, indicating active exploitation is confirmed but attribution has not been publicly disclosed at time of writing. SharePoint vulnerabilities are historically targeted by a range of threat actors including:

| Actor | Techniques | References |
|-------|-----------|-----------|
| Multiple (CISA KEV confirmed exploitation) | T1190, T1098 | [CISA KEV CVE-2026-56164](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) |
| Volt Typhoon (China, known SharePoint targeting) | T1190, T1078 | [MITRE ATT&CK G0144](https://attack.mitre.org/groups/G0144/) |
| APT29 (Russia, M365/SharePoint focus) | T1190, T1098, T1136 | [MITRE ATT&CK G0016](https://attack.mitre.org/groups/G0016/) |

## References

- [CISA Known Exploited Vulnerabilities Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [Microsoft SharePoint Server Security Updates](https://docs.microsoft.com/en-us/officeupdates/sharepoint-updates)
- [MITRE ATT&CK T1190 — Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
- [MITRE ATT&CK T1098 — Account Manipulation](https://attack.mitre.org/techniques/T1098/)
- [MITRE ATT&CK T1548 — Abuse Elevation Control Mechanism](https://attack.mitre.org/techniques/T1548/)
- [CWE-306: Missing Authentication for Critical Function](https://cwe.mitre.org/data/definitions/306.html)
