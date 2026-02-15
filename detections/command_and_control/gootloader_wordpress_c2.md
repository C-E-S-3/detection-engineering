# Gootloader Outbound HTTP POST to Compromised WordPress Sites

## Description

Gootloader C2 commonly uses compromised WordPress sites. This detection identifies outbound HTTP POST requests to URIs containing common WordPress paths (`/wp-content/`, `/wp-includes/`, `/wp-admin/admin-ajax.php`) via the Web data model. Additional risk is applied when the user-agent string indicates a scripting engine rather than a browser.

False positive sources: Legitimate WordPress API interactions, web proxies. Tuning: exclude known internal WordPress sites and proxy infrastructure.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Command and Control |
| Tactic ID | TA0011 |
| Technique | Application Layer Protocol: Web Protocols |
| Technique ID | T1071.001 |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Command & Control (C2) |

## Splunk Detection Query

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Web.Web
where Web.http_method="POST"
    AND (Web.url IN ("*/wp-content/*", "*/wp-includes/*", "*/wp-admin/admin-ajax.php*"))
    AND NOT Web.src_category="web_proxy"
by Web.src Web.dest Web.url Web.http_method Web.status Web.http_user_agent
| `drop_dm_object_name(Web)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(url, "(?i)admin-ajax\\.php"), 80,
    match(url, "(?i)wp-content/uploads"), 75,
    match(url, "(?i)wp-includes"), 70,
    1=1, 60)
| eval suspicious_ua=if(match(http_user_agent, "(?i)(powershell|wget|curl|python|java/)"), 1, 0)
| eval risk_score=if(suspicious_ua=1, risk_score+15, risk_score)
| where risk_score >= 65
| table firstTime lastTime src dest url http_method http_user_agent status risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| POST to admin-ajax.php | 80 | Primary Gootloader C2 endpoint |
| POST to wp-content/uploads | 75 | Common Gootloader payload staging path |
| POST to wp-includes | 70 | WordPress internal path abuse |
| +15 bonus: scripting engine user-agent | - | Non-browser UA strongly indicates automated C2 |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| Gootloader / UNC2565 | [MITRE - Gootloader (S1138)](https://attack.mitre.org/software/S1138/) |

## References

- [Mandiant - Tracking and Disrupting GootLoader Operations](https://www.mandiant.com/resources/tracking-and-disrupting-gootloader-operations)
