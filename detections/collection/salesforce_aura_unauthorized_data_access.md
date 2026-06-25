# Salesforce Aura Endpoint Unauthorized Data Access

## Description

Detects abuse of misconfigured Salesforce Aura framework endpoints (also known as Lightning Web Components / Aura Component Framework) to extract sensitive organizational data without authorization. Mandiant released AuraInspector — an open-source auditing tool — revealing that Aura endpoints exposed via `/s/recordlist/*`, `/apex/*`, and `/graphql` often lack proper access controls, allowing unauthenticated or low-privilege users to enumerate accounts, retrieve sensitive records (PII, credit card numbers, health information, identity documents), and in worst cases modify or destroy records. Attackers enumerate these endpoints via GraphQL introspection and bypass record retrieval limits by chaining Aura method calls. Detection focuses on anomalous access volume, bulk GraphQL requests, and access from unexpected user agents or IPs. Common false positives: legitimate Salesforce reporting tools, partner integrations, and ETL pipelines; establish a volume and user-agent baseline before alerting.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Collection |
| Tactic ID | TA0009 |
| Technique | Data from Information Repositories |
| Technique ID | T1213 |

Secondary techniques: T1190 (Exploit Public-Facing Application — misconfigured Aura endpoint as attack surface), T1087.004 (Account Discovery: Cloud Account — enumeration of Salesforce user accounts), T1485 (Data Destruction — potential record deletion via misconfigured access controls)

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Actions on Objectives |

## Splunk Detection Query

```spl
index=web sourcetype IN ("access_combined","nginx:plus:kv","iis","apache:access")
  (uri_path="*/s/recordlist/*" OR uri_path="*/apex/*" OR uri_path="*/graphql")
| stats count as request_count
        dc(uri_path) as unique_paths
        dc(clientip) as unique_src_ips
        min(_time) as firstTime max(_time) as lastTime
  by clientip, http_user_agent
| eval risk_score=case(
    request_count > 5000 AND unique_paths > 5, 90,
    request_count > 2000 AND match(http_user_agent, "(?i)python|curl|requests|aura|inspector"), 85,
    request_count > 1000, 75,
    request_count > 500 AND unique_paths > 3, 70,
    1=1, 40)
| where risk_score >= 70
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime lastTime clientip http_user_agent request_count unique_paths risk_score
```

**Supplemental: GraphQL introspection queries against Salesforce (bulk data extraction attempt)**

```spl
index=web sourcetype IN ("access_combined","nginx:plus:kv","iis","apache:access")
  uri_path="*/graphql"
| rex field=_raw "Content-Length:\s+(?<content_length>\d+)"
| eval content_length_kb=round(content_length/1024, 1)
| eval is_introspection=if(match(_raw, "__schema|__type|__introspection"), 1, 0)
| stats count as request_count
        sum(content_length_kb) as total_content_kb
        max(content_length_kb) as max_request_kb
        sum(is_introspection) as introspection_count
        min(_time) as firstTime max(_time) as lastTime
  by clientip, http_user_agent
| eval risk_score=case(
    introspection_count > 0 AND request_count > 10, 90,
    max_request_kb > 10240, 85,
    total_content_kb > 50000, 80,
    request_count > 200 AND max_request_kb > 1024, 75,
    1=1, 40)
| where risk_score >= 75
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime lastTime clientip http_user_agent request_count introspection_count total_content_kb max_request_kb risk_score
```

**Supplemental: Aura method enumeration — high volume of unique Aura controller calls**

```spl
index=web sourcetype IN ("access_combined","nginx:plus:kv","iis","apache:access")
  (uri_path="*/apex/*" OR uri_path="*/s/recordlist/*")
| rex field=uri_path "apex/(?<aura_controller>[^/?]+)"
| stats count as request_count
        dc(aura_controller) as unique_controllers
        min(_time) as firstTime max(_time) as lastTime
  by clientip
| eval risk_score=case(
    unique_controllers > 20 AND request_count > 100, 88,
    unique_controllers > 10 AND request_count > 50, 78,
    unique_controllers > 5 AND request_count > 20, 65,
    1=1, 40)
| where risk_score >= 65
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime lastTime clientip request_count unique_controllers risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| >5,000 Aura endpoint requests from single IP across >5 unique paths | 90 | Systematic enumeration pattern characteristic of AuraInspector-style scanning |
| GraphQL introspection query followed by >10 API calls | 90 | Introspection reveals available objects; subsequent calls are data extraction |
| Python/curl/requests user agent accessing Aura endpoint at volume | 85 | AuraInspector and similar tools use scripted HTTP clients, not browsers |
| Request payload >10 MB to GraphQL endpoint | 85 | Bulk record extraction via GraphQL batching to bypass per-request limits |
| >20 unique Aura controller endpoints accessed per IP | 88 | Systematic controller enumeration phase of an AuraInspector audit/attack |

## Associated Threat Actors

| Actor | Relationship to Detection |
|-------|--------------------------|
| Unattributed / opportunistic | No specific threat actor tied to AuraInspector exploitation in published reports as of April 2026; Mandiant released AuraInspector as a defensive auditing tool but the same techniques are available to attackers. Misconfigurations in Salesforce Aura deployments create broad exposure to credential theft and data exfiltration |

## References

- [Mandiant / Google - Auditing Salesforce Aura Data Exposure (April 2026)](https://cloud.google.com/blog/topics/threat-intelligence/auditing-salesforce-aura-data-exposure/)
- [MITRE ATT&CK - T1213 Data from Information Repositories](https://attack.mitre.org/techniques/T1213/)
- [MITRE ATT&CK - T1190 Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
- [Mandiant AuraInspector (GitHub)](https://github.com/mandiant/AuraInspector)
