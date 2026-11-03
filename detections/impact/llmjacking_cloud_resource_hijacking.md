# LLMJacking: Cloud LLM Resource Hijacking

## Description

Detects cloud LLM resource hijacking ("LLMJacking"), where threat actors use stolen cloud IAM credentials to invoke LLM APIs (Amazon Bedrock, Vertex AI, Azure OpenAI) at the victim's expense, or exploit CVE-2026-40217 in exposed LiteLLM instances to achieve the same without credential theft. Stolen capacity is resold through LLM Mixer relay services (jet-night.com, newapi.pro). Victim costs can reach $10,000–$100,000+ per day before detection.

False positives for the DNS IOC query are negligible. Cloud audit log queries may produce false positives from legitimate high-volume LLM usage; tune the count threshold and principal whitelist for your environment.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Impact |
| Tactic ID | TA0040 |
| Technique | Resource Hijacking |
| Technique ID | T1496 |
| Secondary Tactic | Credential Access |
| Secondary Tactic ID | TA0006 |
| Secondary Technique | Unsecured Credentials |
| Secondary Technique ID | T1552 |
| Tertiary Technique | Valid Accounts: Cloud Accounts |
| Tertiary Technique ID | T1078.004 |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Actions on Objectives |

## Splunk Detection Query

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Network_Resolution.DNS
where DNS.query IN ("jet-night.com","newapi.pro")
by DNS.src DNS.query DNS.record_type
| `drop_dm_object_name(DNS)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=90
| table firstTime lastTime src query record_type risk_score
```

**Supplemental — AWS Bedrock anomalous InvokeModel from external IP:**

```spl
`aws_cloudtrail`
  eventName IN ("InvokeModel","InvokeModelWithResponseStream","Converse","ConverseStream")
  NOT (sourceIPAddress="10.*" OR sourceIPAddress="172.16.*" OR sourceIPAddress="192.168.*"
       OR sourceIPAddress="amazonaws.com")
| stats count min(_time) as firstTime max(_time) as lastTime
    values(eventName) as events values(requestParameters.modelId) as models
    by userIdentity.arn sourceIPAddress awsRegion errorCode
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    isnull(errorCode) AND count > 500, 90,
    isnull(errorCode) AND count > 100, 75,
    isnull(errorCode), 55,
    1=1, 40)
| where risk_score >= 55
| table firstTime lastTime userIdentity.arn sourceIPAddress awsRegion events models count risk_score
```

**Supplemental — Cloud audit log disablement prior to LLM abuse:**

```spl
`aws_cloudtrail`
  eventName IN ("StopLogging","DeleteTrail","UpdateTrail","PutEventSelectors")
| stats count min(_time) as firstTime max(_time) as lastTime values(eventName) as events
    by userIdentity.arn sourceIPAddress awsRegion
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=90
| table firstTime lastTime userIdentity.arn sourceIPAddress awsRegion events risk_score
```

**Supplemental — LiteLLM CVE-2026-40217 admin endpoint access from external IP:**

```spl
`web`
  (uri_path="*/admin/model/new" OR uri_path="*/admin/config/update"
   OR uri_path="*/admin/user/new" OR uri_path="*/key/generate")
  NOT (src_ip="10.*" OR src_ip="172.16.*" OR src_ip="192.168.*")
| stats count min(_time) as firstTime max(_time) as lastTime values(status) as statuses
    by src_ip dest uri_path http_method
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(statuses,"200") OR match(statuses,"201"), 90,
    match(statuses,"403"), 60,
    1=1, 50)
| where risk_score >= 60
| table firstTime lastTime src_ip dest uri_path http_method statuses count risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| DNS query to LLM Mixer relay domain | 90 | Confirmed LLMJacking infrastructure; near-certain malicious |
| Unauthenticated external LLM API call volume >500 | 90 | High-volume resource hijacking in progress |
| Unauthenticated external LLM API call volume >100 | 75 | Moderate-volume suspected hijacking |
| Any external unauthenticated LLM API call | 55 | Anomalous; requires investigation |
| Cloud audit log disabled | 90 | Pre-attack logging suppression; high urgency |
| LiteLLM admin endpoint 200/201 from external | 90 | CVE-2026-40217 exploit success |
| LiteLLM admin endpoint 403 from external | 60 | CVE-2026-40217 exploit attempt (failed) |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| UNC6993 | [Google GTIG — LLMJacking (2026-11-02)](https://cloud.google.com/blog/topics/threat-intelligence/llmjacking-monetizing-compromised-cloud-models) |
| PoeLLM / Canto Incognito (LiteLLM targeting) | [Lumen Black Lotus Labs — Canto Incognito (2026-10-07)](https://www.lumen.com/blog/en-us/canto-incognito-tracking-the-poellm-malware) |

## References

- [Google GTIG — LLMJacking: Monetizing Compromised Cloud Models (2026-11-02)](https://cloud.google.com/blog/topics/threat-intelligence/llmjacking-monetizing-compromised-cloud-models)
- [MITRE ATT&CK — T1496: Resource Hijacking](https://attack.mitre.org/techniques/T1496/)
- [MITRE ATT&CK — T1078.004: Valid Accounts: Cloud Accounts](https://attack.mitre.org/techniques/T1078/004/)
- [MITRE ATT&CK — T1562.008: Impair Defenses: Disable Cloud Logs](https://attack.mitre.org/techniques/T1562/008/)
- [CVE-2026-40217 — LiteLLM Privilege Escalation](https://nvd.nist.gov/vuln/detail/CVE-2026-40217)
