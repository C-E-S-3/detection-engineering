---
scraped_at: 2026-11-03T00:00:00Z
source_url: https://cloud.google.com/blog/topics/threat-intelligence/llmjacking-monetizing-compromised-cloud-models
report_type: threat-intel
severity: high
title: "LLMJacking: Monetizing Compromised Cloud Models"
---

# LLMJacking: Monetizing Compromised Cloud Models

**Source:** Google GTIG / Mandiant  
**Published:** 2026-11-02  
**Severity:** High

---

## 1. IOCs

### Domains

| Indicator | Role |
|-----------|------|
| jet-night.com | LLM Mixer — fraudulent LLM relay service |
| newapi.pro | LLM Mixer — fraudulent LLM relay service |

### CVEs

| CVE | Product | Description |
|-----|---------|-------------|
| CVE-2026-40217 | LiteLLM (≤1.73.1) | Privilege escalation via malformed model routing request; allows unauthenticated caller to invoke admin-only API endpoints |

---

## 2. TTPs

| MITRE Technique | ID | Description |
|-----------------|-----|-------------|
| Resource Hijacking | T1496 | Stolen cloud credentials used to invoke LLM APIs at victim's expense; bills tens of thousands of dollars per day |
| Valid Accounts: Cloud Accounts | T1078.004 | Initial access via stolen IAM keys (exposed in public repositories, phishing, or infostealer output) |
| Unsecured Credentials | T1552 | Harvesting cloud API keys from source code repositories, environment files, and CI/CD pipeline logs |
| Impair Defenses: Disable Cloud Logs | T1562.008 | Disabling cloud audit logging to evade detection of LLM API calls |
| Exploit Public-Facing Application | T1190 | CVE-2026-40217 LiteLLM RCE for direct LLM platform compromise |
| Proxy: Multi-hop Proxy | T1090.003 | "LLM Mixer" relay services (jet-night.com, newapi.pro) aggregate stolen keys and resell LLM capacity |

---

## 3. Malware & Tools

| Name | Type | Notes |
|------|------|-------|
| LLM Mixer | Criminal relay service | Aggregates stolen cloud LLM credentials; sells discounted access via jet-night.com and newapi.pro |
| Custom credential harvesters | Infostealer variants | Modified infostealers targeting `~/.aws/credentials`, `.env` files, GitHub tokens |

---

## 4. Threat Actor Attribution

**Tracked cluster:** UNC6993 (Google GTIG designation)

UNC6993 is a financially motivated threat cluster operating LLMJacking campaigns since early 2026. The group harvests cloud provider credentials (AWS, GCP, Azure) with LLM API access, then either invokes models directly for resale revenue or routes victim API keys through LLM Mixer relay services at `jet-night.com` and `newapi.pro`. Downstream customers of these relay services receive discounted access to Claude, GPT-4, Gemini, and other frontier models paid for by the compromised victims.

CVE-2026-40217 added a direct exploitation vector: unauthenticated privilege escalation on exposed LiteLLM instances converts any internet-exposed LiteLLM proxy into a compromised LLM gateway without requiring credential theft.

Estimated victim costs range from $10,000 to $100,000+ per day depending on model usage and access scope.

---

## 5. Splunk Detection Searches

### Detection 1 — DNS Queries to Known LLM Mixer Domains

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

### Detection 2 — Cloud Audit Log: LLM Service Enabled by New Principal

```spl
`aws_cloudtrail`
  (eventName="CreateKey" OR eventName="EnableKey" OR eventName="InvokeModel" OR eventName="InvokeModelWithResponseStream")
  sourceIPAddress!="10.*" sourceIPAddress!="172.16.*" sourceIPAddress!="192.168.*"
| stats count min(_time) as firstTime max(_time) as lastTime values(eventName) as events
    by userIdentity.arn sourceIPAddress awsRegion
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(events, "InvokeModel") AND count > 100, 85,
    match(events, "InvokeModel"), 65,
    1=1, 50)
| where risk_score >= 50
| table firstTime lastTime userIdentity.arn sourceIPAddress awsRegion events count risk_score
```

### Detection 3 — Cloud Audit Log: LLM Logging Disabled

```spl
`aws_cloudtrail`
  (eventName="StopLogging" OR eventName="DeleteTrail" OR eventName="UpdateTrail")
  requestParameters.includeGlobalServiceEvents=false
| stats count min(_time) as firstTime max(_time) as lastTime values(eventName) as events
    by userIdentity.arn sourceIPAddress awsRegion
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=90
| table firstTime lastTime userIdentity.arn sourceIPAddress awsRegion events risk_score
```

### Detection 4 — LiteLLM CVE-2026-40217 Exploitation Attempt

```spl
`web`
  (uri_path="*/admin/model/new" OR uri_path="*/admin/config/update")
  (status=200 OR status=201 OR status=403)
  NOT (src_ip IN ("10.0.0.0/8","172.16.0.0/12","192.168.0.0/16"))
| stats count min(_time) as firstTime max(_time) as lastTime values(status) as statuses
    by src_ip uri_path dest
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(statuses,"200") OR match(statuses,"201"), 90,
    match(statuses,"403"), 60,
    1=1, 50)
| where risk_score >= 60
| table firstTime lastTime src_ip dest uri_path statuses count risk_score
```

---

## 6. Executive Summary

Google GTIG published an analysis of LLMJacking on November 2, 2026, expanding on earlier reporting of cloud-credential-based LLM abuse. The core technique is simple: threat actors harvest valid cloud IAM credentials with access to LLM API services (Amazon Bedrock, Vertex AI, Azure OpenAI), then invoke models at scale to generate revenue by reselling access through gray-market relay services — primarily `jet-night.com` and `newapi.pro`, collectively termed "LLM Mixers."

A new exploitation vector was added by CVE-2026-40217 in LiteLLM ≤1.73.1, which allows privilege escalation on exposed LiteLLM instances without requiring credential theft. Combined with credential harvesting, the campaign attributed to cluster UNC6993 inflicts costs of $10,000–$100,000+ per day on victims before detection.

Detection priority: monitor DNS for LLM Mixer domains, alert on cloud audit log disablement events, and monitor LiteLLM admin API access from non-RFC1918 sources. Any environment hosting an internet-exposed LiteLLM instance should patch to ≥1.73.2 immediately.
