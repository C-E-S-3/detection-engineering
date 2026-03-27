---
scraped_at: 2024-06-10T15:00:00Z
source_url: https://www.zscaler.com/blogs/customer-stories/inter-s-data-security-journey-protecting-33-petabytes-zscaler
report_type: threat-intel
---

# Threat Intelligence Report: Inter’s Data Security Journey

**Note:** This source is a customer success story and strategic overview. It does not contain actionable threat intelligence such as IOCs, malware, or direct TTPs. Below is a structured analysis of the content, with explicit notes on the absence of threat indicators.

---

## 1. Indicators of Compromise (IOCs)

**No IOCs found.**  
The text does not provide any IP addresses, domains, URLs, file hashes, email addresses, file names, registry keys, mutexes, or C2 infrastructure details.

---

## 2. TTPs (MITRE ATT&CK Mapping)

**No direct TTPs observed.**  
The article discusses general security practices and solutions (e.g., DLP, DSPM, CASB, Zero Trust), but does not describe adversary techniques or attack chains.  
However, the following defensive security concepts are mentioned:

- Data Loss Prevention (DLP)
- Data Security Posture Management (DSPM)
- Zero Trust Access
- SSL/TLS Inspection
- Cloud and SaaS Security

These are not MITRE ATT&CK techniques, but rather defensive controls.

---

## 3. Malware & Tools

**No malware or offensive tools referenced.**  
The article only mentions legitimate security solutions and platforms:

- Zscaler Data Security Platform (DLP, DSPM, CASB)
- Zscaler Internet Access (ZIA)
- Zscaler Private Access (ZPA)
- Amazon Bedrock (for AI/LLM deployment)
- Deloitte (consulting partner)

No malware families, LOLBins, or custom offensive tooling are described.

---

## 4. Threat Actor / Campaign Attribution

**No threat actor or campaign attribution provided.**  
The article references a "recent breach resulting in the theft of 1 billion reals from Brazil’s financial system," but does not attribute this to any specific threat actor, campaign, or malware.

- No APT, cybercrime, or hacktivist group names
- No campaign names
- No specific motivations or targeting details beyond general financial sector risk

---

## 5. Splunk Detection Searches

**No actionable Splunk searches can be provided.**  
Without IOCs or adversary TTPs, there are no detection searches to recommend.  
However, organizations may consider monitoring for:

- Unusual data access patterns
- Excessive privilege usage
- Unauthorized data movement across cloud/SaaS/endpoints

Example (generic, not based on source):

```spl
# Detect excessive data access from privileged accounts (generic example)
index=cloud sourcetype=aws:cloudtrail action=GetObject OR action=DownloadObject user_role="Admin" 
| stats count by user_name, action, src_ip
| where count > 100
```
*Comment: This detects unusually high data access by privileged users, which may indicate insider risk or compromised accounts.*

---

## 6. Executive Summary

This Zscaler customer story details Inter’s journey to modernize data security for a digital-first financial institution managing 33 petabytes of sensitive data. The narrative highlights the transition from fragmented, legacy controls to unified, context-aware protection leveraging Zscaler’s Data Security platform, including DLP, DSPM, and AI security. While the article references the risk of large-scale breaches and regulatory penalties, it does not provide actionable threat intelligence or technical indicators. Organizations in the financial sector should prioritize unified data security, visibility, and adaptive controls to mitigate evolving risks, but no immediate threat actions are required based on this source.

---

**Conclusion:**  
This source is a strategic customer story and does not contain threat intelligence content (IOCs, TTPs, malware, or actor attribution). It is useful for understanding security best practices and technology adoption, but not for operational threat detection or response.
