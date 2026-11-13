---
scraped_at: 2026-11-13T00:00:00Z
source_url: https://unit42.paloaltonetworks.com/cairn-framework-ai-autonomous-attacks/
report_type: threat-intel
severity: critical
title: "CL-STA-1238: 25 Autonomous AI-Assisted Attacks Using Cairn Framework Against Semiconductor, Defense, and Civil Society"
---

# CL-STA-1238: 25 Autonomous AI-Assisted Attacks Using Cairn Framework

**Source:** Unit 42 (Palo Alto Networks)  
**Published:** 2026-11-12  
**Severity:** Critical  
**Tracking ID:** CL-STA-1238  

## Summary

Unit 42 published research documenting a China-nexus threat cluster (CL-STA-1238) that conducted 25 autonomous attack operations against at least 19 organizations between August and September 2026. Unauthorized access or confirmed data retrieval was established at 10 of the targeted organizations.

The attackers used a customized fork of the open-source Cairn AI penetration testing framework enhanced with a proprietary exploitation skill pack not present in the public project. The fork was hosted on a server in Hong Kong. AI models used were Zhipu GLM 5.2 and DeepSeek V4 Flash/Pro — domestic Chinese LLMs rather than Western models, consistent with operational security practices aligned with Chinese state-linked actors.

**Targeted sectors:** Semiconductor manufacturing, defense, and civil society organizations.  
**Attribution confidence:** Moderate (China-nexus intelligence collection).

## Technical Details

**Attack Framework:** Cairn (open-source agentic pentesting framework), custom fork with proprietary exploitation skill pack  
**AI Models:** Zhipu GLM 5.2, DeepSeek V4 Flash/Pro  
**Hosting:** Hong Kong server  
**Initial Access Methods:** Authentication bypasses, exposed APIs, and weak credentials  
**Scale:** 25 autonomous operations against 19 organizations; confirmed breach at 10  

The AI raised the volume and coverage of exploitation attempts but not the technical complexity of individual exploits. The exploited weaknesses were foundational security hygiene failures (exposed APIs, auth bypasses, default credentials) rather than novel zero-days.

## Threat Significance

This report represents publicly confirmed operational use of AI-autonomous attack frameworks for real-world targeted intrusion campaigns at scale against critical infrastructure. Unlike AI-assisted human operator models, CL-STA-1238 demonstrates autonomous end-to-end attack chains achieving confirmed data retrieval.

The choice of Zhipu and DeepSeek over Western LLMs suggests deliberate alignment with Chinese domestic AI infrastructure, reducing exposure to Western provider logging and content policies.

**Defensive implications:** Expect increased attack volume and parallelism from AI-autonomous frameworks. Identity hardening and exposure reduction of APIs and authentication surfaces are the primary controls.

## Indicators of Compromise

No specific network IOCs (domains, IPs, hashes) were published in available sources as of this report.

**Behavioral indicators:**
- High-velocity, automated-pace authentication attempts across multiple API endpoints without human-pattern timing
- Rapid sequential API enumeration and fuzzing
- Exploitation of multiple distinct authentication bypass techniques within a single session timeline
- Access patterns inconsistent with legitimate user behavior (simultaneous multi-path enumeration)

## MITRE ATT&CK Mapping

| Tactic | ID | Technique |
|--------|-----|-----------|
| Initial Access | TA0001 | T1133 — External Remote Services |
| Initial Access | TA0001 | T1190 — Exploit Public-Facing Application |
| Credential Access | TA0006 | T1110 — Brute Force |
| Discovery | TA0007 | T1046 — Network Service Discovery |
| Collection | TA0009 | T1213 — Data from Information Repositories |

## Associated Threat Actors

| Actor | Description | References |
|-------|-------------|-----------|
| CL-STA-1238 | China-nexus intelligence collection cluster; autonomous AI-assisted attacks targeting semiconductor, defense, civil society (Aug–Sep 2026) | [Unit 42 Report](https://unit42.paloaltonetworks.com/cairn-framework-ai-autonomous-attacks/) |

## References

- [Unit 42 — Attackers Use Autonomous AI to Target Semiconductor, Defense and Civil Society Sectors](https://unit42.paloaltonetworks.com/cairn-framework-ai-autonomous-attacks/)
- [Help Net Security — Attackers breached 10 organizations with an open-source AI pentest framework](https://www.helpnetsecurity.com/2026/11/12/cairn-autonomous-ai-cyberattacks/)
- [CSO Online — Palo Alto tracks a massive Chinese AI attack](https://www.csoonline.com/article/4247565/palo-alto-tracks-a-massive-chinese-ai-attack-that-sadly-lives-up-to-industry-fears.html)
- [DEV Community — CL-STA-1238: 25 Autonomous Attacks Using Cairn](https://dev.to/anoymask/cl-sta-1238-25-autonomous-attacks-using-cairn-unauthorized-access-or-data-retrieval-confirmed-at-j6a)
