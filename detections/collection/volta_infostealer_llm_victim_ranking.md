# VOLTA Infostealer — LLM API Abuse and Artifact Detection

## Description

Detects activity associated with the VOLTA infostealer, a Windows credential harvester that uses LLM APIs (Claude, Gemini, Kimi via OpenRouter) to rank victims by financial value. VOLTA drops characteristic artifact files in `%APPDATA%` (`volta_debug.txt`, `volta_dox.zip`, `volta_doxnet.zip`) during execution. The malware is distributed via phishing with password-protected archives and uses randomized binary filenames per victim. False positive risk for the filesystem detection is extremely low; the LLM API network detection may fire on developer workstations with AI tooling.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Collection |
| Tactic ID | TA0009 |
| Technique | Data from Local System |
| Technique ID | T1005 |

**Secondary tactics:** Credential Access (TA0006 — T1555, T1539), Defense Evasion (TA0005 — T1027)

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Actions on Objectives |

## Splunk Detection Query

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Filesystem
  where Filesystem.file_name IN ("volta_debug.txt", "volta_dox.zip", "volta_doxnet.zip")
    AND Filesystem.file_path="*\\AppData\\*"
  by Filesystem.dest Filesystem.user Filesystem.file_name Filesystem.file_path Filesystem.process_id
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=90
| where risk_score >= 50
| table firstTime lastTime dest user file_name file_path process_id risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| Any VOLTA artifact filename present in `%APPDATA%` | 90 | These filenames are unique to VOLTA; presence is near-certain indicator of compromise |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| Unknown (VOLTA campaign operator) | [Cisco Talos — VOLTA Infostealer](https://blog.talosintelligence.com/volta-infostealer-llm-victim-ranking/) |

## References

- [Cisco Talos: VOLTA Infostealer — LLM-Assisted Victim Prioritization (2026-10-31)](https://blog.talosintelligence.com/volta-infostealer-llm-victim-ranking/)
- [MITRE ATT&CK T1005 — Data from Local System](https://attack.mitre.org/techniques/T1005/)
- [MITRE ATT&CK T1555 — Credentials from Password Stores](https://attack.mitre.org/techniques/T1555/)
