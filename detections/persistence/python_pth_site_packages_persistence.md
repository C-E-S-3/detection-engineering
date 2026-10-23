# Python .pth File Site-Packages Persistence

## Description

Detects creation of unexpected `.pth` files in Python `site-packages` directories. Python automatically executes code in `.pth` files beginning with `import` on every Python interpreter startup — making this a stealthy persistence mechanism that triggers before user code runs, bypasses most application-level security controls, and survives `pip uninstall` of the attacker's primary package if the `.pth` file is planted by a postinstall hook.

This technique was used in the October 2026 LiteLLM 1.107.0 supply chain attack (`cook.pth`) and is a recurring pattern in PyPI supply chain compromises (e.g., TeamPCP/UNC6780's LiteLLM CVE-2026-42271 attack). False positives exist: some legitimate Python packages install `.pth` files as part of their normal operation (e.g., editable `pip install -e` installs create `.pth` files). Tune by baseline-whitelisting known-good `.pth` files in your environment.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Persistence |
| Tactic ID | TA0003 |
| Technique | Event Triggered Execution |
| Technique ID | T1546 |
| Secondary Tactic | Initial Access |
| Secondary Tactic ID | TA0001 |
| Secondary Technique | Supply Chain Compromise: Compromise Software Dependencies |
| Secondary Technique ID | T1195.001 |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Installation |

## Splunk Detection Query

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Filesystem
    where (Filesystem.file_path="*/site-packages/*.pth"
           OR Filesystem.file_path="*\\site-packages\\*.pth")
        AND Filesystem.action IN ("created","modified","write")
        AND NOT (Filesystem.process_name IN ("pip","pip3","pip2","pip.exe","pip3.exe",
                                              "python","python3","python.exe","python3.exe",
                                              "uv","uv.exe","poetry","poetry.exe",
                                              "conda","conda.exe","mamba","mamba.exe",
                                              "setup.py","easy_install","installer"))
    by Filesystem.dest Filesystem.user Filesystem.process_name
       Filesystem.file_path Filesystem.file_name Filesystem.process_id
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(file_name, "(?i)(cook|payload|loader|persist|boot|start|init|auto|run|exec|hook)\.pth"), 90,
    match(process_name, "(?i)(curl|wget|bash|sh|cmd|powershell|pwsh|node|npm|npx)"), 85,
    NOT match(process_name, "(?i)(pip|python|uv|poetry|conda|mamba|setup)"), 70,
    1=1, 50)
| where risk_score >= 50
| table firstTime lastTime dest user process_name file_path file_name process_id risk_score
```

**Supplemental raw-index query (for environments without Endpoint data model acceleration):**

```spl
index=endpoint_logs (source="*sysmon*" OR source="*auditd*")
(EventCode=11 OR type="create" OR type="write")
(TargetFilename="*site-packages*.pth" OR path="*site-packages*.pth")
NOT (Image="*pip*" OR Image="*python*" OR Image="*uv*" OR Image="*conda*")
| eval risk_score=case(
    match(TargetFilename,"(?i)(cook|loader|persist)\.pth"), 90,
    1=1, 65)
| where risk_score >= 65
| table _time host user Image TargetFilename risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| `.pth` filename matches common malware naming patterns (cook, payload, loader, etc.) | 90 | High-confidence supply chain indicator — matches LiteLLM attack pattern |
| `.pth` created by shell/download tool (curl, bash, node, npm) | 85 | Package manager tooling expected; shells and downloaders are not |
| `.pth` created by any process outside known Python package managers | 70 | Unexpected writer for site-packages directory |
| Any non-package-manager `.pth` creation | 50 | Warrants investigation |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| Unknown (LiteLLM 1.107.0 supply chain) | [BerriAI GitHub Issue #47826](https://github.com/BerriAI/litellm/issues/47826) |
| TeamPCP (UNC6780) | [MITRE ATT&CK G1009 — TeamPCP](https://attack.mitre.org/groups/G1009/) |

## References

- [BerriAI GitHub Issue #47826 — LiteLLM 1.107.0 Compromise](https://github.com/BerriAI/litellm/issues/47826)
- [StepSecurity — litellm 1.107.0 Compromised on PyPI](https://www.stepsecurity.io/blog/litellm-1-107-0-compromised-pypi-backdoored-wheels-credential-stealer)
- [Python docs — site.py and .pth files](https://docs.python.org/3/library/site.html)
- [MITRE T1546 — Event Triggered Execution](https://attack.mitre.org/techniques/T1546/)
- [MITRE T1195.001 — Supply Chain Compromise: Software Dependencies](https://attack.mitre.org/techniques/T1195/001/)
