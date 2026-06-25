# QUIETVAULT AI-Assisted Credential Stealer

## Description

Detects QUIETVAULT, a novel credential stealer that leverages locally-installed AI command-line tools (e.g., Ollama, `llm` CLI, GPT4All) to intelligently search for configuration files, credentials, and sensitive data on compromised hosts. Unlike traditional credential stealers that use hardcoded regex patterns, QUIETVAULT queries a local LLM at runtime to identify high-value file paths and extract secrets — making it more adaptive and harder to detect via signature-based rules. The technique represents a new class of AI-augmented malware identified in M-Trends 2026. Key detection pivot: unexpected process spawning from AI CLI tools, or AI processes accessing credential stores and configuration files outside their normal operational context. Common false positives: developers legitimately using AI tools for coding assistance; tune on the child process tree and file-access paths to distinguish dev usage from malicious use.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Credential Access |
| Tactic ID | TA0006 |
| Technique | Unsecured Credentials: Credentials in Files |
| Technique ID | T1552.001 |

Secondary techniques: T1083 (File and Directory Discovery — AI-guided enumeration of config paths), T1005 (Data from Local System — collection of discovered credentials), T1059.001 (Command and Scripting Interpreter: PowerShell — post-discovery command execution), T1027 (Obfuscated Files or Information — LLM output used to avoid static signatures)

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Exploitation |
| Actions on Objectives |

## Splunk Detection Query

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.parent_process_name IN ("ollama.exe","ollama","llm","gpt4all","lmstudio",
      "koboldcpp","llamafile","jan","msty","openwebui")
    AND Processes.process_name IN ("cmd.exe","powershell.exe","bash","sh","python.exe","python3",
        "find.exe","where.exe","dir","ls","cat","type","more")
  by Processes.dest Processes.user Processes.parent_process_name
     Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| eval risk_score=case(
    match(process, "(?i)\.aws|\.ssh|id_rsa|id_ed25519|\.pem|\.key"), 95,
    match(process, "(?i)password|passwd|credential|secret|token|api.key"), 90,
    match(process, "(?i)\.env|config\.ini|settings\.py|web\.config|appsettings"), 85,
    match(process, "(?i)\.git/config|\.npmrc|\.docker/config|kubeconfig|\.kube"), 85,
    match(process, "(?i)AppData.*Roaming|AppData.*Local.*Pass"), 80,
    1=1, 65)
| where risk_score >= 80
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

**Supplemental: AI process accessing credential file paths (file system audit)**

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Filesystem
  where Filesystem.process_name IN ("ollama.exe","ollama","llm","gpt4all","lmstudio",
      "koboldcpp","llamafile","jan","msty")
    AND (Filesystem.file_path="*\\AppData\\Roaming\\*\\passwords*"
         OR Filesystem.file_path="*/.aws/*"
         OR Filesystem.file_path="*/.ssh/id_*"
         OR Filesystem.file_path="*/.kube/config"
         OR Filesystem.file_path="*/.npmrc"
         OR Filesystem.file_path="*/.docker/config.json"
         OR Filesystem.file_path="*/credentials"
         OR Filesystem.file_path="*/.env"
         OR Filesystem.file_path="*/secrets.yml"
         OR Filesystem.file_path="*/secrets.yaml")
  by Filesystem.dest Filesystem.user Filesystem.process_name Filesystem.file_path Filesystem.action
| `drop_dm_object_name(Filesystem)`
| eval risk_score=case(
    match(file_path, "(?i)id_rsa|id_ed25519|\.pem|\.p12|\.pfx"), 95,
    match(file_path, "(?i)\.aws/credentials|kubeconfig|\.kube/config"), 92,
    match(file_path, "(?i)\.ssh/|\.npmrc|\.docker/config"), 88,
    match(file_path, "(?i)\.env|secrets\.(yml|yaml|json)"), 85,
    1=1, 75)
| where risk_score >= 85
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime lastTime dest user process_name file_path action risk_score
```

**Supplemental: Suspicious AI CLI invocation with credential-related prompt (command line)**

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.process_name IN ("ollama.exe","ollama","llm","gpt4all","llamafile")
    AND (Processes.process="*find*password*" OR Processes.process="*find*credential*"
         OR Processes.process="*list*secret*" OR Processes.process="*config*file*"
         OR Processes.process="*extract*key*" OR Processes.process="*locate*token*")
  by Processes.dest Processes.user Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| eval risk_score=case(
    match(process, "(?i)password|credential|secret|api.key|token"), 85,
    match(process, "(?i)find|locate|search|list.*file"), 70,
    1=1, 60)
| where risk_score >= 70
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime lastTime dest user process_name process risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| AI CLI spawning shell accessing AWS/SSH credential files | 95 | SSH private keys and AWS credentials are primary QUIETVAULT targets; AI tool has no legitimate reason to read these |
| AI process accessing kubeconfig or .docker/config.json | 92 | Cloud/container credentials are high-value targets; AI tool filesystem access here is anomalous |
| AI CLI spawning child process accessing .env / secrets files | 85–90 | Application secrets files; QUIETVAULT uses LLM to identify which config files hold credentials |
| AI CLI command line containing credential-search prompt terms | 70–85 | Direct evidence of QUIETVAULT's LLM-querying behavior; "find password" style prompts in CLI |
| AI process spawning powershell.exe / cmd.exe | 65 | Lateral movement after discovery; baseline dev workflows to tune FP rate |

## Associated Threat Actors

| Actor | Relationship to Detection |
|-------|--------------------------|
| UNC (unnamed cluster) | QUIETVAULT identified in M-Trends 2026 as a novel credential stealer using local AI command-line tools to search for configuration files containing credentials; specific actor attribution not yet confirmed |

## References

- [Google M-Trends 2026](https://cloud.google.com/blog/topics/threat-intelligence/m-trends-2026/)
- [MITRE ATT&CK - T1552.001 Unsecured Credentials: Credentials in Files](https://attack.mitre.org/techniques/T1552/001/)
- [MITRE ATT&CK - T1083 File and Directory Discovery](https://attack.mitre.org/techniques/T1083/)
- [MITRE ATT&CK - T1005 Data from Local System](https://attack.mitre.org/techniques/T1005/)
