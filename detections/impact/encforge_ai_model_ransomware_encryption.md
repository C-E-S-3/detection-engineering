# ENCFORGE Ransomware: AI/ML Model File Mass Encryption (JADEPUFFER)

## Description

Detects mass encryption of AI and machine learning model files by ENCFORGE ransomware, deployed by the JADEPUFFER agentic threat actor via Langflow RCE (CVE-2025-3248). ENCFORGE is a Go-based Linux ransomware that targets approximately 180 AI/ML-specific file extensions including trained model weights (`.h5`, `.safetensors`, `.pt`, `.onnx`, `.pkl`), datasets (`.parquet`, `.npy`, `.npz`), and pipeline artifacts (`.ckpt`, `.joblib`). This differentiates it from traditional ransomware — where typical ransomware encrypts documents and business files indiscriminately, ENCFORGE specifically seeks out AI model repositories and dataset stores.

The detection monitors two complementary signals: (1) high-volume file renaming/modification activity concentrated on AI/ML file extensions, and (2) creation of ENCFORGE-specific ransom notes (`ENCFORGE_README.txt`). On Linux hosts, also monitor for UPX-packed ELF binary execution from `/tmp` or `/dev/shm`, which is characteristic of the JADEPUFFER initial access pattern after Langflow RCE.

False positives for the file extension detection: AI/ML training pipelines that checkpointing large model batches may trigger the threshold. Tune by suppressing known training frameworks (PyTorch, TensorFlow, Keras) that write model files as part of normal training jobs. The ransom note detection has no expected false positives.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Impact |
| Tactic ID | TA0040 |
| Technique | Data Encrypted for Impact |
| Technique ID | T1486 |
| Secondary Tactic | Initial Access |
| Secondary Tactic ID | TA0001 |
| Secondary Technique | Exploit Public-Facing Application |
| Secondary Technique ID | T1190 |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Actions on Objectives |

## Splunk Detection Query

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Filesystem
  where Filesystem.action IN ("created","modified","renamed")
    AND (match(Filesystem.file_name,
         "(?i)\.(h5|hdf5|safetensors|pt|pth|pkl|pickle|ckpt|onnx|pb|tflite|npy|npz|parquet|arrow|feather|joblib|model|caffemodel|prototxt|t7|mar|pmml|cbm|lgbm|xgb|bin|weights)$"))
  by Filesystem.dest Filesystem.user Filesystem.process_name _time
| `drop_dm_object_name(Filesystem)`
| bucket _time span=1m
| stats count as ai_file_ops_per_min by dest user process_name _time
| where ai_file_ops_per_min > 50
| eval risk_score=case(
    ai_file_ops_per_min > 500, 97,
    ai_file_ops_per_min > 200, 92,
    ai_file_ops_per_min > 50,  80,
    1=1, 70)
| stats min(risk_score) as risk_score max(ai_file_ops_per_min) as peak_ai_file_ops
    min(_time) as firstTime max(_time) as lastTime
  by dest user process_name
| where risk_score >= 80
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime lastTime dest user process_name peak_ai_file_ops risk_score
```

**Supplemental: ENCFORGE ransom note creation**

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Filesystem
  where Filesystem.action="created"
    AND Filesystem.file_name="ENCFORGE_README.txt"
  by Filesystem.dest Filesystem.user Filesystem.process_name Filesystem.file_path Filesystem.file_name
| `drop_dm_object_name(Filesystem)`
| eval risk_score=100
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime lastTime dest user process_name file_path file_name risk_score
```

**Supplemental: UPX-packed ELF execution from writable temp path (Linux — JADEPUFFER post-exploitation)**

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where (match(Processes.process, "(?i)/tmp/|/dev/shm/|/var/tmp/"))
    AND Processes.parent_process_name IN ("python","python3","gunicorn","uvicorn","langflow","sh","bash")
  by Processes.dest Processes.user Processes.parent_process_name Processes.parent_process
     Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| eval risk_score=case(
    match(parent_process, "(?i)langflow|gunicorn|uvicorn"), 95,
    match(process, "(?i)/dev/shm/"), 92,
    match(process, "(?i)/tmp/"), 85,
    1=1, 80)
| where risk_score >= 85
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime lastTime dest user parent_process_name parent_process process_name process risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| ENCFORGE_README.txt created anywhere | 100 | Definitive ransomware indicator — no legitimate process creates this file |
| >500 AI/ML file ops/min | 97 | Mass encryption in progress; time-sensitive response required |
| >200 AI/ML file ops/min | 92 | High-confidence encryption; correlate with process and user context |
| >50 AI/ML file ops/min | 80 | Suspicious AI file activity; may be training checkpoint, investigate |
| ELF from /tmp or /dev/shm via Python web parent | 95 | JADEPUFFER post-Langflow-RCE execution pattern; direct path to ENCFORGE deployment |
| ELF from /dev/shm via any parent | 92 | Memory-resident execution to avoid disk forensics |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| JADEPUFFER | [Sysdig — JADEPUFFER Deploys ENCFORGE (2026-07-21)](https://www.sysdig.com/blog/jadepuffer-evolves-the-agentic-threat-actor-deploys-ransomware-built-to-destroy-ai-models) |
| JADEPUFFER (prior campaign) | [Sysdig — JADEPUFFER: Agentic Ransomware (2026-07-04)](https://www.sysdig.com/blog/jadepuffer-agentic-ransomware-for-automated-database-extortion) |

## References

- [Sysdig — JADEPUFFER Deploys ENCFORGE Ransomware (2026-07-21)](https://www.sysdig.com/blog/jadepuffer-evolves-the-agentic-threat-actor-deploys-ransomware-built-to-destroy-ai-models)
- [NVD — CVE-2025-3248 (Langflow unauthenticated RCE)](https://nvd.nist.gov/vuln/detail/CVE-2025-3248)
- [MITRE ATT&CK — T1486 Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486/)
- [MITRE ATT&CK — T1190 Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
