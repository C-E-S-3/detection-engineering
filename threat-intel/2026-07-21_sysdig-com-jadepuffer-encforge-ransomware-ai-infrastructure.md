---
scraped_at: 2026-07-25T01:00:00Z
source_url: https://www.sysdig.com/blog/jadepuffer-evolves-the-agentic-threat-actor-deploys-ransomware-built-to-destroy-ai-models
report_type: threat-intel
severity: critical
title: "JADEPUFFER Deploys ENCFORGE Ransomware Targeting AI Model Infrastructure"
---

# JADEPUFFER Deploys ENCFORGE Ransomware Targeting AI Model Infrastructure

**Source:** Sysdig Threat Research Team  
**Published:** ~2026-07-21  
**Severity:** Critical

## Summary

JADEPUFFER, an agentic threat actor previously associated with automated database extortion campaigns, has evolved its toolset to deploy ENCFORGE — a purpose-built ransomware designed to destroy AI and machine learning model infrastructure. Where prior JADEPUFFER campaigns used scripted lateral movement to exfiltrate and ransom database contents, this new phase targets AI model files directly, including trained weights, datasets, and pipeline artifacts. Sysdig attributes the shift to the increasing financial value of proprietary AI model assets.

ENCFORGE exploits CVE-2025-3248, the unauthenticated remote code execution vulnerability in Langflow's `/api/v1/validate/code` endpoint (CVSS 9.8), to gain initial execution on AI pipeline servers. Once deployed, ENCFORGE performs mass encryption targeting approximately 180 AI/ML-specific file extensions using AES-256-CTR for file content and RSA-2048 for key encryption.

## Threat Actor

**JADEPUFFER** — agentic threat actor; uses automated AI-assisted reconnaissance and exploitation pipelines targeting AI/ML infrastructure. First documented by Sysdig in early 2026 targeting exposed Langflow instances for database extortion. No confirmed nation-state attribution; assessed financially motivated.

## Attack Chain

1. **Initial Access:** Exploit CVE-2025-3248 in exposed Langflow instances (default port 7860 or 443) — unauthenticated POST to `/api/v1/validate/code` executes arbitrary Python
2. **Execution:** Python reverse shell or wget/curl to download ENCFORGE ELF binary to `/tmp`
3. **Discovery:** ENCFORGE enumerates mounted filesystems and NFS/CIFS shares for model storage directories
4. **Impact:** Mass encryption of AI/ML model files; ransom note `ENCFORGE_README.txt` dropped per directory; C2 beacon to 34.153.223[.]102:9191 (TLS) with host ID and encrypted key material

## Malware: ENCFORGE

| Property | Detail |
|----------|--------|
| Type | Ransomware (Linux ELF) |
| Language | Go |
| Packer | UPX (obfuscation via UPX header manipulation) |
| Encryption | AES-256-CTR (file content) + RSA-2048 (key wrap) |
| Targeted Extensions | ~180 AI/ML: `.h5`, `.hdf5`, `.safetensors`, `.pkl`, `.pickle`, `.pt`, `.pth`, `.bin`, `.weights`, `.ckpt`, `.onnx`, `.pb`, `.tflite`, `.npy`, `.npz`, `.parquet`, `.arrow`, `.feather`, `.joblib`, `.model`, `.caffemodel`, `.prototxt`, `.t7`, `.mar`, `.pmml`, `.cbm`, `.lgbm`, `.xgb` and others |
| Ransom Note | `ENCFORGE_README.txt` per encrypted directory |
| C2 | 34.153.223[.]102:9191 (TLS, Google Cloud VM) |
| Anti-recovery | Unlinks original files after encryption; does not target VSS (Linux-focused) |

## IOCs

| Type | Indicator | Context |
|------|-----------|---------|
| SHA256 | `ea7822eac6cecef7746c606b862b4d3034856caf754c4cf69533662637905328` | ENCFORGE unpacked ELF binary |
| IP | `34.153.223[.]102` | C2 server, TCP 9191, TLS, Google Cloud |

## MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|--------|-----------|----|
| Initial Access | Exploit Public-Facing Application | T1190 |
| Execution | Command and Scripting Interpreter: Python | T1059.006 |
| Discovery | File and Directory Discovery | T1083 |
| Discovery | Network Share Discovery | T1135 |
| Impact | Data Encrypted for Impact | T1486 |
| C2 | Application Layer Protocol: Web Protocols | T1071.001 |

## Lockheed Martin Kill Chain

Exploitation → Actions on Objectives

## Detections

- `detections/execution/python_web_framework_os_command_execution.md` — covers Langflow RCE initial access (CVE-2025-3248)
- `detections/impact/encforge_ai_model_ransomware_encryption.md` — NEW detection for ENCFORGE AI/ML file targeting

## References

- [Sysdig — JADEPUFFER Deploys ENCFORGE Ransomware (2026-07-21)](https://www.sysdig.com/blog/jadepuffer-evolves-the-agentic-threat-actor-deploys-ransomware-built-to-destroy-ai-models)
- [NVD — CVE-2025-3248 (Langflow unauthenticated RCE)](https://nvd.nist.gov/vuln/detail/CVE-2025-3248)
- [Sysdig — JADEPUFFER: Agentic Ransomware for Automated Database Extortion (2026-07-04)](https://www.sysdig.com/blog/jadepuffer-agentic-ransomware-for-automated-database-extortion)
- [MITRE ATT&CK — T1486 Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486/)
- [MITRE ATT&CK — T1190 Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
