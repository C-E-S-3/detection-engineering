# Detection Engineering Guide

Reference for adding, structuring, and maintaining detections in this repository.

---

## CRITICAL: Public Repository Safety Rules

**This is a PUBLIC repository.** The following content MUST NEVER be committed:

1. **Ansible playbooks, roles, or inventory files** — all infrastructure code belongs in private repos (inframan, ansible-builder)
2. **Internal hostnames** — no `*.eskridge.internal`, `*.svc.eskridge.internal`, or host-specific names (nucbox-*, pve-*, beelink-*, secops-*, protectli-*)
3. **Internal IP addresses** — no RFC1918 addresses from the homelab (10.0.42.x, 10.0.69.x, 172.16.4.x, etc.)
4. **Secrets infrastructure references** — no OpenBao/Vault URLs, secret paths, API credentials, or token references
5. **Network topology details** — no VLAN descriptions, jump host configurations, or deployment architecture

**Allowed content:** Detection rules (Splunk SPL, Wazuh XML), IOCs, threat intel reports, MITRE ATT&CK mappings, and detection documentation. All content must be generic and not reference the homelab environment.

---

## Repository Structure

```
detections/
├── _template.md
├── initial_access/
│   ├── README.md
│   └── <detection_name>.md
├── execution/
│   ├── README.md
│   └── <detection_name>.md
├── persistence/
│   ├── README.md
│   └── <detection_name>.md
├── defense_evasion/
│   ├── README.md
│   └── <detection_name>.md
├── credential_access/
│   ├── README.md
│   └── <detection_name>.md
├── lateral_movement/
│   ├── README.md
│   └── <detection_name>.md
├── command_and_control/
│   ├── README.md
│   └── <detection_name>.md
├── collection/
│   ├── README.md
│   └── <detection_name>.md
└── impact/
    ├── README.md
    └── <detection_name>.md
```

Category folders map to MITRE ATT&CK tactics. Place each detection in the folder matching its **primary** tactic.

---

## Adding a New Detection

### 1. Create the detection file

- Copy `detections/_template.md` into the appropriate category folder.
- Name the file using lowercase snake_case: `<threat_or_technique>_<brief_description>.md`
  - Examples: `gootloader_wscript_js_execution.md`, `suspicious_powershell_encoded_command.md`, `medusa_smb_lateral_movement.md`

### 2. Fill in all required metadata

Every detection file **must** contain these sections:

| Section | Description |
|---------|-------------|
| **Detection Name** | H1 header, clear and descriptive |
| **Description** | What behavior this detects, why it matters, and expected false positive sources |
| **MITRE ATT&CK Mapping** | Tactic ID (TAxxxx), Technique ID (Txxxx), and Sub-technique where applicable |
| **Lockheed Martin Kill Chain Phase** | Which phase(s): Reconnaissance, Weaponization, Delivery, Exploitation, Installation, C2, Actions on Objectives |
| **Splunk SPL Query** | The detection query in a fenced code block (```spl) |
| **Risk Score Logic** | Explanation of risk scoring thresholds if applicable |
| **Associated Threat Actors** | Known threat actors/malware families that use this technique |
| **References** | Links to threat intel, MITRE pages, vendor advisories |

### 3. Write the SPL query

**Use Splunk ES Data Models whenever possible.** Preferred data models:

| Data Model | Use For |
|------------|---------|
| `Endpoint.Processes` | Process execution, command lines, parent-child relationships |
| `Endpoint.Filesystem` | File creation, modification, deletion |
| `Endpoint.Registry` | Registry key/value modifications |
| `Endpoint.Services` | Service creation and modification |
| `Network_Traffic.All_Traffic` | Firewall, netflow, connection data |
| `Network_Resolution.DNS` | DNS queries and responses |
| `Web.Web` | HTTP/HTTPS requests (proxy, WAF) |
| `Authentication` | Login events, authentication failures |
| `Change` | Configuration and system changes |

**SPL conventions used in this repo:**

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Processes
where Processes.process_name="example.exe"
by Processes.dest Processes.user Processes.parent_process_name
   Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
```

Key patterns:
- Use `tstats` with `security_content_summariesonly` for accelerated data model searches.
- Use `drop_dm_object_name()` to strip the data model prefix from field names.
- Use `security_content_ctime()` to format time fields.
- Include `firstTime` and `lastTime` for analyst triage context.
- When risk scoring, use `eval risk_score=case(...)` with a `where risk_score >= <threshold>` filter.
- End with a `| table` listing the most relevant fields for triage.

**When raw index searches are necessary** (no applicable data model), use the source macro convention (e.g., `` `crowdstrike` ``, `` `o365` ``, `` `fortigate` ``).

### 4. Update the category README

After adding a detection, update the `README.md` in that category folder:
- Add the detection to the table of detections.
- If the detection covers a new threat actor, add the actor to the Threat Actors section with links.

### 5. File naming rules

- All lowercase, snake_case: `lazarus_dll_sideloading.md`
- Prefix with threat name when detection is threat-specific: `gootloader_registry_stuffing.md`
- Use generic technique name for broad detections: `suspicious_powershell_encoded_command.md`
- No spaces, no special characters beyond underscores.

---

## MITRE ATT&CK Tactic to Folder Mapping

| Folder | MITRE Tactic | Tactic ID | Kill Chain Phase |
|--------|-------------|-----------|------------------|
| `initial_access/` | Initial Access | TA0001 | Delivery |
| `execution/` | Execution | TA0002 | Exploitation |
| `persistence/` | Persistence | TA0003 | Installation |
| `defense_evasion/` | Defense Evasion | TA0005 | Exploitation / Installation |
| `credential_access/` | Credential Access | TA0006 | Actions on Objectives |
| `lateral_movement/` | Lateral Movement | TA0008 | Actions on Objectives |
| `command_and_control/` | Command and Control | TA0011 | C2 |
| `collection/` | Collection | TA0009 | Actions on Objectives |
| `impact/` | Impact | TA0040 | Actions on Objectives |

If a detection spans multiple tactics, place it in the **primary** tactic folder and note the secondary tactics in the MITRE mapping section of the file.

---

## Lockheed Martin Cyber Kill Chain Reference

Use these phase names in detection metadata:

1. **Reconnaissance** - Target identification and information gathering
2. **Weaponization** - Coupling an exploit with a backdoor into a deliverable payload
3. **Delivery** - Transmission of the weapon to the target (phishing, SEO poisoning, watering hole)
4. **Exploitation** - Triggering the payload (user execution, vulnerability exploitation)
5. **Installation** - Installing persistence mechanisms (scheduled tasks, registry, services)
6. **Command & Control (C2)** - Establishing a channel for remote control
7. **Actions on Objectives** - Achieving the mission (data exfil, ransomware, lateral movement)

---

## Risk Scoring Guidelines

Detections in this repo use a tiered risk scoring model:

| Risk Level | Score Range | Meaning |
|------------|------------|---------|
| Critical | 90-100 | High-confidence malicious activity, near-certain true positive |
| High | 75-89 | Strong indicator of compromise, requires immediate investigation |
| Medium | 50-74 | Suspicious activity, needs analyst review |
| Low | 25-49 | Anomalous but potentially benign, useful for correlation |
| Info | 0-24 | Context enrichment, not actionable alone |

When building composite risk scores (summing multiple risk factors), document each component and its weight.

---

## Category README Requirements

Each category folder's `README.md` must contain:

1. **Category description** - What this tactic covers
2. **Detection index** - Table listing all detections in the folder with name, MITRE technique, and brief description
3. **Threat actors** - Table of known threat actors that use techniques in this category, with links to:
   - MITRE ATT&CK group page
   - Relevant threat intelligence reports
   - Associated malware/tools

---

## Checklist for New Detections

Before committing a new detection, verify:

- [ ] File is in the correct category folder
- [ ] File follows naming convention (`lowercase_snake_case.md`)
- [ ] Description clearly states what is detected and why
- [ ] MITRE ATT&CK mapping includes tactic and technique IDs
- [ ] Lockheed Kill Chain phase is specified
- [ ] SPL query uses ES data models where applicable
- [ ] SPL follows repo conventions (`tstats`, `drop_dm_object_name`, `security_content_ctime`)
- [ ] Risk scoring logic is documented if present
- [ ] Known threat actors are listed
- [ ] Category README is updated with the new detection
- [ ] References section includes relevant links
