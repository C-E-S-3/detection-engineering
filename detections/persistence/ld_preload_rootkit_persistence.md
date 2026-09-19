# Linux LD_PRELOAD Rootkit Persistence via /etc/ld.so.preload

## Description

Detects installation of LD_PRELOAD rootkits on Linux systems, a technique where a malicious shared library is registered in `/etc/ld.so.preload` so it is automatically injected into every dynamically linked process on the system. This allows the rootkit to intercept and patch standard library calls (readdir, stat, opendir, etc.) to hide its own files, processes, and network connections from administrative tools.

The primary indicator is any write to `/etc/ld.so.preload`. Secondary indicators include creation or modification of shared libraries in standard library paths with suspicious naming patterns. The SIXZUT rootkit (used by Red Heron) uses this technique with the disguised filename `libglthread.so.2`.

**False positive sources:** Legitimate security software or debugging tools that use LD_PRELOAD injection (e.g., `libsegfault.so`, `libtcmalloc.so`). These should be allowlisted by process name or known library path. Modification of `/etc/ld.so.preload` should be exceptionally rare outside of initial system configuration.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| **Tactic** | Persistence (TA0003) |
| **Technique** | Hijack Execution Flow: Dynamic Linker Hijacking (T1574.006) |
| **Sub-technique** | LD_PRELOAD via /etc/ld.so.preload |

**Secondary Techniques:**
- Defense Evasion: Rootkit (T1014) — SIXZUT patches 15 Linux functions to hide artifacts
- Defense Evasion: Indicator Removal (T1070) — hidden processes and network connections

## Lockheed Martin Kill Chain Phase

**Installation**

## Splunk SPL Query

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Filesystem
  where Filesystem.file_path="/etc/ld.so.preload"
     OR Filesystem.file_name="libglthread.so.2"
     OR (Filesystem.file_path IN ("/lib/*", "/lib64/*", "/usr/lib/*", "/usr/lib64/*")
         AND Filesystem.file_name="*.so*"
         AND Filesystem.action=created)
  by Filesystem.dest Filesystem.user Filesystem.file_path Filesystem.file_name
     Filesystem.process_name Filesystem.process_path Filesystem.action
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    file_path="/etc/ld.so.preload", 90,
    file_name="libglthread.so.2", 90,
    match(file_name, "lib[a-z]{4,8}thread"), 70,
    action="created" AND match(file_path, "^/(lib|usr/lib)"), 50,
    true(), 40)
| where risk_score >= 50
| table firstTime lastTime dest user file_path file_name process_name process_path action risk_score
```

## Risk Score Logic

| Score | Condition |
|-------|-----------|
| 90 | Write to `/etc/ld.so.preload` — nearly always malicious outside initial OS config |
| 90 | File `libglthread.so.2` created or modified — SIXZUT rootkit (Red Heron) specific indicator |
| 70 | Library filename matching the pattern `lib[4-8 char word]thread` in library paths — suspicious masquerading pattern used by LD_PRELOAD rootkits |
| 50 | New `.so` file created in `/lib` or `/usr/lib` paths by a non-package-manager process — anomalous but requires context |

## Associated Threat Actors

| Actor | Malware | Campaign |
|-------|---------|---------|
| Red Heron | SIXZUT (deployed as `libglthread.so.2`) | Multinational Gitea CVE-2026-60004 exploitation campaign; 13 organizations compromised across 5+ countries; espionage focus; disclosed September 2026 |
| Generic rootkit operators | Diamorphine, Reptile, Azazel, Necro | LD_PRELOAD rootkits are a common Linux stealth persistence technique used across multiple threat actors and penetration testing frameworks |

## References

- [Acronis TRU: Red Heron exploits Gitea n-day flaw exposing new Linux rootkit (SIXZUT)](https://www.acronis.com/en/tru/posts/red-heron-exploits-gitea-n-day-flaw-in-multinational-campaign-exposing-new-linux-rootkit/)
- [MITRE ATT&CK T1574.006 — Dynamic Linker Hijacking](https://attack.mitre.org/techniques/T1574/006/)
- [MITRE ATT&CK T1014 — Rootkit](https://attack.mitre.org/techniques/T1014/)
- [Linux Persistence Techniques: /etc/ld.so.preload](https://attack.mitre.org/techniques/T1574/006/)
- [Threat Intel: 2026-09-19_acronis-tru-red-heron-jitterly-sixzut-gitea.md]
