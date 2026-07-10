# Balbooa Forms Unrestricted File Upload RCE (CVE-2026-56291)

## Description

Detects exploitation of CVE-2026-56291, a CVSS 9.8 critical vulnerability in the Balbooa Forms component for Joomla. The vulnerability allows unauthenticated attackers to POST arbitrary files — including PHP webshells — to the component's upload endpoint (`/index.php?option=com_balbooa&task=form.upload`) without authentication or MIME-type validation. Successful exploitation results in a PHP webshell hosted under `/media/com_balbooa/` or `/images/com_balbooa/`, enabling full remote code execution.

Added to CISA KEV on 2026-07-10. Federal agencies must apply mitigations per BOD 26-04 by 2026-07-13.

**False positive sources:** Legitimate form submissions by end users will POST to `com_balbooa` but should not match the specific upload task variants. Rules for PHP file access in the Balbooa media path (103754, 103756) and successful upload responses (103753) are high-fidelity and should not produce false positives in normal operation.

## MITRE ATT&CK Mapping

| Field | Value |
|-------|-------|
| Tactic | Initial Access |
| Tactic ID | TA0001 |
| Technique | Exploit Public-Facing Application |
| Technique ID | T1190 |
| Secondary Technique | Server Software Component: Web Shell |
| Secondary Technique ID | T1505.003 |
| Tertiary Technique | Command and Scripting Interpreter: Unix Shell |
| Tertiary Technique ID | T1059.004 |

## Lockheed Martin Kill Chain

| Phase |
|-------|
| Exploitation |
| Installation |

## Wazuh Rules

| Rule ID | Level | Description |
|---------|-------|-------------|
| 103751 | 0 | POST to com_balbooa component (base anchor, no alert) |
| 103752 | 13 | POST to Balbooa Forms upload task — exploitation attempt |
| 103753 | 15 | Balbooa upload endpoint returned 2xx — webshell upload confirmed |
| 103754 | 15 | PHP file accessed in Balbooa media path — webshell execution |
| 103755 | 13 | 3+ upload probes in 60s from same IP — automated exploit tool |
| 103756 | 15 | Webshell command parameter in Balbooa media path — active execution |

## Splunk Detection Query

```spl
index=web sourcetype=traefik_json
  (uri_path="*option=com_balbooa*" OR uri_path="*/media/com_balbooa/*.ph*" OR uri_path="*/images/com_balbooa/*.ph*")
| eval upload_attempt=if(match(uri_path,"option=com_balbooa") AND match(http_method,"POST") AND match(uri_path,"task=form\.(upload|file|submit|save)"),1,0)
| eval webshell_exec=if(match(uri_path,"(?i)/(?:media|images)/com_balbooa/.*\.ph(?:p[3-8]?|tml)"),1,0)
| eval cmd_exec=if(match(uri_path,"(?:cmd=|command=|exec=|shell=|run=|system=)"),1,0)
| stats count as total_requests
    sum(upload_attempt) as upload_attempts
    sum(webshell_exec) as webshell_hits
    sum(cmd_exec) as cmd_exec_hits
    values(uri_path) as paths
    by src_ip dest_host http_status
| eval risk_score=case(
    cmd_exec_hits > 0, 100,
    webshell_hits > 0 AND upload_attempts > 0, 95,
    webshell_hits > 0, 85,
    upload_attempts > 0 AND http_status="200", 90,
    upload_attempts > 0, 70,
    1=1, 30)
| where risk_score >= 70
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table src_ip dest_host http_status upload_attempts webshell_hits cmd_exec_hits paths risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| Command execution parameter in webshell path | 100 | Active webshell in use — confirmed RCE |
| Webshell access after PHP upload | 95 | Two-stage attack confirmed |
| PHP file in Balbooa media path accessed | 85 | Likely webshell execution |
| Successful PHP upload (2xx) | 90 | Upload confirmed, execution imminent |
| PHP upload attempt (any status) | 70 | Upload attempted, may have failed |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| Opportunistic attackers / mass scanning | [CISA KEV CVE-2026-56291](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) |
| Web application targeting groups | [MITRE T1190](https://attack.mitre.org/techniques/T1190/) |

## References

- [CISA KEV — CVE-2026-56291](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [NVD CVE-2026-56291](https://nvd.nist.gov/vuln/detail/CVE-2026-56291)
- [MITRE ATT&CK T1190](https://attack.mitre.org/techniques/T1190/)
- [MITRE ATT&CK T1505.003](https://attack.mitre.org/techniques/T1505/003/)
- [ESKA-419: CISA KEV July 10 Batch](https://eskridge.paperclipai.com/ESKA/issues/ESKA-419)
