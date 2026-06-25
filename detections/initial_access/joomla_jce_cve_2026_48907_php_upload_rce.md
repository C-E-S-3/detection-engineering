# Joomla JCE PHP Upload RCE (CVE-2026-48907)

## Description

Detects exploitation of CVE-2026-48907, a CVSS 10.0 critical vulnerability in the Widget Factory Joomla Content Editor (JCE) extension. The vulnerability allows unauthenticated attackers to create new JCE editor profiles via `/index.php?option=com_jce&task=plugin.save`, then upload PHP files that bypass Joomla's authentication gate. Successful exploitation results in a PHP webshell hosted in Joomla's `/images/stories/` directory, enabling full remote code execution.

Added to CISA KEV on 2026-06-16. Federal agencies must apply mitigations per BOD 26-04 by 2026-06-30.

**False positive sources:** Legitimate JCE plugin administration by Joomla admins will trigger the JCE component probing rules (102403, 102411). Rules anchored on PHP files in upload paths (102402, 102410) and successful POST exploitation rules (102401, 102406) are high-fidelity. The two-stage correlation rule (102409) represents confirmed attack activity.

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
| 102400 | 13 | POST to JCE plugin task endpoints (unauthenticated profile/upload) |
| 102401 | 15 | JCE plugin task returned 2xx — exploitation succeeded |
| 102402 | 15 | PHP file accessed in Joomla upload path — webshell execution |
| 102403 | 10 | JCE component access — fingerprinting probe |
| 102404 | 8 | Joomla administrator area access |
| 102405 | 13 | PHP extension in POST to Joomla — webshell upload attempt |
| 102406 | 15 | Successful PHP upload (2xx response) — webshell confirmed |
| 102407 | 13 | 5+ JCE probes in 60s — automated scanner |
| 102408 | 14 | JCE probing across multiple hosts — distributed campaign |
| 102409 | 15 | Two-stage: JCE probe then PHP access — confirmed attack |
| 102410 | 15 | Webshell command parameter in upload path |
| 102411 | 9 | JCE task/view endpoint access (broad anchor) |
| 102412 | 12 | JCE endpoint returned 2xx — unauthenticated access confirmed |

## Splunk Detection Query

```spl
index=web sourcetype=traefik_json
  (uri_path="*option=com_jce*" OR uri_path="*/images/stories/*.php*")
| eval jce_probe=if(match(uri_path,"option=com_jce"),1,0)
| eval php_upload=if(match(uri_path,"option=com_jce") AND match(http_method,"POST") AND match(uri_path,"task=plugin"),1,0)
| eval webshell_exec=if(match(uri_path,"/images/stories/.*\.php"),1,0)
| eval cmd_exec=if(match(uri_path,"(?:cmd=|command=|exec=|shell=)"),1,0)
| stats count as total_requests
    sum(jce_probe) as jce_probes
    sum(php_upload) as upload_attempts
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
    jce_probes >= 5, 60,
    1=1, 30)
| where risk_score >= 60
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table src_ip dest_host http_status jce_probes upload_attempts webshell_hits cmd_exec_hits paths risk_score
```

## Risk Score Logic

| Condition | Score | Rationale |
|-----------|-------|-----------|
| Command execution parameter in webshell path | 100 | Active webshell in use — confirmed RCE |
| Webshell access after PHP upload | 95 | Two-stage attack confirmed |
| PHP file in upload path accessed | 85 | Likely webshell execution |
| Successful PHP upload (2xx) | 90 | Upload confirmed, execution imminent |
| PHP upload attempt (any status) | 70 | Upload attempted, may have failed |
| 5+ JCE probes from single source | 60 | Automated scanner, elevated monitoring |

## Associated Threat Actors

| Actor | References |
|-------|-----------|
| Opportunistic attackers / mass scanning | [CISA KEV CVE-2026-48907](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) |
| Web application targeting groups | [MITRE T1190](https://attack.mitre.org/techniques/T1190/) |

## References

- [CISA KEV — CVE-2026-48907](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [NVD CVE-2026-48907](https://nvd.nist.gov/vuln/detail/CVE-2026-48907)
- [MITRE ATT&CK T1190](https://attack.mitre.org/techniques/T1190/)
- [MITRE ATT&CK T1505.003](https://attack.mitre.org/techniques/T1505/003/)
- [JCE Joomla Extension Security Advisory](https://www.joomlacontenteditor.net/support/security)
