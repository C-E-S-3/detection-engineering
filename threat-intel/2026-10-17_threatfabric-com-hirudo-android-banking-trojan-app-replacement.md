---
scraped_at: 2026-10-17T00:00:00Z
source_url: https://www.threatfabric.com/blogs/hirudo-from-fake-updates-to-patched-banking-apps
report_type: threat-intel
severity: high
title: "Hirudo Android Banking Trojan — App Replacement to Bypass Security Checks"
---

# Hirudo Android Banking Trojan — App Replacement to Bypass Security Checks

**Source:** ThreatFabric  
**Published:** 2026-10-13 to 2026-10-16  
**Severity:** High

---

## 1. IOCs

No public IOCs (hashes, domains, IPs) were available in secondary reporting. ThreatFabric's original report contains an IOC appendix accessible to paying subscribers. The following dropper application names are known:

| Type | Value | Context |
|------|-------|---------|
| App name | Shopora | Hirudo dropper — shopping theme |
| App name | 1V1 X | Hirudo dropper — adult content theme |
| App name | KoiShort | Hirudo dropper — short drama theme |
| App name | ZoyaTV | Hirudo dropper — video streaming theme |
| Infrastructure | Amazon CloudFront | Hosting platform for dropper APK delivery (CDN-based evasion) |

*No file hashes, C2 domains, or IP addresses were publicly disclosed as of 2026-10-17.*

---

## 2. TTPs

| MITRE ID | Technique | Description |
|----------|-----------|-------------|
| T1655.001 | Masquerading: Match Legitimate Name or Location (Mobile) | Hirudo uninstalls the legitimate banking app and installs a patched trojanized copy with the same package name and icon |
| T1411 | Input Capture: GUI Input Capture (Mobile) | Trojanized app captures credentials and PINs entered in the fake banking UI via internal hooking engine |
| T1513 | Screen Capture (Mobile) | WebRTC-based live screen streaming to attacker; real-time viewing without victim awareness |
| T1429 | Capture Audio (Mobile) | Remote camera activation; live video feed exfiltrated to attacker |
| T1412 | Capture SMS Messages (Mobile) | SMS interception to steal OTPs and 2FA codes |
| T1407 | Download New Code at Runtime (Mobile) | Dropper apps delivered via CloudFront download and install the banking app replacements at runtime |
| T1630.001 | Indicator Removal on Host: Uninstall Malicious Application (inverted) | Uninstalls the legitimate banking app to replace it; also disables Google Play Integrity API checks |
| T1418.001 | Software Discovery: Security Software Discovery (Mobile) | Internal hooking engine blinds Accessibility service monitors, signature verification, and Google Play Protect |

**Novel TTP — App Replacement:**  
Hirudo's defining technique is uninstalling the legitimate banking application and silently replacing it with a patched copy. The patched copy disables all security checks internally (Play Integrity API, code signature verification, Accessibility service monitoring), making the trojan invisible to on-device security mechanisms. This technique was not previously documented in public ThreatFabric reporting.

---

## 3. Malware & Tools

| Name | Type | Notes |
|------|------|-------|
| Hirudo | Android Banking Trojan / RAT | Named by ThreatFabric; combines credential theft via app replacement with full RAT capabilities (WebRTC screen share, remote camera, SMS theft). Internal code references banks in Indonesia, China, India, Mexico, Morocco, and Thailand. |
| Dropper APKs | Android Dropper | Disguised as entertainment apps (Shopora, 1V1 X, KoiShort, ZoyaTV); delivered via Amazon CloudFront |

---

## 4. Threat Actor Attribution

| Field | Value |
|-------|-------|
| Attribution | Unknown, financially motivated |
| Language indicators | Chinese-language backend administration panel observed |
| Geographic focus | Indonesia (primary); bank code references suggest planned expansion to China, India, Mexico, Morocco, Thailand |
| Infrastructure | Amazon CloudFront (CDN) for dropper delivery; exposed backend analyzed by ThreatFabric in August 2026 containing thousands of stolen credential and device records |
| Motivation | Financial fraud — credential theft, account takeover of mobile banking applications |

---

## 5. Splunk Detection Searches

These searches require Android MDM/EMM telemetry in Splunk (Workspace ONE, Jamf, Microsoft Intune, or similar). Replace the `` `mdm` `` macro with the appropriate index/sourcetype for your environment.

**Search 1 — Banking App Uninstall Followed by Rapid Reinstall (App Replacement Pattern)**

```spl
`mdm` action IN ("app_uninstalled", "app_installed")
    app_category="finance"
| eval event_pair=case(action="app_uninstalled", "uninstall", action="app_installed", "install", 1=1, "other")
| stats
    values(action) as actions
    min(_time) as firstTime
    max(_time) as lastTime
    dc(action) as action_count
    by device_id user app_package_name
| where action_count >= 2
    AND (lastTime - firstTime) <= 300
| eval time_diff_sec = lastTime - firstTime
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    time_diff_sec <= 60, 85,
    time_diff_sec <= 300, 70,
    1=1, 55)
| where risk_score >= 70
| table firstTime lastTime device_id user app_package_name actions time_diff_sec risk_score
```

**Search 2 — Accessibility Service Enabled by Non-System App**

```spl
`mdm` event_type="accessibility_service_enabled"
    NOT app_package_name IN ("com.google.*", "com.android.*", "com.samsung.*")
| stats count min(_time) as firstTime max(_time) as lastTime by device_id user app_package_name service_name
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=75
| table firstTime lastTime device_id user app_package_name service_name risk_score
```

**Search 3 — App Installation from Non-Play-Store Source**

```spl
`mdm` event_type="app_installed" install_source NOT IN ("com.android.vending", "com.google.android.packageinstaller")
    app_category="finance"
| stats count min(_time) as firstTime max(_time) as lastTime by device_id user app_package_name install_source
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=80
| table firstTime lastTime device_id user app_package_name install_source risk_score
```

---

## 6. Executive Summary

ThreatFabric disclosed Hirudo, a novel Android banking trojan, in October 2026. The malware introduces an industry-first technique: rather than overlaying a fake UI over legitimate banking apps, Hirudo completely uninstalls the target banking application and reinstalls a patched trojanized copy in its place. The patch disables all security checks internally, including Google Play Integrity API validation, code signature verification, and Accessibility service monitoring, rendering the trojan invisible to on-device security tools.

Hirudo is distributed via dropper applications (Shopora, 1V1 X, KoiShort, ZoyaTV) hosted on Amazon CloudFront. Once installed, it provides the attacker with a full RAT capability including WebRTC-based live screen viewing, remote camera access, SMS interception, and credential capture.

The backend infrastructure, observed in August 2026, used a Chinese-language administration panel and contained thousands of stolen device records and credentials. Current targeting is focused on Indonesian banks, with internal code referencing expansion targets including China, India, Mexico, Morocco, and Thailand.

No specific IOCs (hashes, domains, IPs) are publicly available. Detection requires Android MDM/EMM telemetry integrated with Splunk and monitoring for the behavioral patterns described above.

---

## References

- [ThreatFabric — Hirudo: From Fake Updates to Patched Banking Apps](https://www.threatfabric.com/blogs/hirudo-from-fake-updates-to-patched-banking-apps)
- [BleepingComputer — Hirudo Android malware replaces banking apps to evade security checks](https://www.bleepingcomputer.com/news/security/hirudo-android-malware-replaces-banking-apps-to-evade-security-checks/)
- [SecurityOnline — Hirudo Banking Trojan Android Apps](https://securityonline.info/hirudo-banking-trojan-android-apps/)
- [MITRE ATT&CK — T1655.001 Masquerading: Match Legitimate Name or Location (Mobile)](https://attack.mitre.org/techniques/T1655/001/)
- [MITRE ATT&CK — T1411 Input Capture: GUI Input Capture (Mobile)](https://attack.mitre.org/techniques/T1411/)
- [MITRE ATT&CK — T1513 Screen Capture (Mobile)](https://attack.mitre.org/techniques/T1513/)
- [MITRE ATT&CK — T1412 Capture SMS Messages (Mobile)](https://attack.mitre.org/techniques/T1412/)
