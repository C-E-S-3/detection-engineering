---
scraped_at: 2026-11-03T00:00:00Z
source_url: https://cloud.google.com/blog/topics/threat-intelligence/shutting-the-door-on-the-xcpe-botnet
report_type: threat-intel
severity: high
title: "Shutting the Door on the XCPE Botnet"
---

# Shutting the Door on the XCPE Botnet

**Source:** Google GTIG / Mandiant  
**Published:** 2026-11-02  
**Severity:** High

---

## 1. IOCs

### Domains — MQTT C2 / Bootstrap

| Indicator | Role |
|-----------|------|
| szbboys.com | Primary MQTT C2 broker domain |
| mqtt.szbboys.com | MQTT broker subdomain |
| ott.szbboys.com | MQTT broker subdomain |
| anyevonline.com | Bootstrap / device registration C2 |
| intermedia-arts.tv | Fallback C2 (system package delivery) |
| yokatvonline.com | Fallback C2 (system package delivery) |

### Domains — Affiliate Module C2

| Indicator | Affiliate |
|-----------|-----------|
| linkfog.cn | Linkfog residential proxy |
| cloudbrokerapi.xyz | Linkfog |
| dddlink.link | Linkfog |
| smrtai.cc | Linkfog |
| bkdomain.cn | Linkfog |
| columbus2024.com | Linkfog |
| bd-devmetrics.net | Jaguar residential proxy |
| tx-devmetrics.net | Jaguar residential proxy |
| bestipip.com | IPWeb/BWM residential proxy |
| fecebbbk.xyz | IPWeb/BWM |
| guangzhouroot.com | IPWeb/BWM |
| amhib.com | Bird ad fraud |
| disview.com | Bird ad fraud |
| prataw.com | Bird ad fraud |
| auqee.com | Bird ad fraud |
| alptk.com | Bird ad fraud |
| mfiny.com | Bird ad fraud |
| leisurepuz.com | Bird ad fraud |
| earn.fm | EarnFM affiliate |
| geo-loadbalanced.com | EarnFM affiliate |
| collection.shixunsuda.com | Fission affiliate |
| analysis.shixunsuda.com | Fission affiliate |
| gtxvdqvuweqs.com | GaGaNode/IPCola affiliate |
| hiddeninplainsight.top | HiddenView affiliate |
| dgjm.online | Spirit affiliate |
| drgdj.top | Spirit affiliate |
| spiritlib.cyou | Spirit affiliate |
| dmurdce.xyz | Moyu affiliate |
| edisajalsjfdfh.shop | Moyu affiliate |
| ty4523.space | Moyu affiliate |

### IP Addresses

| Indicator | Role |
|-----------|------|
| 219.134.163.210 | MQTT C2 broker (TCP 3885–3887) |
| 219.134.163.211 | MQTT C2 broker (TCP 3885–3887) |
| 23.94.49.57 | File hosting / auxiliary C2 |
| 38.145.197.135 | File hosting / auxiliary C2 |

### File Hashes (SHA-256)

| Hash | Description |
|------|-------------|
| 3768f470934a111f1c3e3d098eb1392a3cb6f3e298ef5fd2a6309e6a98ee1e18 | x.cpe — XCPE primary backdoor (preinstalled firmware) |
| 350d6db477e8567cf9347c1144b3a0b25550e7ce63bb800b056b8a7a8ef56af4 | com.oemservice — XCPE dropper module |
| 1f2ab93c35f0c37d9b88f82268183a2f77491aa6b142a48381524b18e217b960 | com.abc.nexus — loader / execution engine |
| fda3c8fdf7849814e270bbbc00adfa1e15ba8977f5b2508df5febf5dbd3075b2 | com.vs.grass — utility module |
| b3690b3b013ac60752a6d05c3f53ea1f3e844d4603c5b90d258a30c596d0691b | libseccomp_guard.so — anti-analysis hook |
| ebcca22b96f7a30ae155efa2f25af29a369c6e9cfc99cb3bb0b72f35bc5528ed | com.android.sso.auth.handler — dropper |
| 42be8f18d6006ca092de191331d38e70a0d8383db701a759466dec59a0986135 | libexploit.so — privilege escalation |
| 7830ce3c3222dd9b25a77a16116dcf832a24b4b9a0bc998501e12415a828fb42 | libnative_keys.so — key storage |
| d4011b684ba389bf0b2dd8ded74fe8a4729b1cad4e6c18cfd928cb99a625a6e4 | Bird affiliate APK |
| cd8ef4ba20823b926b45a04946f24e45a7bcd4bf2bfc439cac8061a43f146903 | Linkfog affiliate APK |
| 331d3a1cf85656c3657e97bab6f15b6e4ce30bf319069b22e8356dccac230321 | Linkfog affiliate ELF |
| d3b94a74121e885bc698c8f56b9433247139be29b40ae1d0655dd558ecf5f9fa | Jaguar affiliate APK |
| e2bfca7225af84f116de7ed10e4ad425d0ebfd6e19903d226b9768282865700f | Jaguar affiliate ELF |
| d48cffc6d7e7c06f2d3db34ce6d4a53d5c25636179b7087a1e762f5d6bfa07f5 | AppSalt affiliate APK |
| 69116e8f681ea312e7e9e3a8a436f66b3e98566c621412599ecaaa25348daadb | Spirit affiliate APK |
| f2ed4a40fbb21d0560e82bdd2e85e825970d32052348241b487dd93191ebef2a | Moyu / GaGaNode / Netnut affiliate APK |
| a63757715b35ddd99916b63a1354de1ec05ac5855a480fe9a547b002e2091dcb | Traffmonetizer affiliate ELF |
| 9e18c113eb8d2ba813199c7f90e26d80af3124d871fc31eea7253319a8406e8e | EarnFM libfleetshare.so |
| 742b7ad8b95d4e0784c914f2b84706124f5a86a404e0fd479a0a97a784c2bb9e | Fission affiliate APK |
| a6c7ef9b6d5277dada145361164ff79e1e6c6be1cd28f6739113c72ee30ea4cc | HiddenView affiliate APK |

---

## 2. TTPs

| MITRE Technique | ID | Description |
|-----------------|-----|-------------|
| Supply Chain Compromise: Compromise Hardware Supply Chain | T1195.003 | Backdoor pre-installed by OEM (Videostrong Technology Co.) in Android firmware on set-top boxes |
| Non-Application Layer Protocol | T1095 | MQTT C2 over TCP 3885–3887 (non-standard MQTT ports) |
| Implant Internal Image | T1525 | `x.cpe` and `com.oemservice` embedded in device firmware partition |
| Impair Defenses | T1562 | Disables Google Play Protect and prevents app uninstallation |
| Resource Hijacking | T1496 | Devices enrolled as residential proxies and ad fraud nodes against victim will |
| Proxy: Multi-hop Proxy | T1090.003 | Enrolled devices form residential proxy pool (Linkfog, Jaguar, IPWeb/BWM affiliates) |
| Boot or Logon Autostart Execution | T1547 | Persistence via Android system partition (survives factory reset) |

---

## 3. Malware & Tools

| Name | Type | Notes |
|------|------|-------|
| XCPE (`x.cpe`) | Android firmware backdoor | Pre-installed in `/system` partition by Videostrong; MQTT C2; modular affiliate loader |
| com.oemservice | Dropper | Loads and installs affiliate modules at MQTT C2 direction |
| com.abc.nexus | Loader / execution engine | Manages module lifecycle |
| libseccomp_guard.so | Anti-analysis | Hooks `seccomp` to detect and evade analysis environments |
| libexploit.so | Privilege escalation | Used to maintain root on non-rooted devices where possible |
| Bird | Ad fraud APK | Background ad impression fraud |
| Linkfog | Residential proxy APK + ELF | Routes commercial proxy traffic through device |
| Jaguar | Residential proxy APK + ELF | Alternative residential proxy affiliate |
| IPWeb/BWM | Residential proxy | Bandwidth monetization |
| Traffmonetizer | ELF residential proxy | Linux bandwidth monetization |
| EarnFM | Bandwidth sharing | libfleetshare.so |
| Fission | Ad fraud | APK-based ad fraud |
| HiddenView | Ad fraud | APK-based ad fraud |
| Spirit | Ad fraud | APK-based |
| GaGaNode / IPCola | Residential proxy | P2P network node |
| Moyu | Ad fraud | APK-based |
| AppSalt | Ad fraud / proxy | APK-based |

---

## 4. Threat Actor Attribution

**Attribution:** Videostrong Technology Co. (Chinese OEM/ODM manufacturer)

Videostrong manufactures Android-based set-top boxes sold under numerous white-label brand names globally. Google GTIG assessed with high confidence that Videostrong deliberately embedded XCPE as a preinstalled backdoor across its product line. The botnet comprises 1.3 million+ infected devices across North America, Europe, and Asia-Pacific. The operator monetizes the botnet via affiliate agreements with residential proxy and ad fraud platforms, receiving revenue for each enrolled device.

No nation-state tasking has been identified; the operation is assessed as financially motivated.

---

## 5. Splunk Detection Searches

### Detection 1 — DNS Queries to Known XCPE C2 Domains

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Network_Resolution.DNS
where DNS.query IN (
  "szbboys.com", "mqtt.szbboys.com", "ott.szbboys.com",
  "anyevonline.com", "intermedia-arts.tv", "yokatvonline.com",
  "linkfog.cn", "cloudbrokerapi.xyz", "dddlink.link",
  "smrtai.cc", "bkdomain.cn", "columbus2024.com",
  "bd-devmetrics.net", "tx-devmetrics.net",
  "bestipip.com", "fecebbbk.xyz", "guangzhouroot.com",
  "amhib.com", "disview.com", "prataw.com",
  "auqee.com", "alptk.com", "mfiny.com", "leisurepuz.com",
  "earn.fm", "geo-loadbalanced.com",
  "collection.shixunsuda.com", "analysis.shixunsuda.com",
  "gtxvdqvuweqs.com", "hiddeninplainsight.top",
  "dgjm.online", "drgdj.top", "spiritlib.cyou",
  "dmurdce.xyz", "edisajalsjfdfh.shop", "ty4523.space"
)
by DNS.src DNS.query DNS.record_type
| `drop_dm_object_name(DNS)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    query IN ("szbboys.com","mqtt.szbboys.com","ott.szbboys.com"), 95,
    query IN ("anyevonline.com","intermedia-arts.tv","yokatvonline.com"), 90,
    1=1, 75)
| where risk_score >= 75
| table firstTime lastTime src query record_type risk_score
```

### Detection 2 — MQTT C2 on Non-Standard Ports to Known XCPE IPs

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Network_Traffic.All_Traffic
where (All_Traffic.dest_port=3885 OR All_Traffic.dest_port=3886 OR All_Traffic.dest_port=3887)
  AND All_Traffic.dest IN ("219.134.163.210","219.134.163.211","23.94.49.57","38.145.197.135")
by All_Traffic.src All_Traffic.dest All_Traffic.dest_port All_Traffic.action
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=100
| table firstTime lastTime src dest dest_port action risk_score
```

### Detection 3 — Outbound MQTT on Non-Standard Ports (Behavioral, No IOC Required)

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Network_Traffic.All_Traffic
where (All_Traffic.dest_port=3885 OR All_Traffic.dest_port=3886 OR All_Traffic.dest_port=3887)
  AND All_Traffic.direction="outbound"
by All_Traffic.src All_Traffic.dest All_Traffic.dest_port
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=70
| table firstTime lastTime src dest dest_port risk_score
```

---

## 6. Executive Summary

Google GTIG published a detailed analysis of the XCPE botnet on November 2, 2026. XCPE is a firmware-level Android backdoor pre-installed by Videostrong Technology Co., a Chinese OEM/ODM manufacturer, across its set-top box product line. The backdoor (`x.cpe` / package `com.oemservice`) resides in the Android system partition and survives factory resets. It establishes MQTT C2 connectivity to `szbboys.com` on non-standard TCP ports 3885–3887, then downloads and installs affiliate modules from a library of 10+ commercial residential proxy and ad fraud services (Linkfog, Jaguar, Bird, EarnFM, Fission, HiddenView, Spirit, Moyu, GaGaNode, Traffmonetizer, AppSalt).

Google GTIG estimates 1.3 million+ devices were compromised at peak. The operator earns revenue by leasing device bandwidth and ad impressions to affiliate platforms. Devices affected include set-top boxes sold under numerous white-label brands globally.

Detection priority: environments with IoT/BYOD device populations should monitor for DNS resolution of the XCPE C2 domain list and outbound TCP connections on ports 3885–3887.
