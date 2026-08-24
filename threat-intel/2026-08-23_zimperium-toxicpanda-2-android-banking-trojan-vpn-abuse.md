---
scraped_at: 2026-08-24T00:00:00Z
source_url: https://zimperium.com/blog/the-toxicpanda-never-sleeps-toxicpanda-2.0-prepares-its-next-strike-on-mobile
report_type: threat-intel
severity: high
title: "ToxicPanda 2.0 — Android Banking Trojan Abuses VPN Permissions, ADB Wireless Debugging, and WebSocket C2 (349 Financial Apps, 16 Countries)"
---

# ToxicPanda 2.0 — Android Banking Trojan Abuses VPN Permissions, ADB Wireless Debugging, and WebSocket C2

**Source:** Zimperium zLabs (report + IOC repository at github.com/Zimperium/IOC/tree/master/2026-08-ToxicPanda); BleepingComputer 2026-08-23
**Published:** 2026-08-23
**Severity:** High
**Threat Actor:** Unattributed cybercrime operator ("TGR-CRI-*"-style tracking); ToxicPanda/TgToxic evolution — Asian-origin operators expanded to Europe and LATAM in 2024, now global

---

## 1. IOCs

### C2 domains

| Indicator | Context |
|-----------|---------|
| cctvv2[.]com | ToxicPanda 2.0 panel/C2 (`/panel` endpoint) |
| www[.]v17001[.]com | ToxicPanda 2.0 panel/C2 (`/panel` endpoint) |
| www[.]w17907[.]com | ToxicPanda 2.0 panel/C2 (`/panel` endpoint) |
| g8688808[.]com | ToxicPanda 2.0 panel/C2 |
| googleplaydown[.]com | Phishing distribution — fake Google Play download portal serving APK payloads |

### Distribution URLs / AWS S3 buckets and Telegram bot deliveries

| Indicator | Context |
|-----------|---------|
| xcmtxc1oam1[.]s3[.]ap-south-1[.]amazonaws[.]com | ToxicPanda 2.0 payload staging bucket (ap-south-1) |
| ui920fht4m1[.]s3[.]mx-central-1[.]amazonaws[.]com | ToxicPanda 2.0 payload staging bucket (mx-central-1) |
| osy4u8pmu[.]s3[.]ap-southeast-1[.]amazonaws[.]com | ToxicPanda 2.0 payload staging bucket (ap-southeast-1) |
| ejjsi5fbl[.]s3[.]ap-southeast-1[.]amazonaws[.]com | ToxicPanda 2.0 payload staging bucket (ap-southeast-1) |
| svhc5arco[.]s3[.]ap-southeast-1[.]amazonaws[.]com | ToxicPanda 2.0 payload staging bucket (ap-southeast-1) |
| api[.]telegram[.]org/file/bot8331125434:AAEsxWq7_xZWUjN0IFLO3fTU54ZCBnZS4YI/documents/file_22526.apk | ToxicPanda 2.0 APK delivered via Telegram Bot API |
| api[.]telegram[.]org/file/bot8978201863:AAG4vnsJVOAbABfF6dXhhM8YJ14pd5LaxVw/documents/file_1389.apk | ToxicPanda 2.0 APK delivered via Telegram Bot API |
| https://googleplaydown[.]com/dUyFpz0Ai7Sp | ToxicPanda 2.0 phishing lure URL |

### File hashes (SHA-256) — dropper/APK stage (Zimperium `apks.csv`, subset)

| Hash | Context |
|------|---------|
| 3c76887d942a2a1c02455070887e14015ea9fe63fc9e4777bfbc633ba29601d5 | ToxicPanda 2.0 APK |
| 6174d8867e02177913dd28e17e67aac03a0be80f6cf2640a53a2ec8dd68c8f03 | ToxicPanda 2.0 APK |
| 6ca69f5ecdfefb9e267745407b4400534dcacf25b500ac88a40ad267ab86b336 | ToxicPanda 2.0 APK |
| 5890f6378baf86d74d0cfdc9ed6a46f9e769da12512d645eb6f1d8a868b349ea | ToxicPanda 2.0 APK |
| e8a4d5ad6fdf97ebd647f6e4ab218c18bb624114d445785b9579a80427ae6d67 | ToxicPanda 2.0 APK |
| da240b9352248448e3875c9a47679070c42801a0c426d2daba3854470d99bd43 | ToxicPanda 2.0 APK |
| 6a622b79aa2634b0ce77b6d2126ab575a8225f79b4c4c3b05cf520738a2b874b | ToxicPanda 2.0 APK |
| a6a9babbd8c3ffd0801ccdaded12b55b7a3195289337a22145f0e4ece7984cbf | ToxicPanda 2.0 APK |
| 35e7357982afa73e75e23b5be7e0cf550059f0a2b30cc499f60e24a8185abf6d | ToxicPanda 2.0 APK |
| ce65703cd7cca1f110494588b697dbd1d682be4f162437b1ee03c1aad4b24692 | ToxicPanda 2.0 APK |
| 051942c62e42763b18f55397e8019286c0feaff024a627d06acdf3dd1789b9bf | ToxicPanda 2.0 APK |
| 72a8fe68b4af92d3a45bfc38fa6a0c823fe82369c301f48a374451107b244368 | ToxicPanda 2.0 APK |
| f5557345f710d937cb1f61bdb11f6409b24416bb7d32bf4465f98439b079a291 | ToxicPanda 2.0 APK |
| 9b33c1f05f1c3cfce73b08ce7f480623611096492d427b5e71221622b5cd95ef | ToxicPanda 2.0 APK |
| 95ccc098982c6b48abe0038cdd1f15c4bc1ed5cd95b569d58c59072fe4d0bb57 | ToxicPanda 2.0 APK |
| dd80e4a86448d7b85387fdae9e932c7803477bcc0846650e6748b87a1787d8da | ToxicPanda 2.0 APK |
| 19dd5def1b19c18f1fc7db6c4fccdd60631f1dca5490da0cd68e8010ca244a54 | ToxicPanda 2.0 APK |
| f5ebbe98bab20e11569b01e632d9abacf6536887ec115d2d44e163c612d8923b | ToxicPanda 2.0 APK |
| 3ead5e2eec9b77066d661f5acdf82f5d82d18cedd3a3158a894dd29458533ec6 | ToxicPanda 2.0 APK |
| 6b85e5cea712e490eee0786a2ac67edc92c6ad8493b60f79a95cf06768b272ec | ToxicPanda 2.0 APK |

### File hashes (SHA-256) — dropper stage (Zimperium `dropers.csv`, subset)

| Hash | Context |
|------|---------|
| d0b44b17f97097480fabd89c86a4dd3ed2e6e60c61a498f17bb722e3fb9cc0d7 | ToxicPanda 2.0 dropper |
| 82156990c18aa0b85970b9fa3c11e16545c4fc435ecebb92ed80c325dc83e953 | ToxicPanda 2.0 dropper |
| ef48459e8c814944eb4d5b56339421084facfb6d36aef015da016b996a0d8e54 | ToxicPanda 2.0 dropper |
| d82e6ff06aa1077ad2492aa1a9bd6e787d8a094521589039f1d3773e163ca59a | ToxicPanda 2.0 dropper |
| 90e105bb10cabaef70e62680aae061ab731de649ff0503f42d52c78640a51215 | ToxicPanda 2.0 dropper |
| 1199c3cb7707938f48c2611ae29699ad80a16132654f287c957edb36ccd74553 | ToxicPanda 2.0 dropper |
| e0f3bda1d5236c7881fe4447b1531d3c8c5456ecfef942640b9b0c1c3e470c1e | ToxicPanda 2.0 dropper |
| 290b4f9a3297f52af2e9344bac0a3f2e13efdaa7d01c24b5bb6d47420ce9f73f | ToxicPanda 2.0 dropper |
| 1aae4a54a4c1b136cd78342a2c0265eb926f066760219bfbf3ce5e4b6a2657bd | ToxicPanda 2.0 dropper |
| e59d1f0a0c708fd678a55e431fb9dd8f068887a459a7caf92ff310687821ffd1 | ToxicPanda 2.0 dropper |
| 37ee9d0f4945c969cf40b47d83b154eeae52097d1881bef74ef4a49eb18112d8 | ToxicPanda 2.0 dropper |
| cca23611b6937113bdaa3114818b9c07ba12096afa42a4648a06a0e7781cdc1c | ToxicPanda 2.0 dropper |
| d9b0374aad45b47f22c4ca33636e5a45e91b514b16cb8c72c25ac6f18072081e | ToxicPanda 2.0 dropper |
| 3c32b4359e53cdbf4d4d6f4bf12245ab606dd32f1a7931dc09808c6ac431f6e6 | ToxicPanda 2.0 dropper |
| 1f42182cd6bdd162c47372f6ef7e8822fb873f1f4b03d5128832108a4eaa66ee | ToxicPanda 2.0 dropper |

> **Note:** Zimperium's full IOC feed contains 100+ SHA-256 APK samples and 50+ dropper samples. The subset above is the highest-confidence, most-recent submissions. Consumers should ingest the full CSVs at github.com/Zimperium/IOC/tree/master/2026-08-ToxicPanda for maximum coverage.

---

## 2. TTPs (MITRE ATT&CK — Mobile / M-ATT&CK)

| Tactic | Technique ID | Technique Name | Usage |
|--------|--------------|----------------|-------|
| Initial Access | T1660 | Phishing (Mobile) | Malvertising and Telegram distribution of trojanized APKs impersonating legitimate apps ("googleplaydown[.]com" fake Play Store portal) |
| Execution | T1575 | Native API (JNI) / on-device dropper | Dropper hidden in the app's asset directory decrypted and loaded after gaining VPN permission gate |
| Persistence | T1541 | Foreground Persistence | Persistent VPN foreground service tunnels device traffic through the local interface |
| Defense Evasion | T1628.002 | User Evasion — Suppress Application Icon | Icon hidden after install; user cannot easily locate/remove the app |
| Defense Evasion | T1516 | Input Injection | Overlay/AccessibilityService fraud on top of banking apps |
| Defense Evasion | T1629.002 | Impair Defenses — Disable or Modify Tools | VPN interface blocks Google Play and Google Play Services from communicating (blocks Play Protect signature updates and remote app removal) |
| Discovery | T1420 | File and Directory Discovery | Enumerates installed banking/crypto apps against 349-app target list |
| Command and Control | T1437.001 | Application Layer Protocol: Web Protocols | Initial HTTPS handshake to `/panel` endpoint |
| Command and Control | T1481.003 | Web Service: One-Way Communication (WebSocket) | Bidirectional WebSocket channel to C2 after initial HTTPS handshake — 167 remote commands |
| Credential Access | T1417.001 | Input Capture: Keylogging | AccessibilityService keylogging |
| Credential Access | T1417.002 | Input Capture: GUI Input Capture (Overlays) | Invisible overlays capture PINs from 140+ banking and cryptocurrency apps |
| Impact | T1616 | Call Control | Fraud-enabling call redirection (present in TGT parent family) |
| Impact | T1641 | Data Manipulation (On-Device Fraud) | Automated in-app transaction manipulation post credential capture |
| Persistence / Execution | T1626.001 | Abuse Elevation Control Mechanism — Device Administrator Permissions | Requests device-admin to hinder uninstallation |
| Execution / Discovery | (Novel) | ADB Wireless Debugging (`adb tcpip`) Abuse | The malware programmatically enables Android Wireless Debugging to reach a local `adb` shell, giving it shell-level command execution without root and without physical USB. Bleeds into T1622 (Debugger Evasion / dev-tool abuse). |

---

## 3. Malware & Tools

- **ToxicPanda / TgToxic** (aka BingoMod-linked lineage) — Android banking trojan first reported by Cleafy in October 2024 targeting Europe and Latin America.
- **ToxicPanda 2.0** — August 2026 evolution with:
  - **167 remote commands** (previous versions: dozens)
  - **349 target apps** across banking, financial, e-wallet, and cryptocurrency categories in 16 countries
  - **PIN harvesting workflow** covering 140+ banking and crypto apps via invisible AccessibilityService overlays
  - **Fake VPN installation screen** used as a trust-lever to obtain `BIND_VPN_SERVICE`, then used to gate Play Protect
  - **Local `adb` shell over Wireless Debugging** — first Android banking trojan family to weaponize `adb tcpip` for shell-level access without root
  - **WebSocket-based C2** replacing older TCP/HTTP polling
  - **AWS S3 payload staging** across ap-south-1, mx-central-1, and ap-southeast-1
  - **Telegram Bot API document delivery** as an out-of-band distribution channel

---

## 4. Threat Actor / Campaign Attribution

Zimperium and downstream reporting refer to the operator as an Asian-origin cybercrime group whose infrastructure and code lineage tie back to the 2024 TgToxic/ToxicPanda campaigns. No named APT attribution. The malware-as-a-service or affiliate structure is consistent with the broader Asian mobile-banker ecosystem (Gigabud, GoldPickaxe/GoldDigger, Copybara — often overlapping distribution channels and target lists).

Campaign covers **16 countries** and **349 financial applications** (banking, brokerage, e-wallet, crypto exchange, and non-custodial wallet apps).

---

## 5. Splunk Detection Searches

Endpoint fleets that back mobile devices (MDM, mobile threat defense) usually forward telemetry as HTTP proxy/DNS/firewall logs. Detections below assume Network_Traffic, Web, and DNS data models fed by corporate proxy / SSE / EDR agent.

**Detect network egress to known ToxicPanda 2.0 C2 panels:**

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Web.Web
where Web.url IN ("*cctvv2.com/panel*","*v17001.com/panel*","*w17907.com/panel*","*g8688808.com*","*googleplaydown.com*")
by Web.src Web.user Web.dest Web.url Web.http_user_agent Web.http_method
| `drop_dm_object_name(Web)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=90
| table firstTime lastTime src user dest url http_user_agent http_method risk_score
```

**Detect APK downloads from ToxicPanda 2.0 AWS S3 staging buckets and Telegram Bot API document endpoints:**

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Web.Web
where (Web.url IN ("*xcmtxc1oam1.s3.ap-south-1.amazonaws.com*",
                   "*ui920fht4m1.s3.mx-central-1.amazonaws.com*",
                   "*osy4u8pmu.s3.ap-southeast-1.amazonaws.com*",
                   "*ejjsi5fbl.s3.ap-southeast-1.amazonaws.com*",
                   "*svhc5arco.s3.ap-southeast-1.amazonaws.com*")
       OR (Web.url="*api.telegram.org/file/bot*" AND Web.url="*.apk"))
by Web.src Web.user Web.dest Web.url Web.http_user_agent
| `drop_dm_object_name(Web)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=90
| table firstTime lastTime src user dest url http_user_agent risk_score
```

**Detect DNS resolution of ToxicPanda 2.0 infrastructure:**

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Network_Resolution.DNS
where DNS.query IN ("cctvv2.com","www.v17001.com","www.w17907.com","g8688808.com","googleplaydown.com",
                    "xcmtxc1oam1.s3.ap-south-1.amazonaws.com",
                    "ui920fht4m1.s3.mx-central-1.amazonaws.com",
                    "osy4u8pmu.s3.ap-southeast-1.amazonaws.com",
                    "ejjsi5fbl.s3.ap-southeast-1.amazonaws.com",
                    "svhc5arco.s3.ap-southeast-1.amazonaws.com")
by DNS.src DNS.query DNS.answer
| `drop_dm_object_name(DNS)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=90
| table firstTime lastTime src query answer risk_score
```

**Detect ToxicPanda 2.0 APK samples on file share / email inbound (SHA-256 hash lookup):**

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Filesystem
where Filesystem.file_hash IN (
  "3c76887d942a2a1c02455070887e14015ea9fe63fc9e4777bfbc633ba29601d5",
  "6174d8867e02177913dd28e17e67aac03a0be80f6cf2640a53a2ec8dd68c8f03",
  "6ca69f5ecdfefb9e267745407b4400534dcacf25b500ac88a40ad267ab86b336",
  "5890f6378baf86d74d0cfdc9ed6a46f9e769da12512d645eb6f1d8a868b349ea",
  "e8a4d5ad6fdf97ebd647f6e4ab218c18bb624114d445785b9579a80427ae6d67",
  "da240b9352248448e3875c9a47679070c42801a0c426d2daba3854470d99bd43",
  "6a622b79aa2634b0ce77b6d2126ab575a8225f79b4c4c3b05cf520738a2b874b",
  "a6a9babbd8c3ffd0801ccdaded12b55b7a3195289337a22145f0e4ece7984cbf",
  "d0b44b17f97097480fabd89c86a4dd3ed2e6e60c61a498f17bb722e3fb9cc0d7",
  "82156990c18aa0b85970b9fa3c11e16545c4fc435ecebb92ed80c325dc83e953",
  "ef48459e8c814944eb4d5b56339421084facfb6d36aef015da016b996a0d8e54",
  "d82e6ff06aa1077ad2492aa1a9bd6e787d8a094521589039f1d3773e163ca59a"
)
by Filesystem.dest Filesystem.user Filesystem.file_name Filesystem.file_path Filesystem.file_hash
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=95
| table firstTime lastTime dest user file_name file_path file_hash risk_score
```

**Detect Telegram Bot API `/file/bot*/documents/*.apk` retrieval (any bot ID) — hunts the distribution technique, not just the observed bot tokens:**

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Web.Web
where Web.url="*api.telegram.org/file/bot*/documents/*"
  AND (Web.url="*.apk" OR Web.url="*.dex" OR Web.url="*.jar")
by Web.src Web.user Web.dest Web.url Web.http_user_agent
| `drop_dm_object_name(Web)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=80
| table firstTime lastTime src user dest url http_user_agent risk_score
```

---

## 6. Executive Summary

**ToxicPanda 2.0** is a materially upgraded Android banking trojan disclosed by Zimperium zLabs on **2026-08-23**. It expands its parent (TgToxic/ToxicPanda) capabilities to **167 remote commands, 349 targeted financial apps across 16 countries, and a PIN-harvesting workflow covering 140+ banking and crypto apps**. Distribution is via **malvertising, a phishing site impersonating Google Play (`googleplaydown[.]com`)**, and **APK delivery via Telegram Bot API and multiple AWS S3 buckets**.

Two behaviors materially change defender playbooks:

1. **VPN-service abuse for Google Play blockade.** The malware asks for `BIND_VPN_SERVICE` on a fake "installation" screen, then uses the local VPN interface to blackhole traffic to Google Play and Google Play Services — cutting Play Protect signature refreshes and preventing Google's remote app-removal from reaching the device.
2. **Android Wireless Debugging (`adb tcpip`) abuse for shell-level access without root.** The malware enables `adb` over Wi-Fi and reaches a local `adb` shell, giving the operator shell-level command execution without needing root, without physical USB, and without user awareness.

Command-and-control moved to a **WebSocket channel** established after an initial HTTPS handshake to `/panel`, and payloads are staged from **five distinct AWS S3 buckets** across three regions.

**Recommended actions:**

1. Block DNS resolution and network egress to the C2 domains and S3 staging buckets listed above at proxy/SSE tier.
2. Hunt for corporate MDM devices with Wireless Debugging enabled (`adb tcpip` state) — this is highly unusual on production endpoints.
3. Deploy the SHA-256 hash sweep against email attachment, file-share, and MDM app inventories.
4. Communicate to at-risk users (retail banking / crypto / e-wallet users, especially in the 16 covered countries) about sideloaded APK risk and the fake "installation" screen.
5. Ingest the full Zimperium IOC feed at `github.com/Zimperium/IOC/tree/master/2026-08-ToxicPanda` for continued detection coverage as Zimperium updates it.

---

## References

- [Zimperium zLabs — The ToxicPanda Never Sleeps: ToxicPanda 2.0 Prepares its Next Strike on Mobile](https://zimperium.com/blog/the-toxicpanda-never-sleeps-toxicpanda-2.0-prepares-its-next-strike-on-mobile)
- [Zimperium IOC Repository — 2026-08-ToxicPanda](https://github.com/Zimperium/IOC/tree/master/2026-08-ToxicPanda)
- [BleepingComputer — ToxicPanda Android malware uses VPN permissions to block Google Play (2026-08-23)](https://www.bleepingcomputer.com/news/security/toxicpanda-android-malware-uses-vpn-permissions-to-block-google-play/)
- [The Hacker News — ToxicPanda 2.0 and GoldDigger Expand Android Banking Attacks with On-Device Fraud](https://thehackernews.com/2026/08/toxicpanda-20-and-golddigger-expand.html)
- [Cleafy — ToxicPanda: a new banking trojan from Asia hit Europe and LATAM (original 2024 report)](https://www.cleafy.com/cleafy-labs/toxicpanda-a-new-banking-trojan-from-asia-hit-europe-and-latam)
- [MITRE ATT&CK — Mobile Techniques](https://attack.mitre.org/matrices/mobile/)
