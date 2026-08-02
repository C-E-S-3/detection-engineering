---
scraped_at: "2026-08-02T00:00:00Z"
source_url: https://unit42.paloaltonetworks.com/malicious-npm-pypi-packages-supply-chain-july-2026/
report_type: threat-intel
severity: high
title: "Unit 42: Multi-Actor Malicious npm/PyPI Supply Chain Campaign — Credential Theft, Crypto Wallet Exfil, Malicious MCP Servers (July 2026)"
---

# Unit 42: Multi-Actor Malicious npm/PyPI Supply Chain Campaign — July 2026

Unit 42 (Palo Alto Networks) published July 14, 2026 (IOC file updated July 31, 2026) documenting a multi-actor malicious package campaign across npm and PyPI registries. Threat actors published 47+ packages employing credential theft from `.env` files, cryptocurrency wallet private key extraction, clipboard address manipulation, malicious MCP server integrations, RCE droppers, and reverse shell payloads. North Korean-linked actors are among the observed threat actors, with packages targeting AI coding agents and MCP clients.

## 1. IOCs

### Domains
| Indicator | Context |
|-----------|---------|
| `archonseven[.]com` | C2 domain — credential exfiltration |
| `b2k4.notun[.]tech` | C2 domain — payload delivery |
| `cawray[.]site` | C2 domain — credential exfiltration |
| `contextfort[.]ai` | Malicious MCP server masquerading as legitimate AI tooling |
| `edrukca[.]site` | C2 domain — reverse shell callback |
| `keywise[.]com[.]br` | C2 domain — crypto wallet key exfiltration |
| `mainnet.unstoppableapi[.]xyz` | Blockchain-themed C2 proxy |
| `newnz.seav[.]eu[.]org` | C2 domain — payload staging |
| `nppacks[.]com` | Typosquatted npm registry mirror — payload delivery |
| `saferw.serveo[.]net` | Attacker-controlled serveo.net SSH tunnel (reverse shell relay) |
| `server.saferpanichub[.]com` | C2 domain — exfiltration endpoint |
| `sterlingstfinancehub[.]com` | Finance-themed C2 lure domain |
| `855e-35-192-215-234.ngrok[.]io` | ngrok tunnel — reverse shell and exfiltration relay |
| `strictly-adjusted-ewe.ngrok-free[.]app` | ngrok tunnel — reverse shell and exfiltration relay |

### IP Addresses
| Indicator | Context |
|-----------|---------|
| `37.60.255[.]218` | C2 server |
| `45.9.148[.]93` | C2 server |
| `47.98.255[.]144` | C2 server (Alibaba Cloud) |
| `64.176.198[.]19` | C2 server |
| `64.227.183[.]144` | C2 server (DigitalOcean) |
| `90.189.217[.]244` | C2 server |
| `103.179.142[.]69` | C2 server |
| `103.179.142[.]105` | C2 server |
| `128.199.217[.]232` | C2 server (DigitalOcean) |
| `135.181.241[.]80` | C2 server (Hetzner) |
| `151.115.53[.]100` | C2 server |
| `157.173.114[.]28` | C2 server |
| `178.238.226[.]8` | C2 server |
| `212.2.237[.]74` | C2 server |

### File Hashes (SHA256)
```
0a545dd1b703cddfb3d582c8c70f65f556bbd580bfa836a387121eb837bda61b
0d6b083208097d5b3e189891338540f6c64faaaaf268b0bb0b085dd53d5857b4
1682e8d82016b3f10434d2ebac995fd3b6aa812f079bfd7888652e94a994d851
19e6ed42248f9d03beb343a7c09a864dcd3cd671c29e1e5eac93579225224ac9
1a2ca8b8e0344fe3d80da7352206a470245443e2349a237bc093df934ddc011f
1fc23ec18a94a599a34c74ef5f49a1e27acd37a07d5846661702b5e7e81a6a24
249a4c7cacdd8e99a2a089a5c0ce904f2eff22e0e40fcfb10f7824dca6c51ecb
2623c6e3c1f5a7b5e735a64813bc0e1382ae45831f5fadffb08c0e7b096627f7
2af7b513c05e76d7da5f75bb0a223c894a706c99ef2c2ddfe4eae542f95a08e0
34fcbe7e90fc87a4f3766469c19a64f24672d7adb99e0198f5ba10d58911368b
3627f582420ad2782d452fe6d13fae42658d1484296351d3916703e25dcadd14
391e51354118fb87dc57650cbbd94258c3f7c0a0d6868040b7a473ad626ff25e
40a3b969d81ef1ef35dd9ebcc6774e060b1b8949d3d74f38ca6b7d789c95cdb3
40b1208dda0cd5dd95c6b57764b2cfe7145b3ed9457f498408b4aaa05bf3ef50
447f430b46fad5a3f8e8c5aad1f8f7f79af069489c3d9c29224bb9f14f0c7bf4
45bb8d1ab2c13bf4354294e13d3c9be15de625d807301905b98462f43f93e893
4e3bed10a8eff3e9205c1f37f647512464271d5ac65df7ae4709735621a38320
4efbef69eb3b09bacff892d6a55778d07c418e7f15eba3cf1245e8cdfd8dda0b
51a57bfc9ed3eb6451c1c289607814d59e1698c666fb97ac5f694c398f23d045
55249f296b63a8bcf911b8bc96de43c1ac2b4a56c150a19d33d892a47e57352c
58bb25777e0aa86bcd2125101e0bca4e8732b03d91bd8d2f205b446a2a8d5c86
626330d22f77d9cbca9d40cc06568041703f194610c4c5a84bbb05a2e4ee7459
6298f3150ad94a242e649886d47c59c634a4d04b9af5ee15e3bf335c40b5e58e
667a8f568a611f2f3d84a366b7946b360e055bece9699c95aad619637ab72a38
6cee9e838792ac5e2098362d68ce93a9a2c095d476dc16b289fe8509c99b2b8b
6da0b4c1a5d0d3fb6e6a2990a82ba51db1f68a3bba818baa46526a29731e2342
7615140f78d9a0ce31cc9fe8c54c60028a7439cb32526fd97b10afef7145dd78
77417df21b4b4e8d86b8bda4afeef93fd36f355362586b2d1f51121a82244167
80f6c010fd260d0bcf18a4b6a8d62505adbed50d2e615ed9522c4bfd61c00661
813c78b5b6ef28a9c0ed35f2c6cd88fc50880ab91f8777dfe7aaccb1c24b08d5
81aabf646619ea5f4a72457cd3aa17c5988003d67e6454f45e7cb33613021bac
82707cfdf24dcb762f4615f01e1ba4d3dfdec4abe9cd588558d2634d7e6a5eeb
8f0158855a656b629ca76ebca565f18bc25563ded34b65d6771632c20edb68ec
9164054d0bf0b7c8820da4f742860940998984555e65820e4fa8dd07b6bd67ec
98ce3c6e4dd05887ea619f2bbfeb2e2c2805ed07e85e119b79b828b7ef8be397
9fe944147c15a87963b06baf6473288d64c23655a0ba9369c35566272d8efc73
a40bf9c75d1bfa6d66f1179f2321de6589f80d3089d992797a9cb0e84f6196ce
b064a3efb04ed77e6c57955089ce639e193d166c8ea2216c98c3e9b701ea2cff
b287347a5bff8af360ce0e6500c336b6fe6d97920abc26202c9d843ffebc5f89
b55f3b8a7334af049ba3f70a9ad3fe78574b1e180c68baf9a7110d104387a636
b728eba4f0d6d16602fbad05a591f14391594262d3584b2e249e97f86e4dcc5a
b82936f37648518425c7d3cf9e09eaffa41d7cdb3840f6a40287e3a108880f7b
ba6b73b0ca0dc7f86b3b397893ac32d729fd53f9df20643288f141f29d020af7
c1ac43d23f89d41eb4ff131678ab562ab2cfed9aa334b13767ef141d303b0e5b
c905cb512018cc55512c6a22677c3d6f389c47afd54d7c85797868fc4fcb90e9
d1e54270433a94aa3d45d888e4c62299bee3480eb2cb4a5489c7dda69d476c3e
d3fd32f915c239872c9e7ed9408b1f36dfcef03aa68f9a396d05c437667cdb43
d8fe8f3fe838d5b1a1043096f6f6bb6f524f5f1b0c9f83a081078a824daa0cf3
d966161b93100fb8905b9b81bd03e57bbc93f21534acee88999e77798e913d5b
da8a96bc74e265f945f1cc6992c6dc0f9ea36ed1991f7b8d312db79d9bf78c40
db65c1b9f9e4cb4d729f45ad4b6fcf3e277caf9eb4c875425dec93fd883f9136
dfd5cb91d06b9649d4cab500343af80ad1144a9e46641cc406f43dd169003c22
e1d16fb635060d23e889b0617d77f0cf06d00cc19b43a2c8b5ac53ac027ac722
e2a0f4440f67998a0215d49be31746ea192bfcb4dc4ee532a218f8cf13605714
e316b1e13154dc6115e1e0c023f6fe3d17861cae839d4a4a81779b6aad9a24f8
e3364ee21cae6725451e8bc9ab9933df0000fd19814170bd132da68d1906d5ff
e6d8192960a89d5480868b94088cccdaa1560f9c8a0b0282ced2b7c1f72341b6
e83f274bf9914c6cfc0c6b3cdadf089565f49dace4aca93287c22aba9641c8f3
eb0687daed29f3651c61b0a2aa4a0cdcf2049a1ebae2e15e2dd9326471d318a1
f04f43b6f7c2d86109c495179b497f7fb45fd95816623de1b77900f71b4f99ed
```

## 2. Malware & Tools

| Name | Registry | Description |
|------|----------|-------------|
| Credential stealer | npm / PyPI | Reads `.env`, `~/.aws/credentials`, browser cookie/session stores; exfiltrates to C2 |
| Crypto wallet extractor | npm | Scans for common wallet keystore paths; exfiltrates private keys |
| Clipboard hijacker | npm | Browser-context JS monitors clipboard for wallet address patterns; replaces with attacker wallet |
| Malicious MCP server | npm | Published as legitimate AI coding tools; intercepts developer tool calls to leak workspace context |
| RCE dropper | PyPI | `postinstall`/`setup.py` script downloads and executes second-stage shellcode |
| Reverse shell | npm | Lifecycle script spawns reverse shell to ngrok/serveo relay tunnel |

## 3. Actor Attribution

Multiple distinct threat actors observed in this campaign:
- **North Korean-linked actors (UNC4899 / Lazarus nexus):** AI-themed packages targeting developers on Hugging Face, MCP repository indexes, and cryptocurrency-themed repos; designed to exploit AI coding agents that auto-integrate dependencies
- **Financially-motivated actors:** Credential theft and crypto wallet extraction for direct monetization
- No single group attribution for all 47+ packages

## 4. TTPs

| Tactic | Technique ID | Technique | Notes |
|--------|-------------|-----------|-------|
| Initial Access | T1195.001 | Supply Chain Compromise: Compromise Software Dependencies | Malicious packages published to npm/PyPI registries |
| Execution | T1059.007 | Command and Scripting Interpreter: JavaScript | npm lifecycle scripts (preinstall, postinstall) execute payloads |
| Execution | T1059.006 | Command and Scripting Interpreter: Python | PyPI setup.py executes second-stage droppers |
| Credential Access | T1552.001 | Unsecured Credentials: Credentials in Files | Reads .env, ~/.aws/credentials, ~/.ssh/ |
| Credential Access | T1555.003 | Credentials from Password Stores: Credentials from Web Browsers | Browser cookie and session token theft |
| Collection | T1115 | Clipboard Data | Monitors and replaces cryptocurrency wallet addresses in clipboard |
| Command and Control | T1090 | Proxy | ngrok and serveo tunnels as C2 relay |
| Impact | T1657 | Financial Theft | Crypto wallet private key exfiltration and clipboard address hijacking |

## 5. Splunk Detections

### npm postinstall spawning shell or network connection
```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where Processes.parent_process_name IN ("npm", "node", "pip", "pip3", "python", "python3")
    AND Processes.process_name IN ("sh", "bash", "cmd.exe", "powershell.exe", "curl", "wget", "nc", "ncat")
  by Processes.dest Processes.user Processes.parent_process_name Processes.process_name
     Processes.process Processes.process_id Processes.parent_process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime, lastTime, dest, user, parent_process_name, process_name, process, count
```

### Network connection to malicious C2 IPs from developer tooling
```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Traffic.All_Traffic
  where All_Traffic.dest_ip IN ("37.60.255.218","45.9.148.93","47.98.255.144","64.176.198.19",
    "64.227.183.144","90.189.217.244","103.179.142.69","103.179.142.105","128.199.217.232",
    "135.181.241.80","151.115.53.100","157.173.114.28","178.238.226.8","212.2.237.74")
  by All_Traffic.src All_Traffic.dest_ip All_Traffic.dest_port All_Traffic.app
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime, lastTime, src, dest_ip, dest_port, app, count
```

### DNS query for malicious npm/PyPI C2 domains
```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Network_Resolution.DNS
  where DNS.query IN ("archonseven.com","cawray.site","contextfort.ai","edrukca.site",
    "nppacks.com","server.saferpanichub.com","sterlingstfinancehub.com",
    "mainnet.unstoppableapi.xyz","keywise.com.br")
    OR DNS.query IN ("*.ngrok.io","*.ngrok-free.app","*.serveo.net")
  by DNS.src DNS.query DNS.answer
| `drop_dm_object_name(DNS)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime, lastTime, src, query, answer, count
```

### File hash match — malicious npm/PyPI packages
```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Filesystem
  where Filesystem.file_hash IN (
    "0a545dd1b703cddfb3d582c8c70f65f556bbd580bfa836a387121eb837bda61b",
    "1682e8d82016b3f10434d2ebac995fd3b6aa812f079bfd7888652e94a994d851",
    "2af7b513c05e76d7da5f75bb0a223c894a706c99ef2c2ddfe4eae542f95a08e0",
    "40a3b969d81ef1ef35dd9ebcc6774e060b1b8949d3d74f38ca6b7d789c95cdb3",
    "b287347a5bff8af360ce0e6500c336b6fe6d97920abc26202c9d843ffebc5f89",
    "e316b1e13154dc6115e1e0c023f6fe3d17861cae839d4a4a81779b6aad9a24f8"
  )
  by Filesystem.dest Filesystem.user Filesystem.file_name Filesystem.file_path Filesystem.file_hash
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime, lastTime, dest, user, file_name, file_path, file_hash
```

## 6. Executive Summary

**Published:** July 14, 2026 (IOC file updated July 31, 2026)  
**Registries Affected:** npm, PyPI  
**Package Count:** 47+  
**Actor Count:** Multiple — including North Korean-linked threat actors  

Unit 42 documented an intensifying multi-actor campaign abusing open-source package registries. The campaign is notable for targeting AI-adjacent infrastructure: packages were published to Hugging Face, MCP repository indexes, and crypto-themed AI repositories, specifically designed to be auto-integrated by AI coding agents. This extends the attack surface beyond human developers to automated development pipelines. Techniques include credential theft from common developer configuration files, cryptocurrency wallet private key extraction, clipboard hijacking, and RCE via malicious lifecycle scripts. The npm v12 platform hardening (lifecycle scripts disabled by default) directly mitigates the most common execution vector.

## 7. References

- [Unit 42 — Malicious npm/PyPI Supply Chain Campaign July 2026](https://unit42.paloaltonetworks.com/malicious-npm-pypi-packages-supply-chain-july-2026/)
- [Google GTIG — Batten Down Your Packages: Mitigation Guidance for Supply Chain Compromise](https://cloud.google.com/blog/topics/threat-intelligence/mitigation-guidance-for-supply-chain-compromise)
- [npm v12 lifecycle scripts disabled by default](https://docs.npmjs.com/)
- [MITRE ATT&CK T1195.001 — Supply Chain Compromise: Compromise Software Dependencies](https://attack.mitre.org/techniques/T1195/001/)
- [MITRE ATT&CK T1552.001 — Unsecured Credentials: Credentials in Files](https://attack.mitre.org/techniques/T1552/001/)
