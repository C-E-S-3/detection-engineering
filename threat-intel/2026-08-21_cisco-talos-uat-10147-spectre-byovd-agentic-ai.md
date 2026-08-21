---
scraped_at: 2026-08-21T00:00:00Z
source_url: https://github.com/Cisco-Talos/IOCs/tree/main/2026/08
report_type: threat-intel
severity: critical
title: "UAT-10147: SPECTRE Cross-Platform Implant with BYOVD and Agentic AI-Assisted Campaigns"
---

# UAT-10147: SPECTRE Cross-Platform Implant with BYOVD and Agentic AI-Assisted Campaigns

**Source:** Cisco Talos (IOC repository — 2026/08 directory)  
**Published:** ~2026-08-21 (IOC files added August 2026, after 2026-08-17 JWR report)  
**Severity:** Critical  
**Threat Actor:** UAT-10147

---

## 1. IOCs

### IP Addresses

**SPECTRE Campaign:**

| IP | Context |
|----|---------|
| 27.124.2.46 | SPECTRE C2 / implant callback infrastructure |
| 27.124.2.48 | SPECTRE C2 / implant callback infrastructure |
| 27.124.2.52 | SPECTRE C2 / implant callback infrastructure |
| 139.180.197.150 | SPECTRE C2 (also used in agentic AI campaign, port 54321) |

**Agentic AI Campaign:**

| IP | Context |
|----|---------|
| 18.140.163.186 | Agentic AI campaign payload hosting / C2 |

### Domains

**SPECTRE Campaign:**

| Domain | Context |
|--------|---------|
| vip8888vn.xyz | SPECTRE malware distribution / C2 |
| b.niupilao.vip | SPECTRE infrastructure |
| vip.niupilao.vip | SPECTRE infrastructure |
| udvyiwvfs.cyou | SPECTRE C2 / malware staging |

**Agentic AI Campaign:**

| Domain | Context |
|--------|---------|
| adminapi.tippusoni.in | Payload staging host (pr.exe, svchosts.exe, dll.zip) |
| kl21177.com | Malware distribution / batch file hosting (user.bat, user.txt) |

### File Hashes (SHA256)

**SPECTRE Campaign (44 samples):**

| Hash | Context |
|------|---------|
| 008f28989917a9712657de5675fc024b65cb27536734e9b54ea6c3af00ea70f2 | SPECTRE implant sample |
| 11ccfdfb0dfe782ba0eeabaa8e65619a792f9258476a072b774ef19a5240b944 | SPECTRE implant sample |
| 1c2edfb1b280fdc570591c88da5b1adbd249be6b8cc306a42525a515adaf73e8 | SPECTRE implant sample |
| 21274d668e28b01172fa326f42e396b825708ddc2336ae388d6729627c525775 | SPECTRE implant sample |
| 43124b72616ef38b0c8a07b167e971b0e4479626fb5ef2303b2ed993e21f6c4c | SPECTRE implant sample |
| 50d88f3d8f91f18195f1e9948cf6b47d69d7e19226957b1e7e3b2e4bd7c4fef4 | SPECTRE implant sample |
| 59a386b75b84f137c4e17c37e3430fc93c0184102b3fbdfe649cef2e0335d85b | SPECTRE implant sample |
| 684e7ed556dcc9e2fe24fcfd73e6b9c29d7126584f87c5331c2607d39e29329f | SPECTRE implant sample |
| 76df454fe87620dd59efb483a56a8b573c7d16207635cf2616a67e25dab57779 | SPECTRE implant sample |
| 77cce6576f93961651133b543948ea3853cc2f06b8c3fd523f6858d6d18ad775 | SPECTRE implant sample |
| 830c6ca21a7da0eed436f8371c8a86baa62ab857a5478a222dd3189645d4d084 | SPECTRE implant sample |
| 91d00ca46d1013c031aa8ff2e54b7b3496bac78f6147842766bffd4d32a2e042 | SPECTRE implant sample |
| 7565a5bc56fcd94c7f52cf7428747cd4f52d0d3b485900d3d9b06b470ccba23b | SPECTRE implant sample |
| b74beab9dac9ee7853b5e846eec6f778db01867b49f64d6be259ea9e19006121 | SPECTRE implant sample |
| bfbd1aa2c0ace1575e86dc5cedc0754e4ae4aae97e70ac9f0523a2e8e8b22ed9 | SPECTRE implant sample |
| c88dab534081650d5a385f9bc5c61eced41b4e9fe63ace6173aa536c4aaffa67 | SPECTRE implant sample |
| cf0a6353f1fccf63fca02ed41eafd3da8d55f77b8b4c45666a37fa3cdc33da55 | SPECTRE implant sample |
| 41f1514ad52c870bc4b51291cb939067e8ace23ec308419253ee0a2497bf2e21 | SPECTRE implant sample |
| dd4c16c65513c3eb66691f87d5bb5595d38554395ec89be2b9e325e013ef53d5 | SPECTRE implant sample |
| dee976f262498184d746cc8305cc9e6905ad762c661df8d7daec120f14060b41 | SPECTRE implant sample |
| 2e9f10f5cc9fb5c9f935ee78a21de70168e398b7a47db54373a5dcb19c485398 | SPECTRE implant sample |
| e315f955a9b44a9c875d2e47f2a91e9e77043bd553ad616ada38eaf669d44b2e | SPECTRE implant sample |
| 58725b8e592435026928c39622f41b7ad4f4dc62e353eb459c3b4858eafd9e82 | SPECTRE implant sample |
| 544a7d9d4de3904ad35e6cc87f34cb556fda722c3d3cae1a6334645f1a950cc7 | SPECTRE implant sample |
| 9a8e9d587b570d4074f1c8317b163aa8d0c566efd88f294d9d85bc7776352a28 | SPECTRE implant sample |
| 722bd55e1496cb614f4f365a4203da6166c637f2c6b9ec0da3844637bc6e9e9d | SPECTRE implant sample |
| 0345406e85aa7759c0af0372c23de0c5f3e9b6d53e970405e5c168f55c51a7e0 | SPECTRE implant sample |
| 23a7adda56e2e5519e01f57f16f99e4be611aac4fa908f2ee2d99e3d96e14865 | SPECTRE implant sample |
| 9619259c1ea9b1c6b8279fdb761018b14a41acc94f67f1469bf68bf393b4ba74 | SPECTRE implant sample |
| f07d869ddd17d4359e26da43574d0d07987b500a390196b72b3c1747a4cbb3bf | SPECTRE implant sample |
| d0da3be9de8e7068a65247b8195d73e88f454820e13c1de62675e1f845d6fabf | SPECTRE implant sample |
| 0f56c703e9b7ddeb90646927bac05a5c6d95308c8e13b88e5d4f4b572423e036 | SPECTRE implant sample |
| 35c960bda30ceeb22216fad7776b43ecf44aaccf2ff7f600f91a1afb49a8a43c | SPECTRE implant sample |
| 7172ebfb4e96e3b0bff59e87f670c5512144d445b276746c8c78593272720ebf | SPECTRE implant sample |
| b02664c71d1a40760ff6eb253d1a9022d93262698d528d95e8983bf848b8827b | SPECTRE implant sample |
| dbe956ae1135e81ae06220393ee80caacc62006295a1fb26e87f048a7a78b81b | SPECTRE implant sample |
| 4bbba075f56ee15760b1397100a82f2c7425b866cf1a35684fda5b712783f97b | SPECTRE implant sample |
| 1c70b2a55b6f3a3382f40fe15293b609d047103b0c6c7da0049f7c0e365ea880 | SPECTRE implant sample |
| fc54b68f0a375600c8ab23d894b56837db287b32209c0a455fb439a780593c80 | SPECTRE implant sample |
| b0c1c3b806a60807854173f2199ba49baf5c2729051b14e4725cb90cfc755519 | SPECTRE implant sample |
| 089b19f7760a53272f580432460dc959cbb8ffb87bde43152795ff5d893debdd | SPECTRE implant sample |
| 1fc83b41d201bfbc4db94e332e0c770be9d74591d9817c1b938ccdf17c7a48a9 | SPECTRE implant sample |
| fea09e46f6adf23aa17c56faa14d19168b5417ed90d7b2b36f2c8dd5f6014ea7 | SPECTRE implant sample |
| 061b765659bf24b62d242d4f8ca9a9884037e186714517509a8f48b54e1123a0 | SPECTRE implant sample |

**Agentic AI Campaign (12 samples):**

| Hash | Context |
|------|---------|
| 175e83adc721cd7d634ebd2c63fb8d2404c009067bc7719ef02c5d1f9d81e9a1 | UAT-10147 agentic AI campaign payload |
| 1f0496ad392b5b9edf9e59a56af4d8e17638ddbb12e086f104d9a0f316ad59a1 | UAT-10147 agentic AI campaign payload |
| 37cabc04da36e710dd4aee8609ab7553c039a54dd085460854e9ddb49b0e7032 | UAT-10147 agentic AI campaign payload |
| 50232092004b9ad335e1e72e3a6dcfde93c4470007ddfcc637e6e5f899f68be0 | UAT-10147 agentic AI campaign payload |
| 73b272612cec9e03a7e2f7516ece600fb1b45b719fa9d93b382ed25ec314e5c0 | UAT-10147 agentic AI campaign payload |
| 9fa27b231502d6d33441ab54227da50cbd325847ce2272f9c0e79b4ea873e432 | UAT-10147 agentic AI campaign payload |
| cfce59111338701b2990be9aadc80166ac0618cb57483d6a065f1e2526a34494 | UAT-10147 agentic AI campaign payload |
| fbe9c6052d7261bd252322e155d86bd370340f1fbb2b0a1e9c7b444f6275614a | UAT-10147 agentic AI campaign payload |
| 00892f276299a13721642e8a9bcbcb949a658547c6c8271866a1997b79f1e5c5 | UAT-10147 agentic AI campaign payload |
| 23a83c6bbdd7d6c09a5187338065d15f2a90a252772813cba83b9818aa56cef7 | UAT-10147 agentic AI campaign payload |
| 8280502c2c6902e61fc4c02a9a81b4720688449a5bca3d89dbd1e2edd507c69a | UAT-10147 agentic AI campaign payload |
| d190b349d791267a9583ba9f4a1ab0e4199d1a3abfd4dae514ed5def0754ba94 | UAT-10147 agentic AI campaign payload |

---

## 2. TTPs (MITRE ATT&CK)

### SPECTRE Campaign

| Tactic | Technique | ID | Description |
|--------|-----------|-----|-------------|
| Defense Evasion | Bring Your Own Vulnerable Driver (BYOVD) | T1211 / T1562.001 | Loads a signed but vulnerable kernel driver to disable/bypass EDR solutions |
| Persistence | Boot or Logon Autostart Execution: Kernel Modules and Extensions | T1547.006 | Linux rootkit component persists via kernel module |
| Defense Evasion | Rootkit | T1014 | SPECTRE Linux rootkit hides processes, files, and network connections from the OS |
| Execution | Native API | T1106 | Kernel-level API calls to bypass userspace security monitoring |
| Command and Control | Encrypted Channel | T1573 | Encrypted C2 communications to 27.124.2.x and 139.180.197.150 |
| Discovery | System Information Discovery | T1082 | Cross-platform implant performs host enumeration |
| Lateral Movement | Remote Services | T1021 | Cross-platform implant supports lateral movement |

### Agentic AI Campaign

| Tactic | Technique | ID | Description |
|--------|-----------|-----|-------------|
| Execution | User Execution: Malicious File | T1204.002 | Victims execute pr.exe, svchosts.exe delivered from adminapi.tippusoni.in |
| Defense Evasion | Masquerading: Match Legitimate Name or Location | T1036.005 | svchosts.exe (extra 's') masquerades as Windows svchost.exe |
| Execution | Command and Scripting Interpreter: Windows Command Shell | T1059.003 | user.bat batch files for payload staging and execution |
| Command and Control | Web Service | T1102 | Payloads staged at numbered directory paths (/1/, /4/, /5/) suggesting organized C2 staging |
| Resource Development | Stage Capabilities: Upload Malware | T1608.001 | DLL, executable, and archive payloads pre-staged at C2 for victim download |

---

## 3. Malware & Tools

### SPECTRE
- **Type:** Cross-platform implant with Linux rootkit and BYOVD (Bring Your Own Vulnerable Driver) capability
- **Platforms:** Linux (rootkit component), Windows (BYOVD/EDR evasion component)
- **BYOVD capability:** Loads a legitimate but vulnerable signed driver into the Windows kernel to terminate/disable EDR sensor processes — a kernel-level EDR bypass
- **Linux rootkit:** Hides files, network connections, and processes from OS-level visibility; persists as a kernel module
- **C2:** Encrypted communications; 27.124.2.x range and 139.180.197.150
- **Significance:** Cross-platform capability combined with kernel-level EDR evasion makes this a high-sophistication implant

### UAT-10147 Agentic AI Payloads
- **Type:** Staged malware using agentic AI assistance in development/deployment
- **Staging:** Payloads hosted at `adminapi.tippusoni.in` under numbered directories (`/4/pr.exe`, `/5/svchosts.exe`, `/1/dll.zip`)
- **Execution:** `user.bat` batch files from `kl21177.com` orchestrate download and execution
- **Masquerading:** `svchosts.exe` (with extra 's') mimics Windows system process name
- **C2:** `139.180.197.150:54321`, `18.140.163.186`

---

## 4. Threat Actor / Campaign Attribution

**UAT-10147** is a Cisco Talos-tracked threat actor operating two parallel campaigns observed in August 2026:

1. **SPECTRE campaign:** Deploys a cross-platform implant combining a Linux rootkit with BYOVD kernel exploitation for Windows EDR bypass. The combination suggests an actor targeting heterogeneous enterprise environments (Linux servers + Windows endpoints) with the capability to evade modern endpoint security products at the kernel level.

2. **Agentic AI campaign:** Uses agentic AI assistance in campaign tooling development and/or deployment automation, deploying payloads through organized staging infrastructure (adminapi.tippusoni.in). The use of numbered directory staging paths suggests automated or agentic tooling for victim management.

The actor's use of BYOVD places them in a small category of threat actors with kernel-level exploitation capability, typically associated with sophisticated criminal or state-adjacent groups.

---

## 5. Splunk Detection Searches

### 5a. BYOVD — Vulnerable Driver Load for EDR Evasion

Detects loading of kernel drivers followed by security tool process terminations — the BYOVD EDR evasion pattern used by SPECTRE.

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where Processes.process_name IN ("sc.exe","reg.exe","fltMC.exe")
    (Processes.process="*kernel*" OR Processes.process="*.sys*" OR Processes.process="*driver*"
    OR Processes.process="*service*create*")
    by Processes.dest Processes.user Processes.parent_process_name
       Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| join dest
    [| tstats `security_content_summariesonly` count min(_time) as kill_time
        from datamodel=Endpoint.Processes
        where Processes.process IN ("*MsMpEng*","*CrowdStrike*","*SentinelAgent*","*cb.exe*","*bdservicehost*")
        AND Processes.action="killed"
        by Processes.dest]
| table firstTime lastTime dest user parent_process_name process_name process process_id kill_time
```

### 5b. SPECTRE — Linux Rootkit Kernel Module Persistence (Syslog)

```spl
index=linux_logs sourcetype IN ("syslog","linux_secure","linux_audit")
(message="insmod*" OR message="modprobe*" OR message="module*loaded*" OR message="rmmod*")
NOT (module IN ("e1000","vmxnet3","vmw_vmci","vboxguest","nvidia","xfs","ext4"))
| rex field=message "module[= ]+(?P<module_name>\S+)"
| stats count min(_time) as firstTime max(_time) as lastTime
    values(host) as hosts values(module_name) as modules
    by sourcetype index
| where count > 0
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime lastTime hosts modules count
```

### 5c. SPECTRE / UAT-10147 — Known C2 IP Lookup (Network Traffic)

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Network_Traffic.All_Traffic
    where All_Traffic.dest_ip IN (
        "27.124.2.46","27.124.2.48","27.124.2.52",
        "139.180.197.150","18.140.163.186"
    )
    by All_Traffic.src_ip All_Traffic.dest_ip All_Traffic.dest_port All_Traffic.app All_Traffic.user
| `drop_dm_object_name(All_Traffic)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime lastTime src_ip dest_ip dest_port app user count
```

### 5d. UAT-10147 Agentic AI — Masqueraded Executable Detection

Detects executables with names closely mimicking Windows system processes (e.g., svchosts.exe with extra 's').

```spl
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
    from datamodel=Endpoint.Processes
    where (Processes.process_name="svchosts.exe" OR Processes.process_name="lsasss.exe"
        OR Processes.process_name="csrsss.exe" OR Processes.process_name="winlogons.exe"
        OR Processes.process_name="spoolsvs.exe")
    by Processes.dest Processes.user Processes.parent_process_name
       Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| table firstTime lastTime dest user parent_process_name process_name process process_id
```

---

## 6. Executive Summary

Cisco Talos published IOC data in August 2026 for two distinct UAT-10147 campaigns representing a significant escalation in threat actor sophistication.

**SPECTRE** is a cross-platform implant combining a Windows Bring Your Own Vulnerable Driver (BYOVD) capability for kernel-level EDR evasion with a Linux rootkit component. The BYOVD technique — loading a legitimate but vulnerable signed driver to disable endpoint security at kernel level — significantly limits the effectiveness of traditional EDR solutions and requires kernel-level countermeasures to detect. 44 unique SPECTRE samples have been identified. C2 infrastructure is concentrated in the 27.124.2.x range with a secondary node at 139.180.197.150.

**Agentic AI campaign:** UAT-10147 is also conducting a separate campaign using AI-assisted tooling, staging payloads (pr.exe, svchosts.exe, dll.zip) at adminapi.tippusoni.in through a structured numbered-directory system suggestive of automated C2 management. The masquerading of payloads as Windows system component names and the organized staging infrastructure indicate operational maturity.

**Defensive priorities:** Block SPECTRE C2 IPs (27.124.2.46/48/52, 139.180.197.150, 18.140.163.186) and domains at network perimeter; monitor for unsigned or anomalous kernel driver loads correlated with subsequent EDR process kills; alert on kernel module loads outside a known-good baseline on Linux systems; block agentic AI staging domains (adminapi.tippusoni.in, kl21177.com) at DNS/proxy; hunt for svchosts.exe (extra 's') and similar masqueraded process names.
