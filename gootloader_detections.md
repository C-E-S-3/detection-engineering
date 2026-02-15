# Gootloader Detection Rules (Splunk SPL)

---

### Wscript Executing JavaScript from User Downloads or Temp Directories

Gootloader delivers malicious `.js` files inside ZIP archives downloaded from SEO-poisoned search results. Victims double-click the JavaScript file, which launches `wscript.exe`. This detection identifies `wscript.exe` executing `.js` files from common download and staging paths.

```
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Processes
where Processes.process_name="wscript.exe"
    AND (Processes.process IN ("*\\Downloads\\*.js*", "*\\Temp\\*.js*", "*\\AppData\\Local\\*.js*", "*\\Desktop\\*.js*"))
by Processes.dest Processes.user Processes.parent_process_name Processes.parent_process
   Processes.process_name Processes.process Processes.process_id Processes.parent_process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(process, "(?i)\\\\Downloads\\\\.*\\.js"), 80,
    match(process, "(?i)\\\\Temp\\\\.*\\.js"), 85,
    match(process, "(?i)\\\\Desktop\\\\.*\\.js"), 75,
    1=1, 60)
| where risk_score >= 60
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

---

### Gootloader Obfuscated JavaScript File Creation

Gootloader drops heavily obfuscated JavaScript files with characteristic large file sizes (typically 40 KB+). This detection looks for `.js` file creation events in user-writable directories that may indicate Gootloader staging.

```
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Filesystem
where Filesystem.file_name="*.js"
    AND (Filesystem.file_path IN ("*\\Downloads\\*", "*\\Temp\\*", "*\\AppData\\*", "*\\Desktop\\*"))
by Filesystem.dest Filesystem.user Filesystem.file_name Filesystem.file_path Filesystem.process_name
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(file_path, "(?i)\\\\Temp\\\\"), 70,
    match(file_path, "(?i)\\\\Downloads\\\\"), 65,
    1=1, 50)
| where risk_score >= 50
| table firstTime lastTime dest user file_name file_path process_name risk_score
```

---

### Gootloader Registry Stuffing - Large Registry Value Writes

A hallmark of Gootloader is storing encoded payloads in the Windows registry (registry stuffing). The malware writes large base64-encoded or hex-encoded blobs to registry keys under HKCU, often under paths like `HKCU\SOFTWARE\<random>`. This detection identifies PowerShell or wscript writing unusually large values to the registry.

```
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Registry
where (Registry.process_name IN ("powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe"))
    AND Registry.registry_path="HKEY_CURRENT_USER\\SOFTWARE\\*"
    AND Registry.action="modified"
by Registry.dest Registry.user Registry.process_name Registry.registry_path
   Registry.registry_key_name Registry.registry_value_name
| `drop_dm_object_name(Registry)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(process_name, "(?i)wscript"), 80,
    match(process_name, "(?i)powershell"), 75,
    1=1, 55)
| table firstTime lastTime dest user process_name registry_path registry_key_name registry_value_name risk_score
```

---

### PowerShell Decoding and Executing Payload from Registry

After initial JavaScript execution, Gootloader uses PowerShell to read encoded payloads stored in the registry, decode them, and execute them in memory. This detection looks for PowerShell commands that reference registry paths in combination with decoding functions.

```
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Processes
where Processes.process_name IN ("powershell.exe", "pwsh.exe")
    AND (Processes.process IN ("*HKCU*", "*HKEY_CURRENT_USER*", "*Get-ItemProperty*", "*gp *"))
    AND (Processes.process IN ("*[System.Convert]*", "*FromBase64String*", "*[System.Text.Encoding]*",
         "*Invoke-Expression*", "*iex *", "*-encodedcommand*", "*-enc *"))
by Processes.dest Processes.user Processes.parent_process_name Processes.parent_process
   Processes.process_name Processes.process Processes.process_id Processes.parent_process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(process, "(?i)FromBase64String") AND match(process, "(?i)HKCU"), 95,
    match(process, "(?i)Invoke-Expression") AND match(process, "(?i)Get-ItemProperty"), 90,
    match(process, "(?i)-enc") AND match(process, "(?i)HKEY_CURRENT_USER"), 85,
    1=1, 70)
| where risk_score >= 70
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

---

### Gootloader Scheduled Task Persistence

Gootloader establishes persistence by creating scheduled tasks that re-execute the malicious JavaScript or PowerShell payload. Tasks are commonly created via `schtasks.exe` or PowerShell and may reference wscript, cscript, or PowerShell with obfuscated arguments.

```
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Processes
where (Processes.process_name="schtasks.exe" AND Processes.process="*/create*"
    AND (Processes.process IN ("*wscript*", "*cscript*", "*powershell*", "*pwsh*", "*.js*")))
by Processes.dest Processes.user Processes.parent_process_name Processes.parent_process
   Processes.process_name Processes.process Processes.process_id Processes.parent_process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(process, "(?i)wscript.*\\.js"), 90,
    match(process, "(?i)cscript.*\\.js"), 90,
    match(process, "(?i)powershell.*-enc"), 85,
    1=1, 65)
| where risk_score >= 65
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

---

### Wscript Spawning PowerShell - Gootloader Stage Transition

A key indicator of Gootloader execution is the process chain where `wscript.exe` (executing the initial .js file) spawns `powershell.exe` or `cscript.exe` for the next stage. This parent-child relationship is uncommon in legitimate activity and is a strong signal for Gootloader.

```
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Processes
where Processes.parent_process_name="wscript.exe"
    AND Processes.process_name IN ("powershell.exe", "pwsh.exe", "cscript.exe", "cmd.exe")
by Processes.dest Processes.user Processes.parent_process_name Processes.parent_process
   Processes.process_name Processes.process Processes.process_id Processes.parent_process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    process_name="powershell.exe" OR process_name="pwsh.exe", 90,
    process_name="cscript.exe", 80,
    process_name="cmd.exe", 70,
    1=1, 60)
| where risk_score >= 60
| table firstTime lastTime dest user parent_process_name parent_process process_name process risk_score
```

---

### Gootloader C2 Beaconing Over HTTPS

Gootloader communicates with C2 infrastructure over HTTPS, often using compromised WordPress sites. This detection uses the Network Traffic data model to identify repeated outbound connections to uncommon external destinations that match Gootloader beaconing patterns.

```
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Network_Traffic.All_Traffic
where All_Traffic.dest_port IN (443, 80)
    AND All_Traffic.action="allowed"
by All_Traffic.src All_Traffic.dest All_Traffic.dest_port All_Traffic.app
| `drop_dm_object_name(All_Traffic)`
| eventstats dc(dest) as unique_dests by src
| where unique_dests >= 5
| bin _time span=10m
| stats count as request_count values(dest) as destinations dc(dest) as unique_targets by src _time
| streamstats window=6 avg(request_count) as avg_requests stdev(request_count) as stdev_requests by src
| where stdev_requests < 3 AND avg_requests > 5
| eval risk_score=case(
    stdev_requests < 1 AND avg_requests > 15, 85,
    stdev_requests < 2 AND avg_requests > 10, 75,
    1=1, 60)
| where risk_score >= 60
| table _time src destinations unique_targets avg_requests stdev_requests risk_score
```

---

### DNS Queries to Newly Registered or Low-Reputation Domains

Gootloader C2 domains are often recently registered or hosted on compromised sites. This detection correlates DNS query activity to identify hosts resolving an unusually high number of unique domains in short time windows, which may indicate Gootloader C2 checkin or payload retrieval.

```
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Network_Resolution.DNS
where DNS.message_type="Query"
by DNS.src DNS.query DNS.answer
| `drop_dm_object_name(DNS)`
| rex field=query "(?<tld>[^\.]+)\.(?<domain_suffix>[^\.]+)$"
| eval query_length=len(query)
| eval has_digits=if(match(query, "\d{3,}"), 1, 0)
| eval consonant_ratio=round((len(replace(query, "[aeiouAEIOU\.\-\d]", "")) / len(replace(query, "[\.\-]", "")))*100, 2)
| where query_length > 20 OR has_digits=1 OR consonant_ratio > 65
| stats count dc(query) as unique_queries values(query) as suspicious_queries by src
| where unique_queries >= 3
| eval risk_score=case(
    unique_queries >= 10, 85,
    unique_queries >= 5, 70,
    1=1, 55)
| where risk_score >= 55
| table src unique_queries suspicious_queries risk_score
```

---

### Gootloader ZIP Archive with Embedded JavaScript Downloaded via Browser

Gootloader distributes payloads as ZIP files containing a single JavaScript file. Users reach the download via SEO-poisoned search results. This detection identifies browser processes writing ZIP files followed by JavaScript file creation from archive extraction.

```
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Filesystem
where Filesystem.file_name="*.zip"
    AND Filesystem.file_path IN ("*\\Downloads\\*", "*\\Temp\\*", "*\\Desktop\\*")
    AND Filesystem.process_name IN ("chrome.exe", "msedge.exe", "firefox.exe", "iexplore.exe", "browser_broker.exe")
by Filesystem.dest Filesystem.user Filesystem.file_name Filesystem.file_path Filesystem.process_name
| `drop_dm_object_name(Filesystem)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| join dest user
    [| tstats `security_content_summariesonly` count min(_time) as js_firstTime max(_time) as js_lastTime
     from datamodel=Endpoint.Filesystem
     where Filesystem.file_name="*.js"
         AND Filesystem.file_path IN ("*\\Downloads\\*", "*\\Temp\\*", "*\\Desktop\\*")
     by Filesystem.dest Filesystem.user Filesystem.file_name Filesystem.file_path
     | `drop_dm_object_name(Filesystem)`
     | rename file_name as js_file_name file_path as js_file_path]
| where js_firstTime >= firstTime AND (js_firstTime - firstTime) < 300
| eval risk_score=80
| table firstTime js_firstTime dest user file_name file_path js_file_name js_file_path process_name risk_score
```

---

### Gootloader Process Chain - Full Kill Chain Correlation

This detection correlates the full Gootloader process chain: a browser downloads a file, followed by `explorer.exe` or the user launching `wscript.exe` against a `.js` file, which then spawns PowerShell. Observing this full chain on a single host in a short window is a high-confidence indicator of Gootloader activity.

```
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Processes
where Processes.process_name="wscript.exe"
    AND Processes.process="*.js*"
by Processes.dest Processes.user Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| rename process_id as wscript_pid
| join dest
    [| tstats `security_content_summariesonly` count min(_time) as ps_firstTime max(_time) as ps_lastTime
     from datamodel=Endpoint.Processes
     where Processes.parent_process_name="wscript.exe"
         AND Processes.process_name IN ("powershell.exe", "pwsh.exe")
     by Processes.dest Processes.user Processes.parent_process_name
        Processes.process_name Processes.process Processes.parent_process_id
     | `drop_dm_object_name(Processes)`
     | rename process_name as child_process_name process as child_process parent_process_id as wscript_pid]
| where ps_firstTime >= firstTime AND (ps_firstTime - firstTime) < 120
| eval risk_score=95
| eval risk_level="critical"
| table firstTime ps_firstTime dest user process_name process child_process_name child_process risk_score risk_level
```

---

### Gootloader Outbound HTTP POST to Compromised WordPress Sites

Gootloader C2 commonly uses compromised WordPress sites. Outbound HTTP POST requests to URIs containing common WordPress paths like `/wp-content/`, `/wp-includes/`, or `/wp-admin/admin-ajax.php` from non-browser processes can indicate Gootloader C2 activity.

```
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Web.Web
where Web.http_method="POST"
    AND (Web.url IN ("*/wp-content/*", "*/wp-includes/*", "*/wp-admin/admin-ajax.php*"))
    AND NOT Web.src_category="web_proxy"
by Web.src Web.dest Web.url Web.http_method Web.status Web.http_user_agent
| `drop_dm_object_name(Web)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(url, "(?i)admin-ajax\\.php"), 80,
    match(url, "(?i)wp-content/uploads"), 75,
    match(url, "(?i)wp-includes"), 70,
    1=1, 60)
| eval suspicious_ua=if(match(http_user_agent, "(?i)(powershell|wget|curl|python|java/)"), 1, 0)
| eval risk_score=if(suspicious_ua=1, risk_score+15, risk_score)
| where risk_score >= 65
| table firstTime lastTime src dest url http_method http_user_agent status risk_score
```

---

### Cscript or Wscript Executing from Non-Standard Directories

Gootloader may stage its JavaScript payload in non-standard directories. Cscript or wscript executing scripts from paths outside `C:\Windows\` is suspicious and warrants investigation.

```
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Processes
where Processes.process_name IN ("wscript.exe", "cscript.exe")
    AND NOT Processes.process IN ("*\\Windows\\System32\\*", "*\\Windows\\SysWOW64\\*", "*\\Program Files*")
    AND Processes.process="*.js*"
by Processes.dest Processes.user Processes.parent_process_name Processes.parent_process
   Processes.process_name Processes.process Processes.process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(process, "(?i)\\\\Users\\\\.*\\\\AppData\\\\"), 80,
    match(process, "(?i)\\\\Users\\\\.*\\\\Downloads\\\\"), 80,
    match(process, "(?i)\\\\Temp\\\\"), 85,
    match(process, "(?i)\\\\ProgramData\\\\"), 75,
    1=1, 65)
| where risk_score >= 65
| table firstTime lastTime dest user parent_process_name process_name process risk_score
```

---

### PowerShell with Long Encoded Command Line (Gootloader Payload Execution)

Gootloader frequently uses PowerShell with heavily obfuscated or base64-encoded commands. This detection looks for PowerShell execution with unusually long command lines, which is characteristic of encoded Gootloader payloads.

```
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
from datamodel=Endpoint.Processes
where Processes.process_name IN ("powershell.exe", "pwsh.exe")
by Processes.dest Processes.user Processes.parent_process_name Processes.parent_process
   Processes.process_name Processes.process Processes.process_id Processes.parent_process_id
| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval cmd_length=len(process)
| eval has_encoded_cmd=if(match(process, "(?i)(-enc|-encodedcommand)\s+[A-Za-z0-9+/=]{100,}"), 1, 0)
| eval has_hidden_window=if(match(process, "(?i)-w(indowstyle)?\s*(hidden|1)"), 1, 0)
| eval has_noprofile=if(match(process, "(?i)-nop(rofile)?"), 1, 0)
| eval risk_score=case(
    cmd_length > 2000 AND has_encoded_cmd=1, 90,
    cmd_length > 1000 AND has_encoded_cmd=1, 85,
    cmd_length > 500 AND has_hidden_window=1, 75,
    cmd_length > 2000, 70,
    1=1, 50)
| eval risk_score=if(has_hidden_window=1 AND has_noprofile=1, risk_score+10, risk_score)
| eval risk_score=if(match(parent_process_name, "(?i)wscript"), risk_score+10, risk_score)
| where risk_score >= 70
| table firstTime lastTime dest user parent_process_name process_name cmd_length has_encoded_cmd has_hidden_window risk_score
```
