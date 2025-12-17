# Medusa Ransomware

### Check for Invoke-SMBExec and Invoke-WMIExec

```
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime 
from datamodel=Endpoint.Processes 
where (Processes.process_name IN ("powershell.exe", "pwsh.exe", "powershell_ise.exe")
    AND Processes.process IN ("*Invoke-SMBExec*", "*Invoke-WMIExec*"))
    OR (Processes.process_name IN ("wmiprvse.exe", "wmic.exe")
    AND Processes.parent_process_name IN ("powershell.exe", "pwsh.exe", "cmd.exe")
    AND Processes.process IN ("*process call create*", "*wmic*process*"))
by Processes.dest Processes.user Processes.parent_process_name Processes.parent_process 
   Processes.process_name Processes.process Processes.process_id Processes.parent_process_id
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    match(process, "(?i)Invoke-SMBExec"), 85,
    match(process, "(?i)Invoke-WMIExec"), 85,
    match(process, "(?i)process call create") AND match(parent_process_name, "(?i)powershell"), 75,
    1=1, 50)
| where risk_score >= 75
```

### Medusa specific indicators
```
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime 
from datamodel=Endpoint.Processes 
where (
    (Processes.process_name IN ("powershell.exe", "pwsh.exe") 
     AND Processes.process IN ("*Invoke-SMBExec*", "*Invoke-WMIExec*", "*Invoke-TheHash*"))
    OR 
    (Processes.process IN ("*\\admin$*", "*\\c$*") 
     AND Processes.process_name IN ("powershell.exe", "cmd.exe"))
    OR
    (Processes.process_name="rundll32.exe" 
     AND Processes.process IN ("*comsvcs.dll*", "*MiniDump*"))
)
by Processes.dest Processes.user Processes.parent_process_name Processes.process_name 
   Processes.process Processes.process_id Processes.original_file_name
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)`
| eventstats dc(dest) as unique_targets by user
| where unique_targets >= 3
| table firstTime lastTime user dest parent_process_name process_name process unique_targets
```
