# WMI Risk Rule

```
| tstats summariesonly=false count, 
  values(Processes.process) as process,
  values(Processes.parent_process_name) as parent_process,
  values(Processes.user) as user,
  min(_time) as firstTime,
  max(_time) as lastTime
  FROM datamodel=Endpoint.Processes 
  WHERE (Processes.process_name IN ("wmic.exe", "scrcons.exe") 
    OR Processes.original_file_name IN ("wmic.exe", "scrcons.exe"))
  BY Processes.dest, Processes.process_name, Processes.process_guid
| `drop_dm_object_name("Processes")`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
| eval risk_score=case(
    like(process, "%process call create%"), 50,
    like(process, "%/node:%") OR like(process, "%/NODE:%"), 45,
    like(process, "%shadowcopy%"), 40,
    like(process, "%AntiVirusProduct%") OR like(process, "%AntiSpywareProduct%"), 35,
    like(process, "%namespace%"), 30,
    1==1, 25
  )
| eval risk_message="WMI command execution detected on dest=".dest." process=".process_name." user=".user
| eval risk_object=dest
| eval risk_object_type="system"
| eval threat_object=user
| eval threat_object_type="user"
| fields firstTime, lastTime, dest, user, process_name, process, parent_process, count, risk_score, risk_object, risk_object_type, threat_object, threat_object_type, risk_message
```
