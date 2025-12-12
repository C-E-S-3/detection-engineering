# Suspicious Powershell Risk Rule

```
`crowdstrike`
process_name IN ("powershell.exe", "pwsh.exe", "cmd.exe")
| eval base_risk=5

| eval cmdline_risk=case(
    match(process, "(?i)-encodedcommand|-enc\s"), 60,
    match(process, "(?i)downloadstring|downloadfile|invoke-webrequest|invoke-restmethod"), 50,
    match(process, "(?i)invoke-expression|iex\s|iex\)"), 45,
    match(process, "(?i)bypass|unrestricted|-nop|-w\shidden|-windowstyle\shidden"), 40,
    match(process, "(?i)bitstransfer|start-bitstransfer"), 35,
    match(process, "(?i)net\suser|net\slocalgroup|net\sgroup"), 30,
    match(process, "(?i)mimikatz|invoke-mimikatz|dumpcreds"), 100,
    match(process, "(?i)empire|metasploit|cobalt"), 100,
    match(process, "(?i)nslookup|ping\s-n|timeout|sleep"), 15,
    match(process, "(?i)powershell.exe.*powershell.exe|cmd.exe.*cmd.exe"), 25,
    1=1, 0
)

| eval parent_risk=case(
    parent_process_name IN ("explorer.exe", "services.exe", "svchost.exe"), 0,
    parent_process_name IN ("winword.exe", "excel.exe", "outlook.exe", "acrord32.exe"), 50,
    parent_process_name IN ("wscript.exe", "cscript.exe", "mshta.exe"), 60,
    parent_process_name IN ("w3wp.exe", "httpd.exe", "nginx.exe", "tomcat.exe"), 70,
    parent_process_name IN ("powershell.exe", "cmd.exe"), 30,
    parent_process_name IN ("wmiprvse.exe", "wmic.exe"), 40,
    1=1, 10
)

| eval user_risk=case(
    match(user_sid, "-500$"), 35,
    match(user, "(?i)SYSTEM"), 20,
    1=1, 0
)

| eval network_risk=case(
    match(process, "(?i)http://|https://"), 30,
    match(process, "(?i)\\\\\\\\[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+"), 40,
    1=1, 0
)

| eval total_risk=base_risk + cmdline_risk + parent_risk + user_risk + network_risk
| where total_risk >= 50
| eval risk_level=case(total_risk>=120, "critical", total_risk>=80, "high", total_risk>=60, "medium", 1=1, "low")
```
