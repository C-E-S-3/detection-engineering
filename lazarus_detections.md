### Detecting Lazarus via Crowdstrike EDR

```
`crowdstrike` 
(FileName IN ("*.dll", "*.exe", "*.scr", "*.vbs", "*.ps1") OR ProcessCommandLine="*")
| search 
    (FileName IN ("mscoree.dll", "iertutil.dll", "oleaut32.dll") AND NOT (Image="C:\\Windows\\System32\\*" OR Image="C:\\Windows\\SysWOW64\\*"))
    OR (ProcessCommandLine="*certutil* -decode*" OR ProcessCommandLine="*certutil* -urlcache*")
    OR (ProcessCommandLine="*rundll32* javascript:*" OR ProcessCommandLine="*rundll32.exe*,a /p:*")
    OR (ProcessCommandLine="*mshta* http*" OR ProcessCommandLine="*mshta* javascript:*")
    OR (ProcessCommandLine="*regsvr32* /s /u /i:http*" OR ProcessCommandLine="*regsvr32* scrobj.dll*")
    OR (FileName="*.scr" AND ParentImage!="*explorer.exe")
| stats count by ComputerName, FileName, ProcessCommandLine, ParentImage, Image, UserName
| where count > 0
```

### Lazarus C2 Beaconing

```
(`infoblox_dns` OR `zscaler_dns`) 
| stats count dc(query) as unique_queries by src_ip, dest_domain 
| where unique_queries > 50 AND unique_queries < 200
| join src_ip [
    search (`infoblox_dns` OR `zscaler_dns`)
    | bin _time span=1h
    | stats count by _time, src_ip
    | streamstats window=10 stdev(count) as std_dev avg(count) as avg_count by src_ip
    | where (count > avg_count + (2*std_dev)) OR (std_dev < 5 AND avg_count > 20)
]
| table src_ip, dest_domain, unique_queries
```

### Lazarus DGA

```
(`infoblox_dns` OR `zscaler_dns`)
| rex field=query "(?<domain>[^.]+\.[^.]+)$"
| eval domain_length=len(query)
| eval entropy=0
| eval query_lower=lower(query)
| rex field=query_lower mode=sed "s/[aeiou]//g"
| eval consonant_ratio=len(query_lower)/domain_length
| where domain_length > 20 AND consonant_ratio > 0.7
| stats count by src_ip, query, domain_length
| where count < 5
```

### LOLBAS

```
`crowdstrike`
(Image="*\\certutil.exe" OR Image="*\\bitsadmin.exe" OR Image="*\\mshta.exe" 
OR Image="*\\regsvr32.exe" OR Image="*\\rundll32.exe" OR Image="*\\wmic.exe"
OR Image="*\\powershell.exe" OR Image="*\\wscript.exe" OR Image="*\\cscript.exe")
| search 
    (ProcessCommandLine="*certutil* -urlcache*" OR ProcessCommandLine="*certutil* -decode*")
    OR (ProcessCommandLine="*bitsadmin* /transfer*")
    OR (ProcessCommandLine="*mshta* http*" OR ProcessCommandLine="*mshta* vbscript:*")
    OR (ProcessCommandLine="*regsvr32* /s /u /i:http*")
    OR (ProcessCommandLine="*rundll32* javascript:*" OR ProcessCommandLine="*rundll32*,a /p:*")
    OR (ProcessCommandLine="*wmic* process call create*" AND ProcessCommandLine="*http*")
    OR (ProcessCommandLine="*powershell*" AND ProcessCommandLine="*downloadstring*" OR ProcessCommandLine="*iex*")
| stats count by ComputerName, Image, ProcessCommandLine, ParentImage, UserName, _time
```

### O365 Spearfishing

```
`o365` (sourcetype="o365:management:activity" OR sourcetype="ms:o365:management")
Operation IN ("MailItemsAccessed", "Send", "SendAs", "SendOnBehalf")
| search 
    (Subject="*payment*" OR Subject="*invoice*" OR Subject="*urgent*" OR Subject="*document*" OR Subject="*proposal*")
    AND (AttachmentFileName="*.zip" OR AttachmentFileName="*.rar" OR AttachmentFileName="*.iso" 
         OR AttachmentFileName="*.doc" OR AttachmentFileName="*.docm" OR AttachmentFileName="*.xls" OR AttachmentFileName="*.xlsm")
| eval suspicious_sender=if(match(ClientIP, "^(103\.|5\.|45\.|185\.)"), "yes", "no")
| where suspicious_sender="yes" OR (AttachmentFileName="*.iso" OR AttachmentFileName="*.rar")
| stats count by UserId, ClientIP, Subject, AttachmentFileName, Operation
```

### Fortigate Suspicious Outbound

```
`fortigate` 
(action="accept" OR action="allowed") dstip!="10.*" dstip!="172.16.*" dstip!="192.168.*"
| search dstport IN (443, 8080, 8443, 8888, 53, 80)
| stats sum(bytes_out) as total_bytes dc(dstip) as unique_dest count by srcip, dstport
| where (total_bytes > 10485760 AND unique_dest > 50) OR (dstport=53 AND count > 1000)
| table srcip, dstport, total_bytes, unique_dest, count
```

### Cryptocurrency Wallet/Exchange

```
`zscaler_dns` OR `infoblox_dns`
| search query IN ("*blockchain*", "*binance*", "*coinbase*", "*kraken*", "*bitstamp*", 
                   "*crypto*", "*wallet*", "*metamask*", "*ledger*")
| stats count dc(query) as unique_crypto_queries by src_ip
| where unique_crypto_queries > 10
| join src_ip [
    search `crowdstrike` 
    (FileName="*wallet*" OR ProcessCommandLine="*wallet*" OR ProcessCommandLine="*crypto*" OR ProcessCommandLine="*bitcoin*")
]
| table src_ip, ComputerName, unique_crypto_queries, ProcessCommandLine
```


