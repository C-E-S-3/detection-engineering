# Role Based Delegation


```
| tstats summariesonly=t count from datamodel=Endpoint.Authentication 
    where nodename=Authentication 
        Authentication.signature_id=4662 
        Authentication.dest=$target$ 
    by Authentication.src_user, Authentication.dest, _time span=5m
| join type=inner src_user dest [
    search `wineventlog_security` EventCode=4769 
    | rename TargetUserName as target_user, ServiceName as dest
    | stats count by src_user, dest, _time
]
| where count > 0
```


# Write Delegation

```
`wineventlog_security` EventCode=4662 AccessMask="0x20"
| rex field=Properties "(?<property_guids>[a-f0-9\-]{36})" max_match=20
| eval delegation_properties=mvfilter(match(property_guids,
    "3f78c3e5-f79a-46bd-a0b8-9d18116ddc79|800d94d7-b7a1-42a1-b14d-7cae1423d07f|bf967a68-0de6-11d0-a285-00aa003049e2"))
| where mvcount(delegation_properties) > 0
| eval property_name=case(
    match(Properties,"3f78c3e5-f79a-46bd-a0b8-9d18116ddc79"), "msDS-AllowedToActOnBehalfOfOtherIdentity (RBCD)",
    match(Properties,"800d94d7-b7a1-42a1-b14d-7cae1423d07f"), "msDS-AllowedToDelegateTo (Constrained)",
    match(Properties,"bf967a68-0de6-11d0-a285-00aa003049e2"), "userAccountControl (possible TFD flip)")
| eval attack_severity=case(
    match(property_name,"RBCD"), "critical",
    match(property_name,"Constrained"), "high",
    match(property_name,"userAccountControl"), "medium")

```


# RBA Scaling

```
`wineventlog_security` EventCode=4662 AccessMask="0x20"
    Properties="*3f78c3e5-f79a-46bd-a0b8-9d18116ddc79*"
| lookup delegation_admin_allowlist SubjectUserName OUTPUT allowed
| search allowed!="true"
| stats count as event_count, 
        values(ObjectName) as target_objects,
        earliest(_time) as first_seen,
        latest(_time) as last_seen
        by SubjectUserName, SubjectDomainName, Computer
| eval normalized_count=min(event_count, 10),
       risk_score=(normalized_count * 4.0) + 1.0,
       risk_object=SubjectUserName,
       risk_object_type="user",
       threat_object="msDS-AllowedToActOnBehalfOfOtherIdentity",
       threat_object_type="other",
       risk_message="User ".SubjectUserName." wrote RBCD property on ".mvcount(target_objects)." computer object(s) - possible RBCD takeover attack",
       mitre_technique_id="T1558.003"
| table _time, risk_object, risk_object_type, risk_score, 
        threat_object, threat_object_type, risk_message, 
        mitre_technique_id, target_objects
```

# Check UserAccountControl

```
`wineventlog_security` EventCode=4742 
| eval tfd_before=if(like(OldUacValue,"%0x80000%"),"true","false"),
       tfd_after=if(like(NewUacValue,"%0x80000%"),"true","false")
| where tfd_before="false" AND tfd_after="true"
```
