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


# Core Detection

```
`wineventlog_security` EventCode=4662 
    ObjectType="*computer*" 
    AccessMask="0x20"
    Properties="*3f78c3e5-f79a-46bd-a0b8-9d18116ddc79*"
| eval 
    property_guid="3f78c3e5-f79a-46bd-a0b8-9d18116ddc79",
    property_name="msDS-AllowedToActOnBehalfOfOtherIdentity",
    attack_technique="T1558.003/T1550 - RBCD Configuration",
    src_user=mvindex(split(SubjectUserName,"$"),0),
    is_machine_account=if(match(SubjectUserName,"\$$"),"true","false")
| lookup delegation_admin_allowlist SubjectUserName OUTPUT allowed
| search allowed!="true"
| lookup asset_category dest AS ObjectName OUTPUT asset_tier, asset_criticality
| eval risk_score=case(
    asset_tier="tier0", 90,
    asset_tier="tier1", 70,
    is_machine_account="true", 60,
    1=1, 50)
| table _time, SubjectUserName, SubjectDomainName, ObjectName, ObjectDN, 
        property_name, AccessMask, risk_score, asset_tier, attack_technique, 
        Computer, SubjectLogonId
| sort - risk_score, - _time
```


# Correlated

```
`wineventlog_security` (EventCode=4662 OR EventCode=4769)
| eval 
    event_type=case(
        EventCode=4662 AND AccessMask="0x20" AND match(Properties,"3f78c3e5-f79a-46bd-a0b8-9d18116ddc79"), "rbcd_write",
        EventCode=4769, "kerberos_tgs"
    )
| where isnotnull(event_type)
| eval 
    actor=case(
        event_type="rbcd_write", SubjectUserName,
        event_type="kerberos_tgs", TargetUserName
    ),
    actor_domain=case(
        event_type="rbcd_write", SubjectDomainName,
        event_type="kerberos_tgs", TargetDomainName
    ),
    rbcd_target=if(event_type="rbcd_write", ObjectName, null()),
    tgs_service=if(event_type="kerberos_tgs", ServiceName, null()),
    tgs_ticket_options=if(event_type="kerberos_tgs", TicketOptions, null()),
    tgs_ticket_encryption=if(event_type="kerberos_tgs", TicketEncryptionType, null())
| eval actor=lower(replace(actor,"\$$",""))
| eval rbcd_target=lower(replace(rbcd_target,"\$$","")),
       tgs_service=lower(replace(tgs_service,"\$$",""))
| stats 
    earliest(eval(if(event_type="rbcd_write",_time,null()))) as rbcd_write_time,
    latest(eval(if(event_type="rbcd_write",_time,null()))) as rbcd_write_latest,
    values(rbcd_target) as rbcd_targets,
    earliest(eval(if(event_type="kerberos_tgs",_time,null()))) as tgs_first_time,
    latest(eval(if(event_type="kerberos_tgs",_time,null()))) as tgs_last_time,
    values(tgs_service) as tgs_services_requested,
    values(tgs_ticket_options) as tgs_options,
    values(tgs_ticket_encryption) as tgs_enc_types,
    dc_values(eval(if(event_type="kerberos_tgs",tgs_service,null()))) as distinct_tgs_services,
    count(eval(event_type="rbcd_write")) as rbcd_write_count,
    count(eval(event_type="kerberos_tgs")) as tgs_count
    by actor, actor_domain
| where rbcd_write_count > 0 AND tgs_count > 0
| eval time_delta_sec=tgs_first_time - rbcd_write_time
| where time_delta_sec >= 0 AND time_delta_sec <= 600
| eval 
    tgs_targets_match_rbcd=if(mvcount(mvfilter(match(tgs_services_requested,mvjoin(rbcd_targets,"|"))))>0,"true","false"),
    rbcd_write_time_readable=strftime(rbcd_write_time,"%Y-%m-%d %H:%M:%S"),
    tgs_first_time_readable=strftime(tgs_first_time,"%Y-%m-%d %H:%M:%S"),
    attack_chain="T1558.003 - RBCD: AllowedToAct write followed by TGS request within ".time_delta_sec."s",
    risk_score=case(
        tgs_targets_match_rbcd="true" AND time_delta_sec <= 60, 95,
        tgs_targets_match_rbcd="true", 85,
        time_delta_sec <= 60, 70,
        1=1, 60
    )
| lookup delegation_admin_allowlist actor OUTPUT allowed
| search allowed!="true"
| table rbcd_write_time_readable, tgs_first_time_readable, time_delta_sec,
        actor, actor_domain, rbcd_targets, tgs_services_requested, 
        tgs_targets_match_rbcd, rbcd_write_count, tgs_count, 
        tgs_enc_types, risk_score, attack_chain
| sort - risk_score, rbcd_write_time_readable
```
