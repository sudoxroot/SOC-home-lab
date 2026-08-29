

## Overview

This lab demonstrates the detection of an LSASS memory access attempt on a Windows endpoint using Sysmon and ELK.

The technique is mapped to MITRE ATT&CK T1003.001, OS Credential Dumping: LSASS Memory.

The goal was not just to perform the attack, but to understand what endpoint telemetry it creates and how that activity can be identified from a SOC perspective.

## Lab Environment

Victim & Attack: Windows 10

Monitoring: Sysmon

Log Collection: Winlogbeat

Log Processing: Logstash

SIEM: Elasticsearch and Kibana

## Attack Concept

LSASS, or Local Security Authority Subsystem Service, is responsible for important Windows authentication operations.

An attacker with sufficient privileges may attempt to access the memory of lsass.exe to obtain credential material.

The behavior I focused on detecting was a suspicious process attempting to access:

C:\Windows\System32\lsass.exe

This activity is useful for detection because Sysmon can generate Event ID 10 when one process accesses another process.

## Sysmon Configuration

Initially, the ProcessAccess section of the Sysmon configuration was empty:

```xml
<ProcessAccess onmatch="include">
</ProcessAccess>
```

Because there were no conditions inside the include rule, Sysmon was not generating the required Process Access events.

I changed the configuration to specifically monitor LSASS:

```xml
<ProcessAccess onmatch="include">
    <TargetImage condition="end with">lsass.exe</TargetImage>
</ProcessAccess>
```

This keeps the telemetry focused instead of logging every process access event on the system.

## Applying the Configuration

After modifying the XML file, I reloaded the configuration:

```powershell
cd C:\Sysmon
.\sysmon64.exe -c .\sysmonconfig-export.xml
```

I then verified the active Sysmon configuration:

```powershell
.\sysmon64.exe -c
```

The important thing to confirm was that ProcessAccess contained the LSASS target rule.

## Attack

I attacked via the process dumping tool (procdump) which tried to assess lsass.exe but failed due to system securtiy :


## Detection

The primary telemetry for this technique is:
Sysmon Event ID 10: Process Access
I checked the Windows Sysmon Operational log with:

```powershell
Get-WinEvent -FilterHashtable @{
    LogName="Microsoft-Windows-Sysmon/Operational"
    Id=10
} -MaxEvents 10
```

I also used:

```powershell
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" |
Where-Object {$_.Id -eq 10} |
Select-Object -First 10
```

The detection should identify events where the target process is lsass.exe.

## Important Fields

The most useful fields during investigation are:

SourceImage

TargetImage

GrantedAccess

SourceProcessId

TargetProcessId

User

CallTrace

The most important relationship is:

SourceImage → accesses → lsass.exe

A legitimate Windows process accessing LSASS is not automatically malicious. The source process, its location, parent process, user context and access rights all need to be considered.

## ELK Detection

Once the Sysmon event is successfully forwarded through Winlogbeat and Logstash into Elasticsearch, the first Kibana query can be:

```text
event.code: 10
```

A more focused query is:

```text
event.code: 10 AND winlog.event_data.TargetImage: "*lsass.exe"
```

Depending on the ECS mapping, the TargetImage field may need to be searched directly.

The investigation should then focus on identifying the process responsible for accessing LSASS.

## Investigation Approach

When an LSASS access event appears, I would investigate it in this order:

1. Identify the SourceImage.
2. Confirm the TargetImage is lsass.exe.
3. Check the GrantedAccess value.
4. Identify the user associated with the process.
5. Check the process creation event.
6. Investigate the parent process.
7. Check whether the executable is running from a suspicious location.
8. Correlate the activity with other events around the same timestamp.

For example, a suspicious process launched from a user writable directory and subsequently accessing LSASS would deserve much more attention than a known Windows security component.

## MITRE ATT&CK Mapping

Tactic: Credential Access

Technique: T1003, OS Credential Dumping

Sub technique: T1003.001, LSASS Memory

Telemetry: Sysmon Event ID 10, Process Access

## Detection Logic

A basic detection can be represented as:

```text
Sysmon Event ID 10
AND
TargetImage = lsass.exe
```

A stronger detection adds context:

```text
Sysmon Event ID 10
AND
TargetImage = lsass.exe
AND
SourceImage is suspicious or unexpected
```

Additional indicators such as unusual process location, suspicious parent process, unexpected user context and abnormal access rights can help reduce false positives.

## What I Learned

The main issue in this lab was not the SIEM itself. The problem was the endpoint telemetry configuration.

Sysmon was running correctly and was already generating other events, but Event ID 10 was missing because ProcessAccess had no actual filtering rule.

This was a good reminder that detection starts at the endpoint. If the required telemetry is not generated by the endpoint, the SIEM cannot magically recover it later.

The useful detection chain is:

```text
LSASS access attempt
        ↓
Sysmon Event ID 10
        ↓
Winlogbeat
        ↓
Logstash
        ↓
Elasticsearch
        ↓
Kibana
        ↓
SOC investigation
```

## Conclusion

This lab covered the detection side of LSASS credential access rather than treating credential dumping as simply an offensive tool execution.

The important takeaway is that suspicious access to lsass.exe can provide a strong endpoint detection signal when Sysmon is configured correctly.

The next step would be improving the detection by adding process reputation, parent process, execution path and access rights so that legitimate LSASS activity is separated from genuinely suspicious behavior.