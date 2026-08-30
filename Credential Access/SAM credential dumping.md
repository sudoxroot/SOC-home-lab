# SAM Credential Dumping Detection

## Overview

This lab focused on detecting an attempted SAM credential dumping attack against a Windows endpoint.  
The activity maps to MITRE ATT&CK T1003.002, Security Account Manager, under OS Credential Dumping.  
The simulation attempted to export the Windows SAM and SYSTEM registry hives using `reg.exe`.  
Microsoft Defender detected and blocked the activity before the hive files could be successfully created.  
The investigation was performed using Sysmon, Windows Security logs, Microsoft Defender, and ELK.

## Lab Environment

  
Victim: Windows  
SIEM: ELK Stack  
Endpoint Telemetry: Sysmon  
Endpoint Protection: Microsoft Defender  
MITRE ATT&CK: T1003.002

## Attack Simulation

The SAM hive was targeted with:  
`reg.exe save HKLM\SAM C:\Temp\sam_lab\sam.save`  
The SYSTEM hive was also targeted with:  
`reg.exe save HKLM\SYSTEM C:\Temp\sam_lab\system.save`  
The goal was to reproduce the behavior of an attacker attempting to obtain the registry hives used during local credential extraction.  
Microsoft Defender detected the activity and blocked it.  
The expected files were not created:  
`C:\Temp\sam_lab\sam.save`  
`C:\Temp\sam_lab\system.save`  
Because the files were never successfully written, there was no new Sysmon Event ID 11 for these specific files.

## Telemetry

### Sysmon Event ID 1

Sysmon Event ID 1 provided the main process creation telemetry for the investigation.  
The event included useful information such as:  
`Image`  
`CommandLine`  
`User`  
`IntegrityLevel`  
`ParentImage`  
`ParentCommandLine`  
The test confirmed that command line information was available and could be used for detection.  
The simulated SAM command appeared through `cmd.exe` with:  
`echo reg save HKLM\SAM C:\Temp\sam_lab\sam.save`  
The SYSTEM simulation was recorded in the same way.

### Sysmon Event ID 11

Sysmon Event ID 11 was already working on the endpoint and previous file creation events were visible.  
However, no new Event ID 11 appeared for `sam.save` or `system.save`.  
This was expected because Defender blocked the operation before the files could be created.  
**This was an important part of the investigation because the absence of a FileCreate event did not mean the credential access attempt did not happen.**

### Windows Security Event ID 4688

Windows Security Event ID 4688 can also provide process creation visibility and can be useful as a secondary source for command line based detection.  
For this particular test, Sysmon Event ID 1 and Microsoft Defender provided the strongest confirmed evidence.

### Microsoft Defender

Microsoft Defender recorded the actual `reg.exe` activity and detected the attempted hive exports.  
The observed commands included:  
`C:\Windows\System32\reg.exe save HKLM\SAM C:\Temp\sam_lab\sam.save`  
`C:\Windows\System32\reg.exe save HKLM\SYSTEM C:\Temp\sam_lab\system.save`  
The Defender telemetry showed `ActionSuccess: True`, confirming that Defender successfully handled the detected activity.
<img width="604" height="52" alt="a1" src="https://github.com/user-attachments/assets/34f6e27b-1f96-4387-9275-aa68fe400b99" />


## Detection Logic

The main detection opportunity is suspicious use of `reg.exe` to save sensitive registry hives.  
A useful detection condition is:  
<img width="1296" height="615" alt="e1" src="https://github.com/user-attachments/assets/a0e2cb27-e322-473e-a3eb-f0df33684bc0" />

`process.name: reg.exe`  
combined with:  
`process.command_line: *save*`  
and either:  
`process.command_line: *HKLM\SAM*`  
or:  
`process.command_line: *HKLM\SYSTEM*`  
The goal is to detect the combination of the executable and suspicious command line rather than alerting on every normal use of `reg.exe`.



### Kibana KQL

SAM hive:  
`process.name : "reg.exe" and process.command_line : ("*save*" and "*HKLM\\SAM*")`  
SYSTEM hive:  
`process.name : "reg.exe" and process.command_line : ("*save*" and "*HKLM\\SYSTEM*")`  
Broader hunt:  
`process.name : "reg.exe" and process.command_line : ("*HKLM\\SAM*" or "*HKLM\\SYSTEM*")`  
Field names can vary depending on the Winlogbeat and ECS configuration, so the raw Sysmon event should be checked if the query does not return results.
<img width="1917" height="842" alt="elk1" src="https://github.com/user-attachments/assets/8c38d4b9-1c95-4c75-bf29-d4d52bf76453" />

## Investigation

The first step was to identify the process responsible for the activity and confirm that `reg.exe` was involved.  
The executable path was checked to verify that it was the legitimate Windows binary:  
`C:\Windows\System32\reg.exe`  
The full command line was then reviewed for suspicious registry operations, particularly:  
`reg save HKLM\SAM`  
`reg save HKLM\SYSTEM`  
The associated user account was checked to determine whether the activity was expected administrative behavior.  
The parent process was also reviewed. An unexpected PowerShell process, command shell, script interpreter, or other unusual parent would increase the suspicion level.  
Process integrity was checked to determine whether the activity was running with elevated privileges.  
Additional events around the same timestamp were then reviewed, including `cmd.exe`, `powershell.exe`, other `reg.exe` executions, SAM and SYSTEM references, file creation events, and Defender detections.  
Finally, the destination directory was checked to determine whether the hive files actually existed.  
In this lab, they did not because Defender blocked the operation.

## False Positives

There are legitimate situations where administrators or security tools may interact with the registry using `reg.exe`.  
Potential sources include:  
System administration  
Registry troubleshooting  
Backup and recovery operations  
Security and forensic tools  
Administrative scripts  
Because of this, the detection should not simply alert on every execution of `reg.exe`.  
Combining `reg.exe` with `save` and sensitive hives such as `HKLM\SAM` or `HKLM\SYSTEM` produces a much stronger detection signal.  
The user, parent process, destination path, privilege level, and surrounding activity should still be reviewed before making a final decision.

## Severity

Recommended Severity: High  
The activity targets credential material stored in the SAM registry hive and can indicate an attempt to obtain local account password hashes.  
The SYSTEM hive may also be targeted as part of the credential extraction process.  
In this lab, the actual impact was reduced because Microsoft Defender detected and blocked the activity.  
If the hive export succeeds, the incident should be treated with higher urgency and investigated for possible credential compromise.

## Analyst Verdict

Verdict: Suspicious Credential Access Attempt  
The simulated attack was unsuccessful because Microsoft Defender blocked the registry hive export.  
However, the attempt itself was significant enough to investigate.  
From a SOC perspective, successful credential extraction is not required for the behavior to be considered suspicious. The attempted access can provide an early indicator of an attacker moving toward credential theft.

## MITRE ATT&CK

Tactic: Credential Access  
Technique: T1003 OS Credential Dumping  
Sub Technique: T1003.002 Security Account Manager  
Technique Name: Security Account Manager

## Key Findings

Sysmon Event ID 1 was confirmed to be working correctly.  
Process creation and command line information were available for investigation.  
Microsoft Defender detected the actual SAM and SYSTEM hive export attempts.  
The expected SAM and SYSTEM files were not created.  
No new Sysmon Event ID 11 was generated for the attempted files.  
Previous Event ID 11 events confirmed that FileCreate telemetry was functioning correctly.  
The strongest detection signal was the combination of suspicious `reg.exe` command line activity and Microsoft Defender telemetry.  
One of the main lessons from this lab was that a blocked attack may not produce every expected telemetry event.  
If Defender stops the operation before a file is created, there may be no corresponding FileCreate event.  
This is why process telemetry, endpoint protection alerts, and SIEM data should be investigated together.


    

## Conclusion

This lab demonstrated the detection of a SAM credential dumping attempt even though the actual credential extraction was prevented.  
Sysmon Event ID 1 provided the process and command line visibility, while Microsoft Defender provided confirmation that the suspicious registry operations were detected and blocked.  
The attempted access to `HKLM\SAM` and `HKLM\SYSTEM` was the key behavioral indicator.  
The missing Event ID 11 was also useful information rather than a telemetry failure. Defender stopped the operation before the target files could be created.  
For a SOC analyst, the main takeaway is that detection should not depend on a single event type. Combining process creation telemetry, command line analysis, endpoint protection alerts, and SIEM investigation provides a much clearer picture of what actually happened.
