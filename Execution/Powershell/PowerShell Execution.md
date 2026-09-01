# PowerShell Execution Detection

## Overview

This lab focused on detecting suspicious PowerShell execution on a Windows endpoint.  
The activity maps to MITRE ATT&CK T1059.001, PowerShell, under the Command and Scripting Interpreter technique.  
PowerShell is commonly used for legitimate administration, but it can also be abused to execute commands, scripts, download payloads, perform discovery, and support other stages of an attack.  
For this lab, I used harmless PowerShell commands so the detection could be tested without deploying an actual payload.

## Lab Objective

The main objective was to generate PowerShell telemetry and verify that the activity could be detected through Windows PowerShell logging and Sysmon.  
The detection was based primarily on:  
Sysmon Event ID 1 for process creation  
PowerShell Event ID 4104 for Script Block Logging  
The combination provides better visibility than simply searching for powershell.exe. MITRE's current detection strategy also recommends correlating PowerShell execution with encoded commands, unusual parent processes, suspicious modules, network activity, and child process creation.

## Attack Simulation

A normal PowerShell command was first executed to generate basic PowerShell process activity.

```powershell
powershell.exe -NoProfile -Command "Get-ComputerInfo | Select-Object WindowsProductName, WindowsVersion, OsArchitecture"
```

I then generated an encoded PowerShell command using a harmless Get-Date command.

```powershell
$cmd = 'Get-Date'
$encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($cmd))
powershell.exe -NoProfile -EncodedCommand $encoded
```

The purpose of using the encoded command was to reproduce a behavior that defenders may want to investigate without executing malicious code.

## PowerShell Logging

PowerShell Script Block Logging was enabled so that executed script blocks could be captured.  
The relevant log channel is:

```text
Microsoft-Windows-PowerShell/Operational
```

The main event used during the investigation was Event ID 4104.  
Event 4104 provides visibility into PowerShell script block execution and is one of the telemetry sources used by MITRE's current PowerShell detection strategy.

## Sysmon Telemetry

Sysmon Event ID 1 was used to identify the PowerShell process creation.  
The important fields during the investigation included:

```text
Image
CommandLine
ParentImage
ParentCommandLine
User
ProcessId
```

The command line and parent process are particularly useful because they provide context around how PowerShell was started.  
MITRE's detection guidance specifically recommends looking at encoded or obfuscated PowerShell arguments and abnormal process lineage instead of treating every PowerShell execution as malicious.

## Detection Logic

A simple detection such as:

```text
process.name: powershell.exe
```

would create a lot of noise because PowerShell is widely used for legitimate administration.  
A better approach is to look for PowerShell execution combined with suspicious command line indicators.  
Example:

```text
event.code: "1"
AND process.name: "powershell.exe"
AND process.command_line: (*-enc* OR *-encodedcommand* OR *-nop* OR *-noprofile*)
```

The exact field names may vary depending on the Winlogbeat and ECS mapping used in the environment.  
Another useful query is:

```text
event.code: "4104"
```

This allows the analyst to inspect the actual PowerShell script block associated with the activity.

## Investigation Process

When a PowerShell alert is generated, I would investigate it in the following order:

1. Identify the PowerShell process
    
2. Review the complete command line
    
3. Identify the user who launched it
    
4. Check the parent process
    
5. Locate the corresponding PowerShell 4104 event
    
6. Review the script block contents
    
7. Check whether PowerShell spawned another process
    
8. Check for network activity around the same timestamp
    
9. Determine whether the activity matches an approved administrative task
    
10. Escalate if the execution chain contains suspicious or unexplained behavior  
    This approach helps distinguish normal PowerShell administration from potentially malicious execution.
    

## Important Detection Indicators

The following behaviors deserve additional investigation:

```text
powershell.exe with -EncodedCommand
powershell.exe with heavily obfuscated arguments
PowerShell launched by an unusual parent process
PowerShell running under an unexpected user
PowerShell spawning cmd.exe or another executable
PowerShell followed by network connections
PowerShell creating suspicious files
PowerShell executing unusually long script blocks
```

MITRE's current PowerShell detection strategy specifically highlights encoded commands, unusual parent processes, suspicious modules, network connections, and child process spawning as useful behavioral indicators.

## Telemetry Used

|Source|Event ID|Purpose|
|---|--:|---|
|Sysmon|1|Process Creation|
|PowerShell|4104|Script Block Logging|
|PowerShell|4103|Module Logging, if enabled|
|PowerShell|4105|Script block start, if available|
|PowerShell|4106|Script block stop, if available|
|Sysmon|3|Network Connection, when applicable|
|MITRE currently lists PowerShell Events 4103, 4104, 4105 and 4106 alongside Sysmon Event ID 1 as relevant sources for its PowerShell execution detection strategy.|||

## MITRE ATT&CK Mapping

Technique: Command and Scripting Interpreter  
Sub Technique: PowerShell  
Technique ID: T1059.001  
Tactic: Execution  
Platform: Windows  
The activity is mapped to T1059.001 according to the current MITRE ATT&CK technique entry.

## Result

The lab successfully demonstrated how PowerShell execution can be investigated using endpoint telemetry instead of relying only on the presence of powershell.exe.  
Sysmon provided process creation context while PowerShell Script Block Logging provided visibility into the executed script content.  
The main takeaway from this lab is that PowerShell itself is not necessarily malicious. The useful detection comes from understanding the context around its execution, especially the command line, parent process, user, script contents, and related activity.

## Conclusion

This detection provides a good foundation for more advanced PowerShell monitoring.  
The next step would be to correlate PowerShell execution with process creation, network connections, file creation, and suspicious parent processes to build a stronger behavioral detection rather than relying on simple keyword matching.