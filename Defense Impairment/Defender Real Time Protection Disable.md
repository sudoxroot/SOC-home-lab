# Defender Real Time Protection Disable Detection

## Overview

This lab demonstrates the detection of an attempt to disable Microsoft Defender Real Time Protection on a Windows endpoint.  
The activity maps to MITRE ATT&CK **T1562.001 – Impair Defenses: Disable or Modify Tools**, a technique attackers can use to weaken security controls and reduce endpoint visibility.  
The simulation was performed on a Windows lab machine using PowerShell. The main objective was not to bypass the security controls completely, but to generate realistic endpoint telemetry and investigate how a SOC analyst could detect the activity.

## Lab Environment

**Attacker:** Kali Linux  
**Victim:** Windows 10/11  
**Monitoring:** Sysmon  
**Log Collection:** Winlogbeat  
**SIEM:** Elasticsearch + Logstash + Kibana  
**Security Control:** Microsoft Defender

## Attack Simulation

The following PowerShell command was used from an elevated PowerShell session:

```powershell
Set-MpPreference -DisableRealtimeMonitoring $true
```

This attempts to disable Microsoft Defender Real Time Protection.  
The resulting Defender state was then checked with:

```powershell
Get-MpComputerStatus | Select-Object RealTimeProtectionEnabled
```

The configuration was also checked with:

```powershell
Get-MpPreference | Select-Object DisableRealtimeMonitoring
```

If Tamper Protection prevents the change, the command may fail. This is still useful from a detection perspective because the attempted modification itself is suspicious and can generate relevant telemetry.

## MITRE ATT&CK

**Tactic:** Defense Evasion  
**Technique:** T1562.001  
**Name:** Impair Defenses: Disable or Modify Tools  
The technique covers attempts to disable, modify, or interfere with security tools such as antivirus, EDR, logging agents, and other defensive mechanisms.

## Detection

The primary detection source was Sysmon Event ID 1, which provides process creation telemetry.  
The important process was:

```text
powershell.exe
```

The command line was then inspected for Defender configuration changes such as:

```text
Set-MpPreference
DisableRealtimeMonitoring
```

A useful Kibana query for the collected ECS data is:

```text
process.name : "powershell.exe" AND process.command_line : "*Set-MpPreference*"
```

A more specific query is:

```text
process.name : "powershell.exe" AND process.command_line : "*DisableRealtimeMonitoring*"
```

If the command line is stored inside the raw event message instead of an ECS field, searching for `Set-MpPreference` or `DisableRealtimeMonitoring` in the event message can also be useful.

## PowerShell Telemetry

PowerShell Operational logging can provide another layer of visibility.  
The relevant log is:

```text
Microsoft-Windows-PowerShell/Operational
```

If Script Block Logging is enabled, the executed PowerShell content can provide direct evidence of the attempted Defender modification.  
Useful event information includes:

```text
PowerShell execution
Set-MpPreference
DisableRealtimeMonitoring
User account
Host name
Parent process
Timestamp
```

Using both Sysmon and PowerShell telemetry makes the detection more reliable because the activity can be investigated from multiple sources.

## Investigation

Once the alert is triggered, the first step is to identify which account executed the command.  
Next, I would check the parent process of PowerShell to determine how PowerShell was launched.  
The complete command line should then be reviewed to determine exactly which Defender setting was being modified.  
I would also investigate activity immediately before and after the event.  
For example, suspicious activity before the Defender modification could include unusual PowerShell execution, script interpreters, downloaded files, or other execution techniques.  
Activity after the modification could include credential access, persistence, file creation, or network connections.  
The important part of the investigation is the timeline. A Defender modification followed by other suspicious activity is much more concerning than an administrator making an isolated configuration change.

## False Positives

There are legitimate situations where Defender settings may be changed.  
Possible examples include:  
**System administration**  
**Security testing**  
**Troubleshooting**  
**Software deployment**  
**Enterprise configuration management**  
Because of this, `Set-MpPreference` should not automatically be treated as malicious without considering the user, parent process, host, timing, and surrounding activity.

## Severity

**Initial Severity:** Medium  
**Severity can be increased to High or Critical when combined with other suspicious activity.**  
For example:  
PowerShell execution alone: Low  
PowerShell modifying Defender: Medium  
Defender modification by an unusual user or process: High  
Defender modification followed by credential access or lateral movement: Critical

## Remediation

After completing the simulation, Defender configuration was restored:

```powershell
Set-MpPreference -DisableRealtimeMonitoring $false
```

The Defender status was then checked again:

```powershell
Get-MpComputerStatus | Select-Object RealTimeProtectionEnabled
```

I also recommend checking Defender exclusions after the test:

```powershell
Get-MpPreference | Select-Object ExclusionPath,ExclusionProcess,ExclusionExtension
```

MITRE recommends auditing security tools and checking for unexpected Defender exclusions as part of defense impairment monitoring.

## Key Takeaway

This lab showed why a SOC should not only monitor obvious malware execution.  
Attackers may first try to weaken the security controls protecting the endpoint.  
A PowerShell command that attempts to disable Defender can therefore become an important early warning signal.  
The strongest detection comes from correlating the Defender modification with the user, parent process, command line, PowerShell telemetry, and the activity that happens immediately before and after it.

## Evidence

Screenshots included with this lab show the PowerShell execution, generated Windows/Sysmon telemetry, and the corresponding Kibana detection.

## References

MITRE ATT&CK: T1562.001 – Impair Defenses: Disable or Modify Tools  
Microsoft Defender PowerShell documentation: Set-MpPreference