# Windows Service Creation Detection

## Overview

This lab demonstrates the detection of Windows service creation, mapped to MITRE ATT&CK T1543.003, Windows Service.  
The objective was to simulate an attacker creating a new Windows service and then investigate the activity through Windows telemetry and Sysmon.  
The test was performed on a Windows endpoint using `sc.exe` to create a service named `SOC-Lab-Service`.

## MITRE ATT&CK

Technique: Create or Modify System Process  
Sub Technique: T1543.003 Windows Service  
Tactic: Persistence / Privilege Escalation

## Attack Simulation

The service was created from an elevated PowerShell session using:

```powershell
sc.exe create SOC-Lab-Service binPath= "C:\Windows\System32\notepad.exe" start= demand
```

The service was then queried to confirm that it had been created:

```powershell
sc.exe query SOC-Lab-Service
```

The service appeared successfully with the following state:

```text
SERVICE_NAME: SOC-Lab-Service
TYPE               : 10  WIN32_OWN_PROCESS
STATE              : 1  STOPPED
WIN32_EXIT_CODE    : 0  (0x0)
```

An attempt was also made to start the service:

```powershell
sc.exe start SOC-Lab-Service
```

The service returned error 1053:

```text
[SC] StartService FAILED 1053:
The service did not respond to the start or control request in a timely fashion.
```

This happened because `notepad.exe` is a normal Windows application and is not designed to communicate with the Windows Service Control Manager as a service.  
The service creation itself was successful, so the failed start did not prevent the main detection objective from being completed.

## Detection

The primary detection source for this activity is the Windows System log.  
Event ID 7045 indicates that a service was installed on the system.  
The Security log can also provide Event ID 4697 when the relevant auditing is enabled.  
The service creation activity can additionally be correlated with Sysmon Event ID 1, which provides process creation information for `sc.exe`.

## Windows Event 7045

The System log was checked for service installation events using:

```powershell
Get-WinEvent -FilterHashtable @{
    LogName='System'
    Id=7045
} | Select-Object -First 5 | Format-List
```

The investigation focused on the service name, service path, service type, start type and account involved in the installation.

## Windows Event 4697

The Security log was checked for service installation events using:

```powershell
Get-WinEvent -FilterHashtable @{
    LogName='Security'
    Id=4697
} | Select-Object -First 5 | Format-List
```

Event 4697 is useful because it can provide additional security context around the service installation.

## Sysmon Detection

Sysmon Event ID 1 was used to investigate the process responsible for creating the service.  
The following command was used:

```powershell
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" |
Where-Object {$_.Id -eq 1 -and $_.Message -match "sc.exe"} |
Select-Object -First 10 | Format-List
```

The important fields during investigation include the process image, command line, parent process, parent command line, user, process ID and parent process ID.

## ELK Investigation

The activity can be investigated in Kibana by searching for the service name:

```text
SOC-Lab-Service
```

The Windows service installation events can then be investigated using:

```text
event.code: 7045
```

and:

```text
event.code: 4697
```

Sysmon process creation can be investigated using:

```text
event.code: 1
```

A more focused search can be used for the service creation utility:

```text
event.code: 1 AND process.name: "sc.exe"
```

The exact ECS field names may vary depending on the Winlogbeat and Sysmon configuration, so the fields should be verified against the actual events received by Elasticsearch.

## Detection Logic

A basic detection can flag Windows service installation events:

```text
event.code: 7045 OR event.code: 4697
```

A stronger detection should correlate the service installation with process creation and examine the service executable, creating user and parent process.  
Suspicious characteristics include an unexpected service name, an unusual executable path, a service created by an unexpected account, scripting interpreters in the service command line and binaries located in user writable directories.

## Investigation Steps

1. Identify the newly created service.
    
2. Determine which account created the service.
    
3. Check the service executable and its location.
    
4. Identify the process responsible for creating the service.
    
5. Review the parent process and command line.
    
6. Check whether the executable was recently created.
    
7. Determine whether the service was started after creation.
    
8. Search for other suspicious activity from the same user or host.
    
9. Correlate the activity with authentication and process creation events.
    
10. Remove the service after completing the lab.
    

## False Positives

Windows services are commonly created by legitimate software.  
Common examples include security software, backup applications, VPN clients, monitoring agents, application installers and Windows components.  
Because of this, Event 7045 or 4697 should not automatically be treated as malicious.  
Service name, executable path, account, parent process and expected software should be considered before escalating the alert.

## Severity

Medium by default.  
The severity should increase when service creation is combined with suspicious executable paths, unexpected administrative accounts, unusual parent processes or immediate execution.

## Cleanup

After completing the investigation, the test service was removed using:

```powershell
sc.exe stop SOC-Lab-Service
sc.exe delete SOC-Lab-Service
```

This keeps the Windows endpoint clean and prevents the lab service from remaining on the system.

## Key Takeaway

The main lesson from this lab was that service creation should not be investigated from a single event alone.  
Event 7045 provides evidence that a service was installed, while Event 4697 and Sysmon Event 1 can provide additional context.  
Correlating these events makes it easier to distinguish normal software installation from suspicious service creation.  
This lab also highlighted an important part of detection engineering: the attack does not have to execute successfully for useful telemetry to be generated.  
In this case, the service failed to start because the test payload was not a service executable, but the service creation activity itself remained useful for detection and investigation.