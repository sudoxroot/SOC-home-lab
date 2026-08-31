
# Scheduled Task Creation Detection

## Overview

This lab demonstrates the detection of Windows Scheduled Task creation, a technique commonly abused by attackers for persistence and execution.

The activity maps to MITRE ATT&CK T1053.005, Scheduled Task/Job: Scheduled Task.

The attack was simulated on a Windows endpoint by creating a scheduled task using `schtasks.exe`. The task was configured to execute a harmless command that writes a test entry to a local file.

The main goal of the lab was not just to create the task, but to detect and investigate the activity using Windows Security logs and Sysmon telemetry forwarded into ELK.

## MITRE ATT&CK Mapping

Tactic: Persistence

Technique: T1053.005

Technique Name: Scheduled Task/Job: Scheduled Task

The same technique can also be used for execution, depending on how the scheduled task is being abused.

## Attack Simulation

A test directory was created on the Windows endpoint:

```powershell
New-Item -ItemType Directory -Path C:\SOC-Lab -Force
```

A scheduled task was then created using:

```powershell
schtasks /create /tn "SOC-Lab-Test2" /tr "cmd.exe /c echo ScheduledTaskExecuted >> C:\SOC-Lab\execution.log" /sc once /st 23:59 /f
```

The task was manually executed for testing:

```powershell
schtasks /run /tn "SOC-Lab-Test2"
```
<img width="834" height="241" alt="a1" src="https://github.com/user-attachments/assets/d067d8da-a36d-4fff-9d3f-64dc3b0841d1" />

The resulting file was checked to confirm that the task executed successfully:

```powershell
Get-Content C:\SOC-Lab\execution.log
```
<img width="778" height="31" alt="e1" src="https://github.com/user-attachments/assets/f97a9632-d373-47ca-a28d-71bb3cd4ad68" />

## Detection

The main Windows Security event used for this detection was Event ID 4698.

Event ID 4698 records the creation of a scheduled task and can provide useful information such as the task name, task content and account involved.

The event was initially not appearing because the required auditing was disabled.

The auditing configuration was checked with:

```powershell
auditpol /get /subcategory:"Other Object Access Events"
```

After enabling the required auditing:

```powershell
auditpol /set /subcategory:"Other Object Access Events" /success:enable /failure:enable
```

the scheduled task was created again and the resulting Security event was investigated.

## Sysmon Telemetry

Sysmon Event ID 1 was also used to identify the process responsible for creating the scheduled task.

The relevant process was:

```text
schtasks.exe
```

The important fields during investigation were:

```text
Image
CommandLine
ParentImage
User
ProcessId
ParentProcessId
UtcTime
```

The command line was especially useful because it showed that `schtasks.exe` was being used to create the scheduled task.

The parent process was also reviewed to determine whether the activity originated from PowerShell, Command Prompt, an interactive user session or another process.
I also checked the Event ID 4698 cuz it was generated when a scheduled task is assigned to the system:
<img width="1340" height="749" alt="e2" src="https://github.com/user-attachments/assets/38a3d9c5-a06f-4f13-83a3-9b5b39ab4a67" />

## Detection Query

A basic Kibana query for scheduled task creation:

```text
event.code:"4698"
```

A more focused search can look for scheduled tasks containing command interpreters:

```text
event.code:"4698" AND winlog.event_data.TaskContent:*cmd*
```

PowerShell activity can also be investigated with:

```text
event.code:"4698" AND winlog.event_data.TaskContent:*powershell*
```

The exact field names may vary depending on the Winlogbeat and ECS configuration, so the raw Event ID 4698 document should be inspected first if these fields do not return results.
<img width="1637" height="774" alt="elk1" src="https://github.com/user-attachments/assets/cdf724f4-e515-42c6-a44d-5f665a0966b8" />

## Investigation Steps

The investigation started by identifying Event ID 4698 in the Windows Security logs.

The task name and task content were then reviewed to understand what the scheduled task was configured to execute.

Next, Sysmon Event ID 1 was checked for `schtasks.exe`.

The command line was examined to determine how the task was created.

The parent process was investigated to establish where the activity originated.

The user account responsible for creating the task was also reviewed.

Finally, the task execution was confirmed by checking for the resulting process activity and the test file created by the task.

## Investigation Timeline

```text
PowerShell
    |
    v
schtasks.exe
    |
    v
Scheduled Task Created
    |
    v
Security Event ID 4698
    |
    v
Scheduled Task Executed
    |
    v
cmd.exe
    |
    v
Test File Created
```

This timeline provides a simple example of how process telemetry and Windows Security telemetry can be combined to understand the complete activity.

## Suspicious Indicators

Scheduled task creation is not automatically malicious.

During a real investigation, I would pay closer attention to tasks that:

```text
Use PowerShell or command interpreters
Execute files from temporary or unusual directories
Use randomly generated task names
Run under SYSTEM unexpectedly
Execute scripts or encoded commands
Run at logon or startup
Are created by unusual accounts
Appear shortly after another suspicious process
Connect to external systems after execution
```

A task named `SOC-Lab-Test2` executing a harmless command is expected in this lab.

A randomly named task executing PowerShell from an unusual directory would require much more investigation.

## False Positives

Scheduled tasks are heavily used by Windows and legitimate software.

Possible sources of legitimate scheduled task creation include:

```text
Windows maintenance
Microsoft Defender
Software updates
Backup applications
Monitoring software
Enterprise management tools
Application installers
System administrators
```

Because of this, detecting every Event ID 4698 as malicious would create unnecessary alerts.

The task name, command line, user, parent process and execution context should all be considered before escalating the alert.

## Severity

Medium

The severity can increase when scheduled task creation is combined with other suspicious activity such as PowerShell execution, encoded commands, unusual executables, SYSTEM execution or network connections.

## Telemetry Used

```text
Windows Security Event ID 4698
Sysmon Event ID 1
Process Creation
Command Line
Parent Process
User Account
Task Name
Task Content
```

## Cleanup

The test scheduled task was removed after the investigation:

```powershell
schtasks /delete /tn "SOC-Lab-Test2" /f
```

The lab directory can also be removed:

```powershell
Remove-Item C:\SOC-Lab -Recurse -Force
```

## Key Takeaway

This lab showed how a relatively simple Windows feature can become useful attacker infrastructure.

The important part of the detection was not just finding `schtasks.exe`. The investigation became much more useful when the process creation event was correlated with Windows Security Event ID 4698 and the scheduled task's actual contents.

This is also a good example of why endpoint telemetry needs to be combined rather than relying on a single event ID.
