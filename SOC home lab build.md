

## 1. Why I'm Building This

Basically I want a small but realistic SOC setup where I can pull logs off a Windows box, ship them to a SIEM, dig into anything sketchy, and eventually write my own detections and alerts.
This is a defensive-security lab, and I'm using it to get hands-on with:

- Windows log analysis
- SIEM monitoring
- Endpoint telemetry
- Sysmon
- Log collection/parsing
- Detection engineering
- MITRE ATT&CK mapping
- Incident investigation
- Alert triage
- Threat hunting
- Basic attack simulation

Just having ELK running isn't the point. What actually matters is generating real security data and then digging into it like an analyst would.

## 2. Lab Architecture

Rough flow:

```
                    SOC Analyst
                         │
                         ▼
                      Kibana
                         │
                         ▼
                  Elasticsearch
                         ▲
                         │
                     Logstash
                         ▲
                         │
                    Winlogbeat
                         ▲
                         │
                Windows 10/11 VM
                         │
                    ┌────┴────┐
                    │         │
              Windows Logs   Sysmon
```

- The Windows box is the monitored endpoint.
- Winlogbeat grabs Windows Event Logs and forwards them to Logstash.
- Logstash receives, processes, and forwards everything.
- Elasticsearch stores and indexes it all.
- Kibana is where I search, visualize, build dashboards, and actually investigate.

Down the line I'll probably bolt on more sources — Linux boxes, network gear, firewall logs, maybe another Windows endpoint.

## 3. Machines

**SIEM Server**

- OS: Ubuntu 24.04
- Runs: Elasticsearch, Logstash, Kibana
- Job: central log collection, storage, analysis, visualization

**Windows Endpoint**

- OS: Windows 10/11
- Runs: Winlogbeat, Sysmon, Windows Event Logs
- Job: generate and forward endpoint security telemetry

**Attacker Machine**

- Kali Linux
- Job: controlled attack simulation only

Kali should only ever be talking to my own lab machines — nothing else.

## 4. Network Setup

All three machines need to see each other.

Example:

- Ubuntu SIEM — `192.168.x.x`
- Windows Victim — `192.168.x.x`
- Kali — `192.168.x.x`

IPs will shift depending on how the VM networking is set up, so don't hardcode anything mentally.

**Always check connectivity before troubleshooting ELK.**

From Windows:

```
ping <SIEM-IP>
```

From Ubuntu:

```
ping <WINDOWS-IP>
```

For Logstash specifically:

```
Test-NetConnection <SIEM-IP> -Port 5044
```

If port 5044 isn't reachable, there's zero point digging into the Winlogbeat config yet.

## 5. Elasticsearch

This is the storage/search engine for everything. It takes structured events and indexes them.

Check the service:

```
sudo systemctl status elasticsearch
```

Check it's responding:

```
curl -k -u elastic https://localhost:9200
```

Stuff worth keeping an eye on:

- Cluster health
- Node status
- Index health
- Disk usage
- Memory usage
- Authentication

Handy command:

```
curl -k -u elastic https://localhost:9200/_cluster/health?pretty
```

The whole idea in one line: **logs → Elasticsearch → searchable data**.

## 6. Logstash

Sits between the collector and Elasticsearch.

Current basic flow:

```
Winlogbeat
     ↓
Logstash :5044
     ↓
Elasticsearch
```

A pipeline is normally three chunks: `input`, `filter`, `output`.

```
input {
    beats {
        port => 5044
    }
}

filter {
    ...
}

output {
    elasticsearch {
        ...
    }
}
```

Keep it dead simple at first. Don't go building elaborate filters right out of the gate — first prove Winlogbeat → Logstash → Elasticsearch actually works end to end, _then_ worry about parsing/enrichment.

## 7. Winlogbeat

Lives on the Windows endpoint, collects Event Logs, ships them to the SIEM.

Channels I care about:

- Security
- System
- Application
- PowerShell

(more can be added depending on config)

Check it:

```
Get-Service winlogbeat
```

Start / stop:

```
Start-Service winlogbeat
Stop-Service winlogbeat
```

Check config:

```
Get-Content "C:\Program Files\Winlogbeat\winlogbeat.yml"
```

Test config:

```
.\winlogbeat.exe test config -c .\winlogbeat.yml
```

Test output/connectivity:

```
.\winlogbeat.exe test output -c .\winlogbeat.yml
```

Also make sure it's set up as a proper Windows service so it survives a reboot.

## 8. Sysmon

Probably the single most important piece of this whole lab. Regular Windows logs are fine, but Sysmon gives way richer endpoint telemetry — stuff like:

- Process creation
- Network connections
- File creation
- Registry activity
- Process relationships
- Command lines
- Hashes
- DNS activity

The big one: **Event ID 1 — Process Creation.**

Lets me answer questions like:

- What ran?
- Who launched it?
- What was the command line?
- What was the parent process?
- When did it happen?

Example chain:

```
WINWORD.EXE
      ↓
powershell.exe
      ↓
cmd.exe
      ↓
suspicious process
```

That kind of chain tells me way more than just "PowerShell ran."

## 9. Event IDs Worth Actually Knowing

Not trying to memorize hundreds of these — just the ones I'll actually use.

**Windows:**

|ID|Meaning|
|---|---|
|4624|Successful logon|
|4625|Failed logon|
|4672|Special privileges assigned|
|4688|Process creation|
|4698|Scheduled task created|
|4720|User account created|
|4728|User added to security-enabled global group|
|4732|User added to security-enabled local group|
|7045|New service installed|
|1102|Security audit log cleared|

**Sysmon:**

|ID|Meaning|
|---|---|
|1|Process creation|
|3|Network connection|
|7|Image loaded|
|8|CreateRemoteThread|
|10|Process access|
|11|File creation|
|12/13/14|Registry activity|
|22|DNS query|

The numbers themselves don't matter as much as understanding what each one actually represents and how they correlate together.

## 10. Kibana

This is where most of the real analyst work happens — searching, filtering, visualizing, dashboarding, investigating, building detection logic.

Once logs start flowing, first thing is just confirming events are actually landing.

Fields worth knowing:

- `@timestamp`
- `host.name`
- `event.code`
- `event.category`
- `event.action`
- `user.name`
- `process.name`
- `process.command_line`
- `process.parent.name`
- `source.ip`
- `destination.ip`

(exact fields depend on parsing)

## 11. First Dashboard

Not trying to build some giant flashy SOC dashboard on day one. Start simple:

- Total events
- Events over time
- Successful logons
- Failed logons
- Top users
- Top processes
- Top source IPs
- Top destination IPs
- Most common event IDs
- PowerShell activity

It should answer one question: **"what's happening on my Windows endpoint right now?"** — not look impressive.

## 12. Testing the Pipeline

Before touching attack simulation, generate normal, boring activity first.

On Windows:

- Log in / log out
- Open apps
- Open PowerShell
- Open CMD
- Browse the filesystem
- Create/delete a file
- Start/stop apps

Then go check Kibana — I should be able to trace those actions as events.

Example flow:

```
PowerShell opened
        ↓
Sysmon process creation event
        ↓
Winlogbeat
        ↓
Logstash
        ↓
Elasticsearch
        ↓
Kibana
```

If I can't trace that whole chain, the lab isn't ready for attack sim yet.

## 13. Detection Engineering

Once telemetry is solid, shift the question from "can I see logs?" to **"can I detect suspicious behavior?"**

Things worth building detections for:

- Multiple failed logins
- PowerShell with sketchy command-line args
- Encoded PowerShell
- New local user created
- Scheduled task created
- New Windows service installed
- Security logs cleared
- Weird parent-child process relationships
- Unexpected outbound connections

## 14. MITRE ATT&CK Mapping

Every detection should eventually map to an actual ATT&CK technique. Examples:

- PowerShell abuse → **T1059.001** (PowerShell)
- Scheduled task abuse → **T1053.005** (Scheduled Task/Job)
- Account creation → **T1136** (Create Account)

This is what makes the lab feel real instead of just "random alerts I made up" — I'm building around actual adversary behavior.

## 15. Attack Simulation

Once the defensive pipeline works, I can start throwing controlled attacks from Kali.

```
Attack
  ↓
Windows generates telemetry
  ↓
Winlogbeat collects it
  ↓
Logstash processes it
  ↓
Elasticsearch stores it
  ↓
Kibana displays it
  ↓
SOC analyst investigates
```

Simulation ideas:

- Failed login attempts
- PowerShell execution
- Command execution
- User creation
- Scheduled task creation
- Service creation
- Suspicious process execution
- Network recon

The point isn't "hacking the VM" — it's checking whether I can actually catch what happened afterward.

## 16. Investigation Method

Whenever something looks off, run through the same checklist every time:

1. What happened?
2. When did it happen?
3. Which host?
4. Which user?
5. Which process?
6. What was the parent process?
7. What command line ran?
8. Any network connections?
9. What happened right before/after?
10. Which MITRE ATT&CK technique does this map to?

This is a lot closer to real SOC work than just staring blankly at a dashboard.

## 17. Incident Timeline

For anything interesting, build an actual timeline. Example:

```
10:32:11 — Failed login
10:32:18 — Successful login
10:33:04 — PowerShell launched
10:33:07 — Suspicious command executed
10:33:10 — Network connection created
10:33:15 — New scheduled task created
10:34:02 — New process spawned
```

Then ask:

- What was the initial access?
- What got executed?
- What account was used?
- Was persistence set up?
- Any network comms?
- What evidence backs the conclusion?

## 18. Alert Triage

Not every alert is a real incident. Classify each one:

- True Positive
- False Positive
- Benign / expected activity
- Needs investigation

For true positives, document: alert, host, user, timestamp, evidence, technique, severity, analysis, conclusion, recommended action.

This stuff will eventually double as portfolio material.

## 19. Lab Documentation

For every experiment worth remembering, log:

- Date
- Objective
- Environment
- Action performed
- Expected result
- Actual result
- Logs generated
- Detection
- Investigation
- Conclusion
- Lessons learned

Example:

> **Experiment:** Detect suspicious PowerShell execution **Objective:** Check if Sysmon + Winlogbeat gives enough telemetry to catch PowerShell execution. **Action:** Ran PowerShell on the Windows endpoint. **Expected:** Sysmon Event ID 1 records the process creation. **Observed:** Process creation event showed up in Elasticsearch. **Detection:** Matched on PowerShell process name + command-line fields. **Conclusion:** Telemetry is enough for basic PowerShell detection.

## 20. Things to Avoid

- Don't build a massive dashboard before the data pipeline is even confirmed working.
- Don't install five different SIEM products at once.
- Don't blindly copy detection rules without understanding the events behind them.
- Don't treat every alert as malicious.
- Don't only focus on attack tools — understanding _normal_ Windows behavior matters just as much.

Above all: **don't confuse "I have a SIEM running" with "I have a SOC lab."**

A SOC lab actually becomes valuable once I can go:

```
Raw telemetry → Detection → Alert → Investigation →
Evidence → MITRE technique → Conclusion → Response
```

## 21. Final Target Architecture

```
                         ┌───────────────┐
                         │    Analyst    │
                         └───────┬───────┘
                                 │
                                 ▼
                         ┌───────────────┐
                         │    Kibana     │
                         │ Investigation │
                         └───────┬───────┘
                                 │
                                 ▼
                         ┌───────────────┐
                         │ Elasticsearch │
                         │    Storage    │
                         └───────▲───────┘
                                 │
                         ┌───────┴───────┐
                         │   Logstash    │
                         │ Parsing/Filter│
                         └───────▲───────┘
                                 │
                         ┌───────┴───────┐
                         │  Winlogbeat   │
                         └───────▲───────┘
                                 │
                    ┌────────────┴────────────┐
                    │                         │
             ┌──────▼──────┐           ┌──────▼──────┐
             │   Windows   │           │    Sysmon   │
             │   Endpoint  │           │  Telemetry  │
             └─────────────┘           └─────────────┘
                    ▲
                    │
             Controlled Attacks
                    │
             ┌──────┴──────┐
             │     Kali    │
             │   Attacker  │
             └─────────────┘
```

Thanks for reading it, I hope this will help you in your journey!!!