# Triage Guide

This document covers how I would triage an alert from each rule in this repo.
The goal is to quickly decide: escalate, close as false positive, or keep watching.

## General Triage Process

For every alert I start with the same four questions:

1. What process triggered the alert, and what spawned it?
2. Which user account was involved, and is this normal for them?
3. Does the timing make sense - business hours, maintenance window, or 3am?
4. Are there other alerts on the same host or same user around the same time?

---

## Rule-by-Rule Triage Notes

### T1059.001 - PowerShell Encoded Command

Decode the base64 first, always. On Linux:
```bash
echo "BASE64STRING" | base64 -d | iconv -f utf-16le -t utf-8
```
If what comes out has IEX, Invoke-WebRequest, or Net.WebClient in it - escalate, don't investigate further.
If the parent is Word or a browser - that's almost certainly initial access, escalate.
If it's an admin script from a management tool running during business hours - document and close.

---

### T1003.001 - LSASS Memory Access

Identify the source process first. Windows Defender (MsMpEng.exe), csrss.exe, and wininit.exe access LSASS legitimately.
If the source is something unexpected like a renamed binary in a temp folder - isolate the host.
Look for follow-up activity: new accounts created, lateral movement, or new persistence mechanisms within 30 minutes.

---

### T1110.001 - Password Spraying

Check whether any logon actually succeeded (Event ID 4624) shortly after the spray.
If yes and the account has admin rights - treat as incident.
Check the source IP. Internal IPs spraying other internal systems is a sign of lateral movement from an already compromised host.
External IPs hitting the VPN or RDP - block and investigate the source.

---

### T1053.005 - Scheduled Task

Pull the full command from the /tr argument. If it points to a file in AppData, Temp, or a user-writable directory - suspicious.
Check if the task runs at startup or at logon with SYSTEM privileges.
Correlate with file creation events around the same timestamp to see if a new binary was dropped.

---

### T1547.001 - Registry Run Key

Look at what the registry value points to. If the binary is not signed or is in an unusual location - suspicious.
Compare against a known-good baseline if you have one.
Low confidence rule - use it as a supporting signal, not a standalone escalation trigger.

---

### T1087.001 - Net User Enumeration

Low confidence rule. The key question is context: is this running standalone as the first thing on a host, or is it one of many discovery commands in a chain?
If you see net user, followed by net localgroup administrators, followed by whoami all within a few minutes - that is a clear discovery phase pattern.

---

### T1027 - Base64 PowerShell via cmd.exe

High confidence rule. Decode the payload first. The parent of cmd.exe is important - if it is an Office application or a browser, treat as likely exploitation.

---

### T1021.006 - WMI Lateral Movement

Identify the target node from the /node: argument. Check whether the executing account has admin rights on the target.
Look at the target host logs for corresponding process creation events.

---

### T1003 - Mimikatz Keywords

Treat as critical. Immediate escalation.
If confirmed - isolate host, reset all credentials that were active on that machine, check for pass-the-hash or Kerberos ticket abuse.

---

### T1059.003 - Unusual Parent for cmd.exe

High confidence rule. Identify the document or URL that triggered the parent process.
Pull the cmd.exe command line and trace what it then executed.
