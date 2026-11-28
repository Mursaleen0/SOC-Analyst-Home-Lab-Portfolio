# MITRE ATT&CK Mapping — Purple Team Home SOC Lab

## What this document is

[MITRE ATT&CK](https://attack.mitre.org/) is a publicly maintained knowledge base of real-world adversary tactics and techniques, organized into a matrix that security teams use as a common reference. Mapping a detection to an ATT&CK technique ID answers a specific question a SOC analyst, hiring manager, or auditor will always ask: *"what real-world behavior does this alert actually catch?"*

Each row below documents one attack simulated in this lab, the ATT&CK technique it maps to, the exact Splunk query (SPL) used to detect it, and the timestamp proving the alert fired for real — not just that the query was written and left untested.

All attacks were simulated inside an isolated VirtualBox lab against VMs I own and control. No systems outside this lab were targeted.

## Mapping table

| # | Attack Simulated | Tactic | Technique ID | Technique Name | Detection Query (SPL) | Evidence — Alert Fired |
|---|---|---|---|---|---|---|
| 1 | SSH brute force against Ubuntu-SIEM, run manually and with Hydra from Kali Linux | Credential Access | [T1110](https://attack.mitre.org/techniques/T1110/) | Brute Force | `index=soc_lab "Failed password" \| rex field=_raw "from (?<src_ip>\d+\.\d+\.\d+\.\d+)" \| stats count by src_ip \| where count >= 5` | 2026-11-27 14:10:01 UTC |
| 2 | sudo access to sensitive files (`/etc/shadow`, `/root`) after simulating privilege escalation | Privilege Escalation | [T1548.003](https://attack.mitre.org/techniques/T1548/003/) | Abuse Elevation Control Mechanism: Sudo and Sudo Caching | `index=soc_lab "sudo" "COMMAND=" "/etc/shadow" OR "/etc/passwd" OR "/root" \| rex field=_raw "USER=(?<target_user>\S+)\s*;\s*COMMAND=(?<command>.+)" \| table _time, host, target_user, command` | 2026-11-28 10:00:02 UTC |
| 3 | Nmap SYN scan of ports 1–1000 against Ubuntu-SIEM from Kali Linux | Discovery | [T1046](https://attack.mitre.org/techniques/T1046/) | Network Service Discovery | `index=soc_lab "UFW BLOCK" \| rex field=_raw "SRC=(?<src_ip>\d+\.\d+\.\d+\.\d+).*DPT=(?<dpt>\d+)" \| stats dc(dpt) as distinct_ports by src_ip \| where distinct_ports >= 5` | 2026-11-28 11:45:29 UTC, 11:50:01 UTC, 11:55:00 UTC |

## Data sources per detection

| # | Log Source | Splunk Sourcetype | Index |
|---|---|---|---|
| 1 | `/var/log/auth.log` (SSH authentication events) | `linux_secure` | `soc_lab` |
| 2 | `/var/log/auth.log` (sudo command audit lines) | `linux_secure` | `soc_lab` |
| 3 | `/var/log/ufw.log` (firewall block/allow events) | `syslog` | `soc_lab` |

## Why distinct detections matter here

A single failed login, a single sudo command, or a single blocked connection is normal background noise on any system. Each query above is built around a **threshold or pattern**, not a single event, which is what separates a usable detection from noise:

- **T1110**: flags an IP only once it crosses 5 or more failed logins, not any one failure.
- **T1548.003**: filters 61 total sudo events on the box down to the 3 that touched a genuinely sensitive path, rather than alerting on routine admin commands.
- **T1046**: counts **distinct ports** per source IP rather than total blocked connections, since the signature of a scan is breadth across ports, not volume at one port.

## Notes on scope

- Severity ratings, full incident narratives, and recommended remediations for each technique are documented separately in `reports/` (see `incident-001-ssh-bruteforce.md`, `incident-002-sudo-escalation.md`, `incident-003-port-scan.md`).
- All three alerts are scheduled Splunk alerts (`*/5 * * * *`, 15-minute lookback window), each verified through Splunk's own **Trigger History**, not just a manually run search.
