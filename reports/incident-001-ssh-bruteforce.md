# Incident Report 001 — SSH Brute Force

## Summary

A brute-force password-guessing attack was simulated against the Ubuntu-SIEM host over SSH, using both manual login attempts and the automated tool Hydra from a Kali Linux attack VM on the same isolated network. The attack was detected by a Splunk scheduled alert monitoring failed SSH authentication events, which correctly identified the pattern of repeated failures from a single source IP and fired in real time.

## MITRE ATT&CK Mapping

| Field | Value |
|---|---|
| Tactic | Credential Access |
| Technique | [T1110 — Brute Force](https://attack.mitre.org/techniques/T1110/) |

## Environment

| Role | Host | IP |
|---|---|---|
| Attacker | Kali Linux | 10.0.0.12 |
| Target | Ubuntu-SIEM | 10.0.0.13 |

## Attack Narrative

1. A non-existent username (`invaliduser`) was used to attempt SSH login to Ubuntu-SIEM, both manually (wrong passwords entered by hand) and via Hydra with a small password list:

```
hydra -l invaliduser -P /tmp/passlist.txt ssh://10.0.0.13 -t 1 -W 2
```

2. None of the attempts succeeded — this is expected, since the goal was to test detection, not to actually compromise the host.
3. Ubuntu's authentication log (`/var/log/auth.log`) recorded each failure, including lines such as `Failed password for invalid user invaliduser from 10.0.0.12` and `Invalid user invaliduser from 10.0.0.12`.

## Detection

The raw log data does not auto-extract a `user` field for this log format, so a field extraction (`rex`) was used to pull the username and source IP directly out of the raw event text.

**Investigative query:**
```spl
index=soc_lab ("Failed password" OR "Invalid user")
| rex field=_raw "(?:invalid user |for )(?<user>\S+) from (?<src_ip>\d+\.\d+\.\d+\.\d+)"
| stats count by user, src_ip
```

**Threshold detection logic (alert query):**
```spl
index=soc_lab "Failed password"
| rex field=_raw "from (?<src_ip>\d+\.\d+\.\d+\.\d+)"
| stats count by src_ip
| where count >= 5
```

This flags any source IP responsible for 5 or more failed password attempts, rather than alerting on any single failure, which would be far too noisy for a real environment.

## Evidence

| Item | Detail |
|---|---|
| Alert name | SSH Brute Force - 5+ failed logins from one IP |
| Schedule | Every 5 minutes (`*/5 * * * *`), 15-minute lookback window |
| Trigger condition | Number of Results > 0 |
| **Verified fired** | **2026-11-27 14:10:01 UTC** |
| Result at time of firing | `src_ip=10.0.0.12`, 8 matching failed-login events in the lookback window |

The alert's own Trigger History page (not just a manually run search) confirms this entry, meaning the detection worked unattended, on schedule, exactly as it would in a live monitoring environment.

## Severity

**Medium.** No successful login occurred and the attacker never obtained valid credentials. However, in a non-lab environment, sustained brute-force activity against an internet-facing SSH service represents a real and common attack vector, and the absence of account lockout or rate-limiting on the service itself is a gap worth flagging.

## Recommended Fix

- Disable SSH password authentication entirely and require key-based authentication (`PasswordAuthentication no` in `sshd_config`).
- If password authentication must remain, deploy `fail2ban` or an equivalent tool to automatically block source IPs after a small number of failed attempts.
- Restrict SSH access at the network/firewall level to known, trusted source IP ranges where possible.
- Consider lowering the alert's failure threshold and/or shortening the lookback window for faster detection in a production setting.
