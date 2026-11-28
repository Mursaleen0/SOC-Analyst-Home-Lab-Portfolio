# Incident Report 002 — Sudo Privilege Escalation / Sensitive File Access

## Summary

Privilege escalation via `sudo` was simulated on the Ubuntu-SIEM host, including access to the system's password-hash file (`/etc/shadow`) and the root user's home directory (`/root`). This mimics the behavior of an attacker who has gained a foothold on a system and is attempting to escalate privileges and harvest credentials for offline cracking or further lateral movement. The activity was detected by a Splunk scheduled alert, and confirmed as fired in real time via the alert's Trigger History.

## MITRE ATT&CK Mapping

| Field | Value |
|---|---|
| Tactic | Privilege Escalation |
| Technique | [T1548.003 — Abuse Elevation Control Mechanism: Sudo and Sudo Caching](https://attack.mitre.org/techniques/T1548/003/) |

## Environment

| Role | Host | IP |
|---|---|---|
| Target (local activity) | Ubuntu-SIEM | 10.0.0.13 |

## Attack Narrative

The following commands were run locally on Ubuntu-SIEM to simulate post-escalation attacker behavior:

```bash
sudo ls /root        # Simulates an attacker poking around after escalation
sudo whoami          # Confirms escalation succeeded — classic first command
sudo cat /etc/shadow # Simulates the attacker's primary goal: stealing password hashes
```

`sudo cat /etc/shadow` is treated as the most significant action in this chain: in a real attack, a successful read of this file would give an attacker the system's password hashes to crack offline, independent of the live system's own login protections.

**Sensitive output note:** the real output of `/etc/shadow` contains actual password hashes. That output was never published anywhere, including redacted — only the fact that the command ran (captured by Splunk) is used as evidence here.

## Detection

A broad query first confirmed that all `sudo` activity on the host was being captured end-to-end by the logging pipeline:

```spl
index=soc_lab "sudo" "COMMAND=" | table _time, host, _raw
```

This returned 61 events, including routine administrative commands (e.g. `docker ps`) alongside the test commands above — proving the pipeline misses nothing, but also showing that alerting on every `sudo` command would be far too noisy for a real SOC.

**Clean field extraction** (turns the raw, unreadable log line into structured evidence):

```spl
index=soc_lab "sudo" "COMMAND="
| rex field=_raw "USER=(?<target_user>\S+)\s*;\s*COMMAND=(?<command>.+)"
| table _time, host, target_user, command
```

**Focused, alert-worthy detection** — restricts matches to commands touching known-sensitive paths only:

```spl
index=soc_lab "sudo" "COMMAND=" "/etc/shadow" OR "/etc/passwd" OR "/root"
| rex field=_raw "USER=(?<target_user>\S+)\s*;\s*COMMAND=(?<command>.+)"
| table _time, host, target_user, command
```

This filtered the 61 total sudo events down to 3 genuinely suspicious ones: one `cat /etc/shadow` and two `ls /root` — a realistic, high-signal rule rather than a noisy one.

## Evidence

| Item | Detail |
|---|---|
| Alert name | Sudo Access to Sensitive Files - /etc/shadow or /root |
| Schedule | Every 5 minutes (`*/5 * * * *`), 15-minute lookback window |
| Trigger condition | Number of Results > 0 |
| **Verified fired** | **2026-11-28 10:00:02 UTC** |
| Result at time of firing | `target_user=root`, command matching a fresh `sudo cat /etc/shadow` run specifically to test the alert |

## Severity

**High.** Successful (simulated) access to `/etc/shadow` represents one of the most damaging actions an attacker can take on a compromised Linux host — it enables offline password cracking against every local account on the system, independent of any future login restrictions.

## Recommended Fix

- Apply the principle of least privilege: audit and minimize which users and services have `sudo` rights at all.
- Monitor and alert on **any** access to `/etc/shadow` outside of known, scheduled administrative processes — a single hit on this file is worth investigating even without a volume threshold.
- Consider enabling `auditd` in addition to standard `sudo` logging for tamper-resistant, more granular command auditing.
- Rotate credentials and force a password reset for all local accounts if `/etc/shadow` access is ever confirmed as unauthorized in a real environment.
