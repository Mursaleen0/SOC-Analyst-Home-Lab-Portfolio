# Incident Report 003 — Network Port Scan

## Summary

A TCP SYN port scan was run from a Kali Linux attack VM against the Ubuntu-SIEM host, covering ports 1 through 1000. The host's firewall (`ufw`) correctly blocked all probes except SSH (the only intentionally open service) and logged every blocked attempt. This firewall log was ingested into Splunk as a new data source, and a detection was built around the real signature of a scan — one source IP touching many distinct ports — rather than any single blocked connection. The resulting alert fired three times during testing, each confirmed via the alert's own Trigger History.

## MITRE ATT&CK Mapping

| Field | Value |
|---|---|
| Tactic | Discovery |
| Technique | [T1046 — Network Service Discovery](https://attack.mitre.org/techniques/T1046/) |

## Environment

| Role | Host | IP |
|---|---|---|
| Attacker | Kali Linux | 10.0.0.12 |
| Target | Ubuntu-SIEM | 10.0.0.13 |

## Why a Second Log Source Was Needed

Unlike the SSH brute-force and sudo detections, a port scan generates **no login attempt whatsoever**, so it never appears in `auth.log`. Detecting it required enabling the host firewall's logging feature and ingesting a second log file (`ufw.log`) into Splunk, a deliberate gap identified and solved as part of this project rather than an oversight.

## Attack Narrative

1. The firewall was enabled on Ubuntu-SIEM, with an explicit allow rule for SSH added immediately afterward to avoid a lockout (`ufw`'s default policy is deny-all on incoming traffic):

```bash
sudo ufw enable
sudo ufw allow 22/tcp
sudo ufw logging on
```

2. The scan was run from Kali:

```bash
nmap -sS -p 1-1000 10.0.0.13
```

3. Result: port 22 (SSH) reported open; all other 999 ports reported filtered (no response) — confirming the firewall itself was working as intended, independent of Splunk.
4. The scan generated a new log file, `/var/log/ufw.log`, containing one `[UFW BLOCK]` line per probed port, e.g.:

```
[UFW BLOCK] IN=enp0s8 OUT= MAC=... SRC=10.0.0.12 DST=10.0.0.13 ... DPT=111 PROTO=TCP
```

## Detection

`ufw.log` was added to Splunk as a new monitored input (sourcetype `syslog`, same `soc_lab` index as the other sources — Splunk distinguishes sources by their `source`/`sourcetype` fields, not by index).

**Raw verification:**
```spl
index=soc_lab "UFW BLOCK" | table _time, host, _raw
```

**Field extraction** (pulls out the attacker's IP and the probed port):
```spl
index=soc_lab "UFW BLOCK"
| rex field=_raw "SRC=(?<src_ip>\d+\.\d+\.\d+\.\d+).*DPT=(?<dpt>\d+)"
| table _time, src_ip, dpt
```

**Real detection logic:** a single blocked connection is meaningless on its own — the actual signature of a scan is one source IP touching **many different ports** in a short window. This query counts *distinct* ports per source, not total hits:

```spl
index=soc_lab "UFW BLOCK"
| rex field=_raw "SRC=(?<src_ip>\d+\.\d+\.\d+\.\d+).*DPT=(?<dpt>\d+)"
| stats dc(dpt) as distinct_ports by src_ip
| where distinct_ports >= 5
```

## Evidence

| Item | Detail |
|---|---|
| Alert name | Port Scan Detected - High distinct ports from one IP |
| Schedule | Every 5 minutes (`*/5 * * * *`), 15-minute lookback window |
| Trigger condition | Number of Results > 0 |
| **Verified fired** | **2026-11-28 11:45:29 UTC, 11:50:01 UTC, 11:55:00 UTC** (3 consecutive scheduled runs) |
| Result at time of firing | `src_ip=10.0.0.12`, 10-13 distinct ports probed within the 15-minute window |

The alert fired on three consecutive scheduled runs because the scan data remained within the 15-minute lookback window across multiple checks — demonstrating the alert behaves consistently and predictably on a real schedule, not just once.

## Severity

**Low-Medium.** A port scan alone does not compromise a system; it is reconnaissance. However, it is frequently the first observable step in a larger attack chain (an attacker mapping which services are reachable before attempting to exploit one of them), making early detection valuable even though no direct damage occurs at this stage.

## Recommended Fix

- Firewall logging should remain enabled permanently in any real deployment, not just during testing — this report's entire detection depends on it.
- Consider enabling `ufw`'s rate-limiting feature on exposed services to slow down automated scanning tools.
- Pair this detection with network-level alerting (e.g. an IDS/IPS) for additional coverage beyond host-based firewall logs alone.
- Since `ufw.log` permissions reset after every host reboot, document and, ideally, automate the permission fix (`chmod o+r /var/log/ufw.log`) as part of system startup to avoid silent detection gaps.
