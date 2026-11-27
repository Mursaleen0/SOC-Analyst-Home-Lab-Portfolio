Hands-on SOC Analyst portfolio featuring a Purple Team home lab built with Kali Linux, Ubuntu Server, Splunk Enterprise and Docker. Practicing SIEM log ingestion, security monitoring, attack simulation and threat detection.

## Projects

### 1. Purple Team Home SOC: Attack, Detect and Respond (Kali + Splunk)
- Built a two-VM lab: Kali Linux (attacker) and Ubuntu Server running Splunk Enterprise in Docker
- Set up a private host-only network (10.0.0.0/24) alongside NAT for internet access
- Mounted Ubuntu's /var/log into the Splunk container and ingested auth.log into a dedicated index (soc_lab)
- Troubleshot real issues: file permissions, container health and VM memory limits
- In progress: SSH brute force, sudo escalation and detections mapped to MITRE ATT&CK
- Full notes: [Lab notebook (PDF)](Purple_Team_Home_SOC_Lab_Notebook.pdf)

## Cheatsheets
Quick-reference notes are in the [cheatsheets](cheatsheets) folder.

## Planned
- Wazuh SIEM, Suricata and Sysmon labs
