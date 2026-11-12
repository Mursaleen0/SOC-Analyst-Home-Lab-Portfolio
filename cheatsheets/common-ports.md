I can't see the exact slide from his video, so this is the standard Network+ N10-009 common ports list, which is what that video covers. Check it against the video as you watch.

| Port | Protocol | Service |
|---|---|---|
| 20/21 | TCP | FTP (data/control) |
| 22 | TCP | SSH / SFTP |
| 23 | TCP | Telnet |
| 25 | TCP | SMTP |
| 53 | TCP/UDP | DNS |
| 67/68 | UDP | DHCP (server/client) |
| 69 | UDP | TFTP |
| 80 | TCP | HTTP |
| 88 | TCP/UDP | Kerberos |
| 110 | TCP | POP3 |
| 123 | UDP | NTP |
| 135 | TCP | Microsoft RPC |
| 137-139 | TCP/UDP | NetBIOS |
| 143 | TCP | IMAP |
| 161/162 | UDP | SNMP / SNMP trap |
| 389 | TCP/UDP | LDAP |
| 443 | TCP | HTTPS |
| 445 | TCP | SMB |
| 465/587 | TCP | SMTP secure (SMTPS / submission) |
| 514 | UDP | Syslog |
| 636 | TCP | LDAPS |
| 993 | TCP | IMAPS |
| 995 | TCP | POP3S |
| 1433 | TCP | Microsoft SQL Server |
| 1521 | TCP | Oracle DB |
| 3306 | TCP | MySQL |
| 3389 | TCP/UDP | RDP |
| 5060/5061 | TCP/UDP | SIP / SIP-TLS |

**SOC ports to remember for your lab:** 22, 53, 80, 443, 445, 3389, plus Wazuh's own ports, **1514** (agent to manager) and **1515** (agent enrollment).

Paste this into your GitHub cheat sheet. If you spot a port in the video that isn't here, add it.
