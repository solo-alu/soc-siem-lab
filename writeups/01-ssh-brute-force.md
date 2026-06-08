<<<<<<< HEAD
# Incident Report — SOC-2026-001
## SSH Credential Brute Force Attack
=======
# Incident Writeup 01 — SSH Credential Brute Force

**Incident ID:** SOC-2026-001  
**Date:** June 4, 2026  
**Severity:** High  
**Status:** Contained  
**Author:** Solomon Lee  
**Classification:** Credential Attack / Initial Access

---

## Executive Summary

A credential brute force attack was executed against the DVWA target VM (10.0.1.6) via SSH from the Kali attacker VM (10.0.1.7). The attack generated repeated failed authentication attempts using Hydra, producing 47 failed login events within a 5-minute window. The SOC detection pipeline identified the attack through auth.log monitoring, fired a Kibana alert after 5 failures in 60 seconds, and the Python alert engine automatically created an Azure NSG deny rule blocking the source IP within 5 seconds of threshold breach. No successful authentication was recorded. The attack was fully contained at the network perimeter without manual intervention.

---

## Incident Overview
>>>>>>> bcb22d8b69fc7d297edb5adf59b745acf7856970

| Field | Detail |
|-------|--------|
| Incident ID | SOC-2026-001 |
<<<<<<< HEAD
| Classification | Credential Attack / Initial Access |
=======
| Date | June 4, 2026 |
>>>>>>> bcb22d8b69fc7d297edb5adf59b745acf7856970
| Severity | High |
| CVSS v3.1 Score | 9.8 — Critical |
| CVSS Vector | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H |
| Status | Contained |
| Date Detected | June 4, 2026 |
| Date Contained | June 4, 2026 |
| Author | Solomon Lee |
| Last Updated | June 8, 2026 |

---

## 1. Executive Summary

On June 4, 2026, an automated SSH credential brute force attack was detected against the DVWA target VM (10.0.1.6) originating from the Kali attacker VM (10.0.1.7). The attack tool Hydra generated 47 failed authentication attempts within a 5-minute window. The SOC detection pipeline — comprising Filebeat log shipping, Elasticsearch indexing, Kibana alerting, and a custom Python alert engine — identified the attack within seconds of the detection threshold being breached.

The Python alert engine automatically created an Azure NSG deny rule blocking all inbound traffic from the attacking IP within 5 seconds of detection. No successful authentication was recorded. No data was compromised. All services remained operational throughout the incident. The attack was fully contained at the network perimeter without manual intervention.

---

## 2. Severity Rating

| Metric | Rating | Justification |
|--------|--------|---------------|
| CVSS v3.1 Base Score | 9.8 — Critical | Network-based, no privileges required, no user interaction needed |
| Attack Vector | Network | Attack originated over the network |
| Attack Complexity | Low | No special conditions or preparation required |
| Privileges Required | None | No prior authentication needed to launch attack |
| User Interaction | None | Attack is fully automated, no victim action required |
| Confidentiality Impact | High | Successful compromise would expose system credentials and data |
| Integrity Impact | High | Attacker could modify files, install backdoors, alter configurations |
| Availability Impact | High | Attacker could take the system offline |

The high CVSS score reflects that SSH brute force requires no prior access, no special conditions, and targets a service that is frequently exposed on internet-facing infrastructure. The attack is trivially automated and widely observed in the wild.

---

## 3. Affected Systems

| System | IP Address | Role | Impact |
|--------|-----------|------|--------|
| dvwa-vm | 10.0.1.6 | Target — DVWA web application | Targeted directly — no breach |
| kali-vm | 10.0.1.7 | Attacker — Kali Linux | Source of attack |
| jump-box | 10.0.1.4 | Bastion host | No direct impact |
| elk-vm | 10.0.1.5 | SIEM — ELK Stack | Detection platform — no impact |

No systems were compromised. The dvwa-vm was the intended target. All other systems remained unaffected. The attack did not reach the ELK VM or jump-box at any point.

---

## 4. Incident Details

### Attack Vector

The attacker used Hydra, an automated credential testing tool, to attempt SSH logins against the target VM using a dictionary wordlist. The tool opened parallel TCP connections to port 22 and submitted username and password combinations in rapid succession.

### Vulnerability Exploited

No software vulnerability was exploited. The attack targeted the authentication mechanism of the SSH service itself through credential guessing. The target VM mitigated the attack by having PasswordAuthentication disabled — only SSH key-based authentication was accepted — meaning no password could be guessed successfully.

### Why the Attack Was Unsuccessful

The dvwa-vm was configured with PasswordAuthentication set to no in /etc/ssh/sshd_config. The SSH daemon rejected all password-based authentication attempts before they could be evaluated. Hydra received authentication failure responses for every attempt.

---

## 5. Timeline (UTC)

| Time (UTC) | Event |
|-----------|-------|
| 21:47:00 | Kali VM (10.0.1.7) begins SSH connection attempts to 10.0.1.6 port 22 |
| 21:47:00 | First Invalid user admin entry written to /var/log/auth.log on dvwa-vm |
| 21:47:01 | Filebeat detects new auth.log entries and ships to Logstash at 10.0.1.5:5044 |
| 21:47:02 | Logstash applies Grok filter, parses log into structured fields, indexes into Elasticsearch |
| 21:50:51 | Python alert engine detects 10 attempts from 10.0.1.7 in last 60 seconds |
| 21:50:51 | Threshold exceeded — ALERT fired with source IP and attempt count |
| 21:50:51 | AbuseIPDB reputation check — private IP identified, external query skipped |
| 21:50:52 | Azure CLI called via subprocess — NSG deny rule creation initiated |
| 21:50:57 | NSG deny rule Block-10-0-1-7-20260604215057 created at priority 100 |
| 21:50:57 | All inbound TCP traffic from 10.0.1.7 blocked at Azure network perimeter |
| 21:51:00 | Kibana SSH Brute Force Detection rule fires — Server log action triggered |
| 21:52:00 | Attack continues but all packets silently dropped by NSG before reaching VM |
| 21:52:00 | Operations confirmed normal — no service disruption at any point |

---

## 6. Attack Command and Technical Evidence

The following Hydra command was executed from the Kali VM:

    sudo hydra -l admin -P ~/passwords.txt -t 4 -V ssh://10.0.1.6

| Flag | Purpose |
|------|---------|
| -l admin | Single target username |
| -P ~/passwords.txt | Dictionary wordlist file |
| -t 4 | 4 parallel connection threads |
| -V | Verbose — print every attempt |

Each attempt generated one line in /var/log/auth.log on the target VM:

    Jun 04 21:50:47 dvwa-vm sshd[1287]: Invalid user admin from 10.0.1.7 port 48634
    Jun 04 21:50:47 dvwa-vm sshd[1287]: Invalid user admin from 10.0.1.7 port 48635
    Jun 04 21:50:48 dvwa-vm sshd[1287]: Invalid user admin from 10.0.1.7 port 48636

![Auth log entries on dvwa-vm](screenshots/01-auth-log-entries.png)

---

## 7. Detection and Evidence

### SIEM Evidence — Kibana Discover

All auth.log events were shipped by Filebeat, processed by Logstash, and indexed in Elasticsearch. The following query in Kibana Discover returns all events from this incident:

    message: "Invalid user" AND host.name: "dvwa-vm"

![Kibana Discover showing SSH brute force events](screenshots/01-kibana-discover-ssh-events.png)

### Detection Rules Status

Two layered detection rules were active during the incident:

| Rule Name | Query | Threshold | Window | Fired |
|-----------|-------|-----------|--------|-------|
| SSH Brute Force Detection | message: "Invalid user" | > 5 | 60 seconds | Yes |
| SSH Slow Brute Force Detection | message: "Invalid user" | > 10 | 10 minutes | Yes |

![Kibana detection rules status](screenshots/01-kibana-rule-status.png)

### Automated Response Evidence

The Python alert engine detected the attack and blocked the source IP:

![Python alert engine output](screenshots/01-python-engine-alert.png)

### Azure NSG Block Rule

The deny rule was automatically added to the NSG within 5 seconds:

![Azure NSG deny rule created](screenshots/01-nsg-block-rule.png)

---

## 8. Impact Assessment

### Confidentiality
No data was accessed or exfiltrated. All authentication attempts were rejected. No files were read, copied, or transmitted by the attacker.

### Integrity
No files were modified. No configurations were changed by the attacker. No backdoors or persistence mechanisms were installed.

### Availability
No services were disrupted at any point. DVWA, Filebeat, and all other services remained operational throughout the incident.

| Impact Category | Rating | Detail |
|-----------------|--------|--------|
| Confidentiality | None | No data accessed |
| Integrity | None | No files modified |
| Availability | None | No services disrupted |
| Data compromised | None | — |
| Records affected | 0 | — |
| Financial loss | $0 | — |
| Regulatory impact | None | No breach occurred |

---

## 9. Operational Status

| Phase | Time (UTC) | Status |
|-------|-----------|--------|
| Attack begins | 21:47:00 | Services fully operational |
| Attack detected | 21:50:51 | Services fully operational |
| IP blocked at NSG | 21:50:57 | Services fully operational |
| Operations confirmed normal | 21:52:00 | Fully operational |
| Incident closed | June 4, 2026 22:00:00 | Resolved |

Operations were never interrupted. No recovery time was required because no systems were taken offline. The NSG block rule remains active and the incident is considered fully resolved.

---

## 10. Indicators of Compromise (IOCs)

| Type | Value | Context |
|------|-------|---------|
| Source IP | 10.0.1.7 | Kali attacker VM |
| Target IP | 10.0.1.6 | DVWA target VM |
| Target port | 22/TCP | SSH service |
| Username attempted | admin | Dictionary attack |
| Tool signature | Hydra/9.4 | Visible in SSH daemon logs |
| Log signature | Invalid user admin from 10.0.1.7 | auth.log pattern |
| KQL detection query | message: "Invalid user" AND host.name: "dvwa-vm" | Kibana search |
| NSG rule created | Block-10-0-1-7-20260604215057 | Automated response artifact |

---

## 11. Root Cause Analysis

| Type | Detail |
|------|--------|
| Primary cause | Kali VM and DVWA VM share the same subnet with no network segmentation |
| Secondary cause | SSH port 22 accessible from all VMs on the subnet rather than restricted to jump-box only |
| Contributing factor | No network-level rate limiting prior to Python alert engine deployment |
| Why attack failed | PasswordAuthentication was disabled — no valid authentication mechanism to exploit |

---

## 12. Containment and Eradication

| Action | Method | Time | Status |
|--------|--------|------|--------|
| Source IP blocked at Azure NSG | Python alert engine — automated | 21:50:57 | Complete |
| fail2ban ban rule applied on dvwa-vm | fail2ban daemon — automated | 21:51:00 | Complete |
| Kibana alert logged | Server log connector | 21:51:00 | Complete |
| Attack traffic confirmed dropped | NSG deny rule verification | 21:52:00 | Confirmed |

No manual intervention was required. The automated response pipeline handled detection and containment fully without human action.

---

## 13. Recovery

No recovery actions were required. No systems were compromised, no services were disrupted, and no data was lost. The NSG deny rule created during automated response remains active as a permanent control measure.

System integrity was verified by confirming all services were operational and no unexpected processes, files, or accounts were present on the dvwa-vm following the incident.

---

## 14. Remediation

### Implemented During This Incident
- PasswordAuthentication disabled on all VMs — eliminates brute force attack surface entirely
- fail2ban configured on dvwa-vm — OS-level automatic IP banning after 5 failures in 10 minutes
- Python alert engine deployed — automated detection and NSG blocking within 5 seconds
- Dual Kibana detection rules — fast threshold (60 seconds) and slow-and-low (10 minutes)

### Recommended for Production Environments
- Restrict SSH NSG rule to known administrative IP ranges only
- Deploy Packetbeat for network-level detection of reconnaissance before brute force begins
- Implement network segmentation — separate attack-accessible VMs from SIEM infrastructure
- Deploy Auditbeat for post-authentication file access monitoring
- Enable MFA for all administrative access

---

## 15. Lessons Learned

### What Worked Well
- Filebeat pipeline delivered events to Elasticsearch within 2 to 3 seconds of log generation
- Python alert engine detected and blocked the IP within 5 seconds of threshold breach
- fail2ban provided independent OS-level protection not dependent on the SIEM pipeline
- Layered detection rules caught both fast and slow attack variants
- Zero human intervention required from detection to containment

### What Was Identified as a Gap
- The nmap port scan preceding this attack was not detected — Filebeat watches log files and cannot capture raw SYN packets — Packetbeat required for network-level visibility
- Slow-and-low attacks evaded the original 60-second rule — mitigated by adding a 10-minute rule

### Process Improvements Made
- Detection coverage matrix updated to document monitored and unmonitored attack techniques
- Slow-and-low Kibana rule added to cover throttled brute force attacks
- Apache logs added to Filebeat to detect web application scanning

---

## 16. MITRE ATT&CK Mapping

| Tactic | Technique | Sub-technique | ID | Detected |
|--------|-----------|--------------|-----|---------|
| Reconnaissance | Active Scanning | Network Service Discovery | T1595 | No — needs Packetbeat |
| Initial Access | Brute Force | Password Guessing | T1110.001 | Yes — auth.log via Filebeat |
| Initial Access | Brute Force | Password Spraying | T1110.003 | Yes — auth.log via Filebeat |

---

## Appendix — Detection Pipeline Reference

    dvwa-vm (/var/log/auth.log)
        |
        | Filebeat 8.11.0
        |
    elk-vm Logstash :5044
        |
        | Grok filter — parses raw log into structured fields
        |
    Elasticsearch (filebeat-8.11.0-2026.06.04)
        |
        +-- Kibana Rules (check every 1 min / 5 min)
        |       SSH Brute Force Detection
        |       SSH Slow Brute Force Detection
        |
        +-- Python alert_engine.py (checks every 60s)
                Regex extracts source IP from message field
                Counts per-IP attempts in time window
                Calls AbuseIPDB for reputation (public IPs)
                Calls Azure CLI to create NSG deny rule
                Tracks blocked IPs to prevent duplicate rules
