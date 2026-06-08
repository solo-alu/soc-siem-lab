# SOC & SIEM Lab — Cloud-Based Security Operations Center

**Built by Solomon Lee** | [LinkedIn](https://linkedin.com/in/solomon-lee-962304192) | [GitHub](https://github.com/solo-alu)

[![Azure](https://img.shields.io/badge/Cloud-Microsoft%20Azure-0078D4?logo=microsoftazure)](https://azure.microsoft.com)
[![ELK](https://img.shields.io/badge/SIEM-ELK%20Stack%208.11.0-005571?logo=elasticstack)](https://elastic.co)
[![Python](https://img.shields.io/badge/Automation-Python%203.12-3776AB?logo=python)](https://python.org)
[![Ansible](https://img.shields.io/badge/IaC-Ansible%202.16-EE0000?logo=ansible)](https://ansible.com)
[![Docker](https://img.shields.io/badge/Containers-Docker-2496ED?logo=docker)](https://docker.com)

---

## Overview

A fully functional Security Operations Center built from the ground up on Microsoft Azure, designed to simulate the detection and response capabilities of a real enterprise security team.

This project deploys a private cloud network with a monitored target environment, a complete ELK Stack SIEM pipeline, automated threat detection, threat intelligence enrichment, and an automated response engine that blocks attackers at the network perimeter within seconds of detection — without human intervention.

Every component was built and configured manually. Every attack was simulated against live infrastructure. Every detection rule was tested against real attack traffic. The result is a production-realistic security lab that demonstrates the full lifecycle of a SOC workflow: from log collection to detection to automated response.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Microsoft Azure (eastus2)                  │
│                   Resource Group: soc-lab-rg                  │
│                                                               │
│   VNet: soc-lab-vnet (10.0.0.0/16)                           │
│   Subnet: soc-lab-subnet (10.0.1.0/24)                       │
│                                                               │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐      │
│  │  jump-box   │    │   elk-vm    │    │   dvwa-vm   │      │
│  │ 10.0.1.4   │    │ 10.0.1.5   │    │ 10.0.1.6   │      │
│  │PUBLIC IP   │    │             │    │             │      │
│  │ SSH entry  │    │Elasticsearch│    │   DVWA      │      │
│  │  point     │    │  Logstash   │    │  Filebeat   │      │
│  │            │    │   Kibana    │    │  Metricbeat │      │
│  └─────────────┘    └─────────────┘    │  fail2ban   │      │
│                                         └─────────────┘      │
│                      ┌─────────────┐                         │
│                      │   kali-vm   │                         │
│                      │ 10.0.1.7   │                         │
│                      │  nmap       │                         │
│                      │  Hydra      │                         │
│                      │  Nikto      │                         │
│                      └─────────────┘                         │
└─────────────────────────────────────────────────────────────┘
```

**Security design decisions:**
- Only the jump box has a public IP — all other VMs are invisible to the internet
- All internal access routes through the jump box via SSH ProxyJump
- NSG enforces default-deny with explicit allow rules only for required ports
- Defense in depth: fail2ban → Kibana rules → Python engine → Azure NSG blocking

---

## Tech Stack

| Layer | Technology | Version | Purpose |
|-------|-----------|---------|---------|
| Cloud | Microsoft Azure | — | Infrastructure hosting |
| Network | Azure VNet + NSG | — | Private network + firewall |
| SIEM Storage | Elasticsearch | 8.11.0 | Log indexing and search |
| SIEM Pipeline | Logstash | 8.11.0 | Log parsing and processing |
| SIEM UI | Kibana | 8.11.0 | Dashboards, search, alerting |
| Log Agent | Filebeat | 8.11.0 | Log shipping from endpoints |
| Metrics Agent | Metricbeat | 8.11.0 | System metrics collection |
| Containers | Docker + Compose | — | ELK stack deployment |
| IaC | Ansible | 2.16.3 | Infrastructure automation |
| Alert Engine | Python | 3.12 | Custom detection and response |
| Threat Intel | AbuseIPDB API | v2 | IP reputation enrichment |
| Target App | DVWA | latest | Vulnerable web application |
| Attacker | Kali Linux | — | Attack simulation |
| Host Protection | fail2ban | — | OS-level brute force blocking |

---

## Log Pipeline

```
dvwa-vm                    elk-vm
┌─────────────────┐        ┌────────────────────────────────┐
│ /var/log/       │        │                                │
│  auth.log       │─────── │ Logstash :5044                 │
│  syslog         │ Beats  │  ├── Grok filter               │
│  apache/        │        │  ├── Field extraction          │
│  access.log     │        │  └── Timestamp normalization   │
│  error.log      │        │           │                    │
│                 │        │           ▼                    │
│ Filebeat        │        │ Elasticsearch                  │
│ Metricbeat      │        │  ├── filebeat-8.11.0-*         │
└─────────────────┘        │  └── metricbeat-8.11.0-*       │
                            │           │                    │
                            │           ▼                    │
                            │ Kibana :5601                   │
                            │  ├── Discover                  │
                            │  ├── Dashboards                │
                            │  └── Detection Rules           │
                            └────────────────────────────────┘
```

---

## Automated Detection and Response Pipeline

The Python alert engine runs continuously, querying Elasticsearch every 60 seconds. When an attack is detected it enriches the alert with threat intelligence and automatically blocks the attacker at the Azure network perimeter.

```
Elasticsearch Query (every 60s)
         │
         ▼
  Parse message field
  Extract source IPs via regex
  Count attempts per IP
         │
         ▼
  Threshold exceeded? (>5 in 1 min)
         │
    ┌────┴────┐
    │         │
   YES        NO → wait 60s, repeat
    │
    ▼
  AbuseIPDB reputation check
  (public IPs only — private IPs flagged and skipped)
         │
         ▼
  [ALERT] printed with full context
  IP, attempt count, abuse score, country, ISP
         │
         ▼
  Already blocked in Azure? → skip
         │
         ▼
  az network nsg rule create
  Priority: auto-calculated (no conflicts)
  Source: attacker IP → Deny Inbound TCP
         │
         ▼
  Attacker blocked at network perimeter
  Time from detection to block: < 5 seconds
```

### Sample Alert Output

```
[ALERT] 2026-06-05 18:13:37
  SSH Brute Force Detected
  Source IP:  185.220.101.45
  Attempts:   47 in last 1 minute(s)
  Threshold:  5
  [THREAT INTEL] Abuse Score:   97/100
  [THREAT INTEL] Total Reports: 2,847
  [THREAT INTEL] Country:       RU
  [THREAT INTEL] ISP:           AS60602 Hosting Provider LLC
  [THREAT INTEL] Last Reported: 2026-06-05
  *** HIGH RISK — KNOWN MALICIOUS ACTOR ***
  [BLOCKED] 185.220.101.45 added to NSG deny list
  Rule: Block-185-220-101-45-20260605181337 — Priority: 101
```

---

## Detection Coverage

| Attack Technique | Detected | Method | Rule |
|-----------------|----------|--------|------|
| SSH brute force (fast) | ✅ | auth.log → Filebeat → Kibana | >5 failures/60s |
| SSH brute force (slow) | ✅ | auth.log → Filebeat → Kibana | >10 failures/10min |
| SSH brute force (auto-block) | ✅ | Python alert engine → Azure NSG | >5 failures/60s |
| Web app scanning (Nikto) | ✅ | Apache logs → Filebeat → Kibana | >100 requests/60s |
| Successful SSH login | ✅ | auth.log → Filebeat | Accepted publickey |
| nmap SYN port scan | ❌ | Needs Packetbeat | Network-level gap |
| Post-exploitation file access | ❌ | Needs Auditbeat | Host-level gap |
| SQL injection | 🔄 | See writeup | Planned |
| XSS | 🔄 | See writeup | Planned |
| Command injection | 🔄 | See writeup | Planned |

---

## Attack Simulations and Writeups

Each attack was simulated against the live lab environment. Writeups follow the Google Project Zero / Mandiant professional disclosure format — executive summary, timeline, technical analysis, indicators of compromise, business impact, and remediation.

| # | Attack | Severity | OWASP | Writeup |
|---|--------|----------|-------|---------|
| 01 | SSH Credential Brute Force | High | A07 — Auth Failures | [writeups/01-ssh-brute-force.md](writeups/01-ssh-brute-force.md) |
| 02 | Web Application Reconnaissance | Medium | A05 — Misconfiguration | [writeups/02-web-reconnaissance.md](writeups/02-web-reconnaissance.md) |
| 03 | SQL Injection | Critical | A03 — Injection | [writeups/03-sql-injection.md](writeups/03-sql-injection.md) |
| 04 | Cross-Site Scripting (XSS) | High | A03 — Injection | [writeups/04-xss.md](writeups/04-xss.md) |
| 05 | Command Injection | Critical | A03 — Injection | [writeups/05-command-injection.md](writeups/05-command-injection.md) |
| 06 | Web Login Brute Force | High | A07 — Auth Failures | [writeups/06-web-brute-force.md](writeups/06-web-brute-force.md) |

---

## Repository Structure

```
soc-siem-lab/
├── README.md
├── notes/
│   └── progress.md              # Full build log and phase documentation
├── ansible/
│   ├── inventory.ini            # All 4 VMs with connection details
│   ├── site.yml                 # Master playbook
│   └── roles/
│       ├── filebeat/            # Filebeat installation and config role
│       └── metricbeat/          # Metricbeat installation and config role
├── python/
│   └── alert_engine.py          # Custom detection and response engine
└── writeups/
    ├── 01-ssh-brute-force.md
    ├── 02-web-reconnaissance.md
    ├── 03-sql-injection.md
    ├── 04-xss.md
    ├── 05-command-injection.md
    └── 06-web-brute-force.md
```

---

## How to Reproduce This Lab

### Prerequisites
- Microsoft Azure account (Pay As You Go — free trial quota too low)
- Azure CLI installed and authenticated
- Ansible 2.16.x
- Python 3.10+
- WSL2 (Windows) or Linux/macOS

### 1. Deploy Infrastructure

```bash
# Create resource group
az group create --name soc-lab-rg --location eastus2

# Create VNet and subnet
az network vnet create \
  --resource-group soc-lab-rg \
  --name soc-lab-vnet \
  --address-prefix 10.0.0.0/16 \
  --subnet-name soc-lab-subnet \
  --subnet-prefix 10.0.1.0/24

# Create and configure NSG
az network nsg create --resource-group soc-lab-rg --name soc-lab-nsg
az network nsg rule create -g soc-lab-rg --nsg-name soc-lab-nsg \
  --name Allow-SSH --priority 1000 --protocol Tcp \
  --destination-port-range 22 --access Allow --direction Inbound
az network nsg rule create -g soc-lab-rg --nsg-name soc-lab-nsg \
  --name Allow-Kibana --priority 1100 --protocol Tcp \
  --destination-port-range 5601 --access Allow --direction Inbound

# Deploy VMs (repeat for elk-vm, dvwa-vm, kali-vm with appropriate sizes)
az vm create --resource-group soc-lab-rg --name jump-box \
  --image Canonical:0001-com-ubuntu-server-jammy:22_04-lts:latest \
  --size Standard_D2s_v3 --vnet-name soc-lab-vnet \
  --subnet soc-lab-subnet --nsg soc-lab-nsg \
  --admin-username azureuser --generate-ssh-keys
```

### 2. Deploy ELK Stack

```bash
# SSH into elk-vm
ssh elk-vm

# Set vm.max_map_count (required by Elasticsearch)
sudo sysctl -w vm.max_map_count=262144
echo "vm.max_map_count=262144" | sudo tee -a /etc/sysctl.conf

# Install Docker and deploy ELK
cd ~/elk-stack && docker compose up -d
```

### 3. Run Ansible Automation

```bash
cd ansible/
ansible-playbook -i inventory.ini site.yml
```

### 4. Run the Alert Engine

```bash
# Open Elasticsearch tunnel first
ssh -i ~/.ssh/id_rsa -L 9200:10.0.1.5:9200 azureuser@JUMP_BOX_IP -N &

# Run the engine
cd python/
python3 alert_engine.py
```

---

## Key Design Decisions

**Why a jump box instead of direct VM access?**
Bastion host pattern limits the attack surface to a single hardened entry point. Internal VMs have no public IP — they are unreachable from the internet regardless of what ports are open.

**Why Docker for the ELK Stack?**
Version compatibility between Elasticsearch, Logstash, and Kibana is critical. Docker guarantees all three run on the same 8.11.0 image with no dependency conflicts. Teardown and rebuild is a single command.

**Why a custom Python alert engine alongside Kibana rules?**
Kibana rules detect and log. The Python engine detects, enriches with threat intel, and automatically takes action — blocking attackers at the Azure NSG level within 5 seconds. Kibana cannot do this natively.

**Why Ansible for deployment automation?**
Idempotent infrastructure as code. The entire agent configuration is reproducible from a single command. Adding a new monitored VM means adding one line to inventory.ini and running the playbook.

---

## Skills Demonstrated

```
Cloud Engineering     Azure VNet, NSG, VM deployment, CLI automation
Network Security      Subnet design, firewall rules, jump box architecture
SIEM Engineering      Full ELK pipeline: collection, parsing, indexing, alerting
Detection Engineering KQL queries, threshold rules, slow-and-low detection
Python Security       Elasticsearch queries, API integration, automated response
Infrastructure as Code Ansible roles, idempotent playbooks, Jinja2 templates
Container Management  Docker Compose, volume mounts, container networking
Offensive Security    nmap, Hydra, Nikto, DVWA exploitation, kill chain mapping
Incident Response     Detection, containment, IOC identification, remediation
```

---

## Author

**Solomon Lee**
Computer Science Student, Sacramento State University (Expected Dec 2026)
ISACA Cybersecurity Scholar | Google Cybersecurity & IT Professional Certificate | CCNA

[LinkedIn](https://linkedin.com/in/solomon-lee-962304192) | [GitHub](https://github.com/solo-alu) | solomonlee78@gmail.com

