# SOC Lab Progress

## Phase 1 — Azure Setup
- [x] Azure account created
- [x] Azure CLI installed in WSL
- [x] SSH key generated
- [x] Resource group created (soc-lab-rg, eastus2)

## Phase 2 — Network Infrastructure
- [x] Virtual network created (soc-lab-vnet, 10.0.0.0/16)
- [x] Subnet created (soc-lab-subnet, 10.0.1.0/24)
- [x] NSG created (soc-lab-nsg)
- [x] NSG rules created (SSH :22, Kibana :5601)
- [x] NSG attached to subnet

## Phase 3 — Virtual Machines
- [x] jump-box deployed (Standard_D2s_v3, 10.0.1.4, public IP)
- [x] elk-vm deployed (Standard_D4s_v3, 10.0.1.5)
- [x] dvwa-vm deployed (Standard_D2s_v3, 10.0.1.6)
- [x] kali-vm deployed (Standard_D2s_v3, 10.0.1.7)

## Phase 4 — SSH Configuration
- [x] SSH config file created (~/.ssh/config)
- [x] jump-box accessible (ssh jump-box)
- [x] elk-vm accessible via ProxyJump (ssh elk-vm)
- [x] dvwa-vm accessible via ProxyJump (ssh dvwa-vm)
- [x] kali-vm accessible via ProxyJump (ssh kali-vm)

## Phase 5 — Docker + ELK Stack
- [x] Docker installed on ELK VM
- [x] Virtual memory increased (vm.max_map_count=262144)
- [x] docker-compose.yml created
- [x] Logstash pipeline and config files created
- [x] ELK stack deployed (Elasticsearch, Logstash, Kibana)
- [x] Elasticsearch responding on port 9200
- [x] Kibana accessible at localhost:5601 via SSH tunnel

## Phase 6 — Beats Agents
- [x] Filebeat installed and configured on DVWA VM
- [x] Filebeat sending logs to Logstash at 10.0.1.5:5044
- [x] filebeat-* data view created in Kibana
- [x] Metricbeat installed and configured on DVWA VM
- [x] Metricbeat sending metrics to Logstash at 10.0.1.5:5044
- [x] metricbeat-* data view created in Kibana
- [x] CPU metrics visible in Kibana dashboard

## Phase 7 — DVWA Deployment
- [x] Docker installed on DVWA VM
- [x] DVWA container deployed on port 80
- [x] DVWA accessible via SSH tunnel at localhost:8080
- [x] Database initialized
- [x] Security level set to Low

## Phase 8 — Attack Simulation
- [x] Installed attack tools on Kali VM (nmap, hydra, nikto)
- [x] Port scan against DVWA VM (nmap -sV -O 10.0.1.6)
- [x] SSH brute force attack (Hydra) - generated Invalid user logs
- [x] Web vulnerability scan (Nikto) - found 11 vulnerabilities
- [x] All attacks visible in Kibana Discover (attacker IP 10.0.1.7 in the message field; source.ip is not populated)
- [x] SSH Brute Force Detection rule created in Kibana
- [x] Alert firing automatically when threshold exceeded

## Phase 9 - Attacks Detected
- Port scan: reconnaissance of open ports
- SSH brute force: repeated Invalid user attempts from 10.0.1.7
- Web scan: 11 vulnerabilities found including exposed config directory,
  missing security headers, and admin login page exposed

## Phase 10 — Ansible Automation
- [x] Ansible installed on local WSL (v2.16.3)
- [x] Project structure created (roles/filebeat, roles/metricbeat)
- [x] inventory.ini created with all 4 VMs
- [x] Filebeat role complete (tasks, handlers, templates, defaults)
- [x] Metricbeat role complete (tasks, handlers, templates, defaults)
- [x] site.yml master playbook created

## Phase 11 — Python Alert Engine
- [x] Elasticsearch Python client installed (v8.11.0)
- [x] alert_engine.py — queries ES every 60 seconds
- [x] Detects SSH brute force by parsing message field
- [x] Extracts attacker IP using regex
- [x] Fires alert with IP, attempt count, threshold
- [x] Automatically creates NSG deny rule in Azure
- [x] Checks for existing block rules before creating duplicates
- [x] Dynamic priority calculation prevents rule conflicts
      (bug found later: rules landed after the allow rules on port 80 only, see Phase 14)

## Phase 12 — Threat Intel Enrichment
- [x] AbuseIPDB integration added to alert_engine.py
- [x] ipaddress module detects private vs public IPs
- [x] Private IPs skip API call with explanatory message
- [x] Public IPs query AbuseIPDB for abuse score, reports, country, ISP
- [x] High risk IPs (score > 50) flagged with warning
- [x] Full pipeline tested and working

## Phase 13— Advanced Configurations (Option 3)
- [x] fail2ban installed on dvwa-vm
      maxretry=5, bantime=3600, findtime=600
      Watches /var/log/auth.log
      OS-level protection independent of SIEM

- [x] DVWA container recreated with log volume mount
      /var/log/dvwa-apache mapped from container to VM
      Filebeat now watches Apache access and error logs

- [x] HTTP port 80 opened in NSG (Allow-HTTP, priority 1200)
      Enables web attack simulation from Kali VM

- [x] Apache logs added to Filebeat config
      /var/log/dvwa-apache/access.log
      /var/log/dvwa-apache/error.log
      Nikto web scans now visible in SIEM — 6,216 events detected

- [x] Slow-and-low detection rule created in Kibana
      Name: SSH Slow Brute Force Detection
      Query: message: "Invalid user"
      Threshold: IS ABOVE 10 in 10 minutes
      Check every: 5 minutes
      Rule runs without errors (Kibana's Success ratio measures rule execution,
      not detection accuracy)

## Phase 14 — Self-Review: Auto-Block Was Not Enforcing
- [x] Found in my own writeup 01 evidence: the June 8 auto-block rule
      Block-10-0-1-7-20260608221111 sat at priority 1201, port 80, TCP only
- [x] Root cause 1: get_next_priority() returned max(existing) + 1, so the
      Deny landed after Allow-SSH (1000) and Allow-HTTP (1200). NSG rules are
      evaluated lowest number first and the first match wins, so it never fired
- [x] Root cause 2: the rule create call set no destination port, and the
      Azure CLI defaults that to 80, so SSH (22) was never in scope
- [x] Root cause 3: the "already blocked" check matched any rule with the IP,
      so the broken rule would have stopped a correct one from being created
- [x] Fix: Deny goes in the lowest free priority below the first Allow rule
      (100-999), all protocols, all ports; existing rules only count if they
      actually block; IP is remembered only after Azure confirms
- [x] Verified with a simulated Azure CLI that reproduces the June 8 rule
      exactly with the old code and a priority-100 all-ports deny with the new
- [ ] Re-test on Azure: nc -vz 10.0.1.6 22 from kali-vm before/after the block,
      az network nic list-effective-nsg on dvwa-vm, screenshots into writeup 01
- [x] Removed the system module from filebeat.yml.j2 (it read auth.log a second
      time and could double attempt counts); engine also de-duplicates by file
      offset
- [x] AbuseIPDB key now read from the ABUSEIPDB_API_KEY environment variable
- [x] Added --unblock IP to reset the lab after a test
- [ ] Add elk-stack/docker-compose.yml and Logstash pipeline config to the repo
      (they still live only on elk-vm)

