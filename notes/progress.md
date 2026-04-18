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
- [x] jump-box deployed (Standard_D2s_v3, 10.0.1.4, public IP: 20.62.119.46)
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
- [x] All attacks visible in Kibana Discover (source.ip: 10.0.1.7)
- [x] SSH Brute Force Detection rule created in Kibana
- [x] Alert firing automatically when threshold exceeded

## Attacks Detected
- Port scan: reconnaissance of open ports
- SSH brute force: repeated Invalid user attempts from 10.0.1.7
- Web scan: 11 vulnerabilities found including exposed config directory,
  missing security headers, and admin login page exposed

## Next Session
- [ ] Ansible automation playbooks
- [ ] Python detection engine
- [ ] Advanced configurations (TLS, RBAC, threat intel)
