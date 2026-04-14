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

## Next Session
- [ ] Configure SSH config file for jump box access
- [ ] SSH into jump box and verify connectivity
- [ ] SSH into internal VMs via jump box
