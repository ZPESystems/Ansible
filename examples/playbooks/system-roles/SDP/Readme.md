# ZPE Service Delivery Platform (SDP) Ansible Automation

This document describes the Service Delivery Platform SDP Ansible Automation use case. This case considers the following requirements:

- Configure a brand new Nodegrid device, it includes its network connections, firewall, and hypervisor
- Deploy a list of Virtual Machines

## Steps

In the following example, two Virtual Machines shall be deployed:

1. Install Ansible community libvirt

```bash
ansible-galaxy collection install community.libvirt
```

2. Create the Inventory. An inventory example is provided

3. Execute the playbook `100_configure_network.yaml`
```bash
ansible-playbook 100_configure_network.yaml --limit company
```

4. Execute the playbook `200_create_virtual_machines.yaml`
```bash
ansible-playbook 200_create_virtual_machines.yaml --limit company
```



