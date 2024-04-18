# ZPE Wireguard Hub-Spoke automated peering service: Spoke

This document describes the deployment of the *ZPE Wireguard Hub-Spoke automated peering service*. This service consists of having a centralized node, i.e., the **Hub**, and multiple **Spokes** in remote locations which require to configure a Point-to-Point VPN, i.e., a Wireguard tunnel. To this end, each **Spoke** shall request the **Hub** the required information to create a Wireguard peering VPN. Once the peering VPN is established, both the **Spoke** and the **Hub** must have IP connectivity over it. 

![](figs/network-diagram.png)

This document describes the deployment and configuration of the **Spoke**. The following diagram depicts the overall objective:

![](figs/vpn-diagram.png)


## Requirements

For all the devices (i.e., the Hub and all the Spokes), the following requirements must be met:
- Clone the repo [Nodegrid Ansible Library](https://github.com/ZPESystems/Ansible) and execute:

```bash
git clone https://github.com/ZPESystems/Ansible 
cd Ansible
ansible-playbook nodegrid_install.yml
```

## Deploying the **Spoke**
### Deploying from the Nodegrid Spoke device

The deploying and configuration consist on the execution of an ansible playbook as follows:

- Connect to the Spoke using the **ansible** user

- Go to the path `Ansible/examples/playbooks/wireguard-hub-spoke-peering`:

- Modify the file `setup-wireguard-spoke.yaml`, specifying:
  - `HUB_URI: "http://{{ PUBLIC_IP }}:8080"`
  - `PORT_KNOCKING: true` to enable port knocking feature
  - `PORT_KNOCKING_IP: "{{ PUBLIC_IP }}"`


```yaml
- hosts: localhost
  gather_facts: false
  connection: local
  become: true

  tasks:
    - name: setting up wg spoke role
      include_role:
        name: setup-wg-spoke
      vars:
        HUB_URI: 'http://{{ PUBLIC_IP }}:8080' # Hub URI for peering requests
        # Nodegrid Variables
        NODEGRID_URI: "https://localhost"
        NODEGRID_API_PREFIX: "/api/v1"
        NODEGRID_CREATE_API_USER: true # Ansible playbook create the NODEGRID_USER and retrieves the NODEGRID_KEY
        NODEGRID_DELETE_API_USER: true # Ansible playbook deletes the NODEGRID_USER
        NODEGRID_USER: "zpeapi" # Nodegrid API User
        NODEGRID_KEY: "" # Nodegrid API User key must be defined if NODEGRID_CREATE_API_USER is fale

        # Wireguard Peering Variables
        WIREGUARD_IFACE_NAME: 'wg-spoke1' # Spokes's UNIQUE Network :: Wireguard interface name
        WIREGUARD_PEER_ID: 'spoke1' # Hub's UNIQUE PEER ID. It mus be unique per each Spoke

        # Port Knocking Variables
        PORT_KNOCKING: false # true for enabling port knocking. If true, the following vars are taken in consideration
        PORT_KNOCKING_IP: "{{ PUBLIC_IP }}" # remote IP for port knocking
        PORT1: 1110 # first port to knock
        PORT2: 2220 # second port to knock
        PORT3: 3330 # third port to knock

```

- Execute the playbook:

```bash
ansible-playbook setup-wireguard-spoke.yaml
```

- To manually verify, execute the following:

```bash
ping 10.20.0.1
```

