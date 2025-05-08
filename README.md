# Nodegrid Ansible Library

In this repository, you'll find the Ansible Library for Nodegrid - a Ansible collection designed to manage and interact with Nodegrid devices.

This library is currently under active development. For a complete list of available modules, refer to the [LibrarySupport.md](LibrarySupport.md) file.

## Installation

You can install the library either from the **full repository** (recommended) or from a **release file**.

The full repository includes the installation script, usage examples, and additional resources to help you get started. 
Release file contains only the Ansible collection itself 

### Installating on Nodegrid

**Requirements**
- Nodegrid version 6.0 or higher (recommended 6.0.15 or newer)

Installation must be performed by the default `admin` user. In a clustered environment, it must be installed **only on the cluster coordinator**, as it will manage all Nodegrid peers in the cluster.

You can install the Ansible Library using one of the following methods:

**1. Clone the repository (Recommended)**
- Log in to the WebUI as a `admin` user.
- Open a Console connection to the Nodegrid.
- Run the following commands:
```shell script
shell
git clone https://github.com/ZPESystems/Ansible.git /tmp/Ansible
cd /tmp/Ansible
export LANG="en_US.UTF-8"
ansible-playbook nodegrid_install.yml
```

**2. Download the repository as ZIP file**
- Download the ZIP file from: [https://github.com/ZPESystems/Ansible](https://github.com/ZPESystems/Ansible)
- Log in to the WebUI as a `admin` user.
- Open the **File Manager** and navigate to `admin_group`folder.
- Upload the `.zip` file you downloaded.
- Close the File Manager.
- Open a Console connection to the Nodegrid
- Run the following commands:
```shell script
shell
cd /var/local/file_manager/admin_group/
unzip Ansible-main.zip
cd Ansible-main
export LANG="en_US.UTF-8"
ansible-playbook nodegrid_install.yml
```

**[Optional] Allow a user to connect to the ansible user via ssh**

It is possible to authorize a user to access the ansible user via ssh by running `setup_authorize_user.yml` playbook inside the examples folder. For this, it is necessary to paste the ssh public key of the user in the playbook execution.
```shell script
sudo su - ansible
ansible-playbook ./examples/playbooks/setup/setup_authorize_user.yml
```

#### Ready to run the first playbook

> Always run playbooks on the Nodegrid with the **ansible user**

Run your first playbook
```shell script
sudo su - ansible
ansible-playbook /etc/ansible/playbooks/ng_get_facts.yml
```

More examples can be found in the playbook folder
```
cd /etc/ansible/playbooks/
```

### Installating on other systems

**Requirements**
- Python 3.10+ (required library: [ttp](https://pypi.org/project/ttp))
- Ansible core 2.17+

Run the following commands:

```shell
git clone https://github.com/ZPESystems/Ansible.git /tmp/Ansible
cd Ansible
python3 build.py
ansible-galaxy collection install -r build/collections/requirements.yml --force
```

#### ansible.cfg

This is the minimal ansible.cfg recommended file content:

```yaml
[defaults]
interpreter_python = /usr/bin/python3
gathering = explicit
host_key_checking = False

[ssh_connection]
ssh_args = -o ControlMaster=no -o ControlPersist=3600s -o PreferredAuthentications=publickey
```

### Installating from release .tar.gz file

- Choose a release version on: [https://github.com/ZPESystems/Ansible/releases](https://github.com/ZPESystems/Ansible/releases)
- Copy the .tar.gz file link.
- Run the following shell commands:

```shell
# Example for version 1.2.0
cd /tmp
wget https://github.com/ZPESystems/Ansible/releases/download/v1.2.0/zpe-nodegrid-1.2.0.tar.gz
ansible-galaxy collection install zpe-nodegrid-1.2.0.tar.gz --force
```

# Usage
To run playbooks, 
- connect to the Nodegrid as **ansible user**
- create new playbooks in `/etc/ansible/playbooks/`
- run your playbooks with
```
ansible-playbook /etc/ansible/playbooks/<playbook>
```

- to limit the execution to a specific host run
```
ansible-playbook /etc/ansible/playbooks/<playbook> -limit <host/group name>
```

- to run in verbose mode add `-vvv`
```
ansible-playbook /etc/ansible/playbooks/<playbook> -limit <host/group name> -vvv
```

## Inventory

To see all available hosts of the inventory run the command:
```shell script
ansible-inventory --list
```

### Localhost
To run playbooks which configure the Nodegrid no further setup is required. In order to run commands against connected device must the local ansible user setup be compleated.

### Local
The local inventory can be easly expanded by adding new hosts to the hosts file in inventory folder.
The file is located in `/ansible/ansible/inventory`

**Example:** `/ansible/ansible/inventory/hosts.yml`

```yaml
all:
  hosts:
    ng1:
      ansible_host: "192.168.0.100"
      ansible_python_interpreter: "/usr/bin/python3"
      ansible_ssh_private_key_file: "/home/ansible/.ssh/id_ed25519"
      ansible_ssh_user: "ansible"
    ng2:
      ansible_host: "192.168.0.101"
      ansible_python_interpreter: "/usr/bin/python3"
      ansible_ssh_private_key_file: "/home/ansible/.ssh/id_ed25519"
      ansible_ssh_user: "ansible"
my_group:
  hosts:
    ng1:
    ng2:
```

### Cluster
A nodegrid which is part of a Cluster can automatically interact with units within the cluster. 

## Example Playbooks

Example playbooks are available in the [examples](examples/playbooks) folder .

#### Update System Settings
```yaml
- hosts: all
  gather_facts: false
  collections:
    - zpe.nodegrid

  tasks:
  - name: Update System preferences
    zpe.nodegrid.system:
      preferences:
        show_hostname_on_webui_header: "yes"
        idle_timeout: "3600"
        enable_banner: "yes"
```

## Build

Feel free to create and modify the collections inside the folder `collections/ansible_collections/zpe`.
- as admin user build the library running the script `build.py`
```shell script
python3 build.py
```
- install the collection with `ansible-galaxy`
```shell script
ansible-galaxy collection install -r build/collections/requirements.yml --force
```

