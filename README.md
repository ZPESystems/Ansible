# Nodegrid Ansible Library

On this repository you find the Ansible Library for Nodegrid, a set of ansible collections designed to manage and interact with the Nodegrid and its devices.

This library is currently in expansion, read the [LibrarySupport.md](LibrarySupport.md) to see the modules list.

## Requirements
**Nodegrid Version:** 5.6 or higher (recommended 5.6.5 or newer)

## Installation

### Installation on Nodegrid
The collection can be installed by the default 'admin' user, this will enable the use of the Cluster feature to directly manage Nodegrid appliances which are part of the cluster setup.

#### Step 1 - Download the library
You can download this library in a few different ways:
- Download the latest release from the Releases session;
- Download the repository as a zip for a full collection;
- Using the `git clone` command to clone the full repository;

**Downloaded a Release or the repository as zip**
- Connect to the WebUI as a admin user
- Open the file Manager and navigate to admin_group
- Upload the downloaded `.zip` file into the folder
- Close the File Manager window
- Open a Console connection to Nodegrid
- Access the shell as an admin user using the `shell` command
- Navigate to `/var/local/file_manager/admin_group/` 
```shell script
cd /var/local/file_manager/admin_group/
```
- extract the `.zip` file with
```shell script
unzip <file_name>.zip
```

**Using git clone command**
- Connect to the WebUI as a admin user
- Open a Console connection to Nodegrid
- Navigate to `/var/local/file_manager/admin_group/` 
```shell script
cd /var/local/file_manager/admin_group/
```
- Clone the repository
```shell script
git clone https://github.com/ZPESystems/Ansible.git
```

#### Step 2 - Install the library 

In an **admin shell**, navigate to the downloaded library directory and run the installation playbook.
```shell script
ansible-playbook nodegrid_install.yml
```
Become ansible user.
```shell script
sudo su - ansible
```

**[Optional] Allow a user to connect to the ansible user via ssh**

It is possible to authorize a user to access the ansible user via ssh by running `setup_authorize_user.yml` playbook inside the examples folder. For this, it is necessary to paste the ssh public key of the user in the playbook execution.
```shell script
ansible-playbook ./examples/playbooks/setup/setup_authorize_user.yml
```

### Ready to run the first playbook

> Always run playbooks on the Nodegrid with the **ansible user**

Run your first playbook
```
ansible-playbook /etc/ansible/playbooks/ng_get_facts.yml
```

More examples can be found in the playbook folder
```
cd /etc/ansible/playbooks/
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

