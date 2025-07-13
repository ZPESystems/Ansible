#!/usr/bin/python
# Make coding more python3-ish, this is required for contributions to Ansible
from __future__ import (absolute_import, division, print_function, annotations)
#from __future__ import annotations
__metaclass__ = type

from ansible.plugins.action import ActionBase
from ansible.utils.display import Display
import csv
import yaml
import os
import re
from collections import defaultdict

display = Display()

# Add representer for 'None' type in Yaml
def represent_none(self, _):
    return self.represent_scalar('tag:yaml.org,2002:null', '')
yaml.representer.SafeRepresenter.add_representer(type(None), represent_none)

class ActionModule(ActionBase):
    """action module"""
    def run(self, tmp=None, task_vars=None):
        super(ActionModule, self).run(tmp, task_vars)
        del tmp
        self._task_vars = task_vars
        action_module_args = self._task.args.copy()
        if len(set(['csv_ip_based', 'csv_local','csv_usb']).intersection(set(action_module_args.keys()))) == 0:
            return self._result_failed(msg="Neither ip-based, local, nor usb CSV file were provided.")
        if not 'ansible_inventory_path' in action_module_args:
            action_module_args['ansible_inventory_path'] = '/etc/ansible/inventories'
        if not 'ansible_inventory_hosts_filename' in action_module_args:
            action_module_args['ansible_inventory_hosts_filename'] = 'imported_managed_devices.yaml'
        if not 'csv_ansible_devices' in action_module_args:
            return self._result_failed(msg="Ansible devices CSV file is required.")
        validate, msg = self.validate_args(args=action_module_args)
        if not validate:
            display.vvv(f"{msg}")
            return self._result_failed(msg=msg)
        target_devices = self.process_ansible_devices(action_module_args['csv_ansible_devices'],action_module_args['ansible_inventory_path'], action_module_args['ansible_inventory_hosts_filename'])
        if target_devices:
            custom_fields_prefix = action_module_args.get('custom_fields_prefix', 'cf_')
            ip_based_devices = {}
            local_devices = {}
            usb_devices = {}
            if 'csv_ip_based' in action_module_args:
                ip_based_devices = self.process_ip_based_devices(file_name=action_module_args['csv_ip_based'], custom_fields_prefix=custom_fields_prefix)
            if 'csv_local' in action_module_args:
                local_devices = self.process_local_devices(file_name=action_module_args['csv_local'], custom_fields_prefix=custom_fields_prefix)
            if 'csv_usb' in action_module_args:
                usb_devices = self.process_usb_devices(file_name=action_module_args['csv_usb'], custom_fields_prefix=custom_fields_prefix)
                    
            devices = self.merge_devices(ip_based_devices, local_devices, usb_devices)
            ansible_inventory_path = action_module_args.get('ansible_inventory_path', '/etc/ansible/inventories')
            self.save_managed_devices(devices=devices, target_devices=target_devices, ansible_inventory_path=ansible_inventory_path)
            return self._result_changed(msg=f"Managed devices inventory successfully created at {action_module_args['ansible_inventory_path']}. The list of ansible target devices is = {list(target_devices)}. The hosts file is {action_module_args['ansible_inventory_path']}/{action_module_args['ansible_inventory_hosts_filename']}")

    # #########################################
    # Read a CSV file and return the a dict with the devices. Each device is identified by the 'device_key_id' value.
    # - if 'device_type' is list: return a dict of devices, each device referenced by 
    #   its 'ansible_inventory_name', and each containing a list of managed devices.
    # - if 'device_type' is dict: return a dict of devices, each device referenced by 
    #   its 'ansible_inventory_name', and each containing a dict with the target device info.
    def read_csv_devices(self, file_name, device_key_id='ansible_inventory_name', device_type=list, custom_fields_prefix=""):
        devices = {}
        custom_fields = set()
        try:
            with open(file_name, mode='r', newline='') as file_obj:
                reader_obj = csv.DictReader(file_obj)
                if not reader_obj:
                    display.vvv(f"File {file_name} does not contain devices information!")
                    return None
                # Filter custom field names, if exists.
                fieldnames = reader_obj.fieldnames
                if not device_key_id in fieldnames:
                    display.vvv(f"CSV file {file_name} fields does not contain the device ID fieldname {device_key_id}.")
                    return None
                if custom_fields_prefix.strip():
                    custom_fields=set([k for k in fieldnames if re.match(f"^{custom_fields_prefix}.*", k)])
                # Parse the devices information
                for device in reader_obj:
                    settings_to_be_deleted = set()
                    for key,value in device.items():
                        if key in custom_fields:
                            continue
                        if value.strip() == "":
                            settings_to_be_deleted.add(key)
                    for setting in settings_to_be_deleted:
                        device.pop(setting, None)
                    ansible_device = device.pop(device_key_id, None)
                    if not ansible_device:
                        display.vvv(f"Following device does not have a device key ID, defined in the '{device_key_id}' setting. It will not be configured. Device info: {device}")
                        continue
                    if custom_fields:
                        new_device = dict(device)
                        new_device["custom_fields"] = []
                        for cf_key in custom_fields:
                            cf_value = new_device[cf_key]
                            new_device["custom_fields"].append({"field_name":cf_key.removeprefix(custom_fields_prefix) ,"field_value": cf_value})
                            new_device.pop(cf_key, None)
                        device = new_device
                        display.vvv(f"Device with custom fields: {device}")
    
                    if not ansible_device in devices and device_type is list:
                        devices[ansible_device] = []
                    if device_type is list:
                        devices[ansible_device].append(device)
                    elif device_type is dict: 
                        devices[ansible_device] = device
            return devices
        except FileNotFoundError:
            display.vvv(f"The file '{file_name}' was not found. Interrumping the execution.")
        except IOError as e:
            display.vvv(f"Error: An I/O error occurred while accessing '{file_name}'. Error: {e}")
        except csv.Error as e:
            # Handle general CSV-related errors (e.g., malformed CSV)
            display.vvv(f"Error reading CSV file: {file_name}. Error: {e}")
        except Exception as e:
            # Catch any other unexpected exceptions
            display.vvv(f"An unexpected error occurred: {e}")
        return None

    # ###################################
    # Process the Ansible target devices
    def process_ansible_devices(self, csv_ansible_devices, ansible_inventory_path="/etc/ansible/inventories",ansible_inventory_hosts_filename="imported_managed_devices.yaml"):
        devices = self.read_csv_devices(csv_ansible_devices, device_type=dict)
        if not devices:
            display.vvv(f"Error Processing the Ansible Devices!.")
            return None
        group = {}
        display.vvv(f"Ansible devices: {devices}")
        display.vvv(f"Number of Ansible devices to be processed: {len(devices.keys())}")
        for device_name, ansible_device in devices.items():
            group[device_name] = None
            file_name = os.path.join(ansible_inventory_path,'host_vars',f"{device_name}.yaml")
            display.vvv(f"Writting Ansible device config into: {file_name}")
            with open(file_name, 'w') as device_file:
                yaml.safe_dump(ansible_device, device_file)
        file_name = os.path.join(ansible_inventory_path,ansible_inventory_hosts_filename)
        display.vvv(f"Writting hosts file into: {file_name}")
        with open(file_name, 'w') as device_file:
            yaml.safe_dump({"all": {"hosts": group}}, device_file)
        return devices.keys()

    # ###################################
    # Process the IP-based managed devices
    def process_ip_based_devices(self, file_name, custom_fields_prefix=""):
        devices = self.read_csv_devices(file_name, device_type=list, custom_fields_prefix=custom_fields_prefix)
        display.vvv(f"IP-based managed devices: {devices}")
        display.vvv(f"Number of IP-based devices to be processed: {len(devices.keys())}")
        return devices
    
    # ###################################
    # Process the Local managed devices
    def process_local_devices(self, file_name, custom_fields_prefix=""):
        devices = self.read_csv_devices(file_name, device_type=list, custom_fields_prefix=custom_fields_prefix)
        display.vvv(f"Local managed devices: {devices}")
        display.vvv(f"Number of Local devices to be processed: {len(devices.keys())}")
        return devices
    
    # ###################################
    # Process the USB managed devices
    def process_usb_devices(self, file_name, custom_fields_prefix=""):
        devices = self.read_csv_devices(file_name, device_type=list, custom_fields_prefix=custom_fields_prefix)
        display.vvv(f"Usb managed devices: {devices}")
        display.vvv(f"Number of Usb devices to be processed: {len(devices.keys())}")
        return devices
    
    # ###################################
    # Save Managed devices
    def save_managed_devices(self, devices, target_devices, ansible_inventory_path):
        for device_name, managed_devices in devices.items():
            if not device_name in target_devices:
                display.vvv(f"Target device {device_name} is not defined on the list of ansible target devices. Ignoring managed devices: {managed_devices}")
                continue                                
            file_name = os.path.join(ansible_inventory_path,'host_vars',f"{device_name}.yaml")
            display.vvv(f"Writting Managed devices info into: {file_name}")
            with open(file_name, 'a') as device_file:
                yaml.safe_dump({"managed_devices": managed_devices}, device_file)

    # ###################################
    # Merde the managed devices dict into a single dict
    def merge_devices(self, ip_based_devices, local_devices, usb_devices):
        merged_devices = defaultdict(list)
        for key in ip_based_devices.keys() | local_devices.keys() | usb_devices.keys():
            merged_devices[key].extend(ip_based_devices.get(key,[]))
            merged_devices[key].extend(local_devices.get(key,[]))
            merged_devices[key].extend(usb_devices.get(key,[]))
        return dict(merged_devices)

    # ###################################
    # init function
    def __init__(self, *args, **kwargs):
        super(ActionModule, self).__init__(*args, **kwargs)
        self._result = {}
        self._task_vars = None

    def _result_failed(self, msg=''):
        result = dict(
            failed=True,
            changed=False,
            msg=msg
        )
        return result

    def _result_changed(self, msg=''):
        result = dict(
            failed=False,
            changed=True,
            msg=msg
        )
        return result

    def _result_not_changed(self, msg='', settings=dict()):
        result = dict(
            failed=False,
            changed=False,
            settings=settings,
            msg=msg
        )
        return result

    # ###################################
    # Function to validate if a file exists and if it is readable            
    def validate_file(self, file_name, access_priv=os.R_OK):
        if os.path.isfile(file_name) and os.access(file_name, access_priv):
            display.vvv(f"The file '{file_name}' exists and is readable.")
            return True
        else:
            display.vvv(f"The file '{file_name}' does not exist or is not readable.")
            return False
    
    # ###################################
    # Function to validate if a directory exists and if it is writable
    def validate_directory(self, directory_name, access_priv=os.W_OK):
        if os.path.isdir(directory_name) and os.access(directory_name, access_priv):
            display.vvv(f"The directory '{directory_name}' exists and is writable.")
            return True
        else:
            display.vvv(f"The directory '{directory_name}' does not exist or is not readable.")
            return False
    
    # ###################################
    # Function to validate the args
    def validate_args(self, args):
        if 'csv_ip_based' in args:
            if not self.validate_file(args['csv_ip_based']):
                return False, f"Error accessing IP-based file {args['csv_ip_based']}"
        if 'csv_local'in args:
            if not self.validate_file(args['csv_local']):
                return False, f"Error accessing local-devices file {args['csv_local']}"
        if 'csv_usb' in args:
            if not self.validate_file(args['csv_usb']):
                return False, f"Error accessing usb-devices file {args['csv_usb']}"
    
        if not self.validate_file(args['csv_ansible_devices']):
            return False, f"Error accessing ansible devices file {args['csv_ansible_devices']}"
        if not self.validate_directory(args['ansible_inventory_path']):
            return False, f"Error accessing ansible inventory path {args['ansible_inventory_path']}"
        if not self.validate_directory(os.path.join(args['ansible_inventory_path'],'host_vars')):
            display.vvv(f"Creating the host_vars directory {os.path.join(args['ansible_inventory_path'],'host_vars')}")
            os.makedirs(os.path.join(args['ansible_inventory_path'], 'host_vars'), exist_ok=True)
        return True, ""

