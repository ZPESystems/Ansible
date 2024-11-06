#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2023, ZPE Systems <zpesystems.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r'''
---
module: nodegrid dhcp_server
author:
  - Leonardo Fernandes (@zpe-leonardof)

description:
  - The dhcp_server module is used to set up the DHCP Server in a Nodegrid device.

atributes:
  check_mode:
    support: full
  diff_mode:
    support: none
  platform:
    platforms: Nodegrid

options:
  settings:
    description: Set of settings of one DHCP Server
    required: False
    type: dict
    suboptions:
      protocol:
        description: IP Protocol
        required: True
        choices: ['dhcp4','dhcp6']
        default: 'dhcp4'
        type: str
      subnet:
        description: Subnet IPv4 Network Address. Required when 'protocol' is set with 'dhcp4'
        required: True
        default: ''
        type: str
      netmask:
        description: IPv4 subnet mask number. Required when 'protocol' is set with 'dhcp4'
        required: True
        default: ''
        type: str
      prefix:
        description: Prefix IPv6 Network Address. Required when 'protocol' is set with 'dhcp6'
        required: True
        default: ''
        type: str
      length:
        description: IPv6 prefix lengh number. Required when 'protocol' is set with 'dhcp6'
        required: True
        default: ''
        type: str
      domain:
        description: Domain
        required: False
        default: ''
        type: str
      domain_name_servers:
        description: DNS servers
        required: False
        default: ''
        type: str
      router_ip:
        description: Router IP
        required: False
        default: ''
        type: str
      lease_time:
        description: Lease Time
        required: False
        default: '86400'
        type: str
      wifi_controller_ip:
        description: WiFi Controller IP
        required: False
        default: ''
        type: str
  network_range:
    description: DHCP Server Network Range
    required: False
    type: dict
    suboptions:
      subnet:
        description: Subnet IPv4 Network Address. Required for IPv4 DHCP Server
        required: True
        default: ''
        type: str
      netmask:
        description: IPv4 subnet mask number. Required for IPv4 DHCP Server
        required: True
        default: ''
        type: str
      prefix:
        description: Prefix IPv6 Network Address. Required for IPv6 DHCP Server
        required: True
        default: ''
        type: str
      length:
        description: IPv6 prefix lengh number. Required for IPv6 DHCP Server
        required: True
        default: ''
        type: str
      ip_address_start:
        description: Start IP Address
        required: True
        default: ''
        type: str
      ip_address_end:
        description: End IP Address
        required: True
        default: ''
        type: str
  host:
    description: Table of reserved hosts IP address
    required: False
    type: dict
    suboptions:
      hostname:
        description: Unique hostname
        required: True
        default: ''
        type: str
      hw_address:
        description: MAC Address
        required: True
        default: ''
        type: str
      agent_circuit_id:
        description: Agend Circuit ID
        required: True
        default: ''
        type: str
      assigned_hostname:
        description: Assigned Hostname
        required: False
        default: ''
        type: str
      ip_address:
        description: IP Address
        required: True
        default: ''
        type: str
'''

EXAMPLES = r'''

'''

RETURN = r'''

'''

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.zpe.nodegrid.plugins.module_utils.nodegrid_util import run_option, check_os_version_support, field_exist, export_settings, format_settings, run_option_no_diff, result_failed, result_nochanged, run_option_all_settings

import os
import re

# We have to remove the SID from the Environmental settings, to avoid an issue
# were we can not run pexpect.run multiple times
if "DLITF_SID" in os.environ:
    del os.environ["DLITF_SID"]
if "DLITF_SID_ENCRYPT" in os.environ:
    del os.environ["DLITF_SID_ENCRYPT"]

def remove_invalid_dhcp6_fields(suboptions):
    if 'prefix' in suboptions:
        del suboptions['prefix']
    if 'length' in suboptions:
        del suboptions['length']

def remove_invalid_dhcp4_fields(suboptions):
    if 'subnet' in suboptions:
        del suboptions['subnet']
    if 'netmask' in suboptions:
        del suboptions['netmask']

def run_option_settings(option, run_opt):
    suboptions = option['suboptions']
    missing_fields = []

    # Fields validation
    if field_exist(suboptions,'protocol'):
        if suboptions['protocol'] == 'dhcp4':
            if field_exist(suboptions,'subnet'):
                option['cli_path'] += f"{suboptions['subnet']}"
            else:
                missing_fields.append('subnet')
            if field_exist(suboptions,'netmask'):
                option['cli_path'] += f"|{suboptions['netmask']}/settings"
            else:
                missing_fields.append('netmask')
            remove_invalid_dhcp6_fields(suboptions)
        elif suboptions['protocol'] == 'dhcp6':
            if field_exist(suboptions,'prefix'):
                option['cli_path'] += f"{suboptions['prefix']}"
            else:
                missing_fields.append('prefix')
            if field_exist(suboptions,'length'):
                option['cli_path'] += f"|{suboptions['length']}/settings"
            else:
                missing_fields.append('length')
            remove_invalid_dhcp4_fields(suboptions)
        else:
            return result_failed("Invalid protocol")
    else:
        missing_fields.append('protocol')
    if len(missing_fields) > 0:
        return result_failed(f"Missing required field(s): {', '.join(missing_fields)}")
    return run_option(option, run_opt)

def validate_fields_and_update_cli_path(option, lastpath):
    suboptions = option['suboptions']
    if field_exist(suboptions,'subnet') and field_exist(suboptions,'netmask'):
        option['cli_path'] += f"{suboptions['subnet']}|{suboptions['netmask']}/{lastpath}"
    elif field_exist(suboptions,'prefix') and field_exist(suboptions,'length'):
        option['cli_path'] += f"{suboptions['prefix']}|{suboptions['length']}/{lastpath}"
    else:
        return result_failed("Missing required fields: subnet|netmask, or prefix|length")
    remove_invalid_dhcp6_fields(suboptions)
    remove_invalid_dhcp4_fields(suboptions)

def run_option_network_range(option, run_opt):
    suboptions = option['suboptions']
    missing_fields = []

    # Fields validation
    validate_fields_and_update_cli_path(option, 'network_range')
    range_path = option['cli_path']
    if field_exist(suboptions,'ip_address_start'):
        range_path += f"/{suboptions['ip_address_start']}"
    else:
        missing_fields.append('ip_address_start')
    if field_exist(suboptions,'ip_address_end'):
        range_path += f"|{suboptions['ip_address_end']}"
    else:
        missing_fields.append('ip_address_end')
    if len(missing_fields) > 0:
       return result_failed(f"Missing required field(s): {', '.join(missing_fields)}")

    def compare_path(path):
        return path == range_path

    def get_next_path(last_path):
        return range_path

    return run_option_all_settings(option, run_opt, compare_path, get_next_path)

def run_option_host(option, run_opt):
    suboptions = option['suboptions']

    # Fields validation
    if field_exist(suboptions,'subnet') and 'duid' in suboptions:
        del suboptions['duid']
    validate_fields_and_update_cli_path(option, 'hosts')
    cli_path = option['cli_path']
    if not field_exist(suboptions, 'hostname'):
        return result_failed(f"Missing required field: hostname")

    pattern = re.compile(r'/hosts/(\d+):\[(\w+)\]')
    def compare_path(path):
        match = pattern.search(path)
        if match:
            sequence_number, hostname = match.groups()
            return hostname == suboptions['hostname']
        else:
            return True # Empty page returns /hosts/:[]

    def get_next_path(last_path):
        return f"{cli_path}/:[]"

    return run_option_all_settings(option, run_opt, compare_path, get_next_path, remove_invalid_setting=True)

def run_module():
    # define available arguments/parameters a user can pass to the module
    module_args = {
        'settings': dict(type='dict', required=False),
        'network_range': dict(type='dict', required=False),
        'host': dict(type='dict', required=False),
        'skip_invalid_keys': dict(type='bool', default=False, required=False)
    }

    # seed the result dict in the object
    # we primarily care about changed and state
    # changed is if this module effectively modified the target
    # state will include any data that you want your module to pass back
    # for consumption, for example, in a subsequent task
    result = dict(
        changed=False,
        message='',
        output={}
    )

    # the AnsibleModule object will be our abstraction working with Ansible
    # this includes instantiation, a couple of common attr would be the
    # args/params passed to the execution, as well as if the module
    # supports check mode
    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=True
    )

    # List of options to run
    option_list = [
        {
            'name': 'settings',
            'suboptions': module.params['settings'],
            'cli_path': '/settings/dhcp_server/',
            'func': run_option_settings
        },
        {
            'name': 'network_range',
            'suboptions': module.params['network_range'],
            'cli_path': '/settings/dhcp_server/',
            'func': run_option_network_range
        },
        {
            'name': 'host',
            'suboptions': module.params['host'],
            'cli_path': '/settings/dhcp_server/',
            'func': run_option_host
        },
    ]

    # add name in the cli_path
    

    #
    # Nodegrid OS section starts here
    #
    # Lets get the current interface status and check if it must be changed
    res, err_msg, nodegrid_os = check_os_version_support()
    if res == 'error' or res == 'unsupported':
        module.fail_json(msg=err_msg, **result)
    elif res == 'warning':
        result['warning'] = err_msg
        use_config_start_global = False
    else:
        use_config_start_global = True
    result['nodegrid_facts'] = nodegrid_os
    
    #
    # Lets run the options
    #
    run_opt = {
        'skip_invalid_keys': module.params['skip_invalid_keys'],
        'use_config_start_global' : use_config_start_global,
        'check_mode': module.check_mode
    }

    for option in option_list:
        if option['suboptions'] is not None:
            func = option['func']
            res = func(option, run_opt)
            result['output'][option['name']] = res
            if res['failed']:
                result['failed'] = True
                module.fail_json(msg=res['msg'], **result)

    if len(result['output'].keys()) == 0:
        module.fail_json(msg='No inputs', **result)

    # if the user is working with this module in only check mode we do not
    # want to make any changes to the environment, just return the current
    # state with no modifications
    if module.check_mode:
        result['message'] = "No changes where performed, running in check_mode"
        module.exit_json(**result)

    # manipulate or modify the state as needed (this is going to be the
    # part where your module will do what it needs to do)
    result['message'] = 'No change required'
    for key in result['output'].keys():
        item = result['output'][key]
        if item['changed']:
            result['changed'] = True
            result['message'] = 'Import was successful'
            break

    # in the event of a successful module execution, you will want to
    # simple AnsibleModule.exit_json(), passing the key/value results
    module.exit_json(**result)


def main():
    run_module()


if __name__ == '__main__':
    main()
