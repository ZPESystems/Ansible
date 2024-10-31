#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2023, ZPE Systems <zpesystems.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r'''
'''

EXAMPLES = r'''

'''

RETURN = r'''

'''

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.zpe.nodegrid.plugins.module_utils.nodegrid_util import run_option, check_os_version_support, field_exist, export_settings, format_settings, run_option_no_diff

import os
import re

# We have to remove the SID from the Environmental settings, to avoid an issue
# were we can not run pexpect.run multiple times
if "DLITF_SID" in os.environ:
    del os.environ["DLITF_SID"]
if "DLITF_SID_ENCRYPT" in os.environ:
    del os.environ["DLITF_SID_ENCRYPT"]

def result_failed(msg):
    return {'failed': True, 'changed': False, 'msg': msg}

def result_nochanged():
    return {'failed': False, 'changed': False, 'msg': 'No change required'}

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
    network_range_cli_path = option['cli_path']
    if field_exist(suboptions,'ip_address_start'):
        network_range_cli_path += f"/{suboptions['ip_address_start']}"
    else:
        missing_fields.append('ip_address_start')
    if field_exist(suboptions,'ip_address_end'):
        network_range_cli_path += f"|{suboptions['ip_address_end']}"
    else:
        missing_fields.append('ip_address_end')
    if len(missing_fields) > 0:
       return result_failed(f"Missing required field(s): {', '.join(missing_fields)}")
    
    # The DHCP range item path does not support export settings
    # it must be set manually to the diff comparison
    option['settings'] = format_settings(network_range_cli_path, suboptions)
    return run_option(option, run_opt)

def run_option_host(option, run_opt):
    suboptions = option['suboptions']

    # Fields validation
    if field_exist(suboptions,'subnet') and 'duid' in suboptions:
        del suboptions['duid']
    validate_fields_and_update_cli_path(option, 'hosts')
    cli_path = option['cli_path']
    if not field_exist(suboptions, 'hostname'):
        return result_failed(f"Missing required field: hostname")

    # Export current settings
    state, exported_settings, exported_all_settings = export_settings(cli_path)
    if "error" in state:
        return result_failed(f"Failed exporting settings on {cli_path}. Error: {state[1]}")

    # Remove invalid parameters
    for key, value in suboptions.copy().items():
        if not any(key in item for item in exported_settings):
            del suboptions[key]

    settings_list = []
    opts = suboptions.copy()

    # Replace values with the same hostname
    sequence_number = 0
    index_cli_path = None
    changed = False
    pattern = re.compile(r'/hosts/(\d+):\[(\w+)\]\s(\w+)=(.*)')
    for line in exported_settings:
        match = pattern.search(line)
        if match:
            sequence_number, hostname, param_name, param_value = match.groups()
            if hostname == suboptions['hostname']:
                if param_name in opts:
                    if opts[param_name] != param_value:
                        if index_cli_path is None:
                            index_cli_path = f"{cli_path}/{sequence_number}:[{hostname}]"
                        line = f"{index_cli_path} {param_name}={opts[param_name]}"
                        changed = True
                    del opts[param_name]
            settings_list.append(line)
        elif line[0] != '#':
            result_failed(f"Invalid settings line: {line}")

    # Add the remaining options
    if len(opts):
        if index_cli_path is None:
            index_cli_path = f"{cli_path}/{int(sequence_number)+1}:[{suboptions['hostname']}]"
        settings_list.extend( format_settings(index_cli_path, opts) )
        # Sort the list by index
        option['settings'] = sorted(settings_list, key=lambda x: int(x.split('/hosts/')[1].split(':')[0]))
        changed = True
    else:
        option['settings'] = settings_list

    if changed:
        return run_option_no_diff(option, run_opt)
    return result_nochanged()


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
