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
from ansible_collections.zpe.nodegrid.plugins.module_utils.nodegrid_util import check_os_version_support, run_option, format_settings, field_exist, result_failed, to_list, get_shell

import os, json, pexpect

# We have to remove the SID from the Environmental settings, to avoid an issue
# were we can not run pexpect.run multiple times
if "DLITF_SID" in os.environ:
    del os.environ["DLITF_SID"]
if "DLITF_SID_ENCRYPT" in os.environ:
    del os.environ["DLITF_SID_ENCRYPT"]

def run_option_device(option, run_opt):
    suboptions = option['suboptions']
    cli_path = option['cli_path']
    settings_list = []

    if not ('access' in suboptions and field_exist(suboptions['access'], 'name')):
        return result_failed("Field 'access/name' is required")

    if ('port_name' in suboptions['access']):
        port_name = suboptions['access']['port_name']
        suboptions['access'].pop('port_name')
        cli_path += f"/{port_name}"
    else:
        cli_path += f"/{suboptions['access']['name']}"

    for key, value in suboptions.items():

        if key == 'name':
            print("Rename Port")

        # commands, custom_fields
        if key in ['commands','custom_fields']:
            
            if key == 'commands':
                field_name = 'command'
            else:
                field_name = 'field_name'

            for item in to_list(value):
                if field_exist(item, field_name):
                    settings_list.extend( format_settings(f"{cli_path}/{key}/{item[field_name]}",item) )
                else:
                    return result_failed(f"Field '{key}/{field_name} is required")
                
        # access, management, logging
        else:
            settings_list.extend( format_settings(f"{cli_path}/{key}",value) )
        
    option['cli_path'] = cli_path
    option['settings'] = settings_list
    return run_option(option, run_opt)

def run_option_auto_discovery(option, run_opt):
    suboptions = option['suboptions']
    cli_path = option['cli_path']
    settings_list = []
    
    for key, value in suboptions.items():

        # network_scan
        if key in ['network_scan','vm_managers','discovery_rules']:

            if key == 'network_scan':
                field_name = 'scan_id'
            elif key == 'vm_managers':
                field_name = 'vm_server'
            else:
                field_name = 'rule_name'

            for item in to_list(value):
                if field_exist(item, field_name):
                    settings_list.extend( format_settings(f"{cli_path}/{key}/{item[field_name]}",item) )
                else:
                    return result_failed(f"Field '{key}/{field_name}' is required")

        # hostname_detection
        else:
            settings_list.extend( format_settings(f"{cli_path}/{key}",value) )

    option['settings'] = settings_list
    return run_option(option, run_opt)

def facts(option, run_opt):
    suboptions = option['suboptions']
    cli_path = option['cli_path']
    raw = pexpect.run('llconf ini -si /etc/spm_server.ini json')

    inventory = {
        "managed_devices": [],
        "device_disabled": [],
        "device_enabled": [],
        "device_ondemand": [],
        }
    parsed = json.loads(raw)
    if len(parsed) == 1:
        parsed = parsed['(root)']
        for device in parsed:
            inventory['managed_devices'].append(device)
            if parsed[device]['status'] == 'disabled':
                inventory['device_disabled'].append(device)
            elif parsed[device]['status'] == 'enabled':
                inventory['device_enabled'].append(device)
            elif parsed[device]['status'] == 'ondemand':
                inventory['device_ondemand'].append(device)
    result = dict(
        changed=False,
        failed=False,
        devices=inventory
    )
    return result

def run_module():
    # define available arguments/parameters a user can pass to the module
    module_args = dict(
        device=dict(type='dict', required=False),
        auto_discovery=dict(type='dict', required=False),
        skip_invalid_keys=dict(type='bool', default=False, required=False),
        facts=dict(type='bool', default=False, required=False)
    )

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
            'name': 'device',
            'suboptions': module.params['device'],
            'cli_path': '/settings/devices',
            'func': run_option_device
        },
        {
            'name': 'auto_discovery',
            'suboptions': module.params['auto_discovery'],
            'cli_path': '/settings/auto_discovery',
            'func': run_option_auto_discovery
        },
        {
            'name': 'facts',
            'suboptions': module.params['facts'],
            'cli_path': '',
            'func': facts
        },
    ]

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
        'check_mode': module.check_mode,
    }

    for option in option_list:
        if option['suboptions'] is not None:
            func = option['func']
            res = func(option, run_opt)
            if option['name'] == 'facts':
                result['facts'] = res['devices']
                result['failed'] = False
            else:
                result['output'][option['name']] = res
            if res['failed']:
                result['failed'] = True
                module.fail_json(msg=res['msg'], **result)

    if len(result['output'].keys()) == 0 and option['name'] != 'facts':
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
