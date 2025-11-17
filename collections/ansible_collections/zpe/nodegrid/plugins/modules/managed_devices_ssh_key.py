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
from ansible_collections.zpe.nodegrid.plugins.module_utils.nodegrid_util import check_os_version_support, run_option, format_settings, field_exist, result_failed, to_list, get_shell, get_cli, close_cli, execute_cmd, read_table, read_table_row, read_path_option


import os, json, pexpect, re
from collections import OrderedDict
import traceback
# Settings dependencies



# We have to remove the SID from the Environmental settings, to avoid an issue
# were we can not run pexpect.run multiple times
if "DLITF_SID" in os.environ:
    del os.environ["DLITF_SID"]
if "DLITF_SID_ENCRYPT" in os.environ:
    del os.environ["DLITF_SID_ENCRYPT"]

def run_option_device(option, run_opt):
    suboptions = option['suboptions']
    cli_path = option['cli_path']
    check_mode = run_opt['check_mode']
    settings_list = []
    cmds = None
    cmd_results = None
    change_name_message = None

    if not (field_exist(suboptions, 'name')):
        return result_failed("Field device 'name' is required")
    if not (field_exist(suboptions, 'ssh_key_type')):
        return result_failed("Field 'ssh_key_type' is required. Valid options are: ecdsa_256, ecdsa_384, ecdsa_521, ed25519, rsa_1024, rsa_2048, rsa_4096.")
    if not (field_exist(suboptions, 'ssh_private_key')):
        return result_failed("Field 'ssh_private_key' is required")
    if not (field_exist(suboptions, 'ssh_public_key')):
        return result_failed("Field 'ssh_public_key' is required")
        
    device_name = suboptions['name']
    ssh_key_type = suboptions['ssh_key_type']
    ssh_private_key = suboptions['ssh_private_key']
    ssh_public_key = suboptions['ssh_public_key']

    # Check if allow_pre-shared_ssh_key is enabled
    cmd_result = read_path_option(f"/settings/devices/{device_name}/access", "allow_pre-shared_ssh_key")
    if cmd_result[0] == "error":
        return result_failed(f"Failed to get device '{device_name}' 'allow_pre-shared_ssh_key' option. Error: {cmd_result[1]}")

    if cmd_result[1]["value"] == "no":
        return result_failed(f"Device '{device_name}' setting 'allow_pre-shared_ssh_key' is set to '{cmd_result[1]['value']}'. It is required to be enabled ('yes' option)")

    cmds = [{'confirm': True,'cmd': f"cd /settings/devices/{device_name}/access; ssh_keys; set ssh_key_type={ssh_key_type}; generate_key_pair; return;"}]
    cmd_results = list()
    cmd_result = dict()
    if not check_mode:
        try:
            cmd_cli = get_cli(timeout=60)
            for cmd in cmds:
                cmd_result = execute_cmd(cmd_cli, cmd)
                if cmd_result['error']:
                    return result_failed(f"Failed ssh generate_key_pair for device '{device_name}'. Results: f{cmd_result}")
                cmd_results.append(cmd_result)
            close_cli(cmd_cli)
        except Exception as exc:
            return result_failed(f"Failed ssh generate_key_pair for device '{device_name}', ssh_key_type: {ssh_key_type}. Results: f{cmd_result}")

    option['cli_path'] = cli_path
    option['settings'] = settings_list
    result = run_option(option, run_opt)

    if check_mode:
        if cmds:
            result['cmds'] = cmds
        return result

    # If device named was changed, update the return result
    if cmd_results:
        result['cmds_output'] = cmd_results
        result['changed'] = True
        result['message'] = f"Manage device '{device_name}' ssh key type '{ssh_key_type}' generated successfully."
    return result

def run_module():
    # define available arguments/parameters a user can pass to the module
    module_args = dict(
        device=dict(type='dict', required=False),
        skip_invalid_keys=dict(type='bool', default=False, required=False),
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

    if len(result['output'].keys()) == 0:
        module.fail_json(msg='No inputs', **result)

    # if the user is working with this module in only check mode we do not
    # want to make any changes to the environment, just return the current
    # state with no modifications
    if module.check_mode:
        result['changed'] = False
        result['message'] = "No changes where performed, running in check_mode"
        module.exit_json(**result)

    # manipulate or modify the state as needed (this is going to be the
    # part where your module will do what it needs to do)
    result['message'] = 'No change required'
    for key in result['output'].keys():
        item = result['output'][key]
        if item['changed']:
            result['changed'] = True
            #result['message'] = 'Import was successful'
            break

    # in the event of a successful module execution, you will want to
    # simple AnsibleModule.exit_json(), passing the key/value results
    module.exit_json(**result)


def main():
    run_module()


if __name__ == '__main__':
    main()
