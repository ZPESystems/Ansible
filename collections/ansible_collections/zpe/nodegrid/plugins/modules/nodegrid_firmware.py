#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2023, ZPE Systems <zpesystems.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r'''
---
module: firmware_upgrade
author: Diego Montero (@zpe-diegom)
'''

EXAMPLES = r'''
'''

RETURN = r'''
# These are examples of possible return values, and in general should use other names for return values.

'''

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.facts.compat import ansible_facts
from ansible_collections.zpe.nodegrid.plugins.module_utils.nodegrid_util import get_cli, close_cli, execute_cmd, check_os_version_support, result_failed

import traceback
import os

# We have to remove the SID from the Environmental settings, to avoid an issue
# were we can not run pexpect.run multiple times
if "DLITF_SID" in os.environ:
    del os.environ["DLITF_SID"]
if "DLITF_SID_ENCRYPT" in os.environ:
    del os.environ["DLITF_SID_ENCRYPT"]

CONVERSION_FACTORS = { "B": 1, "KB":1024, "MB":1048576, "GB": 1073741824, "TB": 1099511627776, "PB": 1125899906842624, "EB":1152921504606846976 , "ZB": 1180591620717411303424, "YB": 1208925819614629174706176}
def human_read_to_byte(size):
    num_ndx = 0
    while num_ndx < len(size):
        if str.isdigit(size[num_ndx]):
            num_ndx += 1
        else:
            break
    num_part = int(size[:num_ndx])
    str_part = size[num_ndx:].strip().upper()
    return num_part * CONVERSION_FACTORS[str_part]

def firmware_upgrade(option, run_opt, mounts):
    check_mode = run_opt['check_mode']
    timeout = run_opt.get('timeout', 60)
    result = {
        'changed': False,
        'failed': False,
    }
    
    if not os.path.exists(f"/var/sw/{option.get('nodegrid_iso_filename')}"):
        result['failed'] = True
        result['msg'] = f"Nodegrid iso file does not exists: '/var/sw/{option.get('nodegrid_iso_filename')}'"
        return result

    size_available = -1
    for mount in mounts:
        if mount['mount'] == '/var':
            size_available = mount['size_available']

    if size_available == -1:
        result['failed'] = True
        result['msg'] = f"/var mount path not available. Mounts: {mounts}"
        return result

    requested_size = human_read_to_byte(option['nodegrid_available_space'])
    if size_available < requested_size:
        result['failed'] = True
        result['msg'] = f"About 5.0 GB (plus the image size) is needed in '/var' before starting the upgrade. '/var' mount path size_available={size_available}bytes < requested_size={requested_size}bytes (nodegrid_available_space: {option['nodegrid_available_space']})"
        return result

    cmds = [ 
        {'cmd': "software_upgrade"},
        {'cmd': "set image_location=local_system"},
        {'cmd': f"set filename={option.get('nodegrid_iso_filename')}"},
        {'cmd': "commit"},
    ]

    #    if run_opt['use_config_start_global']:
    #        cmds.insert(0, {'cmd': 'config_start'})
    #        cmds.append({'cmd': 'config_confirm'})

    if check_mode:
        result['changed'] = False
        result['cmds'] = cmds
        return result
    

    cmd_results = list()
    cmd_result = dict()
    try:
        cmd_cli = get_cli(timeout=timeout)
        for cmd in cmds:
            cmd_result = execute_cmd(cmd_cli, cmd)
            if cmd_result['error']:
                return result_failed(f"Failed to execute firmware upgrade. Results: f{cmd_result}")
            cmd_results.append(cmd_result)
        close_cli(cmd_cli)
    except Exception as exc:
        return result_failed(f"Failed to execute firmware upgrade. Results: f{exc}")

    if cmd_results:
        result['cmds_output'] = cmd_results
        result['changed'] = True
    return result

def run_module():
    # define available arguments/parameters a user can pass to the module
    module_args = dict(
        nodegrid_iso_filename=dict(type='str', required=True),
        nodegrid_target_version=dict(type='str', required=True),
        nodegrid_available_space=dict(type='str', required=False, default="5GB"),
        skip_invalid_keys=dict(type='bool', default=False, required=False),
        timeout=dict(type=int, default=60, required=False),
        filter=dict(type="str", required=False, default="mounts"),
    )

    # seed the result dict in the object
    # we primarily care about changed and state
    # changed is if this module effectively modified the target
    # state will include any data that you want your module to pass back
    # for consumption, for example, in a subsequent task
    result = dict(
        changed=False,
        failed=False,
    )

    # the AnsibleModule object will be our abstraction working with Ansible
    # this includes instantiation, a couple of common attr would be the
    # args/params passed to the execution, as well as if the module
    # supports check mode
    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=True
    )
    timeout = module.params.get('timeout', 60)
    #
    # Nodegrid OS section starts here
    #
    # Lets get the current interface status and check if it must be changed
    res, err_msg, nodegrid_os = check_os_version_support(timeout=module.params['timeout'])
    if res == 'error' or res == 'unsupported':
        module.fail_json(msg=err_msg, **result)
    elif res == 'warning':
        result['warning'] = err_msg
        use_config_start_global = False
    else:
        use_config_start_global = True
    
    upgrade_msg = f"Upgrading from Nodegrid version {nodegrid_os['version']} to version {module.params['nodegrid_target_version']}"

    if module.check_mode:
        result['nodegrid_os'] = nodegrid_os

    run_opt = {
        'skip_invalid_keys': module.params['skip_invalid_keys'],
        'use_config_start_global' : use_config_start_global,
        'check_mode': module.check_mode,
        'timeout': module.params['timeout']
    }

    mounts = ansible_facts(module)

    result = firmware_upgrade(module.params, run_opt, mounts['mounts'])
    result['message'] = upgrade_msg
    
    if result.get('failed'):
        module.fail_json(msg=result.pop('msg',''), **result)


    # in the event of a successful module execution, you will want to
    # simple AnsibleModule.exit_json(), passing the key/value results
    module.exit_json(**result)


def main():
    run_module()


if __name__ == '__main__':
    main()
