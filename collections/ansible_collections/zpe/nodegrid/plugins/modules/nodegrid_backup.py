#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2023, ZPE Systems <zpesystems.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r'''
---
module: nodegrid_backup
author: Diego Montero (@zpe-diegom)
'''

EXAMPLES = r'''
'''

RETURN = r'''
# These are examples of possible return values, and in general should use other names for return values.

'''

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.zpe.nodegrid.plugins.module_utils.nodegrid_util import nodegrid_cli, execute_cmd, check_os_version_support, result_failed, NodegridError

import os
from datetime import datetime, timezone

# We have to remove the SID from the Environmental settings, to avoid an issue
# were we can not run pexpect.run multiple times
if "DLITF_SID" in os.environ:
    del os.environ["DLITF_SID"]
if "DLITF_SID_ENCRYPT" in os.environ:
    del os.environ["DLITF_SID_ENCRYPT"]

def nodegrid_backup(option, run_opt):
    check_mode = run_opt['check_mode']
    timeout = run_opt.get('timeout', 60)
    # Generate the timestamp
    now_utc = datetime.now(timezone.utc)
    iso_basic_short = now_utc.strftime("%Y%m%dT%H%M%SZ")
    filename_split = option['backup_filename'].split('.')
    filename_extension = ".".join(filename_split[1:]) 
    backup_filename = f"{filename_split[0]}-{iso_basic_short}.{filename_extension}" if len(filename_split) > 1 else f"{filename_split[0]}-{iso_basic_short}"
    backup_file_permissions = option['backup_file_permissions']
    result = {
        'changed': False,
        'failed': False,
    }
    result['backup_filename'] = backup_filename
    cmds = [ 
        {'cmd': "save_settings"},
        {'cmd': f"set filename={backup_filename}"},
        {'cmd': "save"},
        {'cmd': "finish"},
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
        with nodegrid_cli(timeout) as cmd_cli:
            for cmd in cmds:
                cmd_result = execute_cmd(cmd_cli, cmd, timeout=timeout)
                cmd_results.append(cmd_result)
    except (NodegridError, Exception) as e:
        return result_failed(msg=f"Failed to create the backup. Results: f{e}")

    try:
        mode_octal = int(backup_file_permissions, 8)
        backup_filepath = os.path.join("/backup",backup_filename)
        os.chmod(backup_filepath, mode_octal)
    except Exception as e:
        return result_failed(f"Failed to change backup file '/backup/{backup_filename}' permissions '{backup_file_permissions}'. Error: f{e}")

    if cmd_results:
        result['cmds_output'] = cmd_results
        result['changed'] = True
    return result

def run_module():
    # define available arguments/parameters a user can pass to the module
    module_args = dict(
        backup_filename=dict(type='str', required=True),
        backup_file_permissions=dict(type='str', required=False, default='755'),
        backup_files_rotation=dict(type='int', required=False, default=5),
        skip_invalid_keys=dict(type='bool', default=False, required=False),
        timeout=dict(type=int, default=60, required=False),
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
    
    backup_msg = f"Backing up configuration for device {nodegrid_os} into file '{module.params['backup_filename']}'"

    if module.check_mode:
        result['nodegrid_os'] = nodegrid_os

    run_opt = {
        'skip_invalid_keys': module.params['skip_invalid_keys'],
        'use_config_start_global' : use_config_start_global,
        'check_mode': module.check_mode,
        'timeout': module.params['timeout']
    }

    result = nodegrid_backup(module.params, run_opt)
    result['message'] = backup_msg
    
    if result.get('failed'):
        module.fail_json(msg=result.pop('msg',''), **result)


    # in the event of a successful module execution, you will want to
    # simple AnsibleModule.exit_json(), passing the key/value results
    module.exit_json(**result)


def main():
    run_module()


if __name__ == '__main__':
    main()
