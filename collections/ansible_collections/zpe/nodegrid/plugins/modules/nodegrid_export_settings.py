#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2023, ZPE Systems <zpesystems.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r'''
---
module: nodegrid_export_settings
author: Diego Montero (@zpe-diegom)
'''

EXAMPLES = r'''
'''

RETURN = r'''
# These are examples of possible return values, and in general should use other names for return values.

'''

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.zpe.nodegrid.plugins.module_utils.nodegrid_util import export_settings, check_os_version_support, result_failed, NodegridError, run_cli_command

import os
from datetime import datetime, timezone

# We have to remove the SID from the Environmental settings, to avoid an issue
# were we can not run pexpect.run multiple times
if "DLITF_SID" in os.environ:
    del os.environ["DLITF_SID"]
if "DLITF_SID_ENCRYPT" in os.environ:
    del os.environ["DLITF_SID_ENCRYPT"]

def nodegrid_export_settings(option, run_opt):
    check_mode = run_opt['check_mode']
    timeout = run_opt.get('timeout', 60)
    export_settings_file_extension = option.get('export_settings_file_extension', '.cli')
    # Generate the timestamp
    now_utc = datetime.now(timezone.utc)
    iso_basic_short = now_utc.strftime("%Y%m%dT%H%M%SZ")
    export_settings_filename = f"{option['export_settings_filename'].removesuffix(export_settings_file_extension)}-{iso_basic_short}{export_settings_file_extension}" 
    export_settings_file_permissions = option['export_settings_file_permissions']
    result = dict(
        changed=False,
        failed=False,
        export_settings_filename='',
    )
    result['export_settings_filename'] = export_settings_filename

    options = [ "--{0}".format(cmd_option.replace('_','-')) for cmd_option in ['include_empty', 'no_default', 'not_enabled', 'plain_password', 'with_options'] if option[cmd_option]]

    cmd = {'cmd': f"export_settings /settings --file /tmp/{export_settings_filename} {' '.join(options)}"}

    if check_mode:
        result['changed'] = False
        result['cmd'] = cmd
        return result
    
    cmd_result = run_cli_command(cmd, timeout=timeout)
    if cmd_result['error']:
        return result_failed(msg=f"Failed to export settings. Results: {cmd_result['msg']}")

    try:
        mode_octal = int(export_settings_file_permissions, 8)
        export_settings_filepath = os.path.join("/tmp",export_settings_filename)
        os.chmod(export_settings_filepath, mode_octal)
    except Exception as e:
        return result_failed(f"Failed to change export settings file '{export_settings_filename}' permissions to '{export_settings_file_permissions}'. Error: {e}")

    if cmd_result:
        result['cmds_output'] = cmd_result
        result['changed'] = True
    return result

def run_module():
    # define available arguments/parameters a user can pass to the module
    module_args = dict(
        export_settings_filename=dict(type='str', required=True),
        export_settings_file_permissions=dict(type='str', required=False, default='755'),
        include_empty=dict(type='bool', default=False, required=False),
        no_default=dict(type='bool', default=False, required=False),
        not_enabled=dict(type='bool', default=False, required=False),
        plain_password=dict(type='bool', default=False, required=False),
        with_options=dict(type='bool', default=False, required=False),
        skip_invalid_keys=dict(type='bool', default=False, required=False),
        timeout=dict(type='int', default=120, required=False),
        debug=dict(type='bool', default=False, required=False),
        max_retries=dict(type='int', default=3, required=False),
        base_delay=dict(type='float', default=2.0, required=False),
        max_delay=dict(type='float', default=10.0, required=False),
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
    
    export_settings_msg = f"Exporting the settings for device {nodegrid_os} into file '{module.params['export_settings_filename']}'"

    if module.params.get('debug'):
        result['nodegrid_os'] = nodegrid_os

    run_opt = {
        'skip_invalid_keys': module.params['skip_invalid_keys'],
        'use_config_start_global' : use_config_start_global,
        'check_mode': module.check_mode,
        'debug': module.params.get('debug', False),
        'timeout': module.params.get('timeout', 60),
        'max_retries': module.params.get('max_retries', 2),
        'base_delay': module.params.get('base_delay', 2.0), 
        'max_delay': module.params.get('max_delay',10.0),
    }

    result = nodegrid_export_settings(module.params, run_opt)
    result['message'] = export_settings_msg
    
    if result.get('failed'):
        module.fail_json(msg=result.pop('msg',''), **result)


    # in the event of a successful module execution, you will want to
    # simple AnsibleModule.exit_json(), passing the key/value results
    module.exit_json(**result)


def main():
    run_module()


if __name__ == '__main__':
    main()
