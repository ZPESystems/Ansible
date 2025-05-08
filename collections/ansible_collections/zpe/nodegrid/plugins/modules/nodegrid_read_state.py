#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2023, ZPE Systems <zpesystems.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r'''
---
module: connection_facts
author: Rene Neumann (@zpe-rneumann)
'''

EXAMPLES = r'''
'''

RETURN = r'''
# These are examples of possible return values, and in general should use other names for return values.

'''

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.zpe.nodegrid.plugins.module_utils.nodegrid_util import get_cli, close_cli, execute_cmd, check_os_version_support, read_table, read_table_row, result_failed, read_path_option

import traceback
import pexpect
import os
import re

# We have to remove the SID from the Environmental settings, to avoid an issue
# were we can not run pexpect.run multiple times
if "DLITF_SID" in os.environ:
    del os.environ["DLITF_SID"]
if "DLITF_SID_ENCRYPT" in os.environ:
    del os.environ["DLITF_SID_ENCRYPT"]

def run_option_read_options(option, run_opt):
    suboptions = option['suboptions']
    if not 'path' in suboptions.keys():
        return result_failed(f"The 'path' to read the options must be defined")
    if not 'options' in suboptions.keys():
        return result_failed(f"The 'options' to be read must be defined (list or option)")

    if type(suboptions['options']) == str:
        options = [suboptions['options']]
    elif type(suboptions['options'] == list):
        options = suboptions['options']
    else:
        return result_failed(f"The 'options' must be a string or a list of strings")
    
    result = dict(
        changed=False,
        failed=False,
        message=''
    )

    result['results'] = []
    for option in options:
        try:
            read_option = read_path_option(suboptions['path'], option)
        except Exception as e:
            return result_failed(f"Failed to get option 'method' from path '{suboptions['path']}'. Error: {e}")
        if read_option[0].lower() == 'error':
            return result_failed(f"Failed to get option '{option}' from path '{suboptions['path']}'. Error: {read_option[1]}")
        result['results'].append(read_option[1])
    return result

def run_option_read_table(option, run_opt):
    suboptions = option['suboptions']
    if not 'path' in suboptions.keys():
        return result_failed(f"The 'path' to read the table must be defined")
    
    result = dict(
        changed=False,
        failed=False,
        message='',
    )
    try:
        table = read_table(suboptions['path'])
        if table[0].lower() == 'error':
            return result_failed(f"Failed to read the table on cli: 'show {suboptions['path']}'. Error: {table[1]}")
        result['table'] = table[1]
    except Exception:
        result['failed'] = True
        result['message'] = traceback.format_exc()
    
    if result['failed']:
        module.fail_json(msg=result['message'], **result)

    return result


def run_module():
    # define available arguments/parameters a user can pass to the module
    module_args = dict(
        read_options = dict(type='dict', required=False),
        read_table = dict(type='dict', required=False),
        timeout=dict(type=int, default=60)
    )

#    # define available arguments/parameters a user can pass to the module
#    module_args = dict(
#        path=dict(type=str, required=True),
#        timeout=dict(type=int, default=60)
#    )

    # seed the result dict in the object
    # we primarily care about changed and state
    # changed is if this module effectively modified the target
    # state will include any data that you want your module to pass back
    # for consumption, for example, in a subsequent task
    result = dict(
        changed=False,
        failed=False,
        message='',
        output = {}
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
            'name': 'read_options',
            'suboptions': module.params['read_options'],
            'func': run_option_read_options
        },
        {
            'name': 'read_table',
            'suboptions': module.params['read_table'],
            'func': run_option_read_table
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
        'use_config_start_global' : use_config_start_global,
        'check_mode': module.check_mode,
        'timeout': module.params['timeout']
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
            break

    # in the event of a successful module execution, you will want to
    # simple AnsibleModule.exit_json(), passing the key/value results
    module.exit_json(**result)


def main():
    run_module()

if __name__ == '__main__':
    main()
