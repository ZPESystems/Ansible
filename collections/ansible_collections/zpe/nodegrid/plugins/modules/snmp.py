#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2023, ZPE Systems <zpesystems.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r'''
---
module: network_snmp
author: Rene Neumann (@zpe-rneumann)
'''

EXAMPLES = r'''
'''

RETURN = r'''

'''

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.zpe.nodegrid.plugins.module_utils.nodegrid_util import check_os_version_support, dict_diff, NodegridError, run_cli_command, run_cli_commands, run_option, result_failed, nodegrid_cli_validate_inputs, cli_settings_reorder
import os, copy
from collections import OrderedDict

# We have to remove the SID from the Environmental settings, to avoid an issue
# were we can not run pexpect.run multiple times
if 'DLITF_SID' in os.environ:
    del os.environ['DLITF_SID']
if 'DLITF_SID_ENCRYPT' in os.environ:
    del os.environ['DLITF_SID_ENCRYPT']


# Managed Device Management dependencies
snmp_rule_dependencies= OrderedDict({
    'version': OrderedDict({
        'version_v1|v2': ['access_type', 'oid', 'source', 'community', 'snmp_for_ipv6'],
        'version_3': ['access_type', 'oid', 'security_level', 'authentication_algorithm', 'privacy_algorithm', 'username', 'authentication_password', 'privacy_password']
        }),
    'access_type': ('validate', ['read_only', 'read_and_write']),
    'security_level': ('validate', ['authnopriv', 'noauthnopriv', 'authpriv']),
    'authentication_algorithm': ('validate', ['md5', 'sha', 'sha-224', 'sha-256', 'sha-384', 'sha-512']),
    'privacy_algorithm': ('validate', ['aes', 'aes-192', 'aes-256', 'des']),
    })

def run_option_snmp_rule(option,run_opt):
    suboptions = option['suboptions']
    
    if not 'version' in suboptions:
        return result_failed(f"Field 'version' is required. Supported version values: {', '.join(snmp_rule_dependencies['version'].keys())}")

    # Clean the required options
    try:
        option['suboptions'] = nodegrid_cli_validate_inputs(suboptions, snmp_rule_dependencies)
        option['suboptions'] = cli_settings_reorder(suboptions, snmp_rule_dependencies, initial_order=OrderedDict())
    except Exception as e:
        return {'failed': True, 'changed': False, 'msg': f"Error validating/ordering input values. Error: {e}"}

    if suboptions['version'] == "version_v1|v2":
        if not 'community' in option['suboptions'] or len(option['suboptions']['community'].strip()) == 0:
            return result_failed("Field 'community' is required")
        source = option['suboptions']['source'] if 'source' in option['suboptions'] and len(option['suboptions']['source'].strip())>0 else 'default'
        option['cli_path'] += f"/{option['suboptions']['community']}_{source}"
    elif suboptions['version'] == "version_3":
        if not 'username' in option['suboptions'] or len(option['suboptions']['username'].strip()) == 0:
            return result_failed("Field 'username' is required")
        option['cli_path'] += f"/{option['suboptions']['username']}"

    return run_option(option, run_opt)


def run_option_snmp_system(option,run_opt):
    return run_option(option, run_opt)


def run_module():
    # define available arguments/parameters a user can pass to the module
    module_args = dict(
        system=dict(type='dict', required=False),
        rule=dict(type='dict', required=False),
        skip_invalid_keys=dict(type='bool', default=False, required=False),
        timeout=dict(type='int', default=60, required=False),
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
        output=dict(),
        message=''
    )

    # the AnsibleModule object will be our abstraction working with Ansible
    # this includes instantiation, a couple of common attr would be the
    # args/params passed to the execution, as well as if the module
    # supports check mode
    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=True
    )
    
    # Nodegrid CLI pexpect timeout
    timeout = module.params['timeout']
    
    # List of options to run
    option_list = [
        {
            'name': 'rule',
            'suboptions': module.params['rule'],
            'cli_path': '/settings/snmp/v1_v2_v3',
            'func': run_option_snmp_rule
        },
        {
            'name': 'system',
            'suboptions': module.params['system'],
            'cli_path': '/settings/snmp/system',
            'func': run_option_snmp_system
        },
    ]

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

    if module.params['debug']:
        result['nodegrid_os'] = nodegrid_os
    
    # Lets run the options
    #
    run_opt = {
        'skip_invalid_keys': module.params['skip_invalid_keys'],
        'use_config_start_global' : use_config_start_global,
        'check_mode': module.check_mode,
        'timeout': module.params['timeout'],
        'debug': module.params['debug'],
        'max_retries': module.params.get('max_retries', 2),
        'base_delay': module.params.get('base_delay', 2.0), 
        'max_delay': module.params.get('max_delay',10.0),
    }

    for option in option_list:
        if option['suboptions'] is not None:
            func = option['func']
            res = func(option, run_opt)
            if res['failed']:
                result.pop('output', None)
                result['failed'] = True
                module.fail_json(msg=res['msg'], **result)
            if option['name'] == 'facts':
                result['facts'] = res['devices']
                result['failed'] = False
            else:
                result['output'][option['name']] = res

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
            result['message'] = 'Import was successful'
            break

    # in the event of a successful module execution, you will want to
    # simple AnsibleModule.exit_json(), passing the key/value results
    module.exit_json(**result)


def main():
    run_module()


if __name__ == '__main__':
    main()
