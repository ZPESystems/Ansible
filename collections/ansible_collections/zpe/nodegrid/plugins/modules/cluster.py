#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2023, ZPE Systems <zpesystems.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r'''
module: cluster
author: Rene Neumann (@zpe-rneumann)
short_description: This module handles cluster setup details on Nodegrid OS
version_added: "1.0.0"
'''

EXAMPLES = r'''

'''

RETURN = r'''

'''

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.zpe.nodegrid.plugins.module_utils.nodegrid_util import run_option, check_os_version_support, run_option_adding_field_in_the_path

import os

# We have to remove the SID from the Environmental settings, to avoid an issue
# were we can not run pexpect.run multiple times
if "DLITF_SID" in os.environ:
    del os.environ["DLITF_SID"]
if "DLITF_SID_ENCRYPT" in os.environ:
    del os.environ["DLITF_SID_ENCRYPT"]

def run_option_network_connections(option, run_opt):
    return run_option_adding_field_in_the_path(option, run_opt, 'name')

def run_module():
    # define available arguments/parameters a user can pass to the module
    module_args = dict(
        settings=dict(type='dict', required=False),
        peers=dict(type='dict', required=False),
        clusters=dict(type='dict', required=False),
        enrollment_range=dict(type='dict', required=False),
        management=dict(type='dict', required=False),
        skip_invalid_keys=dict(type='bool', default=False, required=False)
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
            'name': 'settings',
            'suboptions': module.params['settings'],
            'cli_path': '/settings/cluster/settings',
            'func': run_option
        },
        # {
        #     'name': 'peers',
        #     'suboptions': module.params['peers'],
        #     'cli_path': '/settings/cluster/cluster_peers',
        #     'func': run_option_network_connections
        # },
        {
            'name': 'clusters',
            'suboptions': module.params['clusters'],
            'cli_path': '/settings/cluster/cluster_clusters',
            'func': run_option_network_connections
        },
        {
            'name': 'enrollment_range',
            'suboptions': module.params['enrollment_range'],
            'cli_path': '/settings/cluster/cluster_enrollment_range',
            'func': run_option_network_connections
        },
        {
            'name': 'management',
            'suboptions': module.params['management'],
            'cli_path': '/settings/cluster/cluster_management',
            'func': run_option_network_connections
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
