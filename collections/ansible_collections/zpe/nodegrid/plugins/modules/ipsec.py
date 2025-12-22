#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2023, ZPE Systems <zpesystems.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r'''
module: ipsec
author: Diego Montero (@zpe-diegom)
short_description: This module handles network->ipsec details on Nodegrid OS
version_added: "1.0.0"
description: The module is used to manage the Network IPSEC options on Nodegrid OS 5.6 or newer
options:
    skip_invalid_keys:
        description: Skip invalid settings keys if they don't exist in the Nodegrid model/OS version
        required: False
        default: False
        type: bool
    settings:
        description:
        required: False
        type: dict
        suboptions:
'''

EXAMPLES = r'''

'''

RETURN = r'''

'''

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.zpe.nodegrid.plugins.module_utils.nodegrid_util import run_option, check_os_version_support, run_option_adding_field_in_the_path, field_exist, export_settings

import os
from collections import OrderedDict
import traceback

# We have to remove the SID from the Environmental settings, to avoid an issue
# were we can not run pexpect.run multiple times
if "DLITF_SID" in os.environ:
    del os.environ["DLITF_SID"]
if "DLITF_SID_ENCRYPT" in os.environ:
    del os.environ["DLITF_SID_ENCRYPT"]

def run_option_ipsec_global(option, run_opt):
    suboptions = option['suboptions']
    return run_option(option, run_opt)

def run_option_ipsec_ike_profile(option, run_opt):
    # Settings to be deleted/discarded if empty
    settings_to_delete_if_empty = [
        'mtu',
        'custom_parameters',
    ]
    # Settings dependencies
    dependencies = OrderedDict()
    dependencies = {
        'ike_version': 
        {
            'ikev1': 
            [
                'phase_1_mode',
                'phase_1_encryption',
                'phase_1_authentication',
                'phase_1_diffie-hellman_group',
                'phase_1_lifetime',
            ],
            'ikev2': 
            [
                'phase_1_encryption',
                'phase_1_authentication',
                'phase_1_diffie-hellman_group',
                'phase_1_lifetime',
            ],
        },
        'phase_2_authentication_protocol':
        {
            'esp':
            [
                'phase_2_encryption',
                'phase_2_authentication',
                'phase_2_pfs_group',
                'phase_2_lifetime',
            ],
            'ah':
            [
                'phase_2_authentication',
                'phase_2_pfs_group',
                'phase_2_lifetime',
            ]
        },
        'enable_dead_peer_detection':
        [
            'dead_peer_detection_number_of_retries',
            'dead_peer_detection_interval',
            'dead_peer_detection_action',
        ]
    }
    suboptions = option['suboptions']
    check_mode = run_opt['check_mode']
    field_name = 'profile_name'
    if field_exist(suboptions, field_name):
        cli_path =  f"{option['cli_path']}/{suboptions[field_name]}"
        # Remove invalid parameters
        #
        try:

            # Identifies and collects configuration settings that should be deleted
            # based on a mismatch between current suboptions and their declared dependencies.
            settings_tobe_deleted = set()
            for dependency in dependencies:

                # If the dependency is a dictionary, iterate over suboption values that do NOT match the current value in suboptions.
                # For those mismatched values, collect associated settings for deletion,
                # but only if they aren’t already valid under the current suboption value.
                if isinstance(dependencies[dependency], dict):
                    for dep_rem in {key:value for key, value in dependencies[dependency].items() if dependency in suboptions and key not in [suboptions[dependency]]}:
                        for setting in dependencies[dependency][dep_rem]:
                            if (suboptions[dependency] not in dependencies[dependency]) or (setting not in dependencies[dependency][suboptions[dependency]]):
                                settings_tobe_deleted.add(setting)

                # Elif the dependency is a list and the suboption is explicitly set to "no",
                # mark all associated settings for deletion.
                elif isinstance(dependencies[dependency], list) and dependency in suboptions and str(suboptions[dependency]).strip().lower() == "no":
                    for setting in dependencies[dependency]:
                        settings_tobe_deleted.add(setting)

            # Delete settings not required
            for setting in settings_tobe_deleted:
                suboptions.pop(setting, None)
            
            # Delete settings that are empty
            for setting in settings_to_delete_if_empty:
                if setting in suboptions and str(suboptions[setting]).strip() == "":
                    suboptions.pop(setting, None)

        except Exception as e:
            return {'failed': True, 'changed': False, 'msg': f"{suboptions} | Key/value error: {e} | {traceback.format_exc()}"}

        return run_option_adding_field_in_the_path(option, run_opt, field_name)
    else:
        return {'failed': True, 'changed': False, 'msg': f"Field '{field_name}' is required"}

'initiate_tunnel',
'ike_profile',
'authentication_method',
'secret',
'left_public_key',
'right_public_key',
'authentication_method',
'left_certificate',
'right_certificate',
'left_id',
'left_address',
'right_id',
'right_address',
'enable_monitoring',
'monitoring_source_ip_address',
'monitoring_destination_ip_address',
'monitoring_number_of_retries',
'monitoring_interval',
'monitoring_action',
'monitoring_failover_ipsec_tunnel',


def run_option_ipsec_tunnel(option, run_opt):
    # Settings to be deleted/discarded if empty
    settings_to_delete_if_empty = [
        'custom_up_down_script',
        'left_source_ip_address',
        'left_subnet',
        'right_source_ip_address',
        'right_subnet',
    ]

    # Settings dependencies
    dependencies = OrderedDict()
    dependencies = {
        'authentication_method':  # pre-shared_key, rsa_key, certificate
        ("validate", {
            'pre-shared_key': ['secred'],
            'rsa_key': ['left_public_key', 'right_public_key'],
            'certificate': ['left_certificate', 'right_certificate']
        }),
        'left_address':
        ("validate", {
            'ip_address': ['left_ip_address'],
        }),
        'enable_monitoring': 
        [
            'monitoring_source_ip_address',
            'monitoring_destination_ip_address',
            'monitoring_number_of_retries',
            'monitoring_interval',
            'monitoring_action',
        ],
        'monitoring_action':
        ("validate", {
            'restart_ipsec': [], 
            'restart_tunnel': [],
            'failover': ['monitoring_failover_ipsec_tunnel'],
        }),
    }
    
    # Settings to be renamed
    rename_settings = {
        'custom_up_down_script': 'custom_up|down_script',
    }

    suboptions = option['suboptions']
    check_mode = run_opt['check_mode']
    field_name = 'name'
    if field_exist(suboptions, field_name) and suboptions[field_name]:
        cli_path =  f"{option['cli_path']}/{suboptions[field_name]}"
        #
        # Remove invalid parameters
        #
        try:

            # Identifies and collects configuration settings that should be deleted
            # based on a mismatch between current suboptions and their declared dependencies.
            settings_tobe_deleted = set()
            for dependency in dependencies:

                # If the dependency is a dictionary, iterate over suboption values that do NOT match the current value in suboptions.
                # For those mismatched values, collect associated settings for deletion,
                # but only if they aren’t already valid under the current suboption value.
                if isinstance(dependencies[dependency], dict):
                    for dep_rem in {key:value for key, value in dependencies[dependency].items() if dependency in suboptions and key not in [suboptions[dependency]]}:
                        for setting in dependencies[dependency][dep_rem]:
                            if (suboptions[dependency] not in dependencies[dependency]) or (setting not in dependencies[dependency][suboptions[dependency]]):
                                settings_tobe_deleted.add(setting)

                # Elif the dependency is a list and the suboption is explicitly set to "no",
                # mark all associated settings for deletion.
                elif isinstance(dependencies[dependency], list) and dependency in suboptions and str(suboptions[dependency]).strip().lower() == "no":
                    for setting in dependencies[dependency]:
                        settings_tobe_deleted.add(setting)

                # Elseif check dependencies that are selectable, and for each selected option, there are dependencies attached.
                elif isinstance(dependencies[dependency], tuple):
                    if not dependency in suboptions:
                        continue
                    atuple = dependencies[dependency]
                    items_to_validate = {}
                    if atuple[0] == "validate" and suboptions[dependency] in atuple[1]:
                        if dependency in suboptions:
                            valid_options = atuple[1][suboptions[dependency]]
                            items_to_validate = {option:values for option,values in atuple[1].items() if not option == suboptions[dependency]}
                        else:
                            valid_options = []
                            items_to_validate = {option:values for option,values in atuple[1].items()}
                    else:
                        valid_options = []
                        items_to_validate = {option:values for option,values in atuple[1].items()}

                    for key,value in items_to_validate.items():
                        for v in value:
                            if not v in valid_options:
                                settings_tobe_deleted.add(v)

            # Delete settings not required
            for setting in settings_tobe_deleted:
                suboptions.pop(setting, None)

            # Delete settings that are empty
            for setting in settings_to_delete_if_empty:
                if setting in suboptions and str(suboptions[setting]).strip() == "":
                    suboptions.pop(setting, None)

            # Remove old setting key name, and add its corresponding
            for setting in rename_settings:
                if setting in suboptions:
                    tmp_key = rename_settings[setting]
                    tmp_value = suboptions[setting]
                    suboptions.pop(setting, None)
                    suboptions[tmp_key] = tmp_value

        except Exception as e:
            return {'failed': True, 'changed': False, 'msg': f"{suboptions} | Key/value error: {e} | {traceback.format_exc()}"}

        return run_option_adding_field_in_the_path(option, run_opt, field_name)
    else:
        return {'failed': True, 'changed': False, 'msg': f"Field '{field_name}' is required"}


def run_module():
    # define available arguments/parameters a user can pass to the module
    module_args = dict(
        ipsec_global=dict(type='dict', required=False),
        ipsec_ike_profile=dict(type='dict', required=False),
        ipsec_tunnel=dict(type='dict', required=False),
        skip_invalid_keys=dict(type='bool', default=False, required=False),
        timeout=dict(type='int', default=60, required=False),
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
            'name': 'ipsec_global',
            'suboptions': module.params['ipsec_global'],
            'cli_path': '/settings/ipsec/global',
            'func': run_option_ipsec_global
        },
        {
            'name': 'ipsec_ike_profile',
            'suboptions': module.params['ipsec_ike_profile'],
            'cli_path': '/settings/ipsec/ike_profile',
            'func': run_option_ipsec_ike_profile
        },
        {
            'name': 'ipsec_tunnel',
            'suboptions': module.params['ipsec_tunnel'],
            'cli_path': '/settings/ipsec/tunnel',
            'func': run_option_ipsec_tunnel
        },
    ]

    # add name in the cli_path
    

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
    result['nodegrid_facts'] = nodegrid_os
    
    #
    # Lets run the options
    #
    run_opt = {
        'skip_invalid_keys': module.params['skip_invalid_keys'],
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

    if result and len(result['output'].keys()) == 0:
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
