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
from ansible_collections.zpe.nodegrid.plugins.module_utils.nodegrid_util import run_option, check_os_version_support, run_option_adding_field_in_the_path, execute_cmd, get_cli, close_cli

import os
from collections import OrderedDict
import traceback

# We have to remove the SID from the Environmental settings, to avoid an issue
# were we can not run pexpect.run multiple times
if "DLITF_SID" in os.environ:
    del os.environ["DLITF_SID"]
if "DLITF_SID_ENCRYPT" in os.environ:
    del os.environ["DLITF_SID_ENCRYPT"]

def run_option_cluster_settings(option, run_opt, timeout=60):
    suboptions = option['suboptions']

    # Settings dependencies
    dependencies = OrderedDict()
    dependencies = {
        'enable_cluster': ['cluster_name', 'type', 'enable_clustering_access'],
        'type': 
        {
            'coordinator': 
            [
                'allow_enrollment',
                'psk',
                'cluster_mode',
                'polling_rate'
            ],
            'peer': 
            [
                'coordinator_address',
                'psk'
            ],
        },
    }

    try:
        settings_tobe_deleted = set()
        for dependency in dependencies:
            if isinstance(dependencies[dependency], dict):
                for dep_rem in {key:value for key, value in dependencies[dependency].items() if dependency in suboptions and key not in [suboptions[dependency]]}:
                    for setting in dependencies[dependency][dep_rem]:
                        if (suboptions[dependency] not in dependencies[dependency]) or (setting not in dependencies[dependency][suboptions[dependency]]):
                            settings_tobe_deleted.add(setting)

            elif isinstance(dependencies[dependency], list) and dependency in suboptions and suboptions[dependency].lower() == "no":
                for setting in dependencies[dependency]:
                    settings_tobe_deleted.add(setting)

        # Delete settings not required
        for setting in settings_tobe_deleted:
            suboptions.pop(setting, None)

    except Exception as e:
        return {'failed': True, 'changed': False, 'msg': f"{suboptions} | Key/value error: {e} | {traceback.format_exc()}"}

    if suboptions['type'] == 'peer':
        cmd_cli_show = get_cli(timeout=timeout)
        #build cmd
        cmd = {
            'cmd' : "show /settings/cluster/cluster_peers/",
            'ignore_error': True
        }
        cmd_result = execute_cmd(cmd_cli_show, cmd)
        close_cli(cmd_cli_show)
        cluster_peers = cmd_result['json'][0]['data']
    
        result = dict(
            changed=False,
            failed=False,
            message='',
            msg=''
        )
        for cluster in cluster_peers:
            if "type" in cluster and cluster["type"].lower() == 'coordinator':
                if cluster['status'].lower() != "online" or cluster['address'] != suboptions['coordinator_address']:
                    # Build out commands to disable cluster and reconfigure
                    cmds = [dict(cmd="cd /settings/cluster/settings"), dict(cmd="edit"), dict(cmd="set enable_cluster=no"), dict(cmd="commit")]
                    if not run_opt['check_mode']:
                        try:
                            cmd_results = []
                            cmd_cli = get_cli(timeout=timeout)
                            for cmd in cmds:
                                cmd_result = execute_cmd(cmd_cli, cmd)
                                if 'ignore_error' in cmd.keys():
                                    cmd_result['ignore_error'] = cmd['ignore_error']
                                cmd_result['command'] = cmd.get('cmd')
                                cmd_results.append(cmd_result)
                                if cmd_result['error']:
                                    result['failed'] = True
                                    result['message'] = cmd_result['stdout'].split('\r\n\r\n')[1]
                                    cmds.append(dict(cmd='cancel', ignore_error=True))
                                    cmds.append(dict(cmd='revert', ignore_error=True))
                                    cmds.append(dict(cmd='config_revert', ignore_error=True))
                                    cmd_result = execute_cmd(cmd_cli, dict(cmd='cancel'))
                                    cmd_results.append(cmd_result)
                                    cmd_result = execute_cmd(cmd_cli, dict(cmd='revert'))
                                    cmd_results.append(cmd_result)
                                    cmd_result = execute_cmd(cmd_cli, dict(cmd='config_revert'))
                                    cmd_results.append(cmd_result)
                                    break;
                                result['changed'] = True
                            if run_opt['debug']:
                                result['cmds_output'] = cmd_results
                        except Exception as exc:
                            result['failed'] = True
                            result['message'] = str(exc)
                        finally:
                            close_cli(cmd_cli)
                    result = run_option(option, run_opt)
                    if run_opt['check_mode']:
                        result['cmds'] = cmds
                    return result
                else:
                    result['message'] = cluster
                    return result
    return run_option(option, run_opt)

def run_option_network_connections(option, run_opt):
    return run_option_adding_field_in_the_path(option, run_opt, 'name')

def run_option_cluster_clusters(option, run_opt, timeout=30):
    #option = {
    #    'name': 'clusters',
    #    'suboptions': module.params['clusters'],
    #    'cli_path': '/settings/cluster/cluster_clusters',
    #    'func': run_option_cluster_clusters
    #}
    #run_opt = {
    #    'skip_invalid_keys': module.params['skip_invalid_keys'],
    #    'use_config_start_global' : use_config_start_global,
    #    'check_mode': module.check_mode,
    #    'debug': module.params.get('debug', False)
    #}
    
    options = option['suboptions']
    cmd_cli_show = get_cli(timeout=timeout)
    #build cmd
    cmd = {
        'cmd' : "show /settings/cluster/cluster_clusters/",
        'ignore_error': True
    }
    cmd_result = execute_cmd(cmd_cli_show, cmd)
    close_cli(cmd_cli_show)
    clusters = cmd_result['json'][0]['data']

    result = dict(
        changed=False,
        failed=False,
        message='',
        msg=''
    )
    # Build out commands
    cmds = []

    cluster_found = False
    for cluster in clusters:
        if "cluster name" in cluster and cluster["cluster name"] == options['remote_cluster_name']:
            cluster_found = True
            if cluster['status'].lower() != "online":
                cluster_found = False
                cmds.append(dict(cmd=f"disjoin {options['remote_cluster_name']}"))

    if not cluster_found:
        cmds.append(dict(cmd="join"))
        cmds.append(dict(cmd=f"set remote_cluster_name={options['remote_cluster_name']}"))
        cmds.append(dict(cmd=f"set coordinator_address={options['coordinator_address']}"))
        cmds.append(dict(cmd=f"set psk={options['psk']}"))

    if run_opt['check_mode']:
        # Display Changes
        result['changed'] = False
        result['message'] = "No changes where performed, running in check_mode"
        result['cmds'] = cmds
        return result
    
    if run_opt['debug']:
        result['cmds'] = cmds
    
    # Apply Changes
    if len(cmds) == 0:
        result['changed'] = False
        return result
    else:
        cmds.insert(0, {'cmd': f"cd /settings/cluster/cluster_clusters/"})
        cmds.insert(0, {'cmd': f"config_start"})
        cmds.append({'cmd': f"commit"})
        cmds.append({'cmd': f"config_confirm"})
    try:
        cmd_results = []
        cmd_cli = get_cli(timeout=timeout)
        for cmd in cmds:
            cmd_result = execute_cmd(cmd_cli, cmd)
            if 'template' in cmd.keys():
                cmd_result['template'] = cmd['template']
            if 'set_fact' in cmd.keys():
                cmd_result['set_fact'] = cmd['set_fact']
            if 'ignore_error' in cmd.keys():
                cmd_result['ignore_error'] = cmd['ignore_error']
            if 'json' in cmd.keys():
                cmd_result['json'] = cmd['json']
            cmd_result['command'] = cmd.get('cmd')
            cmd_results.append(cmd_result)
            if cmd_result['error']:
                result['failed'] = True
                result['message'] = cmd_result['stdout'].split('\r\n\r\n')[1]
                cmds.append(dict(cmd='cancel', ignore_error=True))
                cmds.append(dict(cmd='revert', ignore_error=True))
                cmds.append(dict(cmd='config_revert', ignore_error=True))
                cmd_result = execute_cmd(cmd_cli, dict(cmd='cancel'))
                cmd_results.append(cmd_result)
                cmd_result = execute_cmd(cmd_cli, dict(cmd='revert'))
                cmd_results.append(cmd_result)
                cmd_result = execute_cmd(cmd_cli, dict(cmd='config_revert'))
                cmd_results.append(cmd_result)
                break;
            result['changed'] = True
        if run_opt['debug']:
            result['cmds_output'] = cmd_results
    except Exception as exc:
        result['failed'] = True
        result['message'] = str(exc)
    finally:
        close_cli(cmd_cli)
    #    result['cmds'] = cmds
    return result

    #return run_option_adding_field_in_the_path(option, run_opt, 'name')

def run_module():
    # define available arguments/parameters a user can pass to the module
    module_args = dict(
        settings=dict(type='dict', required=False),
        peers=dict(type='dict', required=False),
        clusters=dict(type='dict', required=False),
        enrollment_range=dict(type='dict', required=False),
        management=dict(type='dict', required=False),
        skip_invalid_keys=dict(type='bool', default=False, required=False),
        debug=dict(type='bool', default=False, required=False)
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
            'func': run_option_cluster_settings
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
            'func': run_option_cluster_clusters
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
        'check_mode': module.check_mode,
        'debug': module.params.get('debug', False)
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
