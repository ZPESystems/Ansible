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
from ansible_collections.zpe.nodegrid.plugins.module_utils.nodegrid_util import get_cli, close_cli, execute_cmd, check_os_version_support, dict_diff, import_settings

import os, copy


# We have to remove the SID from the Environmental settings, to avoid an issue
# were we can not run pexpect.run multiple times
if "DLITF_SID" in os.environ:
    del os.environ["DLITF_SID"]
if "DLITF_SID_ENCRYPT" in os.environ:
    del os.environ["DLITF_SID_ENCRYPT"]


def get_rules( endpoint , rule , timeout):
    cmd_cli = get_cli(timeout=timeout)

    #build cmd
    cmd = {
        'cmd' : str('ls /settings/' + endpoint + "/" + rule)
    }
    cmd_result = execute_cmd(cmd_cli, cmd)
    data = {}
    if cmd_result['error']:
       data[rule] =  {'error': cmd_result['error']}
       data[rule] = {'error_full': cmd_result}
    else:
        if len(cmd_result['json']) > 0:
            rule_data = {}
            for item in cmd_result['json']:
                   rule_data.update({item['path'] :_get_rule(str(endpoint + '/'+ rule), item['path'], cmd_cli) } )
            data[rule] = {'current_state': rule_data}
        else:
            data[rule] = {'current_state': cmd_result}
    close_cli(cmd_cli)
    return data

def _get_rule( endpoint: str,rule_number: str, cmd_cli: dict) -> dict:
    #build cmd
    cmd: dict = {
        'cmd' : str('export_settings /settings/' + endpoint + '/' + rule_number + ' --plain-password' )
    }
    cmd_result = execute_cmd(cmd_cli, cmd)
    data = {}
    if cmd_result['error']:
       data[rule_number] =  {'error': cmd_result}
    else:
       data = cmd_result['json'][0]['data']
    return data


def get_snmp_system( endpoint: str , timeout: int = 60 ) -> dict:
    cmd_cli = get_cli(timeout=timeout)

    #build cmd
    cmd = {
        'cmd' : str('show /settings/' + endpoint )
    }
    cmd_result = execute_cmd(cmd_cli, cmd)
    data = {}
    if cmd_result['error']:
       data =  {'error': cmd_result['error']}
    else:
       data =  cmd_result['json'][0]['data']
    close_cli(cmd_cli)
    return data

def resort_rule(rule: dict):
    new_rule: dict = {}
    sort_list = ['version','community','source', 'verison', 'username', 'security_level', 'authentication_algorithm',
                 'authentication_password', 'privacy_algorithm', 'privacy_password']
    for key in sort_list:
        if key in rule.keys():
            new_rule[key] = rule[key]
            rule.pop(key)
    new_rule = {**new_rule, **rule}
    return new_rule

def run_module():
    # define available arguments/parameters a user can pass to the module
    module_args = dict(
        system=dict(type='dict', required=False),
        rules=dict(type='list', required=False),
        timeout=dict(type=int, default=60),
        debug=dict(type='bool', default=False)
    )

    # seed the result dict in the object
    # we primarily care about changed and state
    # changed is if this module effectively modified the target
    # state will include any data that you want your module to pass back
    # for consumption, for example, in a subsequent task
    result = dict(
        changed=False,
        failed=False,
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
    #
    # Nodegrid OS section starts here
    #
    if "timeout" in module.params.keys():
        try:
            timeout = int(module.params['timeout'])
        except:
            timeout = 60
    # Lets get the current status and check if it must be changed
    res, err_msg, nodegrid_os = check_os_version_support()
    if res == 'error' or res == 'unsupported':
        module.fail_json(msg=err_msg, **result)
    elif res == 'warning':
        result['warning'] = err_msg
    # result['nodegrid_facts'] = nodegrid_os

  ## Find out what needs to be changed
    diff_chains = {
        'system': {},
        'snmp_rules': {}
    }
    #Get Current NAT Data

        # Look at SNMP settings rules
    desired_state_rules = []
    if module.params['rules']:
        snmp_rules = module.params['rules']
        # Look at Firewall rules
        rules_current = {}
        chain = "v1_v2_v3"
        # Get the current state of the rules
        rules_current.update(get_rules("snmp", chain, module.params['timeout']))
        # [TODO] This Section needs to expanded to cover different actions, currently we will consider only add and update
        diff_rules = []
        if module.params['debug']:
            result['rules_current'] = copy.deepcopy(rules_current)
            result['rules_desired'] = copy.deepcopy(snmp_rules)
        for rule in snmp_rules:
            # The v3 needs to be handled different to v1 and v2
            if 'version' in rule.keys():
                    # Before continue, do we ensure that a source is defined, by default value will be set default
                    if 'source' not in rule.keys() and rule['version'] == 'version_v1|v2':
                        rule['source'] = "default"
                    if 'source' in rule.keys() and len(rule['source']) == 0 and rule['version'] == 'version_v1|v2':
                        rule['source'] = "default"
                    # Lets define the rule number
                    if str(rule['version']).strip() == 'version_v1|v2':
                        rule['rule_number'] = str(rule['community'] + "_" + rule['source'])
                    if str(rule['version']).strip() == 'version_3':
                        if 'username' in rule.keys():
                            rule['rule_number'] = rule['username']
                        else:
                            result['failed'] = True
                            result['msg'] = "For SNMP Version 3 must a username parameter be defined"
                            break

                    # Ansible inventory dose not honor the order or dictonaries and sort alphabetically, as order is
                    # important to some settings are we reordering the rule dictinorary
                    rule = resort_rule(rule)
                    if 'rule_number' in rule.keys():
                        if module.params['debug']:
                            result[rule['rule_number']] = rule.copy()
                        # We set the desired state
                        desired_state = rule
                        # We found a matching rule number in the current state, we will check against this specific rule
                        if str(rule['rule_number']) in rules_current[chain]['current_state'].keys():
                            diff_chains['snmp_rules'] = {}
                            current_state = rules_current[chain]['current_state'][str(rule['rule_number'])]
                            diff_state = dict_diff(desired_state,current_state)
                            if module.params['debug']:
                                result['diff_state'] = diff_state.copy()
                            if len(diff_state) > 0:
                                diff_state['rule_number'] = rule['rule_number']
                                diff_rules.append(diff_state)
                        else:
                             rule.pop('rule_number')
                             diff_rules.append(rule)
                        diff_chains['snmp_rules'] = diff_rules
            else:
                result['failed'] = True
                result['msg'] = "Version parameter must be defined"
                break

    # Look at SNMP System details
    if module.params['system']:
            snmp_system = module.params['system']
            system_current = {}
            # Get the current state of the policy
            system_current.update(get_snmp_system("snmp/system", module.params['timeout']))
            if module.params['debug']:
                result['system_current'] = system_current.copy()
                result['system_desired'] = snmp_system.copy()
            # Create a diff
            diff = []
            for item in snmp_system:
                if system_current[item]:
                    if str(snmp_system[item]).strip() != str(system_current[item]).strip():
                        diff.append({item: snmp_system[item]})
            diff_chains['system'] = diff


    # Build out commands
    cmds = []
    # # Build Commands for SNMP  rules
    if len(diff_chains['snmp_rules']) > 0:
        for rule in diff_chains['snmp_rules']:
            if 'rule_number' in rule.keys():
                cmds.append({'cmd': f"cd /settings/snmp/v1_v2_v3/{rule['rule_number']}"})
            else:
                cmds.append({'cmd': f"cd /settings/snmp/v1_v2_v3/"})
                cmds.append({'cmd': "add"})
            for setting in rule:
                if 'rule_number' != setting:
                    cmd = {'cmd': f"set {setting}={rule[setting]}"}
                cmds.append(cmd)
            cmds.append({'cmd': "commit"})

    # Build Commands for SNMP System settings
    if len(diff_chains['system']) > 0:
        cmds.append({'cmd': f"cd /settings/snmp/system/"})
        for rule in diff_chains['system']:
            for setting in rule:
                cmd = {'cmd': f"set {setting}='{rule[setting]}'"}
                cmds.append(cmd)
        cmds.append({'cmd': "commit"})

    # as fail save add system roll back
    if len(cmds) > 0:
        cmds.insert(0, {'cmd': f"config_start"})
        cmds.append({'cmd': f"config_confirm"})

    if module.params['debug']:
        result['cmds'] = cmds
        result['diff'] = diff_chains

    if module.check_mode:
        # Display Changes
        result['diff'] = diff_chains
        result['message'] = "No changes where performed, running in check_mode"
        module.exit_json(**result)
    ## Pushing Changes

    # Apply Changes
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
                break;
            result['changed'] = True
        close_cli(cmd_cli)
        result['cmds_output'] = cmd_results
    except Exception as exc:
        result['failed'] = True
        result['message'] = str(exc)

    if result['failed']:
        module.fail_json(msg=result['message'], **result)

    # in the event of a successful module execution, you will want to
    # simple AnsibleModule.exit_json(), passing the key/value results
    module.exit_json(**result)


def main():
    run_module()


if __name__ == '__main__':
    main()
