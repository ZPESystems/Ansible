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
from ansible_collections.zpe.nodegrid.plugins.module_utils.nodegrid_util import nodegrid_cli, execute_cmd, check_os_version_support, dict_diff, NodegridError
import os, copy


# We have to remove the SID from the Environmental settings, to avoid an issue
# were we can not run pexpect.run multiple times
if "DLITF_SID" in os.environ:
    del os.environ["DLITF_SID"]
if "DLITF_SID_ENCRYPT" in os.environ:
    del os.environ["DLITF_SID_ENCRYPT"]


def get_rules(endpoint , rule , timeout=60):
    result = dict(error=False, msg='', rules=dict())
    try:
        cmd = dict(cmd=f"ls /settings/{endpoint}/{rule}")
        with nodegrid_cli(timeout=timeout) as cmd_cli:
            cmd_result = execute_cmd(cmd_cli, cmd, timeout=timeout)
            if len(cmd_result['json']) > 0:
                rule_data = {}
                for item in cmd_result['json']:
                    rule_state = _get_rule(f"{endpoint}/{rule}", item['path'], cmd_cli, timeout=timeout)
                    if 'rule' in rule_state:
                        rule_data.update({item['path'] : rule_state['rule']} )
                result['rules'][rule] = {'current_state': rule_data}
            #else:
            #    result['rules'][rule] = {'current_state': cmd_result}
    except (NodegridError, Exception) as e:
        result['error'] = True
        result['msg'] = f"CLI Error: f{e}"
        return result
    return result

def _get_rule(endpoint: str, rule_number: str, cmd_cli, timeout=60) -> dict:
    result = dict(error=False, msg='', rule=None)
    cmd = dict(cmd=f"export_settings /settings/{endpoint}/{rule_number} --plain-password")
    cmd_result = execute_cmd(cmd_cli, cmd, timeout=timeout)
    if cmd_result['json']:
        result['rule'] = cmd_result['json'][0]['data']
    return result


def get_snmp_system(endpoint: str , timeout: int = 60) -> dict:
    result = dict(error=False, msg='', state=dict())
    cmd = dict(cmd=f"show /settings/{endpoint}")
    try:
        with nodegrid_cli(timeout=timeout) as cmd_cli:
            cmd_result = execute_cmd(cmd_cli, cmd, timeout=timeout)
    except (NodegridError, Exception) as e:
        result['error'] = True
        result['msg'] = f"CLI Error: f{e}"
        return result
    result['state'] =  cmd_result['json'][0]['data']
    return result


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
        timeout=dict(type='int', default=60, required=False),
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
    timeout = module.params['timeout']

    # Lets get the current status and check if it must be changed
    res, err_msg, nodegrid_os = check_os_version_support(timeout=timeout)
    if res == 'error' or res == 'unsupported':
        module.fail_json(msg=err_msg, **result)
    elif res == 'warning':
        result['warning'] = err_msg

    if module.params['debug']:
        result['nodegrid_os'] = nodegrid_os

  ## Find out what needs to be changed
    diff_chains = {
        'system': {},
        'snmp_rules': {}
    }

    # Look at SNMP settings rules
    #desired_state_rules = []
    if module.params['rules']:
        snmp_rules = module.params['rules']
        # Look at Firewall rules
        rules_current = {}
        chain = "v1_v2_v3"
        # Get the current state of the rules
        get_rules_current = get_rules("snmp", chain, timeout=timeout)
        if get_rules_current['error']:
            result['failed'] = True
            result['msg'] = f"{get_rules_current['msg']}"
            module.fail_json(msg=result['msg'], **result)

        rules_current.update(get_rules_current['rules'])
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
                        module.fail_json(msg=result['msg'], **result)

                # Ansible inventory dose not honor the order or dictonaries and sort alphabetically, as order is
                # important to some settings are we reordering the rule dictinorary
                rule = resort_rule(rule)
                if 'rule_number' in rule.keys():
                    if module.params['debug']:
                        result[rule['rule_number']] = rule.copy()
                    # We set the desired state
                    desired_state = rule
                    # We found a matching rule number in the current state, we will check against this specific rule
                    if 'current_state' in rules_current and isinstance(rules_current[chain]['current_state'], dict) and rule['rule_number'] in rules_current[chain]['current_state'].keys():
                        diff_chains['snmp_rules'] = {}
                        current_state = rules_current[chain]['current_state'][str(rule['rule_number'])]
                        diff_state = dict_diff(desired_state,current_state)
                        if module.params['debug']:
                            result['diff_state'] = diff_state.copy()
                        if len(diff_state) > 0:
                            diff_state['rule_number'] = rule['rule_number']
                            diff_rules.append(diff_state)
                    else:
                         rule.pop('rule_number', None)
                         diff_rules.append(rule)
                    diff_chains['snmp_rules'] = diff_rules
            else:
                result['failed'] = True
                result['msg'] = "SNMP version parameter must be defined"
                module.fail_json(msg=result['msg'], **result)

    # Look at SNMP System details
    if module.params['system']:
        snmp_system = module.params['system']
        system_current = {}
        # Get the current state of the policy
        snmp_system_current = get_snmp_system("snmp/system", timeout=timeout)
        if snmp_system_current['error']:
            result['failed'] = True 
            result['msg'] = snmp_system_current['msg']
            module.fail_json(msg=result['msg'], **result)

        system_current.update(snmp_system_current['state'])
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
        with nodegrid_cli(timeout=timeout) as cmd_cli:
            for cmd in cmds:
                cmd_result = execute_cmd(cmd_cli, cmd, timeout=timeout)
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
                    result['msg'] = cmd_result['stdout_lines']
                    break;
                result['changed'] = True
        result['cmds_output'] = cmd_results
    except (NodegridError, Exception) as e:
        result['error'] = True
        result['msg'] = f"CLI Error: f{e}"

    if result['failed']:
        module.fail_json(msg=result['msg'], **result)

    # in the event of a successful module execution, you will want to
    # simple AnsibleModule.exit_json(), passing the key/value results
    module.exit_json(**result)


def main():
    run_module()


if __name__ == '__main__':
    main()
