#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2023, ZPE Systems <zpesystems.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r'''
---
module: firewall
author: Rene Neumann (@zpe-rneumann)
'''

EXAMPLES = r'''
'''

RETURN = r'''

'''

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.zpe.nodegrid.plugins.module_utils.nodegrid_util import get_cli, close_cli, execute_cmd, check_os_version_support, dict_diff

import os


# We have to remove the SID from the Environmental settings, to avoid an issue
# were we can not run pexpect.run multiple times
if "DLITF_SID" in os.environ:
    del os.environ["DLITF_SID"]
if "DLITF_SID_ENCRYPT" in os.environ:
    del os.environ["DLITF_SID_ENCRYPT"]


def get_chain( endpoint , chain , timeout):
    cmd_cli = get_cli(timeout=timeout)

    #build cmd
    cmd = {
        'cmd' : str('show /settings/' + endpoint + '/chains/' + chain)
    }
    cmd_result = execute_cmd(cmd_cli, cmd)
    data = {}
    if cmd_result['error']:
       data[chain] =  {'error': cmd_result['error']}
    else:
        for item in cmd_result['json']:
            data[chain] =  {'current_state': item['data']}
            rule_data = {}
            for rule in item['data']:
                if 'rules' in rule.keys():
                    rule_number = rule['rules']
                    rule_data.update({rule_number :_get_rule(endpoint + '/chains/'+ chain, rule_number, cmd_cli) } )
            data[chain].update({'current_state_rules': rule_data })
    close_cli(cmd_cli)
    return data

def clean_chain( endpoint , chain , timeout):
    #build cmd
    cmd = {
        'cmd' : str('delete /settings/' + endpoint + '/chains/' + chain + ' -'),
        'confirm': True
    }
    data = {chain: {'current_state': {}, 'current_state_rules':{}}}
    return data, cmd

def _get_rule( endpoint: str,rule_number: str, cmd_cli: dict) -> dict:
    #build cmd
    cmd: dict = {
        'cmd' : str('show /settings/' + endpoint + '/' + rule_number)
    }
    cmd_result = execute_cmd(cmd_cli, cmd)
    data = {}
    if cmd_result['error']:
       data[rule_number] =  {'error': cmd_result['error']}
    else:
       data = cmd_result['json'][0]['data']
    return data

def get_policy( endpoint: str , timeout: int = 60 ) -> dict:
    cmd_cli = get_cli(timeout=timeout)

    #build cmd
    cmd = {
        'cmd' : str('show /settings/' + endpoint + '/policy/')
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
    sort_list = ['target','rule_number','description','source_net4','destination_net4','protocol','protocol_number',
                 'destination_port','destination_udp_port','input_interface',
                 'output_interface','fragments','reverse_match_for_source_ip|mask','reverse_match_for_destination_ip|mask',
                 'reverse_match_for_source_port','reverse_match_for_destination_port','reverse_match_for_protocol',
                 'reverse_match_for_tcp_flags','reverse_match_for_icmp_type','reverse_match_for_input_interface',
                 'enable_state_match','reverse_match_for_output_interface','reject_with','log_level','log_prefix',
                 'log_tcp_sequence_numbers','log_options_from_the_tcp_packet_header','log_options_from_the_ip_packet_header']
    for key in sort_list:
        if key in rule.keys():
            new_rule[key] = rule[key]
            rule.pop(key)
    new_rule = {**new_rule, **rule}
    return new_rule

def run_module():
    # define available arguments/parameters a user can pass to the module
    module_args = dict(
        ipv4_nat=dict(type='dict', required=False),
        ipv4_firewall=dict(type='dict', required=False),
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
        'ipv4_nat': {},
        'ipv4_nat_policy': {},
        'ipv4_firewall': {},
        'ipv4_firewall_policy': {},
    }
    
    # Build out commands
    cmds = []

    #Get Current NAT Data
    if module.params['ipv4_nat']:
        ipv4_nat = module.params['ipv4_nat']
        # Look at NAT rules
        if 'chains' in ipv4_nat.keys():
            chains_current = {}
            for chain in ipv4_nat['chains']:
                # Clean Rules if clean_and_config is yes
                if 'clean_and_config' in ipv4_nat.keys() and ipv4_nat['clean_and_config']:
                    data, cmd = clean_chain("ipv4_nat", chain, module.params['timeout'])
                    chains_current.update(data)
                    cmds.append(cmd)
                else:
                    # Get the current state of the chain
                    chains_current.update(get_chain("ipv4_nat", chain, module.params['timeout']))
                # [TODO] This Section needs to expanded to cover different actions, currently we will consider only add and update
                diff_rules = []
                #for rule in ipv4_nat['chains'][chain]:
                for rule in sorted(ipv4_nat['chains'][chain], key=lambda x: x.get('rule_number', float('inf'))):
                    # Before continue, do we ensure that a target is defined, by default value will be set MASQUERADE
                    if 'target' not in rule.keys():
                        rule['target'] = "MASQUERADE"
                    # We found a rule number in the desired state, we will check against this specific rule #
                    if 'rule_number' in rule.keys():
                        # We set the desired state
                        desired_state = rule
                        # We found a matching rule number in the current state, we will check against this specific rule
                        if str(rule['rule_number']) in chains_current[chain]['current_state_rules'].keys():
                            current_state = chains_current[chain]['current_state_rules'][str(rule['rule_number'])]
                            diff_state = dict_diff(desired_state,current_state)
                            if len(diff_state) > 0:
                                 diff_state['rule_number']=str(rule['rule_number'])
                                 diff_state['target'] = str(rule['target'])
                                 diff_rules.append(diff_state)
                        # We found no matching rule number in the current state
                        else:
                            rule.pop('rule_number')
                            diff_rules.append(rule)
                    # We rule number was defined in current state
                    else:
                        diff_rules.append(rule)
                diff_chains['ipv4_nat'][chain] = diff_rules
        # Look at NAT policies
        if 'policy' in ipv4_nat.keys():
            policy_current = {}
            # Get the current state of the plocy
            policy_current.update(get_policy("ipv4_nat", module.params['timeout']))
            # Create a diff
            diff = []
            for item in ipv4_nat['policy']:
                if policy_current[item]:
                    if ipv4_nat['policy'][item] != policy_current[item]:
                        diff.append({item: ipv4_nat['policy'][item]})
            diff_chains['ipv4_nat_policy'] = diff

    #Get Current FIREWALL Data
    if module.params['ipv4_firewall']:
        ipv4_firewall = module.params['ipv4_firewall']
        # Look at Firewall rules
        if 'chains' in ipv4_firewall.keys():
            chains_current = {}
            for chain in ipv4_firewall['chains']:
                # Clean Rules if clean_and_config is yes
                if 'clean_and_config' in ipv4_firewall.keys() and ipv4_firewall['clean_and_config']:
                    data, cmd = clean_chain("ipv4_firewall", chain, module.params['timeout'])
                    chains_current.update(data)
                    cmds.append(cmd)
                else:
                    # Get the current state of the chain
                    chains_current.update(get_chain("ipv4_firewall", chain, module.params['timeout']))
                # [TODO] This Section needs to expanded to cover different actions, currently we will consider only add and update
                diff_rules = []
                #for rule in ipv4_firewall['chains'][chain]:
                for rule in sorted(ipv4_firewall['chains'][chain], key=lambda x: x.get('rule_number', float('inf'))):
                    # Before continue, do we ensure that a target is defined, by default value will be set MASQUERADE
                    if 'target' not in rule.keys():
                        rule['target'] = "ACCEPT"
                    # Ansible inventory dose not honor the order or dictonaries and sort alphabetically, as order is
                    # imporant to some settings are we reordering the rule disctonary
                    rule = resort_rule(rule)
                    # We found a rule number in the desired state, we will check against this specific rule #
                    if 'rule_number' in rule.keys():
                        # We set the desired state
                        desired_state = rule
                        # We found a matching rule number in the current state, we will check against this specific rule
                        if str(rule['rule_number']) in chains_current[chain]['current_state_rules'].keys():
                            current_state = chains_current[chain]['current_state_rules'][str(rule['rule_number'])]
                            diff_state = dict_diff(desired_state,current_state)
                            if len(diff_state) > 0:
                                 diff_state['rule_number']=str(rule['rule_number'])
                                 diff_state['target'] = str(rule['target'])
                                 diff_rules.append(diff_state)
                        # We found no matching rule number in the current state
                        else:
                            rule.pop('rule_number')
                            diff_rules.append(rule)
                    # We rule number was defined in current state
                    else:
                        diff_rules.append(rule)
                diff_chains['ipv4_firewall'][chain] = diff_rules
        # Look at Firewall policies
        if 'policy' in ipv4_firewall.keys():
            policy_current = {}
            # Get the current state of the policy
            policy_current.update(get_policy("ipv4_firewall", module.params['timeout']))
            # Create a diff
            diff = []
            for item in ipv4_firewall['policy']:
                if policy_current[item]:
                    if ipv4_firewall['policy'][item] != policy_current[item]:
                        diff.append({item: ipv4_firewall['policy'][item]})
            diff_chains['ipv4_firewall_policy'] = diff

    # Build Commands for IPv4 NAT rules
    for chain in diff_chains['ipv4_nat']:
        if len(diff_chains['ipv4_nat'][chain]) > 0:
            for rule in diff_chains['ipv4_nat'][chain]:
                if 'rule_number' in rule.keys():
                    cmds.append({'cmd': f"cd /settings/ipv4_nat/chains/{chain}/{rule['rule_number']}"})
                else:
                    cmds.append({'cmd': f"cd /settings/ipv4_nat/chains/{chain}/"})
                    cmds.append({'cmd': "add"})
                for setting in rule:
                    cmd = {'cmd': f"set {setting}={rule[setting]}"}
                    cmds.append(cmd)
                cmds.append({'cmd': "commit"})
                cmds.append({'cmd': "cd"})

    # Build Commands for IPv4 NAT Policy
    if len(diff_chains['ipv4_nat_policy']) > 0:
        cmds.append({'cmd': f"cd /settings/ipv4_nat/policy/"})
        for rule in diff_chains['ipv4_nat_policy']:
            for setting in rule:
                cmd = {'cmd': f"set {setting}={rule[setting]}"}
                cmds.append(cmd)
        cmds.append({'cmd': "commit"})
        cmds.append({'cmd': "cd"})

    # Build Commands for IPv4 Firewall rules
    for chain in diff_chains['ipv4_firewall']:
        if len(diff_chains['ipv4_firewall'][chain]) > 0:
            for rule in diff_chains['ipv4_firewall'][chain]:
                if 'rule_number' in rule.keys():
                    cmds.append({'cmd': f"cd /settings/ipv4_firewall/chains/{chain}/{rule['rule_number']}"})
                else:
                    cmds.append({'cmd': f"cd /settings/ipv4_firewall/chains/{chain}/"})
                    cmds.append({'cmd': "add"})
                for setting in rule:
                    cmd = {'cmd': f"set {setting}={rule[setting]}"}
                    cmds.append(cmd)
                cmds.append({'cmd': "commit"})
                cmds.append({'cmd': "cd"})

    # Build Commands for IPv4 Firewall Policy
    if len(diff_chains['ipv4_firewall_policy']) > 0:
        cmds.append({'cmd': f"cd /settings/ipv4_firewall/policy/"})
        for rule in diff_chains['ipv4_firewall_policy']:
            for setting in rule:
                cmd = {'cmd': f"set {setting}={rule[setting]}"}
                cmds.append(cmd)
        cmds.append({'cmd': "commit"})
        cmds.append({'cmd': "cd"})

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
