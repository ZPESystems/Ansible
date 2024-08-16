#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2023, ZPE Systems <zpesystems.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r'''
---
module: nodegrid ipv4_firewall
author: 
- Rene Neumann (@zpe-rneumann)
- Diego Montero (@zpe-diegom)

description:
- M(firewall) is used to set up, maintain, and inspect the firewall rules in a Nodegrid device. It only considers the following firewall iptables chains:
   INPUT, FORWARD, OUTPUT 

atributes:
    check_mode:
        support: full
    diff_mode:
        support: none
    platform:
        platforms: Nodegrid

notes:
    - This module handles individual rules. 

options:
  action:
    description:
      - Specifies the action to be performed for a rule into a chain
      - Only applicable for chain rules, not for chain policy
    type: str
    choices: [append, insert, modify]
    default: append
  state:
    description:
      - Whether the rule should be absent or present
      - Only applicable for chain rules, not for chain policy
    type: str
    choices: [ present, absent ]
    default: present
  flush:
    description:
      - Flushes all the rules from the specified chain 
      - A chain selectio is required
    type: bool
    default: false
  chain:
    description:
      - Specifies the chain to be configured 
    type: str
    choices: [INPUT, OUTPUT, FORWARD]
  policy:
    description:
      - Specifies the chain policy to be configured 
    type: str
    choices: [ACCEPT, DROP]
  target:
    description:
      - Specifies the chain policy to be configured 
    type: str
    choices: [ACCEPT, DROP, LOG, REJECT, RETURN]
    defautl: ACCEPT
  rule_number:
    description:
      - Specifies the rule number in the chain
      - Number greater or equal to 0.
    type: str
    defautl: ''
  description:
    description:
      - Defines the rule description
    type: str
    defautl: ''
  source_net4:
    description:
      - IPv4 source network
    type: str
    defautl: ''
  destination_net4:
    description:
      - IPv4 destination network
    type: str
    defautl: ''
  source_mac_address:
    description:
      - source MAC address
    type: str
    defautl: ''
  protocol:
    description:
      - Specifies the rule protocol 
    type: str
    choices: [numeric, icmp, tcp, udp]
    default: numeric
  protocol_number:
    description:
      - Specifies the rule protocol based on an integer
      - enabled when protocol=numeric
    type: srt
    default: ''
  source_port:
    description:
      - Specifies tcp source port
      - enabled when protocol=tcp
    type: srt
    default: ''
  destination_port:
    description:
      - Specifies tcp destination port
      - enabled when protocol=tcp
    type: srt
    default: ''
  tcp_flag_syn:
    description:
      - tcp flags
      - enabled when protocol=tcp
    type: srt
    choices: [any, set, unset]
    default: any
  tcp_flag_ack:
    description:
      - tcp flags
      - enabled when protocol=tcp
    type: srt
    choices: [any, set, unset]
    default: any
  tcp_flag_fin:
    description:
      - tcp flags
      - enabled when protocol=tcp
    type: srt
    choices: [any, set, unset]
    default: any
  tcp_flag_rst:
    description:
      - tcp flags
      - enabled when protocol=tcp
    type: srt
    choices: [any, set, unset]
    default: any
  tcp_flag_urg:
    description:
      - tcp flags
      - enabled when protocol=tcp
    type: srt
    choices: [any, set, unset]
    default: any
  tcp_flag_psh:
    description:
      - tcp flags
      - enabled when protocol=tcp
    type: srt
    choices: [any, set, unset]
    default: any
  source_udp_port:
    description:
      - Specifies udp source port
      - enabled when protocol=udp
    type: srt
    default: ''
  destination_udp_port:
    description:
      - Specifies udp destination port
      - enabled when protocol=udp
    type: srt
    default: ''
  icmp_type:
    description:
      - Specifies icmp type of message
      - enabled when protocol=icmp
    type: srt
    choices: [tos_host_redirect, tos_host_unreachable, tos_network_redirect, tos_network_unreachable, address_mask_reply, address_mask_request, any, communication_prohibited, destination_unreachable, echo_reply, echo_request, fragmentation_needed, host_precedence_violation, host_prohibited, host_redirect, host_unknown, host_unreachable, bad_ip_header, network_prohibited, network_redirect, network_unknown, network_unreachable, parameter_problem, port_unreachable, precedence_cutoff, protocol_unreachable, redirect, required_option_missing, router_advertisement, router_solicitation, source_quench, source_route_failed, time_exceeded, timestamp_reply, timestamp_request, ttl_zero_during_reassembly, ttl_zero_during_transit]
    default: 'any'
  input_interface:
    description:
      - Defines the Input Interface
    type: srt
    default: ''
  output_interface:
    description:
      - Defines the Output Interface
    type: srt
    default: ''
  fragments:
    description:
      - IP fragments criteria
    type: srt
    choices: [all_packets_and_fragments, unfragmented_packets_and_1st_packets, 2nd_and_further_packets]
    default: all_packets_and_fragments
  reverse_match_for_source_ip_mask:
    description:
      - reverse criteria option
    type: srt
    choices: [yes, no]
    default: no
  reverse_match_for_destination_ip_mask:
    description:
      - reverse criteria option
    type: srt
    choices: [yes, no]
    default: no
  reverse_match_for_source_mac_address:
    description:
      - reverse criteria option
    type: srt
    choices: [yes, no]
    default: no
  reverse_match_for_source_port:
    description:
      - reverse criteria option
    type: srt
    choices: [yes, no]
    default: no
  reverse_match_for_destination_port:
    description:
      - reverse criteria option
    type: srt
    choices: [yes, no]
    default: no
  reverse_match_for_protocol:
    description:
      - reverse criteria option
    type: srt
    choices: [yes, no]
    default: no
  reverse_match_for_tcp_flags:
    description:
      - reverse criteria option
    type: srt
    choices: [yes, no]
    default: no
  reverse_match_for_icmp_type:
    description:
      - reverse criteria option
    type: srt
    choices: [yes, no]
    default: no
  reverse_match_for_input_interface:
    description:
      - reverse criteria option
    type: srt
    choices: [yes, no]
    default: no
  reverse_match_for_output_interface:
    description:
      - reverse criteria option
    type: srt
    choices: [yes, no]
    default: no
  enable_state_match:
    description:
      - enable socket state match
    type: srt
    choices: [yes, no]
    default: no
  new:
    description:
      - enable socket state match
      - enabled when enable_state_match=yes
    type: srt
    choices: [yes, no]
    default: no
  established:
    description:
      - enable socket state match
      - enabled when enable_state_match=yes
    type: srt
    choices: [yes, no]
    default: no
  related:
    description:
      - enable socket state match
      - enabled when enable_state_match=yes
    type: srt
    choices: [yes, no]
    default: no
  invalid:
    description:
      - enable socket state match
      - enabled when enable_state_match=yes
    type: srt
    choices: [yes, no]
    default: no
  reverse_state_match:
    description:
      - enable socket state match
      - reverse criteria option
      - enabled when enable_state_match=yes
    type: srt
    choices: [yes, no]
    default: no
  reject_with:
    description:
      - reject message
    type: srt
    choices: [administratively_prohibited, host_prohibited, host_unreacheable, network_prohibited, network_unreacheable, port_unreacheable, protocol_unreacheable, tcp_reset]
    default: port_unreacheable
  log_level:
    description:
      - defines log level
    type: srt
    choices: [alert, critical, debug, emergency, error, info, notice, warning]
    default: debug
  log_prefix:
    description:
      - defines log prefix information
    type: srt
    default: ''
  log_tcp_sequence_numbers:
    description:
      - log the tcp sequence numbers
    type: srt
    choices: [yes, no]
    default: no
  log_options_from_the_tcp_packet_header:
    description:
      - log the options from the tcp packet header
    type: srt
    choices: [yes, no]
    default: no
  log_options_from_the_ip_packet_header:
    description:
      - log the options from the ip packet header
    type: srt
    choices: [yes, no]
    default: no
  debug:
    description:
      - debug mode. Shows the executed commands on the output
    type: bool
    default: false
  timeout:
    description:
      - Timeout time for cli commands execution
    type: int
    default: 30
'''

EXAMPLES = r'''

- name: Set Policy ACCEPT to the INPUT chain
  zpe.nodegrid.firewallv2:
    chain: INPUT
    policy: ACCEPT

- name: Set Policy DROP to the FORWARD chain
  zpe.nodegrid.firewallv2:
    chain: FORWARD
    policy: DROP

- name: Append a rule into the INPUT chain
  zpe.nodegrid.firewallv2:
    action: append
    state: present
    chain: INPUT
    input_interface: eth0
    description: DEFAULT_RULE_DO_NOT_REMOVE

- name: Delete the first rule that matches the config in the INPUT chain
  zpe.nodegrid.firewallv2:
    action: append
    state: absent
    chain: INPUT
    input_interface: eth0
    description: DEFAULT_RULE_DO_NOT_REMOVE
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

def get_chain_policy(table, chain, timeout=30) -> dict:
    cmd_cli = get_cli(timeout=timeout)

    #build cmd
    cmd = {
        'cmd': f"show /settings/{table}/policy/ {chain}"
    }
    cmd_result = execute_cmd(cmd_cli, cmd)
    data = {}
    if cmd_result['error']:
        return dict(error=True, msg=f"Can\'t detect current policy for chain {chain}. Error: {cmd_result['stdout']}")
    else:
       data =  cmd_result['json'][0]['data']
    close_cli(cmd_cli)
    return dict(error=False, chain=chain, policy=data[chain])

def set_chain_policy(table, chain, policy) -> dict:
    return dict(cmd = f"set /settings/{table}/policy/ {chain}={policy}")

def _get_rule(table, chain, rule_number, cmd_cli) -> dict:
    #build cmd
    cmd: dict = {
        'cmd' : f"show /settings/{table}/chains/{chain}/{rule_number}"
    }
    cmd_result = execute_cmd(cmd_cli, cmd)
    data = {}
    if cmd_result['error']:
        return dict(error=True, msg=f"Error getting rule number {rule_number} in chain {chain}. Error: {cmd_result['stdout']}")
    else:
       return cmd_result['json'][0]['data']

def get_rules_present(table, chain, timeout=30) -> dict:
    cmd_cli = get_cli(timeout=timeout)
    #build cmd
    cmd = {
        'cmd' : f"show /settings/{table}/chains/{chain}"
    }
    cmd_result = execute_cmd(cmd_cli, cmd)
    data = dict(error=False, rules=[], msg='')
    if cmd_result['error']:
        return dict(error=True, msg=f"Cannot get present rules in chain {chain}. Error: {cmd_result['error']}")
    else:
        for item in cmd_result['json']:
            for rule in item['data']:
                if 'rules' in rule.keys():
                    rule_number = rule['rules']
                    data['rules'].extend([_get_rule(table=table, chain=chain, rule_number=rule_number, cmd_cli=cmd_cli) ])
    close_cli(cmd_cli)
    return data

def create_rule(params):
    keys_to_exclude = ['action', 'state', 'chain', 'policy', 'debug']
    return {key:value for key, value in params.items() if key not in keys_to_exclude }


def check_rule_present(rules, new_rule, is_insert):
    for rule in rules:
        diff_state = dict_diff(new_rule,rule)
        if not is_insert:
            diff_state.pop("rule_number", None)

        if len(diff_state) == 0:
            return True, rule
    return False, {}


def insert_rule(table, chain, new_rule):
    cmds = []
    dependencies = {
        'protocol': {
            'numeric': ['protocol_number'],
            'tcp': ['source_port', 'destination_port', 'tcp_flag_syn', 'tcp_flag_ack', 'tcp_flag_fin', 'tcp_flag_rst', 'tcp_flag_urg', 'tcp_flag_psh'],
            'udp': ['source_udp_port', 'destination_udp_port'],
            'icmp': ['icmp_type'],
            'enable_state_match': ['new', 'established', 'related', 'invalid', 'reverse_state_match'],
        }
    }

    rename_settings = {
        'reverse_match_for_source_ip_mask': 'reverse_match_for_source_ip|mask',
        'reverse_match_for_destination_ip_mask': 'reverse_match_for_destination_ip|mask'
    }

    for dependency in dependencies:
        for dep_rem in {key:value for key, value in dependencies[dependency].items() if key not in [new_rule['protocol']]}:
            for setting in dependencies[dependency][dep_rem]:
                new_rule.pop(setting)

    cmds.append(dict(cmd=f"cd /settings/{table}/chains/{chain}/"))
    cmds.append(dict(cmd="add"))
    for setting in new_rule:
        if new_rule[setting] and len(str(new_rule[setting]).strip()) > 0:
            if setting in rename_settings:
                cmds.append(dict(cmd=f"set {rename_settings[setting]}={new_rule[setting]}"))
            else:
                cmds.append(dict(cmd=f"set {setting}={new_rule[setting]}"))
    return new_rule, cmds

def append_rule(table, chain, new_rule):
    cmds = []
    new_rule.pop("rule_number", None)
    dependencies = {
        'protocol': {
            'numeric': ['protocol_number'],
            'tcp': ['source_port', 'destination_port', 'tcp_flag_syn', 'tcp_flag_ack', 'tcp_flag_fin', 'tcp_flag_rst', 'tcp_flag_urg', 'tcp_flag_psh'],
            'udp': ['source_udp_port', 'destination_udp_port'],
            'icmp': ['icmp_type'],
            'enable_state_match': ['new', 'established', 'related', 'invalid', 'reverse_state_match'],
        }
    }

    rename_settings = {
        'reverse_match_for_source_ip_mask': 'reverse_match_for_source_ip|mask',
        'reverse_match_for_destination_ip_mask': 'reverse_match_for_destination_ip|mask'
    }

    for dependency in dependencies:
        for dep_rem in {key:value for key, value in dependencies[dependency].items() if key not in [new_rule['protocol']]}:
            for setting in dependencies[dependency][dep_rem]:
                new_rule.pop(setting)

    cmds.append(dict(cmd=f"cd /settings/{table}/chains/{chain}/"))
    cmds.append(dict(cmd="add"))
    for setting in new_rule:
        if new_rule[setting] and len(str(new_rule[setting]).strip()) > 0:
            if setting in rename_settings:
                cmds.append(dict(cmd=f"set {rename_settings[setting]}={new_rule[setting]}"))
            else:
                cmds.append(dict(cmd=f"set {setting}={new_rule[setting]}"))
    return new_rule, cmds

def update_rule(table, chain, rule, new_rule):
    cmds = []
    if len(rule) > 0:
        diff_state = dict_diff(new_rule,rule)
    else:
        diff_state = new_rule
    if len(diff_state) == 0:
        return diff_state, []

    cmds.append(dict(cmd=f"cd /settings/{table}/chains/{chain}/{new_rule['rule_number']}"))
    for setting in diff_state:
        if len(str(diff_state[setting]).strip()) > 0:
            cmds.append(dict(cmd=f"set {setting}={diff_state[setting]}"))
    return diff_state, cmds

    
def delete_rule(table, chain, rule):
    cmds = []
    cmds.append(dict(cmd=f"cd /settings/{table}/chains/{chain}/"))
    cmds.append(dict(cmd=f"delete {rule['rule_number']}"))
    return cmds

def flush_rules(table, chain):
    cmds = []
    cmds.append(dict(cmd=f"delete /settings/{table}/chains/{chain} -", confirm=True))
    return cmds

def run_module():
    # define available arguments/parameters a user can pass to the module
    module_args = dict(
        action=dict(type='str', default='append', choices=['append', 'insert', 'modify']),
        debug=dict(type='bool', default=False),
        timeout=dict(type=int, default=30),
        flush=dict(type='bool', default=False),
        state=dict(type='str', default='present', choices=['absent', 'present']),
        chain=dict(type='str', choices=['INPUT', 'OUTPUT', 'FORWARD']),
        policy=dict(type='str', choices=['ACCEPT', 'DROP']),
        target=dict(type='str', default='ACCEPT', choices=['ACCEPT', 'DROP', 'LOG', 'REJECT', 'RETURN']),
        rule_number=dict(type='str', default=''),
        description=dict(type='str', default=''),
        source_net4=dict(type='str', default=''),
        destination_net4=dict(type='str', default=''),
        source_mac_address=dict(type='str', default=''),
        protocol=dict(type='str', default='numeric', choices=['numeric', 'icmp', 'tcp', 'udp']),
        # protocol=numeric
        protocol_number=dict(type='str', default=''),
        # protocol=tcp
        source_port=dict(type='str', default=''),
        destination_port=dict(type='str', default=''),
        #   tcp flags
        tcp_flag_syn=dict(type='str', default='any', choices=['any', 'set', 'unset']),
        tcp_flag_ack=dict(type='str', default='any', choices=['any', 'set', 'unset']),
        tcp_flag_fin=dict(type='str', default='any', choices=['any', 'set', 'unset']),
        tcp_flag_rst=dict(type='str', default='any', choices=['any', 'set', 'unset']),
        tcp_flag_urg=dict(type='str', default='any', choices=['any', 'set', 'unset']),
        tcp_flag_psh=dict(type='str', default='any', choices=['any', 'set', 'unset']),
        # protocol=udp
        source_udp_port=dict(type='str', default=''),
        destination_udp_port=dict(type='str', default=''),
        # protocol=icmp
        icmp_type=dict(type='str', default='any', choices=['any', 'tos_host_redirect', 'tos_host_unreachable', 'tos_network_redirect', 'tos_network_unreachable', 'address_mask_reply', 'address_mask_request', 'any', 'communication_prohibited', 'destination_unreachable', 'echo_reply', 'echo_request', 'fragmentation_needed', 'host_precedence_violation', 'host_prohibited', 'host_redirect', 'host_unknown', 'host_unreachable', 'bad_ip_header', 'network_prohibited', 'network_redirect', 'network_unknown', 'network_unreachable', 'parameter_problem', 'port_unreachable', 'precedence_cutoff', 'protocol_unreachable', 'redirect', 'required_option_missing', 'router_advertisement', 'router_solicitation', 'source_quench', 'source_route_failed', 'time_exceeded', 'timestamp_reply', 'timestamp_request', 'ttl_zero_during_reassembly', 'ttl_zero_during_transit']),       
        input_interface=dict(type='str', default='any'),
        output_interface=dict(type='str', default='any'),
        fragments=dict(type='str', default='all_packets_and_fragments', choices=['all_packets_and_fragments', 'unfragmented_packets_and_1st_packets', '2nd_and_further_packets']),
        reverse_match_for_source_ip_mask=dict(type='str', default='no', choices=['yes', 'no']),
        reverse_match_for_destination_ip_mask=dict(type='str', default='no', choices=['yes', 'no']),
        reverse_match_for_source_mac_address=dict(type='str', default='no', choices=['yes', 'no']),
        reverse_match_for_source_port=dict(type='str', default='no', choices=['yes', 'no']),
        reverse_match_for_destination_port=dict(type='str', default='no', choices=['yes', 'no']),
        reverse_match_for_protocol=dict(type='str', default='no', choices=['yes', 'no']),
        reverse_match_for_tcp_flags=dict(type='str', default='no', choices=['yes', 'no']),
        reverse_match_for_icmp_type=dict(type='str', default='no', choices=['yes', 'no']),
        reverse_match_for_input_interface=dict(type='str', default='no', choices=['yes', 'no']),
        reverse_match_for_output_interface=dict(type='str', default='no', choices=['yes', 'no']),
        enable_state_match=dict(type='str', default='no', choices=['yes', 'no']),
        new=dict(type='str', default='no', choices=['yes', 'no']),
        established=dict(type='str', default='no', choices=['yes', 'no']),
        related=dict(type='str', default='no', choices=['yes', 'no']),
        invalid=dict(type='str', default='no', choices=['yes', 'no']),
        reverse_state_match=dict(type='str', default='no', choices=['yes', 'no']),
        reject_with=dict(type='str', default='port_unreacheable', choices=['administratively_prohibited', 'host_prohibited', 'host_unreacheable', 'network_prohibited', 'network_unreacheable', 'port_unreacheable', 'protocol_unreacheable', 'tcp_reset']),
        log_level=dict(type='str', default='debug', choices=['alert', 'critical', 'debug', 'emergency', 'error', 'info', 'notice', 'warning']),
        log_pefix=dict(type='str', default=""),
        log_tcp_sequence_numbers=dict(type='str', default='no', choices=['yes', 'no']),
        log_options_from_the_tcp_packet_header=dict(type='str', default='no', choices=['yes', 'no']),
        log_options_from_the_ip_packet_header=dict(type='str', default='no', choices=['yes', 'no'])
    )

    # the AnsibleModule object will be our abstraction working with Ansible
    # this includes instantiation, a couple of common attr would be the
    # args/params passed to the execution, as well as if the module
    # supports check mode
    module = AnsibleModule(
        argument_spec=module_args,
#        required_if=[
#            ('action', 'append', ('rule_number', ...), False),
#        ],
        supports_check_mode=True
    )
    
    # Firewall Table
    table = "ipv4_firewall"

    # seed the result dict in the object
    # we primarily care about changed and state
    # changed is if this module effectively modified the target
    # state will include any data that you want your module to pass back
    # for consumption, for example, in a subsequent task
    result = dict(
        changed=False,
        failed=False,
        message='',
        table=table,
        chain=module.params['chain'],
        state=module.params['state'],
    )
    #
    # Nodegrid OS section starts here
    #
    timeout = int(module.params.pop('timeout', 30))
    debug = module.params.pop('debug', False)

    # Lets get the current status and check if it must be changed
    res, err_msg, nodegrid_os = check_os_version_support()
    if res == 'error' or res == 'unsupported':
        module.fail_json(msg=err_msg, **result)
    elif res == 'warning':
        result['warning'] = err_msg

     # Check if chain option is required
    if result['chain'] is None:
        module.fail_json(msg="A Chain parameter must be specified Values: INPUT, OUTPUT, FORWARD.")

    # Check action 'insert'
    if module.params['action'] == 'insert' and not module.params["rule_number"].isdigit():
        module.fail_json(msg="Action 'insert' requires a 'rule_number', which must be an integer greater or equal to 0.")
    # Check action 'modify'
    if module.params['action'] == 'modify' and not module.params["rule_number"].isdigit():
        module.fail_json(msg="Action 'modify' requires a 'rule_number', which must be an integer greater or equal to 0.")
    # Check action 'append'
    if module.params['action'] == 'append' and module.params['rule_number'].strip() != "":
        module.fail_json(msg="Action 'append' does not requires a 'rule_number'. It is required to be removed")

    # Build out commands
    cmds = []
    diff_state = {}
    flush = module.params['flush']
    

    # Set the policy
    if module.params['policy']:
        if result['state'] == 'absent':
            module.fail_json(msg=f"Chain {module.params['chain']} cannot be deleted!")
        current_policy = get_chain_policy(table=table, chain=module.params['chain'])
        if current_policy.get('error', False):
            module.fail_json(msg=current_policy.get('msg'))

        changed = (current_policy['policy'] != module.params['policy'])
        if changed:
            diff_state = current_policy
            cmds.extend([set_chain_policy(table=table, chain=module.params['chain'], policy=module.params['policy'])])
    elif flush:
        cmds.extend(flush_rules(table=table, chain=module.params['chain']))
        diff_state = cmds[-1]['cmd']
    else:
        insert = (module.params['action'] == 'insert')
        modify = (module.params['action'] == 'modify')
        rules_present = get_rules_present(table=table, chain=module.params['chain'], timeout=timeout)
        if rules_present.get('error', False):
            module.fail_json(msg=rules_present.get('msg'))
            
        parsed_rule = create_rule(params=module.params)

        # If insert: check if rule_number is within range
        if insert and int(parsed_rule['rule_number']) > len(rules_present['rules']):
            module.fail_json(msg=f"Rule insert error: rule number {module.params.get('rule_number', None)} is out of bounds. Current rules range from: 0,...,{len(rules_present['rules'])-1}.")
        # If modify: check if rule_number is within range
        if modify and int(parsed_rule['rule_number']) > len(rules_present['rules'])-1:
            module.fail_json(msg=f"Rule modify error: rule number {module.params.get('rule_number', None)} is out of bounds. Current rules range from: 0,...,{len(rules_present['rules'])-1}.")

        if modify:
            rule_is_present = True
            rule_present = rules_present['rules'][int(parsed_rule['rule_number'])]
        else:
            rule_is_present, rule_present = check_rule_present(rules=rules_present['rules'], new_rule=parsed_rule, is_insert=insert)

        should_be_present = (result['state'] == 'present')
        if modify:
            result['changed'] = rule_is_present
        else:
            result['changed'] = (rule_is_present != should_be_present)
        if result['changed'] is False:
            module.exit_json(**result)

        # Build the modifications
        if should_be_present:
            if insert:
                diff_state, cmds = insert_rule(table=table, chain=module.params['chain'], new_rule=parsed_rule)
            elif modify:
                diff_state, cmds = update_rule(table=table, chain=module.params['chain'], rule=rule_present, new_rule=parsed_rule)
            else:
                diff_state, cmds = append_rule(table=table, chain=module.params['chain'], new_rule=parsed_rule)
        else:
            cmds.extend(delete_rule(table=table, chain=module.params['chain'], rule=rule_present))
            diff_state = cmds[-1]['cmd']

    if module.check_mode:
        # Display Changes
        result['diff'] = diff_state
        result['changed'] = False
        result['message'] = "No changes where performed, running in check_mode"
        result['cmds'] = cmds
        module.exit_json(**result)
    
    if debug:
        result['diff'] = diff_state
        result['cmds'] = cmds

    # Apply Changes
    if len(cmds) == 0:
        result['changed'] = False
        module.exit_json(**result)
    else:
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
                cmd_result = execute_cmd(cmd_cli, dict(cmd='config_revert'))
                break;
            result['changed'] = True
        if debug:
            result['cmds_output'] = cmd_results
    except Exception as exc:
        result['failed'] = True
        result['message'] = str(exc)
    finally:
        close_cli(cmd_cli)


    
    if result['failed']:
        module.fail_json(msg=result['message'], **result)

    # in the event of a successful module execution, you will want to
    # simple AnsibleModule.exit_json(), passing the key/value results
    module.exit_json(**result)

def main():
    run_module()


if __name__ == '__main__':
    main()
