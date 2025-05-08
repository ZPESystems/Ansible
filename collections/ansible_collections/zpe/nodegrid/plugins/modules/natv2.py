#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2024, ZPE Systems <zpesystems.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r'''
---
module: nodegrid ipv4_firewall
author: 
- Diego Montero (@zpe-diegom)

description:
- M(nat) is used to set up, maintain, and inspect the NAT rules in a Nodegrid device.
  It only considers the following nat iptables chains: PREROUTING, INPUT, OUTPUT, POSTROUTING.

atributes:
    check_mode:
        support: full
    diff_mode:
        support: none
    platform:
        platforms: Nodegrid

notes:
    - This module handles individual Nodegrid NAT rules for the following chains: PREROUTING, INPUT, OUTPUT, POSTROUTING, and user-defined.

options:
  action:
    description:
      - Set the action to be performed for a rule into a chain.
      - Only applicable for chain rules, not for chain policy.
    type: str
    choices: [ append, insert, modify ]
    default: append
  state:
    description:
      - Whether the rule should be absent or present.
      - Only applicable for chain rules, not for chain policy.
    type: str
    choices: [ present, absent ]
    default: present
  chain:
    description:
      - Specify the firewall chain to be configured.
      - It could be any of the built-in chains: V(INPUT), V(OUTPUT), V(PREROUTING), V(POSTROUTING).
      - It could be any user-defined chain.
    type: str
  chain_management:
    description:
      - If V(true) and O(state) is V(present), the chain will be created if needed.
        Any other defined parameter will be ignored.
      - If V(true) and O(state) is V(absent), the chain will be deleted if the only
        other parameter passed are O(chain).
    type: bool
    default: false  
  policy:
    description:
      - Set policy for the chain.
      - Only built-in chains can have policies (i.e., INPUT, OUTPUT, PREROUTING, POSTROUTING).
      - This parameter requires the O(chain) parameter.
      - If you specify this parameter, all other parameters will be ignored.
      - This parameter is used to set the default policy for the given O(chain).
    type: str
    choices: [ ACCEPT, DROP ]
  flush:
    description:
      - Flushes all the rules from the specified chain.
      - This parameter requires the O(chain) parameter.
      - If you specify this parameter, all other parameters will be ignored.
    type: bool
    default: false
  target:
    description:
      - Set the chain rule target.
      - For the built-in chains, the targets are:
        - PREROUTING: ACCEPT, DNAT, LOG, REDIRECT, RETURN.
        - INPUT: ACCEPT, LOG, RETURN, SNAT.
        - OUTPUT: ACCEPT, DNAT, LOG, REDIRECT, RETURN.
        - POSTROUTING: ACCEPT, LOG, MASQUERADE, RETURN, SNAT.
      - It can be any user-defined chain.
    type: str
  rule_number:
    description:
      - Set the rule number in the chain. This number defines the rule's relative position and its precedence (lower number implies higher precedence).
      - This parameter requires the O(action) set to V(insert).
      - Number must be greater or equal to 0.
    type: str
    defautl: ''
  description:
    description:
      - Set the rule description.
    type: str
    defautl: ''
  source_net4:
    description:
      - Set the IPv4 source network.
    type: str
    defautl: ''
  destination_net4:
    description:
      - Set the IPv4 destination network.
    type: str
    defautl: ''
  source_mac_address:
    description:
      - Set the source MAC address.
    type: str
    defautl: ''
  protocol:
    description:
      - Set the protocol of the rule or of the packet to check.
      - The specified protocol can be one of V(tcp), V(udp), V(icmp), V(numeric).
    type: str
    choices: [ numeric, icmp, tcp, udp ]
    default: numeric
  protocol_number:
    description:
      - Set the rule protocol based on an number.
      - This parameter requires the O(protocol) set to V(numeric).
      - Protocol numbers for reference C(/etc/protocols).
    type: srt
    default: ''
  source_port:
    description:
      - Specify the TCP source port.
      - This parameter requires the O(protocol) set to V(tcp).
    type: srt
    default: ''
  destination_port:
    description:
      - Specifies TCP destination port.
      - This parameter requires the O(protocol) set to V(tcp).
    type: srt
    default: ''
  tcp_flag_syn:
    description:
      - Set the TCP SYN flags.
      - This parameter requires the O(protocol) set to V(tcp).
    type: srt
    choices: [ any, set, unset ]
    default: any
  tcp_flag_ack:
    description:
      - Set the TCP ACK flags.
      - This parameter requires the O(protocol) set to V(tcp).
    type: srt
    choices: [ any, set, unset ]
    default: any
  tcp_flag_fin:
    description:
      - Set the TCP FIN flags.
      - This parameter requires the O(protocol) set to V(tcp).
    type: srt
    choices: [ any, set, unset ]
    default: any
  tcp_flag_rst:
    description:
      - Set the TCP RST flags.
      - This parameter requires the O(protocol) set to V(tcp).
    type: srt
    choices: [ any, set, unset ]
    default: any
  tcp_flag_urg:
    description:
      - Set the TCP URG flags.
      - This parameter requires the O(protocol) set to V(tcp).
    type: srt
    choices: [ any, set, unset ]
    default: any
  tcp_flag_psh:
    description:
      - Set the TCP PSH flags.
      - This parameter requires the O(protocol) set to V(tcp).
    type: srt
    choices: [ any, set, unset ]
    default: any
  source_udp_port:
    description:
      - Specify the UDP source port.
      - This parameter requires the O(protocol) set to V(udp).
    type: srt
    default: ''
  destination_udp_port:
    description:
      - Specify the UDP destination port.
      - This parameter requires the O(protocol) set to V(udp).
    type: srt
    default: ''
  icmp_type:
    description:
      - Set the ICMP type of message.
      - This parameter requires the O(protocol) set to V(icmp).
    type: srt
    choices: [ tos_host_redirect, tos_host_unreachable, tos_network_redirect, tos_network_unreachable, address_mask_reply, address_mask_request, any, communication_prohibited, destination_unreachable, echo_reply, echo_request, fragmentation_needed, host_precedence_violation, host_prohibited, host_redirect, host_unknown, host_unreachable, bad_ip_header, network_prohibited, network_redirect, network_unknown, network_unreachable, parameter_problem, port_unreachable, precedence_cutoff, protocol_unreachable, redirect, required_option_missing, router_advertisement, router_solicitation, source_quench, source_route_failed, time_exceeded, timestamp_reply, timestamp_request, ttl_zero_during_reassembly, ttl_zero_during_transit ]
    default: 'any'
  input_interface:
    description:
      - Name of an interface via which a packet was received (only for packets
        entering the V(INPUT) and V(PREROUTING) chains or a user-defined chain).
      - If this option is omitted, any interface name will match.
    type: srt
    default: ''
  output_interface:
    description:
      - Name of an interface via which a packet is going to be sent (for
        packets entering the V(OUTPUT), and V(POSTROUTING) chains or a user-defined chain).
      - If this option is omitted, any interface name will match.
    type: srt
    default: ''
  fragments:
    description:
      - This means that the rule only refers to second and further fragments of fragmented packets.
      - Since there is no way to tell the source or destination ports of such
        a packet (or ICMP type), such a packet will not match any rules which specify them.
    type: srt
    choices: [ all_packets_and_fragments, unfragmented_packets_and_1st_packets, 2nd_and_further_packets ]
    default: all_packets_and_fragments
  reverse_match_for_source_ip_mask:
    description:
      - Reverse criteria option for O(source_net4).
    type: srt
    choices: [ yes, no ]
    default: no
  reverse_match_for_destination_ip_mask:
    description:
      - Reverse criteria option for O(destination_net4).
    type: srt
    choices: [ yes, no ]
    default: no
  reverse_match_for_source_mac_address:
    description:
      - Reverse criteria option for O(source_mac_address).
    type: srt
    choices: [ yes, no ]
    default: no
  reverse_match_for_protocol:
    description:
      - Reverse criteria option for O(protocol).
    type: srt
    choices: [ yes, no ]
    default: no
  reverse_match_for_source_port:
    description:
      - Reverse criteria option for O(source_port).
      - This parameter requires the O(protocol) set to V(tcp).
    type: srt
    choices: [ yes, no ]
    default: no
  reverse_match_for_destination_port:
    description:
      - Reverse criteria option for O(destination_port).
      - This parameter requires the O(protocol) set to V(tcp).
    type: srt
    choices: [ yes, no ]
    default: no
  reverse_match_for_tcp_flags:
    description:
      - Reverse criteria option for O(tcp_flags).
      - This parameter requires the O(protocol) set to V(tcp).
    type: srt
    choices: [ yes, no ]
    default: no
  reverse_match_for_icmp_type:
    description:
      - Reverse criteria option for O(icmp_type).
      - This parameter requires the O(protocol) set to V(icmp).
    type: srt
    choices: [ yes, no ]
    default: no
  reverse_match_for_input_interface:
    description:
      - Reverse criteria option for O(input_interface).
    type: srt
    choices: [ yes, no ]
    default: no
  reverse_match_for_output_interface:
    description:
      - Reverse criteria option for O(output_interface).
    type: srt
    choices: [ yes, no ]
    default: no
  enable_state_match:
    description:
      - Enable connection tracking based on the following connection states: NEW, ESTABLISHED, RELATED, INVALID, SNAT, DNAT.
      - When O(enable_state_match) is set to V(yes), at least one of the parametes O(new), O(established), O(related), O(invalid), O(snat), O(dnat)
        is required to be set to V(yes).
    type: srt
    choices: [ yes, no ]
    default: no
  new:
    description:
      - Enable tracking a packet that has started a ne connectionm, or otherwise associated with a connection 
        which has not seen packets in both directions.
      - This parameter requires the O(enable_state_match) set to V(yes).
    type: srt
    choices: [ yes, no ]
    default: no
  established:
    description:
      - Enable tracking packets that are associated wi a known connection that has seen packets in both directions.
      - This parameter requires the O(enable_state_match) set to V(yes).
    type: srt
    choices: [ yes, no ]
    default: no
  related:
    description:
      - Enable tracking a packet that is starting a new connection, but is associated win an existing connection, such 
        as an FTP data transfer, or an ICMP error.
      - This parameter requires the O(enable_state_match) set to V(yes).
    type: srt
    choices: [ yes, no ]
    default: no
  invalid:
    description:
      - Enable tracking packets not associated with no known connections.
      - This parameter requires the O(enable_state_match) set to V(yes).
    type: srt
    choices: [ yes, no ]
    default: no
  snat:
    description:
      - Enable tracking connections that need SRC NAT in the original direction.
      - This parameter requires the O(enable_state_match) set to V(yes).
    type: srt
    choices: [ yes, no ]
    default: no
  dnat:
    description:
      - Enable tracking connections that need DST NAT in the original direction.
      - This parameter requires the O(enable_state_match) set to V(yes).
    type: srt
    choices: [ yes, no ]
    default: no
  reverse_state_match:
    description:
      - Reverse criteria option for O(enable_state_match) and related state parameters.
      - This parameter requires the O(enable_state_match) set to V(yes).
    type: srt
    choices: [ yes, no ]
    default: no
  reject_with:
    description:
      - Reject message.
    type: srt
    choices: [ administratively_prohibited, host_prohibited, host_unreacheable, network_prohibited, network_unreacheable, port_unreacheable, protocol_unreacheable, tcp_reset ]
    default: port_unreacheable
  log_level:
    description:
      - Logging level according to the syslogd-defined priorities.
    type: srt
    choices: [ alert, critical, debug, emergency, error, info, notice, warning]
    default: debug
  log_prefix:
    description:
      - Specifies a log text prefix for the rule.
    type: srt
    default: ''
  log_tcp_sequence_numbers:
    description:
      - Log the TCP sequence numbers.
    type: srt
    choices: [ yes, no ]
    default: no
  log_options_from_the_tcp_packet_header:
    description:
      - Log the options from the TCP packet header.
    type: srt
    choices: [ yes, no ]
    default: no
  log_options_from_the_ip_packet_header:
    description:
      - Log the options from the IP packet header.
    type: srt
    choices: [ yes, no ]
    default: no
  debug:
    description:
      - Debug mode. Shows the executed commands on the output.
    type: bool
    default: false
  timeout:
    description:
      - Timeout time for cli commands when executed.
    type: int
    default: 60
'''

EXAMPLES = r'''

- name: Flush INPUT chain
  zpe.nodegrid.natv2:
    chain: INPUT
    flush: yes
- name: Flush OUTPUT chain
  zpe.nodegrid.firewallv2:
    chain: OUTPUT
    flush: yes
- name: Flush PREROUTING chain
  zpe.nodegrid.firewallv2:
    chain: PREROUTING
    flush: yes

- name: Create Chain DOCKER
  zpe.nodegrid.natv2:
    chain: DOCKER
    chain_management: yes

- name: Delete Chain DOCKER
  zpe.nodegrid.natv2:
    chain: DOCKER
    state: absent
    chain_management: yes

- name: Flush chain DOCKER
  zpe.nodegrid.natv2:
    chain: DOCKER
    flush: yes

- name: Configure NAT, INPUT chain
  block:
  - name: Apply INPUT Policy
    zpe.nodegrid.natv2:
      chain: INPUT
      policy: ACCEPT
  - name: Define Rule 0
    zpe.nodegrid.natv2:
      debug: yes
      state: present # present, absent
      chain: input
      action: insert # insert, append, modify
      target: ACCEPT
      rule_number: 0
      input_interface: lo
      enable_state_match: yes
      new: yes
      snat: no
      reverse_state_match: yes
      description: RULE_0
- name: Configure NAT, user defined LIBVIRT chain
  block:
  - name: Create the LIBVIRT chain
    zpe.nodegrid.natv2:
      chain: LIBVIRT
      state: present
      chain_management: yes
  - name: Define Rule 0
    zpe.nodegrid.natv2:
      chain: LIBVIRT
      action: insert
      state: present
      target: ACCEPT
      rule_number: 0
      input_interface: eth0
      description: eth0_rule
- name: Configure NAT, PREROUTING chain
  block:
  - name: Apply PREROUTING Policy
    zpe.nodegrid.natv2:
      chain: PREROUTING
      policy: ACCEPT
  - name: Append a rule
    zpe.nodegrid.natv2:
      state: present # present, absent
      chain: prerouting
      action: insert # insert, append, modify
      target: ACCEPT
      rule_number: 0
      input_interface: eth0
      enable_state_match: yes
      new: yes
      related: yes
      reverse_state_match: no
      description: RULE_0_PREROUTING
- name: Configure NAT, POSTROUTING chain
  block:
  - name: Apply POSTROUTING Policy
    zpe.nodegrid.natv2:
      chain: POSTROUTING
      policy: ACCEPT
  - name: Append a rule
    zpe.nodegrid.natv2:
      state: present # present, absent
      chain: postrouting
      action: append # insert, append, modify
      target: MASQUERADE
      output_interface: eth0
      enable_state_match: yes
      snat: yes
      description: RULE_0_POSTROUTING

'''

RETURN = r'''

'''

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.zpe.nodegrid.plugins.module_utils.nodegrid_util import get_cli, close_cli, execute_cmd, check_os_version_support, dict_diff

import os
from collections import OrderedDict

BUILTIN_CHAINS = ["PREROUTING", "INPUT", "OUTPUT", "POSTROUTING"]
TARGET_DEFAULTS ={
    "PREROUTING": ["ACCEPT", "DNAT", "LOG", "REDIRECT", "RETURN"],
    "INPUT": ["ACCEPT", "LOG", "RETURN", "SNAT"],
    "OUTPUT": ["ACCEPT", "DNAT", "LOG", "REDIRECT", "RETURN"],
    "POSTROUTING": ["ACCEPT", "LOG", "MASQUERADE", "RETURN", "SNAT"]
} 

ALL_TARGET_DEFAULTS = set()
for chain in TARGET_DEFAULTS:
    for target in TARGET_DEFAULTS[chain]:
        ALL_TARGET_DEFAULTS.add(target)

TARGET_DEFAULTS["user-chain"] = [target for target in ALL_TARGET_DEFAULTS]

# We have to remove the SID from the Environmental settings, to avoid an issue
# were we can not run pexpect.run multiple times
if "DLITF_SID" in os.environ:
    del os.environ["DLITF_SID"]
if "DLITF_SID_ENCRYPT" in os.environ:
    del os.environ["DLITF_SID_ENCRYPT"]


def get_chains_present(table, timeout=60) -> dict:
    cmd_cli = get_cli(timeout=timeout)
    #build cmd
    cmd = {
        'cmd' : f"show /settings/{table}/chains"
    }
    cmd_result = execute_cmd(cmd_cli, cmd)
    data = dict(error=False, chains=[], user_chains=[], msg='')
    if cmd_result['error']:
        return dict(error=True, msg=f"Cannot get present chains in firewall. Error: {cmd_result['error']}")
    else:
        for item in cmd_result['json']:
            for chain in item['data']:
                if 'chain' in chain.keys():
                    data['chains'].append(chain['chain'])
                    if not chain['chain'] in BUILTIN_CHAINS:
                        data['user_chains'].append(chain['chain'])
    close_cli(cmd_cli)
    return data


def create_chain(table, chain):
    cmds = []
    cmds.append(dict(cmd=f"add /settings/{table}/chains/"))
    cmds.append(dict(cmd=f"set chain={chain}"))
    return cmds


def delete_chain(table, chain):
    cmds = []
    cmds.append(dict(cmd=f"delete /settings/{table}/chains/ {chain}", confirm=True))
    return cmds


def get_chain_policy(table, chain, timeout=60) -> dict:
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


def get_rules_present(table, chain, timeout=60) -> dict:
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


def resort_rule(rule: dict, sort_list: list):
    new_rule = OrderedDict()
    for key in sort_list:
        if key in rule.keys():
            new_rule[key] = rule[key]
            rule.pop(key)
    new_rule = {**new_rule, **rule}
    return new_rule


def create_rule(params, chain, sort_list):
    if chain in BUILTIN_CHAINS:
        keys_to_exclude = ['action', 'state', 'chain', 'policy', 'debug', 'chain_management']
    else:
        keys_to_exclude = ['action', 'state', 'chain', 'policy', 'debug', 'chain_management', 'reverse_match_for_source_mac_address']
    rule = {key:value for key, value in params.items() if key not in keys_to_exclude }
    return resort_rule(rule, sort_list)


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
            'tcp': ['source_port', 'destination_port', 'tcp_flag_syn', 'tcp_flag_ack', 'tcp_flag_fin', 'tcp_flag_rst', 'tcp_flag_urg', 'tcp_flag_psh', 'to_ports'],
            'udp': ['source_udp_port', 'destination_udp_port', 'to_ports'],
            'icmp': ['icmp_type']
        },
        'enable_state_match': ['new', 'established', 'related', 'invalid', 'snat', 'dnat', 'reverse_state_match'],
    }

    chain_dependencies = {
        "PREROUTING": ["source_mac_address", "to_ports", "input_interface", "reverse_match_for_source_mac_address", "reverse_match_for_input_interface"],
        "INPUT": ["source_mac_address", "input_interface", "reverse_match_for_source_mac_address", "reverse_match_for_input_interface"],
        "OUTPUT": ["to_ports", "output_interface", "reverse_match_for_output_interface"],
        "POSTROUTING": ["to_ports", "output_interface", "reverse_match_for_output_interface"],
        "user-chain": ["to_ports", "input_interface", "output_interface", "reverse_match_for_input_interface", "reverse_match_for_output_interface"],
    }

    _chain = chain if chain in BUILTIN_CHAINS else "user-chain"
    all_chain_dependencies = set()
    for a_chain in chain_dependencies:
        for setting in chain_dependencies[a_chain]:
            all_chain_dependencies.add(setting)
    for setting in chain_dependencies[_chain]:
        all_chain_dependencies.discard(setting)

    rename_settings = {
        'reverse_match_for_source_ip_mask': 'reverse_match_for_source_ip|mask',
        'reverse_match_for_destination_ip_mask': 'reverse_match_for_destination_ip|mask'
    }

    for dependency in dependencies:
        if isinstance(dependencies[dependency], dict):
            for dep_rem in {key:value for key, value in dependencies[dependency].items() if key not in [new_rule[dependency]]}:
                for setting in dependencies[dependency][dep_rem]:
                    if not setting in dependencies[dependency][new_rule[dependency]]:
                        new_rule.pop(setting, None)
        elif isinstance(dependencies[dependency], list) and new_rule[dependency].lower() == "no":
            for setting in dependencies[dependency]:
                new_rule.pop(setting, None)

    for setting in all_chain_dependencies:
        new_rule.pop(setting)

    cmds.append(dict(cmd=f"cd /settings/{table}/chains/{chain}/"))
    cmds.append(dict(cmd="add"))
    for setting in new_rule:
        if new_rule[setting] and len(str(new_rule[setting]).strip()) > 0:
            if setting in rename_settings:
                cmds.append(dict(cmd=f"set {rename_settings[setting]}={new_rule[setting].replace(' ','_')}"))
            else:
                cmds.append(dict(cmd=f"set {setting}={new_rule[setting].replace(' ','_')}"))
    return new_rule, cmds


def append_rule(table, chain, new_rule):
    cmds = []
    new_rule.pop("rule_number", None)
    dependencies = {
        'protocol': {
            'numeric': ['protocol_number'],
            'tcp': ['source_port', 'destination_port', 'tcp_flag_syn', 'tcp_flag_ack', 'tcp_flag_fin', 'tcp_flag_rst', 'tcp_flag_urg', 'tcp_flag_psh'],
            'udp': ['source_udp_port', 'destination_udp_port'],
            'icmp': ['icmp_type']
        },
        'enable_state_match': ['new', 'established', 'related', 'invalid', 'snat', 'dnat', 'reverse_state_match'],
    }

    chain_dependencies = {
        "PREROUTING": ["source_mac_address", "to_ports", "input_interface", "reverse_match_for_source_mac_address", "reverse_match_for_input_interface"],
        "INPUT": ["source_mac_address", "input_interface", "reverse_match_for_source_mac_address", "reverse_match_for_input_interface"],
        "OUTPUT": ["to_ports", "output_interface", "reverse_match_for_output_interface"],
        "POSTROUTING": ["to_ports", "output_interface", "reverse_match_for_output_interface"],
        "user-chain": ["to_ports", "input_interface", "output_interface", "reverse_match_for_input_interface", "reverse_match_for_output_interface"]
    }

    _chain = chain if chain in BUILTIN_CHAINS else "user-chain"
    all_chain_dependencies = set()
    for a_chain in chain_dependencies:
        for setting in chain_dependencies[a_chain]:
            all_chain_dependencies.add(setting)
    for setting in chain_dependencies[_chain]:
        all_chain_dependencies.discard(setting)

    rename_settings = {
        'reverse_match_for_source_ip_mask': 'reverse_match_for_source_ip|mask',
        'reverse_match_for_destination_ip_mask': 'reverse_match_for_destination_ip|mask'
    }

    for dependency in dependencies:
        if isinstance(dependencies[dependency], dict):
            for dep_rem in {key:value for key, value in dependencies[dependency].items() if key not in [new_rule[dependency]]}:
                for setting in dependencies[dependency][dep_rem]:
                    if not setting in dependencies[dependency][new_rule[dependency]]:
                        new_rule.pop(setting, None)
        elif isinstance(dependencies[dependency], list) and new_rule[dependency].lower() == "no":
            for setting in dependencies[dependency]:
                new_rule.pop(setting, None)

    for setting in all_chain_dependencies:
        new_rule.pop(setting)

    cmds.append(dict(cmd=f"cd /settings/{table}/chains/{chain}/"))
    cmds.append(dict(cmd="add"))
    for setting in new_rule:
        if new_rule[setting] and len(str(new_rule[setting]).strip()) > 0:
            if setting in rename_settings:
                cmds.append(dict(cmd=f"set {rename_settings[setting]}={new_rule[setting].replace(' ','_')}"))
            else:
                cmds.append(dict(cmd=f"set {setting}={new_rule[setting].replace(' ','_')}"))
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
            cmds.append(dict(cmd=f"set {setting}={diff_state[setting].replace(' ','_')}"))
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
    module_args = OrderedDict(
        action=dict(type='str'),
        debug=dict(type='bool', default=False),
        timeout=dict(type=int, default=60),
        flush=dict(type='bool', default=False),
        state=dict(type='str', default='present', choices=['absent', 'present']),
        chain=dict(type='str'),
        chain_management=dict(type='bool', default=False),
        policy=dict(type='str', choices=['ACCEPT', 'DROP']),
        target=dict(type='str'),
        rule_number=dict(type='str', default=''),
        description=dict(type='str', default=''),
        source_net4=dict(type='str', default=''),
        destination_net4=dict(type='str', default=''),
        source_mac_address=dict(type='str', default=''), # PREROUTING, INPUT
        protocol=dict(type='str', default='numeric', choices=['numeric', 'icmp', 'tcp', 'udp']),
        # protocol=numeric
        protocol_number=dict(type='str', default=''),
        # protocol=tcp
        source_port=dict(type='str', default=''),
        destination_port=dict(type='str', default=''),
        #to_ports=dict(type='str', default=''), # PREROUTING, OUTPUT, POSTROUTING, user-chain: this parameter works for both protocol=tcp and protocol=udp
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
        to_ports=dict(type='str', default=''), # PREROUTING, OUTPUT, POSTROUTING, user-chain: this parameter works for both protocol=tcp and protocol=udp
        # protocol=icmp
        icmp_type=dict(type='str', default='any', choices=['any', 'tos_host_redirect', 'tos_host_unreachable', 'tos_network_redirect', 'tos_network_unreachable', 'address_mask_reply', 'address_mask_request', 'any', 'communication_prohibited', 'destination_unreachable', 'echo_reply', 'echo_request', 'fragmentation_needed', 'host_precedence_violation', 'host_prohibited', 'host_redirect', 'host_unknown', 'host_unreachable', 'bad_ip_header', 'network_prohibited', 'network_redirect', 'network_unknown', 'network_unreachable', 'parameter_problem', 'port_unreachable', 'precedence_cutoff', 'protocol_unreachable', 'redirect', 'required_option_missing', 'router_advertisement', 'router_solicitation', 'source_quench', 'source_route_failed', 'time_exceeded', 'timestamp_reply', 'timestamp_request', 'ttl_zero_during_reassembly', 'ttl_zero_during_transit']),       
        input_interface=dict(type='str', default='any'), # PREROUTING, INPUT, user-chain
        output_interface=dict(type='str', default='any'), # OUTPUT, POSTROUTING, user-chain
        fragments=dict(type='str', default='all_packets_and_fragments', choices=['all_packets_and_fragments', 'unfragmented_packets_and_1st_packets', '2nd_and_further_packets']),
        reverse_match_for_source_ip_mask=dict(type='str', default='no', choices=['yes', 'no']),
        reverse_match_for_destination_ip_mask=dict(type='str', default='no', choices=['yes', 'no']),
        reverse_match_for_source_mac_address=dict(type='str', default='no', choices=['yes', 'no']), # PREROUTING, INPUT, NO user-chain
        reverse_match_for_source_port=dict(type='str', default='no', choices=['yes', 'no']),
        reverse_match_for_destination_port=dict(type='str', default='no', choices=['yes', 'no']),
        reverse_match_for_protocol=dict(type='str', default='no', choices=['yes', 'no']),
        reverse_match_for_tcp_flags=dict(type='str', default='no', choices=['yes', 'no']),
        reverse_match_for_icmp_type=dict(type='str', default='no', choices=['yes', 'no']),
        reverse_match_for_input_interface=dict(type='str', default='no', choices=['yes', 'no']), # PREROUTING, INPUT, user-chain
        reverse_match_for_output_interface=dict(type='str', default='no', choices=['yes', 'no']), # OUTPUT, POSTROUTING, user-chain
        enable_state_match=dict(type='str', default='no', choices=['yes', 'no']),
        # enable_state_match=yes
        new=dict(type='str', default='no', choices=['yes', 'no']),
        established=dict(type='str', default='no', choices=['yes', 'no']),
        related=dict(type='str', default='no', choices=['yes', 'no']),
        invalid=dict(type='str', default='no', choices=['yes', 'no']),
        snat=dict(type='str', default='no', choices=['yes', 'no']),
        dnat=dict(type='str', default='no', choices=['yes', 'no']),
        reverse_state_match=dict(type='str', default='no', choices=['yes', 'no']),

        to_source=dict(type='str', default=''),
        to_destination=dict(type='str', default=''),
        #reject_with=dict(type='str', default='port_unreacheable', choices=['administratively_prohibited', 'host_prohibited', 'host_unreacheable', 'network_prohibited', 'network_unreacheable', 'port_unreacheable', 'protocol_unreacheable', 'tcp_reset']),
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
    table = "ipv4_nat"

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
    timeout = int(module.params.pop('timeout', 60))
    debug = module.params.pop('debug', False)

    # Lets get the current status and check if it must be changed
    res, err_msg, nodegrid_os = check_os_version_support()
    if res == 'error' or res == 'unsupported':
        module.fail_json(msg=err_msg, **result)
    elif res == 'warning':
        result['warning'] = err_msg

    # Check chain
    chain_management = module.params['chain_management']
    get_chains = get_chains_present(table=table)
    if get_chains['error']:
        module.fail_json(msg=f"Error on getting the list of present chains. Error: {get_chains[msg]}")
    chains = get_chains["chains"]
    user_chains = get_chains["user_chains"]
    chain_is_present = True if result['chain'] in chains else False
    if not result['chain'] in chains and not chain_management:
        module.fail_json(msg=f"Chain '{result['chain']}' does not exist. To create it, set the parameter 'chain_management' to yes")

    # Check action 'insert'
    if module.params['action'] == 'insert' and not module.params["rule_number"].isdigit():
        module.fail_json(msg="Action 'insert' requires a 'rule_number', which must be an integer greater or equal to 0.")
    # Check action 'modify'
    if module.params['action'] == 'modify' and not module.params["rule_number"].isdigit():
        module.fail_json(msg="Action 'modify' requires a 'rule_number', which must be an integer greater or equal to 0.")
    # Check action 'append'
    if module.params['action'] == 'append' and module.params['rule_number'].strip() != "":
        module.fail_json(msg="Action 'append' does not requires a 'rule_number'.")

    # Build out commands
    cmds = []
    diff_state = dict()
    flush = module.params['flush']
    should_be_present = (result['state'] == 'present')
    
    # Set the policy
    if module.params['policy']:
        if result['state'] == 'absent' and result['chain'] in BUILTIN_CHAINS:
            module.fail_json(msg=f"Chain {module.params['chain']} cannot be deleted!")
        if not result['chain'] in BUILTIN_CHAINS:
            module.fail_json(msg=f"A policy cannot be set for chain {module.params['chain']}")
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
    elif chain_management:
        if not chain_is_present and should_be_present:
            cmds.extend(create_chain(table=table, chain=module.params['chain']))
        elif chain_is_present and not should_be_present:
            cmds.extend(delete_chain(table=table, chain=module.params['chain']))
    else:
        if not module.params['action']:
            if module.params["rule_number"].isdigit():
                module.params['action'] = 'insert'
            else:
                module.params['action'] = 'append'
        elif not module.params['action'] in ['append', 'insert', 'modify']:
            module.fail_json(msg=f"Rule action '{module.params['action']}' incorrect. Valid options are: append, insert, modify.")
        if not module.params['chain'] in chains:
            module.fail_json(msg=f"Chain '{module.params['chain']}' does not exits. Current chains are: {chains}. To create a chain, set the parameter 'chain_management' to yes")

        if module.params['target'] is None:
            module.params['target'] = "ACCEPT"
        elif module.params['chain'] in BUILTIN_CHAINS:
            if not module.params['target'] in TARGET_DEFAULTS[module.params['chain']] + [i for i in user_chains if i != module.params['chain']]:
                module.fail_json(msg=f"Rule target '{module.params['target']}' incorrect. Valid values include: {TARGET_DEFAULTS[module.params['chain']] + [i for i in user_chains if i != module.params['chain']]}")
        elif not module.params['chain'] in BUILTIN_CHAINS:
            if not module.params['target'] in TARGET_DEFAULTS['user-chain'] + [i for i in user_chains if i != module.params['chain']]:
                module.fail_json(msg=f"Rule target '{module.params['target']}' incorrect. Valid values include: {TARGET_DEFAULTS['user-chain'] + [i for i in user_chains if i != module.params['chain']]}")

        insert = (module.params['action'] == 'insert')
        modify = (module.params['action'] == 'modify')
        append = (module.params['action'] == 'append')
        rules_present = get_rules_present(table=table, chain=module.params['chain'], timeout=timeout)
        if rules_present.get('error', False):
            module.fail_json(msg=rules_present.get('msg'))        
        parsed_rule = create_rule(params=module.params, chain=module.params['chain'], sort_list=[key for key in module_args])

        # Build the modifications
        if should_be_present:
            # If insert: check if rule_number is within range
            if insert and int(parsed_rule['rule_number']) > len(rules_present['rules']):
                module.fail_json(msg=f"Rule insert error: rule number {module.params.get('rule_number', None)} is out of bounds. Current rules range from: 0,...,{len(rules_present['rules'])-1}.")
            # If modify: check if rule_number is within range
            if modify and int(parsed_rule['rule_number']) > len(rules_present['rules'])-1:
                module.fail_json(msg=f"Rule modify error: rule number {module.params.get('rule_number', None)} is out of bounds. Current rules range from: 0,...,{len(rules_present['rules'])-1}.")

            if modify:
                rule_is_present = True
                rule_present = rules_present['rules'][int(parsed_rule['rule_number'])]
                result['changed'] = rule_is_present
            else:
                rule_is_present, rule_present = check_rule_present(rules=rules_present['rules'], new_rule=parsed_rule, is_insert=insert)
                result['changed'] = (rule_is_present != should_be_present)

            if insert:
                diff_state, cmds = insert_rule(table=table, chain=module.params['chain'], new_rule=parsed_rule)
            elif modify:
                diff_state, cmds = update_rule(table=table, chain=module.params['chain'], rule=rule_present, new_rule=parsed_rule)
            elif append:
                diff_state, cmds = append_rule(table=table, chain=module.params['chain'], new_rule=parsed_rule)
        else:
            if module.params["rule_number"].isdigit() and int(parsed_rule['rule_number']) < len(rules_present['rules']):
                rule_is_present, rule_present = check_rule_present(rules=rules_present['rules'], new_rule=parsed_rule, is_insert=True)
                if rule_is_present:
                    cmds.extend(delete_rule(table=table, chain=module.params['chain'], rule=rule_present))
                    diff_state = cmds[-1]['cmd']
                    result['changed'] = True
            elif module.params["rule_number"] == '': 
                rule_is_present, rule_present = check_rule_present(rules=rules_present['rules'], new_rule=parsed_rule, is_insert=False)
                if rule_is_present:
                    cmds.extend(delete_rule(table=table, chain=module.params['chain'], rule=rule_present))
                    diff_state = cmds[-1]['cmd']
                    result['changed'] = True
            
    if result['changed'] is False:
        module.exit_json(**result)

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
