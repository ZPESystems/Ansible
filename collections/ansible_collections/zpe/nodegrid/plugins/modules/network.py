#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2023, ZPE Systems <zpesystems.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r'''
module: network
author: Rene Neumann (@zpe-rneumann)
short_description: This module handles network details on Nodegrid OS
version_added: "1.0.0"
description: The module is used to manage the Network options on Nodegrid OS 5.6 or newer
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
    connections:
        description: Set of settings of one network interface connection
        required: True
        type: dict
        suboptions:
            state:
                description: State of the connection
                required: False
                choices: ['up','down', 'exist', 'absent']
                default: 'exist'
                type: str
            name:
                description: Name of the connection
                required: True
                choices: []
                default: 
                type: str
            type:
                description: Type of connection to be used
                required: False
                choices: ['analog_modem', 'bridge', 'loopback', 'pppoe', 'wifi', 'bonding', 'ethernet', 'mobile_broadband_gsm', 'vlan']
                default: 'ethernet'
                type: str
            set_as_primary_connection:
                description: Should this connection be the primary connection, only one connection can be primary
                required: False
                choices: ['yes', 'no']
                default: 'no'
                type: str
            block_unsolicited_incoming_packets:
                description: Enable firewall rules to block incomming packets
                required: False
                choices: ['yes', 'no']
                default: 
                type: str
            connect_automatically:
                description: Enable the connection automatically
                required: False
                choices: ['yes', 'no']
                default: 'yes'
                type: str
            ipv4_mode:
                description: Define the IPv4 mode
                required: False
                choices: ['no_ipv4_address', 'dhcp', 'static']
                default: 'dhcp'
                type: str
            ipv4_address:
                description: Define the IPv4 Address
                required: False
                choices: []
                default: 
                type: str
            ipv4_bitmask:
                description: Define IPv4 Bitmask  i.e. 16 or 24
                required: False
                choices: []
                default: 
                type: str
            ipv4_dns_server:
                description: Define manually a IPv4 dns server address
                required: False
                choices: []
                default: 
                type: str
            ipv4_gateway:
                description: Define a IPv4 gateway address
                required: False
                choices: []
                default: 
                type: str
            ipv4_default_route_metric:
                description: Define a IPv4 default route metric for the connection
                required: False
                choices: []
                default: '100'
                type: str
            ipv4_ignore_obtained_default_gateway:
                description: Define if the default gateway settings which were received through DHCP should be ignored
                required: False
                choices: ['yes', 'no']
                default: 'no'
                type: str
            ipv4_ignore_obtained_dns_server:
                description: Define if the dns server  settings which were received through DHCP should be ignored
                required: False
                choices: ['yes', 'no']
                default: 'no'
                type: str
            ipv6_mode:
                description: Define the IPv6 mode
                required: False
                choices: ['no_ipv6_address', 'address_auto_configuration', 'link-local_only', 'stateful_dhcpv6', 'static']
                default: 'no_ipv6_address'
                type: str
            ipv6_address:
                description: Define the IPv6 Address
                required: False
                choices: []
                default: 
                type: str
            ipv6_prefix_length:
                description: Define IPv6 prefix  i.e. 64 or 128
                required: False
                choices: []
                default: 
                type: str
            ipv6_dns_server:
                description: Define manually a IPv6 dns server address
                required: False
                choices: []
                default: 
                type: str
            ipv6_gateway:
                description: Define a IPv6 gateway address
                required: False
                choices: []
                default: 
                type: str
            ipv6_default_route_metric:
                description: Define a IPv6 default route metric for the connection
                required: False
                choices: []
                default: '100'
                type: str
            ipv6_ignore_obtained_default_gateway:
                description: Define if the default gateway settings which were received through DHCP should be ignored
                required: False
                choices: ['yes', 'no']
                default: 'no'
                type: str
            ipv6_ignore_obtained_dns_server:
                description: Define if the dns server  settings which were received through DHCP should be ignored
                required: False
                choices: ['yes', 'no']
                default: 'no'
                type: str
            enable_ip_passthrough:
                description: Define if IP_Passthrough should be enabled or not
                required: False
                choices: ['yes', 'no']
                default: 'no'
                type: str
            ethernet_connection:
                description: Define the connection name which should be used for IP passthrough
                required: False
                choices: []
                default: 
                type: str
            mac_address:
                description: Define a specific client mac address, client defined will be receiving the forwarded traffic
                required: False
                choices: []
                default: 
                type: str
            port_intercepts:
                description: Define port intercepts which will not be forwarded to the client
                required: False
                choices: []
                default: 
                type: str
            vlan_id:
                description: Define a vlan id for a VLAN connection
                required: False
                choices: []
                default: 
                type: str
            ethernet_interface:
                description: Name of the physical ethernet interface to be used
                required: False
                choices: []
                default: 
                type: str
            enable_lldp:
                description: Enable LLDP on the connection
                required: False
                choices: ['yes', 'no']
                default: 
                type: str
            ethernet_link_mode:
                description: Allow the definition of link mode
                required: False
                choices: ['100m|full', '100m|half', '10m|full', '10m|half', '1g|full', 'auto']
                default: 'auto'
                type: str
            enable_data_usage_monitoring:
                description: Define if data use monitoring is enabled or not
                required: False
                choices: ['yes', 'no']
                default: 'yes'
                type: str
            enable_second_sim_card:
                description: Define if a 2nd SIM card is present for a CELLULAR connection
                required: False
                choices: ['yes', 'no']
                default: 'no'
                type: str
            sim-1_apn_configuration:
                description: SIM 1 APN configuration
                required: False
                choices: ['automatic', 'manual']
                default: 'automatic'
                type: str
            sim-1_mtu:
                description: Defines SIM1 MTU value
                required: False
                choices: []
                default: 'auto'
                type: str
            sim-1_personal_identification_number:
                description: Defines SIM 1 PIN if required for the card
                required: False
                choices: []
                default: 
                type: str
            sim-1_user_name:
                description: Allows definition of SIM1 APN user name for manual configuration
                required: False
                choices: []
                default: 
                type: str
            sim-1_password:
                description: Allows definition of SIM1 APN password for manual configuration
                required: False
                choices: []
                default: 
                type: str
            sim-1_access_point_name:
                description: Allows definition of SIM1 APN for manual configuration
                required: False
                choices: []
                default: 
                type: str
            bridge_interfaces:
                description: Defines the physical interfaces which are used for the bridge interface
                required: False
                choices: []
                default: 
                type: str
            enable_spanning_tree_protocol:
                description: Defines if Spanning Tree should enabled on the bridge interface
                required: False
                choices: ['yes', 'no']
                default: 'yes'
                type: str
            forward_delay:
                description: Defines STP forwarding delay setting on the bridge interface
                required: False
                choices: []
                default: '5'
                type: str
            hello_time:
                description: Defines STP hello time setting on the bridge interface
                required: False
                choices: []
                default: '2'
                type: str
            max_age:
                description: Defines STP max time setting on the bridge interface
                required: False
                choices: []
                default: '20'
                type: str

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

def run_option_network_settings(option, run_opt):
    suboptions = option['suboptions']
    # Delete option set_as_primary_connection if set to no 
    if 'enable_network_failover' in suboptions and suboptions['enable_network_failover'] == "no":
        suboptions.pop('enable_network_failover', None)
    return run_option(option, run_opt)


def run_option_network_connections(option, run_opt):
    # Settings to be deleted/discarded if empty
    settings_to_delete_if_empty = [
        'ipv4_default_route_metric', 
        'ipv6_default_route_metric',
        'sim-1_phone_number',
        'sim-1_apn_configuration',
        'sim-1_user_name',
        'sim-1_password',
        'sim-1_access_point_name',
        'sim-1_personal_identification_number',
        'sim-2_phone_number',
        'sim-2_apn_configuration',
        'sim-2_user_name',
        'sim-2_password',
        'sim-2_access_point_name',
        'sim-2_personal_identification_number'
    ]

    # Settings dependencies
    dependencies = OrderedDict()
    dependencies = {
        'type': 
        {
            'ethernet': 
            [
                'ethernet_interface',
                'enable_lldp',
                'port_id',
                'port_description',
                'mtu',
                'enable_ip_passthrough',
                'ethernet_connection',
                'mac_address',
                'port_intercepts'
            ],
            'bridge': 
            [
                'enable_lldp',
                'port_id',
                'port_description',
                'bridge_interfaces',
                'bridge_mac_configuration',
                'bridge_mac_address',
                'enable_spanning_tree_protocol',
                'hello_time',
                'forward_delay',
                'max_age',
                'ageing_time'
            ],
            'vlan': 
            [
                'ethernet_interface',
                'vlan_id',
                'enable_ip_passthrough',
                'ethernet_connection',
                'mac_address',
                'port_intercepts'
            ],
            'wifi': 
            [
                'ethernet_interface',
                'enable_lldp',
                'port_id',
                'port_description',
                'wifi_ssid',
                'wifi_bssid',
                'hidden_network',
                'wifi_security',
                'psk',
                'wpa2_username',
                'wpa2_password', 
                'wpa2_method',
                'wpa2_phase2_auth',
                'wpa2_validate_server_certificate',
                'enable_ip_passthrough',
                'ethernet_connection',
                'mac_address',
                'port_intercepts'
            ],
            'mobile_broadband_gsm':
            [
                'ethernet_interface',
                'enable_lldp',
                'port_id',
                'port_description',
                'enable_connection_health_monitoring',
                'ensure_connection_is_up',
                'ip_address',
                'interval',
                'sim-1_phone_number',
                'sim-1_apn_configuration',
                'sim-1_user_name',
                'sim-1_password',
                'sim-1_access_point_name',
                'sim-1_personal_identification_number',
                'sim-1_mtu',
                'sim-1_allowed_modes',
                'sim-1_preferred_mode',
                'enable_data_usage_monitoring',
                'sim-1_data_limit_value',
                'sim-1_data_warning',
                'sim-1_renew_day',
                'enable_global_positioning_system',
                'polling_time',
                'gps_antenna',
                'enable_second_sim_card',
                'active_sim_card',
                'sim-2_phone_number',
                'sim-2_apn_configuration',
                'sim-2_user_name',
                'sim-2_password',
                'sim-2_access_point_name',
                'sim-2_personal_identification_number',
                'sim-2_mtu',
                'sim-2_allowed_modes',
                'sim-2_preferred_mode',
                'sim-2_enable_data_usage_monitoring',
                'sim-2_data_limit_value',
                'sim-2_data_warning',
                'sim-2-renew_day',
                'enable_ip_passthrough',
                'ethernet_connection',
                'mac_address',
                'port_intercepts'
            ],
            'bonding':
            [
                'bonding_mode',
                'slaves',
                'link_monitoring',
                'monitoring_frequency',
                'link_up_delay',
                'link_down_delay',
                'system_priority',
                'actor_mac_address',
                'user_port_key',
                'lacp_rate',
                'aggregation_selection_logic',
                'transmit_hash_policy',
                'bond_mac_configuration',
                'bond_fail-over-mac_policy',
                'bond_mac_address'
            ]
        },
        'bond_mac_configuration':
        {
            'bond_fail-over-mac': ['bond_fail-over-mac_policy'],
            'bond_custom_mac': ['bond_mac_address']
        },
        'bridge_mac_configuration':
        {
            'bridge_custom_mac': ['bridge_mac_address'],
            'use_mac_from_first_interface': []
        },
        'wifi_security': 
        { 
            'disabled': [],
            'wpa2_personal': ['psk'],
            'wpa3_personal': ['psk'],
            'wpa2_enterprise': 
            [
                'wpa2_username',
                'wpa2_password',
                'wpa2_method',
                'wpa2_phase2_auth',
                'wpa2_validate_server_certificate'
            ],
        },
        'sim-1_apn_configuration':
        {
            'manual':
            [
                'sim-1_user_name',
                'sim-1_password',
                'sim-1_access_point_name' 
            ],
            'automatic': []
        },
        'sim-2_apn_configuration': 
        {
            'manual': 
            [
                'sim-2_user_name',
                'sim-2_password',
                'sim-2_access_point_name' 
            ],
            'automatic': []
        },
        'ipv4_mode':
        {
            'static': ['ipv4_address', 'ipv4_bitmask', 'ipv4_gateway'],
            'dhcp': [],
            'no_ipv4_address': []
        },
        'ipv6_mode':
        {
            'static': ['ipv6_address', 'ipv6_prefix_length', 'ipv6_gateway'],
            'stateful_dhcpv6': [],
            'link-local_only': [],
            'no_ipv6_address': [],
            'address_auto_configuration': []
        },
        'enable_lldp': 
        [
            'port_id',
            'port_description'
        ],
        'enable_ip_passthrough': 
        [
            'ethernet_connection',
            'mac_address',
            'port_intercepts'
        ],
        'enable_connection_health_monitoring':
        [
            'ensure_connection_is_up',
            'ip_address',
            'interval'
        ],
        'enable_data_usage_monitoring':
        [
            'sim-1_data_limit_value', 
            'sim-1_data_warning', 
            'sim-1_renew_day'
        ],
        'sim-2_enable_data_usage_monitoring':
        [
            'sim-2_data_limit_value', 
            'sim-2_data_warning', 
            'sim-2_renew_day'
        ],
        'enable_global_positioning_system': 
        [
            'polling_time', 
            'gps_antenna'
        ],
        'enable_second_sim_card': 
        [
            'active_sim_card', 
            'sim-2_phone_number', 
            'sim-2_apn_configuration', 
            'sim-2_user_name', 
            'sim-2_password', 
            'sim-2_access_point_name', 
            'sim-2_personal_identification_number', 
            'sim-2_mtu', 
            'sim-2_allowed_modes', 
            'sim-2_preferred_mode', 
            'sim-2_enable_data_usage_monitoring', 
            'sim-2_data_limit_value', 
            'sim-2_data_warning', 
            'sim-2_renew_day'
        ],
    }

    suboptions = option['suboptions']
    check_mode = run_opt['check_mode']
    field_name = 'name'
    if field_exist(suboptions, field_name):
        cli_path =  f"{option['cli_path']}/{suboptions[field_name]}"
        # Lets export the settings to the cli path
        state, exported_settings, exported_all_settings = export_settings(cli_path)
        if not "error" in state:
            if "ethernet_interface" in option['suboptions']:
                del option['suboptions']['ethernet_interface']
        
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
                elif isinstance(dependencies[dependency], list) and dependency in suboptions and suboptions[dependency].lower() == "no":
                    for setting in dependencies[dependency]:
                        settings_tobe_deleted.add(setting)

            # Delete settings not required
            for setting in settings_tobe_deleted:
                suboptions.pop(setting, None)

            # Delete settings that are empty
            for setting in settings_to_delete_if_empty:
                if setting in suboptions and suboptions[setting].strip() == "":
                    suboptions.pop(setting, None)

            # Delete option set_as_primary_connection if set to no 
            if 'set_as_primary_connection' in suboptions and suboptions['set_as_primary_connection'] == "no":
                suboptions.pop('set_as_primary_connection', None)

        except Exception as e:
            return {'failed': True, 'changed': False, 'msg': f"{suboptions} | Key/value error: {e} | {traceback.format_exc()}"}

        return run_option_adding_field_in_the_path(option, run_opt, field_name)
    else:
        return {'failed': True, 'changed': False, 'msg': f"Field '{field_name}' is required"}


def run_module():
    # define available arguments/parameters a user can pass to the module
    module_args = dict(
        settings=dict(type='dict', required=False),
        connection=dict(type='dict', required=False),
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
            'cli_path': '/settings/network_settings',
            'func': run_option_network_settings
        },
        {
            'name': 'connection',
            'suboptions': module.params['connection'],
            'cli_path': '/settings/network_connections',
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
