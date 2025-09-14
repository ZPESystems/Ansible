#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2023, ZPE Systems <zpesystems.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r'''
'''

EXAMPLES = r'''

'''

RETURN = r'''

'''

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.zpe.nodegrid.plugins.module_utils.nodegrid_util import check_os_version_support, run_option, format_settings, field_exist, result_failed, to_list, get_shell, get_cli, close_cli, execute_cmd, read_table, read_table_row


import os, json, pexpect, re
from collections import OrderedDict
import traceback
# Settings dependencies
device_type_not_support_logging = ['usb_device', 'usb_kvm', 'usb_sensor']
device_type_not_support_management = ['usb_device']
managed_device_type = {
    'serial': ['local_serial', 'pdu_cpi_serial'],
    'usb': ['pdu_cpi_serial', 'usb_device', 'usb_kvm', 'usb_sensor', 'usb_serialb'],
    'ip_based': [
        'cimc_ucs', 
        'console_server_acs', 
        'console_server_acs6000', 
        'console_server_digicp', 
        'console_server_lantronix', 
        'console_server_nodegrid', 
        'console_server_opengear', 
        'console_server_perle', 
        'console_server_raritan', 
        'device_console', 
        'door_lock_with_rfid', 
        'drac', 
        'idrac6', 
        'ilo', 
        'ilom', 
        'imm', 
        'infrabox', 
        'intel_bmc', 
        'ipmi_1.5', 
        'ipmi_2.0', 
        'kvm_aten', 
        'kvm_dsr', 
        'kvm_mpu', 
        'kvm_raritan', 
        'netapp', 
        'nodegrid_ap', 
        'openbmc', 
        'pdu_apc', 
        'pdu_austin_hughes', 
        'pdu_baytech', 
        'pdu_cpi', 
        'pdu_cyberpower', 
        'pdu_digital_loggers', 
        'pdu_eaton', 
        'pdu_enconnex', 
        'pdu_geist', 
        'pdu_hpe_g2', 
        'pdu_ice', 
        'pdu_mph2', 
        'pdu_pm3000', 
        'pdu_raritan', 
        'pdu_rittal', 
        'pdu_rnx', 
        'pdu_servertech', 
        'pdu_tripplite', 
        'switch_edgecore', 
        'switch_zpe', 
        'ups_apc', 
        'ups_netagent', 
        'virtual_console_kvm', 
        'virtual_console_vmware'
    ]
}
# Define a set with all types of managed devices
managed_device_types = set([item for sublist in managed_device_type.values() for item in sublist])

# Function to get the managed device family type base on its tipe. Family types: serial, usb, ip_based.
def get_device_type(device_type):
    for family, types in managed_device_type.items():
        if device_type in types:
            return family
    return None

# Managed devices-> Device dependencies
device_dependencies = OrderedDict()
device_dependencies = {
    'type': 
    {
        'local_serial': 
        [
            'name',
            'port_name',
            'type',
            'description',
            'address_location',
            'coordinates',
            'web_url',
            'launch_url_via_html5', # yes, no
            'username',
            'password',
            'baud_rate', #baud_rate options: 115200, 19200, 230400, 38400, 57600, 9600, Auto
            'parity', #parity options: Even, None, Odd
            'flow_control', #flow_control options: Hardware, None, Software
            'data_bits', #data_bits options: 5, 6, 7, 8
            'stop_bits', #stop_bits options: 1, 2
            'rs-232_signal_for_device_state_detection', #rs-232_signal_for_device_state_detection options: Auto, CTS, DCD, None
            'enable_device_state_detection_based_in_data_flow', #enable_device_state_detection_based_in_data_flow options: no, yes
            'data_flow_scan_interval', 
            'enable_hostname_detection', #enable_hostname_detection options: no, yes
            'multisession', #multisession options: no, yes
            'read-write_multisession', #read-write_multisession options: no, yes 
            'enable_serial_port_settings_via_escape_sequence', #enable_serial_port_settings_via_escape_sequence options: no, yes
            'icon', #icon options: 128technology.png, fortinet.png, kvm.png, nodegrid.png, paloalto.png, paloalto2.png, paloaltofirewall.png, raritan.png, servertech.png, air_flow-temperature.png, apc.png, apple_black.png, arista.png, aruba.png, centos.png, cisco_color.png, cloudgenix.png, cpi.png, dell.png, docker.png, door_lock.png, dust_particle.png, emc.png, firewall.png, gpio.png, hp.png, ibm_black.png, juniper.png, linux_black.png, linux_color.png, lxc.png, netapp.png, ocp.png, oracle.png, outlet.png, passcode.png, pdu.png, perle.png, pinconfirm.png, pincode.png, relay.png, rfid_reader.png, router_green.png, schneider.png, sdwan.png, serial_console.png, server.png, server_grey.png, signal_indicator.png, signal_tower.png, storage_blue.png, storage_grey.png, storage_grey_dark.png, supermicro.png, switch.png, switch_purple.png, temperature-humidity.png, terminal.png, ups.png, usb.png, vm.png, vmware.png, windows_black.png, windows_color.png, zpe.png
            'mode', #mode options: disabled, discovered, enabled, on-demand
            'skip_authentication_to_access_device', #skip_authentication_to_access_device options: no, yes
            'skip_authentication_in_ssh_sessions', #skip_authentication_in_ssh_sessions options: no, yes
            'skip_authentication_in_telnet_sessions', #skip_authentication_in_telnet_sessions options: no, yes
            'skip_authentication_in_raw_sessions', #skip_authentication_in_raw_sessions options: no, yes
            'skip_authentication_in_web_sessions', #skip_authentication_in_web_sessions options: no, yes
            'escape_sequence',
            'power_control_key',
            'show_text_information', #show_text_information options: no, yes
            'enable_ip_alias', #enable_ip_alias options: no, yes
            'ip_alias', 
            'interface', 
            'ip_alias_browser_action', #ip_alias_browser_action options: console, web 
            'ip_alias_telnet', #ip_alias_telnet options: no, yes
            'ip_alias_telnet_port', 
            'ip_alias_binary', #ip_alias_binary options: no, yes
            'ip_alias_binary_port', 
            'enable_second_ip_alias', #enable_second_ip_alias options: no, yes
            'sec_ip_alias', 
            'sec_interface', 
            'sec_ip_alias_browser_action', #sec_ip_alias_browser_action options: console, web
            'sec_ip_alias_telnet', #sec_ip_alias_telnet options: no, yes
            'sec_ip_alias_telnet_port', 
            'sec_ip_alias_binary', #sec_ip_alias_binary options: no, yes
            'sec_ip_alias_binary_port', 
            'allow_ssh_protocol', #allow_ssh_protocol options: no, yes
            'ssh_port', 
            'allow_telnet_protocol', #allow_telnet_protocol options: no, yes
            'telnet_port', 
            'allow_binary_socket', #allow_binary_socket options: no, yes
            'tcp_socket_port'
        ],
        'pdu_cpi_serial': 
        [
            'name',
            'port_name',
            'type',
            'description',
            'address_location',
            'coordinates',
            'web_url',
            'launch_url_via_html5', # yes, no
            'username',
            'password',
            'baud_rate', #baud_rate options: 115200, 19200, 230400, 38400, 57600, 9600, Auto
            'parity', #parity options: Even, None, Odd
            'flow_control', #flow_control options: Hardware, None, Software
            'data_bits', #data_bits options: 5, 6, 7, 8
            'stop_bits', #stop_bits options: 1, 2
            'rs-232_signal_for_device_state_detection', #rs-232_signal_for_device_state_detection options: Auto, CTS, DCD, None
            'enable_device_state_detection_based_in_data_flow', #enable_device_state_detection_based_in_data_flow options: no, yes
            'data_flow_scan_interval', 
            'enable_hostname_detection', #enable_hostname_detection options: no, yes
            'multisession', #multisession options: no, yes
            'read-write_multisession', #read-write_multisession options: no, yes 
            'enable_serial_port_settings_via_escape_sequence', #enable_serial_port_settings_via_escape_sequence options: no, yes
            'icon', #icon options: 128technology.png, fortinet.png, kvm.png, nodegrid.png, paloalto.png, paloalto2.png, paloaltofirewall.png, raritan.png, servertech.png, air_flow-temperature.png, apc.png, apple_black.png, arista.png, aruba.png, centos.png, cisco_color.png, cloudgenix.png, cpi.png, dell.png, docker.png, door_lock.png, dust_particle.png, emc.png, firewall.png, gpio.png, hp.png, ibm_black.png, juniper.png, linux_black.png, linux_color.png, lxc.png, netapp.png, ocp.png, oracle.png, outlet.png, passcode.png, pdu.png, perle.png, pinconfirm.png, pincode.png, relay.png, rfid_reader.png, router_green.png, schneider.png, sdwan.png, serial_console.png, server.png, server_grey.png, signal_indicator.png, signal_tower.png, storage_blue.png, storage_grey.png, storage_grey_dark.png, supermicro.png, switch.png, switch_purple.png, temperature-humidity.png, terminal.png, ups.png, usb.png, vm.png, vmware.png, windows_black.png, windows_color.png, zpe.png
            'mode', #mode options: disabled, discovered, enabled, on-demand
            'skip_authentication_to_access_device', #skip_authentication_to_access_device options: no, yes
            'skip_authentication_in_ssh_sessions', #skip_authentication_in_ssh_sessions options: no, yes
            'skip_authentication_in_telnet_sessions', #skip_authentication_in_telnet_sessions options: no, yes
            'skip_authentication_in_raw_sessions', #skip_authentication_in_raw_sessions options: no, yes
            'skip_authentication_in_web_sessions', #skip_authentication_in_web_sessions options: no, yes
            'escape_sequence',
            'power_control_key',
            'show_text_information', #show_text_information options: no, yes
            'enable_ip_alias', #enable_ip_alias options: no, yes
            'ip_alias', 
            'interface', 
            'ip_alias_browser_action', #ip_alias_browser_action options: console, web 
            'ip_alias_telnet', #ip_alias_telnet options: no, yes
            'ip_alias_telnet_port', 
            'ip_alias_binary', #ip_alias_binary options: no, yes
            'ip_alias_binary_port', 
            'enable_second_ip_alias', #enable_second_ip_alias options: no, yes
            'sec_ip_alias', 
            'sec_interface', 
            'sec_ip_alias_browser_action', #sec_ip_alias_browser_action options: console, web
            'sec_ip_alias_telnet', #sec_ip_alias_telnet options: no, yes
            'sec_ip_alias_telnet_port', 
            'sec_ip_alias_binary', #sec_ip_alias_binary options: no, yes
            'sec_ip_alias_binary_port', 
            'allow_ssh_protocol', #allow_ssh_protocol options: no, yes
            'ssh_port', 
            'allow_telnet_protocol', #allow_telnet_protocol options: no, yes
            'telnet_port', 
            'allow_binary_socket', #allow_binary_socket options: no, yes
            'tcp_socket_port'
        ],
        'usb_serialb':
        {
            'name',
            'port_name',
            'type',
            'description',
            'address_location',
            'coordinates',
            'web_url',
            'launch_url_via_html5',
            'username',
            'password',
            'baud_rate',
            'parity',
            'flow_control',
            'data_bits',
            'stop_bits',
            'rs-232_signal_for_device_state_detection',
            'enable_device_state_detection_based_in_data_flow',
            'data_flow_scan_interval',
            'enable_hostname_detection',
            'multisession',
            'read-write_multisession',
            'enable_serial_port_settings_via_escape_sequence',
            'map_to_virtual_machine',
            'virtual_machine_name',
            'icon',
            'mode',
            'skip_authentication_to_access_device',
            'skip_authentication_in_ssh_sessions',
            'skip_authentication_in_telnet_sessions',
            'skip_authentication_in_raw_sessions',
            'skip_authentication_in_web_sessions',
            'escape_sequence',
            'power_control_key',
            'show_text_information',
            'enable_ip_alias',
            'ip_alias',
            'interface',
            'ip_alias_browser_action',
            'ip_alias_telnet',
            'ip_alias_telnet_port',
            'ip_alias_binary',
            'ip_alias_binary_port',
            'enable_second_ip_alias',
            'sec_ip_alias',
            'sec_interface',
            'sec_ip_alias_browser_action',
            'sec_ip_alias_telnet',
            'sec_ip_alias_telnet_port',
            'sec_ip_alias_binary',
            'sec_ip_alias_binary_port',
            'allow_ssh_protocol',
            'ssh_port',
            'allow_telnet_protocol',
            'telnet_port',
            'allow_binary_socket',
            'tcp_socket_port'
        },
        'usb_device':
        {
            'name',
            'port_name',
            'type',
            'description',
            'address_location',
            'coordinates',
            'web_url',
            'launch_url_via_html5',
            'icon',
            'mode',
            'map_to_virtual_machine',
            'virtual_machine_name'
        },
        'usb_sensor':
        {
            'name',
            'port_name',
            'type',
            'description',
            'address_location',
            'coordinates',
            'web_url',
            'launch_url_via_html5',
            'icon',
            'mode',
            'map_to_virtual_machine',
            'virtual_machine_name'
        },
        'usb_kvm':
        {
            'name',
            'port_name',
            'type',
            'description',
            'address_location',
            'coordinates',
            'web_url',
            'launch_url_via_html5',
            'icon',
            'mode',
            'map_to_virtual_machine',
            'virtual_machine_name'
        },
        'ip_based':
        [
            'name',
            'type',
            'description',
            'ip_address',
            'port',
            'address_location',
            'coordinates',
            'web_url',
            'launch_url_via_html5',
            'method',
            'credential',
            'username',
            'password',
            'allow_pre-shared_ssh_key',
            'enable_device_state_detection_based_on_network_traffic',
            'enable_hostname_detection',
            'multisession',
            'read-write_multisession',
            'enable_send_break',
            'break_sequence',
            'icon',
            'mode',
            'expiration', # date, days, never
            'expiration_date',
            'duration',
            'end_point' # appliance, kvm_port,pdu_port, serial_port,usb_port
            'port_number',
            'skip_authentication_to_access_device',
            'skip_authentication_in_ssh_sessions',
            'skip_authentication_in_telnet_sessions',
            'skip_authentication_in_raw_sessions',
            'skip_authentication_in_web_sessions',
            'escape_sequence',
            'power_control_key',
            'show_text_information',
            'enable_ip_alias',
            'ip_alias',
            'interface',
            'ip_alias_browser_action',
            'ip_alias_telnet',
            'ip_alias_telnet_port',
            'ip_alias_binary',
            'ip_alias_binary_port',
            'enable_second_ip_alias',
            'sec_ip_alias',
            'sec_interface',
            'sec_ip_alias_browser_action',
            'sec_ip_alias_telnet',
            'sec_ip_alias_telnet_port',
            'sec_ip_alias_binary',
            'sec_ip_alias_binary_port',
            'allow_ssh_protocol',
            'ssh_port',
            'allow_telnet_protocol',
            'telnet_port',
            'allow_binary_socket',
            'tcp_socket_port'
        ]
    },
    'expiration': ("validate", {
        'never': [],
        'date': ['expiration_date'],
        'days': ['duration']
    }),
    'end_point': ("validate", { 
        'appliance': [],
        'kvm_port': ['port_number'],
        'pdu_port': ['port_number'],
        'serial_port': ['port_number'],
        'usb_port': ['port_number']
    }),
    'credential':("validate",{
        'set_now': ['password'],
        'ask_during_login': []
    }),
    'enable_device_state_detection_based_in_data_flow': 
    [
        'data_flow_scan_interval'
    ],
    'skip_authentication_to_access_device': 
    [   'skip_authentication_in_raw_sessions',
        'skip_authentication_in_ssh_sessions',
        'skip_authentication_in_telnet_sessions',
        'skip_authentication_in_web_sessions'
     ],
    'allow_ssh_protocol': ['ssh_port'],
    'allow_telnet_protocol': ['telnet_port'],
    'allow_binary_socket': ['tcp_socket_port'],
    'map_to_virtual_machine': ['virtual_machine_name'],
    'enable_send_break': ['break_sequence'],
    'enable_ip_alias': ['ip_alias', 'interface', 'ip_alias_browser_action', 'ip_alias_telnet', 'ip_alias_telnet_port', 'ip_alias_binary', 'ip_alias_binary_port'],
    'ip_alias_telnet': ['ip_alias_telnet_port'],
    'ip_alias_binary': ['ip_alias_binary_port'],
    'enable_second_ip_alias': ['sec_ip_alias', 'sec_interface', 'sec_ip_alias_browser_action', 'sec_ip_alias_telnet', 'sec_ip_alias_telnet_port', 'sec_ip_alias_binary', 'sec_ip_alias_binary_port'],
    'sec_ip_alias_telnet': ['sec_ip_alias_telnet_port'],
    'sec_ip_alias_binary': ['sec_ip_alias_binary_port']
}



# We have to remove the SID from the Environmental settings, to avoid an issue
# were we can not run pexpect.run multiple times
if "DLITF_SID" in os.environ:
    del os.environ["DLITF_SID"]
if "DLITF_SID_ENCRYPT" in os.environ:
    del os.environ["DLITF_SID_ENCRYPT"]

def run_option_device(option, run_opt):
    suboptions = option['suboptions']
    cli_path = option['cli_path']
    settings_list = []
    cmd_results = None
    change_name_message = None

    if not ('access' in suboptions and field_exist(suboptions['access'], 'name')):
        return result_failed("Field 'access/name' is required")
    
    if not ('access' in suboptions and field_exist(suboptions['access'], 'type')):
        return result_failed("Field 'access/type' is required")
    
    if suboptions['access']['type'] not in managed_device_types:
        return result_failed(f"Managed device type '{suboptions['access']['type']}' not supported. Supported values include: {managed_device_types}")
    
    # Control if device type is ip_based: change suboptions device type.
    device_type = get_device_type(suboptions['access']['type'])
    if device_type == "ip_based":
        device_type = suboptions['access']['type']
        suboptions['access'].pop('port_name', None)
        suboptions['access']['type'] = "ip_based"
    
    # Clean the required options
    try:
        settings_tobe_deleted = set()
        for dependency in device_dependencies:
            if isinstance(device_dependencies[dependency], dict):
                for dep_rem in {key:value for key, value in device_dependencies[dependency].items() if dependency in suboptions['access'] and key not in [suboptions['access'][dependency]]}:
                    for setting in device_dependencies[dependency][dep_rem]:
                        if (suboptions['access'][dependency] not in device_dependencies[dependency]) or (setting not in device_dependencies[dependency][suboptions['access'][dependency]]):
                            settings_tobe_deleted.add(setting)

            elif isinstance(device_dependencies[dependency], list) and dependency in suboptions['access'] and suboptions['access'][dependency].lower() == "no":
                for setting in device_dependencies[dependency]:
                    settings_tobe_deleted.add(setting)
            elif isinstance(device_dependencies[dependency], tuple):
                if not dependency in suboptions['access']:
                    continue
                atuple = device_dependencies[dependency]
                if atuple[0] == "validate" and suboptions['access'][dependency] in atuple[1]:
                    if dependency in suboptions['access']:
                        valid_options = atuple[1][suboptions['access'][dependency]]
                        items_to_validate = {option:values for option,values in atuple[1].items() if not option == suboptions['access'][dependency]}
                    else:
                        valid_options = []
                        items_to_validate = {option:values for option,values in atuple[1].items()}
                    for key,value in items_to_validate.items():
                        for v in value:
                            if not v in valid_options:
                                settings_tobe_deleted.add(v)

        # Delete settings not required
        for setting in settings_tobe_deleted:
            suboptions['access'].pop(setting, None)
    except Exception as e:
        return {'failed': True, 'changed': False, 'msg': f"{suboptions['access']} | Key/value error: {e} | {traceback.format_exc()}"}
        
    # Change back if device_type is ip_based
    if device_type in managed_device_type['ip_based']:
        suboptions['access']['type'] = device_type

    # Control if the device is TTY or USB: it must have the port_name option
    if ('port_name' in suboptions['access']):
        port_name = suboptions['access']['port_name']
        suboptions['access'].pop('port_name')

        # Change managed device name supported only for devices connected through tty or usb (local_serial / usb_serial)
        # The name is changed based on an specific cli command (i.e., no via import_settings). For example:
        # /settings/devices/ttyS1-router1 {spm_rename},ttyS1,spm_name
        #
        # Validate 'port_name' format against the pattern ttyS{numbers} or usbS{numbers}-{numbers}
        pattern = re.compile("^ttyS([0-9]+)$|^ttyS([0-9]+)-([0-9]+)$|^usbS([0-9])$|^usbS([0-9]+-[0-9]+)$")
        if pattern.match(port_name):
            new_name = suboptions['access']['name'].strip()
            suboptions['access'].pop('name')
            devices_table = read_table("/settings/devices")
            if devices_table[0].lower() == 'error':
                return result_failed(f"Failed to get device table on cli: 'show /settings/devices'. Error: {devices_table[1]}")
            # Devices table header
            # 'name'  'connected through'  'type'  'access'  'monitoring'
            device = read_table_row(devices_table[1], 1, port_name)
            if device is None:
                return result_failed(f"Device port '{port_name}' does not exist!")
            current_name = device[0]
            
            device_type = suboptions["access"]["type"]
            pattern = re.compile("^ttyS([0-9]+)$|^ttyS([0-9]+)-([0-9]+)$")
            if pattern.match(port_name):
                # serial port type options
                if device_type not in managed_device_type['serial']:
                    return result_failed(f"Serial port '{port_name}' does not support type '{device_type}'. Supported types include:{managed_device_type['serial']}")
            else:
                # usb port type options
                if device_type not in managed_device_type['usb']:
                    return result_failed(f"USB port '{port_name}' does not support type '{device_type}'. Supported types include:{managed_device_type['usb']}")
            settings_tobe_deleted = set()
            for setting in suboptions["access"]:
                if not setting in device_dependencies["type"][device_type]:
                    settings_tobe_deleted.add(setting)
            
            for setting in settings_tobe_deleted:
                suboptions["access"].pop(setting, None)

            if new_name != current_name:
                cmds = [{'confirm': True,'cmd': f"cd /settings/devices; rename {port_name}; set new_name={new_name}"}]
                cmd_results = list()
                cmd_result = dict()
                try:
                    cmd_cli = get_cli(timeout=60)
                    for cmd in cmds:
                        cmd_result = execute_cmd(cmd_cli, cmd)
                        if cmd_result['error']:
                            return result_failed(f"Failed changing name device '{port_name}' with name '{new_name}'. Results: f{cmd_result}")
                        cmd_results.append(cmd_result)
                    close_cli(cmd_cli)
                    change_name_message = f"managed_device_name: {current_name} -> {new_name}"
                    cli_path += f"/{new_name}"
                except Exception as exc:
                    return result_failed(f"Failed changing name device '{port_name}' with name '{new_name}'. Results: f{cmd_results}")
            else:
                cli_path += f"/{current_name}"
        else:
            cli_path += f"/{port_name}"
    else:
        cli_path += f"/{suboptions['access']['name'].strip()}"

    if 'access' in suboptions:
        access_ordered = OrderedDict(suboptions['access'])
        for ordered_setting, settings in {key:value for key,value in device_dependencies.items() if type(value) is list}.items():
            if ordered_setting in access_ordered:
                for setting in [key for key in settings if key in access_ordered]:
                    tmp_value= access_ordered.pop(setting)
                    access_ordered[setting] = tmp_value

        for ordered_setting, atuple in {key:value for key,value in device_dependencies.items() if type(value) is tuple}.items():
            if ordered_setting in access_ordered:
                if atuple[0] == "validate" and access_ordered[ordered_setting] in atuple[1]:
                    for setting in atuple[1][access_ordered[ordered_setting]]:
                        tmp_value= access_ordered.pop(setting)
                        access_ordered[setting] = tmp_value
        suboptions['access'] = access_ordered
        #return result_failed(f"Access: {suboptions['access']}")

    for key, value in suboptions.items():
        # commands
        if key in ['commands']:
            field_name = 'command'
            for item in to_list(value):
                if field_exist(item, field_name):
                    settings_list.extend( format_settings(f"{cli_path}/{key}/{item[field_name]}",item) )
                else:
                    return result_failed(f"Field '{key}/{field_name} is required")
        # custom_fields
        elif key in ['custom_fields']:
            field_name = 'field_name'
            for item in to_list(value):
                if field_exist(item, field_name):
                    if (not 'field_value' in item) or ('field_value' in item and str(item['field_value']).strip() == ""):
                        item['field_value'] = "na"
                    settings_list.extend( format_settings(f"{cli_path}/{key}/{item[field_name]}",item) )
                else:
                    return result_failed(f"Field '{key}/{field_name} is required")
        # Logging 
        elif key in ['logging']:
            if not suboptions['access']['type'] in device_type_not_support_logging:
                settings_list.extend( format_settings(f"{cli_path}/{key}",value) )
        # Management
        elif key in ['management']:
            if not suboptions['access']['type'] in device_type_not_support_management:
                settings_list.extend( format_settings(f"{cli_path}/{key}",value) )
        # Access 
        elif key in ['access']:
            settings_list.extend( format_settings(f"{cli_path}/{key}",value) )
        else:
            return result_failed(f"Suboption '{key}' not supported!")

    option['cli_path'] = cli_path
    option['settings'] = settings_list
    result = run_option(option, run_opt)

    # If device named was changed, update the return result
    if cmd_results:
        result['cmds_output'] = cmd_results
        result['changed'] = True
        if result['message'] == 'No change required':
            result['message'] = change_name_message
        else:
            result['message'] += f" | {change_name_message}"
    return result

def run_option_auto_discovery(option, run_opt):
    suboptions = option['suboptions']
    cli_path = option['cli_path']
    settings_list = []
    
    for key, value in suboptions.items():

        # network_scan
        if key in ['network_scan','vm_managers','discovery_rules']:

            if key == 'network_scan':
                field_name = 'scan_id'
            elif key == 'vm_managers':
                field_name = 'vm_server'
            else:
                field_name = 'rule_name'

            for item in to_list(value):
                if field_exist(item, field_name):
                    settings_list.extend( format_settings(f"{cli_path}/{key}/{item[field_name]}",item) )
                else:
                    return result_failed(f"Field '{key}/{field_name}' is required")

        # hostname_detection
        else:
            settings_list.extend( format_settings(f"{cli_path}/{key}",value) )

    option['settings'] = settings_list
    return run_option(option, run_opt)

def facts(option, run_opt):
    suboptions = option['suboptions']
    cli_path = option['cli_path']
    raw = pexpect.run('llconf ini -si /etc/spm_server.ini json')

    inventory = {
        "managed_devices": [],
        "device_disabled": [],
        "device_enabled": [],
        "device_ondemand": [],
        }
    parsed = json.loads(raw)
    if len(parsed) == 1:
        parsed = parsed['(root)']
        for device in parsed:
            inventory['managed_devices'].append(device)
            if parsed[device]['status'] == 'disabled':
                inventory['device_disabled'].append(device)
            elif parsed[device]['status'] == 'enabled':
                inventory['device_enabled'].append(device)
            elif parsed[device]['status'] == 'ondemand':
                inventory['device_ondemand'].append(device)
    result = dict(
        changed=False,
        failed=False,
        devices=inventory
    )
    return result

def run_module():
    # define available arguments/parameters a user can pass to the module
    module_args = dict(
        device=dict(type='dict', required=False),
        auto_discovery=dict(type='dict', required=False),
        skip_invalid_keys=dict(type='bool', default=False, required=False),
        facts=dict(type='bool', default=False, required=False)
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
            'name': 'device',
            'suboptions': module.params['device'],
            'cli_path': '/settings/devices',
            'func': run_option_device
        },
        {
            'name': 'auto_discovery',
            'suboptions': module.params['auto_discovery'],
            'cli_path': '/settings/auto_discovery',
            'func': run_option_auto_discovery
        },
        {
            'name': 'facts',
            'suboptions': module.params['facts'],
            'cli_path': '',
            'func': facts
        },
    ]

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
    }

    for option in option_list:
        if option['suboptions'] is not None:
            func = option['func']
            res = func(option, run_opt)
            if option['name'] == 'facts':
                result['facts'] = res['devices']
                result['failed'] = False
            else:
                result['output'][option['name']] = res
            if res['failed']:
                result['failed'] = True
                module.fail_json(msg=res['msg'], **result)

    if len(result['output'].keys()) == 0 and option['name'] != 'facts':
        module.fail_json(msg='No inputs', **result)

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
