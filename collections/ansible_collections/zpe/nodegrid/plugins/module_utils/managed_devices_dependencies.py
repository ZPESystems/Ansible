
from collections import OrderedDict
from ansible_collections.zpe.nodegrid.plugins.module_utils.nodegrid_util import format_settings, nodegrid_cli_validate_inputs, pop_keys, cli_settings_reorder


# Manage Device local serial or usb dependencies
local_managed_device_type = {
    'serial': ['local_serial', 'pdu_cpi_serial'],
    'usb': ['pdu_cpi_serial', 'usb_device', 'usb_kvm', 'usb_sensor', 'usb_serialb'],
}


# Managed Device Management dependencies
management_dependencies= OrderedDict({
    'ssh_and_telnet':
    {
        'ssh_and_telnet': ['credential'],
        'credential':{
            'use_same_as_access': [],
            'use_specific': ['username', 'password']
        }
    },
    'ipmi':{
        'ipmi': ['credential'],
        'credential':{
            'use_same_as_access': [],
            'use_specific': ['username', 'password']
        }
    },
    'snmp': 
    {
        'snmp': ['snmp_version'],
        'snmp_version':
        {
            'v1': ['snmp_community'],
            'v2': ['snmp_community'],
            'v3': ['snmpv3_username', 'snmpv3_security_level', 'snmpv3_authentication_algorithm','snmpv3_authentication_password', 'snmpv3_privacy_algorithm', 'snmpv3_privacy_password'],
        },
        'snmpv3_security_level': ("validate", ['authnopriv', 'authpriv', 'noauthnopriv']),
        'snmpv3_authentication_algorithm': ('validate', ['md5', 'sha']),
        'snmpv3_privacy_algorithm': ('validate', ['aes', 'des']),
    },
    'discover_ports':
    {
        'discover_ports': ['discover_interval', 'discovered_name','purge_disabled_end_point_ports'],
        'discovered_name':
        {
            'inherit_from_appliance':[],
            'use_pattern': ['pattern_name']
        },
        'purge_disabled_end_point_ports': ['action'],
        'action': ("validate", ['disable_ports', 'remove_ports']),
    },
    'discover_outlets':
    {
        'discover_outlets': ['discover_interval']
    }
})


# Managed Device Logging dependencies
logging_dependencies= OrderedDict({
    'data_logging':
    {
        'data_logging': ['enable_data_logging_alerts'],
        'enable_data_logging_alerts': ['data_script_1','data_script_2','data_script_3','data_script_4','data_script_5','data_string_1','data_string_2','data_string_3','data_string_4','data_string_5'],
    },
    'event_logging':
    {
        'event_logging': ['enable_event_logging_alerts','event_log_frequency','event_log_unit'],
        'enable_event_logging_alerts': ['event_script_1','event_script_2','event_script_3','event_script_4','event_script_5','event_string_1','event_string_2','event_string_3','event_string_4','event_string_5'],
        'event_log_unit': ('validate', ['hours', 'minutes'])
    }
})


# Nodegrid Managed Devices Families and dependencies
device_family_dependencies = OrderedDict({
        'ai module': [],
        'aten kvm': ['name','type','description','ip_address','address_location','coordinates','web_url','launch_via_nodegrid','method','username','credential','allow_pre-shared_ssh_key','enable_device_state_detection_based_on_network_traffic','enable_hostname_detection','multisession','read-write_multisession','enable_send_break','icon','mode','expiration','end_point','skip_authentication_to_access_device','escape_sequence','power_control_key','show_text_information','enable_ip_alias','enable_second_ip_alias','allow_ssh_protocol','allow_telnet_protocol','allow_binary_socket'],
        'avocent dsr': ['name','type','description','ip_address','address_location','coordinates','web_url','launch_via_nodegrid','method','username','credential','allow_pre-shared_ssh_key','enable_device_state_detection_based_on_network_traffic','multisession','read-write_multisession','enable_send_break','icon','mode','expiration','end_point','skip_authentication_to_access_device','escape_sequence','power_control_key','show_text_information','enable_ip_alias','enable_second_ip_alias','allow_ssh_protocol','allow_telnet_protocol','allow_binary_socket'],
        'avocent mpu': ['name','type','description','ip_address','address_location','coordinates','web_url','launch_via_nodegrid','method','username','credential','allow_pre-shared_ssh_key','enable_device_state_detection_based_on_network_traffic','multisession','read-write_multisession','enable_send_break','icon','mode','expiration','end_point','skip_authentication_to_access_device','escape_sequence','power_control_key','show_text_information','enable_ip_alias','enable_second_ip_alias','allow_ssh_protocol','allow_telnet_protocol','allow_binary_socket'],
        'cimc ucs': ['name','type','description','ip_address','chassis_id','blade_id','address_location','coordinates','web_url','launch_via_nodegrid','method','username','credential','allow_pre-shared_ssh_key','enable_device_state_detection_based_on_network_traffic','enable_hostname_detection','multisession','read-write_multisession','enable_send_break','icon','mode','expiration','skip_authentication_to_access_device','escape_sequence','power_control_key','show_text_information','enable_ip_alias','enable_second_ip_alias','allow_ssh_protocol','allow_telnet_protocol','allow_binary_socket'],
        'console server': ['name','type','description','ip_address','port','address_location','coordinates','web_url','launch_via_nodegrid','method','username','credential','allow_pre-shared_ssh_key','enable_device_state_detection_based_on_network_traffic','enable_hostname_detection','multisession','read-write_multisession','enable_send_break','icon','mode','expiration','end_point','skip_authentication_to_access_device','escape_sequence','power_control_key','show_text_information','enable_ip_alias','enable_second_ip_alias','allow_ssh_protocol','allow_telnet_protocol','allow_binary_socket'],
        'device console': ['name','type','description','ip_address','port','address_location','coordinates','web_url','launch_via_nodegrid','method','username','credential','allow_pre-shared_ssh_key','enable_device_state_detection_based_on_network_traffic','enable_hostname_detection','multisession','read-write_multisession','enable_send_break','icon','mode','expiration','end_point','skip_authentication_to_access_device','escape_sequence','power_control_key','show_text_information','enable_ip_alias','enable_second_ip_alias','allow_ssh_protocol','allow_telnet_protocol','allow_binary_socket'],
        'door lock with rfid': ['name','type','description','address_location','coordinates','door_state_module','door_state_channel','electrical_lock_state_module','electrical_lock_state_channel','mechanical_lock_state_module','mechanical_lock_state_channel','door_lock_trigger_module','door_lock_trigger_channel','enable_device_state_detection_based_on_network_traffic','icon','mode','enable_door_control'],
        'drac': ['name','type','description','ip_address','address_location','coordinates','web_url','launch_via_nodegrid','method','username','credential','allow_pre-shared_ssh_key','enable_device_state_detection_based_on_network_traffic','enable_hostname_detection','multisession','read-write_multisession','enable_send_break','icon','mode','expiration','end_point','skip_authentication_to_access_device','escape_sequence','power_control_key','show_text_information','enable_ip_alias','enable_second_ip_alias','allow_ssh_protocol','allow_telnet_protocol','allow_binary_socket'],
        'ilo': ['name','type','description','ip_address','address_location','coordinates','web_url','launch_via_nodegrid','method','username','credential','allow_pre-shared_ssh_key','enable_device_state_detection_based_on_network_traffic','enable_hostname_detection','multisession','read-write_multisession','enable_send_break','icon','mode','expiration','end_point','skip_authentication_to_access_device','escape_sequence','power_control_key','show_text_information','enable_ip_alias','enable_second_ip_alias','allow_ssh_protocol','allow_telnet_protocol','allow_binary_socket'],
        'ilom': ['name','type','description','ip_address','address_location','coordinates','web_url','launch_via_nodegrid','method','username','credential','allow_pre-shared_ssh_key','enable_device_state_detection_based_on_network_traffic','enable_hostname_detection','multisession','read-write_multisession','enable_send_break','icon','mode','expiration','end_point','skip_authentication_to_access_device','escape_sequence','power_control_key','show_text_information','enable_ip_alias','enable_second_ip_alias','allow_ssh_protocol','allow_telnet_protocol','allow_binary_socket'],
        'imm': ['name','type','description','ip_address','address_location','coordinates','web_url','launch_via_nodegrid','method','username','credential','allow_pre-shared_ssh_key','enable_device_state_detection_based_on_network_traffic','enable_hostname_detection','multisession','read-write_multisession','enable_send_break','icon','mode','expiration','end_point','skip_authentication_to_access_device','escape_sequence','power_control_key','show_text_information','enable_ip_alias','enable_second_ip_alias','allow_ssh_protocol','allow_telnet_protocol','allow_binary_socket'],
        'infrabox': ['name','type','description','ip_address','address_location','coordinates','web_url','launch_via_nodegrid','method','username','credential','allow_pre-shared_ssh_key','enable_device_state_detection_based_on_network_traffic','enable_hostname_detection','multisession','read-write_multisession','enable_send_break','icon','mode','expiration','end_point','skip_authentication_to_access_device','escape_sequence','power_control_key','show_text_information','enable_ip_alias','enable_second_ip_alias','allow_ssh_protocol','allow_telnet_protocol','allow_binary_socket'],
        'ipmi 1.5': ['name','type','description','ip_address','address_location','coordinates','web_url','launch_via_nodegrid','method','username','credential','allow_pre-shared_ssh_key','enable_device_state_detection_based_on_network_traffic','enable_hostname_detection','multisession','read-write_multisession','enable_send_break','icon','mode','expiration','end_point','skip_authentication_to_access_device','escape_sequence','power_control_key','show_text_information','enable_ip_alias','enable_second_ip_alias','allow_ssh_protocol','allow_telnet_protocol','allow_binary_socket'],
        'ipmi 2.0': ['name','type','description','ip_address','address_location','coordinates','web_url','launch_via_nodegrid','method','username','credential','allow_pre-shared_ssh_key','enable_device_state_detection_based_on_network_traffic','enable_hostname_detection','multisession','read-write_multisession','enable_send_break','icon','mode','expiration','end_point','skip_authentication_to_access_device','escape_sequence','power_control_key','show_text_information','enable_ip_alias','enable_second_ip_alias','allow_ssh_protocol','allow_telnet_protocol','allow_binary_socket'],
        'local serial devices': ['name','port_name','type','description','address_location','coordinates','web_url','launch_via_nodegrid','method','username','password','baud_rate','parity','flow_control','data_bits','stop_bits','rs-232_signal_for_device_state_detection','enable_device_state_detection_based_in_data_flow','data_flow_scan_interval','enable_hostname_detection','hostname_detection_login','hostname_detection_credential','hostname_detection_username','hostname_detection_password''multisession','read-write_multisession','enable_serial_port_settings_via_escape_sequence','icon','mode','skip_authentication_to_access_device','skip_authentication_in_ssh_sessions','skip_authentication_in_telnet_sessions','skip_authentication_in_raw_sessions','skip_authentication_in_web_sessions','escape_sequence','power_control_key','show_text_information','enable_ip_alias','ip_alias','interface','ip_alias_browser_action','ip_alias_telnet','ip_alias_telnet_port','ip_alias_binary','ip_alias_binary_port','enable_second_ip_alias','sec_ip_alias','sec_interface','sec_ip_alias_browser_action','sec_ip_alias_telnet','sec_ip_alias_telnet_port','sec_ip_alias_binary','sec_ip_alias_binary_port','allow_ssh_protocol','ssh_port','allow_telnet_protocol','telnet_port','allow_binary_socket','tcp_socket_port'],
        'netapp': ['name','type','description','ip_address','address_location','coordinates','web_url','launch_via_nodegrid','method','username','credential','allow_pre-shared_ssh_key','enable_device_state_detection_based_on_network_traffic','enable_hostname_detection','multisession','read-write_multisession','enable_send_break','icon','mode','expiration','end_point','skip_authentication_to_access_device','escape_sequence','power_control_key','show_text_information','enable_ip_alias','enable_second_ip_alias','allow_ssh_protocol','allow_telnet_protocol','allow_binary_socket'],
        'nodegrid ap': ['name','type','description','ip_address','port','address_location','coordinates','web_url','launch_via_nodegrid','method','username','credential','allow_pre-shared_ssh_key','enable_device_state_detection_based_on_network_traffic','enable_hostname_detection','multisession','read-write_multisession','enable_send_break','icon','mode','expiration','end_point','skip_authentication_to_access_device','escape_sequence','power_control_key','show_text_information','enable_ip_alias','enable_second_ip_alias','allow_ssh_protocol','allow_telnet_protocol','allow_binary_socket'],
        'openbmc': ['name','type','description','ip_address','address_location','coordinates','web_url','launch_via_nodegrid','method','username','credential','allow_pre-shared_ssh_key','enable_device_state_detection_based_on_network_traffic','enable_hostname_detection','multisession','read-write_multisession','enable_send_break','icon','mode','expiration','end_point','fru','skip_authentication_to_access_device','escape_sequence','power_control_key','show_text_information','enable_ip_alias','enable_second_ip_alias','allow_ssh_protocol','allow_telnet_protocol','allow_binary_socket'],
        'pdu': ['name','type','description','ip_address','address_location','coordinates','web_url','launch_via_nodegrid','method','username','credential','allow_pre-shared_ssh_key','enable_device_state_detection_based_on_network_traffic','enable_hostname_detection','multisession','read-write_multisession','enable_send_break','icon','mode','expiration','end_point','skip_authentication_to_access_device','escape_sequence','power_control_key','show_text_information','enable_ip_alias','enable_second_ip_alias','allow_ssh_protocol','allow_telnet_protocol','allow_binary_socket'],
        'pdu local serial': ['name','port_name','type','description','address_location','coordinates','web_url','launch_via_nodegrid','method','username','password','baud_rate','parity','flow_control','data_bits','stop_bits','rs-232_signal_for_device_state_detection','enable_device_state_detection_based_in_data_flow','data_flow_scan_interval','enable_hostname_detection','hostname_detection_login','hostname_detection_credential','hostname_detection_username','hostname_detection_password','multisession','read-write_multisession','enable_serial_port_settings_via_escape_sequence','icon','mode','skip_authentication_to_access_device','skip_authentication_in_ssh_sessions','skip_authentication_in_telnet_sessions','skip_authentication_in_raw_sessions','skip_authentication_in_web_sessions','escape_sequence','power_control_key','show_text_information','enable_ip_alias','ip_alias','interface','ip_alias_browser_action','ip_alias_telnet','ip_alias_telnet_port','ip_alias_binary','ip_alias_binary_port','enable_second_ip_alias','sec_ip_alias','sec_interface','sec_ip_alias_browser_action','sec_ip_alias_telnet','sec_ip_alias_telnet_port','sec_ip_alias_binary','sec_ip_alias_binary_port','allow_ssh_protocol','ssh_port','allow_telnet_protocol','telnet_port','allow_binary_socket','tcp_socket_port'],
        'raritan kvm': ['name','type','description','ip_address','address_location','coordinates','web_url','launch_via_nodegrid','method','username','credential','allow_pre-shared_ssh_key','enable_device_state_detection_based_on_network_traffic','multisession','read-write_multisession','enable_send_break','icon','mode','expiration','end_point','skip_authentication_to_access_device','escape_sequence','power_control_key','show_text_information','enable_ip_alias','enable_second_ip_alias','allow_ssh_protocol','allow_telnet_protocol','allow_binary_socket'],
        'switch': ['name','type','description','ip_address','address_location','coordinates','web_url','launch_via_nodegrid','method','username','credential','allow_pre-shared_ssh_key','enable_device_state_detection_based_on_network_traffic','enable_hostname_detection','multisession','read-write_multisession','enable_send_break','icon','mode','expiration','end_point','skip_authentication_to_access_device','escape_sequence','power_control_key','show_text_information','enable_ip_alias','enable_second_ip_alias','allow_ssh_protocol','allow_telnet_protocol','allow_binary_socket'],
        'usb': [],
        'usb device': ['name','port_name','type','description','address_location','coordinates','web_url','launch_via_nodegrid','method','icon','mode','allow_pre-shared_ssh_key','map_to_virtual_machine','virtual_machine_name'],
        'usb kvm': ['name','port_name','type','description','address_location','coordinates','web_url','launch_via_nodegrid','method','icon','mode','map_to_virtual_machine','virtual_machine_name'],
        'usb ocp': [],
        'usb sensor': ['name','port_name','type','description','address_location','coordinates','icon','mode','allow_pre-shared_ssh_key','map_to_virtual_machine','virtual_machine_name'],
        'virtual console kvm': ['name','type','description','ip_address','port','address_location','coordinates','web_url','launch_via_nodegrid','method','username','credential','allow_pre-shared_ssh_key','enable_device_state_detection_based_on_network_traffic','multisession','read-write_multisession','enable_send_break','icon','mode','expiration','end_point','skip_authentication_to_access_device','escape_sequence','power_control_key','show_text_information','enable_ip_alias','enable_second_ip_alias','allow_ssh_protocol','allow_telnet_protocol','allow_binary_socket'],
        'virtual console vmware': ['name','type','description','ip_address','address_location','coordinates','web_url','launch_via_nodegrid','method','allow_pre-shared_ssh_key','enable_device_state_detection_based_on_network_traffic','vm_manager','multisession','read-write_multisession','enable_send_break','icon','mode','expiration','end_point','skip_authentication_to_access_device','escape_sequence','power_control_key','show_text_information','enable_ip_alias','enable_second_ip_alias','allow_ssh_protocol','allow_telnet_protocol','allow_binary_socket'],
})


# Nodegrid Protected Managed Devices
protected_devices_types = OrderedDict({
    'ai_module_nvidia_jetson': dict(family='ai module', support={}),
    'cimc_ucs': dict(family='cimc ucs', support={'management':['ssh_and_telnet'], 'logging':['data_logging','event_logging']}),
    'console_server_acs': dict(family='console server', support={'management':['ssh_and_telnet','discover_ports'], 'logging':['data_logging']}),
    'console_server_acs6000': dict(family='console server', support={'management':['snmp','ssh_and_telnet','discover_ports'], 'logging':['data_logging']}),
    'console_server_digicp': dict(family='console server', support={'management':['ssh_and_telnet','discover_ports'], 'logging':['data_logging']}),
    'console_server_lantronix': dict(family='console server', support={'management':['ssh_and_telnet','discover_ports'], 'logging':['data_logging']}),
    'console_server_nodegrid': dict(family='console server', support={'management':['ssh_and_telnet','discover_ports'], 'logging':['data_logging']}),
    'console_server_opengear': dict(family='console server', support={'management':['ssh_and_telnet','discover_ports'], 'logging':['data_logging']}),
    'console_server_perle': dict(family='console server', support={'management':['ssh_and_telnet','discover_ports'], 'logging':['data_logging']}),
    'console_server_raritan': dict(family='console server', support={'management':['ssh_and_telnet','discover_ports'], 'logging':['data_logging']}),
    'device_console': dict(family='device console', support={'management':['snmp'], 'logging':['data_logging']}),
    'door_lock_with_rfid': dict(family='door lock with rfid', support={'management':['snmp'], 'logging':['data_logging','event_logging']}),
    'drac': dict(family='drac', support={'management':['ipmi','ssh_and_telnet'], 'logging':['data_logging','event_logging']}),
    'idrac6': dict(family='drac', support={'management':['ipmi','ssh_and_telnet'], 'logging':['data_logging','event_logging']}),
    'ilo': dict(family='ilo', support={'management':['ipmi','ssh_and_telnet'], 'logging':['data_logging','event_logging']}),
    'ilom': dict(family='ilom', support={'management':['ssh_and_telnet'], 'logging':['data_logging','event_logging']}),
    'imm': dict(family='imm', support={'management':['ssh_and_telnet'], 'logging':['data_logging','event_logging']}),
    'infrabox': dict(family='infrabox', support={'management':['snmp'], 'logging':['data_logging','event_logging']}),
    'intel_bmc': dict(family='ipmi 2.0', support={'management':['ipmi'], 'logging':['data_logging','event_logging']}),
    'ipmi_1.5': dict(family='ipmi 1.5', support={'management':['ipmi','ssh_and_telnet'], 'logging':['data_logging','event_logging']}),
    'ipmi_2.0': dict(family='ipmi 2.0', support={'management':['ipmi'], 'logging':['data_logging','event_logging']}),
    'kvm_aten': dict(family='aten kvm', support={'management':['ssh_and_telnet','discover_ports'], 'logging':['data_logging']}),
    'kvm_dsr': dict(family='avocent dsr', support={'management':['ssh_and_telnet','discover_ports']}),
    'kvm_mpu': dict(family='avocent mpu', support={'management':['ssh_and_telnet','discover_ports']}),
    'kvm_raritan': dict(family='raritan kvm', support={'management':['ssh_and_telnet','discover_ports']}),
    'local_serial': dict(family='local serial devices', support={'management':[], 'logging':['data_logging']}),
    'netapp': dict(family='netapp', support={'management':['ssh_and_telnet'], 'logging':['data_logging','event_logging']}),
    'nodegrid_ap': dict(family='nodegrid ap', support={'management':['snmp'], 'logging':['data_logging']}),
    'openbmc': dict(family='openbmc', support={'management':['ssh_and_telnet'], 'logging':['data_logging','event_logging']}),
    'pdu_apc': dict(family='pdu', support={'management':['snmp','ssh_and_telnet','discover_outlets'], 'logging':['data_logging']}),
    'pdu_austin_hughes': dict(family='pdu', support={'management':['snmp','discover_outlets'], 'logging':['data_logging']}),
    'pdu_baytech': dict(family='pdu', support={'management':['snmp','discover_outlets'], 'logging':['data_logging']}),
    'pdu_cpi': dict(family='pdu', support={'management':['snmp','discover_outlets'], 'logging':['data_logging']}),
    'pdu_cpi_serial': dict(family='pdu local serial', support={'management':['discover_outlets'], 'logging':['data_logging']}),
    'pdu_cyberpower': dict(family='pdu', support={'management':['snmp','ssh_and_telnet','discover_outlets'], 'logging':['data_logging']}),
    'pdu_digital_loggers': dict(family='pdu', support={'management':['snmp','discover_outlets'], 'logging':['data_logging']}),
    'pdu_eaton': dict(family='pdu', support={'management':['snmp','ssh_and_telnet','discover_outlets'], 'logging':['data_logging']}),
    'pdu_enconnex': dict(family='pdu', support={'management':['snmp','ssh_and_telnet','discover_outlets'], 'logging':['data_logging']}),
    'pdu_geist': dict(family='pdu', support={'management':['snmp','discover_outlets'], 'logging':['data_logging']}),
    'pdu_hpe_g2': dict(family='pdu', support={'management':['snmp','discover_outlets'], 'logging':['data_logging']}),
    'pdu_ice': dict(family='pdu', support={'management':['snmp','discover_outlets'], 'logging':['data_logging']}),
    'pdu_mph2': dict(family='pdu', support={'management':['snmp','ssh_and_telnet','discover_outlets'], 'logging':['data_logging']}),
    'pdu_pm3000': dict(family='pdu', support={'management':['snmp','ssh_and_telnet','discover_outlets'], 'logging':['data_logging']}),
    'pdu_raritan': dict(family='pdu', support={'management':['snmp','ssh_and_telnet','discover_outlets'], 'logging':['data_logging']}),
    'pdu_rittal': dict(family='pdu', support={'management':['snmp','discover_outlets'], 'logging':['data_logging']}),
    'pdu_rnx': dict(family='pdu', support={'management':['snmp','discover_outlets'], 'logging':['data_logging']}),
    'pdu_servertech': dict(family='pdu', support={'management':['snmp','ssh_and_telnet','discover_outlets'], 'logging':['data_logging']}),
    'pdu_tripplite': dict(family='pdu', support={'management':['snmp','discover_outlets'], 'logging':['data_logging']}),
    'switch_edgecore': dict(family='switch', support={'management':['snmp','discover_switch_ports'], 'logging':['data_logging']}),
    'switch_zpe': dict(family='switch', support={'management':['snmp','discover_switch_ports'], 'logging':['data_logging']}),
    'ups_apc': dict(family='pdu', support={'management':['snmp','ssh_and_telnet','discover_outlets'], 'logging':['data_logging']}),
    'ups_netagent': dict(family='pdu', support={'management':['snmp','discover_outlets'], 'logging':['data_logging']}),
    'usb': dict(family='usb', support={}),
    'usb_device': dict(family='usb device', support={}),
    'usb_kvm': dict(family='usb kvm', support={'management':[]}),
    'usb_ocp': dict(family='usb ocp', support={}),
    'usb_sensor': dict(family='usb sensor', support={'management':[]}),
    'usb_serial': dict(family='local serial devices', support={}),
    'usb_serialb': dict(family='local serial devices', support={'management':[], 'logging':['data_logging']}),
    'virtual_console_kvm': dict(family='virtual console kvm', support={'management':['ssh_and_telnet'], 'logging':['data_logging']}),
    'virtual_console_vmware': dict(family='virtual console vmware', support={'management':[], 'logging':['data_logging']}),
})

# Managed devices types family dependencies
device_family_type_dependencies = OrderedDict({
    'family': {
        'ai module': ['device_type_name', 'login_prompt', 'password_prompt', 'command_prompt', 'console_escape_sequence'],
        'aten kvm': ['device_type_name','protocol', 'login_prompt', 'password_prompt', 'command_prompt', 'console_escape_sequence'],
        'avocent dsr': ['device_type_name','protocol', 'login_prompt', 'password_prompt', 'command_prompt', 'console_escape_sequence'],
        'avocent mpu': ['device_type_name','protocol', 'login_prompt', 'password_prompt', 'command_prompt', 'console_escape_sequence'],
        'cimc ucs': ['device_type_name','protocol', 'login_prompt', 'password_prompt', 'command_prompt', 'console_escape_sequence'],
        'console server': ['device_type_name','protocol', 'login_prompt', 'password_prompt', 'command_prompt', 'console_escape_sequence'],
        'device console': ['device_type_name','protocol', 'login_prompt', 'password_prompt', 'command_prompt', 'console_escape_sequence'],
        'door lock with rfid': ['device_type_name','protocol', 'login_prompt', 'password_prompt', 'command_prompt', 'console_escape_sequence'],
        'drac': ['device_type_name','protocol', 'login_prompt', 'password_prompt', 'command_prompt', 'console_escape_sequence'],
        'ilo': ['device_type_name','protocol', 'login_prompt', 'password_prompt', 'command_prompt', 'console_escape_sequence'],
        'ilom': ['device_type_name','protocol', 'login_prompt', 'password_prompt', 'command_prompt', 'console_escape_sequence'],
        'imm': ['device_type_name','protocol', 'login_prompt', 'password_prompt', 'command_prompt', 'console_escape_sequence'],
        'infrabox': ['device_type_name','protocol', 'login_prompt', 'password_prompt', 'command_prompt', 'console_escape_sequence'],
        'ipmi 1.5': ['device_type_name','protocol', 'login_prompt', 'password_prompt', 'command_prompt', 'console_escape_sequence'],
        'ipmi 2.0': ['device_type_name','protocol', 'login_prompt', 'password_prompt', 'command_prompt', 'console_escape_sequence'],
        'local serial devices': ['device_type_name', 'login_prompt', 'password_prompt', 'command_prompt', 'console_escape_sequence'],
        'netapp': ['device_type_name','protocol', 'login_prompt', 'password_prompt', 'command_prompt', 'console_escape_sequence'],
        'nodegrid ap': ['device_type_name','protocol', 'login_prompt', 'password_prompt', 'command_prompt', 'console_escape_sequence'],
        'openbmc': ['device_type_name','protocol', 'login_prompt', 'password_prompt', 'command_prompt', 'console_escape_sequence'],
        'pdu': ['device_type_name','protocol', 'login_prompt', 'password_prompt', 'command_prompt', 'console_escape_sequence'],
        'pdu local serial': ['device_type_name', 'login_prompt', 'password_prompt', 'command_prompt', 'console_escape_sequence'],
        'raritan kvm': ['device_type_name','protocol', 'login_prompt', 'password_prompt', 'command_prompt', 'console_escape_sequence'],
        'switch': ['device_type_name','protocol', 'login_prompt', 'password_prompt', 'command_prompt', 'console_escape_sequence'],
        'usb': ['device_type_name','protocol', 'login_prompt', 'password_prompt', 'command_prompt', 'console_escape_sequence'],
        'usb device': ['device_type_name','protocol', 'login_prompt', 'password_prompt', 'command_prompt', 'console_escape_sequence'],
        'usb kvm': ['device_type_name','protocol', 'login_prompt', 'password_prompt', 'command_prompt', 'console_escape_sequence'],
        'usb ocp': ['device_type_name','protocol', 'login_prompt', 'password_prompt', 'command_prompt', 'console_escape_sequence'],
        'usb sensor': ['device_type_name','protocol', 'login_prompt', 'password_prompt', 'command_prompt', 'console_escape_sequence'], 
        'virtual console kvm': ['device_type_name','protocol', 'login_prompt', 'password_prompt', 'command_prompt', 'console_escape_sequence'],
        'virtual console vmware': ['device_type_name','protocol', 'login_prompt', 'password_prompt', 'command_prompt', 'console_escape_sequence']
    },
    'protocol':{
        'ssh': ['ssh_options'],
        'telnet': [],
        'ipmi': [],
        'snmp': [],
        'none': [],
    }
})

# Managed devices types family protocol dependencies
device_family_type_protocol_options = OrderedDict({
        'aten kvm': ['ssh', 'ipmi', 'telnet', 'none'],
        'avocent dsr': ['ssh', 'ipmi', 'telnet', 'none'],
        'avocent mpu': ['ssh', 'ipmi', 'telnet', 'none'],
        'cimc ucs': ['ssh', 'ipmi', 'telnet', 'none'],
        'console server': ['ssh', 'ipmi', 'telnet', 'none'],
        'device console': ['ssh', 'ipmi', 'telnet', 'none'],
        'door lock with rfid': ['ssh', 'ipmi', 'telnet', 'none'],
        'drac': ['ssh', 'ipmi', 'telnet', 'none'],
        'ilo': ['ssh', 'ipmi', 'telnet', 'none'],
        'ilom': ['ssh', 'ipmi', 'telnet', 'none'],
        'imm': ['ssh', 'ipmi', 'telnet', 'none'],
        'infrabox': ['ssh', 'ipmi', 'telnet', 'none'],
        'ipmi 1.5': ['ssh', 'ipmi', 'telnet', 'none'],
        'ipmi 2.0': ['ssh', 'ipmi', 'telnet', 'none'],
        'netapp': ['ssh', 'ipmi', 'telnet', 'none'],
        'nodegrid ap': ['ssh', 'ipmi', 'telnet', 'none'],
        'openbmc': ['ssh', 'ipmi', 'telnet', 'none'],
        'pdu': ['ssh', 'snmp', 'ipmi', 'telnet', 'none'],
        'raritan kvm': ['ssh', 'ipmi', 'telnet', 'none'],
        'switch': ['ssh', 'snmp', 'ipmi', 'telnet', 'none'],
        'usb': ['ssh', 'ipmi', 'telnet', 'none'],
        'usb device': ['ssh', 'ipmi', 'telnet', 'none'],
        'usb kvm': ['ssh', 'ipmi', 'telnet', 'none'],
        'usb ocp': ['ssh', 'ipmi', 'telnet', 'none'],
        'usb sensor': ['ssh', 'ipmi', 'telnet', 'none'],
        'virtual console kvm': ['ssh', 'ipmi', 'telnet', 'none'],
        'virtual console vmware': ['ssh', 'ipmi', 'telnet', 'none']
})

# Managed Device dependencies extra (it extends the Managed Device Family dependencies)
device_dependencies = OrderedDict({
    'launch_via_nodegrid': ['method'],
    'enable_door_control': ['rfid_reader_device'],
    'method': ('validate', ['browser_forwarder','internal_browser']),
    'hostname_detection_credential': ('validate', ['use_same_as_access','use_specific']),
    'fru': {
        'side_plane_board': [],
        'server_board': ['slot_number'],
    },
    'expiration': {
        'never': [],
        'date': ['expiration_date'],
        'days': ['duration']
    },
    'end_point': {
        'appliance': [],
        'kvm_port': ['port_number'],
        'pdu_port': ['port_number'],
        'serial_port': ['port_number'],
        'usb_port': ['port_number']
    },
    'credential': {
        'set_now': ['password'],
        'ask_during_login': []
    },
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
})


# Function to get a Managed Device family from device_type
def get_device_family(device_type):
    if not device_type in protected_devices_types.keys():
        raise Exception(f"Device type is not included in the protected device types. Valid options include: {protected_devices_types.keys()}")
    return protected_devices_types[device_type]


# Function to get Managed Device dependencies
def get_device_family_dependencies():
    dependencies = OrderedDict()
    dependencies.update({'family': device_family_dependencies})
    dependencies.update(device_dependencies)
    return dependencies


# Validate the Managed Device logging support and dependencies
def validate_logging_fields(cli_path, device_type, settings):
    device_type_support = protected_devices_types[device_type].get('support', None)
    if device_type_support and 'logging' in device_type_support:
        for support in logging_dependencies.keys():
            all_settings = set()
            for key, setting in logging_dependencies[support].items():
                if isinstance(setting, dict):
                    all_settings.add(key)
                    for _, asetting in setting.items():
                        if isinstance(asetting, list):
                            all_settings |= set(asetting)
                elif isinstance(setting, list):
                    all_settings |= set(setting)            
            if support not in device_type_support['logging'] or support not in settings: 
                all_settings.add(support)
                pop_keys(settings, all_settings)
            elif str(settings[support]).strip() == 'no':
                pop_keys(settings, all_settings)
            elif str(settings[support]).strip() == 'yes':
                settings = nodegrid_cli_validate_inputs(settings, logging_dependencies[support])
                settings = cli_settings_reorder(settings, logging_dependencies[support], OrderedDict({support: 'yes'}))
    else: 
        all_settings = set()
        for _, support_value in logging_dependencies.items():
            for key, setting in support_value.items():
                all_settings.add(key)
                if isinstance(setting, dict):
                    for _, asetting in setting.items():
                        if isinstance(asetting, list):
                            all_settings |= set(asetting)
                elif isinstance(setting, list):
                    all_settings |= set(setting)
        pop_keys(settings, all_settings)
    return format_settings(f"{cli_path}",settings)


# Validate the Managed Device management support and dependencies
def validate_management_fields(cli_path, device_type, settings):
    device_type_support = protected_devices_types[device_type].get('support', None)
    if device_type_support and 'management' in device_type_support:
        keys_validated = set()
        for support in management_dependencies.keys():
            all_settings = set()
            for key, setting in management_dependencies[support].items():
                if isinstance(setting, dict):
                    all_settings.add(key)
                    for _, asetting in setting.items():
                        if isinstance(asetting, list):
                            all_settings |= set(asetting)
                elif isinstance(setting, list):
                    all_settings |= set(setting)
            if support not in device_type_support['management'] or support not in settings: 
                all_settings.add(support)
                pop_keys(settings, all_settings - keys_validated)
            elif str(settings[support]).strip() == 'no':
                pop_keys(settings, all_settings)
            elif str(settings[support]).strip() == 'yes':
                keys_validated |= set(all_settings)
                settings = nodegrid_cli_validate_inputs(settings, management_dependencies[support])
                settings = cli_settings_reorder(settings, management_dependencies[support], OrderedDict({support: 'yes'}))
    else: 
        all_settings = set()
        for _, support_value in management_dependencies.items():
            for key, setting in support_value.items():
                all_settings.add(key)
                if isinstance(setting, dict):
                    for _, asetting in setting.items():
                        if isinstance(asetting, list):
                            all_settings |= set(asetting)
                elif isinstance(setting, list):
                    all_settings |= set(setting)
        pop_keys(settings, all_settings)
    return format_settings(f"{cli_path}",settings)
