
from collections import OrderedDict

# Managed devices-> Device dependencies
#ip_devices_types = set(["cimc_ucs","console_server_acs","console_server_acs6000","console_server_digicp","console_server_lantronix","console_server_nodegrid","console_server_opengear","console_server_perle","console_server_raritan","device_console","door_lock_with_rfid","drac","idrac6","ilo","ilom","imm","infrabox","intel_bmc","ipmi_1.5","ipmi_2.0","kvm_aten","kvm_dsr","kvm_mpu","kvm_raritan","netapp","nodegrid_ap","openbmc","pdu_apc","pdu_austin_hughes","pdu_baytech","pdu_cpi","pdu_cyberpower","pdu_digital_loggers","pdu_eaton","pdu_enconnex","pdu_geist","pdu_hpe_g2","pdu_ice","pdu_mph2","pdu_pm3000","pdu_raritan","pdu_rittal","pdu_rnx","pdu_servertech","pdu_tripplite","switch_edgecore","switch_zpe","ups_apc","ups_netagent","virtual_console_kvm","virtual_console_vmware"])
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
        [
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
        ],
        'usb_device':
        [
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
        ],
        'usb_sensor':
        [
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
        ],
        'usb_kvm':
        [
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
        ],
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
        ],
        'cimc_ucs': ['name','type','description','ip_address','chassis_id','blade_id','address_location','coordinates','web_url','launch_via_nodegrid','username','credential','allow_pre-shared_ssh_key','enable_device_state_detection_based_on_network_traffic','enable_hostname_detection','multisession','read-write_multisession','enable_send_break','icon','mode','expiration','skip_authentication_to_access_device','escape_sequence','power_control_key','show_text_information','enable_ip_alias','enable_second_ip_alias','allow_ssh_protocol','allow_telnet_protocol','allow_binary_socket'],
        'console_server_acs': ['name','type','description','ip_address','port','address_location','coordinates','web_url','launch_via_nodegrid','username','credential','allow_pre-shared_ssh_key','enable_device_state_detection_based_on_network_traffic','enable_hostname_detection','multisession','read-write_multisession','enable_send_break','icon','mode','expiration','end_point','skip_authentication_to_access_device','escape_sequence','power_control_key','show_text_information','enable_ip_alias','enable_second_ip_alias','allow_ssh_protocol','allow_telnet_protocol','allow_binary_socket'],
        'console_server_acs6000': ['name','type','description','ip_address','port','address_location','coordinates','web_url','launch_via_nodegrid','username','credential','allow_pre-shared_ssh_key','enable_device_state_detection_based_on_network_traffic','enable_hostname_detection','multisession','read-write_multisession','enable_send_break','icon','mode','expiration','end_point','skip_authentication_to_access_device','escape_sequence','power_control_key','show_text_information','enable_ip_alias','enable_second_ip_alias','allow_ssh_protocol','allow_telnet_protocol','allow_binary_socket'],
        'console_server_digicp': ['name','type','description','ip_address','port','address_location','coordinates','web_url','launch_via_nodegrid','username','credential','allow_pre-shared_ssh_key','enable_device_state_detection_based_on_network_traffic','enable_hostname_detection','multisession','read-write_multisession','enable_send_break','icon','mode','expiration','end_point','skip_authentication_to_access_device','escape_sequence','power_control_key','show_text_information','enable_ip_alias','enable_second_ip_alias','allow_ssh_protocol','allow_telnet_protocol','allow_binary_socket'],
        'console_server_lantronix': ['name','type','description','ip_address','port','address_location','coordinates','web_url','launch_via_nodegrid','username','credential','allow_pre-shared_ssh_key','enable_device_state_detection_based_on_network_traffic','enable_hostname_detection','multisession','read-write_multisession','enable_send_break','icon','mode','expiration','end_point','skip_authentication_to_access_device','escape_sequence','power_control_key','show_text_information','enable_ip_alias','enable_second_ip_alias','allow_ssh_protocol','allow_telnet_protocol','allow_binary_socket'],
        'console_server_nodegrid': ['name','type','description','ip_address','port','address_location','coordinates','web_url','launch_via_nodegrid','username','credential','allow_pre-shared_ssh_key','enable_device_state_detection_based_on_network_traffic','enable_hostname_detection','multisession','read-write_multisession','enable_send_break','icon','mode','expiration','end_point','skip_authentication_to_access_device','escape_sequence','power_control_key','show_text_information','enable_ip_alias','enable_second_ip_alias','allow_ssh_protocol','allow_telnet_protocol','allow_binary_socket'],
        'console_server_opengear': ['name','type','description','ip_address','port','address_location','coordinates','web_url','launch_via_nodegrid','username','credential','allow_pre-shared_ssh_key','enable_device_state_detection_based_on_network_traffic','enable_hostname_detection','multisession','read-write_multisession','enable_send_break','icon','mode','expiration','end_point','skip_authentication_to_access_device','escape_sequence','power_control_key','show_text_information','enable_ip_alias','enable_second_ip_alias','allow_ssh_protocol','allow_telnet_protocol','allow_binary_socket'],
        'console_server_perle': ['name','type','description','ip_address','port','address_location','coordinates','web_url','launch_via_nodegrid','username','credential','allow_pre-shared_ssh_key','enable_device_state_detection_based_on_network_traffic','enable_hostname_detection','multisession','read-write_multisession','enable_send_break','icon','mode','expiration','end_point','skip_authentication_to_access_device','escape_sequence','power_control_key','show_text_information','enable_ip_alias','enable_second_ip_alias','allow_ssh_protocol','allow_telnet_protocol','allow_binary_socket'],
        'console_server_raritan': ['name','type','description','ip_address','port','address_location','coordinates','web_url','launch_via_nodegrid','username','credential','allow_pre-shared_ssh_key','enable_device_state_detection_based_on_network_traffic','enable_hostname_detection','multisession','read-write_multisession','enable_send_break','icon','mode','expiration','end_point','skip_authentication_to_access_device','escape_sequence','power_control_key','show_text_information','enable_ip_alias','enable_second_ip_alias','allow_ssh_protocol','allow_telnet_protocol','allow_binary_socket'],
        'device_console': ['name','type','description','ip_address','port','address_location','coordinates','web_url','launch_via_nodegrid','username','credential','allow_pre-shared_ssh_key','enable_device_state_detection_based_on_network_traffic','enable_hostname_detection','multisession','read-write_multisession','enable_send_break','icon','mode','expiration','end_point','skip_authentication_to_access_device','escape_sequence','power_control_key','show_text_information','enable_ip_alias','enable_second_ip_alias','allow_ssh_protocol','allow_telnet_protocol','allow_binary_socket'],
        'door_lock_with_rfid':['name','type','description','address_location','coordinates','door_state_module','door_state_channel','electrical_lock_state_module','electrical_lock_state_channel','mechanical_lock_state_module','mechanical_lock_state_channel','door_lock_trigger_module','door_lock_trigger_channel','enable_device_state_detection_based_on_network_traffic','icon','mode','enable_door_control'],
        'drac': ['name','type','description','ip_address','address_location','coordinates','web_url','launch_via_nodegrid','username','credential','allow_pre-shared_ssh_key','enable_device_state_detection_based_on_network_traffic','enable_hostname_detection','multisession','read-write_multisession','enable_send_break','icon','mode','expiration','end_point','skip_authentication_to_access_device','escape_sequence','power_control_key','show_text_information','enable_ip_alias','enable_second_ip_alias','allow_ssh_protocol','allow_telnet_protocol','allow_binary_socket'],
        'idrac6': ['name','type','description','ip_address','address_location','coordinates','web_url','launch_via_nodegrid','username','credential','allow_pre-shared_ssh_key','enable_device_state_detection_based_on_network_traffic','enable_hostname_detection','multisession','read-write_multisession','enable_send_break','icon','mode','expiration','end_point','skip_authentication_to_access_device','escape_sequence','power_control_key','show_text_information','enable_ip_alias','enable_second_ip_alias','allow_ssh_protocol','allow_telnet_protocol','allow_binary_socket'],
        'ilo': ['name','type','description','ip_address','address_location','coordinates','web_url','launch_via_nodegrid','username','credential','allow_pre-shared_ssh_key','enable_device_state_detection_based_on_network_traffic','enable_hostname_detection','multisession','read-write_multisession','enable_send_break','icon','mode','expiration','end_point','skip_authentication_to_access_device','escape_sequence','power_control_key','show_text_information','enable_ip_alias','enable_second_ip_alias','allow_ssh_protocol','allow_telnet_protocol','allow_binary_socket'],
        'ilom': ['name','type','description','ip_address','address_location','coordinates','web_url','launch_via_nodegrid','username','credential','allow_pre-shared_ssh_key','enable_device_state_detection_based_on_network_traffic','enable_hostname_detection','multisession','read-write_multisession','enable_send_break','icon','mode','expiration','end_point','skip_authentication_to_access_device','escape_sequence','power_control_key','show_text_information','enable_ip_alias','enable_second_ip_alias','allow_ssh_protocol','allow_telnet_protocol','allow_binary_socket'],
        'imm': ['name','type','description','ip_address','address_location','coordinates','web_url','launch_via_nodegrid','username','credential','allow_pre-shared_ssh_key','enable_device_state_detection_based_on_network_traffic','enable_hostname_detection','multisession','read-write_multisession','enable_send_break','icon','mode','expiration','end_point','skip_authentication_to_access_device','escape_sequence','power_control_key','show_text_information','enable_ip_alias','enable_second_ip_alias','allow_ssh_protocol','allow_telnet_protocol','allow_binary_socket'],
        'infrabox': ['name','type','description','ip_address','address_location','coordinates','web_url','launch_via_nodegrid','username','credential','allow_pre-shared_ssh_key','enable_device_state_detection_based_on_network_traffic','enable_hostname_detection','multisession','read-write_multisession','enable_send_break','icon','mode','expiration','end_point','skip_authentication_to_access_device','escape_sequence','power_control_key','show_text_information','enable_ip_alias','enable_second_ip_alias','allow_ssh_protocol','allow_telnet_protocol','allow_binary_socket'],
        'intel_bmc': ['name','type','description','ip_address','address_location','coordinates','web_url','launch_via_nodegrid','username','credential','allow_pre-shared_ssh_key','enable_device_state_detection_based_on_network_traffic','enable_hostname_detection','multisession','read-write_multisession','enable_send_break','icon','mode','expiration','end_point','skip_authentication_to_access_device','escape_sequence','power_control_key','show_text_information','enable_ip_alias','enable_second_ip_alias','allow_ssh_protocol','allow_telnet_protocol','allow_binary_socket'],
        'ipmi_1.5': ['name','type','description','ip_address','address_location','coordinates','web_url','launch_via_nodegrid','username','credential','allow_pre-shared_ssh_key','enable_device_state_detection_based_on_network_traffic','enable_hostname_detection','multisession','read-write_multisession','enable_send_break','icon','mode','expiration','end_point','skip_authentication_to_access_device','escape_sequence','power_control_key','show_text_information','enable_ip_alias','enable_second_ip_alias','allow_ssh_protocol','allow_telnet_protocol','allow_binary_socket'],
        'ipmi_2.0': ['name','type','description','ip_address','address_location','coordinates','web_url','launch_via_nodegrid','username','credential','allow_pre-shared_ssh_key','enable_device_state_detection_based_on_network_traffic','enable_hostname_detection','multisession','read-write_multisession','enable_send_break','icon','mode','expiration','end_point','skip_authentication_to_access_device','escape_sequence','power_control_key','show_text_information','enable_ip_alias','enable_second_ip_alias','allow_ssh_protocol','allow_telnet_protocol','allow_binary_socket'],
        'kvm_aten': ['name','type','description','ip_address','address_location','coordinates','web_url','launch_via_nodegrid','username','credential','allow_pre-shared_ssh_key','enable_device_state_detection_based_on_network_traffic','enable_hostname_detection','multisession','read-write_multisession','enable_send_break','icon','mode','expiration','end_point','skip_authentication_to_access_device','escape_sequence','power_control_key','show_text_information','enable_ip_alias','enable_second_ip_alias','allow_ssh_protocol','allow_telnet_protocol','allow_binary_socket'],
        'kvm_dsr': ['name','type','description','ip_address','address_location','coordinates','web_url','launch_via_nodegrid','username','credential','allow_pre-shared_ssh_key','enable_device_state_detection_based_on_network_traffic','multisession','read-write_multisession','enable_send_break','icon','mode','expiration','end_point','skip_authentication_to_access_device','escape_sequence','power_control_key','show_text_information','enable_ip_alias','enable_second_ip_alias','allow_ssh_protocol','allow_telnet_protocol','allow_binary_socket'],
        'kvm_mpu': ['name','type','description','ip_address','address_location','coordinates','web_url','launch_via_nodegrid','username','credential','allow_pre-shared_ssh_key','enable_device_state_detection_based_on_network_traffic','multisession','read-write_multisession','enable_send_break','icon','mode','expiration','end_point','skip_authentication_to_access_device','escape_sequence','power_control_key','show_text_information','enable_ip_alias','enable_second_ip_alias','allow_ssh_protocol','allow_telnet_protocol','allow_binary_socket'],
        'kvm_raritan': ['name','type','description','ip_address','address_location','coordinates','web_url','launch_via_nodegrid','username','credential','allow_pre-shared_ssh_key','enable_device_state_detection_based_on_network_traffic','multisession','read-write_multisession','enable_send_break','icon','mode','expiration','end_point','skip_authentication_to_access_device','escape_sequence','power_control_key','show_text_information','enable_ip_alias','enable_second_ip_alias','allow_ssh_protocol','allow_telnet_protocol','allow_binary_socket'],
        'netapp': ['name','type','description','ip_address','address_location','coordinates','web_url','launch_via_nodegrid','username','credential','allow_pre-shared_ssh_key','enable_device_state_detection_based_on_network_traffic','enable_hostname_detection','multisession','read-write_multisession','enable_send_break','icon','mode','expiration','end_point','skip_authentication_to_access_device','escape_sequence','power_control_key','show_text_information','enable_ip_alias','enable_second_ip_alias','allow_ssh_protocol','allow_telnet_protocol','allow_binary_socket'],
        'nodegrid_ap': ['name','type','description','ip_address','port','address_location','coordinates','web_url','launch_via_nodegrid','username','credential','allow_pre-shared_ssh_key','enable_device_state_detection_based_on_network_traffic','enable_hostname_detection','multisession','read-write_multisession','enable_send_break','icon','mode','expiration','end_point','skip_authentication_to_access_device','escape_sequence','power_control_key','show_text_information','enable_ip_alias','enable_second_ip_alias','allow_ssh_protocol','allow_telnet_protocol','allow_binary_socket'],
        'openbmc': ['name','type','description','ip_address','address_location','coordinates','web_url','launch_via_nodegrid','username','credential','allow_pre-shared_ssh_key','enable_device_state_detection_based_on_network_traffic','enable_hostname_detection','multisession','read-write_multisession','enable_send_break','icon','mode','expiration','end_point','fru','skip_authentication_to_access_device','escape_sequence','power_control_key','show_text_information','enable_ip_alias','enable_second_ip_alias','allow_ssh_protocol','allow_telnet_protocol','allow_binary_socket'],
        'pdu_apc': ['name','type','description','ip_address','address_location','coordinates','web_url','launch_via_nodegrid','username','credential','allow_pre-shared_ssh_key','enable_device_state_detection_based_on_network_traffic','enable_hostname_detection','multisession','read-write_multisession','enable_send_break','icon','mode','expiration','end_point','skip_authentication_to_access_device','escape_sequence','power_control_key','show_text_information','enable_ip_alias','enable_second_ip_alias','allow_ssh_protocol','allow_telnet_protocol','allow_binary_socket'],
        'pdu_austin_hughes': ['name','type','description','ip_address','address_location','coordinates','web_url','launch_via_nodegrid','username','credential','allow_pre-shared_ssh_key','enable_device_state_detection_based_on_network_traffic','enable_hostname_detection','multisession','read-write_multisession','enable_send_break','icon','mode','expiration','end_point','skip_authentication_to_access_device','escape_sequence','power_control_key','show_text_information','enable_ip_alias','enable_second_ip_alias','allow_ssh_protocol','allow_telnet_protocol','allow_binary_socket'],
        'pdu_baytech': ['name','type','description','ip_address','address_location','coordinates','web_url','launch_via_nodegrid','username','credential','allow_pre-shared_ssh_key','enable_device_state_detection_based_on_network_traffic','enable_hostname_detection','multisession','read-write_multisession','enable_send_break','icon','mode','expiration','end_point','skip_authentication_to_access_device','escape_sequence','power_control_key','show_text_information','enable_ip_alias','enable_second_ip_alias','allow_ssh_protocol','allow_telnet_protocol','allow_binary_socket'],
        'pdu_cpi': ['name','type','description','ip_address','address_location','coordinates','web_url','launch_via_nodegrid','username','credential','allow_pre-shared_ssh_key','enable_device_state_detection_based_on_network_traffic','enable_hostname_detection','multisession','read-write_multisession','enable_send_break','icon','mode','expiration','end_point','skip_authentication_to_access_device','escape_sequence','power_control_key','show_text_information','enable_ip_alias','enable_second_ip_alias','allow_ssh_protocol','allow_telnet_protocol','allow_binary_socket'],
        'pdu_cyberpower': ['name','type','description','ip_address','address_location','coordinates','web_url','launch_via_nodegrid','username','credential','allow_pre-shared_ssh_key','enable_device_state_detection_based_on_network_traffic','enable_hostname_detection','multisession','read-write_multisession','enable_send_break','icon','mode','expiration','end_point','skip_authentication_to_access_device','escape_sequence','power_control_key','show_text_information','enable_ip_alias','enable_second_ip_alias','allow_ssh_protocol','allow_telnet_protocol','allow_binary_socket'],
        'pdu_digital_loggers': ['name','type','description','ip_address','address_location','coordinates','web_url','launch_via_nodegrid','username','credential','allow_pre-shared_ssh_key','enable_device_state_detection_based_on_network_traffic','enable_hostname_detection','multisession','read-write_multisession','enable_send_break','icon','mode','expiration','end_point','skip_authentication_to_access_device','escape_sequence','power_control_key','show_text_information','enable_ip_alias','enable_second_ip_alias','allow_ssh_protocol','allow_telnet_protocol','allow_binary_socket'],
        'pdu_eaton': ['name','type','description','ip_address','address_location','coordinates','web_url','launch_via_nodegrid','username','credential','allow_pre-shared_ssh_key','enable_device_state_detection_based_on_network_traffic','enable_hostname_detection','multisession','read-write_multisession','enable_send_break','icon','mode','expiration','end_point','skip_authentication_to_access_device','escape_sequence','power_control_key','show_text_information','enable_ip_alias','enable_second_ip_alias','allow_ssh_protocol','allow_telnet_protocol','allow_binary_socket'],
        'pdu_enconnex': ['name','type','description','ip_address','address_location','coordinates','web_url','launch_via_nodegrid','username','credential','allow_pre-shared_ssh_key','enable_device_state_detection_based_on_network_traffic','enable_hostname_detection','multisession','read-write_multisession','enable_send_break','icon','mode','expiration','end_point','skip_authentication_to_access_device','escape_sequence','power_control_key','show_text_information','enable_ip_alias','enable_second_ip_alias','allow_ssh_protocol','allow_telnet_protocol','allow_binary_socket'],
        'pdu_geist': ['name','type','description','ip_address','address_location','coordinates','web_url','launch_via_nodegrid','username','credential','allow_pre-shared_ssh_key','enable_device_state_detection_based_on_network_traffic','enable_hostname_detection','multisession','read-write_multisession','enable_send_break','icon','mode','expiration','end_point','skip_authentication_to_access_device','escape_sequence','power_control_key','show_text_information','enable_ip_alias','enable_second_ip_alias','allow_ssh_protocol','allow_telnet_protocol','allow_binary_socket'],
        'pdu_hpe_g2': ['name','type','description','ip_address','address_location','coordinates','web_url','launch_via_nodegrid','username','credential','allow_pre-shared_ssh_key','enable_device_state_detection_based_on_network_traffic','enable_hostname_detection','multisession','read-write_multisession','enable_send_break','icon','mode','expiration','end_point','skip_authentication_to_access_device','escape_sequence','power_control_key','show_text_information','enable_ip_alias','enable_second_ip_alias','allow_ssh_protocol','allow_telnet_protocol','allow_binary_socket'],
        'pdu_ice': ['name','type','description','ip_address','address_location','coordinates','web_url','launch_via_nodegrid','username','credential','allow_pre-shared_ssh_key','enable_device_state_detection_based_on_network_traffic','enable_hostname_detection','multisession','read-write_multisession','enable_send_break','icon','mode','expiration','end_point','skip_authentication_to_access_device','escape_sequence','power_control_key','show_text_information','enable_ip_alias','enable_second_ip_alias','allow_ssh_protocol','allow_telnet_protocol','allow_binary_socket'],
        'pdu_mph2': ['name','type','description','ip_address','address_location','coordinates','web_url','launch_via_nodegrid','username','credential','allow_pre-shared_ssh_key','enable_device_state_detection_based_on_network_traffic','enable_hostname_detection','multisession','read-write_multisession','enable_send_break','icon','mode','expiration','end_point','skip_authentication_to_access_device','escape_sequence','power_control_key','show_text_information','enable_ip_alias','enable_second_ip_alias','allow_ssh_protocol','allow_telnet_protocol','allow_binary_socket'],
        'pdu_pm3000': ['name','type','description','ip_address','address_location','coordinates','web_url','launch_via_nodegrid','username','credential','allow_pre-shared_ssh_key','enable_device_state_detection_based_on_network_traffic','enable_hostname_detection','multisession','read-write_multisession','enable_send_break','icon','mode','expiration','end_point','skip_authentication_to_access_device','escape_sequence','power_control_key','show_text_information','enable_ip_alias','enable_second_ip_alias','allow_ssh_protocol','allow_telnet_protocol','allow_binary_socket'],
        'pdu_raritan': ['name','type','description','ip_address','address_location','coordinates','web_url','launch_via_nodegrid','username','credential','allow_pre-shared_ssh_key','enable_device_state_detection_based_on_network_traffic','enable_hostname_detection','multisession','read-write_multisession','enable_send_break','icon','mode','expiration','end_point','skip_authentication_to_access_device','escape_sequence','power_control_key','show_text_information','enable_ip_alias','enable_second_ip_alias','allow_ssh_protocol','allow_telnet_protocol','allow_binary_socket'],
        'pdu_rittal': ['name','type','description','ip_address','address_location','coordinates','web_url','launch_via_nodegrid','username','credential','allow_pre-shared_ssh_key','enable_device_state_detection_based_on_network_traffic','enable_hostname_detection','multisession','read-write_multisession','enable_send_break','icon','mode','expiration','end_point','skip_authentication_to_access_device','escape_sequence','power_control_key','show_text_information','enable_ip_alias','enable_second_ip_alias','allow_ssh_protocol','allow_telnet_protocol','allow_binary_socket'],
        'pdu_rnx': ['name','type','description','ip_address','address_location','coordinates','web_url','launch_via_nodegrid','username','credential','allow_pre-shared_ssh_key','enable_device_state_detection_based_on_network_traffic','enable_hostname_detection','multisession','read-write_multisession','enable_send_break','icon','mode','expiration','end_point','skip_authentication_to_access_device','escape_sequence','power_control_key','show_text_information','enable_ip_alias','enable_second_ip_alias','allow_ssh_protocol','allow_telnet_protocol','allow_binary_socket'],
        'pdu_servertech': ['name','type','description','ip_address','address_location','coordinates','web_url','launch_via_nodegrid','username','credential','allow_pre-shared_ssh_key','enable_device_state_detection_based_on_network_traffic','enable_hostname_detection','multisession','read-write_multisession','enable_send_break','icon','mode','expiration','end_point','skip_authentication_to_access_device','escape_sequence','power_control_key','show_text_information','enable_ip_alias','enable_second_ip_alias','allow_ssh_protocol','allow_telnet_protocol','allow_binary_socket'],
        'pdu_tripplite': ['name','type','description','ip_address','address_location','coordinates','web_url','launch_via_nodegrid','username','credential','allow_pre-shared_ssh_key','enable_device_state_detection_based_on_network_traffic','enable_hostname_detection','multisession','read-write_multisession','enable_send_break','icon','mode','expiration','end_point','skip_authentication_to_access_device','escape_sequence','power_control_key','show_text_information','enable_ip_alias','enable_second_ip_alias','allow_ssh_protocol','allow_telnet_protocol','allow_binary_socket'],
        'switch_edgecore': ['name','type','description','ip_address','address_location','coordinates','web_url','launch_via_nodegrid','username','credential','allow_pre-shared_ssh_key','enable_device_state_detection_based_on_network_traffic','enable_hostname_detection','multisession','read-write_multisession','enable_send_break','icon','mode','expiration','end_point','skip_authentication_to_access_device','escape_sequence','power_control_key','show_text_information','enable_ip_alias','enable_second_ip_alias','allow_ssh_protocol','allow_telnet_protocol','allow_binary_socket'],
        'switch_zpe': ['name','type','description','ip_address','address_location','coordinates','web_url','launch_via_nodegrid','username','credential','allow_pre-shared_ssh_key','enable_device_state_detection_based_on_network_traffic','enable_hostname_detection','multisession','read-write_multisession','enable_send_break','icon','mode','expiration','end_point','skip_authentication_to_access_device','escape_sequence','power_control_key','show_text_information','enable_ip_alias','enable_second_ip_alias','allow_ssh_protocol','allow_telnet_protocol','allow_binary_socket'],
        'ups_apc': ['name','type','description','ip_address','address_location','coordinates','web_url','launch_via_nodegrid','username','credential','allow_pre-shared_ssh_key','enable_device_state_detection_based_on_network_traffic','enable_hostname_detection','multisession','read-write_multisession','enable_send_break','icon','mode','expiration','end_point','skip_authentication_to_access_device','escape_sequence','power_control_key','show_text_information','enable_ip_alias','enable_second_ip_alias','allow_ssh_protocol','allow_telnet_protocol','allow_binary_socket'],
        'ups_netagent': ['name','type','description','ip_address','address_location','coordinates','web_url','launch_via_nodegrid','username','credential','allow_pre-shared_ssh_key','enable_device_state_detection_based_on_network_traffic','enable_hostname_detection','multisession','read-write_multisession','enable_send_break','icon','mode','expiration','end_point','skip_authentication_to_access_device','escape_sequence','power_control_key','show_text_information','enable_ip_alias','enable_second_ip_alias','allow_ssh_protocol','allow_telnet_protocol','allow_binary_socket'],
        'virtual_console_kvm': ['name','type','description','ip_address','port','address_location','coordinates','web_url','launch_via_nodegrid','username','credential','allow_pre-shared_ssh_key','enable_device_state_detection_based_on_network_traffic','multisession','read-write_multisession','enable_send_break','icon','mode','expiration','end_point','skip_authentication_to_access_device','escape_sequence','power_control_key','show_text_information','enable_ip_alias','enable_second_ip_alias','allow_ssh_protocol','allow_telnet_protocol','allow_binary_socket'],
        'virtual_console_vmware': ['name','type','description','ip_address','address_location','coordinates','web_url','launch_via_nodegrid','allow_pre-shared_ssh_key','enable_device_state_detection_based_on_network_traffic','vm_manager','multisession','read-write_multisession','enable_send_break','icon','mode','expiration','end_point','skip_authentication_to_access_device','escape_sequence','power_control_key','show_text_information','enable_ip_alias','enable_second_ip_alias','allow_ssh_protocol','allow_telnet_protocol','allow_binary_socket'],
    },
    'launch_via_nodegrid': ['method'],
    'enable_door_control': ['rfid_reader_device'],
    'method': ('validate', ['browser_forwarder','internal_browser']),
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
}
