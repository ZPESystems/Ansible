#!/usr/bin/env python3

import pandas as pd
import argparse
import os
import sys
import re
import csv

special_character = [ '<', '>', ':' ,'"', '/', '\\', '|', '?', '*' ]
ng_invalid_character = [ '"', '/', '\\', '\'' ]

# columns to ignore special_character check
ng_ignore_columns = set(['ssh_private_key', 'ssh_public_key'])
ng_cols_replace = {'ssh_private_key':[r'[\n\r]+', '<br>']}

colnames = set(['Export', 'ansible_inventory_name', 'ansible_host', 'ansible_port', 'ansible_user', 'ansible_ssh_private_key_file',
            'name', 'type', 'ip_address', 'port', 'username', 'password', 'enable_device_state_detection_based_on_network_traffic', 'multisession', 'icon', 'mode', 'end_point', 'port_number',
            'port_name', 'type', 'description', 'address_location', 'username', 'password', 'baud_rate', 'parity', 'flow_control', 'data_bits', 'stop_bits', 'rs-232_signal_for_device_state_detection', 'enable_device_state_detection_based_in_data_flow', 'data_flow_scan_interval', 'enable_hostname_detection', 'multisession', 'read-write_multisession', 'enable_serial_port_settings_via_escape_sequence', 'icon', 'mode', 'allow_ssh_protocol', 'ssh_port', 'ssh_key_type', 'allow_pre-shared_ssh_key',
            'name', 'port_name', 'type', 'description', 'address_location', 'username', 'password', 'baud_rate', 'parity', 'flow_control', 'data_bits', 'stop_bits', 'rs-232_signal_for_device_state_detection', 'enable_device_state_detection_based_in_data_flow', 'data_flow_scan_interval', 'enable_hostname_detection', 'multisession', 'read-write_multisession', 'enable_serial_port_settings_via_escape_sequence', 'icon', 'mode', 'map_to_virtual_machine', 'virtual_machine_name',
            'rule_name', 'status', 'method', 'action', 'clone_from', 'enforce_device_type', 'inherit_appliance_credentials',
            'Group_Name', 'Device_Name', 'session', 'power', 'door', 'mks', 'kvm', 'reset_device', 'sp_console', 'virtual_media', 'access_log_audit', 'access_log_clear', 'event_log_audit', 'event_log_clear', 'sensors_data', 'monitoring', 'custom_commands',
        ])

pattern = '[' + re.escape(''.join(ng_invalid_character)) + ']'

sheets = {
    'NGM': 'zpe_ngm_ansible_devices.csv',
    'IP_Devices': 'zpe_ngm_ip_devices.csv',
    'Serial_Ports': 'zpe_ngm_serial_devices.csv',
    'USB_Ports': 'zpe_ngm_usb_devices.csv',
    'Discovery_Rules': 'zpe_ngm_discovery_rules.csv',
    'Groups': 'zpe_ngm_groups.csv',
    'Device_Permissions': 'zpe_ngm_device_permissions.csv',
}

def remove_special_characters(text):
    if isinstance(text, str): # Ensure the value is a string before applying regex
        return re.sub(pattern, '_', text)
    return text

def process_xlsx_to_csv_files(excel_filename):
    try:
        ansible_nodes = []
        all_sheets = pd.read_excel(excel_filename, sheet_name=None, dtype=str)
        for sheet_name, filename in sheets.items():
            if not sheet_name in all_sheets:
                continue
            df = all_sheets[sheet_name]
            if "Export" in df.columns:
                df = df[df['Export'].str.fullmatch('yes', case=False)]
            if sheet_name == "NGM":
                df = df.drop_duplicates(subset=['ansible_inventory_name'], keep='first')
                ansible_nodes = df['ansible_inventory_name'].unique()
                if (df['ansible_host'] == '').sum() > 0 or df['ansible_host'].isnull().sum() > 0:
                    return False, f"ansible_host field must be filled in all rows."
            elif 'ansible_inventory_name' in df.columns:
                df = df[df['ansible_inventory_name'].isin(ansible_nodes)]
                for colname in set(df.columns) - ng_ignore_columns:
                    df[colname] = df[colname].apply(remove_special_characters)
            for colname, replacement in ng_cols_replace.items():
                if colname in df.columns:
                    df[colname] = df[colname].str.replace(replacement[0], replacement[1], regex=True)
            for colname in set(df.columns) - colnames:
                df[colname] = "'" + df[colname] + "'"
            df = df.drop('Export', axis=1, errors='ignore')
            df.to_csv(filename, index=False, quoting=csv.QUOTE_NONE, quotechar="'", escapechar="\\")
        return True, ''

    except Exception as e:
        return False, f"Error processing xlsx file: {str(e)}"
    return False, ''

# Function to validate if a file exists and if it is readable            
def validate_file(file_name, access_priv=os.R_OK):
    if not(os.path.isfile(file_name) and os.access(file_name, access_priv)):
        return False, f"The file '{file_name}' does not exist or is not readable."
    return True, ''

# Function to validate the args
def validate_args(args):
    if not (args.nodegrid_importer_xlsx):
        return False, f"Nodegrid Importer xlsx file not defined."
    if args.nodegrid_importer_xlsx:
        result,msg = validate_file(args.nodegrid_importer_xlsx)
        if not result:
            return False, f"Error accessing Nodegrid Importer xlsx file: {args.nodegrid_importer_xlsx}. \\ {msg}"
    return True, ''

# Main function
def main(args):
    result,msg = validate_args(args)
    if not result:
        print(f"Error in processing xlsx file: {args.nodegrid_importer_xlsx}. Output: {msg}")
        return -1
    
    result,msg = process_xlsx_to_csv_files(args.nodegrid_importer_xlsx)
    if not result:
        print(f"Error in processing xlsx file: {args.nodegrid_importer_xlsx}. Output: {msg}")
        return -1
    return 0

# Entry point
if __name__ == '__main__':
    parser = argparse.ArgumentParser()    
    parser.add_argument('--nodegrid_importer_xlsx', type=str, required=True, help='Nodegrid Importer xlsx template file.', metavar='Nodegrid_Importer_Template.xlsx')
    args = parser.parse_args()
    sys.exit(main(args))
