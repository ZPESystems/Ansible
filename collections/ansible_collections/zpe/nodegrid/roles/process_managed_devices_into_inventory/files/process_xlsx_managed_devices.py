#!/usr/bin/env python3

import pandas as pd
import argparse
import os
import sys


sheets = {
    'NGM': 'zpe_ngm_ansible_devices.csv',
    'IP_Devices': 'zpe_ngm_ip_devices.csv',
    'Serial_Ports': 'zpe_ngm_serial_devices.csv',
    'USB_Ports': 'zpe_ngm_usb_devices.csv',
    'Discovery_Rules': 'zpe_ngm_discovery_rules.csv',
    'Groups': 'zpe_ngm_groups.csv',
    'Device_Permissions': 'zpe_ngm_device_permissions.csv',
}

def process_xlsx_to_csv_files(excel_filename):
    try:
        ansible_nodes = []
        all_sheets = pd.read_excel(excel_filename, sheet_name=None)
        for sheet_name, filename in sheets.items():
            if not sheet_name in all_sheets:
                continue
            df = all_sheets[sheet_name]
            print(f"{sheet_name}")
            if "Export" in df.columns:
                df = df[df['Export'].str.fullmatch('yes', case=False)]
            if sheet_name == "NGM":
                df = df.drop_duplicates(subset=['ansible_inventory_name'], keep='first')
                ansible_nodes = df['ansible_inventory_name'].unique()
            elif 'ansible_inventory_name' in df.columns:
                df = df[df['ansible_inventory_name'].isin(ansible_nodes)]
            df = df.drop('Export', axis=1, errors='ignore')
            df.to_csv(filename, index=False)
        return True

    except Exception as e:
        print(f"Error processing xlsx file: {str(e)}")
    return False

# Function to validate if a file exists and if it is readable            
def validate_file(file_name, access_priv=os.R_OK):
    if not(os.path.isfile(file_name) and os.access(file_name, access_priv)):
        print(f"The file '{file_name}' does not exist or is not readable.")
        return False
    return True

# Function to validate the args
def validate_args(args):
    if not (args.nodegrid_importer_xlsx):
        print(f"Nodegrid Importer xlsx file not defined.")
        return False
    if args.nodegrid_importer_xlsx:
        if not validate_file(args.nodegrid_importer_xlsx):
            print(f"Error accessing Nodegrid Importer xlsx file: {args.nodegrid_importer_xlsx}")
            return False
    return True

# Main function
def main(args):
    if not validate_args(args):
        return -1
    
    if not process_xlsx_to_csv_files(args.nodegrid_importer_xlsx):
        print(f"Error in processing xlsx file: {args.nodegrid_importer_xlsx}")
        return -1
    return 0

# Entry point
if __name__ == '__main__':
    parser = argparse.ArgumentParser()    
    parser.add_argument('--nodegrid_importer_xlsx', type=str, required=True, help='Nodegrid Importer xlsx template file.', metavar='Nodegrid_Importer_Template.xlsx')
    args = parser.parse_args()
    sys.exit(main(args))
