#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2023, ZPE Systems <zpesystems.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r'''
module: wireguard
author: Diego Montero (@zpe-diegom)
short_description: This module handles Wireguard configuration on Nodegrid OS
version_added: "1.0.0"
description: The module is used to manage the Wireguard options on Nodegrid OS 6.0.20 or newer
options:
    skip_invalid_keys:
        description: Skip invalid settings keys if they don't exist in the Nodegrid model/OS version
        required: False
        default: False

'''

EXAMPLES = r'''

'''

RETURN = r'''

'''

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.zpe.nodegrid.plugins.module_utils.nodegrid_util import run_option, check_os_version_support, run_option_adding_field_in_the_path, run_option_adding_field_in_the_path_and_append_path, field_exist, export_settings, get_cli, close_cli, execute_cmd

import os
from collections import OrderedDict
import traceback, subprocess

# We have to remove the SID from the Environmental settings, to avoid an issue
# were we can not run pexpect.run multiple times
if "DLITF_SID" in os.environ:
    del os.environ["DLITF_SID"]
if "DLITF_SID_ENCRYPT" in os.environ:
    del os.environ["DLITF_SID_ENCRYPT"]

def generate_wireguard_keys():
    """
    Generate a WireGuard private & public key
    Requires that the 'wg' command is available on PATH
    Returns (private_key, public_key), both strings
    """
    privkey = subprocess.check_output("wg genkey", shell=True).decode("utf-8").strip()
    pubkey = subprocess.check_output(f"echo '{privkey}' | wg pubkey", shell=True).decode("utf-8").strip()
    return dict(private=privkey, public=pubkey)

def get_wireguard_public_key(private_key):
    """
    Generate a WireGuard public key from a private key
    Requires that the 'wg' command is available on PATH
    Returns public_key string
    """
    try:
        pubkey = subprocess.check_output(f"echo '{private_key}' | wg pubkey", shell=True).decode("utf-8").strip()
        return dict(error=False, msg='', public_key=pubkey)
    except subprocess.CalledProcessError as e:
        return dict(error=True, msg=e.output, public_key="")

def _get_wireguard_peer(interface_name, peer_name, cmd_cli) -> dict:
    #build cmd
    cmd: dict = {
        'cmd' : f"show /settings/wireguard/{interface_name}/peers/{peer_name}"
    }
    cmd_result = execute_cmd(cmd_cli, cmd)
    if cmd_result['error']:
        return dict(error=True, msg=f"Error getting peer info {peer_name} for endpoint {interface_name}. Error: {cmd_result['stdout']}")
    else:
        return {peer_name: cmd_result['json'][0]['data']}

def _get_wireguard_endpoint(interface_name, cmd_cli) -> dict:
    #build cmd
    cmd: dict = {
        'cmd' : f"show /settings/wireguard/{interface_name}/interfaces"
    }
    cmd_result = execute_cmd(cmd_cli, cmd)
    data = dict(interfaces={}, peers=[])
    if cmd_result['error']:
        return dict(error=True, msg=f"Error getting endpoint info for {interface_name}. Error: {cmd_result['stdout']}")
    else:
        data['interfaces'] = cmd_result['json'][0]['data']


    #build cmd
    cmd: dict = {
        'cmd' : f"show /settings/wireguard/{interface_name}/peers"
    }
    cmd_result = execute_cmd(cmd_cli, cmd)
    if cmd_result['error']:
        return dict(error=True, msg=f"Cannot get present wireguard peers for endpoint {interface_name}. Error: {cmd_result['error']}")
    else:
        for item in cmd_result['json']:
            for peer in item['data']:
                if 'peer name' in peer.keys():
                    peer_name = peer['peer name']
                    data['peers'].extend([_get_wireguard_peer(interface_name=interface_name, peer_name=peer_name, cmd_cli=cmd_cli) ])
    return {interface_name: data}

def get_wireguard_endpoints_present(timeout=60) -> dict:
    cmd_cli = get_cli(timeout=timeout)
    #build cmd
    cmd = {
        'cmd' : f"show /settings/wireguard"
    }
    cmd_result = execute_cmd(cmd_cli, cmd)
    data = dict(error=False, endpoints=[], msg='')
    if cmd_result['error']:
        return dict(error=True, msg=f"Cannot get present wireguard endpoints. Error: {cmd_result['error']}")
    else:
        for item in cmd_result['json']:
            for endpoint in item['data']:
                if 'interface name' in endpoint.keys():
                    interface_name = endpoint['interface name']
                    data['endpoints'].extend([_get_wireguard_endpoint(interface_name=interface_name, cmd_cli=cmd_cli) ])
    close_cli(cmd_cli)
    return data

# ##########################################################
# Wireguard Server endpoint
def run_option_wireguard_server_endpoint(option, run_opt):
    suboptions = option['suboptions']
    # Settings to be deleted/discarded if empty
    settings_to_delete_if_empty = []

    # Required fields 
    required_fields = ['interface_name', 'internal_address', 'listening_port']
    # Optional fields 
    optional_fields = ['external_address', 'keypair', 'mtu', 'public_key', 'status', 'fwmark', 'keepalive', 'private_key', 'routing_rules']
    
    options_to_be_deleted = []
    for key in suboptions.keys():
        if not key in required_fields + optional_fields + ['interface_type']:
            options_to_be_deleted.append(key)
    for key in options_to_be_deleted:
        suboptions.pop(key, None) 

    for field in required_fields:
        if field not in suboptions:
            return {'failed': True, 'changed': False, 'msg': f"setting '{field}' is required!. Required settings: {required_fields}. Optional settings: {optional_fields}"}

    if 'interface_type' in suboptions and suboptions['interface_type'] != 'server':
        return {'failed': True, 'changed': False, 'msg': f"'interface_type must' be 'server'!"}
    elif 'interface_type' not in suboptions:
        suboptions['interface_type'] = 'server'

    # Check if wireguard interface_name already exists and if it is of different interface_type
    wireguard_endpoints_present = option['wireguard_endpoints_present']
    for wg_endpoint in wireguard_endpoints_present:
        if suboptions['interface_name'] in wg_endpoint.keys():
            if wg_endpoint[suboptions['interface_name']]['interfaces']['interface_type'] != suboptions['interface_type']:
                return {'failed': True, 'changed': False, 'msg': f"Wireguard interface '{suboptions['interface_name']}' already exists and it is of type '{wg_endpoint[suboptions['interface_name']]['interfaces']['interface_type']}'. It is not possible to change it to type '{suboptions['interface_type']}'"}

    # Settings dependencies
    dependencies = OrderedDict()
    dependencies = {
        'interface_type': 
        {
            'server': 
            [
                'external_address', 
                'listening_port'
            ],
            'mesh': 
            [
                'listening_port'
            ]
        },
        'routing_rules':
        {
            'create_routing_rules_on_specific_routing_table': ['table'],
        },
    }
    check_mode = run_opt['check_mode']
    field_name = 'interface_name'

    if 'keypair' in suboptions:
        if suboptions['keypair'] == 'input_manually':
            if not 'private_key' in suboptions or suboptions['private_key'] == "":
                return {'failed': True, 'changed': False, 'msg': f"keypair = '{suboptions['keypair']}'. Private key is required and must not be empty valid Wireguar key."}
            get_public_key = get_wireguard_public_key(suboptions['private_key'])
            if get_public_key['error']:
                return {'failed': True, 'changed': False, 'msg': f"keypair = '{suboptions['keypair']}'. Failed to get Public key from Private key '{suboptions['private_key']}'. A valid Wireguard Private key is required."}

            if not 'public_key' in suboptions or suboptions['public_key'] == "" or suboptions['public_key'] == None:
                suboptions['public_key'] = get_public_key['public_key']
            elif suboptions['public_key'] != get_public_key['public_key']:
                return {'failed': True, 'changed': False, 'msg': f"keypair = {suboptions['keypair']}. Public key '{suboptions['public_key']}' incorrect. Expected value based on private key {get_public_key['public_key']}"}
        else:
            suboptions.pop('keypair', None)
            suboptions.pop('private_key', None)
            suboptions.pop('public_key', None)

    if suboptions.pop('generate_keys', False):
        wg_key = generate_wireguard_keys()
        suboptions.pop('private_key', None)
        suboptions.pop('public_key', None)
        suboptions['keypair'] = "input_manually"
        suboptions['private_key'] = wg_key['private']
        suboptions['public_key'] = wg_key['public']

    if field_exist(suboptions, field_name):
        # Remove invalid parameters
        try:
            settings_tobe_deleted = set()
            for dependency in dependencies:
                if isinstance(dependencies[dependency], dict):
                    for dep_rem in {key:value for key, value in dependencies[dependency].items() if dependency in suboptions and key not in [suboptions[dependency]]}:
                        for setting in dependencies[dependency][dep_rem]:
                            if (suboptions[dependency] not in dependencies[dependency]) or (setting not in dependencies[dependency][suboptions[dependency]]):
                                settings_tobe_deleted.add(setting)

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

        except Exception as e:
            return {'failed': True, 'changed': False, 'msg': f"{wireguard} | Key/value error: {e} | {traceback.format_exc()}"}

        return run_option_adding_field_in_the_path_and_append_path(option, run_opt, field_name, 'interfaces')
    else:
        return {'failed': True, 'changed': False, 'msg': f"Field '{field_name}' is required"}

# ##########################################################
# Wireguard Server peer
def run_option_wireguard_server_peer(option, run_opt):
    suboptions = option['suboptions']
    # Settings to be deleted/discarded if empty
    settings_to_delete_if_empty = []

    # Required fields 
    required_fields = ['interface_name', 'peer_name', 'allowed_ips', 'public_key']
    # Optional fields 
    optional_fields = ['interface_type', 'description', 'keepalive']
    
    options_to_be_deleted = []
    for key in suboptions.keys():
        if not key in required_fields + optional_fields:
            options_to_be_deleted.append(key)
    for key in options_to_be_deleted:
        suboptions.pop(key, None) 

    for field in required_fields:
        if field not in suboptions:
            return {'failed': True, 'changed': False, 'msg': f"setting '{field}' is required!. Required settings: {required_fields}. Optional settings: {optional_fields}"}

    if 'interface_type' in suboptions and suboptions['interface_type'] != 'server':
        return {'failed': True, 'changed': False, 'msg': "'interface_type' must be 'server'!"}

    # Check if wireguard interface_name exists and if it is interface_type=server
    wireguard_endpoints_present = option['wireguard_endpoints_present']
    wireguard_interface = None
    for wg_endpoint in wireguard_endpoints_present:
        if suboptions['interface_name'] in wg_endpoint.keys():
            wireguard_interface = wg_endpoint
            break

    if wireguard_interface is None:
        return {'failed': True, 'changed': False, 'msg': f"Wireguard interface '{suboptions['interface_name']}' does not exists."}
    if wireguard_interface[suboptions['interface_name']]['interfaces']['interface_type'] != 'server':
        return {'failed': True, 'changed': False, 'msg': f"Wireguard interface '{suboptions['interface_name']}' type is {wireguard_interface[suboptions['interface_name']]['interfaces']['interface_type']}, which is different than 'server'."}
    
    
    path_append = f"peers/{suboptions['peer_name']}"
    check_mode = run_opt['check_mode']
    suboptions.pop('interface_type', None)
    return run_option_adding_field_in_the_path_and_append_path(option, run_opt, 'interface_name', path_append, delete_field_name=True)

# ##########################################################
# Wireguard Client endpoint
def run_option_wireguard_client_endpoint(option, run_opt):
    suboptions = option['suboptions']
    # Settings to be deleted/discarded if empty
    settings_to_delete_if_empty = []

    # Required fields 
    required_fields = ['interface_name', 'internal_address']
    # Optional fields 
    optional_fields = ['keypair', 'mtu', 'public_key', 'status', 'fwmark', 'private_key', 'routing_rules']

    options_to_be_deleted = []
    for key in suboptions.keys():
        if not key in required_fields + optional_fields + ['interface_type']:
            options_to_be_deleted.append(key)
    for key in options_to_be_deleted:
        suboptions.pop(key, None) 

    for field in required_fields:
        if field not in suboptions:
            return {'failed': True, 'changed': False, 'msg': f"setting '{field}' is required!. Required settings: {required_fields}. Optional settings: {optional_fields}"}

    if 'interface_type' in suboptions and suboptions['interface_type'] != 'client':
        return {'failed': True, 'changed': False, 'msg': f"'interface_type must' be 'client'!"}
    elif 'interface_type' not in suboptions:
        suboptions['interface_type'] = 'client'

    # Check if wireguard interface_name already exists and if it is of different interface_type
    wireguard_endpoints_present = option['wireguard_endpoints_present']
    for wg_endpoint in wireguard_endpoints_present:
        if suboptions['interface_name'] in wg_endpoint.keys():
            if wg_endpoint[suboptions['interface_name']]['interfaces']['interface_type'] != suboptions['interface_type']:
                return {'failed': True, 'changed': False, 'msg': f"Wireguard interface '{suboptions['interface_name']}' already exists and it is of type '{wg_endpoint[suboptions['interface_name']]['interfaces']['interface_type']}'. It is not possible to change it to type '{suboptions['interface_type']}'"}

    # Settings dependencies
    dependencies = OrderedDict()
    dependencies = {
        'interface_type': 
        {
            'server': 
            [
                'external_address', 
                'listening_port'
            ],
            'mesh': 
            [
                'listening_port'
            ]
        },
        'routing_rules':
        {
            'create_routing_rules_on_specific_routing_table': ['table'],
        },
    }
    check_mode = run_opt['check_mode']
    field_name = 'interface_name'

    if 'keypair' in suboptions:
        if suboptions['keypair'] == 'input_manually':
            if not 'private_key' in suboptions or suboptions['private_key'] == "":
                return {'failed': True, 'changed': False, 'msg': f"keypair = '{suboptions['keypair']}'. Private key is required and must not be empty valid Wireguar key."}
            get_public_key = get_wireguard_public_key(suboptions['private_key'])
            if get_public_key['error']:
                return {'failed': True, 'changed': False, 'msg': f"keypair = '{suboptions['keypair']}'. Failed to get Public key from Private key '{suboptions['private_key']}'. A valid Wireguard Private key is required."}

            if not 'public_key' in suboptions or suboptions['public_key'] == "" or suboptions['public_key'] == None:
                suboptions['public_key'] = get_public_key['public_key']
            elif suboptions['public_key'] != get_public_key['public_key']:
                return {'failed': True, 'changed': False, 'msg': f"keypair = {suboptions['keypair']}. Public key '{suboptions['public_key']}' incorrect. Expected value based on private key {get_public_key['public_key']}"}
        else:
            suboptions.pop('keypair', None)
            suboptions.pop('private_key', None)
            suboptions.pop('public_key', None)

    if suboptions.pop('generate_keys', False):
        wg_key = generate_wireguard_keys()
        suboptions.pop('private_key', None)
        suboptions.pop('public_key', None)
        suboptions['keypair'] = "input_manually"
        suboptions['private_key'] = wg_key['private']
        suboptions['public_key'] = wg_key['public']

    if field_exist(suboptions, field_name):
        # Remove invalid parameters
        try:
            settings_tobe_deleted = set()
            for dependency in dependencies:
                if isinstance(dependencies[dependency], dict):
                    for dep_rem in {key:value for key, value in dependencies[dependency].items() if dependency in suboptions and key not in [suboptions[dependency]]}:
                        for setting in dependencies[dependency][dep_rem]:
                            if (suboptions[dependency] not in dependencies[dependency]) or (setting not in dependencies[dependency][suboptions[dependency]]):
                                settings_tobe_deleted.add(setting)

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

        except Exception as e:
            return {'failed': True, 'changed': False, 'msg': f"{wireguard} | Key/value error: {e} | {traceback.format_exc()}"}

        return run_option_adding_field_in_the_path_and_append_path(option, run_opt, field_name, 'interfaces')
    else:
        return {'failed': True, 'changed': False, 'msg': f"Field '{field_name}' is required"}

# ##########################################################
# Wireguard Client peer
def run_option_wireguard_client_peer(option, run_opt):
    suboptions = option['suboptions']
    # Settings to be deleted/discarded if empty
    settings_to_delete_if_empty = []

    # Required fields 
    required_fields = ['interface_name', 'peer_name', 'allowed_ips', 'public_key', 'external_address', 'listening_port']
    # Optional fields 
    optional_fields = ['interface_type', 'description', 'keepalive']
    
    options_to_be_deleted = []
    for key in suboptions.keys():
        if not key in required_fields + optional_fields:
            options_to_be_deleted.append(key)
    for key in options_to_be_deleted:
        suboptions.pop(key, None) 

    for field in required_fields:
        if field not in suboptions:
            return {'failed': True, 'changed': False, 'msg': f"setting '{field}' is required!. Required settings: {required_fields}. Optional settings: {optional_fields}"}

    if 'interface_type' in suboptions and suboptions['interface_type'] != 'client':
        return {'failed': True, 'changed': False, 'msg': "'interface_type' must be 'client'!"}

    # Check if wireguard interface_name exists and if it is interface_type=server
    wireguard_endpoints_present = option['wireguard_endpoints_present']
    wireguard_interface = None
    for wg_endpoint in wireguard_endpoints_present:
        if suboptions['interface_name'] in wg_endpoint.keys():
            wireguard_interface = wg_endpoint
            break

    if wireguard_interface is None:
        return {'failed': True, 'changed': False, 'msg': f"Wireguard interface '{suboptions['interface_name']}' does not exists."}
    if wireguard_interface[suboptions['interface_name']]['interfaces']['interface_type'] != 'client':
        return {'failed': True, 'changed': False, 'msg': f"Wireguard interface '{suboptions['interface_name']}' type is {wireguard_interface[suboptions['interface_name']]['interfaces']['interface_type']}, which is different than 'client'."}
    
    
    path_append = f"peers/{suboptions['peer_name']}"
    check_mode = run_opt['check_mode']
    suboptions.pop('interface_type', None)
    return run_option_adding_field_in_the_path_and_append_path(option, run_opt, 'interface_name', path_append, delete_field_name=True)

# ##########################################################
# Wireguard Mesh endpoint
def run_option_wireguard_mesh_endpoint(option, run_opt):
    suboptions = option['suboptions']
    # Settings to be deleted/discarded if empty
    settings_to_delete_if_empty = []

    # Required fields 
    required_fields = ['interface_name', 'internal_address', 'listening_port']
    # Optional fields 
    optional_fields = ['keypair', 'mtu', 'public_key', 'status', 'fwmark', 'private_key', 'routing_rules']
    
    options_to_be_deleted = []
    for key in suboptions.keys():
        if not key in required_fields + optional_fields + ['interface_type']:
            options_to_be_deleted.append(key)
    for key in options_to_be_deleted:
        suboptions.pop(key, None) 

    for field in required_fields:
        if field not in suboptions:
            return {'failed': True, 'changed': False, 'msg': f"setting '{field}' is required!. Required settings: {required_fields}. Optional settings: {optional_fields}"}

    if 'interface_type' in suboptions and suboptions['interface_type'] != 'mesh':
        return {'failed': True, 'changed': False, 'msg': f"'interface_type must' be 'mesh'!"}
    elif 'interface_type' not in suboptions:
        suboptions['interface_type'] = 'mesh'

    # Check if wireguard interface_name already exists and if it is of different interface_type
    wireguard_endpoints_present = option['wireguard_endpoints_present']
    for wg_endpoint in wireguard_endpoints_present:
        if suboptions['interface_name'] in wg_endpoint.keys():
            if wg_endpoint[suboptions['interface_name']]['interfaces']['interface_type'] != suboptions['interface_type']:
                return {'failed': True, 'changed': False, 'msg': f"Wireguard interface '{suboptions['interface_name']}' already exists and it is of type '{wg_endpoint[suboptions['interface_name']]['interfaces']['interface_type']}'. It is not possible to change it to type '{suboptions['interface_type']}'"}

    # Settings dependencies
    dependencies = OrderedDict()
    dependencies = {
        'interface_type': 
        {
            'server': 
            [
                'external_address', 
                'listening_port'
            ],
            'mesh': 
            [
                'listening_port'
            ]
        },
        'routing_rules':
        {
            'create_routing_rules_on_specific_routing_table': ['table'],
        },
    }
    check_mode = run_opt['check_mode']
    field_name = 'interface_name'

    if 'keypair' in suboptions:
        if suboptions['keypair'] == 'input_manually':
            if not 'private_key' in suboptions or suboptions['private_key'] == "":
                return {'failed': True, 'changed': False, 'msg': f"keypair = '{suboptions['keypair']}'. Private key is required and must not be empty valid Wireguar key."}
            get_public_key = get_wireguard_public_key(suboptions['private_key'])
            if get_public_key['error']:
                return {'failed': True, 'changed': False, 'msg': f"keypair = '{suboptions['keypair']}'. Failed to get Public key from Private key '{suboptions['private_key']}'. A valid Wireguard Private key is required."}

            if not 'public_key' in suboptions or suboptions['public_key'] == "" or suboptions['public_key'] == None:
                suboptions['public_key'] = get_public_key['public_key']
            elif suboptions['public_key'] != get_public_key['public_key']:
                return {'failed': True, 'changed': False, 'msg': f"keypair = {suboptions['keypair']}. Public key '{suboptions['public_key']}' incorrect. Expected value based on private key {get_public_key['public_key']}"}
        else:
            suboptions.pop('keypair', None)
            suboptions.pop('private_key', None)
            suboptions.pop('public_key', None)

    if suboptions.pop('generate_keys', False):
        wg_key = generate_wireguard_keys()
        suboptions.pop('private_key', None)
        suboptions.pop('public_key', None)
        suboptions['keypair'] = "input_manually"
        suboptions['private_key'] = wg_key['private']
        suboptions['public_key'] = wg_key['public']

    if field_exist(suboptions, field_name):
        # Remove invalid parameters
        try:
            settings_tobe_deleted = set()
            for dependency in dependencies:
                if isinstance(dependencies[dependency], dict):
                    for dep_rem in {key:value for key, value in dependencies[dependency].items() if dependency in suboptions and key not in [suboptions[dependency]]}:
                        for setting in dependencies[dependency][dep_rem]:
                            if (suboptions[dependency] not in dependencies[dependency]) or (setting not in dependencies[dependency][suboptions[dependency]]):
                                settings_tobe_deleted.add(setting)

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

        except Exception as e:
            return {'failed': True, 'changed': False, 'msg': f"{wireguard} | Key/value error: {e} | {traceback.format_exc()}"}
        return run_option_adding_field_in_the_path_and_append_path(option, run_opt, field_name, 'interfaces')
    else:
        return {'failed': True, 'changed': False, 'msg': f"Field '{field_name}' is required"}

# ##########################################################
# Wireguard Mesh peer
def run_option_wireguard_mesh_peer(option, run_opt):
    suboptions = option['suboptions']
    # Settings to be deleted/discarded if empty
    settings_to_delete_if_empty = []

    # Required fields 
    required_fields = ['interface_name', 'peer_name', 'allowed_ips', 'public_key', 'external_address', 'listening_port']
    # Optional fields 
    optional_fields = ['interface_type', 'description', 'keepalive']
    
    options_to_be_deleted = []
    for key in suboptions.keys():
        if not key in required_fields + optional_fields:
            options_to_be_deleted.append(key)
    for key in options_to_be_deleted:
        suboptions.pop(key, None) 

    for field in required_fields:
        if field not in suboptions:
            return {'failed': True, 'changed': False, 'msg': f"setting '{field}' is required!. Required settings: {required_fields}. Optional settings: {optional_fields}"}

    if 'interface_type' in suboptions and suboptions['interface_type'] != 'mesh':
        return {'failed': True, 'changed': False, 'msg': "'interface_type' must be 'mesh'!"}

    # Check if wireguard interface_name exists and if it is interface_type=server
    wireguard_endpoints_present = option['wireguard_endpoints_present']
    wireguard_interface = None
    for wg_endpoint in wireguard_endpoints_present:
        if suboptions['interface_name'] in wg_endpoint.keys():
            wireguard_interface = wg_endpoint
            break

    if wireguard_interface is None:
        return {'failed': True, 'changed': False, 'msg': f"Wireguard interface '{suboptions['interface_name']}' does not exists."}
    if wireguard_interface[suboptions['interface_name']]['interfaces']['interface_type'] != 'mesh':
        return {'failed': True, 'changed': False, 'msg': f"Wireguard interface '{suboptions['interface_name']}' type is {wireguard_interface[suboptions['interface_name']]['interfaces']['interface_type']}, which is different than 'mesh'."}
    
    
    path_append = f"peers/{suboptions['peer_name']}"
    check_mode = run_opt['check_mode']
    suboptions.pop('interface_type', None)
    return run_option_adding_field_in_the_path_and_append_path(option, run_opt, 'interface_name', path_append, delete_field_name=True)

# ######
# Module

def run_module():
    # define available arguments/parameters a user can pass to the module
    module_args = dict(
        server_endpoint=dict(type='dict', required=False),
        server_peer=dict(type='dict', required=False),
        client_endpoint=dict(type='dict', required=False),
        client_peer=dict(type='dict', required=False),
        mesh_endpoint=dict(type='dict', required=False),
        mesh_peer=dict(type='dict', required=False),
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
    
    wireguard_endpoints_present = get_wireguard_endpoints_present().get('endpoints',{})

    # List of options to run
    option_list = [
        {
            'name': 'server_endpoint',
            'suboptions': module.params['server_endpoint'],
            'cli_path': '/settings/wireguard',
            'wireguard_endpoints_present': wireguard_endpoints_present,
            'func': run_option_wireguard_server_endpoint
        },
        {
            'name': 'server_peer',
            'suboptions': module.params['server_peer'],
            'cli_path': '/settings/wireguard',
            'wireguard_endpoints_present': wireguard_endpoints_present,
            'func': run_option_wireguard_server_peer
        },
        {
            'name': 'client_endpoint',
            'suboptions': module.params['client_endpoint'],
            'cli_path': '/settings/wireguard',
            'wireguard_endpoints_present': wireguard_endpoints_present,
            'func': run_option_wireguard_client_endpoint
        },
        {
            'name': 'client_peer',
            'suboptions': module.params['client_peer'],
            'cli_path': '/settings/wireguard',
            'wireguard_endpoints_present': wireguard_endpoints_present,
            'func': run_option_wireguard_client_peer
        },
        {
            'name': 'mesh_endpoint',
            'suboptions': module.params['mesh_endpoint'],
            'cli_path': '/settings/wireguard',
            'wireguard_endpoints_present': wireguard_endpoints_present,
            'func': run_option_wireguard_mesh_endpoint
        },
        {
            'name': 'mesh_peer',
            'suboptions': module.params['mesh_peer'],
            'cli_path': '/settings/wireguard',
            'wireguard_endpoints_present': wireguard_endpoints_present,
            'func': run_option_wireguard_mesh_peer
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
