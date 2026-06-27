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
from ansible_collections.zpe.nodegrid.plugins.module_utils.nodegrid_util import nodegrid_cli, check_os_version_support, run_option, format_settings, field_exist, result_failed, to_list, execute_cmd, read_path_options, NodegridError, nodegrid_cli_validate_inputs, cli_settings_reorder
import os, json, pexpect, re
from collections import OrderedDict
import traceback
from ansible_collections.zpe.nodegrid.plugins.module_utils.managed_devices_dependencies import validate_management_fields, validate_logging_fields, local_managed_device_type, protected_devices_types, get_device_family_dependencies, device_family_type_dependencies, device_family_type_protocol_options 

# We have to remove the SID from the Environmental settings, to avoid an issue
# were we can not run pexpect.run multiple times
if "DLITF_SID" in os.environ:
    del os.environ["DLITF_SID"]
if "DLITF_SID_ENCRYPT" in os.environ:
    del os.environ["DLITF_SID_ENCRYPT"]



def check_current_managed_device(managed_device, timeout=60):
    try:
        cmd = dict(cmd=f"export_settings /settings/devices/{managed_device['name']}/access")
        with nodegrid_cli(timeout) as cmd_cli:
            cmd_result = execute_cmd(cmd_cli, cmd, timeout=timeout)
    except (NodegridError, Exception) as e:
        return dict(error=True, current_type=None, msg=e)
    return dict(error=False, current_type=cmd_result['json'][0]['data']['type'], msg='')

def check_managed_device_type(device_type, timeout=60):
    device_type_details = None
    try:
        cmds = [dict(cmd=f"show /settings/types/{device_type}"), dict(cmd=f"export_settings /settings/types/{device_type}")]
        with nodegrid_cli(timeout) as cmd_cli:
            for cmd in cmds:
                cmd_result = execute_cmd(cmd_cli, cmd, timeout=timeout)
                if not device_type_details:
                    device_type_details = cmd_result['json'][0]['data']
                else:
                    device_type_details['clone_key'] = cmd_result['json'][0]['data']['#clone_key']
    except (NodegridError, Exception) as e:
        return dict(error=True, device_type=None, msg=e)
    return dict(error=False, device_type=device_type_details, msg='')

def get_managed_device_types(timeout=60):
    try:
        cmd = dict(cmd=f"show /settings/types/")
        with nodegrid_cli(timeout) as cmd_cli:
            cmd_result = execute_cmd(cmd_cli, cmd, timeout=timeout)
    except (NodegridError, Exception) as e:
        return dict(error=True, current_type=None, msg=e)
    return dict(error=False, managed_device_types=[md_type.get('device type name').lower() for md_type in cmd_result['json'][0]['data']], msg='')


def run_option_device_type(option, run_opt):
    suboptions = option['suboptions']
    cli_path = option['cli_path']
    check_mode = run_opt['check_mode']
    timeout = run_opt.get('timeout', 60)
    cmds = []
    cmd_results = None
    
    if not ('clone_type' in suboptions):
        return result_failed("Field 'clone_type' is required")
    
    if not ('device_type_name' in suboptions):
        return result_failed("Field 'device_type_name' is required")

    # Get Managed Devices Types
    get_md_types = get_managed_device_types(timeout=timeout)
    if get_md_types['error']:
        return result_failed(f"Error getting current managed devices types. Message: {get_md_types['msg']}")
    managed_device_types = get_md_types['managed_device_types']
    
    if suboptions['clone_type'] not in managed_device_types:
        return result_failed(f"Managed device clone_type '{suboptions['clone_type']}' does not exist. Valid options include: '{managed_device_types}'.")
    
    if suboptions['clone_type'] not in protected_devices_types.keys():
        device_type_details = check_managed_device_type(suboptions['clone_type'], timeout=timeout)
        if device_type_details['error']:
            return result_failed(f"Error getting clone device type '{suboptions['clone_type']}' details. Message: {device_type_details['msg']}")
        clone_family = device_type_details['device_type']['family']
    else:
        clone_family = protected_devices_types[suboptions['clone_type']]['family']

    if suboptions['device_type_name'] in managed_device_types:
        if suboptions['device_type_name'] not in protected_devices_types.keys():
            device_type_details = check_managed_device_type(suboptions['device_type_name'], timeout=timeout)
            if device_type_details['error']:
                return result_failed(f"Error getting device type '{suboptions['device_type_name']}' details. Message: {device_type_details['msg']}")
            current_family = device_type_details['device_type']['family']
        else:
            current_family = protected_devices_types[suboptions['device_type_name']]['family']
        if current_family != clone_family:
            return result_failed(f"Managed device type name '{suboptions['device_type_name']}' is already defined, family='{current_family}'. This conflicts with the new family requested '{clone_family}' derived from clone_type='{suboptions['clone_type']}'.")

    else:
        cmds.append({'confirm': True,'cmd': f"cd /settings/types; clone_type {suboptions['clone_type']}; set device_type_name={suboptions['device_type_name']}; commit"})
        cmd_results = list()
        cmd_result = dict()
        if not check_mode:
            try:
                with nodegrid_cli(timeout=timeout) as cmd_cli:
                    for cmd in cmds:
                        cmd_result = execute_cmd(cmd_cli, cmd, timeout=timeout)
                        cmd_results.append(cmd_result)
            except (NodegridError, Exception) as e:
                return result_failed(msg=f"Failed cloning device type. Clone type='{suboptions['clone_type']}', device_type_name='{suboptions['device_type_name']}'. Error: f{e}")
    suboptions['family'] = clone_family
    device_type_name = suboptions['device_type_name']
    # Clean the required options
    try:
        settings_tobe_deleted = set(['clone_type', 'device_type_name'])
        suboptions = nodegrid_cli_validate_inputs(suboptions, device_family_type_dependencies, settings_tobe_deleted=settings_tobe_deleted)
    except Exception as e:
        return {'failed': True, 'changed': False, 'msg': f"{suboptions['access']} | Key/value error: {e} | {traceback.format_exc()}"}
    suboptions.pop('family')

    if 'protocol' in suboptions and not suboptions['protocol'] in device_family_type_protocol_options[clone_family]:
        return result_failed(f"Protol option '{suboptions['protocol']}' is not valid. Valid options: {device_family_type_protocol_options[clone_family]}")

    cli_path += f"/{device_type_name}"   
    option['cli_path'] = cli_path
    #option['settings'] = settings_list
    result = run_option(option, run_opt)

    if check_mode:
        if cmds:
            result['cmds'] = cmds
        return result

    # If device named was changed, update the return result
    if cmd_results:
        result['cmds_output'] = cmd_results
        result['changed'] = True
    return result


def run_option_device(option, run_opt):
    suboptions = option['suboptions']
    cli_path = option['cli_path']
    check_mode = run_opt['check_mode']
    timeout = run_opt.get('timeout', 60)
    settings_list = []
    cmds = []
    cmd_results = None
    change_name_message = None

    if not ('access' in suboptions and field_exist(suboptions['access'], 'name')):
        return result_failed("Field 'access/name' is required")
    
    if not ('access' in suboptions and field_exist(suboptions['access'], 'type')):
        return result_failed("Field 'access/type' is required")
    
    # Get Managed Devices Types
    get_md_types = get_managed_device_types(timeout=timeout)
    if get_md_types['error']:
        return result_failed(f"Error getting current managed devices types. Message: {get_md_types['msg']}")
    managed_device_types = get_md_types['managed_device_types']

    if suboptions['access']['type'] not in managed_device_types:
        return result_failed(f"Managed device type '{suboptions['access']['type']}' not supported. Supported values include: {managed_device_types}")
    
    # Control device type
    device_type = suboptions['access']['type']
    if device_type not in protected_devices_types.keys():
        device_type_details = check_managed_device_type(device_type, timeout=timeout)
        if device_type_details['error']:
            return result_failed(f"Error getting device type '{device_type}' details. Message: {device_type_details['msg']}")
        device_family = device_type_details['device_type']['family']
        clone_key = device_type_details['device_type']['clone_key']
    else:
        device_family = protected_devices_types[device_type]['family']
        clone_key = suboptions['access']['type']

    suboptions["access"]["family"] = device_family
    device_dependencies = get_device_family_dependencies()

    # Clean the required options
    try:
        settings_tobe_deleted = set(['ssh_key_type', 'ssh_private_key', 'ssh_public_key'])
        suboptions["access"] = nodegrid_cli_validate_inputs(suboptions["access"], device_dependencies, settings_tobe_deleted=settings_tobe_deleted)
        suboptions['access'] = cli_settings_reorder(suboptions['access'], device_dependencies,initial_order=OrderedDict(name=suboptions['access']['name']))
    except Exception as e:
        return {'failed': True, 'changed': False, 'msg': f"{suboptions['access']} | Key/value error: {e} | {traceback.format_exc()}"}
    
    suboptions["access"].pop("family", None)
        
    # Control if the device is TTY or USB: it must have the port_name option
    if ('port_name' in suboptions['access']):
        port_name = suboptions['access']['port_name']
        suboptions['access'].pop('port_name')

        # Change managed device name supported only for devices connected through tty or usb (local_serial / usb_serial)
        # The name is changed based on an specific cli command (i.e., no via import_settings). For example:
        # /settings/devices/ttyS1-router1 {spm_rename},ttyS1,spm_name
        #
        # Validate 'port_name' format against the pattern ttyS{numbers} or usbS{numbers}-{numbers}
        pattern = re.compile("^ttyS([0-9]+)$|^ttyS([0-9]+)-([0-9]+)$|^usbS([0-9]+)$|^usbS([0-9]+)-([0-9]+)$")
        if pattern.match(port_name):
            new_name = suboptions['access']['name'].strip()
            suboptions['access'].pop('name')
            device_options_cli = read_path_options(f"/settings/devices/{port_name}/access")
            if device_options_cli['error']:
                return result_failed(f"Failed to read options: 'show /settings/devices/{port_name}/access'. Error: {device_options_cli}")

            device_options = device_options_cli.get('options', None)
            if device_options is None or not device_options:
                return result_failed(f"Device port '{port_name}' could not be detected by 'show /settings/devices/{port_name}/access'. msg: {device_options_cli}")

            current_name = device_options.get('name',None)
            if current_name is None:
                return result_failed(f"Failing to get device name for port '{port_name}'. Device options: f{device_options_cli}")

            pattern = re.compile("^ttyS([0-9]+)$|^ttyS([0-9]+)-([0-9]+)$")
            if pattern.match(port_name):
                # serial port type options
                if device_type not in local_managed_device_type['serial']:
                    return result_failed(f"Serial port '{port_name}' does not support type '{device_type}'. Supported types include:{local_managed_device_type['serial']}")
            else:
                # usb port type options
                if device_type not in local_managed_device_type['usb']:
                    return result_failed(f"USB port '{port_name}' does not support type '{device_type}'. Supported types include:{local_managed_device_type['usb']}")

            # First change the managed device type if the new type is different
            if suboptions["access"]["type"].strip() != device_options["type"].strip():
                cmds.append({'confirm': True,'cmd': f"cd /settings/devices/{current_name}/access; set type={suboptions['access']['type']}"})
                cmd_results = list()
                cmd_result = dict()
                if not check_mode:
                    try:
                        with nodegrid_cli(timeout=timeout) as cmd_cli:
                            for cmd in cmds:
                                cmd_result = execute_cmd(cmd_cli, cmd, timeout=timeout)
                                cmd_results.append(cmd_result)
                    except (NodegridError, Exception) as e:
                        return result_failed(msg=f"Failed changing device '{current_name}'/access type='{suboptions['access']['type']}'. Current type: '{device_options['type']}'. Error: f{e}")
            # Change the managed device  name if it is different
            if new_name != current_name:
                cmds.append({'confirm': True,'cmd': f"cd /settings/devices; rename {current_name}; set new_name={new_name}"})
                cmd_results = list()
                cmd_result = dict()
                if not check_mode:
                    try:
                        with nodegrid_cli(timeout=timeout) as cmd_cli:
                            for cmd in cmds:
                                cmd_result = execute_cmd(cmd_cli, cmd, timeout=timeout)
                                cmd_results.append(cmd_result)
                        change_name_message = f"managed_device_name: {current_name} -> {new_name}"
                        cli_path += f"/{new_name}"
                    except (NodegridError, Exception) as e:
                        return result_failed(msg=f"Failed changing name device '{current_name}'/port name='{port_name}' with name '{new_name}'. Error: f{e}")
            else:
                cli_path += f"/{current_name}"
        else:
            return result_failed(f"Port name '{port_name}' not supported [Device: {suboptions}]. Port names supported include 'ttyS*' and 'usbS*'")
    else:
        check_managed_device = check_current_managed_device(suboptions['access'], timeout=timeout)
        if not check_managed_device['error'] and suboptions["access"]["type"].strip() != check_managed_device["current_type"].strip():
            # First change the managed device type if the new type is different
            cmds.append({'confirm': True,'cmd': f"cd /settings/devices/{suboptions['access']['name']}/access; set type={suboptions['access']['type']}"})
            cmd_results = list()
            cmd_result = dict()
            if not check_mode:
                try:
                    with nodegrid_cli(timeout=timeout) as cmd_cli:
                        for cmd in cmds:
                            cmd_result = execute_cmd(cmd_cli, cmd, timeout=timeout)
                            cmd_results.append(cmd_result)
                except (NodegridError, Exception) as e:
                    return result_failed(msg=f"Failed changing device '{suboptions['access']['name']}'/access type='{suboptions['access']['type']}'. Current type: '{check_managed_device['current_type']}'. Error: f{e}")
        cli_path += f"/{suboptions['access']['name'].strip()}"

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
            try:
                settings_list.extend(validate_logging_fields(f"{cli_path}/{key}", clone_key, value))
            except (Exception, NodegridError) as e:
                return result_failed(f"Failed validating Logging Fields. Error: {e}")
        # Management
        elif key in ['management']:
            try:
                settings_list.extend(validate_management_fields(f"{cli_path}/{key}", clone_key, value))
            except (Exception, NodegridError) as e:
                return result_failed(f"Failed validating Management Fields. Error: {e}")
        # Access 
        elif key in ['access']:
            settings_list.extend( format_settings(f"{cli_path}/{key}",value) )
        else:
            return result_failed(f"Suboption '{key}' not supported!")

    option['cli_path'] = cli_path
    option['settings'] = settings_list
    result = run_option(option, run_opt)

    if check_mode:
        if cmds:
            result['cmds'] = cmds
        return result

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
    result = dict(
        changed=False,
        failed=False,
    )

    try:
        raw = pexpect.run('llconf ini -si /etc/spm_server.ini json')
        parsed = json.loads(raw)
    except Exception as e:
        result['failed'] = True
        result['msg'] = f"Error executing 'llconf/json'. Error: {e}"
        return result
        

    inventory = {
        "managed_devices": [],
        "device_disabled": [],
        "device_enabled": [],
        "device_ondemand": [],
        }

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
    result['devices'] = inventory
    return result

def run_module():
    # define available arguments/parameters a user can pass to the module
    module_args = dict(
        device=dict(type='dict', required=False),
        type=dict(type='dict', required=False),
        auto_discovery=dict(type='dict', required=False),
        skip_invalid_keys=dict(type='bool', default=False, required=False),
        facts=dict(type='bool', default=False, required=False),
        timeout=dict(type='int', default=60, required=False),
        debug=dict(type='bool', default=False, required=False),
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
            'name': 'type',
            'suboptions': module.params['type'],
            'cli_path': '/settings/types',
            'func': run_option_device_type
        },
        {
            'name': 'auto_discovery',
            'suboptions': module.params['auto_discovery'],
            'cli_path': '/settings/auto_discovery',
            'func': run_option_auto_discovery
        },
        {
            'name': 'facts',
            'suboptions': module.params['facts'] if isinstance(module.params['facts'], bool) and module.params['facts'] else None,
            'cli_path': '',
            'func': facts
        },
    ]

    #
    # Nodegrid OS section starts here
    #
    # Lets get the current interface status and check if it must be changed
    res, err_msg, nodegrid_os = check_os_version_support(timeout=module.params['timeout'])
    if res == 'error' or res == 'unsupported':
        module.fail_json(msg=err_msg, **result)
    elif res == 'warning':
        result['warning'] = err_msg
        use_config_start_global = False
    else:
        use_config_start_global = True

    if module.params['debug']:
        result['nodegrid_os'] = nodegrid_os
    
    # Not required for Managed Devices to create an snapshot before any task
    use_config_start_global = False
    #
    # Lets run the options
    #
    run_opt = {
        'skip_invalid_keys': module.params['skip_invalid_keys'],
        'use_config_start_global' : use_config_start_global,
        'check_mode': module.check_mode,
        'timeout': module.params['timeout'],
        'debug': module.params['debug']
    }

    for option in option_list:
        if option['suboptions'] is not None:
            func = option['func']
            res = func(option, run_opt)
            if res['failed']:
                result.pop('output', None)
                result['failed'] = True
                module.fail_json(msg=res['msg'], **result)
            if option['name'] == 'facts':
                result['facts'] = res['devices']
                result['failed'] = False
            else:
                result['output'][option['name']] = res

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
