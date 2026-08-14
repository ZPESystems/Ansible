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
from ansible_collections.zpe.nodegrid.plugins.module_utils.nodegrid_util import check_os_version_support, run_option, format_settings, field_exist, result_failed, to_list, read_path_options, NodegridError, nodegrid_cli_validate_inputs, pop_keys, cli_settings_reorder, run_cli_command, run_cli_commands
from ansible_collections.zpe.nodegrid.plugins.module_utils.managed_devices_dependencies import validate_management_fields, validate_logging_fields, local_managed_device_type, protected_devices_types, get_device_family_dependencies, device_family_type_dependencies, device_family_type_protocol_options 
import os, re
from collections import OrderedDict

# We have to remove the SID from the Environmental settings, to avoid an issue
# were we can not run pexpect.run multiple times
if "DLITF_SID" in os.environ:
    del os.environ["DLITF_SID"]
if "DLITF_SID_ENCRYPT" in os.environ:
    del os.environ["DLITF_SID_ENCRYPT"]


def check_current_managed_device(managed_device, timeout=60):
    cmd = dict(cmd=f"export_settings /settings/devices/{managed_device['name']}/access")
    cmd_result = run_cli_command(cmd, timeout=timeout)
    if cmd_result['error']:
        return dict(error=True, current_type=None, msg=cmd_result['msg'])
    return dict(error=False, current_type=cmd_result['json'][0]['data']['type'], msg='')


def check_managed_device_type(device_type, timeout=60):
    device_type_details = None
    cmds = [dict(cmd=f"show /settings/types/{device_type}", json=True), dict(cmd=f"export_settings /settings/types/{device_type}", json=True)]
    run_cmds =  run_cli_commands(cmds, timeout=timeout)
    if run_cmds['error']:
        return dict(error=True, device_type=None, msg=run_cmds['msg'])
    device_type_details = run_cmds['cmds_results'][0]['json'][0]['data']
    device_type_details['clone_key'] = run_cmds['cmds_results'][1]['json'][0]['data']['#clone_key']
    return dict(error=False, device_type=device_type_details, msg='')


def get_managed_device_types(timeout=60):
    cmd = dict(cmd=f"show /settings/types/")
    cmd_result = run_cli_command(cmd, timeout=timeout)
    if cmd_result['error']:
        return dict(error=True, managed_device_types=[], msg=cmd_result['msg'])
    return dict(error=False, managed_device_types=[md_type.get('device type name').lower() for md_type in cmd_result['json'][0]['data']], msg='')


def run_option_devices(option, run_opt):
    devices = option['suboptions']
    cli_path = option['cli_path']
    check_mode = run_opt['check_mode']
    change_name_message = ''
    settings_list = []
    cmds = list()
    cmds_results = list()
    for adevice in devices:
        device={
            'access': {key: value for key, value in adevice.items() if key not in ['custom_fields', 'management', 'logging', 'commands']},
            'management': {} if not 'management' in adevice else adevice['management'],
            'custom_fields': [] if not 'custom_fields' in adevice else adevice['custom_fields'],
            'logging': {} if not 'logging' in adevice else adevice['logging'],
            'commands': [] if not 'commands' in adevice else adevice['commands'],
        }
        device_result = run_option_device(device, cli_path, run_opt)
        if not "failed" in device_result:
            settings_list += device_result['settings']
            if 'cmds' in device_result:
                cmds.extend(device_result['cmds'])
            if 'change_name_message' in device_result:
                change_name_message += f"| {device_result['change_name_message']}"
            if 'cmds_results' in device_result:
                cmds_results.extend(device_result['cmds_results'])

    options = {
        'name': 'devices',
        'cli_path': '/settings/devices',
        'suboptions': '',
        'settings': settings_list
        }
    
    result = run_option(options, run_opt)

    if check_mode:
        if cmds:
            result['cmds'] = cmds
        return result

    # If device named was changed, update the return result
    if cmds_results:
        result['cmds_output'] = cmds_results
        result['changed'] = True
        if result['message'] == 'No change required':
            result['message'] = change_name_message
        else:
            result['message'] += f" | {change_name_message}"
    return result


def run_option_device(device, cli_path, run_opt):
    device_result = {
        'cli_path': cli_path,
        'settings': [],
    }
    check_mode = run_opt['check_mode']
    timeout = run_opt.get('timeout', 60)
    settings_list = []
    cmds = list()
    cmds_results = list()
    change_name_message = None

    if not ('access' in device and field_exist(device['access'], 'name')):
        return result_failed("Field 'access/name' is required")
    
    if not ('access' in device and field_exist(device['access'], 'type')):
        return result_failed("Field 'access/type' is required")
    
    # Get Managed Devices Types
    get_md_types = get_managed_device_types(timeout=timeout)
    if get_md_types['error']:
        return result_failed(f"Error getting current managed devices types. Message: {get_md_types['msg']}")
    managed_device_types = get_md_types['managed_device_types']

    if device['access']['type'] not in managed_device_types:
        return result_failed(f"Managed device type '{device['access']['type']}' not supported. Supported values include: {managed_device_types}")
    
    # Control device type
    device_type = device['access']['type']
    if device_type not in protected_devices_types.keys():
        device_type_details = check_managed_device_type(device_type, timeout=timeout)
        if device_type_details['error']:
            return result_failed(f"Error getting device type '{device_type}' details. Message: {device_type_details['msg']}")
        device_family = device_type_details['device_type']['family']
        clone_key = device_type_details['device_type']['clone_key']
    else:
        device_family = protected_devices_types[device_type]['family']
        clone_key = device['access']['type']

    device["access"]["family"] = device_family
    device_dependencies = get_device_family_dependencies()

    # Clean the required options
    try:
        settings_tobe_deleted = set(['ssh_key_type', 'ssh_private_key', 'ssh_public_key'])
        device["access"] = nodegrid_cli_validate_inputs(device["access"], device_dependencies, settings_tobe_deleted=settings_tobe_deleted)
        device['access'] = cli_settings_reorder(device['access'], device_dependencies,initial_order=OrderedDict(name=device['access']['name']))
    except Exception as e:
        return {'failed': True, 'changed': False, 'msg': f"Error validating/ordering input values. Error: {e}"}
    
    device["access"].pop("family", None)

    # Control if the device is TTY or USB: it must have the port_name option
    if ('port_name' in device['access']):
        port_name = device['access']['port_name']
        device['access'].pop('port_name')

        # Change managed device name supported only for devices connected through tty or usb (local_serial / usb_serial)
        # The name is changed based on an specific cli command (i.e., no via import_settings). For example:
        # /settings/devices/ttyS1-router1 {spm_rename},ttyS1,spm_name
        #
        # Validate 'port_name' format against the pattern ttyS{numbers} or usbS{numbers}-{numbers}
        pattern = re.compile("^ttyS([0-9]+)$|^ttyS([0-9]+)-([0-9]+)$|^usbS([0-9]+)$|^usbS([0-9]+)-([0-9]+)$")
        if pattern.match(port_name):
            new_name = device['access']['name'].strip()
            device['access'].pop('name')
            device_options_cli = read_path_options(f"/settings/devices/{port_name}/access")
            if device_options_cli['error']:
                return result_failed(f"Failed to read options: 'show /settings/devices/{port_name}/access'. Error: {device_options_cli}")

            device_options = device_options_cli.get('options', None)
            if device_options is None or not device_options:
                return result_failed(f"Device port '{port_name}' could not be detected by 'show /settings/devices/{port_name}/access'. msg: {device_options_cli}")

            current_name = device_options.get('name',None)
            if current_name is None:
                return result_failed(f"Failing to get device name for port '{port_name}'. Device options: {device_options_cli}")
            
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
            if device["access"]["type"].strip() != device_options["type"].strip():
                cmds.append({'confirm': True,'cmd': f"cd /settings/devices/{current_name}/access; set type={device['access']['type']}"})
                if not check_mode:
                    run_cmds =  run_cli_commands(cmds, timeout=timeout, max_retries=run_opt.get('max_retries'), base_delay=run_opt.get('base_delay'), max_delay=run_opt.get('max_delay'))
                    if run_cmds['error']:
                        return result_failed(msg=f"Failed changing device '{current_name}'/access type='{device['access']['type']}'. Current type: '{device_options['type']}'. Error: {run_cmds['msg']}")
                    cmds_results.extend(run_cmds['cmds_results'])
            # Change the managed device  name if it is different
            if new_name != current_name:
                cmds.append({'confirm': True,'cmd': f"cd /settings/devices; rename {current_name}; set new_name={new_name}"})
                if not check_mode:
                    run_cmds =  run_cli_commands(cmds, timeout=timeout, max_retries=run_opt.get('max_retries'), base_delay=run_opt.get('base_delay'), max_delay=run_opt.get('max_delay'))
                    if run_cmds['error']:
                        return result_failed(msg=f"Failed changing name device '{current_name}'/port name='{port_name}' with name '{new_name}'. Error: {run_cmds['msg']}")
                    cmds_results.extend(run_cmds['cmds_results'])
                    change_name_message = f"managed_device_name: {current_name} -> {new_name}"
                    cli_path += f"/{new_name}"
            else:
                cli_path += f"/{current_name}"
        else:
            return result_failed(f"Port name '{port_name}' not supported [Device: {device}]. Port names supported include 'ttyS*' and 'usbS*'")
    else:
        check_managed_device = check_current_managed_device(device['access'], timeout=timeout)
        if not check_managed_device['error'] and device["access"]["type"].strip() != check_managed_device["current_type"].strip():
            # First change the managed device type if the new type is different
            cmds.append({'confirm': True,'cmd': f"cd /settings/devices/{device['access']['name']}/access; set type={device['access']['type']}"})
            if not check_mode:
                run_cmds =  run_cli_commands(cmds, timeout=timeout, max_retries=run_opt.get('max_retries'), base_delay=run_opt.get('base_delay'), max_delay=run_opt.get('max_delay'))
                if run_cmds['error']:
                    return result_failed(msg=f"Failed changing device '{suboptions['access']['name']}'/access type='{suboptions['access']['type']}'. Current type: '{check_managed_device['current_type']}'. Error: {run_cmds['msg']}")
                cmds_results.extend(run_cmds['cmds_results'])
        cli_path += f"/{device['access']['name'].strip()}"

    for key, value in device.items():
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

    #option['cli_path'] = cli_path
    if cmds:
        device_result['cmds'] = cmds
    if cmds_results:
        device_result['cmds_results'] = cmds_results
    if change_name_message:
        device_result['change_name_message'] = change_name_message
    device_result['settings'] = settings_list
    return device_result


def run_module():
    # define available arguments/parameters a user can pass to the module
    module_args = dict(
        devices=dict(type='list', required=False),
        skip_invalid_keys=dict(type='bool', default=False, required=False),
        timeout=dict(type='int', default=60, required=False),
        debug=dict(type='bool', default=False, required=False),
        max_retries=dict(type='int', default=3, required=False),
        base_delay=dict(type='float', default=2.0, required=False),
        max_delay=dict(type='float', default=10.0, required=False),
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
            'name': 'devices',
            'suboptions': module.params['devices'],
            'cli_path': '/settings/devices',
            'func': run_option_devices
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
        'debug': module.params['debug'],
        'max_retries': module.params.get('max_retries', 2),
        'base_delay': module.params.get('base_delay', 2.0), 
        'max_delay': module.params.get('max_delay',10.0),
    }

    for option in option_list:
        if option['suboptions'] is not None:
            func = option['func']
            res = func(option, run_opt)
            if res['failed']:
                result.pop('output', None)
                result['failed'] = True
                module.fail_json(msg=res['msg'], **result)
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
