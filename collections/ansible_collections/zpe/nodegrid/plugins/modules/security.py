#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2023, ZPE Systems <zpesystems.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r'''
'''

EXAMPLES = r'''
- name: Add authorization
  zpe.nodegrid.security:
    authorization:
    name: 'dev'
    profile:
        # Permissions begin
        track_system_information: "yes"
        terminate_sessions: "no"
        software_upgrade_and_reboot_system: "no"
        configure_system: "no"
        configure_user_accounts: "no"
        apply_&_save_settings: "no"
        shell_access: "no"
        manage_devices_permissions: "no"
        # Permissions end
        restrict_configure_system_permission_to_read_only: "no"
        menu-driven_access_to_devices: "no"
        sudo_permission: "no"
        custom_session_timeout: "no"
        startup_application: "cli"
        email_events_to: ""
    remote_groups:
        remote_groups: ""
    devices:
      - name: NSC
        mks: "no"
        kvm: "no"
        reset_device: "no"
        sp_console: "no"
        virtual_media: "no"
        access_log_audit: "no"
        access_log_clear: "no"
        event_log_audit: "no"
        event_log_clear: "no"
        sensors_data: "no"
        monitoring: "no"
        custom_commands: "no"
        session: "read-write"
        power: "power_control"
        door: "no_access"
    # outlets:  Not supported yet
- name: Add authorization with Managed devices with manage device permissions
  zpe.nodegrid.security:
    authorization:
    name: 'dev'
    profile:
        # Permissions begin
        track_system_information: "yes"
        terminate_sessions: "no"
        software_upgrade_and_reboot_system: "no"
        configure_system: "no"
        configure_user_accounts: "no"
        apply_&_save_settings: "no"
        shell_access: "no"
        manage_devices_permissions: "yes"
        # Permissions end
        # Managed Devices Permissions begin
        manage_devices_general_settings: "yes"
        manage_devices_connection_settings: "no"
        manage_devices_inbound_access_settings: "no"
        manage_devices_management: "no"
        manage_devices_logging: "no"
        manage_devices_custom_fields: "no"
        manage_devices_commands: "no"
        manage_devices_outlets: "no"
        manage_devices_sensor_channels: "no"
        # Managed Devices Permissions end
        restrict_configure_system_permission_to_read_only: "no"
        menu-driven_access_to_devices: "no"
        sudo_permission: "no"
        custom_session_timeout: "no"
        startup_application: "cli"
        email_events_to: ""
'''

RETURN = r'''

'''

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.zpe.nodegrid.plugins.module_utils.nodegrid_util import run_option, check_os_version_support, format_settings, run_option_adding_field_in_the_path, field_exist, result_failed, field_not_exist, to_list, get_cli, execute_cmd, close_cli, read_table, read_table_row, run_option_no_diff, read_path_option, export_settings, settings_to_dict, result_nochanged
from collections import defaultdict

import os

# We have to remove the SID from the Environmental settings, to avoid an issue
# were we can not run pexpect.run multiple times
if "DLITF_SID" in os.environ:
    del os.environ["DLITF_SID"]
if "DLITF_SID_ENCRYPT" in os.environ:
    del os.environ["DLITF_SID_ENCRYPT"]

def run_option_local_account(option, run_opt):
    return run_option_adding_field_in_the_path(option, run_opt, 'username')

def run_authorization_profile(option, run_opt):
    profile = option['suboptions']['profile']
    profile_path = f"{option['cli_path']}/profile"

    #
    # Step 1: Apply general settings and only system permissions
    #

    # Remove all manage device permissions
    permissions_list = [
        'manage_devices_permissions',
        'manage_devices_general_settings',
        'manage_devices_connection_settings',
        'manage_devices_inbound_access_settings',
        'manage_devices_management',
        'manage_devices_logging',
        'manage_devices_custom_fields',
        'manage_devices_commands',
        'manage_devices_outlets',
        'manage_devices_sensor_channels']
    permissions_dict = {}
    for item in permissions_list:
        if item in profile:
            permissions_dict[item] = profile[item]
            profile.pop(item, None)

    # Update permissions
    manage_devices_permissions_enabled = permissions_dict.get('manage_devices_permissions', 'no') == 'yes'
    if manage_devices_permissions_enabled:
        profile['configure_system'] = 'no'
        profile['configure_user_accounts'] = 'no'
    else:
        profile = {**{'manage_devices_permissions': 'no'}, **profile}  # Add in the beginning

    # Apply system permissions
    option['settings'] = format_settings(profile_path,profile)
    profile_result = run_option(option, run_opt)
    if profile_result['failed']:
        return profile_result

    #
    # Step 2: Apply manage devices permissions
    #
    if manage_devices_permissions_enabled:

        # Export the current settings
        state, exported_settings, exported_all_settings = export_settings(profile_path)
        if "error" in state:
            return result_failed(str(state[1]))
        current_settings = settings_to_dict(exported_settings)[profile_path]

        # diff settings
        permissions_dict = {**{'manage_devices_permissions': 'yes'}, **permissions_dict}
        for key, value in current_settings.items():
            if key in permissions_dict and permissions_dict[key] == value:
                permissions_dict.pop(key, None)

        if len(permissions_dict) == 0:
            return result_nochanged()

        profile_result['changed'] = True

        # Add manage devices permissions in a sigle line cli command
        try:
            timeout = run_opt['timeout'] if 'timeout' in run_opt else 60
            cmd_cli = get_cli(timeout=timeout)
            cmd_line = []
            for key, value in permissions_dict.items():
                cmd_line.append(f"{key}='{value}'")
            cmds = [
                {'cmd': f"cd {profile_path}"},
                {'cmd': f"set {' '.join(cmd_line)}"},
                {'cmd': 'commit'}
            ]
            cmd_results = []
            for cmd in cmds:
                cmd_result = execute_cmd(cmd_cli, cmd)
                cmd_result['command'] = cmd.get('cmd')
                cmd_results.append(cmd_result)
                if cmd_result['error']:
                    profile_result['failed'] = True
                    profile_result['changed'] = False
                    break
            close_cli(cmd_cli)
            profile_result['cmds_output'] = cmd_results
        except Exception as exc:
            return result_failed(str(exc))
    return profile_result

def run_option_authorization(option, run_opt):
    suboptions = option['suboptions']
    cli_path = option['cli_path']

    field_name = 'name'
    if field_not_exist(suboptions, field_name):
        return result_failed(f"Field '{field_name}' is required")

    name = suboptions[field_name]
    cli_path += f"/{name}"
    option['cli_path'] = cli_path
    suboptions.pop(field_name, None)

    all_results = dict(
        changed = False,
        failed = False,
    )

    for key, value in suboptions.items():

        # devices
        if key == 'devices':
            for item in to_list(value):
                field_name = 'name'
                if field_exist(item, field_name):
                    device_name = item[field_name]
                    item.pop(field_name, None)
                    option['settings'] = format_settings(f"{cli_path}/{key}/{device_name}",item)
                    result = run_option(option, run_opt)
                    if result['failed']:
                        return result
                    all_results['devices'] = result
                else:
                    return result_failed(f"Field '{key}/{field_name}' is required")

        # profile
        elif key == 'profile':
            result = run_authorization_profile(option, run_opt)
            if result['failed']:
                return result
            all_results['profile'] = result

        # remote_groups
        elif key == 'remote_groups':
            option['settings'] = format_settings(f"{cli_path}/{key}",value)
            result = run_option(option, run_opt)
            if result['failed']:
                return result
            all_results[key] = result

        else:
            return result_failed(f"Invalid authorization option key: '{key}'")

    for key, value in all_results.items():
        if type(value) is dict:
            if value['changed']:
                all_results['changed'] = True
                break
    return all_results


def run_option_authentication(option, run_opt):
    suboptions = option['suboptions']
    cli_path = option['cli_path']
    settings_list = []

    for key, value in suboptions.items():

        # 2-factor, sso
        if key in ['2-factor', 'sso']:
            for item in to_list(value):
                field_name = 'name'
                if field_exist(item, field_name):
                    settings_list.extend( format_settings(f"{cli_path}/{key}/{item[field_name]}",item) )
                else:
                    return result_failed(f"Field '{key}/{field_name}' is required")
        #[TODO] Validated against 5.8 and 6.0 there are changes

        # servers
        elif key in ['servers']:
            #option['import_func'] = run_option_authentication_import
            # Servers table header
            #  index  method  remote server  status   fallback
            servers_table = read_table("/settings/authentication/servers/")
            if servers_table[0].lower() == 'error':
                return result_failed(f"Failed to get authentication servers table on cli: 'show /settings/authentication/servers'. Error: {servers_table[1]}")
            temp_key = len(servers_table[1]['rows'])

            if isinstance(value,list):
                field_name = 'number'
                for server in sorted(value, key=lambda x: x.get(field_name, float('inf'))):
                    if 'method' in server.keys() and server['method'].lower() == "local":
                        server.pop('method')
                        server.pop(field_name) if field_name in server.keys() else None
                        if len(value) == 1:
                            settings_list.extend( format_settings(f"{cli_path}/{key}/1",server))
                        continue
                    elif field_name not in server.keys():
                        return result_failed(f"Field '{field_name}' is required, server is: {server}")
                    else:
                        server_key = server.pop(field_name)
                        authentication_server = read_table_row(servers_table[1], 0, f"{server_key}")
                    if authentication_server:
                        try:
                            read_option = read_path_option(f"{cli_path}/{key}/{server_key}", "method")
                        except Exception as e:
                            return result_failed(f"Failed to get option 'method' from path '{cli_path}/{key}/{server_key}'. Error: {e}")

                        if read_option[0].lower() == 'error':
                            return result_failed(f"Failed to get option 'method' from path '{cli_path}/{key}/{server_key}'. Error: {read_option[1]}")

                        if read_option[1]['value'] == server['method']: #in ['kerberos', 'ldap_or_ad', 'radius', 'tacacs+']:
                            settings_list.extend( format_settings(f"{cli_path}/{key}/{server_key}",server) )
                        else:
                            temp_key += 1
                            settings_list.extend( format_settings(f"{cli_path}/{key}/{temp_key}",server) )
                    else:
                        temp_key += 1
                        settings_list.extend( format_settings(f"{cli_path}/{key}/{temp_key}",server) )
            else:
                return result_failed(f"Authentication Servers have to be provided as a list")
        # console, default_group, realms
        else:
           settings_list.extend( format_settings(f"{cli_path}/{key}",value) )

    option['cli_path'] = cli_path
    option['settings'] = settings_list
    return run_option_no_diff(option, run_opt)
    # return {'failed': False, 'changed': False, 'settings_list': settings_list}

def run_option_authentication_validate_servers(option, run_opt):
    suboptions = option['suboptions']
    cli_path = option['cli_path']
    
    result = dict(
        changed=False,
        failed=False,
        message=''
    )

    for key, value in suboptions.items():
        # servers
        if key in ['servers']:
            # Servers table header
            #  index  method  remote server  status   fallback
            servers_table = read_table("/settings/authentication/servers/")
            if servers_table[0].lower() == 'error':
                return result_failed(f"Failed to get authentication servers table on cli: 'show /settings/authentication/servers'. Error: {servers_table[1]}")

            servers_nodegrid = sum(server[1].lower() != "local" for server in servers_table[1]['rows'])
            server_index = 0

            
            if isinstance(value,list):
                servers_config = sum(server.get('method', '').lower() != "local" for server in value)
                if servers_nodegrid != servers_config:
                    return result_failed(f"Authentication Servers have not been properly configured. Servers on nodegrid = {servers_nodegrid}, Servers on ansible configuration= {servers_config}")
                for server in sorted(value, key=lambda x: x.get('number', float('inf'))):
                    if server.get('method', "").lower() == "local":
                        continue
                    try:
                        server_key = servers_table[1]['rows'][server_index][0] 
                        read_option = read_path_option(f"{cli_path}/{server_key}", "method")
                    except Exception as e:
                        return result_failed(f"Failed to get option 'method' from path '{cli_path}/{server_key}'. Error: {e}")

                    if read_option[0].lower() == 'error':
                        return result_failed(f"Failed to get option 'method' from path '{cli_path}/{server_key}'. Error: {read_option[1]}")

                    if read_option[1]['value'].lower() == server.get('method',"").lower(): 
                        server_index += 1
                    else:
                        return result_failed(f"Authentication Servers have not been properly configured. Server index: {server_key} method {read_option[1]['value'].lower()} does not match with server: {server}")
            else:
                return result_failed(f"Authentication Servers have to be provided as a list")
        else:
            return result_failed(f"Authentication 'servers' section is not defined!")

    result['message'] = "Authentication Servers have been properly configured!"
    return result

def run_module():
    # define available arguments/parameters a user can pass to the module
    module_args = dict(
        local_account=dict(type='dict', required=False),
        authentication=dict(type='dict', required=False),
        authentication_validate_servers=dict(type='dict', required=False),
        authorization=dict(type='dict', required=False),
        password_rules=dict(type='dict', required=False),
        skip_invalid_keys=dict(type='bool', default=False, required=False),
        timeout=dict(type=int, default=60)
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
            'name': 'password_rules',
            'suboptions': module.params['password_rules'],
            'cli_path': '/settings/password_rules', 
            'func': run_option
        },
        {
            'name': 'local_account',
            'suboptions': module.params['local_account'],
            'cli_path': '/settings/local_accounts', 
            'func': run_option_local_account
        },
        {
            'name': 'authorization',
            'suboptions': module.params['authorization'],
            'cli_path': '/settings/authorization', 
            'func': run_option_authorization
        },
        {
            'name': 'authentication',
            'suboptions': module.params['authentication'],
            'cli_path': '/settings/authentication', 
            'func': run_option_authentication
        },
        {
            'name': 'authentication_validate_servers',
            'suboptions': module.params['authentication_validate_servers'],
            'cli_path': '/settings/authentication/servers', 
            'func': run_option_authentication_validate_servers
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
        'timeout': module.params['timeout']
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
