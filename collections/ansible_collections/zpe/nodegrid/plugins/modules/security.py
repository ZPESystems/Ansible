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
from ansible_collections.zpe.nodegrid.plugins.module_utils.nodegrid_util import run_option, check_os_version_support, format_settings, run_option_adding_field_in_the_path, field_exist, result_failed, field_not_exist, to_list, get_cli, execute_cmd, close_cli, read_table, read_table_row, run_option_no_diff, read_path_option, export_settings, settings_to_dict, result_nochanged, dict_diff
from collections import defaultdict

import os

# We have to remove the SID from the Environmental settings, to avoid an issue
# were we can not run pexpect.run multiple times
if "DLITF_SID" in os.environ:
    del os.environ["DLITF_SID"]
if "DLITF_SID_ENCRYPT" in os.environ:
    del os.environ["DLITF_SID_ENCRYPT"]

def run_option_local_account(option, run_opt):
    result = dict(
        failed=False,
        msg=""
    )
    local_account_config = option['suboptions']
    local_accounts_check = get_local_accounts()

    if local_accounts_check['error']:
        return run_option_adding_field_in_the_path(option, run_opt, 'username')
    for local_account in local_accounts_check['local_accounts']:
        if local_account['username'] == local_account_config['username']:
            local_account_nodegrid = _get_local_account(local_account['username'])
            if local_account_nodegrid.get('error', False):
                return run_option_adding_field_in_the_path(option, run_opt, 'username')
            if local_account_config['hash_format_password'] == 'no':
                try:
                    import crypt
                    salt = local_account_nodegrid['password'][0:local_account_nodegrid['password'].rfind("$")+1]
                    password_hashed = crypt.crypt(local_account_config['password'], salt)
                except:
                    password_hashed = ""
            else:
                password_hashed = local_account_config['password']

            if password_hashed == local_account_nodegrid['password']:
                local_account_config['password'] = password_hashed
                local_account_config['hash_format_password'] = 'yes'
            return run_option_adding_field_in_the_path(option, run_opt, 'username')
    return run_option_adding_field_in_the_path(option, run_opt, 'username')

def get_local_accounts(timeout=60) -> dict:
    cmd_cli = get_cli(timeout=timeout)
    #build cmd
    cmd = {
        'cmd' : f"show /settings/local_accounts"
    }
    cmd_result = execute_cmd(cmd_cli, cmd)
    close_cli(cmd_cli)
    result = dict(error=False, local_accounts=[], msg='')
    local_accounts = []
    if cmd_result['error']:
        result['error'] = True
        result['msg'] = f"Cannot get local accounts. Error: {cmd_result['error']}"
    else:
        for local_account in cmd_result['json'][0]['data']:
            local_accounts.append(local_account)
        result['local_accounts'] = local_accounts
    return result

def _get_local_account(username, timeout=60) -> dict:
    #build cmd
    cmd_cli = get_cli(timeout=timeout)
    cmd: dict = {
        'cmd' : f"export_settings /settings/local_accounts/{username} --plain-password"
    }
    cmd_result = execute_cmd(cmd_cli, cmd)
    close_cli(cmd_cli)
    data = {}
    if cmd_result['error']:
        return dict(error=True, msg=f"Error getting local_account username {username}. Error: {cmd_result['stdout']}")
    else:
       return cmd_result['json'][0]['data']

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
                    profile_result['msg'] = cmd_result['json']
                    profile_result['changed'] = False
                    cmd_result = execute_cmd(cmd_cli, dict(cmd='cancel', ignore_error=True))
                    cmd_result = execute_cmd(cmd_cli, dict(cmd='revert', ignore_error=True))
                    cmd_result = execute_cmd(cmd_cli, dict(cmd='config_revert', ignore_error=True))
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

def authentication_servers_validate(servers_nodegrid, servers):
    result = dict(
        failed=False,
        msg=""
    )

    number_servers_nodegrid = sum(server.get('method','').lower() != "local" for server in servers_nodegrid)
    number_servers_config = sum(server.get('method', '').lower() != "local" for server in servers)

    if number_servers_nodegrid != number_servers_config:
        result['failed'] = True
        result['msg'] = f"Number of Authentication Servers is different."
        return result
    elif number_servers_nodegrid == 0:
        return result

    field = 'number'
    if 'index' in servers_nodegrid[0]:
        field = 'index'
    for index in range(0, number_servers_nodegrid):
        server_nodegrid = _get_authentication_server(servers_nodegrid[index].get(field))
        if server_nodegrid.get('error', False):
            result['failed'] = True
            result['msg'] = f"Error getting Authentication Server. Current {server_nodegrid}, Desired: {server}, Error: {server_nodegrid['msg']}"
            return result
        server = servers[index]
        diff_state = dict_diff(server,server_nodegrid)
        if len(diff_state) != 0:
            result['failed'] = True
            result['msg'] = f"authentication server diff. Current {server_nodegrid}, Desired: {server}, Servers Nodegrid: {servers_nodegrid}, Diff: {diff_state}"
            return result
    return result

def _get_authentication_server(server_index, timeout=60) -> dict:
    #build cmd
    cmd_cli = get_cli(timeout=timeout)
    cmd: dict = {
        'cmd' : f"export_settings /settings/authentication/servers/{server_index} --plain-password"
    }
    cmd_result = execute_cmd(cmd_cli, cmd)
    close_cli(cmd_cli)
    data = {}
    if cmd_result['error']:
        return dict(error=True, msg=f"Error getting authentication server index {server_index}. Error: {cmd_result['stdout']}")
    else:
       return cmd_result['json'][0]['data']

def get_servers_present(timeout=60) -> dict:
    cmd_cli = get_cli(timeout=timeout)
    #build cmd
    cmd = {
        'cmd' : f"show /settings/authentication/servers/"
    }
    cmd_result = execute_cmd(cmd_cli, cmd)
    close_cli(cmd_cli)
    result = dict(error=False, servers=[], msg='')
    servers = []
    if cmd_result['error']:
        result['error'] = True
        result['msg'] = f"Cannot get present authentication servers. Error: {cmd_result['error']}"
    else:
        for server in cmd_result['json'][0]['data']:
            servers.append(server)
        if len(servers) > 0:
            field = 'number'
            if 'index' in servers[0]:
                field = 'index'
            result['servers'] = sorted(servers, key=lambda x: x.get(field, float('inf')))
    return result


def run_option_authentication_servers(option, run_opt):
    result = {'failed': False, 'changed': False, 'msg': ""}
    servers = option['suboptions']
    cli_path = option['cli_path']
    settings_list = []

    servers_nodegrid = get_servers_present()
    if servers_nodegrid['error']:
        return result_failed(f"Failed to get authentication servers table on cli: 'show /settings/authentication/servers'. Error: {servers_nodegrid['msg']}")

    temp_key = len(servers_nodegrid['servers'])
    key = 'servers'
    field_name = 'number'
    if 'index' in servers_nodegrid['servers'][0]:
        field_name = 'index'

    servers_validate = authentication_servers_validate(servers_nodegrid['servers'], sorted(servers, key=lambda x: x.get('number' if 'number' in x else 'index', float('inf'))))

    if servers_validate['failed']:
        result['servers_warning'] = servers_validate['msg']
        for server in sorted(servers, key=lambda x: x.get('number' if 'number' in x else 'index', float('inf'))):
            if 'method' in server.keys() and server['method'].lower() == "local":
                server.pop('method')
                server.pop('index' if 'index' in server else 'number', None)
                if len(servers) == 1:
                    settings_list.extend(format_settings(f"{cli_path}/servers/1",server))
                continue
            elif 'index' not in server.keys() and 'number' not in server.keys():
                return result_failed(f"Field 'index' or 'number' is required for server: {server}")
            else:
                server_key = server.pop('index' if 'index' in server else 'number', None)
                settings_list.extend(format_settings(f"{cli_path}/{server_key}",server))
        option['settings'] = settings_list

    if run_opt["check_mode"]:
        result['settings'] = settings_list
        result['msg'] = 'Running in check_mode. Nothing has changed'
        return result
    if len(settings_list) > 0:
        return run_option_no_diff(option, run_opt)
    else:
        return result

def run_option_authentication_validate_servers(option, run_opt):
    servers = option['suboptions']
    cli_path = option['cli_path']

    servers_nodegrid = get_servers_present()
    if servers_nodegrid['error']:
        return result_failed(f"Failed to get authentication servers table on cli: 'show /settings/authentication/servers'. Error: {servers_nodegrid['msg']}")

    result = dict(
        changed=False,
        failed=False,
        message=''
    )

    servers_validate = authentication_servers_validate(servers_nodegrid['servers'], sorted(servers, key=lambda x: x.get('number' if 'number' in x else 'index', float('inf'))))
    if servers_validate['failed']:
        result['message'] = f"Authentication Servers have not been properly configured. {servers_validate['msg']}"
        result['failed'] = True
    else:
        result['message'] = "Authentication Servers have been properly configured."
    return result


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
            result_failed(f"Key not valid: {key}. Authentication Servers must be configured defining a list named: 'authentication_servers'.")

        # console, default_group, realms
        else:
            settings_list.extend( format_settings(f"{cli_path}/{key}",value) )

    option['cli_path'] = cli_path
    option['settings'] = settings_list
    return run_option(option, run_opt)


def run_module():
    # define available arguments/parameters a user can pass to the module
    module_args = dict(
        local_account=dict(type='dict', required=False),
        authentication=dict(type='dict', required=False),
        authentication_validate_servers=dict(type='dict', required=False),
        authentication_servers=dict(type='list', required=False),
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
        {
            'name': 'authentication_servers',
            'suboptions': module.params['authentication_servers'],
            'cli_path': '/settings/authentication/servers',
            'func': run_option_authentication_servers
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
