#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2023, ZPE Systems <zpesystems.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r'''
---
module: auditing
author: Rene Neumann (@zpe-rneumann)
'''

EXAMPLES = r'''
'''

RETURN = r'''

'''

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.zpe.nodegrid.plugins.module_utils.nodegrid_util import get_cli, close_cli, execute_cmd, check_os_version_support, dict_diff, import_settings

import os


# We have to remove the SID from the Environmental settings, to avoid an issue
# were we can not run pexpect.run multiple times
if "DLITF_SID" in os.environ:
    del os.environ["DLITF_SID"]
if "DLITF_SID_ENCRYPT" in os.environ:
    del os.environ["DLITF_SID_ENCRYPT"]

def get_auditing( endpoint: str , timeout: int = 60 ) -> dict:
    cmd_cli = get_cli(timeout=timeout)

    #build cmd
    cmd = {
        'cmd' : str('show /settings/' + endpoint )
    }
    cmd_result = execute_cmd(cmd_cli, cmd)
    data = {}
    if cmd_result['error']:
       data =  {'error': cmd_result['error']}
    else:
       data =  cmd_result['json'][0]['data']
    close_cli(cmd_cli)
    return data

def resort_rule(rule: dict):
    new_rule: dict = {}
    sort_list = ['enable_persistent_logs','ipv4_remote_server', 'ipv6_remote_server','snmptrap_version']
    for key in sort_list:
        if key in rule.keys():
            new_rule[key] = rule[key]
            rule.pop(key)
    new_rule = {**new_rule, **rule}
    return new_rule

def clean_rule(rule: dict) -> dict:
    destinations_syslog1 = {'key': 'ipv4_remote_server','list':['ipv4_address']}
    destinations_syslog2 = {'key': 'ipv6_remote_server', 'list': ['ipv6_address']}

    master_list = [destinations_syslog1,destinations_syslog2]

    for item in master_list:
        if item['key'] in rule.keys():
                if rule[item['key']] == "no":
                    for remove_key in item['list']:
                        if remove_key in rule.keys():
                            rule.pop(remove_key)

    return rule

def run_module():
    # define available arguments/parameters a user can pass to the module
    module_args = dict(
        auditing_settings=dict(type='dict', required=False),
        events_zpe_cloud=dict(type='dict', required=False),
        events_email=dict(type='dict', required=False),
        events_file=dict(type='dict', required=False),
        events_syslog=dict(type='dict', required=False),
        events_snmp=dict(type='dict', required=False),
        event_list=dict(type='dict', required=False),
        destinations_file=dict(type='dict', required=False),
        destinations_syslog=dict(type='dict', required=False),
        destinations_snmp=dict(type='dict', required=False),
        destinations_email=dict(type='dict', required=False),
        timeout=dict(type=int, default=60),
        debug=dict(type='bool', default=False)
    )

    # seed the result dict in the object
    # we primarily care about changed and state
    # changed is if this module effectively modified the target
    # state will include any data that you want your module to pass back
    # for consumption, for example, in a subsequent task
    result = dict(
        changed=False,
        failed=False,
        message=''
    )

    # the AnsibleModule object will be our abstraction working with Ansible
    # this includes instantiation, a couple of common attr would be the
    # args/params passed to the execution, as well as if the module
    # supports check mode
    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=True
    )
    #
    # Nodegrid OS section starts here
    #
    if "timeout" in module.params.keys():
        try:
            timeout = int(module.params['timeout'])
        except:
            timeout = 60
    # Lets get the current status and check if it must be changed
    res, err_msg, nodegrid_os = check_os_version_support()
    if res == 'error' or res == 'unsupported':
        module.fail_json(msg=err_msg, **result)
    elif res == 'warning':
        result['warning'] = err_msg
    # result['nodegrid_facts'] = nodegrid_os

  ## Find out what needs to be changed
    diff_chains = {
        'settings': {},
        'events_zpe_cloud': {},
        'events_file': {},
        'events_syslog': {},
        'events_snmp': {},
        'events_email': {},
        'event_list': {},
        'destinations_file': {},
        'destinations_syslog': {},
        'destinations_snmp': {},
        'destinations_email': {},
    }
    #Get Current NAT Data
    
    # ####################################################################################################
    # Look at Event numbers and actions
    if module.params['event_list']:
        event_list = module.params['event_list']
        for event_num, event_settings in event_list.items():
            if not event_num.isdigit():
                continue
            event_number = int(event_num)
            if event_number < 100 or event_number > 534:
                continue
          
            event_settings_current = {}
            # Get the current state of the event
            event_settings_current.update(get_auditing(f"/auditing/event_list/{event_number}", module.params['timeout']))
            if module.params['debug']:
                if 'system_current' in result:
                    result['system_current'].update({event_number: event_settings_current.copy()})
                else:
                    result['system_current'] = {event_number: event_settings_current.copy()}

                if 'system_desired' in result:
                    result['system_desired'].update({event_number: event_settings.copy()})
                else:
                    result['system_desired'] = {event_number: event_settings.copy()}
            # Create a diff
            diff = []
            try:
                for item in event_settings:
                    if item in event_settings_current:
                        if event_settings[item].strip() != event_settings_current[item].strip():
                            diff.append({item: event_settings[item]})
                    else:
                        diff.append({item: event_settings[item]})

            except Exception as e:
                result['failed'] = True
                result['error'] = f"Error: creating system settings diff. Error Message: {str(e)}"
            finally:
                if len(diff) > 0:
                    diff_chains['event_list'].update({event_number: diff})
    ###########################################################################################################

    # Look at Auditing Settings details
    if module.params['auditing_settings']:
            auditing_settings = module.params['auditing_settings']
            auditing_settings_current = {}
            # Get the current state of the plocy
            auditing_settings_current.update(get_auditing("/auditing/settings", module.params['timeout']))
            if module.params['debug']:
                result['system_current'] = auditing_settings_current.copy()
                result['system_desired'] = auditing_settings.copy()
            # Create a diff
            diff = []
            try:
                for item in auditing_settings:
                    if auditing_settings_current[item]:
                        if auditing_settings[item] != auditing_settings_current[item]:
                            diff.append({item: auditing_settings[item]})
            except Exception as e:
                result['failed'] = True
                result['error'] = f"Error: creating system settings diff. Error Message: {str(e)}"
            finally:
                diff_chains['settings'] = diff

    # Look at Auditing Event Settings for ZPE Cloud details
    if module.params['events_zpe_cloud']:
            auditing_events_zpe_cloud = module.params['events_zpe_cloud']
            auditing_events_zpe_cloud_current = {}
            # Get the current state of the plocy
            auditing_events_zpe_cloud_current.update(get_auditing("/auditing/events/zpe_cloud", module.params['timeout']))
            if module.params['debug']:
                result['events_zpe_cloud_current'] = auditing_events_zpe_cloud_current.copy()
                result['events_zpe_cloud_desired'] = auditing_events_zpe_cloud.copy()
            # Create a diff
            diff = []
            try:
                for item in auditing_events_zpe_cloud:
                    if auditing_events_zpe_cloud_current[item]:
                        if auditing_events_zpe_cloud[item] != auditing_events_zpe_cloud_current[item]:
                            diff.append({item: auditing_events_zpe_cloud[item]})
            except Exception as e:
                result['failed'] = True
                result['error'] = f"Error: creating system settings diff. Error Message: {str(e)}"
            finally:
                diff_chains['events_zpe_cloud'] = diff

    # Look at Auditing Event Settings for E-Mails
    if module.params['events_email']:
            auditing_events_events_email = module.params['events_email']
            auditing_events_events_email_current = {}
            # Get the current state of the plocy
            auditing_events_events_email_current.update(get_auditing("/auditing/events/email", module.params['timeout']))
            if module.params['debug']:
                result['events_email_current'] = auditing_events_events_email_current.copy()
                result['events_email_desired'] = auditing_events_events_email.copy()
            # Create a diff
            diff = []
            try:
                for item in auditing_events_events_email:
                    if auditing_events_events_email_current[item]:
                        if auditing_events_events_email[item] != auditing_events_events_email_current[item]:
                            diff.append({item: auditing_events_events_email[item]})
            except Exception as e:
                result['failed'] = True
                result['error'] = f"Error: creating system settings diff. Error Message: {str(e)}"
            finally:
                diff_chains['events_email'] = diff

    # Look at Auditing Event Settings for files
    if module.params['events_file']:
            auditing_events_events_file = module.params['events_file']
            auditing_events_events_file_current = {}
            # Get the current state of the
            auditing_events_events_file_current.update(get_auditing("/auditing/events/file", module.params['timeout']))
            if module.params['debug']:
                result['events_file_current'] = auditing_events_events_file_current.copy()
                result['events_file_desired'] = auditing_events_events_file.copy()
            # Create a diff
            diff = []
            try:
                for item in auditing_events_events_file:
                    if auditing_events_events_file_current[item]:
                        if auditing_events_events_file[item] != auditing_events_events_file_current[item]:
                            diff.append({item: auditing_events_events_file[item]})
            except Exception as e:
                result['failed'] = True
                result['error'] = f"Error: creating system settings diff. Error Message: {str(e)}"
            finally:
                diff_chains['events_file'] = diff

    # Look at Auditing Event Settings for Syslog
    if module.params['events_syslog']:
            auditing_events_events_syslog = module.params['events_syslog']
            auditing_events_events_syslog_current = {}
            # Get the current state of the
            auditing_events_events_syslog_current.update(get_auditing("/auditing/events/syslog", module.params['timeout']))
            if module.params['debug']:
                result['events_syslog_current'] = auditing_events_events_syslog_current.copy()
                result['events_syslog_desired'] = auditing_events_events_syslog.copy()
            # Create a diff
            diff = []
            try:
                for item in auditing_events_events_syslog:
                    if auditing_events_events_syslog_current[item]:
                        if auditing_events_events_syslog[item] != auditing_events_events_syslog_current[item]:
                            diff.append({item: auditing_events_events_syslog[item]})
            except Exception as e:
                result['failed'] = True
                result['error'] = f"Error: creating system settings diff. Error Message: {str(e)}"
            finally:
                diff_chains['events_syslog'] = diff

    # Look at Auditing Event Settings for SNMP
    if module.params['events_snmp']:
            auditing_events_events_snmp = module.params['events_snmp']
            auditing_events_events_snmp_current = {}
            # Get the current state of the
            auditing_events_events_snmp_current.update(get_auditing("/auditing/events/snmp_trap", module.params['timeout']))
            if module.params['debug']:
                result['events_syslog_current'] = auditing_events_events_snmp_current.copy()
                result['events_syslog_desired'] = auditing_events_events_snmp.copy()
            # Create a diff
            diff = []
            try:
                for item in auditing_events_events_snmp:
                    if auditing_events_events_snmp_current[item]:
                        if auditing_events_events_snmp[item] != auditing_events_events_snmp_current[item]:
                            diff.append({item: auditing_events_events_snmp[item]})
            except Exception as e:
                result['failed'] = True
                result['error'] = f"Error: creating system settings diff. Error Message: {str(e)}"
            finally:
                diff_chains['events_snmp'] = diff

###########################################
    # Look at Auditing Event Destination for E-Mails
    if module.params['destinations_email']:
            auditing_destinations_email = module.params['destinations_email']
            auditing_destinations_email = resort_rule(auditing_destinations_email)
            auditing_destinations_email = clean_rule(auditing_destinations_email)
            auditing_destinations_email_current = {}
            # Get the current state of the plocy
            auditing_destinations_email_current.update(get_auditing("/auditing/destinations/email", module.params['timeout']))
            if module.params['debug']:
                result['destinations_email_current'] = auditing_destinations_email_current.copy()
                result['destinations_email_desired'] = auditing_destinations_email.copy()
            # Create a diff
            diff = []
            try:
                for item in auditing_destinations_email:
                    if auditing_destinations_email_current[item]:
                        if str(auditing_destinations_email[item]) != str(auditing_destinations_email_current[item]):
                            diff.append({item: auditing_destinations_email[item]})
            except Exception as e:
                result['failed'] = True
                result['error'] = f"Error: creating system settings diff. Error Message: {str(e)}"
            finally:
                diff_chains['destinations_email'] = diff

    # Look at Auditing Event Destination for files
    if module.params['destinations_file']:
            auditing_destinations_file = module.params['destinations_file']
            auditing_destinations_file = resort_rule(auditing_destinations_file)
            auditing_destinations_file = clean_rule(auditing_destinations_file)
            auditing_destinations_file_current = {}
            # Get the current state of the
            auditing_destinations_file_current.update(get_auditing("/auditing/destinations/file", module.params['timeout']))
            if module.params['debug']:
                result['destinations_file_current'] = auditing_destinations_file_current.copy()
                result['destinations_file_desired'] = auditing_destinations_file.copy()
            # Create a diff
            diff = []
            try:
                for item in auditing_destinations_file:
                    if auditing_destinations_file_current[item]:
                        if str(auditing_destinations_file[item]) != str(auditing_destinations_file_current[item]):
                            diff.append({item: auditing_destinations_file[item]})
            except Exception as e:
                result['failed'] = True
                result['error'] = f"Error: creating system settings diff. Error Message: {str(e)}"
            finally:
                diff_chains['destinations_file'] = diff

    # Look at Auditing Event Destination for Syslog
    if module.params['destinations_syslog']:
            auditing_destinations_syslog = module.params['destinations_syslog']
            auditing_destinations_syslog = resort_rule(auditing_destinations_syslog)
            auditing_destinations_syslog = clean_rule(auditing_destinations_syslog)
            auditing_destinations_syslog_current = {}
            # Get the current state of the
            auditing_destinations_syslog_current.update(get_auditing("/auditing/destinations/syslog", module.params['timeout']))
            if module.params['debug']:
                result['destinations_syslog_current'] = auditing_destinations_syslog_current.copy()
                result['destinations_syslog_desired'] = auditing_destinations_syslog.copy()
            # Create a diff
            diff = []
            try:
                for item in auditing_destinations_syslog:
                    if item in auditing_destinations_syslog_current and auditing_destinations_syslog_current[item]:
                        if str(auditing_destinations_syslog[item]) != str(auditing_destinations_syslog_current[item]):
                            diff.append({item: auditing_destinations_syslog[item]})
                    else:
                        diff.append({item: auditing_destinations_syslog[item]})
            except Exception as e:
                result['failed'] = True
                result['error'] = f"Error: creating system settings diff. Error Message: {str(e)}"
            finally:
                diff_chains['destinations_syslog'] = diff

    # Look at Auditing Event Destination for SNMP
    if module.params['destinations_snmp']:
            auditing_destinations_snmp = module.params['destinations_snmp']
            auditing_destinations_snmp = resort_rule(auditing_destinations_snmp)
            auditing_destinations_snmp = clean_rule(auditing_destinations_snmp)
            auditing_destinations_snmp_current = {}
            # Get the current state of the
            auditing_destinations_snmp_current.update(get_auditing("/auditing/destinations/snmptrap", module.params['timeout']))
            if module.params['debug']:
                result['destinations_syslog_current'] = auditing_destinations_snmp_current.copy()
                result['destinations_syslog_desired'] = auditing_destinations_snmp.copy()
            # Create a diff
            diff = []
            try:
                for item in auditing_destinations_snmp:
                    if auditing_destinations_snmp_current[item]:
                        if str(auditing_destinations_snmp[item]) != str(auditing_destinations_snmp_current[item]):
                            diff.append({item: auditing_destinations_snmp[item]})
            except Exception as e:
                result['failed'] = True
                result['error'] = f"Error: creating system settings diff. Error Message: {str(e)}"
            finally:
                diff_chains['destinations_snmp'] = diff


    # Build out commands
    cmds = []
    # Build Commands for Auditing settings
    if len(diff_chains['settings']) > 0:
        cmds.append({'cmd': f"cd /settings/auditing/settings"})
        for rule in diff_chains['settings']:
            for setting in rule:
                cmd = {'cmd': f"set {setting}='{rule[setting]}'"}
                cmds.append(cmd)
        cmds.append({'cmd': "commit"})

    # Build Commands for Auditing Events ZPE Cloud
    if len(diff_chains['events_zpe_cloud']) > 0:
        cmds.append({'cmd': f"cd /settings/auditing/events/zpe_cloud"})
        for rule in diff_chains['events_zpe_cloud']:
            for setting in rule:
                cmd = {'cmd': f"set {setting}='{rule[setting]}'"}
                cmds.append(cmd)
        cmds.append({'cmd': "commit"})

    # Build Commands for Auditing Events E-Mail
    if len(diff_chains['events_email']) > 0:
        cmds.append({'cmd': f"cd /settings/auditing/events/email"})
        for rule in diff_chains['events_email']:
            for setting in rule:
                cmd = {'cmd': f"set {setting}='{rule[setting]}'"}
                cmds.append(cmd)
        cmds.append({'cmd': "commit"})

    # Build Commands for Auditing Events File
    if len(diff_chains['events_file']) > 0:
        cmds.append({'cmd': f"cd /settings/auditing/events/file"})
        for rule in diff_chains['events_file']:
            for setting in rule:
                cmd = {'cmd': f"set {setting}='{rule[setting]}'"}
                cmds.append(cmd)
        cmds.append({'cmd': "commit"})

    # Build Commands for Auditing Events Syslog
    if len(diff_chains['events_syslog']) > 0:
        cmds.append({'cmd': f"cd /settings/auditing/events/syslog"})
        for rule in diff_chains['events_syslog']:
            for setting in rule:
                cmd = {'cmd': f"set {setting}='{rule[setting]}'"}
                cmds.append(cmd)
        cmds.append({'cmd': "commit"})

    # Build Commands for Auditing Events SNMP
    if len(diff_chains['events_snmp']) > 0:
        cmds.append({'cmd': f"cd /settings/auditing/events/snmp_trap"})
        for rule in diff_chains['events_snmp']:
            for setting in rule:
                cmd = {'cmd': f"set {setting}='{rule[setting]}'"}
                cmds.append(cmd)
        cmds.append({'cmd': "commit"})
    
    # Build Commands for Auditing Event list
    if len(diff_chains['event_list']) > 0:
        for event_number, event_settings in diff_chains['event_list'].items():
            cmds.append({'cmd': f"cd /settings/auditing/event_list/{event_number}"})
            for rule in event_settings:
                for setting in rule:
                    cmd = {'cmd': f"set {setting}='{rule[setting]}'"}
                    cmds.append(cmd)
        cmds.append({'cmd': "commit"})

    # Build Commands for Auditing Destinations E-Mail
    if len(diff_chains['destinations_email']) > 0:
        cmds.append({'cmd': f"cd /settings/auditing/destinations/email"})
        for rule in diff_chains['destinations_email']:
            for setting in rule:
                cmd = {'cmd': f"set {setting}='{rule[setting]}'"}
                cmds.append(cmd)
        cmds.append({'cmd': "commit"})

    # Build Commands for Auditing Destinations File
    if len(diff_chains['destinations_file']) > 0:
        cmds.append({'cmd': f"cd /settings/auditing/destinations/file"})
        for rule in diff_chains['destinations_file']:
            for setting in rule:
                cmd = {'cmd': f"set {setting}='{rule[setting]}'"}
                cmds.append(cmd)
        cmds.append({'cmd': "commit"})

    # Build Commands for Auditing Destinations Syslog
    if len(diff_chains['destinations_syslog']) > 0:
        cmds.append({'cmd': f"cd /settings/auditing/destinations/syslog"})
        cmd_line = []
        for rule in diff_chains['destinations_syslog']:
            for setting in rule:
                cmd_line.append(f"{setting}='{rule[setting]}'")
        # Add all fields in the same line because some fileds must be set in the
        # same line (ipv4_remote_server and ipv4_address, ipv6_remote_server and ipv6_address)
        cmd = {'cmd': f"set {' '.join(cmd_line)}"}
        cmds.append(cmd)
        cmds.append({'cmd': "commit"})

    # Build Commands for Auditing Destinations SNMP
    if len(diff_chains['destinations_snmp']) > 0:
        cmds.append({'cmd': f"cd /settings/auditing/destinations/snmptrap"})
        for rule in diff_chains['destinations_snmp']:
            for setting in rule:
                cmd = {'cmd': f"set {setting}='{rule[setting]}'"}
                cmds.append(cmd)
        cmds.append({'cmd': "commit"})

    # as fail save add system roll back
    if len(cmds) > 0:
        cmds.insert(0, {'cmd': f"config_start"})
        cmds.append({'cmd': f"config_confirm"})

    if module.params['debug']:
        result['cmds'] = cmds
        result['diff'] = diff_chains

    if module.check_mode:
        # Display Changes
        result['diff'] = diff_chains
        result['message'] = "No changes where performed, running in check_mode"
        module.exit_json(**result)
    ## Pushing Changes

    # Apply Changes
    try:
        cmd_results = []
        cmd_cli = get_cli(timeout=timeout)
        for cmd in cmds:
            cmd_result = execute_cmd(cmd_cli, cmd)
            if 'template' in cmd.keys():
                cmd_result['template'] = cmd['template']
            if 'set_fact' in cmd.keys():
                cmd_result['set_fact'] = cmd['set_fact']
            if 'ignore_error' in cmd.keys():
                cmd_result['ignore_error'] = cmd['ignore_error']
            if 'json' in cmd.keys():
                cmd_result['json'] = cmd['json']
            cmd_result['command'] = cmd.get('cmd')
            cmd_results.append(cmd_result)
            if cmd_result['error']:
                result['failed'] = True
                cmd_result = execute_cmd(cmd_cli, dict(cmd='cancel', ignore_error=True))
                cmd_result = execute_cmd(cmd_cli, dict(cmd='revert', ignore_error=True))
                cmd_result = execute_cmd(cmd_cli, dict(cmd='config_revert', ignore_error=True))
                break;
            result['changed'] = True
        close_cli(cmd_cli)
        result['cmds_output'] = cmd_results
    except Exception as exc:
        result['failed'] = True
        result['message'] = str(exc)

    if result['failed']:
        module.fail_json(msg=result['message'], **result)

    # in the event of a successful module execution, you will want to
    # simple AnsibleModule.exit_json(), passing the key/value results
    module.exit_json(**result)


def main():
    run_module()


if __name__ == '__main__':
    main()
