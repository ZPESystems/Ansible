#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2023, ZPE Systems <zpesystems.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import (absolute_import, division, print_function)

__metaclass__ = type

DOCUMENTATION = r'''
---
module: firewall
author: Rene Neumann (@zpe-rneumann)
'''

EXAMPLES = r'''
'''

RETURN = r'''

'''

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.zpe.nodegrid.plugins.module_utils.nodegrid_util import get_cli, close_cli, execute_cmd, \
    check_os_version_support, dict_diff

import os

# We have to remove the SID from the Environmental settings, to avoid an issue
# were we can not run pexpect.run multiple times
if "DLITF_SID" in os.environ:
    del os.environ["DLITF_SID"]
if "DLITF_SID_ENCRYPT" in os.environ:
    del os.environ["DLITF_SID_ENCRYPT"]


def get_state(endpoint: str, timeout: int = 60) -> dict:
    cmd_cli = get_cli(timeout=timeout)

    # build cmd
    cmd = {
         'cmd': str('show /settings/' + endpoint )
    }

    cmd_result = execute_cmd(cmd_cli, cmd)
    data = {}
    if cmd_result['error']:
        data = {'error': cmd_result['error']}
    else:
        data = cmd_result['json'][0]['data']
    close_cli(cmd_cli)
    return data

def resort_rule(rule: dict) -> dict:
    new_rule: dict = {}
    sort_list = ['enable_detection_of_usb_devices','enable_rpc','enable_grpc','enable_ftp_service','enable_snmp_service',
           'enable_telnet_service_to_nodegrid','enable_telnet_service_to_managed_devices',
           'enable_icmp_echo_reply','enable_icmp_secure_redirects','enable_usb_over_ip','enable_search_engine','enable_dashboards',
           'enable_telegraf','enable_services_status_page','enable_reboot_on_services_status_page','enable_vmware_manager','enable_docker',
           'enable_qemu|kvm','cluster_tcp_port','auto_cluster_enroll','search_engine_tcp_port','enable_search_engine_high_level_cipher_suite',
           'enable_vm_serial_access','vm_serial_port','vmotion_timeout','enable_zero_touch_provisioning','enable_bluetooth',
           'bluetooth_display_name','bluetooth_discoverable_mode','enable_pxe','device_access_per_user_group_authorization',
           'enable_autodiscovery','dhcp_lease_per_autodiscovery_rules','block_host_with_multiple_authentication_fails',
           'allow_root_console_access','rescue_mode_require_authentication','password_protected_boot','ssh_allow_root_access',
           'ssh_tcp_port','ssh_ciphers','ssh_macs','ssh_kexalgorithms','enable_http_access','http_port','enable_https_access',
           'https_port','redirect_http_to_https','enable_https_file_repository','frr_enable_bgp','frr_enable_ospfv2','frr_enable_ospfv3',
            'frr_enable_rip','frr_enable_vrrp','tlsv1.3','tlsv1.2','tlsv1.1','tlsv1','cipher_suite_level']
    for key in sort_list:
        if key in rule.keys():
            new_rule[key] = rule[key]
            rule.pop(key)
    new_rule = {**new_rule, **rule}
    return new_rule

def clean_rule(rule: dict) -> dict:
    status_page = {'key': 'enable_services_status_page','list':['enable_reboot_on_services_status_page']}
    search_engine = {'key': 'enable_search_engine', 'list': ['enable_dashboards']}
    bluetooth = {'key': 'enable_bluetooth', 'list': ['bluetooth_display_name','bluetooth_discoverable_mode']}
    docker = {'key': 'enable_docker', 'list':[]}
    qemu = {'key': 'enable_qemu|kvm', 'list':[]}
    autodiscovery = {'key': 'enable_autodiscovery', 'list':['dhcp_lease_per_autodiscovery_rules']}
    vm_serial_access = {'key': 'enable_vm_serial_access', 'list': ['vm_serial_port','vmotion_timeout']}
    multiple_authentication_fails = {'key': 'block_host_with_multiple_authentication_fails', 'list': ['period_host_will_stay_blocked','timeframe_to_monitor_authentication_fails','number_of_authentication_fails_to_block_host']}
    zpe_cloud = {'key': 'enable_zpe_cloud', 'list':['enable_remote_access', 'enable_file_protection', 'enable_file_encryption']}
    master_list = [autodiscovery,vm_serial_access,status_page,docker,qemu,multiple_authentication_fails,search_engine,bluetooth,zpe_cloud]

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
        services=dict(type='dict', required=False),
        zpe_cloud=dict(type='dict', required=False),
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
        'services': {},
        'zpe_cloud': {},
    }
    # Get Current Services Data
    if module.params['services']:
        services_desired = module.params['services']
        services_desired = resort_rule(services_desired)
        services_desired = clean_rule(services_desired)
        services_current = {}
        services_current.update(get_state("services", module.params['timeout']))
        # [TODO] This Section needs to expanded to cover different actions, currently we will consider only add and update
        diff = []
        try:
            for item in services_desired:
                if item in services_current.keys():
                    # to avoid comparision issues, will we compare string to strings
                    if str(services_desired[item]) != str(services_current[item]):
                        diff.append({item: services_desired[item]})
        except Exception as e:
            result['failed'] = True
            result['error'] = f"Error: creating system settings diff. Error Message: {str(e)}"
        finally:
            diff_chains['services'] = diff
    
    if module.params['zpe_cloud']:
        zpe_cloud_desired = module.params['zpe_cloud']
        zpe_cloud_desired = clean_rule(zpe_cloud_desired)
        zpe_cloud_current = {}
        zpe_cloud_current.update(get_state("zpe_cloud", module.params['timeout']))
        diff = []
        try:
            for item in zpe_cloud_desired:
                if item in zpe_cloud_current.keys():
                    # to avoid comparision issues, will we compare string to strings
                    if str(zpe_cloud_desired[item]) != str(zpe_cloud_current[item]):
                        diff.append({item: zpe_cloud_desired[item]})
        except Exception as e:
            result['failed'] = True
            result['error'] = f"Error: creating system settings diff. Error Message: {str(e)}"
        finally:
            diff_chains['zpe_cloud'] = diff

    # Build out commands
    cmds = []
    #Build Commands for Service
    if len(diff_chains['services']) > 0:
        cmds.append({'cmd': f"cd /settings/services/"})
        for item in diff_chains['services']:
            for setting in item:
                cmd = {'cmd': f"set {setting}={item[setting]}"}
                cmds.append(cmd)
        cmds.append({'cmd': "commit"})
    
    if len(diff_chains['zpe_cloud']) > 0:
        cmds.append({'cmd': f"cd /settings/zpe_cloud/"})
        for item in diff_chains['zpe_cloud']:
            for setting in item:
                cmd = {'cmd': f"set {setting}={item[setting]}"}
                cmds.append(cmd)
        cmds.append({'cmd': "commit"})

    # as fail save add system roll back
    if len(cmds) > 0:
        cmds.insert(0, {'cmd': f"config_start"})
        cmds.append({'cmd': f"config_confirm"})

    if module.params['debug']:
        result['cmds'] = cmds
        result['diff'] = diff_chains
        result['service_current'] = services_current if module.params['services'] else ''
        result['services_desired'] = services_desired if module.params['services'] else ''
        result['zpe_cloud_current'] = zpe_cloud_current if module.params['zpe_cloud'] else ''
        result['zpe_cloud_desired'] = zpe_cloud_desired if module.params['zpe_cloud'] else ''
 #       result['services_skipped'] = services_desired_org

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
