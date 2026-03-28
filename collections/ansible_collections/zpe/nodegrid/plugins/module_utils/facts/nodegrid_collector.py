# Collect facts related to Nodegrid
from __future__ import annotations

from ansible.module_utils.facts import collector
from ansible_collections.zpe.nodegrid.plugins.module_utils.nodegrid_util import NodegridError, nodegrid_cli, execute_cmd, check_os_version_support

# ttp templates
import ansible_collections.zpe.nodegrid.plugins.module_utils.facts.templates.about
import ansible_collections.zpe.nodegrid.plugins.module_utils.facts.templates.cluster_clusters
import ansible_collections.zpe.nodegrid.plugins.module_utils.facts.templates.cpu_usage
import ansible_collections.zpe.nodegrid.plugins.module_utils.facts.templates.device_sessions
import ansible_collections.zpe.nodegrid.plugins.module_utils.facts.templates.disk_usage
import ansible_collections.zpe.nodegrid.plugins.module_utils.facts.templates.event_list
import ansible_collections.zpe.nodegrid.plugins.module_utils.facts.templates.io_ports
import ansible_collections.zpe.nodegrid.plugins.module_utils.facts.templates.memory_usage
import ansible_collections.zpe.nodegrid.plugins.module_utils.facts.templates.open_sessions
import ansible_collections.zpe.nodegrid.plugins.module_utils.facts.templates.power
import ansible_collections.zpe.nodegrid.plugins.module_utils.facts.templates.serial_statistics
import ansible_collections.zpe.nodegrid.plugins.module_utils.facts.templates.serial_statistics_nsr
import ansible_collections.zpe.nodegrid.plugins.module_utils.facts.templates.thermal
import ansible_collections.zpe.nodegrid.plugins.module_utils.facts.templates.usb_devices
import ansible_collections.zpe.nodegrid.plugins.module_utils.facts.templates.usb_sensors

from ansible_collections.zpe.nodegrid.plugins.module_utils.facts.parse import get_template

from ttp import ttp

import os
import re
#import traceback


class NodegridFactCollector(collector.BaseFactCollector):
    '''
    A Nodegrid FactCollector that returns results under 'ansible_facts' top level key. The prefix 'nodegrid_' is defined.
    '''
    _platform = 'nodegrid'
    name = 'nodegrid'
    _fact_ids = set([
                    'about',
                    'cluster_clusters',
                    'cpu_usage',
                    'device_sessions',
                    'disk_usage',
                    'event_list',
                    'io_ports',
                    'memory_usage',
                    'open_sessions',
                    'power',
                    'serial_statistics',
                    'serial_statistics_nsr',
                    'thermal',
                    'usb_devices',
                    'usb_sensors',
                    ])  # type: t.Set[str]

    def __init__(self, collectors=None, namespace=None, filter_spec=None):

        super(NodegridFactCollector, self).__init__(collectors=collectors,
                                                   namespace=namespace)

        self.filter_spec = filter_spec

    # #####################################################################################
    # Wireguad config
    def get_wireguard_endpoints_present(self, timeout=60) -> dict:
        result = dict(
            error=False,
            endpoints=[],
            msg=''
            )
        try:
            cmd = dict(cmd='export_settings /settings/wireguard', ignore_error=False)
            with nodegrid_cli(timeout) as cmd_cli:
               cmd_result = execute_cmd(cmd_cli, cmd, timeout=timeout)

            # Parse the wireguard endpoints
            cmd_output = cmd_result['stdout']
            pattern = r"^.*/interfaces"
            interfaces = set(re.findall(pattern, cmd_output, re.MULTILINE))

            for interface in interfaces:
                wg = dict()
                wg_name = interface.replace("/settings/wireguard/","").replace("/interfaces","").strip()
                pattern = fr"{interface}.*$"
                iface_config = re.findall(pattern, cmd_output, re.MULTILINE)
                wg['interfaces'] = dict(map(lambda x: x.replace(interface,'').strip().split('=',1), iface_config))
                # peers
                peers_pattern = interface.replace("interfaces", "peers")
                pattern = fr"{peers_pattern}.*"
                iface_peers = set(re.findall(pattern, cmd_output, re.MULTILINE))
                if not 'peers' in wg:
                    wg['peers'] = list()
                for iface_peer in iface_peers:
                    pattern = fr"{iface_peer}.*$"
                    peer_config = [element.replace('\n', '').replace('\r', '') for element in re.findall(pattern, cmd_output, re.MULTILINE)]
                    wg['peers'].append(dict(map(lambda x: x.replace(iface_peer,"").strip().split('=',1), peer_config )))
                result['endpoints'].append({wg_name: wg})
        except (NodegridError, Exception) as e:
            result['error'] = True
            result['msg'] = f"{e}"
        return result
    # #####################################################################################

    #def collect(self, module=None, collected_facts=None):
    def _run_commands(self, cmds, timeout=60):
        result = dict(
            changed=False,
            failed=False,
            timeout=False
        )
        # run commands and gather output
        cmd_results = list()
        cmd_result = dict()
        try:
            with nodegrid_cli(timeout) as cmd_cli:
                for cmd in cmds:
                    cmd_result = execute_cmd(cmd_cli, cmd, timeout=timeout)
                    if 'template' in cmd.keys():
                        cmd_result['template'] = cmd['template']
                    if 'set_fact' in cmd.keys():
                        cmd_result['set_fact'] = cmd['set_fact']
                    ignore_error = 'ignore_error' in cmd.keys() and isinstance(cmd['ignore_error'], bool) and cmd['ignore_error'] is True
                    if ignore_error:
                        cmd_result['ignore_error'] = ignore_error
                    if 'json' in cmd.keys():
                        cmd_result['json'] = cmd['json']
                    cmd_result['command'] = cmd.get('cmd')
                    if ignore_error and 'error' in cmd_result and cmd_result['error']:
                        cmd_result['failed'] = True
                    cmd_results.append(cmd_result)
                result['cmds_output'] = cmd_results
        except (NodegridError, Exception) as e:
            result['failed'] = True
            result['message'] = f"{e}"
        return result

    def _get_cmds(self, system_details):
        cmds = list()
        templates_path = "ansible_collections.zpe.nodegrid.plugins.module_utils.facts.templates"
        cmds.append(
            dict(cmd='show /system/about/',
                 template=f"{templates_path}.about",
                 ignore_error=True
                 ),
        )
        cmds.append(
            dict(cmd='show /system/open_sessions/',
                 template=f"{templates_path}.open_sessions",
                 ignore_error=True
                 ),
        )
        cmds.append(
            dict(cmd='show /system/device_sessions/',
                 template=f"{templates_path}.device_sessions",
                 ignore_error=True
                 ),
        )
        cmds.append(
            dict(cmd='show /system/system_usage/cpu_usage/',
                 template=f"{templates_path}.cpu_usage",
                 ignore_error=True
                 ),
        )
        cmds.append(
            dict(cmd='show /system/system_usage/disk_usage/',
                 template=f"{templates_path}.disk_usage",
                 ignore_error=True
                 ),
        )
        cmds.append(
            dict(cmd='show /system/system_usage/memory_usage/',
                 template=f"{templates_path}.memory_usage",
                 ignore_error=True
                 ),
        )
        cmds.append(
            dict(cmd='show /settings/cluster/cluster_clusters/',
                 template=f"{templates_path}.cluster_clusters",
                 ignore_error=True
                 ),
        )

        # Check if System is Nodegrid Manager
        if system_details['system'] == 'Nodegrid Manager':
            return cmds

        # Extra detaisl for systems like GateSR, BoldSR, NetSR, etc.
        cmds.append(
            dict(cmd='show /system/hw_monitor/io_ports/',
                 template=f"{templates_path}.io_ports",
                 ignore_error=True
                 ),
        )
        cmds.append(
            dict(cmd='show /system/hw_monitor/power/',
                 template=f"{templates_path}.power",
                 ignore_error=True
                 ),
        )
        cmds.append(
            dict(cmd='show /system/hw_monitor/thermal/',
                 template=f"{templates_path}.thermal",
                 ignore_error=True
                 ),
        )
        cmds.append(
            dict(cmd='show /system/hw_monitor/usb_sensors/',
                 template=f"{templates_path}.usb_sensors",
                 ignore_error=True
                 ),
        )
        cmds.append(
            dict(cmd='show /system/usb_devices/',
                 template=f"{templates_path}.usb_devices",
                 ignore_error=True
                 ),
        )
        cmds.append(
            dict(cmd='show /system/serial_statistics/',
                 template=f"{templates_path}.serial_statistics_nsr",
                 ignore_error=True
                 ),
        )
        cmds.append(
            dict(cmd='show /system/serial_statistics/',
                 template=f"{templates_path}.serial_statistics",
                 ignore_error=True
                 ),
        )
        return cmds

    def collect(self, module=None, collected_facts=None):
        # We have to remove the SID from the Environmental settings, to avoid an issue
        # were we can not run pexpect.run multiple times
        if "DLITF_SID" in os.environ:
            del os.environ["DLITF_SID"]
        if "DLITF_SID_ENCRYPT" in os.environ:
            del os.environ["DLITF_SID_ENCRYPT"]

        # Get timeout from the params module
        timeout = module.params.get('gather_timeout', 60)

        # Nodegrid OS section starts here
        # Lets get the current status and check if it must be changed
        res, err_msg, nodegrid_os = check_os_version_support(timeout=timeout)
        if res == 'error' or res == 'unsupported':
            return dict(msg=err_msg, failed=True)
        
        cmds = self._get_cmds(nodegrid_os)
        cmds_results = self._run_commands(cmds, timeout=timeout)
        result = dict()
        parsed_dict = dict()
    
        if cmds_results["failed"]:
            return dict(msg=f"{cmds_results}", failed=True)

        for cmd_result in cmds_results.get('cmds_output'):
            if ('error' in cmd_result and isinstance(cmd_result['error'], bool) and cmd_result['error'] is True) or ('failed' in cmd_result and isinstance(cmd_result['failed'], bool) and cmd_result['failed'] is True):
                # TODO: the facts module ignores the result if a gather facts CLI command fails.
                continue
            template = ""
            try:
                template = get_template(cmd_result.get("template"))
                template_exist = True
            except Exception as e:
                result['template_error'] = str(e)
                result['error'] = f"Template file could not be found: {cmd_result.get('template')}"
                template_exist = False
                return dict(msg=result, failed=True)
            if template_exist:
                try:
                    parser = ttp(data=cmd_result['stdout'], template=template)
                    parser.parse()
                    for item in parser.result()[0]:
                        parsed_dict.update(item)
                except Exception as e:
                    # TODO: the facts module ignores if there is a ttp parser fail.
                    result["error_msg"] = str(e)
            else:
                return dict(msg=f"Template file could not be found: {cmd_result.get('template')}", failed=True)

        wireguard_endpoints_present = self.get_wireguard_endpoints_present(timeout=timeout)
        if not wireguard_endpoints_present["error"]:
            parsed_dict['wireguard'] = wireguard_endpoints_present['endpoints']

        return parsed_dict

