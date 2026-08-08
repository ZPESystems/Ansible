# Collect facts related to Nodegrid
from __future__ import annotations

from ansible.module_utils.facts import collector
from ansible_collections.zpe.nodegrid.plugins.module_utils.nodegrid_util import NodegridError, check_os_version_support, run_cli_command, run_cli_commands

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
            cmd_result = run_cli_command(cmd, timeout=timeout)
            if cmd_result['error']:
                result['failed'] = True
                result['msg'] = f"{cmd_result['msg']}"
                return result

            # Parse the wireguard endpoints
            cmd_output = cmd_result['output']
            pattern = r"^.*/interfaces"
            interfaces = set(re.findall(pattern, cmd_output, re.MULTILINE))

            for interface in interfaces:
                wg = dict()
                wg_name = interface.replace("/settings/wireguard/","").replace("/interfaces","").strip()
                pattern = fr"{interface}.*$"
                iface_config = re.findall(pattern, cmd_output, re.MULTILINE)
                wg['interfaces'] = dict(map(lambda x: x.replace(interface,'').strip().split('=',1), iface_config))
                # peers
                #/settings/wireguard/wg1/peers/peer1
                peers_pattern = f"^/settings/wireguard/{wg_name}/peers/.*"
                pattern = fr"{peers_pattern}.*"
                iface_peers = set(line.split()[0] for line in re.findall(pattern, cmd_output, re.MULTILINE))
                if not 'peers' in wg:
                    wg['peers'] = list()
                for iface_peer in iface_peers:
                    peer_name = iface_peer.split(" ")[0].replace(f"/settings/wireguard/{wg_name}/peers/","").strip()
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
    def _run_commands(self, cmds, run_opt=dict()):
        result = dict(
            changed=False,
            failed=False,
            timeout=False,
            cmds_output=list(),
            retries=0,
        )
        timeout = run_opt.get('timeout', 60)
        # run commands and gather output
        run_cmds =  run_cli_commands(cmds, timeout=timeout, max_retries=run_opt.get('max_retries'), base_delay=run_opt.get('base_delay'), max_delay=run_opt.get('max_delay'))
        result['retries'] = run_cmds['retries']
        if run_cmds['error']:
            result['failed'] = True
            result['msg'] = f"{run_cmds['msg']}"
            return result
        result['cmds_output'] = run_cmds['cmds_results']
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
        run_opt = dict(
            timeout=module.params.get('gather_timeout', 60),
            max_retries=module.params.get('max_retries', 2),
            base_delay=module.params.get('base_delay', 2.0), 
            max_delay=module.params.get('max_delay',10.0),
        )

        # Nodegrid OS section starts here
        # Lets get the current status and check if it must be changed
        res, err_msg, nodegrid_os = check_os_version_support(timeout=run_opt.get('timeout'))
        if res == 'error' or res == 'unsupported':
            return dict(msg=err_msg, failed=True)
        
        cmds = self._get_cmds(nodegrid_os)
        cmds_results = self._run_commands(cmds, run_opt=run_opt)
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

        wireguard_endpoints_present = self.get_wireguard_endpoints_present(timeout=run_opt.get('timeout'))
        if not wireguard_endpoints_present["error"]:
            parsed_dict['wireguard'] = wireguard_endpoints_present['endpoints']

        return parsed_dict

