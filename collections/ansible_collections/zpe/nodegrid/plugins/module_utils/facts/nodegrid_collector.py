# Collect facts related to Nodegrid
from __future__ import annotations

from ansible.module_utils.facts import collector
from ansible_collections.zpe.nodegrid.plugins.module_utils.nodegrid_util import get_cli, close_cli, execute_cmd, check_os_version_support, get_system_details

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
import traceback


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

    #def collect(self, module=None, collected_facts=None):
    def _run_commands(self, cmds, timeout=30):
        result = dict(
            changed=False,
            failed=False
        )
        # run commands and gather output
        cmd_results = list()
        cmd_result = dict()
        try:
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
            close_cli(cmd_cli)
            result['cmds_output'] = cmd_results
        except Exception:
            result['failed'] = True
            result['message'] = traceback.format_exc()

        return result

    def _get_cmds(self, system_details):
        cmds = list()
        templates_path = "ansible_collections.zpe.nodegrid.plugins.module_utils.facts.templates"
        cmds.append(
            dict(cmd='show /system/about/',
                 template=f"{templates_path}.about"
                 ),
        )
        cmds.append(
            dict(cmd='show /system/open_sessions/',
                 template=f"{templates_path}.open_sessions"
                 ),
        )
        cmds.append(
            dict(cmd='show /system/device_sessions/',
                 template=f"{templates_path}.device_sessions"
                 ),
        )
        cmds.append(
            dict(cmd='show /system/system_usage/cpu_usage/',
                 template=f"{templates_path}.cpu_usage"
                 ),
        )
        cmds.append(
            dict(cmd='show /system/system_usage/disk_usage/',
                 template=f"{templates_path}.disk_usage"
                 ),
        )
        cmds.append(
            dict(cmd='show /system/system_usage/memory_usage/',
                 template=f"{templates_path}.memory_usage"
                 ),
        )
        cmds.append(
            dict(cmd='show /settings/cluster/cluster_clusters/',
                 template=f"{templates_path}.cluster_clusters",
                 ignore_error=True
                 ),
        )

        # Check if Syste is Nodegrid Manager
        if system_details['system'] == 'Nodegrid Manager':
            return cmds

        # Extra detaisl for systems like 
        cmds.append(
            dict(cmd='show /system/hw_monitor/io_ports/',
                 template=f"{templates_path}.io_ports",
                 ignore_error=True
                 ),
        )
        cmds.append(
            dict(cmd='show /system/hw_monitor/power/',
                 template=f"{templates_path}.power"
                 ),
        )
        cmds.append(
            dict(cmd='show /system/hw_monitor/thermal/',
                 template=f"{templates_path}.thermal"
                 ),
        )
        cmds.append(
            dict(cmd='show /system/hw_monitor/usb_sensors/',
                 template=f"{templates_path}.usb_sensors"
                 ),
        )
        cmds.append(
            dict(cmd='show /system/usb_devices/',
                 template=f"{templates_path}.usb_devices"
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
        #
        # Nodegrid OS section starts here
        #
        timeout = module.params.pop('gather_timeout', 30)
        #timeout = 30
    
        # Lets get the current status and check if it must be changed
        res, err_msg, nodegrid_os = check_os_version_support()
        if res == 'error' or res == 'unsupported':
            return dict(msg=err_msg)

        system_details = get_system_details()
    
        cmds = self._get_cmds(system_details)
        cmds_results = self._run_commands(cmds, timeout=timeout)
        result = dict()
        parsed_dict = dict()
    
        if cmds_results.get('error') or cmds_results.get("failed"):
            return dict(msg=f"{cmds_results}")
        else:
            for cmd_result in cmds_results.get('cmds_output'):
                if cmd_result.get('error'):
                    result['result'] = cmd_result
                else:
                    template = ""
                    try:
                        template = get_template(cmd_result.get("template"))
                        template_exist = True
                    except Exception as e:
                        result['template_error'] = str(e)
                        result['error'] = f"Template file could not be found: {cmd_result.get('template')}"
                        template_exist = False
                        return dict(msg=result)
                    if template_exist:
                        try:
                            parser = ttp(data=cmd_result['stdout'], template=template)
                            parser.parse()
                            for item in parser.result()[0]:
                                parsed_dict.update(item)
                        except Exception as e:
                            result["error_msg"] = str(e)
                            parsed_dict = dict()
                    else:
                        return dict(msg=f"Template file could not be found: {cmd_result.get('template')}")
    
        return parsed_dict

