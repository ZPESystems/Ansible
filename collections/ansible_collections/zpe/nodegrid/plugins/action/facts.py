# -*- coding: utf-8 -*-

from ansible.plugins.action import ActionBase
from ansible_collections.zpe.nodegrid.plugins.module_utils.facts.parse import get_template
from ttp import ttp

class ActionModule(ActionBase):
    """action module"""


    def __init__(self, *args, **kwargs):
        super(ActionModule, self).__init__(*args, **kwargs)
        self._result = {}
        self._task_vars = None

    def _run_command(self, cmds):
        result = dict()
        if len(cmds) >0:
            response = self._execute_module(module_name='zpe.nodegrid.nodegrid_cmds', module_args=cmds, task_vars=self._task_vars)
            if 'cmds_output' in response.keys():
                result["failed"] = False
                result['result'] = response
            else:
                result["failed"] = True
                result['result'] = response
        return result

    def _get_cmds(self):
        cmds = list()
        cmds.append(
            dict(cmd='show /system/about/',
                 template='ansible_collections.zpe.nodegrid.plugins.module_utils.facts.templates.about'
                 ),
        )
        cmds.append(
            dict(cmd='show /system/open_sessions/',
                 template='ansible_collections.zpe.nodegrid.plugins.module_utils.facts.templates.open_sessions'
                 ),
        )
        cmds.append(
            dict(cmd='show /system/device_sessions/',
                 template='ansible_collections.zpe.nodegrid.plugins.module_utils.facts.templates.device_sessions'
                 ),
        )
        cmds.append(
            dict(cmd='show /system/system_usage/cpu_usage/',
                 template='ansible_collections.zpe.nodegrid.plugins.module_utils.facts.templates.cpu_usage'
                 ),
        )
        cmds.append(
            dict(cmd='show /system/system_usage/disk_usage/',
                 template='ansible_collections.zpe.nodegrid.plugins.module_utils.facts.templates.disk_usage'
                 ),
        )
        cmds.append(
            dict(cmd='show /system/system_usage/memory_usage/',
                 template='ansible_collections.zpe.nodegrid.plugins.module_utils.facts.templates.memory_usage'
                 ),
        )
        cmds.append(
            dict(cmd='show /system/hw_monitor/io_ports/',
                 template='ansible_collections.zpe.nodegrid.plugins.module_utils.facts.templates.io_ports',
                 ignore_error=True
                 ),
        )
        cmds.append(
            dict(cmd='show /system/hw_monitor/power/',
                 template='ansible_collections.zpe.nodegrid.plugins.module_utils.facts.templates.power'
                 ),
        )
        cmds.append(
            dict(cmd='show /system/hw_monitor/thermal/',
                 template='ansible_collections.zpe.nodegrid.plugins.module_utils.facts.templates.thermal'
                 ),
        )
        cmds.append(
            dict(cmd='show /system/hw_monitor/usb_sensors/',
                 template='ansible_collections.zpe.nodegrid.plugins.module_utils.facts.templates.usb_sensors'
                 ),
        )
        cmds.append(
            dict(cmd='show /system/usb_devices/',
                 template='ansible_collections.zpe.nodegrid.plugins.module_utils.facts.templates.usb_devices'
                 ),
        )
        cmds.append(
            dict(cmd='show /system/serial_statistics/',
                 template='ansible_collections.zpe.nodegrid.plugins.module_utils.facts.templates.serial_statistics_nsr',
                 ignore_error=True
                 ),
        )
        cmds.append(
            dict(cmd='show /system/serial_statistics/',
                 template='ansible_collections.zpe.nodegrid.plugins.module_utils.facts.templates.serial_statistics',
                 ignore_error=True
                 ),
        )
        cmds.append(
            dict(cmd='show /settings/cluster/cluster_clusters/',
                 template='ansible_collections.zpe.nodegrid.plugins.module_utils.facts.templates.cluster_clusters'
                 ),
        )


        return cmds

    def run(self, task_vars=None):
        self._task_vars = task_vars
        self._playhost = task_vars.get("inventory_hostname")
        result = dict()
        cmds = self._get_cmds()
        cmd_args = dict(
            cmds=cmds
        )

        cmds_results = self._run_command(cmd_args)
        if cmds_results.get('error') or cmds_results.get("failed"):
            return cmds_results
        else:
            parsed_dict = dict()
            for cmd_result in cmds_results.get('result').get('cmds_output'):
                if cmd_result.get('error'):
                    result['result'] = cmd_result
                    result['failed'] = True
                else:
                    template = ""
                    try:
                        template = get_template(cmd_result.get("template"))
                        template_exist = True
                    except Exception as e:
                        result['template_error'] = str(e)
                        result['failed'] = True
                        template_exist = False
                    if template_exist:
                        parser = ttp(data=cmd_result['stdout'], template=template)
                        parser.parse()
                        try:
                            for item in parser.result()[0]:
                                parsed_dict.update(item)
                        except Exception as e:
                            result["failed"] = True
                            result["error_msg"] = str(e)
                            parsed_dict = dict()
                    else:
                        result['failed'] = True
                        result['error'] = "Template file could not be found."
        if len(parsed_dict) > 0:
            result["ansible_facts"] = parsed_dict
            result["failed"] = False
            result["changed"] = False
        else:
            result["failed"] = True
            result["changed"] = False
        return result
