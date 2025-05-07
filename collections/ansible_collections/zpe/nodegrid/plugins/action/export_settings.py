# -*- coding: utf-8 -*-

from ansible.plugins.action import ActionBase
from ansible.utils.display import Display
from time import sleep

# Global variables
OPTION_SETTINGS = 'settings'
OPTION_INCLUDE_PASSWORD = 'include_password'
OPTION_DEFAULT = 'include_default'
OPTION_INCLUDE_OPTIONS = 'include_options'
OPTION_INCLUDE_EMPTY = 'include_empty'
OPTION_DEST = 'dest'
OPTION_TIMEOUT = 'timeout'

display = Display()

class ResultFailedException(Exception):
    "Raised when a failed happens"

class ActionModule(ActionBase):
    """action module"""


    def __init__(self, *args, **kwargs):
        super(ActionModule, self).__init__(*args, **kwargs)
        self._result = {}
        self._task_vars = None

    def _result_failed(self, msg=''):
        result = dict(
            failed=True,
            changed=False,
            message=msg
        )
        return result

    def _result_changed(self, msg=''):
        result = dict(
            failed=False,
            changed=True,
            message=msg
        )
        return result

    def _result_not_changed(self, msg='', settings=dict()):
        result = dict(
            failed=False,
            changed=False,
            settings=settings,
            msg=msg
        )
        return result

    def run(self, task_vars=None):
        self._task_vars = task_vars
        action_module_args = self._task.args.copy()

        if OPTION_TIMEOUT in action_module_args.keys():
            timeout = int(action_module_args[OPTION_TIMEOUT])
        else:
            timeout = "300"


        if OPTION_SETTINGS in action_module_args.keys():
            settings = action_module_args[OPTION_SETTINGS]
            if settings == 'all':
                settings = None
                if timeout == 300:
                    timeout = 900
            elif settings == 'normal':
                settings = ['zpe_cloud','custom_fields','local_accounts','date_and_time','auditing','services'
                            ,'password_rules','devices_session_preferences','power_menu','devices_views_preferences'
                            ,'system_preferences','system_logging','authentication','authorization'
                            , 'network_connections','network_preferences']
            elif settings == 'min':
                settings = ['zpe_cloud','local_accounts','authentication','authorization',
                           'date_and_time','auditing','services','devices_views_preferences'
                            ,'system_logging', 'network_connections','network_preferences']

        if OPTION_DEST in action_module_args.keys():
            dest = action_module_args[OPTION_DEST]
        else:
            dest = None

        if OPTION_INCLUDE_PASSWORD in action_module_args.keys():
            if action_module_args[OPTION_INCLUDE_PASSWORD]:
                include_password = "--plain-password"
            else:
                include_password = ""
        else:
            include_password = "--plain-password"

        if OPTION_DEFAULT in action_module_args.keys():
            if action_module_args[OPTION_DEFAULT]:
                include_default = ""
            else:
                include_default = "--no-default"
        else:
            include_default = "--no-default"

        if OPTION_INCLUDE_OPTIONS in action_module_args.keys():
            if action_module_args[OPTION_INCLUDE_OPTIONS]:
                include_options = "--with-options"
            else:
                include_options = ""
        else:
            include_options = ""


        if OPTION_INCLUDE_EMPTY in action_module_args.keys():
            if action_module_args[OPTION_INCLUDE_EMPTY]:
                include_empty = "--include-empty"
            else:
                include_empty = ""
        else:
            include_empty = ""

        display.vvv(f"{OPTION_SETTINGS} : {settings}")
        display.vvv(f"{OPTION_INCLUDE_PASSWORD} : {include_password}")
        display.vvv(f"{OPTION_DEFAULT} : {include_default}")
        display.vvv(f"{OPTION_INCLUDE_OPTIONS} : {include_options}")
        display.vvv(f"{OPTION_INCLUDE_EMPTY} : {include_empty}")
        display.vvv(f"{OPTION_DEST} : {dest}")

        # Create export_settings command list
        cmds = list()
        if settings is None:
            cmds.append(dict(cmd=f'export_settings /settings/ {include_password} {include_default} {include_options} {include_empty}'))
            cmd_args = dict(
                cmds=cmds,
                timeout=timeout
            )
        else:
            for setting in settings:
                cmds.append(dict(cmd=f'export_settings /settings/{setting} {include_password} {include_default} {include_options} {include_empty}'))
            cmd_args = dict(
                cmds=cmds
            )
        response = self._execute_module(module_name='nodegrid_cmds', module_args=cmd_args, task_vars=self._task_vars)
        if 'cmds_output' in response.keys():
            all_lines = list()
            for cmd_output in response['cmds_output']:
                if not cmd_output['error']:
                    lines = cmd_output['stdout_lines']
                    lines.pop(0)  # remove the first line
                    lines.pop()  # remove the last line
                    all_lines = all_lines + lines

            if dest is not None:
                display.vvv(f"Exporting to : {dest}")
                try:
                    file = open(dest,'w')
                    for line in all_lines:
                        file.write(f"{line}\n")
                    file.close()
                except Exception as e:
                    display.vvvv(str(e))
                    self._result_failed("Failed to write to file:" + str(e))

            return self._result_not_changed("", all_lines)
        else:
            return self._result_failed(str(response))