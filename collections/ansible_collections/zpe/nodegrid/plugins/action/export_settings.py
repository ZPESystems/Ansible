# -*- coding: utf-8 -*-

from ansible.plugins.action import ActionBase
from ansible.utils.display import Display
from time import sleep

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

    def _result_not_changed(self, msg=dict()):
        result = dict(
            failed=False,
            changed=False,
            settings=msg
        )
        return result

    def run(self, task_vars=None):
        self._task_vars = task_vars
        action_module_args = self._task.args.copy()

        # Create export_settings command list
        cmds = list()
        for setting in action_module_args['settings']:
            cmds.append(dict(cmd='export_settings /settings/' + str(setting) + '/ --plain-password'))
        cmd_args = dict(
            cmds=cmds
        )
        response = self._execute_module(module_name='nodegrid_cmds', module_args=cmd_args)
        if 'cmds_output' in response.keys():
            all_lines = list()
            for cmd_output in response['cmds_output']:
                if not cmd_output['error']:
                    lines = cmd_output['stdout_lines']
                    lines.pop(0)  # remove the first line
                    lines.pop()  # remove the last line
                    all_lines = all_lines + lines
                # We can add an option to write the exports directly to a file instead of returning the values
                # with open("zpe_cloud", "w") as file1:
                #     file1.writelines(lines)
            return self._result_not_changed(all_lines)
        else:
            return self._result_failed(str(response))