# -*- coding: utf-8 -*-

from ansible.plugins.action import ActionBase
from ansible.utils.display import Display

display = Display()

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

    def _result_changed(self, msg='', diff='', no_diff='', remove=''):
        result = dict(
            failed=False,
            changed=True,
            message=msg,
        )
        return result

    def _result_not_changed(self, msg=''):
        result = dict(
            failed=False,
            changed=False,
            msg=str(msg),
        )
        return result

    def run(self, task_vars=None):
        self._task_vars = task_vars
        action_module_args = self._task.args.copy()
        cmds = list()
        if 'settings' in action_module_args.keys():
            ### Not Fully implemented
            delete_dict_list = action_module_args['settings']
            for delete_dict in delete_dict_list:
                cmds.append({ 'cmd' : f"cd " + str(delete_dict['path']) })
                cmds.append({'cmd': f"delete " + str(delete_dict['setting']), 'confirm':True })
        if 'fullpath' in action_module_args.keys():
            delete_path = action_module_args['fullpath']
            display.vvv(str(delete_path))
            for fullpath in delete_path:
                path, setting = fullpath.rsplit('/', 1)
                cmds.append({ 'cmd' : f"cd " + str(path) })
                cmds.append({'cmd': f"delete " + str(setting), 'confirm':True } )
        if 'path' in action_module_args.keys() and 'item' in action_module_args.keys():
            delete_path = action_module_args['path']
            if isinstance(delete_path, str):
                for item in action_module_args['item']:
                    cmds.append({ 'cmd' : f"cd " + str(delete_path) })
                    cmds.append({'cmd': f"delete " + str(item), 'confirm':True } )
        cmd_args = dict(cmds=cmds)
        if len(cmds) > 0:
            response = self._execute_module(module_name='zpe.nodegrid.nodegrid_cmds', module_args=cmd_args)
            if 'cmds_output' in response.keys():
                return self._result_changed(msg=str(response['cmds_output']))
            else:
                return self._result_failed(msg=str(response))
        return self._result_not_changed(msg='No Settings to be removed detected')
