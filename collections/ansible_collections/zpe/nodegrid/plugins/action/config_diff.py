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
            message=msg,
            config_remove=False,
            config_update=False,
            config_delete=False
        )
        return result

    def _result_changed(self, msg='', diff='', no_diff='', remove=''):
        if len(diff) > 0:
            update = True
        else:
            update = False
        if len(remove) > 0:
            delete = True
        else:
            delete = False
        result = dict(
            failed=False,
            changed=True,
            message=msg,
            config_difference=diff,
            config_identical=no_diff,
            config_remove=remove,
            config_update=update,
            config_delete=delete
        )
        return result

    def _result_not_changed(self, msg='', diff='', no_diff='', remove=''):
        result = dict(
            failed=False,
            changed=False,
            msg=str(msg),
            config_difference=diff,
            config_identical=no_diff,
            config_remove=remove,
            config_update=False,
            config_delete=False
        )
        return result

    def _detailed_diff(self, before, after, format='list'):
        list_same = list()
        list_diff = list()
        list_remove = list()
        display.vvv(str(before))
        dict_diff = dict()
        for i in before:
            display.vvv(str(i))
            # Check if the settings are provides as a list or as a dictonary,
            # the assumption is that before and after are in teh same format
            if isinstance(i, str):
                if i in after:
                    list_same.append(i)
                else:
                    if format == 'dict':
                        # Lets split i into path and value, we want to get a uniqe key
                        idict = i.split(' ')
                        id = idict[0]
                        if id in dict_diff.keys():
                                display.vvv("id: " + str(id))
                                display.vvv("id: " + str(dict_diff[id]))
                                dict_diff[id].append(i)
                        else:
                                display.vvv("id: " + str(id))
                                listsetting = list()
                                listsetting.append(i)
                                dict_diff[id] = listsetting
                    else:
                        list_diff.append(i)

            if isinstance(i, dict):
                if 'settings' in i.keys():
                    for setting in i['settings']:
                        display.vvv("Setting: " + str(setting))
                        if setting in str(after):
                            list_same.append(setting)
                        else:
                            if format == 'dict':
                                # Lets split i into path and value, we want to get a uniqe key
                                id = i['item']
                                if id in dict_diff.keys():
                                    display.vvv("id: " + str(id))
                                    display.vvv("id: " + str(dict_diff[id]))
                                    dict_diff[id].append(setting)
                                else:
                                    display.vvv("id: " + str(id))
                                    listsetting = list()
                                    listsetting.append(setting)
                                    dict_diff[id] = listsetting
                            else:
                                list_diff.append(setting)

        for j in after:
            if isinstance(j, str):
                if j not in str(before):
                    fullpath = j.split(' ', 1)
                    if type(fullpath) == list:
                        list_remove.append(fullpath[0])
                    else:
                        list_remove.append(fullpath)
            if isinstance(j, dict):
                if 'settings' in j.keys():
                    for setting in j['settings']:
                        if setting not in str(before):
                            fullpath = setting.split(' ', 1)
                            if type(fullpath) == list:
                                list_remove.append(fullpath[0])
                            else:
                                list_remove.append(fullpath)

        if format == 'dict':
            diff_value = dict_diff
        else:
            diff_value = list_diff

        set_remove = set(list_remove)

        return list_same, diff_value, list(set_remove)

    def run(self, task_vars=None):
        self._task_vars = task_vars
        action_module_args = self._task.args.copy()
        if 'result_format' in action_module_args.keys():
            format = action_module_args['result_format']
            if format != "dict":
                format="list"
        else:
            format="list"

        if 'before' in action_module_args.keys():
            before = action_module_args['before']
        else:
            self._result_failed(msg="parameter before must be provided")
        if 'after' in action_module_args.keys():
            after = action_module_args['after']
        else:
            self._result_failed(msg="parameter after must be provided")

        no_diff, diff, list_remove = self._detailed_diff(before, after, format)
        if len(diff) == 0 and len(list_remove) == 0 :
                return self._result_not_changed(msg="provided before and after values are the same", diff=diff, no_diff=no_diff, remove=list_remove)
        else:
                return self._result_changed(msg="provided before and after values are not the same", diff=diff, no_diff=no_diff, remove=list_remove)