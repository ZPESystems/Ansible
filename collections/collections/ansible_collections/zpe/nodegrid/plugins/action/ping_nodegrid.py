# -*- coding: utf-8 -*-

from ansible.plugins.action import ActionBase
from ansible.utils.display import Display
from os.path import exists
from time import sleep

import pexpect

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
    
    def _result_changed(self, msg=''):
        result = dict(
            failed=False,
            changed=True,
            message=msg
        )
        return result
    
    def _result_not_changed(self, msg=''):
        result = dict(
            failed=False,
            changed=False,
            message=msg
        )
        return result

    def run(self, task_vars=None):
        self._task_vars = task_vars
        self._playhost = task_vars.get("inventory_hostname")

        host = task_vars.get("ansible_host")
        username = task_vars.get("ansible_ssh_user")
        options = "-o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no"
        cmd = f"ssh {options} {username}@{host}"

        # try connect
        for cnt in range(60):
            conn_obj = pexpect.spawn(cmd, encoding="utf-8")
            try:
                ret = conn_obj.expect_exact([':~$ ', pexpect.TIMEOUT, pexpect.EOF], timeout=10)
                if ret == 0:
                    return self._result_not_changed()
            except Exception as e:   # pylint: disable=broad-except
                return self._result_failed(str(e))
            finally:
                if conn_obj and conn_obj.isalive():
                    conn_obj.close()
            sleep(5)

        return self._result_failed('Could not connect to host')

