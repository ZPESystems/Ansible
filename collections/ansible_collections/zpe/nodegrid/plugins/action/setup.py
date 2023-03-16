# -*- coding: utf-8 -*-

from ansible.plugins.action import ActionBase
from ansible.utils.display import Display
from time import sleep

import pexpect

display = Display()

# Global variables
OPTION_CHANGE_DEFAULT_PASSWORD = 'password'
OPTION_INSTALL_SSH_KEY = 'ssh_key'

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
    
    def _result_not_changed(self, msg=''):
        result = dict(
            failed=False,
            changed=False,
            message=msg
        )
        return result

    def _install_ssh_key(self, conn_obj, ssh_key):
        conn_obj.sendline('shell sudo su - ansible')
        conn_obj.expect_exact(':~$ ')
        conn_obj.sendline(f"echo '{ssh_key}' >> /home/ansible/.ssh/authorized_keys")
        conn_obj.expect_exact(':~$ ')

    def _change_password_and_install_ssh_key(self, conn_obj, password, ssh_key=None):
        login_tries = 0
        for cnt in range(20):
            ret = conn_obj.expect_exact(['BAD PASSWORD:','Password: ', 'Current password: ', 'New password: ','Retype new password: ', '/]# ', pexpect.TIMEOUT, pexpect.EOF], timeout=10)
            if ret == 0:
                raise ResultFailedException("BAD PASSWORD")
            elif ret == 1:
                if login_tries == 0:
                    conn_obj.sendline('admin')
                elif login_tries == 1:
                    conn_obj.sendline(password)
                else:
                    raise ResultFailedException(f"Could not login to host. Invalid password!")
                login_tries += 1
            elif ret == 2:
                conn_obj.sendline('admin')
            elif ret == 3:
                conn_obj.sendline(password)
            elif ret == 4:
                conn_obj.sendline(password)
            elif ret == 5:
                if ssh_key is not None:
                    self._install_ssh_key(conn_obj, ssh_key)
                return True
            else:
                return False
        raise ResultFailedException("End of loop changing password")

    def run(self, task_vars=None):
        self._task_vars = task_vars
        self._playhost = task_vars.get("inventory_hostname")
        action_module_args = self._task.args.copy()

        host = task_vars.get("ansible_host")
        username = "admin"
        options = "-o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no"
        cmd = f"ssh {options} {username}@{host}"

        password = None
        ssh_key = None

        if OPTION_CHANGE_DEFAULT_PASSWORD in action_module_args.keys():
            password = action_module_args[OPTION_CHANGE_DEFAULT_PASSWORD]
        if OPTION_INSTALL_SSH_KEY in action_module_args.keys():
            ssh_key = action_module_args[OPTION_INSTALL_SSH_KEY]

        if password is None:
            return self._result_not_changed()

        # try connect
        for cnt in range(60):
            conn_obj = pexpect.spawn(cmd, encoding="utf-8")
            try:
                if self._change_password_and_install_ssh_key(conn_obj, password, ssh_key):
                    return self._result_changed()
            except Exception as e:   # pylint: disable=broad-except
                return self._result_failed(str(e))
            finally:
                if conn_obj and conn_obj.isalive():
                    conn_obj.close()
            sleep(5)

        return self._result_failed('Could not connect to host')

        

