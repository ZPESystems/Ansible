# -*- coding: utf-8 -*-

from ansible.plugins.action import ActionBase
from ansible.utils.display import Display
from time import sleep

import pexpect

display = Display()

# Global variables
OPTION_USERNAME = 'username'
OPTION_CHANGE_DEFAULT_PASSWORD = 'password'
OPTION_CHANGE_NEW_PASSWORD = 'new_password'
OPTION_INSTALL_SSH_KEY = 'ssh_key'
OPTION_INSTALL_SSH_KEY_USER = 'ssh_key_user'
OPTION_INSTALL_SSH_KEY_TYPE = 'ssh_key_type'
OPTION_GRANT_SUDOERS = 'ansible_sudoers'

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

    def _change_password(self, conn_obj, password, new_password):
        display.vvv(str(password))
        display.vvv(str(new_password))
        login_tries = 0
        for cnt in range(20):
            ret = conn_obj.expect_exact(['BAD PASSWORD:','Password: ', 'Current password: ', 'New password: ','Retype new password: ', '/]# ', pexpect.TIMEOUT, pexpect.EOF], timeout=10)
            display.vvv(str(ret))
            if ret == 0:
                raise ResultFailedException("BAD PASSWORD, provide a different new password")
            elif ret == 1:
                if login_tries == 0:
                    conn_obj.sendline(password)
                elif login_tries == 1:
                    conn_obj.sendline(new_password)
                    return True
                else:
                    raise ResultFailedException(f"Could not login to host. Invalid password!")
                login_tries += 1
            elif ret == 2:
                conn_obj.sendline(password)
            elif ret == 3:
                conn_obj.sendline(new_password)
            elif ret == 4:
                conn_obj.sendline(new_password)
            elif ret == 5:
                conn_obj.sendline(f'shell')
                conn_obj.expect_exact([':~$ ', ':~# '])
                conn_obj.sendline("passwd")
                display.vvv("Start with Loop")
                for chp in range(10):
                    res = conn_obj.expect_exact(['Current password: ', 'New password: ', 'Retype new password: ', 'password updated successfully' ,'BAD PASSWORD:', ':~$ ', ':~# ', pexpect.TIMEOUT, pexpect.EOF], timeout=10)
                    output = conn_obj.before
                    output = output.replace('\r\r\n', '\r\n')
                    display.vvvv(output)
                    if res == 0:
                        display.vvv("Providing old password")
                        conn_obj.sendline(password)
                    elif res == 1:
                        display.vvv("Providing new password")
                        conn_obj.sendline(new_password)
                    elif res == 2:
                        display.vvv("Providing Password a 2nd time")
                        conn_obj.sendline(new_password)
                    elif res == 3:
                        display.vvv("Password Update Successful")
                        return True
                    elif res == 4:
                        display.vvv("Bad Password detected")
                        raise ResultFailedException("BAD PASSWORD, provide a different new password")
                    else:
                        display.vvv("Prompt was detected, return")
                        return True
                return True
            else:
                return False
        raise ResultFailedException("End of loop changing password")

    def _install_ssh_key(self, conn_obj, password, ssh_key_user, ssh_key, ssh_key_type):
        login_tries = 0
        for cnt in range(20):
            ret = conn_obj.expect_exact(['BAD PASSWORD:','Password: ', '/]# ', pexpect.TIMEOUT, pexpect.EOF], timeout=10)
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
                if ssh_key is not None:
                    conn_obj.sendline(f'shell sudo su - {ssh_key_user}')
                    conn_obj.expect_exact([':~$ ', ':~#'])
                    conn_obj.sendline(f"mkdir /home/{ssh_key_user}/.ssh")
                    conn_obj.expect_exact([':~$ ', ':~#'])
                    conn_obj.sendline(f"chmod 700 /home/{ssh_key_user}/.ssh")
                    conn_obj.expect_exact([':~$ ', ':~#'])
                    conn_obj.sendline(f"echo '{ssh_key_type} {ssh_key}' >> /home/{ssh_key_user}/.ssh/authorized_keys")
                    conn_obj.expect_exact([':~$ ', ':~#'])
                    conn_obj.sendline(f"chmod 600 /home/{ssh_key_user}/.ssh/authorized_keys")
                    conn_obj.expect_exact([':~$ ', ':~#'])
                return True
            else:
                return False
        raise ResultFailedException("End of loop installing ssh_key")

    def _grant_sudoers_permissions(self, conn_obj, password, sudo_user):
        login_tries = 0
        for cnt in range(20):
            ret = conn_obj.expect_exact(['BAD PASSWORD:','Password: ', '/]# ', pexpect.TIMEOUT, pexpect.EOF], timeout=10)
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
                if sudo_user is not None:
                    conn_obj.sendline(f'shell sudo su -')
                    conn_obj.expect_exact([':~$ ', ':~#'])
                    conn_obj.sendline(f"echo '{sudo_user} ALL=(ALL) NOPASSWD: ALL' > /etc/sudoers.d/{sudo_user}")
                    conn_obj.expect_exact([':~$ ', ':~#'])
                    conn_obj.sendline(f"chmod 600 /etc/sudoers.d/{sudo_user}")
                    conn_obj.expect_exact([':~$ ', ':~#'])
                return True
            else:
                return False
        raise ResultFailedException("End of loop installing granting sudoers permissions")

    def run(self, task_vars=None):
        self._task_vars = task_vars
        self._playhost = task_vars.get("inventory_hostname")
        action_module_args = self._task.args.copy()
        display.vvv(str(action_module_args))

        host = task_vars.get("ansible_host")
        options = "-o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no"

        username = None
        password = None
        action_password_change = False
        action_ssh_key = False
        action_sudoers = False
        new_password = None
        ssh_key = None
        ssh_key_user = None
        ssh_key_type = None

        if OPTION_USERNAME in action_module_args.keys():
            username = action_module_args[OPTION_USERNAME]
        else:
            return self._result_failed('No username for the connection was provided')
        if OPTION_CHANGE_DEFAULT_PASSWORD in action_module_args.keys():
            password = action_module_args[OPTION_CHANGE_DEFAULT_PASSWORD]

        # Check if a the password should be changed for the current user
        if OPTION_CHANGE_NEW_PASSWORD in action_module_args.keys():
            new_password = action_module_args[OPTION_CHANGE_NEW_PASSWORD]

        if password is not None and new_password is not None and len(new_password) > 0:
            action_password_change = True

        # Check if a ssh_key should be installed
        if OPTION_INSTALL_SSH_KEY in action_module_args.keys():
            ssh_key = action_module_args[OPTION_INSTALL_SSH_KEY]
            if OPTION_INSTALL_SSH_KEY_USER in action_module_args.keys():
                ssh_key_user = action_module_args[OPTION_INSTALL_SSH_KEY_USER]
            else:
                return self._result_failed('No username was provided, to which the ssh_key should be installed too')
            if OPTION_INSTALL_SSH_KEY_TYPE in action_module_args.keys():
                ssh_key_type = action_module_args[OPTION_INSTALL_SSH_KEY_TYPE]
            else:
                return self._result_failed('No ssh_key_type was provided')

        if len(ssh_key) > 0 and len(ssh_key) > 0 and len(ssh_key_type) > 0:
            if ssh_key_type in ['ssh-rsa']:
                action_ssh_key = True
            else:
                return self._result_failed('No valid ssh_key_type was provided:' + str(ssh_key_type))

        # Check if sudoers permissions should be granted
        if OPTION_GRANT_SUDOERS in action_module_args.keys():
            sudoers_permission = action_module_args[OPTION_GRANT_SUDOERS]

        if sudoers_permission:
            action_sudoers = True

        display.vvv("Change password: " + str(action_password_change) )
        display.vvv("Install SSH-KEY: " + str(action_ssh_key))
        display.vvv("Grant Sudoer permissions: " + str(action_sudoers))

        if action_ssh_key or action_password_change or sudoers_permission:
            cmd = f"ssh {options} {username}@{host}"
        else:
            return self._result_not_changed("No action was defined")

        # try connect
        for cnt in range(60):
            conn_obj = pexpect.spawn(cmd, encoding="utf-8")
            try:
                if action_password_change:
                    status_password_change = self._change_password(conn_obj, password, new_password)
                if action_ssh_key:
                    status_ssh_key = self._install_ssh_key(conn_obj, password, ssh_key_user, ssh_key, ssh_key_type)
                if sudoers_permission:
                    status_sudoers = self._grant_sudoers_permissions(conn_obj, password, sudo_user="ansible")

                return self._result_changed()
            except Exception as e:   # pylint: disable=broad-except
                return self._result_failed(str(e))
            finally:
                if conn_obj and conn_obj.isalive():
                    conn_obj.close()
            sleep(5)

        return self._result_failed('Could not connect to host')

        

