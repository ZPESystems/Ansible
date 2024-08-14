# -*- coding: utf-8 -*-

from ansible.plugins.action import ActionBase
from ansible.utils.display import Display
from time import sleep
import base64, struct

import pexpect

display = Display()

# Global variables
OPTION_USERNAME = 'username'
OPTION_CHANGE_DEFAULT_PASSWORD = 'password'
OPTION_CHANGE_NEW_PASSWORD = 'new_password'
OPTION_SSH_PORT = 'ssh_port'
OPTION_INSTALL_SSH_KEY = 'ssh_key'
OPTION_INSTALL_SSH_KEY_USER = 'ssh_key_user'
OPTION_INSTALL_SSH_KEY_TYPE = 'ssh_key_type'
OPTION_GRANT_SUDOERS = 'ssh_key_user_sudoers'

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
    
    def _expect_for(self, conn_obj, expectation_list=[], timeout=10):
        expectation_list.append(pexpect.TIMEOUT)
        expectation_list.append(pexpect.EOF)
        len = len(expectation_list)
        ret = conn_obj.expect_exact(expectation_list, timeout=timeout)
        if ret == (len-2):  # pexpect.TIMEOUT
            raise ResultFailedException(f"Failure pexpect.TIMEOUT")
        if ret == (len-1):  # pexpect.EOF
            raise ResultFailedException(f"Failure pexpect.EOF")
        return ret

    def _change_password_command(self, conn_obj, password, new_password):
        display.vvv(f"Changing password...")
        conn_obj.sendline("passwd")
        for cnt in range(10):
            ret = self._expect_for(conn_obj, [
                'Current password: ',
                'New password: ',
                'Retype new password: ',
                'password updated successfully',
                'BAD PASSWORD:',
                ':~$ ',
                ':~# '
            ])

            if ret == 0:
                display.vvv("Providing old password")
                conn_obj.sendline(password)
            elif ret == 1:
                display.vvv("Providing new password")
                conn_obj.sendline(new_password)
            elif ret == 2:
                display.vvv("Providing Password a 2nd time")
                conn_obj.sendline(new_password)
            elif ret == 3:
                display.vvv("Password Update Successful")
                return True
            elif ret == 4:
                display.vvv("Bad Password detected")
                raise ResultFailedException(f"BAD PASSWORD, provide a different new password")
            elif ret == 5 or ret == 6:
                display.vvv("Prompt was detected, return")
                return True
            else:
                raise ResultFailedException(f"Failed changing password")
        return False

    def _change_password(self, conn_obj, password, new_password):
        login_tries = 0
        for cnt in range(20):
            expectation_list = [
                'BAD PASSWORD:',
                'Password: ',
                'Current password: ',
                'New password: ',
                'Retype new password: ',
                '/]# ',
                ':~$ ',
                ':~# ',
                'Permission denied (publickey,keyboard-interactive).'
            ]
            ret = self._expect_for(conn_obj, expectation_list)

            if ret == 0:
                display.vvv("Bad Password detected")
                raise ResultFailedException("BAD PASSWORD, provide a different new password")
            elif ret == 1:
                display.vvv(f"Password login_tries: {login_tries}")
                if login_tries == 0:                
                    conn_obj.sendline(password)
                elif login_tries == 1:
                    password = new_password
                    conn_obj.sendline(password)
                elif login_tries == 2:
                    password = 'admin'
                    conn_obj.sendline(password)
                else:
                    raise ResultFailedException(f"Could not login to host. Invalid password!")
                login_tries += 1
            elif ret == 2:
                display.vvv("Providing current password")
                conn_obj.sendline(password)
            elif ret == 3:
                display.vvv("Providing new password")
                conn_obj.sendline(new_password)
            elif ret == 4:
                display.vvv("Providing new password (retype)")
                conn_obj.sendline(new_password)
            elif ret in [5, 6, 7]:
                display.vvv(f"Prompt was detected: {expectation_list}")
                if password == new_password:
                    display.vvv("New password already applied")
                    return True
                if ret == 5:    # CLI prompt detected
                    conn_obj.sendline(f'shell')
                    self._expect_for(conn_obj, [':~$ ', ':~# '])
                    self._change_password_command(conn_obj, password, new_password)
                elif ret in [6, 7]:  # user/root shell prompt detected
                    self._change_password_command(conn_obj, password, new_password)
            elif ret == 8:      # Permission denied
                display.vvv("Permission denied")
                raise ResultFailedException("Permission denied (publickey,keyboard-interactive).")
            else:
                raise ResultFailedException(f"Failed changing password")
        raise ResultFailedException("End of loop changing password")

    def _install_ssh_key_command(self, conn_obj, ssh_key_user, ssh_key, ssh_key_type, comment):
        display.vvv(f"Installing SSH key...")
        conn_obj.sendline(f"mkdir -p /home/{ssh_key_user}/.ssh")
        self._expect_for(conn_obj, [':~$ ', ':~# '])
        conn_obj.sendline(f"chmod 700 /home/{ssh_key_user}/.ssh")
        self._expect_for(conn_obj, [':~$ ', ':~# '])
        conn_obj.sendline(f"echo '{ssh_key_type} {ssh_key} {comment}' >> /home/{ssh_key_user}/.ssh/authorized_keys")
        self._expect_for(conn_obj, [':~$ ', ':~# '])
        conn_obj.sendline(f"chmod 600 /home/{ssh_key_user}/.ssh/authorized_keys")
        self._expect_for(conn_obj, [':~$ ', ':~# '])
        display.vvv(f"SSH key installed")
        return True

    def _install_ssh_key(self, conn_obj, password, ssh_key_user, ssh_key, ssh_key_type, comment=""):
        login_tries = 0
        for cnt in range(20):
            expectation_list = [
                'Permission denied (publickey,keyboard-interactive).',
                'Password: ',
                '/]# ',
                ':~$ ',
                ':~# '
            ]
            ret = self._expect_for(conn_obj, expectation_list)

            if ret == 0: # 'BAD PASSWORD'
                display.vvv("Bad Password detected")
                raise ResultFailedException("Permission denied (publickey,keyboard-interactive). Invalid user or password")
            elif ret == 1: # 'Password: '
                display.vvv(f"Password login_tries: {login_tries}")
                if login_tries < 3:
                    conn_obj.sendline(password)
                else:
                    raise ResultFailedException("Could not login to host. Invalid user or password")
                login_tries += 1
            elif ret in [2, 3, 4]:
                display.vvv(f"Prompt was detected: {expectation_list[ret]}")
                if ret == 2:    # CLI prompt detected
                    conn_obj.sendline(f'shell sudo su - {ssh_key_user}')
                elif ret == 3:  # user shell prompt detected
                    conn_obj.sendline(f'sudo su - {ssh_key_user}')
                else:           # root shell prompt detected
                    conn_obj.sendline(f'su - {ssh_key_user}')

                ret2 = self._expect_for(conn_obj, [':~$ ', ':~# ', 'Password: '])
                if ret2 == 2:
                    conn_obj.sendline(password)
                    self._expect_for(conn_obj, [':~$ ', ':~# '])
                return self._install_ssh_key_command(conn_obj, ssh_key_user, ssh_key, ssh_key_type, comment)
            else:
                raise ResultFailedException("Failed installing ssh key")
        raise ResultFailedException("End of loop installing ssh_key")

    def _grant_sudo_access_command(self, conn_obj, sudo_user):
        display.vvv(f"Granting sudo permissions to user {sudo_user}")
        conn_obj.sendline(f"echo '{sudo_user} ALL=(ALL) NOPASSWD: ALL' > /etc/sudoers.d/{sudo_user}")
        self._expect_for(conn_obj, [':~$ ', ':~# '])
        conn_obj.sendline(f"chmod 600 /etc/sudoers.d/{sudo_user}")
        self._expect_for(conn_obj, [':~$ ', ':~# '])
        display.vvv(f"User {sudo_user} granted sudo permissions")
        return True

    def _grant_sudo_access(self, conn_obj, password, sudo_user):
        login_tries = 0
        for cnt in range(20):
            expectation_list = [
                'Permission denied (publickey,keyboard-interactive).',
                'Password: ',
                '/]# ',
                ':~$ ',
                ':~# '
            ]
            ret = self._expect_for(conn_obj, expectation_list)

            if ret == 0: # 'BAD PASSWORD'
                raise ResultFailedException(f"Permission denied (publickey,keyboard-interactive). Check user password")
            elif ret == 1: # 'Password: '
                if login_tries < 3:
                    conn_obj.sendline(password)
                else:
                    raise ResultFailedException(f"Could not login to host. Invalid password")
                login_tries += 1
            elif ret in [2, 3]:
                if ret == 2:    # CLI prompt detected
                    conn_obj.sendline(f'shell sudo su -')
                else:           # user shell prompt detected
                    conn_obj.sendline(f'sudo su -')

                ret2 = self._expect_for(conn_obj, [':~$ ', ':~# ', 'Password: '])
                if ret2 == 2:
                    conn_obj.sendline(password)
                    self._expect_for(conn_obj, [':~$ ', ':~# '])
                return self._grant_sudo_access_command(conn_obj, sudo_user)
            elif ret == 4: # root shell prompt detected
                return self._grant_sudo_access_command(conn_obj, sudo_user)
            else:
                raise ResultFailedException(f"Failed granting sudo access")
        raise ResultFailedException("End of loop installing granting sudoers permissions")

    def run(self, task_vars=None):
        self._task_vars = task_vars
        self._playhost = task_vars.get("inventory_hostname")
        action_module_args = self._task.args.copy()
        display.vvv(str(action_module_args))

        host = task_vars.get("ansible_host")
        ssh_port = task_vars.get("ansible_ssh_port", 22)
        options = "-o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -o PubkeyAuthentication=no"

        username = None
        password = 'admin'
        action_password_change = False
        action_ssh_key = False
        action_sudoers = False
        new_password = None
        ssh_key = None
        ssh_key_user = 'ansible'
        ssh_key_type = 'ssh-ed25519'

        if OPTION_SSH_PORT in action_module_args.keys():
            ssh_port = action_module_args[OPTION_SSH_PORT]
        options = options + f" -p {ssh_port}"

        if OPTION_USERNAME in action_module_args.keys():
            username = action_module_args[OPTION_USERNAME]
            if len(username) == 0:
                return self._result_failed('The username can not be empty')
        else:
            return self._result_failed('No username for the connection was provided')

        if OPTION_CHANGE_DEFAULT_PASSWORD in action_module_args.keys():
            password = action_module_args[OPTION_CHANGE_DEFAULT_PASSWORD]

        # Check if a the password should be changed for the current user
        if OPTION_CHANGE_NEW_PASSWORD in action_module_args.keys():
            new_password = action_module_args[OPTION_CHANGE_NEW_PASSWORD]
        if new_password is not None and len(new_password) > 0:
            action_password_change = True

        # Check if a ssh_key should be installed
        if OPTION_INSTALL_SSH_KEY_USER in action_module_args.keys():
            ssh_key_user = action_module_args[OPTION_INSTALL_SSH_KEY_USER]
        if OPTION_INSTALL_SSH_KEY in action_module_args.keys():
            ssh_key = action_module_args[OPTION_INSTALL_SSH_KEY]
        if OPTION_INSTALL_SSH_KEY_TYPE in action_module_args.keys():
            ssh_key_type = action_module_args[OPTION_INSTALL_SSH_KEY_TYPE]

        if ssh_key is not None and len(ssh_key) > 0:
            split_key = ssh_key.split()
            display.vvv(f"Key length: {len(split_key)}")
            # If one value was provided, it should be the ssh key
            if len(split_key) == 1:
                ssh_key_value = split_key[0]
                comment = ""
                if ssh_key_type is None or len(ssh_key_type) == 0:
                    return self._result_failed('No ssh_key_type was provided')
            #If two where provided, it should be the type first, then the ssh key
            elif len(split_key) == 2:
                ssh_key_type = split_key[0]
                ssh_key_value = split_key[1]
                comment = ""
            #If three where provided, it should be type, ssh_key and comment
            elif len(split_key) == 3:
                ssh_key_type = split_key[0]
                ssh_key_value = split_key[1]
                comment = split_key[2]
            #If more are provided return an error
            else:
                return self._result_failed('No valid ssh_key was provided:' + str(ssh_key_type))

            #Valdidate that the ssh key is valid
            valid_key_types = ['ssh-ecdsa', 'ssh-ecdsa-sk', 'ssh-ed25519', 'ssh-ed25519-sk', 'ssh-rsa']
            if ssh_key_type in valid_key_types:
                action_ssh_key = True
                try:
                    data = base64.decodebytes(bytes(ssh_key_value, 'utf-8'))
                    int_len = 4
                    str_len = struct.unpack('>I', data[:int_len])[0]  # this should return 7
                    data[int_len:int_len + str_len] == type
                except Exception as e:
                    return self._result_failed(f"No valid ssh_key_type was provided: {ssh_key_type} | {str(e)} | Valid Options: {valid_key_types}")
            else:
                return self._result_failed(f"No valid ssh_key_type was provided: {ssh_key_type} | Valid Options: {valid_key_types}")

            display.vvv(f"ssh_key_type: {ssh_key_type}")
            display.vvv(f"ssh_key_value: {ssh_key_value}")
            display.vvv(f"comment: {comment}")
            display.vvv(f"ssh options: {options}")

        # Check if sudoers permissions should be granted
        if OPTION_GRANT_SUDOERS in action_module_args.keys():
            if action_module_args[OPTION_GRANT_SUDOERS]:
                action_sudoers = True

        display.vvv("Change password: " + str(action_password_change) )
        display.vvv("Install SSH-KEY: " + str(action_ssh_key))
        display.vvv("Grant Sudoer permissions: " + str(action_sudoers))

        if action_ssh_key or action_password_change or action_sudoers:
            cmd = f"ssh {options} {username}@{host}"
            display.vvv(f"{cmd}")
        else:
            return self._result_not_changed("No action was defined")

        # try connect
        try:
            msg = ""
            if action_password_change:
                conn_obj = pexpect.spawn(cmd, encoding="utf-8")
                password_changed = self._change_password(conn_obj, password, new_password)
                if conn_obj and conn_obj.isalive():
                    conn_obj.close()
                if password_changed:
                    password = new_password
                    msg += f"Password for user {username} has been changed. "
                
            if action_ssh_key:
                conn_obj = pexpect.spawn(cmd, encoding="utf-8")
                ssh_key_installed = self._install_ssh_key(conn_obj, password, ssh_key_user, ssh_key_value, ssh_key_type, comment)
                if conn_obj and conn_obj.isalive():
                    conn_obj.close()
                if ssh_key_installed:
                    msg += f"SSH key has been added to user {ssh_key_user}. "
                
            if action_sudoers:
                conn_obj = pexpect.spawn(cmd, encoding="utf-8")
                sudo_access_granted = self._grant_sudo_access(conn_obj, password, sudo_user=ssh_key_user)
                if conn_obj and conn_obj.isalive():
                    conn_obj.close()
                if sudo_access_granted:
                    msg += f"User {ssh_key_user} has been added to sudoers. "

            if password_changed or ssh_key_installed or sudo_access_granted:
                return self._result_changed(msg=msg.strip())
            else:
                return self._result_not_changed(msg="No change was executed!")
        except Exception as e:   # pylint: disable=broad-except
            return self._result_failed(str(e))
        finally:
            if conn_obj and conn_obj.isalive():
                conn_obj.close()