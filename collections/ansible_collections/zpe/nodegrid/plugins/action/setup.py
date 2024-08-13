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
OPTION_INSTALL_SSH_KEY = 'ssh_key'
OPTION_INSTALL_SSH_PORT = 'ssh_port'
OPTION_INSTALL_SSH_USER = 'ssh_user'
OPTION_INSTALL_SSH_KEY_TYPE = 'ssh_key_type'
OPTION_GRANT_SUDOERS = 'grant_sudo_access'

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
        login_tries = 0
        for cnt in range(20):
            ret = conn_obj.expect_exact(['BAD PASSWORD:','Password: ', 'Current password: ', 'New password: ','Retype new password: ', '/]# ', 'Permission denied (publickey,keyboard-interactive).', pexpect.TIMEOUT, pexpect.EOF], timeout=10)
            display.vvv(str(ret))
            if ret == 0:
                raise ResultFailedException("BAD PASSWORD, provide a different new password")
            elif ret == 1:
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
            elif ret == 6:      # Permission denied
                raise ResultFailedException("Permission denied (publickey,keyboard-interactive).")
            elif ret == 7:      # pexpect.TIMEOUT
                raise ResultFailedException("SSH connection TIMEOUT")
            else:
                raise ResultFailedException(f"Failed changing password | Return value {ret} | {conn_obj.before}")
        raise ResultFailedException("End of loop changing password")

    def _add_ssh_key(self, conn_obj, ssh_user, ssh_key, ssh_key_type, comment):
        conn_obj.sendline(f"mkdir -p /home/{ssh_user}/.ssh")
        conn_obj.expect_exact([':~$ ', ':~# '])
        conn_obj.sendline(f"chmod 700 /home/{ssh_user}/.ssh")
        conn_obj.expect_exact([':~$ ', ':~# '])
        conn_obj.sendline(f"echo '{ssh_key_type} {ssh_key} {comment}' >> /home/{ssh_user}/.ssh/authorized_keys")
        conn_obj.expect_exact([':~$ ', ':~# '])
        conn_obj.sendline(f"chmod 600 /home/{ssh_user}/.ssh/authorized_keys")
        conn_obj.expect_exact([':~$ ', ':~# '])
        display.vvv(f"SSH key installed")
        return True

    def _install_ssh_key(self, conn_obj, password, ssh_user, ssh_key, ssh_key_type, comment=""):
        login_tries = 0
        for cnt in range(20):
            ret = conn_obj.expect_exact(['Permission denied (publickey,keyboard-interactive).','Password: ', '/]# ', ':~$ ', ':~# ', pexpect.TIMEOUT, pexpect.EOF], timeout=10)
            if ret == 0: # 'BAD PASSWORD'
                raise ResultFailedException(f"Permission denied (publickey,keyboard-interactive). Check user password: {password}")
            elif ret == 1: # 'Password: '
                if login_tries < 3:
                    conn_obj.sendline(password)
                else:
                    raise ResultFailedException(f"Could not login to host. Invalid password: f{password}")
                login_tries += 1
            elif ret == 2: # '/]# '                 # CLI prompt detected
                conn_obj.sendline(f'shell sudo su - {ssh_user}')
                ret2 = conn_obj.expect_exact([':~$ ', ':~# ', 'Password: '])
                if ret2 == 2:
                    conn_obj.sendline(password)
                    conn_obj.expect_exact([':~$ ', ':~# '])
                return self._add_ssh_key(conn_obj, ssh_user, ssh_key, ssh_key_type, comment)
            elif ret == 3: # ':~$ '                 # user shell prompt detected
                conn_obj.sendline(f'sudo su - {ssh_user}')
                ret2 = conn_obj.expect_exact([':~$ ', ':~# ', 'Password: '])
                if ret2 == 2:
                    conn_obj.sendline(password)
                    conn_obj.expect_exact([':~$ ', ':~# '])
                return self._add_ssh_key(conn_obj, ssh_user, ssh_key, ssh_key_type, comment)
            elif ret == 4: # ':~# '                 # root shell prompt detected
                conn_obj.sendline(f'su - {ssh_user}')
                conn_obj.expect_exact([':~$ ', ':~# '])
                return self._add_ssh_key(conn_obj, ssh_user, ssh_key, ssh_key_type, comment)
            elif ret == 5: # pexpect.TIMEOUT
                raise ResultFailedException("SSH connection TIMEOUT")
            else:
                raise ResultFailedException(f"Failed installing ssh key | Return value {ret} | {conn_obj.before}")
        raise ResultFailedException("End of loop installing ssh_key")

    def _include_user_to_sudoers(self, conn_obj, sudo_user):
        conn_obj.sendline(f"echo '{sudo_user} ALL=(ALL) NOPASSWD: ALL' > /etc/sudoers.d/{sudo_user}")
        conn_obj.expect_exact([':~$ ', ':~# '])
        conn_obj.sendline(f"chmod 600 /etc/sudoers.d/{sudo_user}")
        conn_obj.expect_exact([':~$ ', ':~# '])
        display.vvv(f"User {sudo_user} granted sudo permissions")
        return True

    def _grant_sudo_access(self, conn_obj, password, sudo_user):
        login_tries = 0
        for cnt in range(20):
            ret = conn_obj.expect_exact(['Permission denied (publickey,keyboard-interactive).','Password: ', '/]# ', ':~$ ', ':~# ', pexpect.TIMEOUT, pexpect.EOF], timeout=10)
            if ret == 0: # 'BAD PASSWORD'
                raise ResultFailedException(f"Permission denied (publickey,keyboard-interactive). Check user password: {password}")
            elif ret == 1: # 'Password: '
                if login_tries < 3:
                    conn_obj.sendline(password)
                else:
                    raise ResultFailedException(f"Could not login to host. Invalid password: f{password}")
                login_tries += 1
            elif ret == 2: # '/]# '                 # CLI prompt detected
                conn_obj.sendline(f'shell sudo su -')
                ret2 = conn_obj.expect_exact([':~$ ', ':~# ', 'Password: '])
                if ret2 == 2:
                    conn_obj.sendline(password)
                    conn_obj.expect_exact([':~$ ', ':~# '])
                return self._include_user_to_sudoers(conn_obj, sudo_user)
            elif ret == 3: # ':~$ '                 # user shell prompt detected
                conn_obj.sendline(f'sudo su -')
                ret2 = conn_obj.expect_exact([':~$ ', ':~# ', 'Password: '])
                if ret2 == 2:   
                    conn_obj.sendline(password)
                    conn_obj.expect_exact([':~$ ', ':~# '])
                return self._include_user_to_sudoers(conn_obj, sudo_user)
            elif ret == 4: # ':~# '                 # root shell prompt detected
                return self._include_user_to_sudoers(conn_obj, sudo_user)
            elif ret == 5: # pexpect.TIMEOUT
                raise ResultFailedException("SSH connection TIMEOUT")
            else:
                raise ResultFailedException(f"Failed adding user {sudo_user} to sudoers | Return value {ret} | {conn_obj.before}")
        raise ResultFailedException("End of loop installing granting sudoers permissions")

    def run(self, task_vars=None):
        self._task_vars = task_vars
        self._playhost = task_vars.get("inventory_hostname")
        action_module_args = self._task.args.copy()
        display.vvv(str(action_module_args))

        host = task_vars.get("ansible_host")
        ssh_port = task_vars.get("ansible_ssh_port")
        options = "-o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -o PubkeyAuthentication=no"

        if ssh_port is None:
            ssh_port = 22

        username = None
        password = 'admin'
        action_password_change = False
        action_ssh_key = False
        action_sudoers = False
        new_password = None
        ssh_key = None
        ssh_user = 'ansible'
        ssh_key_type = None

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
        if OPTION_INSTALL_SSH_USER in action_module_args.keys():
            ssh_user = action_module_args[OPTION_INSTALL_SSH_USER]
        if OPTION_INSTALL_SSH_KEY in action_module_args.keys():
            ssh_key = action_module_args[OPTION_INSTALL_SSH_KEY]
        if OPTION_INSTALL_SSH_KEY_TYPE in action_module_args.keys():
            ssh_key_type = action_module_args[OPTION_INSTALL_SSH_KEY_TYPE]
        if OPTION_INSTALL_SSH_PORT in action_module_args.keys():
            ssh_port = action_module_args[OPTION_INSTALL_SSH_PORT]
        options = options + f" -p {ssh_port}"
                
        if ssh_key is not None and len(ssh_key) > 0:
            split_key = ssh_key.split()
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
            valid_key_types = ['ssh-rsa', 'ssh-dsa', 'ssh-ecdsa', 'ssh-ecdsa-sk', 'ssh-ed25519', 'ssh-ed25519-sk']
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

            display.vvv(f"ssh_key_type: {type}")
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
            if action_password_change:
                conn_obj = pexpect.spawn(cmd, encoding="utf-8")
                password_changed = self._change_password(conn_obj, password, new_password)
                if password_changed:
                    password = new_password
                if conn_obj and conn_obj.isalive():
                    conn_obj.close()
            if action_ssh_key:
                conn_obj = pexpect.spawn(cmd, encoding="utf-8")
                ssh_key_installed = self._install_ssh_key(conn_obj, password, ssh_user, ssh_key_value, ssh_key_type, comment)
                if conn_obj and conn_obj.isalive():
                    conn_obj.close()
            if action_sudoers:
                conn_obj = pexpect.spawn(cmd, encoding="utf-8")
                sudo_access_granted = self._grant_sudo_access(conn_obj, password, sudo_user=ssh_user)
                if conn_obj and conn_obj.isalive():
                    conn_obj.close()

            return self._result_changed()
        except Exception as e:   # pylint: disable=broad-except
            return self._result_failed(str(e))
        finally:
            if conn_obj and conn_obj.isalive():
                conn_obj.close()