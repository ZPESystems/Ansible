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
        raise ResultFailedException("End of loop installing granting sudoers permissions")

    def _install_ssh_key(self, conn_obj, password, ssh_key_user, ssh_key, ssh_key_type, comment=""):
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
            elif ret == 2: # '/]# '
                if ssh_key is not None:
                    conn_obj.sendline(f'shell sudo su - {ssh_key_user}')
                    ret2 = conn_obj.expect_exact([':~$ ', ':~#', 'Password: '])
                    if ret2 == 2:
                        conn_obj.sendline(password)
                        conn_obj.expect_exact([':~$ ', ':~#'])
                    conn_obj.sendline(f"mkdir /home/{ssh_key_user}/.ssh")
                    conn_obj.expect_exact([':~$ ', ':~#'])
                    conn_obj.sendline(f"chmod 700 /home/{ssh_key_user}/.ssh")
                    conn_obj.expect_exact([':~$ ', ':~#'])
                    conn_obj.sendline(f"echo '{ssh_key_type} {ssh_key} {comment}' >> /home/{ssh_key_user}/.ssh/authorized_keys")
                    conn_obj.expect_exact([':~$ ', ':~#'])
                    conn_obj.sendline(f"chmod 600 /home/{ssh_key_user}/.ssh/authorized_keys")
                    conn_obj.expect_exact([':~$ ', ':~#'])
                return True
            elif ret == 3: # ':~$ '
                if ssh_key is not None:
                    conn_obj.sendline(f'sudo su - {ssh_key_user}')
                    ret2 = conn_obj.expect_exact([':~$ ', ':~#', 'Password: '])
                    if ret2 == 2:
                        conn_obj.sendline(password)
                        conn_obj.expect_exact([':~$ ', ':~#'])
                    conn_obj.sendline(f"mkdir /home/{ssh_key_user}/.ssh")
                    conn_obj.expect_exact([':~$ ', ':~#'])
                    conn_obj.sendline(f"chmod 700 /home/{ssh_key_user}/.ssh")
                    conn_obj.expect_exact([':~$ ', ':~#'])
                    conn_obj.sendline(f"echo '{ssh_key_type} {ssh_key} {comment}' >> /home/{ssh_key_user}/.ssh/authorized_keys")
                    conn_obj.expect_exact([':~$ ', ':~#'])
                    conn_obj.sendline(f"chmod 600 /home/{ssh_key_user}/.ssh/authorized_keys")
                    conn_obj.expect_exact([':~$ ', ':~#'])
                return True
            elif ret == 4: # ':~# '
                if ssh_key is not None:
                    conn_obj.sendline(f'su - {ssh_key_user}')
                    conn_obj.expect_exact([':~$ ', ':~#'])
                    conn_obj.sendline(f"mkdir /home/{ssh_key_user}/.ssh")
                    conn_obj.expect_exact([':~$ ', ':~#'])
                    conn_obj.sendline(f"chmod 700 /home/{ssh_key_user}/.ssh")
                    conn_obj.expect_exact([':~$ ', ':~#'])
                    conn_obj.sendline(f"echo '{ssh_key_type} {ssh_key} {comment}' >> /home/{ssh_key_user}/.ssh/authorized_keys")
                    conn_obj.expect_exact([':~$ ', ':~#'])
                    conn_obj.sendline(f"chmod 600 /home/{ssh_key_user}/.ssh/authorized_keys")
                    conn_obj.expect_exact([':~$ ', ':~#'])
                return True
            elif ret == 5: # pexpect.TIMEOUT
                raise ResultFailedException("ssh command pexpect.TIMEOUT")
            else:
                raise ResultFailedException(f"ssh command pexpect error | return {ret}")
        raise ResultFailedException("End of loop installing ssh_key")

    def _grant_sudoers_permissions(self, conn_obj, password, sudo_user):
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
            elif ret == 2:
                if sudo_user is not None:
                    conn_obj.sendline(f'shell sudo su -')
                    ret2 = conn_obj.expect_exact([':~$ ', ':~#', 'Password: '])
                    if ret2 == 2:
                        conn_obj.sendline(password)
                        conn_obj.expect_exact([':~$ ', ':~#'])
                    conn_obj.sendline(f"echo '{sudo_user} ALL=(ALL) NOPASSWD: ALL' > /etc/sudoers.d/{sudo_user}")
                    conn_obj.expect_exact([':~$ ', ':~#'])
                    conn_obj.sendline(f"chmod 600 /etc/sudoers.d/{sudo_user}")
                    conn_obj.expect_exact([':~$ ', ':~#'])
                    display.vvv(f"User {sudo_user} granted sudo permissions")
                return True
            elif ret == 3:
                if sudo_user is not None:
                    conn_obj.sendline(f'sudo su -')
                    ret2 = conn_obj.expect_exact([':~$ ', ':~#', 'Password: '])
                    if ret2 == 2:
                        conn_obj.sendline(password)
                        conn_obj.expect_exact([':~$ ', ':~#'])
                    conn_obj.sendline(f"echo '{sudo_user} ALL=(ALL) NOPASSWD: ALL' > /etc/sudoers.d/{sudo_user}")
                    conn_obj.expect_exact([':~$ ', ':~#'])
                    conn_obj.sendline(f"chmod 600 /etc/sudoers.d/{sudo_user}")
                    conn_obj.expect_exact([':~$ ', ':~#'])
                    display.vvv(f"User {sudo_user} granted sudo permissions")
                return True
            elif ret == 4:
                if sudo_user is not None:
                    conn_obj.sendline(f"echo '{sudo_user} ALL=(ALL) NOPASSWD: ALL' > /etc/sudoers.d/{sudo_user}")
                    conn_obj.expect_exact([':~$ ', ':~#'])
                    conn_obj.sendline(f"chmod 600 /etc/sudoers.d/{sudo_user}")
                    conn_obj.expect_exact([':~$ ', ':~#'])
                    display.vvv(f"User {sudo_user} granted sudo permissions")
                return True
            elif ret == 5: # pexpect.TIMEOUT
                raise ResultFailedException("ssh command pexpect.TIMEOUT")
            else:
                raise ResultFailedException(f"Failed adding user {sudo_user} to sudoers | Return value {ret} | {conn_obj.before}")
        raise ResultFailedException("End of loop installing granting sudoers permissions")

    def _install_ssh_key(self, conn_obj, password, ssh_key_user, ssh_key, ssh_key_type, comment=""):
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
            elif ret == 2: # '/]# '                     # CLI prompt detected
                if ssh_key is not None:
                    conn_obj.sendline(f'shell sudo su - {ssh_key_user}')
                    ret2 = conn_obj.expect_exact([':~$ ', ':~#', 'Password: '])
                    if ret2 == 2:
                        conn_obj.sendline(password)
                        conn_obj.expect_exact([':~$ ', ':~#'])
                    conn_obj.sendline(f"mkdir /home/{ssh_key_user}/.ssh")
                    conn_obj.expect_exact([':~$ ', ':~#'])
                    conn_obj.sendline(f"chmod 700 /home/{ssh_key_user}/.ssh")
                    conn_obj.expect_exact([':~$ ', ':~#'])
                    conn_obj.sendline(f"echo '{ssh_key_type} {ssh_key} {comment}' >> /home/{ssh_key_user}/.ssh/authorized_keys")
                    conn_obj.expect_exact([':~$ ', ':~#'])
                    conn_obj.sendline(f"chmod 600 /home/{ssh_key_user}/.ssh/authorized_keys")
                    conn_obj.expect_exact([':~$ ', ':~#'])
                return True
            elif ret == 3: # ':~$ '                     # root shell prompt detected
                if ssh_key is not None:
                    conn_obj.sendline(f'sudo su - {ssh_key_user}')
                    ret2 = conn_obj.expect_exact([':~$ ', ':~#', 'Password: '])
                    if ret2 == 2:
                        conn_obj.sendline(password)
                        conn_obj.expect_exact([':~$ ', ':~#'])
                    conn_obj.sendline(f"mkdir /home/{ssh_key_user}/.ssh")
                    conn_obj.expect_exact([':~$ ', ':~#'])
                    conn_obj.sendline(f"chmod 700 /home/{ssh_key_user}/.ssh")
                    conn_obj.expect_exact([':~$ ', ':~#'])
                    conn_obj.sendline(f"echo '{ssh_key_type} {ssh_key} {comment}' >> /home/{ssh_key_user}/.ssh/authorized_keys")
                    conn_obj.expect_exact([':~$ ', ':~#'])
                    conn_obj.sendline(f"chmod 600 /home/{ssh_key_user}/.ssh/authorized_keys")
                    conn_obj.expect_exact([':~$ ', ':~#'])
                return True
            elif ret == 4: # ':~# '                 # user shell prompt detected
                if ssh_key is not None:
                    conn_obj.sendline(f'su - {ssh_key_user}')
                    conn_obj.expect_exact([':~$ ', ':~#'])
                    conn_obj.sendline(f"mkdir /home/{ssh_key_user}/.ssh")
                    conn_obj.expect_exact([':~$ ', ':~#'])
                    conn_obj.sendline(f"chmod 700 /home/{ssh_key_user}/.ssh")
                    conn_obj.expect_exact([':~$ ', ':~#'])
                    conn_obj.sendline(f"echo '{ssh_key_type} {ssh_key} {comment}' >> /home/{ssh_key_user}/.ssh/authorized_keys")
                    conn_obj.expect_exact([':~$ ', ':~#'])
                    conn_obj.sendline(f"chmod 600 /home/{ssh_key_user}/.ssh/authorized_keys")
                    conn_obj.expect_exact([':~$ ', ':~#'])
                return True
            elif ret == 5: # pexpect.TIMEOUT
                raise ResultFailedException("ssh command pexpect.TIMEOUT")
            else:
                raise ResultFailedException(f"ssh command pexpect error | return {ret}")
        raise ResultFailedException("End of loop installing ssh_key")

    def _grant_sudoers_permissions(self, conn_obj, password, sudo_user):
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
            elif ret == 2:
                if sudo_user is not None:
                    conn_obj.sendline(f'shell sudo su -')
                    ret2 = conn_obj.expect_exact([':~$ ', ':~#', 'Password: '])
                    if ret2 == 2:
                        conn_obj.sendline(password)
                        conn_obj.expect_exact([':~$ ', ':~#'])
                    conn_obj.sendline(f"echo '{sudo_user} ALL=(ALL) NOPASSWD: ALL' > /etc/sudoers.d/{sudo_user}")
                    conn_obj.expect_exact([':~$ ', ':~#'])
                    conn_obj.sendline(f"chmod 600 /etc/sudoers.d/{sudo_user}")
                    conn_obj.expect_exact([':~$ ', ':~#'])
                    display.vvv(f"User {sudo_user} granted sudo permissions")
                return True
            elif ret == 3:
                if sudo_user is not None:
                    conn_obj.sendline(f'sudo su -')
                    ret2 = conn_obj.expect_exact([':~$ ', ':~#', 'Password: '])
                    if ret2 == 2:
                        conn_obj.sendline(password)
                        conn_obj.expect_exact([':~$ ', ':~#'])
                    conn_obj.sendline(f"echo '{sudo_user} ALL=(ALL) NOPASSWD: ALL' > /etc/sudoers.d/{sudo_user}")
                    conn_obj.expect_exact([':~$ ', ':~#'])
                    conn_obj.sendline(f"chmod 600 /etc/sudoers.d/{sudo_user}")
                    conn_obj.expect_exact([':~$ ', ':~#'])
                    display.vvv(f"User {sudo_user} granted sudo permissions")
                return True
            elif ret == 4:
                if sudo_user is not None:
                    conn_obj.sendline(f"echo '{sudo_user} ALL=(ALL) NOPASSWD: ALL' > /etc/sudoers.d/{sudo_user}")
                    conn_obj.expect_exact([':~$ ', ':~#'])
                    conn_obj.sendline(f"chmod 600 /etc/sudoers.d/{sudo_user}")
                    conn_obj.expect_exact([':~$ ', ':~#'])
                    display.vvv(f"User {sudo_user} granted sudo permissions")
                return True
            elif ret == 5: # pexpect.TIMEOUT
                raise ResultFailedException("ssh command pexpect.TIMEOUT")
            else:
                raise ResultFailedException(f"Failed adding user {sudo_user} to sudoers | Return value {ret} | {conn_obj.before}")
        raise ResultFailedException("End of loop installing granting sudoers permissions")

    def run(self, task_vars=None):
        self._task_vars = task_vars
        self._playhost = task_vars.get("inventory_hostname")
        action_module_args = self._task.args.copy()
        display.vvv(str(action_module_args))

        host = task_vars.get("ansible_host")
        options = "-o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -o PubkeyAuthentication=no"

        username = None
        password = None
        action_password_change = False
        action_ssh_key = False
        action_sudoers = False
        new_password = None
        ssh_key = None
        ssh_port = None
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
            if OPTION_INSTALL_SSH_PORT in action_module_args.keys():
                ssh_port = action_module_args[OPTION_INSTALL_SSH_PORT]
                options = options + f" -p {ssh_port}"
                
        if ssh_key is not None and len(ssh_key) > 0 and len(ssh_key_type) > 0:
            split_key = ssh_key.split()
            display.vvv("Key length")
            display.vvv(str(len(split_key)))
            # If one value was provided, it should be the ssh key
            if len(split_key) == 1:
                ssh_key_type = ssh_key_type
                ssh_key_value = split_key[0]
                comment = ""
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
            sudoers_permission = action_module_args[OPTION_GRANT_SUDOERS]
        else:
            sudoers_permission = False

        if sudoers_permission:
            action_sudoers = True

        display.vvv("Change password: " + str(action_password_change) )
        display.vvv("Install SSH-KEY: " + str(action_ssh_key))
        display.vvv("Grant Sudoer permissions: " + str(action_sudoers))

        if action_ssh_key or action_password_change or sudoers_permission:
            cmd = f"ssh {options} {username}@{host}"
            display.vvv(f"{cmd}")
        else:
            return self._result_not_changed("No action was defined")

        # try connect
        for cnt in range(60):
            try:
                if action_password_change:
                    conn_obj = pexpect.spawn(cmd, encoding="utf-8")
                    status_password_change = self._change_password(conn_obj, password, new_password)
                    if conn_obj and conn_obj.isalive():
                        conn_obj.close()
                if action_ssh_key:
                    conn_obj = pexpect.spawn(cmd, encoding="utf-8")
                    status_ssh_key = self._install_ssh_key(conn_obj, password, ssh_key_user, ssh_key_value, ssh_key_type, comment)
                    if conn_obj and conn_obj.isalive():
                        conn_obj.close()
                if sudoers_permission:
                    conn_obj = pexpect.spawn(cmd, encoding="utf-8")
                    status_sudoers = self._grant_sudoers_permissions(conn_obj, password, sudo_user=ssh_key_user)
                    if conn_obj and conn_obj.isalive():
                        conn_obj.close()

                return self._result_changed()
            except Exception as e:   # pylint: disable=broad-except
                return self._result_failed(str(e))
            finally:
                if conn_obj and conn_obj.isalive():
                    conn_obj.close()
            sleep(5)

        return self._result_failed('Could not connect to host')

        

