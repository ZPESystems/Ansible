# -*- coding: utf-8 -*-

from ansible.plugins.action import ActionBase
from ansible.utils.display import Display
from time import sleep
from enum import Enum
import base64, struct

import pexpect

display = Display()

# Global variables
OPTION_LOGIN = 'login'
OPTION_LOGIN_USERNAME = 'username'
OPTION_LOGIN_PASSWORD = 'password'
OPTION_LOGIN_SSH_PORT = 'ssh_port'
OPTION_CHANGE_PASSWORD = 'change_password'
OPTION_CHANGE_PASSWORD_NEW_PASSWORD = 'new_password'
OPTION_INSTALL_SSH_KEY = 'install_ssh_key'
OPTION_INSTALL_SSH_KEY_DATA = 'key'
OPTION_INSTALL_SSH_KEY_USER = 'user'
OPTION_INSTALL_SSH_KEY_TYPE = 'key_type'
GRANT_SUDO_ACCESS = 'grant_sudo_access'
GRANT_SUDO_ACCESS_USER = 'user'
GRANT_SUDO_ACCESS_ENABLE = 'enable'

SSH_ERR_MSG = "Unable to establish SSH connection to the device."

class ResultFailedException(Exception):
    "Raised when a failed happens"

class PromptType(Enum):
    CLI = '/]# '
    USER_SHELL = ':~$ '
    ROOT_SHELL = ':~# '

class ActionModule(ActionBase):
    """action module"""

    _requires_connection = False

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
    
    def _expect_for(self, conn_obj, expectation_list=[], timeout=60, msg=""):
        expectation_list.append(pexpect.TIMEOUT)
        expectation_list.append(pexpect.EOF)
        list_len = len(expectation_list)
        ret = conn_obj.expect_exact(expectation_list, timeout=timeout)
        if ret == (list_len-2):  # pexpect.TIMEOUT
            raise ResultFailedException(f"Failure (TIMEOUT): {msg}")
        if ret == (list_len-1):  # pexpect.EOF
            raise ResultFailedException(f"Failure (EOF): {msg}")
        return ret

    def _login(self, conn_obj, password, new_password):
        display.vvv(f"Login ...")

        login_tries = 0
        pass_changed = False
        
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
            ret = self._expect_for(conn_obj, expectation_list, msg=(SSH_ERR_MSG if cnt == 0 else ''))

            # BAD PASSWORD:
            if ret == 0:  
                display.vvv("Bad Password detected")
                raise ResultFailedException("BAD PASSWORD, provide a different new password")
            
            # Password:
            elif ret == 1:
                display.vvv(f"Password login_tries: {login_tries}")
                if login_tries == 0:                
                    conn_obj.sendline(password)
                elif login_tries == 1:
                    if new_password is None:
                        raise ResultFailedException("Could not login to host. Invalid password!")    
                    password = new_password
                    conn_obj.sendline(new_password)
                elif login_tries == 2:
                    password = 'admin'
                    conn_obj.sendline(password)
                else:
                    raise ResultFailedException("Could not login to host, end of retries. Invalid password!")
                login_tries += 1

            # Current password:
            elif ret == 2:
                if new_password is None:
                    raise ResultFailedException("You are required to change your password immediately!")    
                display.vvv("Providing current password")
                conn_obj.sendline(password)

            # New password:
            elif ret == 3:
                display.vvv("Providing new password")
                conn_obj.sendline(new_password)

            # Retype new password:
            elif ret == 4:
                display.vvv("Providing new password (retype)")
                conn_obj.sendline(new_password)
                pass_changed = True

            # /]# :~$ :~#
            elif ret in [5, 6, 7]:
                display.vvv(f"Prompt was detected: {expectation_list[ret]}")
                prompt_mapping = {
                    5: PromptType.CLI,
                    6: PromptType.USER_SHELL,
                    7: PromptType.ROOT_SHELL
                }
                return prompt_mapping.get(ret, PromptType.CLI), pass_changed, password
            
            # Permission denied (publickey,keyboard-interactive).
            elif ret == 8:
                display.vvv("Permission denied")
                raise ResultFailedException("Permission denied (publickey,keyboard-interactive).")

            else:
                raise ResultFailedException("Failed login")
        raise ResultFailedException("End of loop login")

    def _change_password(self, conn_obj, prompt, password, new_password):
        display.vvv("Changing password ...")

        if prompt == PromptType.CLI:
            conn_obj.sendline('shell')
            self._expect_for(conn_obj, [':~$ ', ':~# '])

        conn_obj.sendline("passwd")

        for cnt in range(10):
            ret = self._expect_for(conn_obj, [
                'Current password: ',
                'New password: ',
                'Retype new password: ',
                'password updated successfully',
                'BAD PASSWORD:',
                'passwords do not match'
            ])

            # Current password:
            if ret == 0:
                display.vvv("Providing old password")
                conn_obj.sendline(password)
            
            # New password:
            elif ret == 1:
                display.vvv("Providing new password")
                conn_obj.sendline(new_password)
            
            # Retype new password:
            elif ret == 2:
                display.vvv("Providing Password a 2nd time")
                conn_obj.sendline(new_password)

            # password updated successfully
            elif ret == 3:
                display.vvv("Password Update Successful")
                self._expect_for(conn_obj, [':~$ ', ':~# '])
                if prompt == PromptType.CLI:
                    conn_obj.sendline('exit')
                    self._expect_for(conn_obj, ['/]# ', ':~$ ', ':~# '])
                return True
            
            # BAD PASSWORD:
            elif ret == 4:
                display.vvv("Bad Password detected")
                reason = ''
                try:
                    self._expect_for(conn_obj, ['/]# ', ':~$ ', ':~# '])
                    reason = f" ({str(conn_obj.before).splitlines()[0]})"
                    display.vvv(reason)
                except Exception as e:   # pylint: disable=broad-except
                    dispaly.vvv(str(e))
                raise ResultFailedException(f"BAD PASSWORD{reason}, provide a different new password")

            # passwords do not match
            elif ret == 5:
                display.vvv("Passwords do not match")
                raise ResultFailedException(f"Passwords do not match")

            else:
                raise ResultFailedException(f"Failed changing password")
        raise ResultFailedException("End of loop change password")

    def _install_ssh_key(self, conn_obj, prompt, ssh_key_user, ssh_key, ssh_key_type, comment=""):
        display.vvv(f"Installing SSH key ...")

        if prompt == PromptType.CLI:
            conn_obj.sendline(f'shell sudo su - {ssh_key_user}')
        elif prompt == PromptType.USER_SHELL:
            conn_obj.sendline(f'sudo su - {ssh_key_user}')
        else: # PromptType.ROOT_SHELL
            conn_obj.sendline(f'su - {ssh_key_user}')
        self._expect_for(conn_obj, [':~$ ', ':~# '])

        conn_obj.sendline(f"mkdir -p /home/{ssh_key_user}/.ssh")
        self._expect_for(conn_obj, [':~$ ', ':~# '])
        conn_obj.sendline(f"chmod 700 /home/{ssh_key_user}/.ssh")
        self._expect_for(conn_obj, [':~$ ', ':~# '])

        # Check if the ssh key is already installed
        conn_obj.sendline(f"grep -q '{ssh_key}' /home/{ssh_key_user}/.ssh/authorized_keys && echo _SUCCESS_ >&2 || echo _FAIL_ >&2")
        ret = self._expect_for(conn_obj, ['_SUCCESS_', '_FAIL_', ':~$ ', ':~# '])
        if ret == 0:
            display.vvv(f"SSH key already installed")
            self._expect_for(conn_obj, [':~$ ', ':~# '])
            conn_obj.sendline('exit')
            self._expect_for(conn_obj, ['/]# ', ':~$ ', ':~# '])
            return False
        if ret == 1:
            display.vvv(f"SSH key is not installed")
            self._expect_for(conn_obj, [':~$ ', ':~# '])

        conn_obj.sendline(f"echo '{ssh_key_type} {ssh_key} {comment}' >> /home/{ssh_key_user}/.ssh/authorized_keys")
        self._expect_for(conn_obj, [':~$ ', ':~# '])
        conn_obj.sendline(f"chmod 600 /home/{ssh_key_user}/.ssh/authorized_keys")
        self._expect_for(conn_obj, [':~$ ', ':~# '])

        conn_obj.sendline('exit')
        self._expect_for(conn_obj, ['/]# ', ':~$ ', ':~# '])

        display.vvv(f"SSH key installed")
        return True

    def _grant_sudo_access(self, conn_obj, prompt, sudo_user):
        display.vvv(f"Granting sudo permissions ...")

        if prompt != PromptType.ROOT_SHELL:
            if prompt == PromptType.CLI:
                conn_obj.sendline(f'shell sudo su -')
            elif prompt == PromptType.USER_SHELL:
                conn_obj.sendline(f'sudo su -')
            self._expect_for(conn_obj, [':~$ ', ':~# '])

        # Check if sudo permissions is granted
        conn_obj.sendline(f"[ -f /etc/sudoers.d/{sudo_user} ] && echo _SUCCESS_ >&2 || echo _FAIL_ >&2")
        ret = self._expect_for(conn_obj, ['_SUCCESS_', '_FAIL_', ':~$ ', ':~# '])
        if ret == 0:
            display.vvv(f"Sudo permissions already granted")
            self._expect_for(conn_obj, [':~$ ', ':~# '])
            if prompt != PromptType.ROOT_SHELL:
                conn_obj.sendline('exit')
                self._expect_for(conn_obj, ['/]# ', ':~$ ', ':~# '])
            return False
        if ret == 1:
            display.vvv(f"Sudo permissions is not granted")
            self._expect_for(conn_obj, [':~$ ', ':~# '])

        conn_obj.sendline(f"echo '{sudo_user} ALL=(ALL) NOPASSWD: ALL' > /etc/sudoers.d/{sudo_user}")
        self._expect_for(conn_obj, [':~$ ', ':~# '])
        conn_obj.sendline(f"chmod 600 /etc/sudoers.d/{sudo_user}")
        self._expect_for(conn_obj, [':~$ ', ':~# '])

        if prompt != PromptType.ROOT_SHELL:
            conn_obj.sendline('exit')
            self._expect_for(conn_obj, ['/]# ', ':~$ ', ':~# '])

        display.vvv(f"Sudo access granted")
        return True

    def run(self, task_vars=None):
        self._task_vars = task_vars
        self._playhost = task_vars.get("inventory_hostname")
        action_module_args = self._task.args.copy()

        options = "-o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no"
        options += " -o PubkeyAuthentication=no -o KbdInteractiveAuthentication=yes"

        username = None
        password = 'admin'
        action_password_change = False
        action_ssh_key = False
        action_sudoers = False
        new_password = None
        ssh_key = None
        ssh_key_user = 'ansible'
        ssh_key_type = 'ssh-ed25519'
        ssh_key_value = None
        sudo_user = 'ansible'

        # 
        # login
        #
        if OPTION_LOGIN in action_module_args.keys():
            login_args = action_module_args[OPTION_LOGIN]

            # username
            if OPTION_LOGIN_USERNAME in login_args.keys():
                username = login_args[OPTION_LOGIN_USERNAME]
                if len(username) == 0:
                    return self._result_failed('The username to login can not be empty')
            else:
                return self._result_failed('No username to login was provided')
            options += f" -l {username}"

            # password
            if OPTION_LOGIN_PASSWORD in login_args.keys():
                password = login_args[OPTION_LOGIN_PASSWORD]

            # ssh port
            ssh_port = self.get_connection_option('port')
            if OPTION_LOGIN_SSH_PORT in login_args.keys():
                ssh_port = login_args[OPTION_LOGIN_SSH_PORT]
            if ssh_port:
                options += f" -p {ssh_port}"
        else:
            return self._result_failed('No login attributes for the connection was provided')

        #
        # change password
        #
        if OPTION_CHANGE_PASSWORD in action_module_args.keys():
            change_pass_args = action_module_args[OPTION_CHANGE_PASSWORD]
        
            # new password
            if OPTION_CHANGE_PASSWORD_NEW_PASSWORD in change_pass_args.keys():
                new_password = change_pass_args[OPTION_CHANGE_PASSWORD_NEW_PASSWORD]
            if new_password is not None and len(new_password) > 0:
                action_password_change = True   # set action
        
        #
        # install ssh key
        #
        if OPTION_INSTALL_SSH_KEY in action_module_args.keys():
            install_ssh_key_args = action_module_args[OPTION_INSTALL_SSH_KEY]
        
            # ssh key user
            if OPTION_INSTALL_SSH_KEY_USER in install_ssh_key_args.keys():
                ssh_key_user = install_ssh_key_args[OPTION_INSTALL_SSH_KEY_USER]

            # ssh key 
            if OPTION_INSTALL_SSH_KEY_DATA in install_ssh_key_args.keys():
                ssh_key = install_ssh_key_args[OPTION_INSTALL_SSH_KEY_DATA]

            # ssh key type
            if OPTION_INSTALL_SSH_KEY_TYPE in install_ssh_key_args.keys():
                ssh_key_type = install_ssh_key_args[OPTION_INSTALL_SSH_KEY_TYPE]

            if ssh_key is not None and len(ssh_key) > 0:
                split_key = ssh_key.split()
                display.vvv(f"Key length: {len(split_key)}")
                # If one value was provided, it should be the ssh key
                if len(split_key) == 1:
                    ssh_key_value = split_key[0]
                    comment = ""
                    if ssh_key_type is None or len(ssh_key_type) == 0:
                        return self._result_failed('No ssh  key_type was provided')
                #If two where provided, it should be the type first, then the ssh key
                elif len(split_key) == 2:
                    ssh_key_type = split_key[0]
                    ssh_key_value = split_key[1]
                    comment = ""
                #If three where provided, it should be type, ssh_key and comment
                elif len(split_key) >= 3:
                    ssh_key_type = split_key[0]
                    ssh_key_value = split_key[1]
                    comment = split_key[2]
                #If more are provided return an error
                else:
                    return self._result_failed('No valid ssh_key was provided:' + str(ssh_key_type))

                #Valdidate that the ssh key is valid
                valid_key_types = ['ssh-ecdsa', 'ssh-ecdsa-sk', 'ssh-ed25519', 'ssh-ed25519-sk', 'ssh-rsa']
                if ssh_key_type in valid_key_types:
                    action_ssh_key = True   # set action
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

        #
        # grant sudo access
        #
        if GRANT_SUDO_ACCESS in action_module_args.keys():
            grant_sudo_access_args = action_module_args[GRANT_SUDO_ACCESS]
        
            # user
            if GRANT_SUDO_ACCESS_USER in grant_sudo_access_args.keys():
                sudo_user = grant_sudo_access_args[GRANT_SUDO_ACCESS_USER]
                if len(sudo_user) == 0:
                    return self._result_failed('The user to grant sudo access can not be empty')

            # enable
            if GRANT_SUDO_ACCESS_ENABLE in grant_sudo_access_args.keys():
                if grant_sudo_access_args[GRANT_SUDO_ACCESS_ENABLE]:
                    action_sudoers = True   # set action

        display.vvv("Change password: " + str(action_password_change) )
        display.vvv("Install SSH-KEY: " + str(action_ssh_key))
        display.vvv("Grant Sudoer permissions: " + str(action_sudoers))

        if action_ssh_key or action_password_change or action_sudoers:
            ssh_executable = self.get_connection_option("ssh_executable")
            ssh_common_args = self.get_connection_option("ssh_common_args")
            ssh_extra_args = self.get_connection_option("ssh_extra_args")
            ssh_host = self.get_connection_option("host")
            cmd = f"{ssh_executable} {ssh_common_args} {ssh_extra_args} {options} {ssh_host}"
            display.vvv(f"{cmd}")
        else:
            return self._result_not_changed("No action was defined")

        # try connect
        conn_obj = None
        try:
            msg = ""
            password_changed = False
            ssh_key_installed = False
            sudo_access_granted = False

            # Login
            conn_obj = pexpect.spawn(cmd, encoding="utf-8")
            conn_obj.setecho(False)
            prompt, password_changed, password = self._login(conn_obj, password, new_password)

            # Change password
            if action_password_change:
                if password != new_password:
                    if not password_changed:
                        password_changed = self._change_password(conn_obj, prompt, password, new_password)
                        password = new_password
                    if password_changed:
                        msg += f"Password for user {username} has been changed. "
                
            # Install SSH key
            if action_ssh_key:
                ssh_key_installed = self._install_ssh_key(conn_obj, prompt, ssh_key_user, ssh_key_value, ssh_key_type, comment)
                if ssh_key_installed:
                    msg += f"SSH key has been added to user {ssh_key_user}. "
                
            # Grant sudo access
            if action_sudoers:
                sudo_access_granted = self._grant_sudo_access(conn_obj, prompt, sudo_user)
                if sudo_access_granted:
                    msg += f"User {sudo_user} has been added to sudoers. "

            if password_changed or ssh_key_installed or sudo_access_granted:
                return self._result_changed(msg=msg.strip())
            else:
                return self._result_not_changed(msg="No change was executed!")
        except Exception as e:   # pylint: disable=broad-except
            return self._result_failed(str(e))
        finally:
            if conn_obj and conn_obj.isalive():
                conn_obj.sendline('exit')
                conn_obj.close()
