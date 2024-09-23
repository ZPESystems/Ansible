# -*- coding: utf-8 -*-

from ansible.plugins.action import ActionBase
from ansible.utils.display import Display
from os import system
from time import sleep

import pexpect

import requests
import urllib3
import time

display = Display()

SSH_ERR_MSG = "Unable to establish SSH connection to the device."

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
    
    def _expect_for(self, conn_obj, expectation_list=[], timeout=10, msg=""):
        expectation_list.append(pexpect.TIMEOUT)
        expectation_list.append(pexpect.EOF)
        list_len = len(expectation_list)
        ret = conn_obj.expect_exact(expectation_list, timeout=timeout)
        if ret == (list_len-2):  # pexpect.TIMEOUT
            raise ResultFailedException(f"Failure (TIMEOUT): {msg}")
        if ret == (list_len-1):  # pexpect.EOF
            raise ResultFailedException(f"Failure (EOF): {msg}")
        return ret
    
    def _connect(self, conn_obj):
        display.vvv('connect')
        expectation_list = [
            ':~$ ',
            ':~# ',
            '/]# ',
            'Password: ',
        ]
        ret = self._expect_for(conn_obj, expectation_list, timeout=60, msg=SSH_ERR_MSG)
        if ret != 0:  
            display.vvv(f"Connection failure: {expectation_list[ret]}")
            raise ResultFailedException("Connection failure")
        return True


    def _upgrade(self, conn_obj, action_module_args):
        display.vvv('upgrade begin')

        # cli
        display.vvv('cli')
        conn_obj.sendline("cli")
        expectation_list = ['/]# ', ':~$ ', ':~# ']
        ret = self._expect_for(conn_obj, expectation_list, timeout=60)
        if ret != 0:  
            display.vvv(f"cli failure: {expectation_list[ret]}")
            raise ResultFailedException("cli failure")
        
        # software_upgrade
        display.vvv('software_upgrade')
        conn_obj.sendline("software_upgrade")
        expectation_list = ['}]# ', '/]# ', ':~$ ', ':~# ']
        ret = self._expect_for(conn_obj, expectation_list)
        if ret != 0:  
            display.vvv(f"software_upgrade failure: {expectation_list[ret]}")
            raise ResultFailedException("software_upgrade failure")
        
        # args
        for key, value in action_module_args.items():

            # set
            display.vvv(f"set {key}={value}")
            conn_obj.sendline(f"set {key}={value}")
            expectation_list = ['}]# ', '/]# ', ':~$ ', ':~# ']
            ret = self._expect_for(conn_obj, expectation_list)
            if ret != 0:  
                display.vvv(f"set failure: {expectation_list[ret]}")
                raise ResultFailedException("set failure")
        
        # upgrade
        display.vvv("upgrade")
        conn_obj.sendline("upgrade")
        expectation_list = ['reboot NOW!', '/]# ', '}]# ', ':~$ ', ':~# ']
        try:
            ret = self._expect_for(conn_obj, expectation_list, timeout=60)
            if ret > 1:
                display.vvv(f"ret: {expectation_list[ret]}")
        except Exception as e:
            display.vvv(str(e))

        display.vvv('upgrade end')
        return True

    def _ping_icmp(self, host, retries, wait_secs):
        tries = 1
        try:
            while (tries <= retries):
                command = f'ping -q -W 1 -c 1 {host} > /dev/null 2>&1'
                exit_code = system(command)
                display.vvv(f'ping to {host}, exit code: {exit_code}')
                if exit_code == 0:
                    return True
                else:
                    tries = tries + 1
                    sleep(wait_secs)
                    continue
        except Exception as error: # pylint: disable=broad-except
            return False
        return False

    def _webwerver_is_ready(senf, host):
        url = f'https://{host}/api/v1/Session'
        body = {
            'username': '',
            'password': ''
        }
        timeout = 60
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        try:
            display.vvv(f'Request to {url}')
            response = requests.post(url, json=body, timeout=timeout, verify=False)
            display.vvv(f'Status code: {response.status_code}')
            if response.status_code == 401:
                return True
        except Exception as e:
            display.vvv(str(e))
        return False

    def run(self, task_vars=None):
        self._task_vars = task_vars
        self._playhost = task_vars.get("inventory_hostname")
        action_module_args = self._task.args.copy()
        host = task_vars.get("ansible_host")
        ansible_ssh_user = task_vars.get('ansible_ssh_user')

        options = "-o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -o PubkeyAuthentication=yes"

        cmd = f"ssh {options} {ansible_ssh_user}@{host}"
        display.vvv(f"{cmd}")

        try:
            # Connect
            conn_obj = pexpect.spawn(cmd, encoding="utf-8")
            self._connect(conn_obj)

            # Send upgrade commands
            result = self._upgrade(conn_obj, action_module_args)
            display.vvv(str(result))

            start_time = time.time()
        
            # Wait for the device to be inaccessible due to the software upgrade
            cnt = 0
            while self._ping_icmp(host, retries=5, wait_secs=1):
                sleep(2)
                cnt += 1
                if cnt >= 120:
                    return self._result_failed("Host didn't reboot")
                
            # Wait for the device to be accessible after the software upgrade
            st = self._ping_icmp(host, retries=720, wait_secs=5)
            if not st:
                return self._result_failed("Host didn't response")

            sleep(10)

            # Wait the Webserver be ready
            while not self._webwerver_is_ready(host):
                sleep(10)

            # Calc the duration
            end_time = time.time()
            duration = end_time - start_time
            minutes = int(duration // 60)
            seconds = duration % 60
            message = f"The upgrade took {minutes} minutes and {seconds} seconds to execute."
            display.vvv(message)

            sleep(10)
            return self._result_changed(msg=message)

        except Exception as e:
            return self._result_failed(str(e))
        finally:
            if conn_obj and conn_obj.isalive():
                conn_obj.close()
