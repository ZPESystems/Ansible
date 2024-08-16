# -*- coding: utf-8 -*-

from ansible.plugins.action import ActionBase
from ansible.utils.display import Display
from os import system
from time import sleep

import json
import requests
import urllib3

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
    
    def _upgrade(self,action_module_args):
        cmds = []
        cmds.append({'cmd': 'software_upgrade'})
        for key, value in action_module_args.items():
            cmds.append({'cmd': f"set {key}={value}"})
        cmds.append({'cmd': 'upgrade'})
        return self._execute_module(module_name='zpe.nodegrid.nodegrid_cmds', module_args={'cmds':cmds})

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

        try:
            # Send upgrade commands
            result = self._upgrade(action_module_args)
            if result['failed']:
                return result
        
            # Wait for the device to be inaccessible due to the software upgrade
            cnt = 0
            while self._ping_icmp(host, retries=5, wait_secs=1):
                sleep(2)
                cnt += 1
                if cnt >= 120:
                    return self._result_failed("Host didn't reboot")
                
            # Wait for the device to be accessible after the software upgrade
            st = self._ping_icmp(host, retries=150, wait_secs=5)
            if not st:
                return self._result_failed("Host didn't response")

            sleep(5)

            # Wait the Webserver be ready
            while not self._webwerver_is_ready(host):
                sleep(2)

            return self._result_changed()

        except Exception as e:
            return self._result_failed(str(e))
