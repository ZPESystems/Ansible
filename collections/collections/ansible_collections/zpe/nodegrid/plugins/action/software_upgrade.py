# -*- coding: utf-8 -*-

from ansible.plugins.action import ActionBase
from ansible.utils.display import Display
from os import system
from time import sleep

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
        return self._execute_module(module_name='nodegrid_cmds', module_args={'cmds':cmds})

    def _ping_icmp(self, host, retries, wait_secs):
        tries = 1
        response = 1
        try:
            while (tries <= retries):
                response = system("ping -q -W 1 -c 1 " + host)
                display.vvv(f"zpe_nodegrid ping_icmp tries={str(tries)}, response={str(response)}")
                if response == 0:
                    return True
                else:
                    tries = tries + 1
                    sleep(wait_secs)
                    continue
        except Exception as error: # pylint: disable=broad-except
            return False
        return False

    def run(self, task_vars=None):
        self._task_vars = task_vars
        self._playhost = task_vars.get("inventory_hostname")
        action_module_args = self._task.args.copy()
        host = task_vars.get("ansible_host")

        ping_wait_sec = 5
        ping_retries = 150

        try:
            # Send upgrade commands
            result = self._upgrade(action_module_args)
            if result['failed']:
                return result
        
            # Make sure device is down first
            cnt = 0
            while self._ping_icmp(host, 1, 1):
                sleep(2)
                cnt += 1
                if cnt >= 120:
                    return self.result_failed("Host didn't reboot")
                
            # Wait software upgrade proccess
            st = self._ping_icmp(host, ping_retries, ping_wait_sec)
            if not st:
                return self._result_failed("Host didn't response")
            sleep(5)
            return self._result_changed()

        except Exception as e:
            return self.result_failed(str(e))
