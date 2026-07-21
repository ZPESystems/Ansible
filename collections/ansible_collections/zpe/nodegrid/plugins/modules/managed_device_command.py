#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2024, ZPE Systems <zpesystems.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r'''
---
module: managed_device_command
short_description: Execute commands on a managed device via its serial console
description:
  - Connects to a managed device configured in Nodegrid via its serial console.
  - Reads the device prompt patterns from managed devices types.
  - Performs auto-login using the device credentials stored in Nodegrid.
  - Sends each command in the provided list and waits for the device shell prompt.
  - Exits the device session with Ctrl+C when done.
author:
  - Daniel Nesvera (@zpe-dnesvera)
options:
  managed_device_name:
    description: Name of the managed device as configured in Nodegrid.
    required: true
    type: str
  commands:
    description: List of commands to execute on the managed device.
    required: true
    type: list
    elements: str
  connect_timeout:
    description: Seconds to wait for the device shell prompt after connecting (autologin may take time).
    required: false
    type: int
    default: 60
  cmd_timeout:
    description: Seconds to wait for the device shell prompt after each command.
    required: false
    type: int
    default: 15
'''

EXAMPLES = r'''
- name: Provision Cisco SG220 switch
  zpe.nodegrid.managed_device_command:
    managed_device_name: Cisco-SG220
    commands:
      - show version
      - configure
      - vlan 10
      - name MGMT
      - exit
      - end
      - copy running-config startup-config

- name: Provision device using variable list
  zpe.nodegrid.managed_device_command:
    managed_device_name: "{{ device }}"
    commands: "{{ lookup('file', '/tmp/commands.txt').splitlines() }}"
    connect_timeout: 90
    cmd_timeout: 30
'''

RETURN = r'''
managed_device_name:
  description: Name of the managed device that was provisioned.
  returned: always
  type: str
results:
  description: Per-command output collected from the device.
  returned: always
  type: list
  elements: dict
  contains:
    command:
      description: The command that was sent.
      type: str
    output:
      description: The output received after the command.
      type: str
'''

import json
import os
import re
import subprocess
import traceback

import pexpect

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.zpe.nodegrid.plugins.module_utils.nodegrid_util import (
    get_cli,
    close_cli,
    check_os_version_support,
    execute_cmd,
)

if "DLITF_SID" in os.environ:
    del os.environ["DLITF_SID"]
if "DLITF_SID_ENCRYPT" in os.environ:
    del os.environ["DLITF_SID_ENCRYPT"]


NG_CLI_PROMPT = ']# '

# Message emitted by Nodegrid when multisession=no and the device is already
# connected by another user.
DEVICE_IN_USE_PATTERN = 'Device is in use'

# Message emitted when multisession=yes but multisessRW=no and a second user
# attempts to connect. Autologin fails because the session is read-only.
DEVICE_READ_ONLY_PATTERN = 'Device session is read-only'

# Known error patterns emitted by managed devices.
# Add more patterns here as needed for other device families.
DEVICE_ERROR_PATTERNS = [
    r'^\s*%\s*Unknown command',           # Cisco: % Unknown command
    r'^\s*%\s*Invalid (command|input)',    # Cisco: % Invalid command / % Invalid input detected
    r'^\s*%\s*Incomplete command',         # Cisco: % Incomplete command
    r'^\s*%\s*Ambiguous command',          # Cisco: % Ambiguous command
    r'^\s*%\s*Error',                      # Cisco generic: % Error ...
    r'^\s*Error:',                         # Generic: Error: ...
    r'\bcommand not found\b',              # Shell: command not found
    r'\bSyntax error\b',                   # Generic syntax error
]

class ManagedDeviceConnection:
    cmd_cli = None



    def __init__(self):
        pass

    def __del__(self):
        pass

    def _load_configuration(self):
        pass

    def _match_error(self):
        pass

    def connect(self):
        pass

    def disconnect(self):
        pass

    def send_command(self):
        pass




def _get_device_shell_prompt(managed_device_name):
    '''
        Resolves managed_device_name -> type -> template -> shell_prompt via llconf.
        Falls back to a generic prompt if any step fails.
    '''
    try:
        proc = subprocess.run(
            ['llconf', 'ini', '-s', '-f', '/etc/spm_server.ini', 'json', managed_device_name],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10
        )
        device_type = json.loads(proc.stdout)[managed_device_name]['type']

        proc = subprocess.run(
            ['llconf', 'ini', '-s', '-f', '/etc/spm_types.ini', 'json', device_type],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10
        )
        template_name = json.loads(proc.stdout)[device_type]['template']

        proc = subprocess.run(
            ['llconf', 'ini', '-s', '-f', '/etc/spm_templates.ini', 'json', template_name],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10
        )
        templ = json.loads(proc.stdout)[template_name]
        return templ.get('shell_prompt', r'\r\n\S+[#>]')

    except Exception:
        return r'\r\n\S+[#>]'


def _match_error(output):
    '''
        Checks the command output against DEVICE_ERROR_PATTERNS.
        Returns the first matching error string, or None if no error is found.
    '''
    for pattern in DEVICE_ERROR_PATTERNS:
        match = re.search(pattern, output, re.MULTILINE | re.IGNORECASE)
        if match:
            return match.group(0).strip()
    return None

def _connect(cmd_cli, managed_device_name, commands, connect_timeout, cmd_timeout, device_prompt):
    # Navigate to the device path
    cmd_cli.sendline(f'cd /access/{managed_device_name}/')
    cmd_cli.expect_exact(NG_CLI_PROMPT)

    # Connect — autologin runs here.

    # Also watch for the "Device is in use" error emitted when multisession=no
    # and another user already holds the serial console session.

    # TODO - This approach assumes managed device has autologin enabled
    cmd_cli.sendline('connect')
    idx = cmd_cli.expect(
        [device_prompt, DEVICE_IN_USE_PATTERN, DEVICE_READ_ONLY_PATTERN, pexpect.TIMEOUT, pexpect.EOF],
        timeout=connect_timeout
    )

    if idx == 1:  # multisession=no — device locked by another user
        try:
            cmd_cli.expect_exact(NG_CLI_PROMPT, timeout=10)
        except Exception:
            pass
        raise RuntimeError(
            f'Device "{managed_device_name}" is in use by another user. '
            f'Wait for the session to end or enable multisession in Nodegrid.'
        )
    elif idx == 2:  # multisession=yes, multisessRW=no — read-only session, autologin failed
        try:
            cmd_cli.expect_exact(NG_CLI_PROMPT, timeout=10)
        except Exception:
            pass
        raise RuntimeError(
            f'Device "{managed_device_name}" session is read-only (multisessRW=no). '
            f'Another user holds the primary session. '
            f'Wait for the session to end or enable multisessRW in Nodegrid.'
        )
    elif idx == 3:
        raise pexpect.TIMEOUT(f'Timeout connecting to device "{managed_device_name}".')
    elif idx == 4:
        raise EOFError(f'EOF while connecting to device "{managed_device_name}".')

    # idx == 0 — device prompt matched, connection successful.
    # Send an empty Enter to flush any residual banner/AAA messages that may
    # appear on the same line as the first prompt.
    cmd_cli.sendline('')
    cmd_cli.expect(device_prompt, timeout=cmd_timeout)

def _provision(cmd_cli, managed_device_name, commands, connect_timeout, cmd_timeout, device_prompt):
    '''
        Sends each command to the device and collects output.
        Stops on the first command whose output matches a known error pattern.
        Returns a list of per-command result dicts.
    '''
    results = []

    for command in commands:
        if not command.strip() or command.strip().startswith('#'):
            continue

        cmd_cli.sendline(command)
        idx = cmd_cli.expect(
            [device_prompt, pexpect.TIMEOUT, pexpect.EOF],
            timeout=cmd_timeout
        )
        output = (cmd_cli.before or '').strip()
        error_match = _match_error(output)
        results.append({
            'command': command,
            'output': output,
            'error': bool(error_match),
            'error_message': error_match or '',
            'timeout': idx == 1,
            'eof': idx == 2,
        })
        if error_match or idx == 2:  # stop on first error or EOF
            break

    return results

def _disconnect(cmd_cli):
    cmd_cli.send('\x05c.')
    cmd_cli.expect_exact(NG_CLI_PROMPT, timeout=15)


def run_module():
    module_args = dict(
        managed_device_name=dict(type='str', required=True),
        commands=dict(type='list', elements='str', required=True),
        connect_timeout=dict(type='int', default=60),
        cmd_timeout=dict(type='int', default=15),
        command_prompt=dict(type='str', default='')
    )

    result = dict(
        changed=False,
        failed=False,
        managed_device_name='',
        results=[],
        message='',
    )

    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=True
    )

    res, err_msg, nodegrid_os = check_os_version_support()
    if res == 'error' or res == 'unsupported':
        module.fail_json(msg=err_msg, **result)
    elif res == 'warning':
        result['warning'] = err_msg

    managed_device_name     = module.params['managed_device_name']
    commands        = module.params['commands']
    connect_timeout = module.params['connect_timeout']
    cmd_timeout     = module.params['cmd_timeout']
    command_prompt  = module.params['command_prompt']

    result['managed_device_name'] = managed_device_name

    device_prompt = None #_get_device_shell_prompt(managed_device_name)
    if not device_prompt:
        device_prompt = r'\r\n\S+[#>]'

    cmd_cli = None
    try:
        cmd_cli = get_cli(timeout=cmd_timeout)
        _connect(
            cmd_cli, managed_device_name, commands, connect_timeout, cmd_timeout, device_prompt
        )

        if module.check_mode:
            result['message'] = 'Check mode: no commands were sent to the device.'
            module.exit_json(**result)

        result['results'] = _provision(
            cmd_cli, managed_device_name, commands, connect_timeout, cmd_timeout, device_prompt
        )
        _disconnect(cmd_cli)
        close_cli(cmd_cli)

        # Fail the task if any command returned a known device error
        failed_cmd = next((r for r in result['results'] if r.get('error')), None)
        if failed_cmd:
            result['failed'] = True
            result['message'] = (
                f"Command failed on device \"{managed_device_name}\": "
                f"\"{failed_cmd['command']}\" -> {failed_cmd['error_message']}"
            )
    except pexpect.TIMEOUT:
        result['failed'] = True
        result['message'] = (
            f'Timeout connecting to or provisioning device "{managed_device_name}". '
            f'Verify the device is reachable and the serial port is configured correctly. '
            f'Partial results: {result["results"]}'
        )
        if cmd_cli:
            cmd_cli.close()
    except Exception:
        result['failed'] = True
        result['message'] = traceback.format_exc()
        if cmd_cli:
            cmd_cli.close()

    if result['failed']:
        module.fail_json(msg=result['message'], **result)

    module.exit_json(**result)

def main():
    run_module()


if __name__ == '__main__':
    main()
