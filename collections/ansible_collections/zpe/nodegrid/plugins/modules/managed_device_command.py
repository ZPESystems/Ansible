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
  timeout:
    description: Seconds to wait for the device shell prompt after connecting and after command.
    required: false
    type: int
    default: 10
  force:
    description:
      - Skip the Read-Write Multisession safety check and connect even when
        another user may be simultaneously connected with write access.
      - When C(false) (default), the task fails if the device has Read-Write
        Multisession enabled, to prevent unintentional command conflicts.
      - When C(true), the task proceeds regardless.
    required: false
    type: bool
    default: false
  pager_prompt:
    description:
      - Pagination prompt string to detect when command output is paged.
      - When matched, the module automatically sends a space to advance to the next page
        and continues accumulating output until the command prompt appears.
    required: false
    type: str
    default: '<--- More --->'
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
    timeout: 90
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

from dataclasses import dataclass, asdict
from typing import List, Optional

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.zpe.nodegrid.plugins.module_utils.nodegrid_util import (
    get_cli,
    close_cli,
    check_os_version_support,
)

if "DLITF_SID" in os.environ:
    del os.environ["DLITF_SID"]
if "DLITF_SID_ENCRYPT" in os.environ:
    del os.environ["DLITF_SID_ENCRYPT"]

@dataclass
class CommandResult:
    command: str
    output: str = ''
    error: bool = False
    error_message: str = ''
    timeout: bool = False
    eof: bool = False

    def to_dict(self) -> dict:
        return asdict(self)

class ManagedDeviceConnection:
    NG_CLI_PROMPT = ']# '
    NG_ESCAPE_KEY = '\x05c.'
    MANAGED_DEVICE_DEFAULT_PROMPT = r'\r\n\S+[#>]'
    MANAGED_DEVICE_DEFAULT_PAGER_PROMPT = '<--- More --->'

    # Message emitted by Nodegrid when multisession=no and the device is already
    # connected by another user.
    MANAGED_DEVICE_IN_USE_PATTERN = 'Device is in use'

    # Message emitted when multisession=yes but multisessRW=no and a second user
    # attempts to connect. Autologin fails because the session is read-only.
    MANAGED_DEVICE_READ_ONLY_PATTERN = 'Device session is read-only'

    # Known error patterns emitted by managed devices.
    # Add more patterns here as needed for other device families.
    MANAGED_DEVICE_ERROR_PATTERNS = [
        r'^\s*%\s*Unknown command',           # Cisco: % Unknown command
        r'^\s*%\s*Invalid (command|input)',    # Cisco: % Invalid command / % Invalid input detected
        r'^\s*%\s*Incomplete command',         # Cisco: % Incomplete command
        r'^\s*%\s*Ambiguous command',          # Cisco: % Ambiguous command
        r'^\s*%\s*Error',                      # Cisco generic: % Error ...
        r'^\s*Error:',                         # Generic: Error: ...
        r'\bcommand not found\b',              # Shell: command not found
        r'\bSyntax error\b',                   # Generic syntax error
    ]

    def __init__(self, name: str, timeout: int = 10, command_prompt: str = '', pager_prompt: str = '', force: bool = False):
        # TODO - validate inputs and raise errors

        self.cmd_cli = get_cli(timeout=timeout)
        self.name = name
        self.timeout = timeout
        self.force = force

        self.multisession = False
        self.multisession_rw = False
        self.pager_prompt = pager_prompt if pager_prompt else self.MANAGED_DEVICE_DEFAULT_PAGER_PROMPT

        self._load_configuration()

        # If multisession read-write is enabled, another user may be simultaneously
        # connected with write access, risking command conflicts.
        if self.multisession and self.multisession_rw and not self.force:
            raise RuntimeError(
                f'Device "{self.name}" has Read-Write Multisession enabled. '
                f'Another user may be connected simultaneously, which could cause '
                f'command conflicts. Use force=true to proceed anyway.'
            )

        # User can override command prompt
        # TODO - the local_serial template is not working properly for Cisco, causing
        # incorrect mapping between commands and results in Ansible reponse
        # It should be '\r\n\S+[#>]'
        # Wrong [#>$%]\s?
        if command_prompt and len(command_prompt) > 0:
            self.command_prompt = command_prompt

        self._connect()

    def __del__(self):
        self._disconnect()

    def _load_configuration(self) -> None:
        proc = subprocess.run(
            ['llconf', 'ini', '-s', '-f', '/etc/spm_server.ini', 'json', self.name],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10
        )
        if not proc.stdout.strip():
            raise RuntimeError(
                f'Managed device "{self.name}" not found. '
                f'Verify the device name matches exactly as configured in Nodegrid.'
            )
        managed_device_config = json.loads(proc.stdout)[self.name]
        managed_device_device_type = managed_device_config.get('type', 'local_serial')

        self.multisession = managed_device_config.get('multisession', 'no') == 'yes'
        self.multisession_rw = managed_device_config.get('multisessRW', 'no') == 'yes'

        # TODO - probably better to use CLI commands instead of llconf
        proc = subprocess.run(
            ['llconf', 'ini', '-s', '-f', '/etc/spm_types.ini', 'json', managed_device_device_type],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10
        )
        if not proc.stdout.strip():
            raise RuntimeError(
                f'Device type "{managed_device_device_type}" not found.'
            )
        template_name = json.loads(proc.stdout)[managed_device_device_type]['template']

        proc = subprocess.run(
            ['llconf', 'ini', '-s', '-f', '/etc/spm_templates.ini', 'json', template_name],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10
        )
        if not proc.stdout.strip():
            raise RuntimeError(
                f'Template "{template_name}" not found.'
            )
        templ = json.loads(proc.stdout)[template_name]

        self.command_prompt = templ.get('shell_prompt', self.MANAGED_DEVICE_DEFAULT_PROMPT)

    def _match_error(self, output: str) -> Optional[str]:
        for pattern in self.MANAGED_DEVICE_ERROR_PATTERNS:
            match = re.search(pattern, output, re.MULTILINE | re.IGNORECASE)
            if match:
                return match.group(0).strip()
        return None

    def _connect(self) -> None:
        # Navigate to the device path
        self.cmd_cli.sendline(f'cd /access/{self.name}/')
        self.cmd_cli.expect_exact(self.NG_CLI_PROMPT)

        # Connect — autologin runs here.

        # Also watch for the "Device is in use" error emitted when multisession=no
        # and another user already holds the serial console session.

        # TODO - This approach assumes managed device has autologin enabled
        self.cmd_cli.sendline('connect')

        # The terminal may not appear immediately after connect; send Enter on each
        # timeout and retry up to 10 times with a 1-second window per attempt.
        for _ in range(10):
            idx = self.cmd_cli.expect(
                [self.command_prompt, self.MANAGED_DEVICE_IN_USE_PATTERN, self.MANAGED_DEVICE_READ_ONLY_PATTERN, pexpect.TIMEOUT, pexpect.EOF],
                timeout=1
            )

            if idx == 0:
                break

            # multisession=no — device locked by another user
            elif idx == 1:
                try:
                    self.cmd_cli.expect_exact(self.NG_CLI_PROMPT, timeout=self.timeout)
                except Exception:
                    pass
                raise RuntimeError(
                    f'Device "{self.name}" is in use by another user. '
                    f'Wait for the session to end or enable multisession in Nodegrid.'
                )

            # multisession=yes, multisessRW=no — read-only session, autologin failed
            elif idx == 2:
                try:
                    self.cmd_cli.expect_exact(self.NG_CLI_PROMPT, timeout=self.timeout)
                except Exception:
                    pass
                raise RuntimeError(
                    f'Device "{self.name}" session is read-only. '
                    f'Another user holds the primary session. '
                    f'Wait for the session to end or enable Read-Write Multisession in Nodegrid.'
                )

            elif idx == 4:
                raise EOFError(f'EOF while connecting to device "{self.name}".')

            # idx == 3 — timeout, nudge the terminal with Enter and retry
            self.cmd_cli.sendline('')

        else:
            raise pexpect.TIMEOUT(f'Timeout connecting to device "{self.name}" after 10 attempts.')

        # Send an empty Enter to flush any residual banner/AAA messages that may
        # appear on the same line as the first prompt.
        self.cmd_cli.sendline('')
        self.cmd_cli.expect(self.command_prompt, timeout=self.timeout)
        self.cmd_cli.buffer = ''

    def _disconnect(self) -> None:
        if self.cmd_cli is None:
            return

        try:
            self.cmd_cli.send(self.NG_ESCAPE_KEY)
            self.cmd_cli.expect_exact(self.NG_CLI_PROMPT, timeout=self.timeout)
            close_cli(self.cmd_cli)
        except Exception:
            pass

    @staticmethod
    def _clean_output(raw: str) -> str:
        # strip ANSI escape sequences then normalize CRLF to LF
        cleaned = re.sub(r'\x1b\[[0-9;]*[A-Za-z]', '', raw)
        cleaned = cleaned.replace('\r\n', '\n').replace('\r', '\n')
        return cleaned.strip()

    def send_command(self, command: str) -> CommandResult:
        # Discard any residual data (e.g. extra prompts) left in pexpect's
        # buffer from the previous command or the connect phase.
        self.cmd_cli.buffer = ''

        self.cmd_cli.sendline(command)

        # Sync past any stale pre-command prompts still in the OS buffer by
        # waiting for the command echo before collecting output.
        try:
            self.cmd_cli.expect_exact(command, timeout=self.timeout)
        except (pexpect.TIMEOUT, pexpect.EOF):
            pass

        output_chunks = []
        timed_out = False
        got_eof = False

        while True:
            patterns = [self.command_prompt, re.escape(self.pager_prompt), pexpect.TIMEOUT, pexpect.EOF]
            idx = self.cmd_cli.expect(patterns, timeout=self.timeout)
            output_chunks.append(self.cmd_cli.before or '')

            if idx == 0:
                break
            elif idx == 1:
                self.cmd_cli.send(' ')
            elif idx == 2:
                timed_out = True
                break
            else:
                got_eof = True
                break

        output = self._clean_output(''.join(output_chunks))
        error_match = self._match_error(output)

        # isso nao deu certo - script ficou stuck no enviou do primeiro exist

        return CommandResult(
            command=command,
            output=output,
            error=bool(error_match),
            error_message=error_match or '',
            timeout=timed_out,
            eof=got_eof,
        )

def _provision(managed_device_connection: ManagedDeviceConnection, commands: List[str]) -> List[dict]:
    results = []

    for command in commands:
        if not command.strip() or command.strip().startswith('#'):
            continue

        cmd_result = managed_device_connection.send_command(command)
        results.append(cmd_result.to_dict())

        # stop on first error or EOF
        if len(cmd_result.error_message) > 0 or cmd_result.eof:
            break

    return results

def run_module():
    module_args = dict(
        managed_device_name=dict(type='str', required=True),
        commands=dict(type='list', elements='str', required=True),
        timeout=dict(type='int', default=10),
        command_prompt=dict(type='str', default=''),
        pager_prompt=dict(type='str', default=''),
        force=dict(type='bool', default=False)
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

    res, err_msg, _ = check_os_version_support()
    if res == 'error' or res == 'unsupported':
        module.fail_json(msg=err_msg, **result)
    elif res == 'warning':
        result['warning'] = err_msg

    managed_device_name = module.params['managed_device_name']
    commands = module.params['commands']
    timeout = module.params['timeout']
    command_prompt = module.params['command_prompt']
    pager_prompt = module.params['pager_prompt']
    session_force = module.params['force']

    result['managed_device_name'] = managed_device_name

    # Connect to managed device
    try:
        managed_device_connection = ManagedDeviceConnection(
            name=managed_device_name,
            timeout=timeout,
            command_prompt=command_prompt,
            pager_prompt=pager_prompt,
            force=session_force,
        )
    except RuntimeError as e:
        result['failed'] = True
        result['message'] = str(e)
        module.fail_json(msg=result['message'], **result)
    except pexpect.TIMEOUT:
        result['failed'] = True
        result['message'] = (
            f'Timeout connecting to device "{managed_device_name}". '
            f'Verify the device is reachable and the serial port is configured correctly. '
            f'Partial results: {result["results"]}'
        )
        module.fail_json(msg=result['message'], **result)

    except Exception:
        result['failed'] = True
        result['message'] = traceback.format_exc()
        module.fail_json(msg=result['message'], **result)

    if module.check_mode:
        result['message'] = 'Check mode: no commands were sent to the device.'
        module.exit_json(**result)

    # Run commands
    try:
        result['results'] = _provision(managed_device_connection, commands)

        # Fail the task if any command returned a known device error
        failed_cmd = next((r for r in result['results'] if r.get('error')), None)
        if failed_cmd:
            result['failed'] = True
            result['message'] = (
                f"Command failed on device \"{managed_device_name}\": "
                f"\"{failed_cmd['command']}\" -> {failed_cmd['error_message']}"
            )
    except RuntimeError as e:
        result['failed'] = True
        result['message'] = str(e)
        module.fail_json(msg=result['message'], **result)
    except pexpect.TIMEOUT:
        result['failed'] = True
        result['message'] = (
            f'Timeout provisioning device "{managed_device_name}". '
            f'Verify the device is reachable and the serial port is configured correctly. '
            f'Partial results: {result["results"]}'
        )
    except Exception:
        result['failed'] = True
        result['message'] = traceback.format_exc()

    if result['failed']:
        module.fail_json(msg=result['message'], **result)

    module.exit_json(**result)

def main():
    run_module()

if __name__ == '__main__':
    main()
