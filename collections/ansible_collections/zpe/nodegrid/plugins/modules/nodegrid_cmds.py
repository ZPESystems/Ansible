#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2023, ZPE Systems <zpesystems.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r'''
---
module: connection_facts
author: Rene Neumann (@zpe-rneumann)
'''

EXAMPLES = r'''
'''

RETURN = r'''
# These are examples of possible return values, and in general should use other names for return values.

'''

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.zpe.nodegrid.plugins.module_utils.nodegrid_util import check_os_version_support, run_cli_commands

import os

# We have to remove the SID from the Environmental settings, to avoid an issue
# were we can not run pexpect.run multiple times
if "DLITF_SID" in os.environ:
    del os.environ["DLITF_SID"]
if "DLITF_SID_ENCRYPT" in os.environ:
    del os.environ["DLITF_SID_ENCRYPT"]

def run_module():
    # define available arguments/parameters a user can pass to the module
    module_args = dict(
        cmds=dict(type='list', required=True),
        timeout=dict(type='int', default=60, required=False),
        debug=dict(type='bool', default=False, required=False),
        max_retries=dict(type='int', default=3, required=False),
        base_delay=dict(type='float', default=2.0, required=False),
        max_delay=dict(type='float', default=10.0, required=False),
    )

    # seed the result dict in the object
    # we primarily care about changed and state
    # changed is if this module effectively modified the target
    # state will include any data that you want your module to pass back
    # for consumption, for example, in a subsequent task
    result = dict(
        changed=False,
        failed=False,
        message='',
        cmds_output=list(),
        retries=0,
    )

    # the AnsibleModule object will be our abstraction working with Ansible
    # this includes instantiation, a couple of common attr would be the
    # args/params passed to the execution, as well as if the module
    # supports check mode
    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=True
    )
    timeout = module.params.get('timeout', 60)
    #
    # Nodegrid OS section starts here
    #
    # Lets get the current interface status and check if it must be changed
    res, err_msg, nodegrid_os = check_os_version_support(timeout=module.params['timeout'])
    if res == 'error' or res == 'unsupported':
        module.fail_json(msg=err_msg, **result)
    elif res == 'warning':
        result['warning'] = err_msg

    if module.params.get('debug'):
        result['nodegrid_facts'] = nodegrid_os

    # if the user is working with this module in only check mode we do not
    # want to make any changes to the environment, just return the current
    # state with no modifications
    if module.check_mode:
        module.exit_json(**result)

    # run commands and gather output
    run_cmds =  run_cli_commands(module.params['cmds'], timeout=timeout, max_retries=module.params.get('max_retries'), base_delay=module.params.get('base_delay'), max_delay=module.params.get('max_delay'))
    result['cmds_output'] = run_cmds['cmds_results']
    result['retries'] = run_cmds['retries']
    if run_cmds['error']:
        result['failed'] = True
        result['message'] = f"{run_cmds['msg']}"

    if result['failed']:
        module.fail_json(msg=result['message'], **result)

    # in the event of a successful module execution, you will want to
    # simple AnsibleModule.exit_json(), passing the key/value results
    module.exit_json(**result)


def main():
    run_module()


if __name__ == '__main__':
    main()
