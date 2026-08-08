#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2024, ZPE Systems <zpesystems.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
#from __future__ import (absolute_import, division, print_function)
from __future__ import annotations
__metaclass__ = type

DOCUMENTATION = r'''
---
module: nodegrid_facts
author: 
- Diego Montero (@zpe-diegom)

description:
    - This module gathers useful variables about remote nodegrid hosts that can 
      be used in playbooks. It can also be executed direbly by C(/usr/bin/ansible) to check what variables are
      available to a host.

atributes:
    check_mode:
        support: full
    diff_mode:
        support: none
    facts:
        support: full
    platform:
        platforms: nodegrid

notes:
    - It is required that the ansible.cfg variables to be set as follows:
      hash_behaviour = merge
      facts_modules = zpe.nodegrid.nodegrid_facts,smart

options:
    gather_timeout:
        description:
            - Set the default timeout in seconds for individual fact gathering.
        type: int
        default: 10
'''

EXAMPLES = r'''
# Display facts from a host.
# ansible host -m zpe.nodegrid.nodegrid_facts
'''


from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.common.text.converters import to_text
from ansible.module_utils.facts.collector import CollectorNotFoundError, CycleFoundInFactDeps, UnresolvedFactDep
from ansible.module_utils.facts.namespace import PrefixFactNamespace

from ansible_collections.zpe.nodegrid.plugins.module_utils.facts.nodegrid_collector import NodegridFactCollector
from ansible_collections.zpe.nodegrid.plugins.module_utils.nodegrid_util import NodegridError

def run_module():
    # define available arguments/parameters a user can pass to the module
    module_args = dict(
        gather_subset=dict(default=["all"], required=False, type='list', elements='str'),
        gather_timeout=dict(default=60, required=False, type='int'),
        max_retries=dict(type='int', default=3, required=False),
        base_delay=dict(type='float', default=2.0, required=False),
        max_delay=dict(type='float', default=10.0, required=False),
    )

    # the AnsibleModule object will be our abstraction working with Ansible
    # this includes instantiation, a couple of common attr would be the
    # args/params passed to the execution, as well as if the module
    # supports check mode   
    module = AnsibleModule(
        argument_spec = module_args,
        supports_check_mode=True,
    )   

    result = dict(
        failed=False,
    )
    
    namespace = PrefixFactNamespace(namespace_name='nodegrid', prefix='nodegrid_')
    try:
        nodegrid_fact_collector = NodegridFactCollector(namespace=namespace)
        nodegrid_facts = nodegrid_fact_collector.collect_with_namespace(module=module, collected_facts=None)
    except (TypeError, CollectorNotFoundError, CycleFoundInFactDeps, UnresolvedFactDep, NodegridError) as e:
        module.fail_json(msg=to_text(e))

    if nodegrid_facts.pop('nodegrid_failed', False):
        result['failed'] = True
        result['message'] = nodegrid_facts['nodegrid_msg']
        module.fail_json(msg=nodegrid_facts['nodegrid_msg'], **result)
    if len(nodegrid_facts) > 0:
        result['ansible_facts'] = nodegrid_facts

    #module.exit_json(ansible_facts=facts_dict)
    module.exit_json(**result)


def main():
    run_module()


if __name__ == '__main__':
    main()
