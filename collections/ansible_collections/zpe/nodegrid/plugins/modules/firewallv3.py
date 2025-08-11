#!/usr/bin/python3

import os
from contextlib import contextmanager
from typing import Any, Optional

import yaml

from ansible.module_utils.basic import AnsibleModule
from ansible.errors import AnsibleModuleError

from ansible_collections.zpe.nodegrid.plugins.module_utils.nodegrid_util import (
    get_cli,
    close_cli,
    execute_cmd,
    check_os_version_support,
)


IPV4 = 4
IPV6 = 6
IP_VERSIONS = (IPV4, IPV6)

SECTION_NAT = "nat"
SECTION_FIREWALL = "firewall"
SECTIONS = (SECTION_NAT, SECTION_FIREWALL)

CHAIN_PREROUTING = "PREROUTING"
CHAIN_INPUT = "INPUT"
CHAIN_FORWARD = "FORWARD"
CHAIN_OUTPUT = "OUTPUT"
CHAIN_POSTROUTING = "POSTROUTING"
BUILTIN_CHAINS = {
    SECTION_NAT: (CHAIN_PREROUTING, CHAIN_INPUT, CHAIN_OUTPUT, CHAIN_POSTROUTING),
    SECTION_FIREWALL: (CHAIN_INPUT, CHAIN_FORWARD, CHAIN_OUTPUT),
}

MARKER_IPV4 = "_ipv4_only"
MARKER_IPV6 = "_ipv6_only"


DOCUMENTATION = f"""
---
module: firewallv3
short_description: Manages the firewall on a ZPE Nodegrid device.
description:
  - Supports IPv4 and IPv6
  - Adds/Removes chains if necessary
  - Adds/Removes rules if necessary
  - Tries to apply the changes as uninterrupting and atomic as possible
options:
  nat:
    description: |
      - Firewall ruleset for the nat section.
      - Each entry is a chain.
      - These builtin chains can have a policy: {", ".join(BUILTIN_CHAINS["nat"])}
      - Each chain has a list of rules.
      - The module will automatically number the rules in the order they are defined.
      - The rule content uses the exact same options (key and values) as the cli.
      - All applicable non-specified rule options are implicitly set to their default value.
      - By default a rule will be used in both IPv4 and IPv6. Use the custom {MARKER_IPV4} and {MARKER_IPV6} markers to change that.
      - Rules using source/destination IPs are by default only included in the ruleset for the ip version.
    type: dict
  firewall:
    description: |
      - Firewall ruleset for the firewall (filter) section.
      - Same basic structure as nat.
      - Policy is allowed for these chains: {", ".join(BUILTIN_CHAINS["firewall"])}
    type: dict
extends_documentation_fragment: action_common_attributes
attributes:
  check_mode:
    support: full
  diff_mode:
    support: full
  platform:
    platforms: nodegrid
"""

EXAMPLES = r"""
# Reset the firewall to factory default
- name: Reset firewall ruleset
  firewallv3:
    nat:
      PREROUTING:
        rules: []
        policy: ACCEPT
      INPUT:
        rules: []
        policy: ACCEPT
      OUTPUT:
        rules: []
        policy: ACCEPT
      POSTROUTING:
        rules: []
        policy: ACCEPT
    firewall:
      INPUT:
        rules:
          - input_interface: lo
            target: ACCEPT
        policy: ACCEPT
      FORWARD:
        rules: []
        policy: ACCEPT
      OUTPUT:
          rules:
            - output_interface: lo
              target: ACCEPT
          policy: ACCEPT

# Basic host firewall
- name: Update firewall ruleset
  firewallv3:
    nat:
      PREROUTING:
        rules: []
        policy: ACCEPT
      INPUT:
        rules: []
        policy: ACCEPT
      OUTPUT:
        rules: []
        policy: ACCEPT
      POSTROUTING:
        rules: []
        policy: ACCEPT
    firewall:
      INPUT:
        rules:
          - description: early_drop_of_invalid_connections
            enable_state_match: "yes"
            invalid: "yes"
            target: DROP
          - description: allow_tracked_connections
            enable_state_match: "yes"
            established: "yes"
            related: "yes"
            target: ACCEPT
          - description: allow_from_loopback
            input_interface: lo
            target: ACCEPT
          - description: allow_icmp
            _ipv4_only: true
            protocol: numeric
            protocol_number: 1
            target: ACCEPT
          - description: allow_icmpv6
            _ipv6_only: true
            protocol: numeric
            protocol_number: 58
            target: ACCEPT
          - description: allow_ssh
            protocol: tcp
            destination_port: 22
            target: ACCEPT
          - description: log_before_drop
            target: LOG
            log_level: info
            log_prefix: input_drop__
        policy: DROP
      FORWARD:
        rules: []
        policy: DROP
      OUTPUT:
        rules: []
        policy: ACCEPT
"""

RETURN = r"""
cmds:
    description: CLI commands that will/would be executed
    type: list
    elements: dict
    returned: always
    sample: |
      - cmd: add /settings/ipv4_firewall/chains/
      - cmd: set chain="MYCUSTOMCHAIN"
      - cmd: save
      - cmd: delete /settings/ipv4_firewall/chains/INPUT/ 11
      - cmd: set /settings/ipv4_firewall/chains/FORWARD/8/ input_interface="eth1" target="DROP"
      - cmd: set /settings/ipv6_firewall/policy/ OUTPUT="ACCEPT"
      - cmd: delete /settings/ipv6_firewall/chains/ MYOLDCHAIN
      - cmd: config_start
      - cmd: commit
      - cmd: shell sleep 5
      - cmd: config_confirm
cmd_results:
    description: Informative message for humans about the module result.
    type: list
    elements: dict
    returned: in non-check-Mode
    sample: |
      - command: add /settings/ipv4_firewall/chains/
        error: false
        json: []
        stdout: |-
          add /settings/ipv4_firewall/chains/
          [ansible@nodegrid {chains}
        stdout_lines:
        - "\aadd /settings/ipv4_firewall/chains/"
        - '[ansible@nodegrid {chains}'
      - command: set chain="MYCUSTOMCHAIN"
        error: false
        json: []
        stdout: |-
          set chain="MYCUSTOMCHAIN"
          [ansible@nodegrid {chains}
        stdout_lines:
        - set chain="MYCUSTOMCHAIN"
        - '[ansible@nodegrid {chains}'
      - command: save
        error: false
        json: []
        stdout: |-
          save
          [ansible@nodegrid /
        stdout_lines:
        - save
        - '[ansible@nodegrid /'
"""


@contextmanager
def cli():
    """CLI to execute commands."""
    resource = get_cli()  # TODO set timeout from module_params
    try:
        yield resource
    finally:
        close_cli(resource)


def validate_module_params(module_params: dict[str, Any]) -> None:
    """Validate the module parameters."""
    # can't use the argument_spec for this, because that does not support arbitrary dict key, like used here for the chains
    for section in SECTIONS:
        if section not in module_params:
            raise AnsibleModuleError(f"Missing section '{section}' in module params", obj=module_params)
        section_data = module_params[section]
        if type(section_data) != dict:
            raise AnsibleModuleError(f"Data of section '{section}' is not a dict", obj=module_params)

        for chain in BUILTIN_CHAINS[section]:
            if chain not in section_data:
                raise AnsibleModuleError(f"Builtin chain '{chain}' in section '{section}' is missing", obj=section_data)

        for chain, chain_data in section_data.items():
            if chain in BUILTIN_CHAINS[section]:
                if "policy" not in chain_data:
                    raise AnsibleModuleError(
                        f"Builtin chain '{chain}' in section '{section}' has no policy", obj=chain_data
                    )
                if chain_data["policy"] not in ("ACCEPT", "DROP"):
                    raise AnsibleModuleError(
                        f"Builtin chain '{chain}' in section '{section}' has invalid policy '{chain_data['policy']}'",
                        obj=chain_data,
                    )
            else:
                if "policy" in chain_data:
                    raise AnsibleModuleError(
                        f"Custom chain '{chain}' in section '{section}' has a policy", obj=chain_data
                    )

            if "rules" not in chain_data:
                raise AnsibleModuleError(
                    f"Field 'rules' in chain '{chain}' in section '{section}' does not exist", obj=chain_data
                )
            if type(chain_data["rules"]) != list:
                raise AnsibleModuleError(
                    f"Field 'rules' in chain '{chain}' in section '{section}' is not a list", obj=chain_data
                )
            for idx, rule_data in enumerate(chain_data["rules"]):
                if type(rule_data) != dict:
                    raise AnsibleModuleError(
                        f"Element {idx} in rule list of chain '{chain}' in section '{section}' is not a dict",
                        obj=rule_data,
                    )
                if MARKER_IPV4 in rule_data and MARKER_IPV6 in rule_data:
                    raise AnsibleModuleError(
                        f"Element {idx} in rule list of chain '{chain}' in section '{section}' has multiple _ipv?_only markers",
                        obj=rule_data,
                    )


def normalize_rule(
    rule: dict[str, Any], ip_version: int, section: str, chain: str, strict_validate: bool = False
) -> dict[str, Any]:
    """Normalize the given rule.

    If strict_validate is True, any found invalid key will cause an exception. If False, they will be silently dropped.
    """
    result = {}

    def update_result(default_values: dict[str, Any]) -> None:
        """Update the result from the input rule using the keys (and default values) of the given dict."""
        # first apply all default values
        result.update(default_values)
        # then overwrite from the input rule
        result.update({k: str(v) for k, v in rule.items() if k in default_values.keys()})

    update_result(
        {
            "description": "",
            "reverse_match_for_source_ip|mask": "no",
            "reverse_match_for_destination_ip|mask": "no",
            "enable_state_match": "no",
            "protocol": "numeric",
            "reverse_match_for_protocol": "no",
            "target": "ACCEPT",
        }
    )

    if chain in (CHAIN_PREROUTING, CHAIN_INPUT, CHAIN_FORWARD):
        update_result(
            {
                "source_mac_address": "",
                "reverse_match_for_source_mac_address": "no",
            }
        )
    if chain not in (CHAIN_OUTPUT, CHAIN_POSTROUTING):
        update_result(
            {
                "input_interface": "any",
                "reverse_match_for_input_interface": "no",
            }
        )
    if chain not in (CHAIN_PREROUTING, CHAIN_INPUT):
        update_result(
            {
                "output_interface": "any",
                "reverse_match_for_output_interface": "no",
            }
        )

    if ip_version == IPV4:
        update_result(
            {
                "source_net4": "",
                "destination_net4": "",
                "fragments": "all_packets_and_fragments",
            }
        )
    if ip_version == IPV6:
        update_result(
            {
                "source_net6": "",
                "destination_net6": "",
            }
        )
    if section == SECTION_NAT:
        update_result(
            {
                "to_source": "",
                "to_destination": "",
            }
        )

    if result["enable_state_match"] == "yes":
        update_result(
            {
                "new": "no",
                "established": "no",
                "related": "no",
                "invalid": "no",
                "reverse_state_match": "no",
            }
        )

    if result["protocol"] == "numeric":
        update_result(
            {
                "protocol_number": "",
            }
        )
    if result["protocol"] in ("tcp", "udp"):
        update_result(
            {
                "reverse_match_for_source_port": "no",
                "reverse_match_for_destination_port": "no",
            }
        )
    if result["protocol"] == "tcp":
        update_result(
            {
                "source_port": "",
                "destination_port": "",
                "tcp_flag_syn": "any",
                "tcp_flag_ack": "any",
                "tcp_flag_fin": "any",
                "tcp_flag_rst": "any",
                "tcp_flag_urg": "any",
                "tcp_flag_psh": "any",
                "reverse_match_for_tcp_flags": "no",
            }
        )
    if result["protocol"] == "udp":
        update_result(
            {
                "source_udp_port": "",
                "destination_udp_port": "",
            }
        )
    if result["protocol"] == "icmp":
        update_result(
            {
                "icmp_type": "destination_unreachable",
                "reverse_match_for_icmp_type": "no",
            }
        )
    if result["target"] == "LOG":
        update_result(
            {
                "log_level": "debug",
                "log_prefix": "",
                "log_tcp_sequence_numbers": "no",
                "log_options_from_the_tcp_packet_header": "no",
                "log_options_from_the_ip_packet_header": "no",
            }
        )
    if section == SECTION_FIREWALL and result["target"] == "REJECT":
        update_result(
            {
                "reject_with": {
                    IPV4: "port_unreacheable",
                    IPV6: "no_route",
                }[ip_version],
            }
        )

    invalid_keys = set(rule.keys()) - {MARKER_IPV4, MARKER_IPV6} - set(result.keys())
    if strict_validate and invalid_keys:
        raise AnsibleModuleError(
            f"rule {rule} contains invalid keys: {invalid_keys}",
            obj=rule,
        )

    return result


def get_current_section_state(ip_version: int, section: str) -> dict[str, dict]:
    """Get the current state of the given ip_version and section."""
    result = {}

    with cli() as cmd_cli:
        # Fetch all the chains, and their policy (if any)
        cmd = f"show /settings/ipv{ip_version}_{section}/chains/"
        cmd_result = execute_cmd(cmd_cli, {"cmd": cmd})
        if cmd_result["error"]:
            raise AnsibleModuleError(f"Command '{cmd}' failed: {cmd_result['error']}", obj=cmd_result)

        for entry in cmd_result["json"][0]["data"]:
            chain = entry["chain"]
            result[chain] = {}

            if chain in BUILTIN_CHAINS[section]:
                result[chain]["policy"] = entry["policy"]

            # Fetch all rules of the chain, mainly to get the rule count
            cmd = f"show /settings/ipv{ip_version}_{section}/chains/{chain}/"
            cmd_result = execute_cmd(cmd_cli, {"cmd": cmd})
            if cmd_result["error"]:
                raise AnsibleModuleError(f"Command '{cmd}' failed: {cmd_result['error']}", obj=cmd_result)

            rule_numbers = [int(entry["rules"]) for entry in cmd_result["json"][0]["data"]]
            rule_count = len(rule_numbers)
            if rule_numbers != list(range(rule_count)):
                # should never happen, but you never know ...
                raise AnsibleModuleError(
                    f"rule numbers are not a continuous sequence from 0 to {rule_count - 1}: {rule_numbers}",
                    obj=rule_numbers,
                )

            result[chain]["rules"] = [None] * rule_count
            for rule_number in sorted(rule_numbers):
                # Fetch the rule options
                cmd = f"show /settings/ipv{ip_version}_{section}/chains/{chain}/{rule_number}/"
                cmd_result = execute_cmd(cmd_cli, {"cmd": cmd})
                if cmd_result["error"]:
                    raise AnsibleModuleError(f"Command '{cmd}' failed: {cmd_result['error']}", obj=cmd_result)

                result[chain]["rules"][rule_number] = normalize_rule(
                    cmd_result["json"][0]["data"],
                    ip_version,
                    section,
                    chain,
                    False,
                )

    return result


def get_current_state() -> dict[str, dict]:
    """Get the current state of the firewall ruleset."""
    return {
        ip_version: {section: get_current_section_state(ip_version, section) for section in SECTIONS}
        for ip_version in IP_VERSIONS
    }


def get_desired_section_state(ip_version: int, section: str, module_params: dict[str, Any]) -> dict[str:dict]:
    """Get the desired state of the given ip_version and section."""
    result = {}
    for chain, chain_data in module_params.items():
        result[chain] = {}
        if "policy" in chain_data:
            result[chain]["policy"] = chain_data["policy"]
        result[chain]["rules"] = []
        for rule_data in chain_data["rules"]:
            if MARKER_IPV4 not in rule_data and MARKER_IPV6 not in rule_data:
                # auto-detect
                if any(key in rule_data for key in ("source_net4", "destination_net4")):
                    rule_data[MARKER_IPV4] = True
                elif any(key in rule_data for key in ("source_net6", "destination_net6")):
                    rule_data[MARKER_IPV6] = True
                elif rule_data.get("to_source"):
                    if 1 <= rule_data["to_source"].find(".") <= 3:
                        rule_data[MARKER_IPV4] = True
                    elif 0 <= rule_data["to_source"].find(":") <= 4:
                        rule_data[MARKER_IPV6] = True
                elif rule_data.get("to_destination"):
                    if 1 <= rule_data["to_destination"].find(".") <= 3:
                        rule_data[MARKER_IPV4] = True
                    elif 0 <= rule_data["to_destination"].find(":") <= 4:
                        rule_data[MARKER_IPV6] = True
            if (ip_version == IPV4 and MARKER_IPV6 in rule_data) or (ip_version == IPV6 and MARKER_IPV4 in rule_data):
                continue
            result[chain]["rules"].append(normalize_rule(rule_data, ip_version, section, chain, True))

    return result


def get_desired_state(module_params: dict[str, Any]) -> dict[str, dict]:
    """Get the desired (normalized) state of the firewall ruleset."""
    return {
        ip_version: {
            section: get_desired_section_state(ip_version, section, module_params[section]) for section in SECTIONS
        }
        for ip_version in IP_VERSIONS
    }


def get_cli_commands(current_state: dict[str, dict], desired_state: dict[str, dict]) -> list[dict[str, Any]]:
    """Get the cli commands required to go from the given current state to the given desired state."""
    result = []

    # step 1: create all new chains, and new rules as no-ops
    for ip_version, sections in desired_state.items():
        for section, chains in sections.items():
            for chain_name, chain_data in chains.items():
                current_chain = current_state[ip_version][section].get(chain_name, {})
                if not current_chain:
                    # add new chain
                    result.append(dict(cmd=f"add '/settings/ipv{ip_version}_{section}/chains/'"))
                    result.append(dict(cmd=f"set chain='{chain_name}'"))
                    result.append(dict(cmd="save"))

                current_rule_count = len(current_chain.get("rules", []))
                desired_rule_count = len(chain_data["rules"])
                for rule_number in range(current_rule_count, desired_rule_count):
                    # add new rule
                    result.append(dict(cmd=f"add '/settings/ipv{ip_version}_{section}/chains/{chain_name}/'"))
                    result.append(dict(cmd=f"set rule_number='{rule_number}' description='no-op' target='RETURN'"))
                    result.append(dict(cmd="save"))

    # step 2: update rule contents, and delete superfluous rules and chains
    for ip_version, sections in desired_state.items():
        for section, chains in sections.items():
            current_section = current_state[ip_version][section]
            for chain_name, chain_data in chains.items():
                current_chain = current_section.get(chain_name, {})
                if "policy" in chain_data and (
                    "policy" not in current_chain or chain_data["policy"] != current_chain["policy"]
                ):
                    # update chain policy
                    result.append(
                        dict(
                            cmd=f"set '/settings/ipv{ip_version}_{section}/policy/' {chain_name}='{chain_data['policy']}'"
                        )
                    )

                for rule_number, desired_rule in enumerate(chain_data["rules"]):
                    try:
                        current_rule = current_chain.get("rules", [])[rule_number]
                    except IndexError:
                        # imitate what the in step 1 created no-op rule looks like
                        current_rule = normalize_rule(
                            dict(target="RETURN", description="no-op"),
                            ip_version,
                            section,
                            chain_name,
                            True,
                        )

                    rule_update_data = {}
                    for key, value in desired_rule.items():
                        if key not in current_rule or current_rule[key] != value:
                            # update rule option
                            rule_update_data[key] = value
                    if desired_rule.get("enable_state_match") == "yes":
                        # quirk: at least one has to be yes at all times, so sort enable before disable by moving the no's to the end
                        for key in ("new", "established", "related", "invalid"):
                            if rule_update_data.get(key) == "no":
                                del rule_update_data[key]
                                rule_update_data[key] = "no"

                    if rule_update_data:
                        # update rule options
                        rule_assignments = " ".join(f"{k}='{v}'" for k, v in rule_update_data.items())
                        result.append(
                            dict(
                                cmd=f"set '/settings/ipv{ip_version}_{section}/chains/{chain_name}/{rule_number}/' {rule_assignments}"
                            )
                        )

                current_rule_count = len(current_chain.get("rules", []))
                desired_rule_count = len(chain_data["rules"])
                for rule_number in range(current_rule_count - 1, desired_rule_count - 1, -1):
                    # delete rule
                    result.append(
                        dict(cmd=f"delete '/settings/ipv{ip_version}_{section}/chains/{chain_name}/' '{rule_number}'")
                    )
            for current_chain in current_section.keys():
                if current_chain not in chains.keys():
                    # delete chain
                    result.append(dict(cmd=f"delete '/settings/ipv{ip_version}_{section}/chains/' '{current_chain}'"))
    if result:
        # this will apply all updates and deletes in one go
        result.append(dict(cmd="config_start"))
        result.append(dict(cmd="commit"))
        result.append(dict(cmd="shell sleep 5"))  # to make sure the new ruleset is fully active before confirmation
        result.append(dict(cmd="config_confirm"))

    return result


def execute_commands(cmds: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Execute the given list of commands, returning their result."""
    if not cmds:
        return []

    cmd_results = []
    with cli() as cmd_cli:
        for cmd in cmds:
            cmd_result = execute_cmd(cmd_cli, cmd)

            if "ignore_error" in cmd.keys():
                cmd_result["ignore_error"] = cmd["ignore_error"]
            cmd_result["command"] = cmd.get("cmd")
            cmd_results.append(cmd_result)

            if cmd_result["error"]:
                break
    return cmd_results


def run_module() -> None:
    """Run the module."""
    module = AnsibleModule(
        argument_spec=dict(
            nat=dict(type="dict", required=True),
            firewall=dict(type="dict", required=True),
        ),
        supports_check_mode=True,
    )

    result = dict(
        changed=False,
        failed=False,
    )

    try:
        validate_module_params(module.params)
    except AnsibleModuleError as e:
        module.fail_json(msg=e.message, **result)

    # Remove the SID from the env, so pexpect.run can start the cli multiple times.
    for var_name in ("DLITF_SID", "DLITF_SID_ENCRYPT"):
        if var_name in os.environ:
            del os.environ[var_name]

    #
    # Nodegrid OS section starts here
    #
    res, err_msg, nodegrid_os = check_os_version_support()
    if res == "error" or res == "unsupported":
        module.fail_json(msg=err_msg, **result)
    elif res == "warning":
        result["warning"] = err_msg

    # get the states
    try:
        current_state = get_current_state()
        desired_state = get_desired_state(module.params)
    except AnsibleModuleError as e:
        module.fail_json(msg=e.message, **result)

    result["diff"] = dict(
        before=yaml.safe_dump(current_state),
        after=yaml.safe_dump(desired_state),
    )

    # get the commands required
    cmds = get_cli_commands(current_state, desired_state)
    result["cmds"] = cmds

    if module.check_mode:
        result["changed"] = bool(cmds)
        module.exit_json(**result)

    # execute the commands
    cmd_results = execute_commands(cmds)
    result["cmd_results"] = cmd_results
    result["changed"] = any(
        cmd_result["command"] in ("commit", "save") and not cmd_result["error"] for cmd_result in cmd_results
    )

    # since execution is aborted after an error, only the last result needs to be checked
    if cmd_results and cmd_results[-1]["error"]:
        module.fail_json(msg=f"Command failed: {cmd_results[-1]['stdout']}", **result)

    module.exit_json(**result)


def main():
    """Main function."""
    run_module()


if __name__ == "__main__":
    main()
