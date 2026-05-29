#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2024, ZPE Systems <zpesystems.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r'''
---
module: nodegrid_elasticsearch_report_load
version_added: "1.0.0"
author:
  - ZPE Systems
short_description: Load device inventory records into a report index in OpenSearch
description:
  - Consumes successful device output from C(nodegrid_elasticsearch_inventory).
  - Creates a target report index when it does not exist.
  - Bulk upserts records and can stamp per-row lifecycle timestamps for created/changed/synced tracking.
  - Uses the same certificate-based HTTPS connection pattern as other Nodegrid OpenSearch modules.
notes:
  - SSL hostname verification is always disabled due to dynamic certificate generation on Nodegrid appliances.
    The C(verify_ssl) option controls CA chain validation only.
  - This module is a role-local library module. It must be invoked by its short name
    (C(nodegrid_elasticsearch_report_load)) when used within the C(nodegrid_elasticsearch_inventory) role.
  - The C(auto_increase_shard_limit) module default is C(false). The C(nodegrid_elasticsearch_inventory)
    role overrides this to C(true) via its role defaults. Override C(nodegrid_report_auto_increase_shard_limit)
    in your playbook to change this behavior.
  - When C(protect_index=true), the module creates a high-priority index template to ensure future
    index recreations inherit the correct mapping and ISM policy, preventing auto-deletion by wildcard templates.
  - The module requires cluster-level privileges when C(auto_increase_shard_limit=true) to update
    C(cluster.max_shards_per_node).
options:
  es_host:
    description:
      - OpenSearch host to connect to.
    type: str
    default: localhost
  es_port:
    description:
      - OpenSearch port to connect to.
    type: int
    default: 9200
  es_timeout:
    description:
      - Timeout in seconds for OpenSearch requests.
    type: int
    default: 30
  target_index:
    description:
      - Name of the report index to create/use.
    type: str
    default: nodegrid_device_report
  id_field:
    description:
      - Preferred field used as document ID.
      - If not present in a record, fallback IDs are generated automatically.
    type: str
    default: uuid
  batch_size:
    description:
      - Number of rows sent per C(_bulk) request.
      - Use 500 to 2000 for large datasets.
    type: int
    default: 1000
  refresh_index:
    description:
      - Refresh target index after loading data.
      - Keep false for better throughput on large loads.
    type: bool
    default: false
  check_shard_capacity:
    description:
      - Check free shard capacity before attempting index creation.
      - Prevents avoidable index-create failures when shard limits are reached.
    type: bool
    default: true
  auto_increase_shard_limit:
    description:
      - Automatically increase C(cluster.max_shards_per_node) when capacity is insufficient.
      - Requires cluster privileges to update cluster settings.
    type: bool
    default: false
  shard_limit_increment:
    description:
      - Minimum increment applied to C(cluster.max_shards_per_node) when auto-increase is enabled.
    type: int
    default: 100
  shard_limit_hard_cap:
    description:
      - Hard cap for C(cluster.max_shards_per_node) when auto-increase is enabled.
      - Automatic updates never exceed this value.
    type: int
    default: 1200
  purge_before_load:
    description:
      - Delete the existing target index before loading new records.
      - Keeps default behavior unchanged when false (incremental upsert).
    type: bool
    default: false
  merge_duplicates:
    description:
      - Merge duplicate rows before loading when C(uuid)+C(name) match.
      - Useful when source indices contain multiple versions of the same device row.
    type: bool
    default: true
  add_row_timestamps:
    description:
      - Add per-row lifecycle metadata.
      - Creates C(created_timestamp_field) once, updates C(updated_timestamp_field) only when
        row content changes, and updates C(synced_timestamp_field) on every sync.
    type: bool
    default: true
  created_timestamp_field:
    description:
      - Field name written once when a row is first created.
    type: str
    default: report_created_at
  updated_timestamp_field:
    description:
      - Field name updated when a row changes.
    type: str
    default: report_updated_at
  synced_timestamp_field:
    description:
      - Field name updated on every synchronization run.
    type: str
    default: report_synced_at
  protect_index:
    description:
      - Ensure a high-priority index template and an ISM keep policy are present for the target report index.
      - Helps prevent wildcard lifecycle jobs or lower-priority templates from deleting or rotating the report index.
    type: bool
    default: true
  policy_id:
    description:
      - ISM policy ID used when C(protect_index=true).
      - The same policy ID is applied in the index template and attached directly to the target index.
    type: str
    default: nodegrid_report_keep_forever
  inventory_result:
    description:
      - Full output dictionary from C(nodegrid_elasticsearch_inventory).
      - If C(devices) is empty, rows are taken from C(inventory_result.device_data.devices).
    type: dict
    default: {}
  devices:
    description:
      - Device rows to load.
      - Typically C(inventory_result.device_data.devices) from the inventory module.
    type: list
    elements: dict
    default: []
  ca_cert:
    description:
      - Path to CA certificate for SSL verification.
    type: str
    default: /etc/opensearch/config/root-ca.pem
  client_cert:
    description:
      - Path to client certificate for authentication.
    type: str
    default: /etc/opensearch/config/admin.pem
  client_key:
    description:
      - Path to client private key for authentication.
    type: str
    default: /etc/opensearch/config/admin-key.pem
  verify_ssl:
    description:
      - Whether to verify SSL CA certificate chain.
      - Kept for compatibility with the existing module interface.
      - Hostname verification remains disabled in this implementation.
    type: bool
    default: false
requirements:
  - requests
  - python >= 3.6
'''

EXAMPLES = r'''
- name: Load inventory module output into a report index
  nodegrid_elasticsearch_report_load:
    inventory_result: "{{ inventory_result }}"

- name: Load explicit device rows into a custom report index
  nodegrid_elasticsearch_report_load:
    target_index: nodegrid_device_report
    devices: "{{ inventory_result.device_data.devices }}"
    batch_size: 1000
    id_field: uuid

- name: Load and refresh index for immediate search visibility
  nodegrid_elasticsearch_report_load:
    devices: "{{ inventory_result.device_data.devices }}"
    refresh_index: true

- name: Keep per-row created/updated timestamps
  nodegrid_elasticsearch_report_load:
    devices: "{{ inventory_result.device_data.devices }}"
    add_row_timestamps: true
    created_timestamp_field: report_created_at
    updated_timestamp_field: report_updated_at
    synced_timestamp_field: report_synced_at

- name: Protect the report index from external retention rules
  nodegrid_elasticsearch_report_load:
    devices: "{{ inventory_result.device_data.devices }}"
    protect_index: true
    policy_id: nodegrid_report_keep_forever

- name: Load with shard auto-increase and hard cap safeguard
  nodegrid_elasticsearch_report_load:
    devices: "{{ inventory_result.device_data.devices }}"
    check_shard_capacity: true
    auto_increase_shard_limit: true
    shard_limit_increment: 100
    shard_limit_hard_cap: 1200
'''

RETURN = r'''
target_index:
  description: The report index used for writes.
  type: str
  returned: always
index_created:
  description: Whether the target index was created by this run.
  type: bool
  returned: always
input_records:
  description: Number of records provided as input.
  type: int
  returned: always
processed:
  description: Number of records processed by bulk requests.
  type: int
  returned: always
created:
  description: Number of newly created documents.
  type: int
  returned: always
updated:
  description: Number of updated documents returned by bulk upsert.
  type: int
  returned: always
noop:
  description: Number of rows skipped by OpenSearch as unchanged.
  type: int
  returned: always
failed:
  description: Number of rows that failed in bulk operations.
  type: int
  returned: always
error_details:
  description: Limited list of per-row bulk errors.
  type: list
  returned: always
shard_open:
  description: Current number of open shards in the cluster (when checked).
  type: int
  returned: always
shard_available:
  description: Available shard slots before reaching the cluster limit (when checked).
  type: int
  returned: always
max_shards_per_node:
  description: Effective cluster.max_shards_per_node value (when checked).
  type: int
  returned: always
shard_limit_changed:
  description: Whether the module changed cluster.max_shards_per_node during this run.
  type: bool
  returned: always
shard_increase_attempted:
  description: Whether this run attempted to increase cluster.max_shards_per_node.
  type: bool
  returned: always
shard_increase_target:
  description: Target cluster.max_shards_per_node computed by the module.
  type: int
  returned: always
shard_increase_error:
  description: Error details from shard-limit increase attempt (if any).
  type: str
  returned: always
shard_retry_after_create_failure:
  description: Whether the module retried index creation after shard-limit failure.
  type: bool
  returned: always
shard_retry_create_error:
  description: Error from retrying index creation after shard auto-increase.
  type: str
  returned: always
index_purged:
  description: Whether the existing target index was deleted before load.
  type: bool
  returned: always
deduplicated_records:
  description: Number of records after duplicate merge.
  type: int
  returned: always
duplicates_merged:
  description: Number of duplicate rows merged into existing records.
  type: int
  returned: always
duplicate_conflicts:
  description: Number of conflicting fields encountered while merging duplicates.
  type: int
  returned: always
index_template_changed:
  description: Whether the module created the high-priority index template for the report index.
  type: bool
  returned: always
policy_created:
  description: Whether the module created the keep-forever ISM policy during this run.
  type: bool
  returned: always
policy_attachment_changed:
  description: Whether the module attached or re-attached the ISM policy to the target index during this run.
  type: bool
  returned: always
'''

import hashlib
import json
import math
import os
from datetime import datetime, timezone
from ansible.module_utils.basic import AnsibleModule

try:
    import requests
except ImportError:
    requests = None


def _build_base_url(host, port):
    return "https://{0}:{1}".format(host, port)


def check_opensearch(host, port, timeout, ca_cert, client_cert, client_key, verify_ssl=False):
    if not os.path.exists(ca_cert):
        raise Exception("CA certificate not found: {0}".format(ca_cert))
    if not os.path.exists(client_cert):
        raise Exception("Client certificate not found: {0}".format(client_cert))
    if not os.path.exists(client_key):
        raise Exception("Client key not found: {0}".format(client_key))
    try:
        response = requests.get(
            _build_base_url(host, port),
            cert=(client_cert, client_key),
            verify=verify_ssl,
            timeout=timeout
        )
        if response.status_code == 200:
            return True
        raise Exception("Check OpenSearch returned HTTPS status {0}".format(response.status_code))
    except (requests.exceptions.RequestException, Exception) as e:
        raise Exception(f"Check OpenSearch HTTPS GET request error: {e}")


def index_exists(host, port, timeout, index_name, ca_cert, client_cert, client_key, verify_ssl=False):
    index_url = "{0}/{1}".format(_build_base_url(host, port), index_name)
    try:
        response = requests.head(
            index_url,
            cert=(client_cert, client_key),
            verify=verify_ssl,
            timeout=timeout
        )
        if response.status_code == 200:
            return True
        if response.status_code == 404:
            return False
        raise Exception("Failed checking index '{0}'. HTTPS status code: {1}, response: {2} ".format(index_name, response.status_code, response.text))
    except (requests.exceptions.RequestException, Exception):
        raise


def delete_index_if_exists(host, port, timeout, index_name, ca_cert, client_cert, client_key, verify_ssl=False):
    index_url = "{0}/{1}".format(_build_base_url(host, port), index_name)
    try:
        head_response = requests.head(
            index_url,
            cert=(client_cert, client_key),
            verify=verify_ssl,
            timeout=timeout
        )
        if head_response.status_code == 404:
            return False
        if head_response.status_code != 200:
            raise Exception("Failed checking index '{0}' before purge. HTTPS head code: {1}. Error: {2}".format(index_name, head_response.status_code, head_response.text))

        delete_response = requests.delete(
            index_url,
            cert=(client_cert, client_key),
            verify=verify_ssl,
            timeout=timeout
        )
        if delete_response.status_code in (200, 202):
            return True
        raise Exception("Failed deleting index '{0}': HTTPS status code {1} body={2}".format(index_name, delete_response.status_code, delete_response.text))
    except (requests.exceptions.RequestException, Exception):
        raise


def _to_int(value, default):
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def get_shard_capacity(host, port, timeout, ca_cert, client_cert, client_key, verify_ssl=False):
    """Return shard usage/capacity based on cluster stats and settings."""
    base_url = _build_base_url(host, port)
    stats_url = "{0}/_cluster/stats".format(base_url)
    health_url = "{0}/_cluster/health".format(base_url)
    settings_url = "{0}/_cluster/settings?include_defaults=true&flat_settings=true".format(base_url)

    try:
        stats_response = requests.get(
            stats_url,
            cert=(client_cert, client_key),
            verify=verify_ssl,
            timeout=timeout
        )
        stats_response.raise_for_status()
        stats = stats_response.json()

        health_response = requests.get(
            health_url,
            cert=(client_cert, client_key),
            verify=verify_ssl,
            timeout=timeout
        )
        health_response.raise_for_status()
        health = health_response.json()

        settings_response = requests.get(
            settings_url,
            cert=(client_cert, client_key),
            verify=verify_ssl,
            timeout=timeout
        )
        settings_response.raise_for_status()
        settings = settings_response.json()
    except (requests.exceptions.RequestException, Exception) as exc:
        return None, str(exc)

    stats_open_shards = _to_int(stats.get("indices", {}).get("shards", {}).get("total"), 0)
    health_active_shards = _to_int(health.get("active_shards"), 0)
    # Use the larger value to avoid undercounting when APIs report different shard totals.
    open_shards = max(stats_open_shards, health_active_shards)
    data_nodes = _to_int(stats.get("nodes", {}).get("count", {}).get("data"), 1)
    data_nodes = max(1, data_nodes)

    transient = settings.get("transient", {})
    persistent = settings.get("persistent", {})
    defaults = settings.get("defaults", {})
    max_shards_per_node = (
        transient.get("cluster.max_shards_per_node")
        or persistent.get("cluster.max_shards_per_node")
        or defaults.get("cluster.max_shards_per_node")
        or 1000
    )
    max_shards_per_node = _to_int(max_shards_per_node, 1000)

    max_open_shards = max_shards_per_node * data_nodes
    available_shards = max_open_shards - open_shards

    return {
        "open_shards": open_shards,
        "stats_open_shards": stats_open_shards,
        "health_active_shards": health_active_shards,
        "data_nodes": data_nodes,
        "max_shards_per_node": max_shards_per_node,
        "max_open_shards": max_open_shards,
        "available_shards": available_shards
    }, None


def is_shard_limit_error(error_text):
    if not error_text:
        return False
    needle = "maximum shards open"
    return needle in str(error_text).lower()


def is_resource_already_exists_error(error_text):
    if not error_text:
        return False
    return "resource_already_exists_exception" in str(error_text).lower()


# ---------------------------------------------------------------------------
# ISM policy and index template helpers (protect index from auto-deletion)
# ---------------------------------------------------------------------------

_DEFAULT_KEEP_FOREVER_POLICY_ID = "nodegrid_report_keep_forever"

_KEEP_FOREVER_POLICY_BODY = {
    "policy": {
        "description": "Keep nodegrid device report index indefinitely - no rotation or deletion",
        "default_state": "keep",
        "states": [
            {
                "name": "keep",
                "actions": [],
                "transitions": []
            }
        ],
        "ism_template": []
    }
}


def _timestamp_mapping_properties(created_timestamp_field, updated_timestamp_field, synced_timestamp_field):
    return {
        created_timestamp_field: {"type": "date"},
        updated_timestamp_field: {"type": "date"},
        synced_timestamp_field: {"type": "date"},
        "coordinates_geo": {"type": "geo_point"}
    }


def ensure_ism_keep_policy(host, port, timeout, ca_cert, client_cert, client_key, verify_ssl, policy_id=_DEFAULT_KEEP_FOREVER_POLICY_ID):
    """Create the keep-forever ISM policy if it does not already exist."""
    base_url = _build_base_url(host, port)
    policy_url = "{0}/_plugins/_ism/policies/{1}".format(base_url, policy_id)
    try:
        head_resp = requests.get(
            policy_url,
            cert=(client_cert, client_key),
            verify=verify_ssl,
            timeout=timeout
        )
        if head_resp.status_code == 200:
            return False, None

        put_resp = requests.put(
            policy_url,
            json=_KEEP_FOREVER_POLICY_BODY,
            cert=(client_cert, client_key),
            verify=verify_ssl,
            timeout=timeout
        )
        if put_resp.status_code in (200, 201):
            return True, None
        return False, "Failed creating ISM policy '{0}': HTTP {1} body={2}".format(
            policy_id, put_resp.status_code, put_resp.text
        )
    except (requests.exceptions.RequestException, Exception) as exc:
        return False, str(exc)


def attach_ism_policy_to_index(host, port, timeout, index_name, ca_cert, client_cert, client_key, verify_ssl=False, policy_id=_DEFAULT_KEEP_FOREVER_POLICY_ID):
    """Attach the keep-forever ISM policy to an index if not already managed."""
    base_url = _build_base_url(host, port)

    explain_url = "{0}/_plugins/_ism/explain/{1}".format(base_url, index_name)
    try:
        explain_resp = requests.get(
            explain_url,
            cert=(client_cert, client_key),
            verify=verify_ssl,
            timeout=timeout
        )
        if explain_resp.status_code == 200:
            explain_body = explain_resp.json()
            index_info = explain_body.get(index_name, {})
            existing_policy = (
                index_info.get("index.plugins.index_state_management.policy_id")
                or index_info.get("attached_policy_id")
            )
            if existing_policy:
                if existing_policy == policy_id:
                    return False, None
                # Detach current policy first so we can attach ours
                remove_url = "{0}/_plugins/_ism/remove/{1}".format(base_url, index_name)
                requests.post(
                    remove_url,
                    cert=(client_cert, client_key),
                    verify=verify_ssl,
                    timeout=timeout
                )
    except requests.exceptions.RequestException:
        pass
    except Exception as e:
        return False, str(e)

    add_url = "{0}/_plugins/_ism/add/{1}".format(base_url, index_name)
    try:
        add_resp = requests.post(
            add_url,
            json={"policy_id": policy_id},
            cert=(client_cert, client_key),
            verify=verify_ssl,
            timeout=timeout
        )
        if add_resp.status_code in (200, 201):
            return True, None
        return False, "Failed attaching ISM policy to '{0}': HTTP {1} body={2}".format(
            index_name, add_resp.status_code, add_resp.text
        )
    except (requests.exceptions.RequestException, Exception) as exc:
        return False, str(exc)


def ensure_index_template(host,    port, timeout, index_name, ca_cert, client_cert, client_key, verify_ssl=False, policy_id=_DEFAULT_KEEP_FOREVER_POLICY_ID, created_timestamp_field="report_created_at", updated_timestamp_field="report_updated_at", synced_timestamp_field="report_synced_at"):
    """Create/update a high-priority index template for the report index.

    This ensures future recreations inherit the correct mapping AND the
    keep-forever ISM policy automatically, preventing auto-deletion by
    wildcard templates with lower priority.
    """
    base_url = _build_base_url(host, port)
    template_name = "{0}_template".format(index_name)
    template_url = "{0}/_index_template/{1}".format(base_url, template_name)

    expected_body = {
        "index_patterns": [index_name],
        "priority": 500,
        "template": {
            "settings": {
                "number_of_shards": 1,
                "number_of_replicas": 0,
                "plugins.index_state_management.policy_id": policy_id
            },
            "mappings": {
                "dynamic": True,
                "properties": _timestamp_mapping_properties(
                    created_timestamp_field,
                    updated_timestamp_field,
                    synced_timestamp_field
                )
            }
        }
    }

    try:
        get_resp = requests.get(
            template_url,
            cert=(client_cert, client_key),
            verify=verify_ssl,
            timeout=timeout
        )
        if get_resp.status_code == 200:
            return False, None

        put_resp = requests.put(
            template_url,
            json=expected_body,
            cert=(client_cert, client_key),
            verify=verify_ssl,
            timeout=timeout
        )
        if put_resp.status_code in (200, 201):
            return True, None
        return False, "Failed creating index template '{0}': HTTP {1} body={2}".format(
            template_name, put_resp.status_code, put_resp.text
        )
    except (requests.exceptions.RequestException, Exception) as exc:
        return False, str(exc)


def get_index_mapping(host, port, timeout, index_name, ca_cert, client_cert, client_key, verify_ssl=False):
    index_url = "{0}/{1}/_mapping".format(_build_base_url(host, port), index_name)
    try:
        response = requests.get(
            index_url,
            cert=(client_cert, client_key),
            verify=verify_ssl,
            timeout=timeout
        )
        response.raise_for_status()
        return response.json(), None
    except (requests.exceptions.RequestException, Exception) as exc:
        return None, str(exc)


def _resolve_mapping_field_type(properties, field_name):
    if not isinstance(properties, dict):
        return None
    if field_name in properties and isinstance(properties.get(field_name), dict):
        return properties.get(field_name, {}).get("type")
    if "." not in field_name:
        return None
    current = properties
    parts = field_name.split(".")
    for idx, part in enumerate(parts):
        field_meta = current.get(part)
        if not isinstance(field_meta, dict):
            return None
        if idx == len(parts) - 1:
            return field_meta.get("type")
        current = field_meta.get("properties", {})
    return None


def get_index_field_type(host, port, timeout, index_name, field_name, ca_cert, client_cert, client_key, verify_ssl):
    mapping, err = get_index_mapping(host, port, timeout, index_name, ca_cert, client_cert, client_key, verify_ssl)
    if err:
        return None, err
    index_mapping = mapping.get(index_name, {})
    properties = index_mapping.get("mappings", {}).get("properties", {})
    return _resolve_mapping_field_type(properties, field_name), None


def ensure_geo_point_field_mapping(host, port, timeout, index_name, field_name, ca_cert, client_cert, client_key, verify_ssl=False):
    field_type, err = get_index_field_type(
        host,
        port,
        timeout,
        index_name,
        field_name,
        ca_cert,
        client_cert,
        client_key,
        verify_ssl
    )
    if err:
        return False, err
    if field_type == "geo_point":
        return False, None
    if field_type is not None:
        return False, (
            "Index '{0}' has incompatible mapping for field '{1}' (found '{2}'). "
            "Field types cannot be changed in place. Delete/recreate the report index or load into a new target index."
        ).format(index_name, field_name, field_type)

    url = "{0}/{1}/_mapping".format(_build_base_url(host, port), index_name)
    body = {
        "properties": {
            field_name: {"type": "geo_point"}
        }
    }
    try:
        response = requests.put(
            url,
            json=body,
            cert=(client_cert, client_key),
            verify=verify_ssl,
            timeout=timeout
        )
        if response.status_code in (200, 201):
            return True, None
        return False, "Failed updating mapping for index '{0}' field '{1}': HTTP {2} body={3}".format(
            index_name, field_name, response.status_code, response.text
        )
    except (requests.exceptions.RequestException, Exception) as exc:
        return False, str(exc)


def set_cluster_max_shards_per_node(host, port, timeout, new_limit, ca_cert, client_cert, client_key, verify_ssl=False):
    url = "{0}/_cluster/settings".format(_build_base_url(host, port))
    body = {"persistent": {"cluster.max_shards_per_node": int(new_limit)}}
    try:
        response = requests.put(
            url,
            json=body,
            cert=(client_cert, client_key),
            verify=verify_ssl,
            timeout=timeout
        )
        if response.status_code in (200, 201):
            return None, {
                "status_code": response.status_code,
                "response": (response.text or "")[:512]
            }
        return "Failed updating cluster.max_shards_per_node to {0}: HTTP {1} body={2}".format(
            new_limit, response.status_code, response.text
        ), {
            "status_code": response.status_code,
            "response": (response.text or "")[:512]
        }
    except (requests.exceptions.RequestException, Exception) as exc:
        return str(exc), {"status_code": None, "response": str(exc)[:512]}


def ensure_shard_capacity_for_index_create_with_debug(
    host,
    port,
    timeout,
    required_shards,
    auto_increase_limit,
    shard_limit_increment,
    shard_limit_hard_cap,
    ca_cert,
    client_cert,
    client_key,
    verify_ssl=False,
    force_increase_attempt=False
):
    debug_info = {
        "shard_increase_attempted": False,
        "shard_increase_target": None,
        "shard_increase_error": None
    }

    capacity, cap_err = get_shard_capacity(host, port, timeout, ca_cert, client_cert, client_key, verify_ssl)
    if cap_err:
        debug_info["shard_increase_error"] = cap_err
        return None, cap_err, debug_info

    if capacity["available_shards"] >= required_shards and not force_increase_attempt:
        capacity["shard_limit_changed"] = False
        return capacity, None, debug_info

    if not auto_increase_limit:
        err_msg = (
            "Insufficient shard capacity to create index. "
            "open_shards={0}, max_open_shards={1}, available_shards={2}, required_shards={3}. "
            "Increase cluster.max_shards_per_node or set auto_increase_shard_limit=true."
        ).format(
            capacity["open_shards"],
            capacity["max_open_shards"],
            capacity["available_shards"],
            required_shards
        )
        debug_info["shard_increase_error"] = err_msg
        return None, err_msg, debug_info

    required_total_open = capacity["open_shards"] + required_shards
    required_per_node = int(math.ceil(float(required_total_open) / float(capacity["data_nodes"])))
    target_limit = max(capacity["max_shards_per_node"] + shard_limit_increment, required_per_node)
    target_limit = min(target_limit, shard_limit_hard_cap)
    debug_info["shard_increase_target"] = target_limit

    if target_limit <= capacity["max_shards_per_node"]:
        err_msg = (
            "Insufficient shard capacity and hard cap prevents auto-increase. "
            "current_max_shards_per_node={0}, hard_cap={1}, required_per_node={2}."
        ).format(
            capacity["max_shards_per_node"],
            shard_limit_hard_cap,
            required_per_node
        )
        debug_info["shard_increase_error"] = err_msg
        return None, err_msg, debug_info

    debug_info["shard_increase_attempted"] = True

    update_err, update_meta = set_cluster_max_shards_per_node(
        host,
        port,
        timeout,
        target_limit,
        ca_cert,
        client_cert,
        client_key,
        verify_ssl
    )
    if update_meta and update_meta.get("response"):
        debug_info["shard_increase_error"] = update_meta.get("response")
    if update_err:
        debug_info["shard_increase_error"] = update_err
        return None, update_err, debug_info

    updated_capacity, updated_err = get_shard_capacity(host, port, timeout, ca_cert, client_cert, client_key, verify_ssl)
    if updated_err:
        debug_info["shard_increase_error"] = updated_err
        return None, updated_err, debug_info

    if updated_capacity["available_shards"] < required_shards:
        err_msg = (
            "Shard limit update completed but capacity is still insufficient. "
            "open_shards={0}, max_open_shards={1}, available_shards={2}, required_shards={3}, hard_cap={4}."
        ).format(
            updated_capacity["open_shards"],
            updated_capacity["max_open_shards"],
            updated_capacity["available_shards"],
            required_shards,
            shard_limit_hard_cap
        )
        debug_info["shard_increase_error"] = err_msg
        return None, err_msg, debug_info

    updated_capacity["shard_limit_changed"] = True
    updated_capacity["new_max_shards_per_node"] = target_limit
    debug_info["shard_increase_error"] = None
    return updated_capacity, None, debug_info


def ensure_shard_capacity_for_index_create(
    host,
    port,
    timeout,
    required_shards,
    auto_increase_limit,
    shard_limit_increment,
    shard_limit_hard_cap,
    ca_cert,
    client_cert,
    client_key,
    verify_ssl
):
    """Backward-compatible wrapper used by tests and external callers."""
    capacity, err, _debug = ensure_shard_capacity_for_index_create_with_debug(
        host,
        port,
        timeout,
        required_shards,
        auto_increase_limit,
        shard_limit_increment,
        shard_limit_hard_cap,
        ca_cert,
        client_cert,
        client_key,
        verify_ssl,
        force_increase_attempt=False
    )
    return capacity, err


def ensure_index_exists(host, port, timeout, index_name, ca_cert, client_cert, client_key, verify_ssl=False, created_timestamp_field="report_created_at", updated_timestamp_field="report_updated_at", synced_timestamp_field="report_synced_at"):
    index_url = "{0}/{1}".format(_build_base_url(host, port), index_name)
    try:
        head_resp = requests.head(
            index_url,
            cert=(client_cert, client_key),
            verify=verify_ssl,
            timeout=timeout
        )

        if head_resp.status_code == 200:
            return False, None
        if head_resp.status_code not in (404,):
            return None, "Failed checking index '{0}': HTTP {1}".format(index_name, head_resp.status_code)

        body = {
            "settings": {
                "index": {
                    "number_of_shards": 1,
                    "number_of_replicas": 0
                }
            },
            "mappings": {
                "dynamic": True,
                "properties": _timestamp_mapping_properties(
                    created_timestamp_field,
                    updated_timestamp_field,
                    synced_timestamp_field
                )
            }
        }
        put_resp = requests.put(
            index_url,
            json=body,
            cert=(client_cert, client_key),
            verify=verify_ssl,
            timeout=timeout
        )
        if put_resp.status_code in (200, 201):
            return True, None
        if put_resp.status_code in (400, 409) and is_resource_already_exists_error(put_resp.text):
            return False, None
        return None, "Failed creating index '{0}': HTTP {1} body={2}".format(index_name, put_resp.status_code, put_resp.text)
    except (requests.exceptions.RequestException, Exception) as exc:
        return None, str(exc)


def generate_document_id(record, id_field):
    if id_field and record.get(id_field):
        base_id = str(record.get(id_field))

        # Avoid collisions when id_field is host-level (for example uuid on Nodegrid data).
        if id_field == "uuid":
            name = record.get("name") or record.get("Name") or record.get("hostname")
            if name:
                return "{0}::{1}".format(base_id, name)
            host = record.get("ngfqdn") or record.get("nodegridhost") or record.get("Nodegrid Host")
            if host:
                return "{0}::{1}".format(base_id, host)

        return base_id

    if record.get("uuid"):
        return str(record.get("uuid"))
    if record.get("id"):
        return str(record.get("id"))

    name = record.get("name") or record.get("Name") or record.get("hostname")
    host = record.get("ngfqdn") or record.get("nodegridhost") or record.get("Nodegrid Host")
    if name and host:
        return "{0}::{1}".format(name, host)
    if name:
        return str(name)

    canonical = json.dumps(record, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha1(canonical.encode("utf-8")).hexdigest()


def _build_scripted_upsert_source():
    # Track created/changed/synced timestamps in one scripted upsert.
    return (
        "boolean changed = false;"
        "for (entry in params.doc.entrySet()) {"
        "def k = entry.getKey();"
        "def v = entry.getValue();"
        "if (!ctx._source.containsKey(k) || ctx._source[k] != v) {"
        "ctx._source[k] = v;"
        "changed = true;"
        "}"
        "}"
        "if (!ctx._source.containsKey(params.created_field)) {"
        "ctx._source[params.created_field] = params.ts;"
        "changed = true;"
        "}"
        "if (changed) {"
        "ctx._source[params.updated_field] = params.ts;"
        "}"
        "ctx._source[params.synced_field] = params.ts;"
    )


def build_bulk_payload(records, index_name, id_field, add_row_timestamps=False, created_timestamp_field="report_created_at", updated_timestamp_field="report_updated_at", synced_timestamp_field="report_synced_at", timestamp_value=None):
    lines = []
    script_source = _build_scripted_upsert_source() if add_row_timestamps else None
    for record in records:
        doc_id = generate_document_id(record, id_field)
        lines.append(json.dumps({"update": {"_index": index_name, "_id": doc_id}}))
        if add_row_timestamps:
            lines.append(json.dumps({
                "scripted_upsert": True,
                "script": {
                    "lang": "painless",
                    "source": script_source,
                    "params": {
                        "doc": record,
                        "ts": timestamp_value,
                        "created_field": created_timestamp_field,
                        "updated_field": updated_timestamp_field,
                        "synced_field": synced_timestamp_field
                    }
                },
                "upsert": {}
            }))
        else:
            lines.append(json.dumps({"doc": record, "doc_as_upsert": True, "detect_noop": True}))
    return "\n".join(lines) + "\n"


def iter_batches(items, batch_size):
    for idx in range(0, len(items), batch_size):
        yield items[idx:idx + batch_size]


def parse_bulk_response(response_json, max_error_details=100):
    result = {
        "processed": 0,
        "created": 0,
        "updated": 0,
        "noop": 0,
        "failed": 0,
        "error_details": []
    }

    for item in response_json.get("items", []):
        entry = item.get("update", {})
        result["processed"] += 1

        status = int(entry.get("status", 500))
        op_result = entry.get("result", "")
        if 200 <= status < 300:
            if op_result == "created":
                result["created"] += 1
            elif op_result == "updated":
                result["updated"] += 1
            elif op_result == "noop":
                result["noop"] += 1
            else:
                result["updated"] += 1
            continue

        result["failed"] += 1
        if len(result["error_details"]) < max_error_details:
            result["error_details"].append({
                "id": entry.get("_id"),
                "status": status,
                "error": entry.get("error", "unknown error")
            })

    return result


def bulk_upsert_devices(host, port, timeout, index_name, records, batch_size, id_field, ca_cert, client_cert, client_key, verify_ssl=False, add_row_timestamps=False, created_timestamp_field="report_created_at", updated_timestamp_field="report_updated_at", synced_timestamp_field="report_synced_at"):
    summary = {
        "processed": 0,
        "created": 0,
        "updated": 0,
        "noop": 0,
        "failed": 0,
        "error_details": []
    }

    bulk_url = "{0}/_bulk".format(_build_base_url(host, port))
    headers = {"Content-Type": "application/x-ndjson"}

    try:
        run_timestamp = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
        for batch in iter_batches(records, batch_size):
            payload = build_bulk_payload(
                batch,
                index_name,
                id_field,
                add_row_timestamps=add_row_timestamps,
                created_timestamp_field=created_timestamp_field,
                updated_timestamp_field=updated_timestamp_field,
                synced_timestamp_field=synced_timestamp_field,
                timestamp_value=run_timestamp
            )
            response = requests.post(
                bulk_url,
                data=payload,
                headers=headers,
                cert=(client_cert, client_key),
                verify=verify_ssl,
                timeout=timeout
            )
            response.raise_for_status()
            chunk_result = parse_bulk_response(response.json())

            for key in ("processed", "created", "updated", "noop", "failed"):
                summary[key] += chunk_result[key]

            remaining = max(0, 100 - len(summary["error_details"]))
            if remaining > 0:
                summary["error_details"].extend(chunk_result["error_details"][:remaining])

        return summary, None
    except (requests.exceptions.RequestException, Exception) as exc:
        return None, str(exc)


def refresh_index(host, port, timeout, index_name, ca_cert, client_cert, client_key, verify_ssl=False):
    refresh_url = "{0}/{1}/_refresh".format(_build_base_url(host, port), index_name)
    try:
        response = requests.post(
            refresh_url,
            cert=(client_cert, client_key),
            verify=verify_ssl,
            timeout=timeout
        )
        if response.status_code in (200, 201):
            return None
        return "Failed to refresh index '{0}': HTTP {1}".format(index_name, response.status_code)
    except (requests.exceptions.RequestException, Exception) as exc:
        return str(exc)


def extract_devices(devices, inventory_result):
    if devices:
        return devices
    if isinstance(inventory_result, dict):
        return inventory_result.get("device_data", {}).get("devices", [])
    return []


def normalize_coordinate_value(value):
    if value is None:
        return None

    lat = None
    lon = None

    if isinstance(value, str):
        parts = [part.strip() for part in value.split(",")]
        if len(parts) != 2:
            return None
        try:
            lat = float(parts[0])
            lon = float(parts[1])
        except (TypeError, ValueError):
            return None
    elif isinstance(value, (list, tuple)) and len(value) == 2:
        try:
            lat = float(value[0])
            lon = float(value[1])
        except (TypeError, ValueError):
            return None
    elif isinstance(value, dict):
        if "lat" not in value or "lon" not in value:
            return None
        try:
            lat = float(value.get("lat"))
            lon = float(value.get("lon"))
        except (TypeError, ValueError):
            return None
    else:
        return None

    if lat < -90.0 or lat > 90.0 or lon < -180.0 or lon > 180.0:
        return None

    return "{0},{1}".format(lat, lon)


def normalize_coordinate_geo_point(value):
    normalized_value = normalize_coordinate_value(value)
    if normalized_value is None:
        return None
    lat_str, lon_str = normalized_value.split(",", 1)
    return {
        "lat": float(lat_str),
        "lon": float(lon_str)
    }


def normalize_record_coordinates(records, coordinates_field="coordinates", geo_point_field="coordinates_geo"):
    normalized_records = []
    for record in records:
        if not isinstance(record, dict):
            normalized_records.append(record)
            continue
        if coordinates_field not in record:
            normalized_records.append(record)
            continue

        normalized_value = normalize_coordinate_value(record.get(coordinates_field))
        normalized_geo_point = normalize_coordinate_geo_point(record.get(coordinates_field))
        if normalized_value is None or normalized_geo_point is None:
            normalized_records.append(record)
            continue

        row = dict(record)
        row[coordinates_field] = normalized_value
        row[geo_point_field] = normalized_geo_point
        normalized_records.append(row)

    return normalized_records


def _is_meaningful_value(value):
    if value is None:
        return False
    if isinstance(value, str):
        stripped = value.strip()
        if stripped == "":
            return False
        if stripped.lower() in ("unknown", "n/a", "na", "null", "none"):
            return False
        return True
    if isinstance(value, (list, dict, tuple, set)):
        return len(value) > 0
    return True


def _get_identity_value(record, key):
    if key in record and _is_meaningful_value(record.get(key)):
        return str(record.get(key))
    if key == "name":
        for alt in ("Name", "hostname"):
            if alt in record and _is_meaningful_value(record.get(alt)):
                return str(record.get(alt))
    return None


def _duplicate_key(record):
    uuid_val = _get_identity_value(record, "uuid")
    name_val = _get_identity_value(record, "name")
    if not uuid_val or not name_val:
        return None
    return "{0}::{1}".format(uuid_val, name_val)


def merge_duplicate_records(records):
    """Merge duplicate records keyed by uuid+name while preserving deterministic output order."""
    out = []
    key_to_index = {}
    duplicates_merged = 0
    conflicts = 0

    for record in records:
        key = _duplicate_key(record)
        if not key:
            out.append(dict(record))
            continue

        if key not in key_to_index:
            key_to_index[key] = len(out)
            out.append(dict(record))
            continue

        duplicates_merged += 1
        idx = key_to_index[key]
        merged = out[idx]
        for field, incoming_value in record.items():
            if field not in merged:
                merged[field] = incoming_value
                continue

            current_value = merged.get(field)
            current_meaningful = _is_meaningful_value(current_value)
            incoming_meaningful = _is_meaningful_value(incoming_value)

            if (not current_meaningful) and incoming_meaningful:
                merged[field] = incoming_value
            elif current_meaningful and incoming_meaningful and current_value != incoming_value:
                conflicts += 1

        out[idx] = merged

    return out, duplicates_merged, conflicts


def run_module():
    module_args = dict(
        es_host=dict(type='str', default='localhost'),
        es_port=dict(type='int', default=9200),
        es_timeout=dict(type='int', default=30),
        target_index=dict(type='str', default='nodegrid_device_report'),
        id_field=dict(type='str', default='uuid'),
        batch_size=dict(type='int', default=1000),
        refresh_index=dict(type='bool', default=False),
        check_shard_capacity=dict(type='bool', default=True),
        auto_increase_shard_limit=dict(type='bool', default=False),
        shard_limit_increment=dict(type='int', default=100),
        shard_limit_hard_cap=dict(type='int', default=1200),
        purge_before_load=dict(type='bool', default=False),
        merge_duplicates=dict(type='bool', default=True),
        add_row_timestamps=dict(type='bool', default=True),
        created_timestamp_field=dict(type='str', default='report_created_at'),
        updated_timestamp_field=dict(type='str', default='report_updated_at'),
        synced_timestamp_field=dict(type='str', default='report_synced_at'),
        protect_index=dict(type='bool', default=True),
        policy_id=dict(type='str', default=_DEFAULT_KEEP_FOREVER_POLICY_ID),
        inventory_result=dict(type='dict', default={}),
        devices=dict(type='list', elements='dict', default=[]),
        ca_cert=dict(type='str', default='/etc/opensearch/config/root-ca.pem'),
        client_cert=dict(type='str', default='/etc/opensearch/config/admin.pem'),
        client_key=dict(type='str', default='/etc/opensearch/config/admin-key.pem'),
        verify_ssl=dict(type='bool', default=False)
    )

    result = dict(
        changed=False,
        target_index='',
        index_created=False,
        shard_open=None,
        shard_available=None,
        max_shards_per_node=None,
        shard_limit_changed=False,
        shard_increase_attempted=False,
        shard_increase_target=None,
        shard_increase_error=None,
        shard_retry_after_create_failure=False,
        shard_retry_create_error=None,
        index_purged=False,
        deduplicated_records=0,
        duplicates_merged=0,
        duplicate_conflicts=0,
        index_template_changed=False,
        policy_created=False,
        policy_attachment_changed=False,
        input_records=0,
        processed=0,
        created=0,
        updated=0,
        noop=0,
        failed=0,
        error_details=[]
    )

    module = AnsibleModule(argument_spec=module_args, supports_check_mode=True)

    if not requests:
        module.fail_json(msg="This module requires the 'requests' Python library")

    es_host = module.params['es_host']
    es_port = module.params['es_port']
    es_timeout = module.params['es_timeout']
    target_index = module.params['target_index']
    id_field = module.params['id_field']
    batch_size = module.params['batch_size']
    do_refresh = module.params['refresh_index']
    check_shard_capacity = module.params['check_shard_capacity']
    auto_increase_shard_limit = module.params['auto_increase_shard_limit']
    shard_limit_increment = module.params['shard_limit_increment']
    shard_limit_hard_cap = module.params['shard_limit_hard_cap']
    purge_before_load = module.params['purge_before_load']
    merge_duplicates = module.params['merge_duplicates']
    add_row_timestamps = module.params['add_row_timestamps']
    created_timestamp_field = module.params['created_timestamp_field']
    updated_timestamp_field = module.params['updated_timestamp_field']
    synced_timestamp_field = module.params['synced_timestamp_field']
    protect_index = module.params['protect_index']
    policy_id = module.params['policy_id']
    inventory_result = module.params['inventory_result']
    devices = module.params['devices']
    ca_cert = module.params['ca_cert']
    client_cert = module.params['client_cert']
    client_key = module.params['client_key']
    verify_ssl = module.params['verify_ssl']

    if batch_size < 1:
        module.fail_json(msg="batch_size must be >= 1", **result)
    if shard_limit_increment < 1:
        module.fail_json(msg="shard_limit_increment must be >= 1", **result)
    if shard_limit_hard_cap < 1:
        module.fail_json(msg="shard_limit_hard_cap must be >= 1", **result)
    if add_row_timestamps and (not created_timestamp_field or not updated_timestamp_field or not synced_timestamp_field):
        module.fail_json(msg="created_timestamp_field, updated_timestamp_field, and synced_timestamp_field must be non-empty when add_row_timestamps=true", **result)
    if protect_index and not policy_id:
        module.fail_json(msg="policy_id must be non-empty when protect_index=true", **result)

    records = extract_devices(devices, inventory_result)
    if not isinstance(records, list):
        module.fail_json(msg="Input devices must be a list of dictionaries", **result)

    result['target_index'] = target_index
    result['input_records'] = len(records)

    if merge_duplicates:
        records, dup_count, dup_conflicts = merge_duplicate_records(records)
        result['duplicates_merged'] = dup_count
        result['duplicate_conflicts'] = dup_conflicts
    records = normalize_record_coordinates(records)
    result['deduplicated_records'] = len(records)

    try:
        check_opensearch(es_host, es_port, es_timeout, ca_cert, client_cert, client_key, verify_ssl)
    except Exception as e:
        module.fail_json(msg=f"OpenSearch is not reachable. Error: {e}", **result)

    try:
        already_exists = index_exists(es_host, es_port, es_timeout, target_index, ca_cert, client_cert, client_key, verify_ssl)
    except Exception as e:
        module.fail_json(msg=str(e), **result)

    if module.check_mode:
        result['changed'] = (purge_before_load and bool(already_exists)) or (not already_exists) or (len(records) > 0)
        module.exit_json(**result)

    if purge_before_load:
        try:
            index_purged = delete_index_if_exists(es_host, es_port, es_timeout, target_index, ca_cert, client_cert, client_key, verify_ssl=verify_ssl)
            already_exists = index_exists(es_host, es_port, es_timeout, target_index, ca_cert, client_cert, client_key, verify_ssl=verify_ssl)
        except Exception as e:
            module.fail_json(msg=str(e), **result)
        result['index_purged'] = bool(index_purged)


    if not already_exists and check_shard_capacity:
        shard_info, shard_err, shard_debug = ensure_shard_capacity_for_index_create_with_debug(
            es_host,
            es_port,
            es_timeout,
            required_shards=1,
            auto_increase_limit=auto_increase_shard_limit,
            shard_limit_increment=shard_limit_increment,
            shard_limit_hard_cap=shard_limit_hard_cap,
            ca_cert=ca_cert,
            client_cert=client_cert,
            client_key=client_key,
            verify_ssl=verify_ssl
        )
        result['shard_increase_attempted'] = shard_debug.get('shard_increase_attempted', False)
        result['shard_increase_target'] = shard_debug.get('shard_increase_target')
        result['shard_increase_error'] = shard_debug.get('shard_increase_error')
        if shard_err:
            module.fail_json(msg=shard_err, **result)

        result['shard_open'] = shard_info.get('open_shards')
        result['shard_available'] = shard_info.get('available_shards')
        result['max_shards_per_node'] = shard_info.get('max_shards_per_node')
        result['shard_limit_changed'] = shard_info.get('shard_limit_changed', False)

    index_created, index_err = ensure_index_exists(
        es_host,
        es_port,
        es_timeout,
        target_index,
        ca_cert,
        client_cert,
        client_key,
        verify_ssl,
        created_timestamp_field=created_timestamp_field,
        updated_timestamp_field=updated_timestamp_field,
        synced_timestamp_field=synced_timestamp_field
    )
    if index_err and is_shard_limit_error(index_err) and auto_increase_shard_limit:
        # Handle race/metric-drift cases: attempt one more capacity check + increase + retry.
        result['shard_retry_after_create_failure'] = True
        shard_info, shard_err, shard_debug = ensure_shard_capacity_for_index_create_with_debug(
            es_host,
            es_port,
            es_timeout,
            required_shards=1,
            auto_increase_limit=True,
            shard_limit_increment=shard_limit_increment,
            shard_limit_hard_cap=shard_limit_hard_cap,
            ca_cert=ca_cert,
            client_cert=client_cert,
            client_key=client_key,
            verify_ssl=verify_ssl,
            force_increase_attempt=True
        )
        result['shard_increase_attempted'] = shard_debug.get('shard_increase_attempted', result['shard_increase_attempted'])
        result['shard_increase_target'] = shard_debug.get('shard_increase_target', result['shard_increase_target'])
        result['shard_increase_error'] = shard_debug.get('shard_increase_error')
        if shard_err:
            module.fail_json(msg=shard_err, **result)

        result['shard_open'] = shard_info.get('open_shards')
        result['shard_available'] = shard_info.get('available_shards')
        result['max_shards_per_node'] = shard_info.get('max_shards_per_node')
        result['shard_limit_changed'] = shard_info.get('shard_limit_changed', False)

        index_created, index_err = ensure_index_exists(
            es_host,
            es_port,
            es_timeout,
            target_index,
            ca_cert,
            client_cert,
            client_key,
            verify_ssl,
            created_timestamp_field=created_timestamp_field,
            updated_timestamp_field=updated_timestamp_field,
            synced_timestamp_field=synced_timestamp_field
        )
        result['shard_retry_create_error'] = index_err

    if index_err and is_shard_limit_error(index_err) and not auto_increase_shard_limit:
        index_err = (
            "{0} "
            "Set auto_increase_shard_limit=true and adjust shard_limit_hard_cap if policy allows."
        ).format(index_err)

    if index_err:
        module.fail_json(msg=index_err, **result)
    result['index_created'] = bool(index_created)

    # Ensure the high-priority index template exists so future recreations
    # inherit the correct mapping and ISM policy (prevents auto-deletion).
    if protect_index:
        _tmpl_changed, tmpl_err = ensure_index_template(
            es_host,
            es_port,
            es_timeout,
            target_index,
            ca_cert,
            client_cert,
            client_key,
            verify_ssl,
            policy_id=policy_id,
            created_timestamp_field=created_timestamp_field,
            updated_timestamp_field=updated_timestamp_field,
            synced_timestamp_field=synced_timestamp_field
        )
        result['index_template_changed'] = bool(_tmpl_changed)
        if tmpl_err:
            # Non-fatal: log via module warn if available, else ignore.
            try:
                module.warn("Could not ensure index template: {0}".format(tmpl_err))
            except Exception:
                pass
        else:
            result['changed'] = result['changed'] or bool(_tmpl_changed)

        # Ensure the keep-forever ISM policy exists and is attached.
        _policy_created, policy_err = ensure_ism_keep_policy(
            es_host,
            es_port,
            es_timeout,
            ca_cert,
            client_cert,
            client_key,
            verify_ssl,
            policy_id=policy_id
        )
        result['policy_created'] = bool(_policy_created)
        if policy_err:
            try:
                module.warn("Could not ensure ISM policy: {0}".format(policy_err))
            except Exception:
                pass
        if not policy_err:
            _attached, attach_err = attach_ism_policy_to_index(
                es_host,
                es_port,
                es_timeout,
                target_index,
                ca_cert,
                client_cert,
                client_key,
                verify_ssl,
                policy_id=policy_id
            )
            result['policy_attachment_changed'] = bool(_attached)
            if attach_err:
                try:
                    module.warn("Could not attach ISM policy to report index: {0}".format(attach_err))
                except Exception:
                    pass
            if not attach_err:
                result['changed'] = result['changed'] or bool(_policy_created) or bool(_attached)

    mapping_changed, mapping_err = ensure_geo_point_field_mapping(
        es_host,
        es_port,
        es_timeout,
        target_index,
        'coordinates_geo',
        ca_cert,
        client_cert,
        client_key,
        verify_ssl
    )
    if mapping_err:
        module.fail_json(msg=mapping_err, **result)
    result['changed'] = result['changed'] or bool(mapping_changed)

    if len(records) == 0:
        result['changed'] = (
            result['index_purged']
            or result['index_created']
            or bool(mapping_changed)
            or result['index_template_changed']
            or result['policy_created']
            or result['policy_attachment_changed']
        )
        module.exit_json(**result)

    for row in records:
        if not isinstance(row, dict):
            module.fail_json(msg="Each device row must be a dictionary", **result)

    write_summary, write_err = bulk_upsert_devices(
        es_host,
        es_port,
        es_timeout,
        target_index,
        records,
        batch_size,
        id_field,
        ca_cert,
        client_cert,
        client_key,
        verify_ssl,
        add_row_timestamps=add_row_timestamps,
        created_timestamp_field=created_timestamp_field,
        updated_timestamp_field=updated_timestamp_field,
        synced_timestamp_field=synced_timestamp_field
    )
    if write_err:
        module.fail_json(msg="Bulk upsert failed: {0}".format(write_err), **result)

    result.update(write_summary)

    if do_refresh:
        refresh_err = refresh_index(es_host, es_port, es_timeout, target_index, ca_cert, client_cert, client_key, verify_ssl)
        if refresh_err:
            module.fail_json(msg=refresh_err, **result)

    result['changed'] = (
        result['index_purged']
        or result['index_created']
        or bool(mapping_changed)
        or result['index_template_changed']
        or result['policy_created']
        or result['policy_attachment_changed']
        or result['created'] > 0
        or result['updated'] > 0
    )

    if result['failed'] > 0:
        module.fail_json(msg="Bulk upsert completed with failed rows", **result)

    module.exit_json(**result)


def main():
    run_module()


if __name__ == '__main__':
    main()

