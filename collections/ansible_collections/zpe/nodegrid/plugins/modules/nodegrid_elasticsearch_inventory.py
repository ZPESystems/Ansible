#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2024, ZPE Systems <zpesystems.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Nodegrid OpenSearch Inventory Module

This Ansible module collects managed device inventory data from OpenSearch (running on Nodegrid)
and validates the data against a configurable minimum schema.

Key Features:
- Validates OpenSearch connectivity via HTTPS with certificate-based authentication
- Retrieves device data from *_device_en indices with scroll-based pagination
- Performs minimum-schema validation (required fields + types)
- Excludes Nodegrid-type devices from inventory
- Flattens nested OpenSearch structures for easier consumption in playbooks
- Preserves all original fields from OpenSearch documents
- Maps searchable field names to expected output field names
- Provides detailed validation error reporting

Output Format:
Valid device records are returned in flattened format where nested dictionaries are
converted to underscore-prefixed keys. For example:
  {
    "name": "PDU",
    "searchable_groups_field": "Groups",
    "searchable_groups_value": "admin",
    "uuid": "a5d0f4ff-11db-423b-8a03-17d0756628e7",
    ...
  }
"""

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r'''
---
module: nodegrid_elasticsearch_inventory
version_added: "1.0.0"
author:
  - ZPE Systems
short_description: Collect managed device inventory data from a local OpenSearch instance
description:
  - This module collects device inventory data from OpenSearch running on Nodegrid.
  - It validates OpenSearch connectivity, retrieves data from *_device_en indices,
    and performs minimum-schema validation on the retrieved documents.
  - Valid records are returned in a flattened format with nested keys joined by underscores.
  - Devices of Type "Nodegrid" are automatically excluded from the inventory.
  - Devices with Type other than "Nodegrid" are valid if they contain all required schema fields
    with correct types; any additional fields are preserved.
  - Results are returned as structured data for use in Ansible playbooks.
notes:
  - SSL hostname verification is always disabled due to dynamic certificate generation on Nodegrid appliances.
    The C(verify_ssl) option controls CA chain validation only.
  - This module is a role-local library module. It must be invoked by its short name
    (C(nodegrid_elasticsearch_inventory)) when used within the C(nodegrid_elasticsearch_inventory) role.
  - The module uses scroll-based pagination and retrieves all documents from matching indices.
  - Records from indices that are temporarily unreachable are silently skipped.
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
    default: 10
  index_pattern:
    description:
      - Index pattern to search for device data.
    type: str
    default: "*_device_en"
  schema:
    description:
      - Schema definition for minimum validation (required fields and types).
      - Data must contain all schema fields with matching types to be considered valid.
      - Additional fields beyond the schema are allowed and preserved in output.
    type: dict
    default:
      hostname: str
      nodegridhost: str
      status: str
      type: str
      mode: str
      groups: str
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
      - Whether to verify SSL certificates.
      - Note: Hostname verification is always disabled due to dynamic certificate generation on Nodegrid.
    type: bool
    default: false
requirements:
  - requests
  - python >= 3.6
'''

EXAMPLES = r'''
- name: Collect inventory from OpenSearch using role defaults
  nodegrid_elasticsearch_inventory:
  register: inventory_result

- name: Display valid device count
  ansible.builtin.debug:
    msg: "Found {{ inventory_result.device_data.valid }} valid devices"

- name: Display first valid device (flattened format)
  ansible.builtin.debug:
    var: inventory_result.device_data.devices[0]

- name: Show validation errors
  ansible.builtin.debug:
    msg: "Device {{ item.index }} failed: {{ item.errors }}"
  loop: "{{ inventory_result.device_data.errors }}"

- name: Collect inventory with custom schema validation
  nodegrid_elasticsearch_inventory:
    schema:
      hostname: str
      ip: str
      status: str
  register: custom_inventory

- name: Collect inventory from a non-default OpenSearch endpoint
  nodegrid_elasticsearch_inventory:
    es_host: opensearch.example.com
    es_port: 9200
    es_timeout: 30
    index_pattern: "*_device_en"
    client_cert: /etc/opensearch/config/admin.pem
    client_key: /etc/opensearch/config/admin-key.pem
  register: remote_inventory
'''

RETURN = r'''
nodegrid_version:
  description: Nodegrid OS version.
  type: str
  returned: always
nodegrid_model:
  description: Nodegrid hardware model.
  type: str
  returned: always
elasticsearch_status:
  description: Status of OpenSearch connectivity.
  type: str
  returned: always
  choices:
    - reachable
    - unreachable
device_data:
  description: Inventory data from OpenSearch.
  type: dict
  returned: always
  contains:
    valid:
      description: Number of valid records (passed minimum schema validation).
      type: int
      returned: always
    invalid:
      description: Number of invalid records (failed minimum schema validation or excluded).
      type: int
      returned: always
    errors:
      description: List of validation errors for invalid records.
      type: list
      returned: always
      contains:
        index:
          description: Index of the record in the original result set.
          type: int
        record:
          description: The original unflattened record that failed validation.
          type: dict
        errors:
          description: List of validation error messages for this record.
          type: list
          example:
            - "Device of Type 'Nodegrid' is excluded from inventory"
            - "Missing required field: Status"
            - "Field 'Type' has invalid type. Expected str, got int"
    devices:
      description: |
        List of valid device records in flattened format.
        Nested dictionaries are flattened with underscore-joined keys.
        For example, searchable.groups.field becomes searchable_groups_field.
        Lists and tuples are converted to string representations.
        All fields from the original OpenSearch document are included.
      type: list
      returned: always
      example:
        - name: "PDU"
          uuid: "a5d0f4ff-11db-423b-8a03-17d0756628e7"
          status: "Unknown"
          type: "pdu_servertech"
          ngfqdn: "ireland-gatesr.emea.zpesystems.local"
          searchable_groups_field: "Groups"
          searchable_groups_value: "admin"
          searchable_status_field: "Status"
          searchable_status_value: "Unknown"
          icon_file: "/icon/terminal.png"
          ip: "10.0.2.5"
          authzgrouplist: "['admin', 'network', 'user']"
'''

import os
from ansible.module_utils.basic import AnsibleModule

try:
    import requests
except ImportError:
    requests = None

# Set up logging for security audit trail
#logger = logging.getLogger(__name__)


def convert_schema_types(schema):
    """Convert string type names to actual Python types."""
    type_mapping = {
        'str': str,
        'int': int,
        'float': float,
        'bool': bool,
        'list': list,
        'dict': dict,
        'tuple': tuple,
        'set': set,
        'NoneType': type(None)
    }

    converted_schema = {}
    for key, type_name in schema.items():
        if isinstance(type_name, str) and type_name in type_mapping:
            converted_schema[key] = type_mapping[type_name]
        else:
            converted_schema[key] = type_name
    return converted_schema


def check_elasticsearch(host, port, timeout, ca_cert, client_cert, client_key, verify_ssl=False):
    """Check if OpenSearch is reachable."""
    url = f"https://{host}:{port}"

    # Verify certificate files exist
    if not os.path.exists(ca_cert):
        raise Exception(f"CA certificate not found: {ca_cert}")
    if not os.path.exists(client_cert):
        raise Exception(f"Client certificate not found: {client_cert}")
    if not os.path.exists(client_key):
        raise Exception(f"Client key not found: {client_key}")

    try:
        response = requests.get(
            url,
            cert=(client_cert, client_key),
            verify=verify_ssl,  # Disable SSL verification due to dynamic certificate generation
            timeout=timeout
        )
        if response.status_code == 200:
            return "reachable"
        else:
            raise Exception(f"Server responded with error. Request url={response.url}. Status code={response.status_code}")
    except requests.exceptions.RequestException as e:
        raise Exception(f"Connection failed: {type(e).__name__}: {str(e)}")


def get_device_data(host, port, index_pattern, timeout, ca_cert, client_cert, client_key, verify_ssl=False):
    """
     Retrieve device data from OpenSearch with pagination and explicit scroll cleanup.

     Fetches all documents from indices matching the pattern and preserves the full original
     _source payload for each device. Uses scroll API for efficient pagination through large result sets.
     Scroll contexts are explicitly cleaned up to prevent resource exhaustion.

     Args:
         host (str): OpenSearch host address
         port (int): OpenSearch port number
         index_pattern (str): Glob pattern to match index names (e.g., "*_device_en")
         timeout (int): Request timeout in seconds
         ca_cert (str): Path to CA certificate file
         client_cert (str): Path to client certificate file
         client_key (str): Path to client private key file
         verify_ssl (bool): Whether to verify SSL certificates

     Returns:
         tuple: (list of device dicts, list of matched index names)
                Returns ([], []) if certificate files are missing or requests fail
     """
    all_results = []

    # Get list of indices matching the pattern
    indices_url = f"https://{host}:{port}/_cat/indices/{index_pattern}?format=json"
    try:
        indices_response = requests.get(
            indices_url,
            cert=(client_cert, client_key),
            verify=verify_ssl,  #Whether to check or disable SSL verification due to dynamic certificate generation
            timeout=timeout
        )
        indices_response.raise_for_status()
        indices = [idx["index"] for idx in indices_response.json()]
    except requests.exceptions.RequestException as e:
        raise Exception(f"Failed to list indices with pattern '{index_pattern}'. Error: {e}")

    for index in indices:
        scroll_url = f"https://{host}:{port}/{index}/_search?scroll=1m"
        query = {
            "query": {"match_all": {}},
            "size": 1000
        }

        scroll_id = None
        try:
            response = requests.post(
                scroll_url,
                json=query,
                cert=(client_cert, client_key),
                verify=verify_ssl,  
                timeout=timeout
            )
            response.raise_for_status()
            result = response.json()

            hits = result.get("hits", {}).get("hits", [])
            for hit in hits:
                source = hit.get("_source", {})
                # Preserve the full original _source payload for valid output.
                all_results.append(source)

            # Handle pagination using scroll API with explicit cleanup
            scroll_id = result.get("_scroll_id")
            while hits and scroll_id:
                try:
                    scroll_response = requests.post(
                        f"https://{host}:{port}/_search/scroll",
                        json={"scroll": "1m", "scroll_id": scroll_id},
                        cert=(client_cert, client_key),
                        verify=verify_ssl,
                        timeout=timeout
                    )
                    scroll_response.raise_for_status()
                    result = scroll_response.json()
                    hits = result.get("hits", {}).get("hits", [])

                    for hit in hits:
                        source = hit.get("_source", {})
                        # Preserve the full original _source payload for valid output.
                        all_results.append(source)

                    scroll_id = result.get("_scroll_id")
                except requests.exceptions.RequestException as e:
                    raise Exception(f"Error during scroll pagination for index '{index}'. Error: {e}")

        except requests.exceptions.RequestException as e:
            raise Exception(f"Error retrieving data from index '{index}'. Error: {e}")
            
        finally:
            # Always cleanup scroll context to prevent resource leaks
            if scroll_id:
                try:
                    cleanup_url = f"https://{host}:{port}/_search/scroll"
                    requests.delete(
                        cleanup_url,
                        json={"scroll_id": [scroll_id]},
                        cert=(client_cert, client_key),
                        verify=verify_ssl,
                        timeout=5
                    )
                except Exception as e:
                    raise Exception(f"Failed to cleanup scroll context. Error: {e}")

    return all_results, indices


def flatten_dict(d, parent_key='', sep='_'):
    """
    Flatten a nested dictionary by joining keys with a separator.

    Recursively processes nested dictionaries, combining parent and child keys with underscores.
    Lists and tuples are converted to their string representation to avoid issues with
    JSON serialization and Ansible playbook compatibility.

    Example:
        >>> data = {
        ...     "searchable": {
        ...         "groups": {"field": "Groups", "value": "admin"}
        ...     },
        ...     "name": "PDU"
        ... }
        >>> flatten_dict(data)
        {
            'name': 'PDU',
            'searchable_groups_field': 'Groups',
            'searchable_groups_value': 'admin'
        }

    Args:
        d (dict): Dictionary to flatten
        parent_key (str): Parent key prefix (used internally during recursion)
        sep (str): Separator character to join keys (default: '_')

    Returns:
        dict: Flattened dictionary with no nested dicts
    """
    items = []
    for k, v in d.items():
        new_key = f"{parent_key}{sep}{k}" if parent_key else k
        if isinstance(v, dict):
            items.extend(flatten_dict(v, new_key, sep=sep).items())
        elif isinstance(v, (list, tuple)):
            # Convert list/tuple to string representation for flattened output
            items.append((new_key, str(v)))
        else:
            items.append((new_key, v))
    return dict(items)


def validate_data(data, schema):
    """
    Validate data against a minimum schema contract and return flattened results.

    Performs minimum-schema validation: each record must contain all required schema fields
    with the correct types. Additional fields beyond the schema are allowed and preserved.
    Devices with Type='Nodegrid' are automatically excluded from inventory.

    Validation Process:
    1. Extracts field values from OpenSearch searchable mappings where available
    2. Falls back to native _source field names if searchable mappings are missing
    3. Checks that all required schema fields are present with correct types
    4. Excludes Type='Nodegrid' devices

    Output Format:
    - Valid records are FLATTENED: nested dicts become underscore-prefixed keys
    - All original fields are preserved in the flattened output
    - Lists/tuples are converted to string representations

    Args:
        data (list): List of device records from OpenSearch (full _source payloads)
        schema (dict): Schema definition mapping field names to Python type names (as strings)
                      e.g., {'hostname': 'str', 'status': 'str', 'type': 'str'}

    Returns:
        tuple: (valid_records, invalid_records, errors)
               - valid_records (list): Flattened dicts of records that passed validation
               - invalid_records (list): Original unflattened dicts of failed records
               - errors (list): Error details for each failed record with index, original record, and error messages

    Field Mapping Priority:
    1. searchable[key].field value from OpenSearch document
    2. Native _source field (e.g., 'name', 'ngfqdn', 'status', 'type', 'mode', 'groups')
    3. Exact schema key name
    """
    # Convert string type names to actual Python types
    converted_schema = convert_schema_types(schema)

    valid_records = []
    invalid_records = []
    errors = []

    # Define the actual field mappings from OpenSearch data to expected fields
    field_mappings = {
        'hostname': 'Name',
        'nodegridhost': 'Nodegrid Host',
        'status': 'Status',
        'type': 'Type',
        'mode': 'Mode',
        'groups': 'Groups'
    }

    # Native _source keys used when searchable mapping is missing.
    source_field_mappings = {
        'hostname': 'name',
        'nodegridhost': 'ngfqdn',
        'status': 'status',
        'type': 'type',
        'mode': 'mode',
        'groups': 'groups'
    }

    def build_validation_view(item):
        """
        Build a validation field view from raw OpenSearch document.

        Extracts searchable field mappings (field/value pairs) and merges them into a view
        used for schema validation. This allows validation to work with OpenSearch's
        searchable field structure while preserving the original payload for output.

        Args:
            item (dict): Original OpenSearch _source document

        Returns:
            dict: Dictionary with searchable fields extracted and mapped for validation
        """
        validation_view = dict(item)
        searchable = item.get('searchable', {})
        if isinstance(searchable, dict):
            for field_info in searchable.values():
                if not isinstance(field_info, dict):
                    continue
                field_name = field_info.get('field')
                if field_name and 'value' in field_info:
                    validation_view[field_name] = field_info['value']
        return validation_view

    for idx, item in enumerate(data):
        is_valid = True
        item_errors = []
        validation_item = build_validation_view(item)

        # Skip devices of Type "Nodegrid"
        device_type = validation_item.get('Type', validation_item.get('type'))
        if device_type == 'Nodegrid':
            item_errors.append("Device of Type 'Nodegrid' is excluded from inventory")
            is_valid = False

        # Validate required schema fields, allowing mapped source names or schema names.
        for key, expected_type in converted_schema.items():
            mapped_field_name = field_mappings.get(key, key)
            source_field_name = source_field_mappings.get(key, key)
            candidate_field_names = [mapped_field_name, source_field_name, key]

            # Keep order, remove duplicates.
            candidate_field_names = list(dict.fromkeys(candidate_field_names))

            found_fields = [field_name for field_name in candidate_field_names if field_name in validation_item]
            if not found_fields:
                is_valid = False
                item_errors.append(f"Missing required field: {mapped_field_name}")
                continue

            if not any(isinstance(validation_item[field_name], expected_type) for field_name in found_fields):
                is_valid = False
                actual_types = ", ".join(
                    f"{field_name}={type(validation_item[field_name]).__name__}" for field_name in found_fields
                )
                item_errors.append(
                    f"Field '{mapped_field_name}' has invalid type. Expected {expected_type.__name__}, got {actual_types}"
                )

        if is_valid:
            # Flatten the record for output: nested dicts become underscore-prefixed keys.
            flattened_record = flatten_dict(item)
            valid_records.append(flattened_record)
        else:
            invalid_records.append(item)
            errors.append({
                "index": idx,
                "record": item,
                "errors": item_errors
            })

    return valid_records, invalid_records, errors


def run_module():
    """
    Execute the Nodegrid Elasticsearch Inventory module.

    Workflow:
    1. Parse module arguments with defaults
    2. Check OpenSearch connectivity (HTTPS + certs)
    3. Retrieve device data from OpenSearch with pagination
    4. Validate each record against minimum schema
    5. Flatten valid records for output
    6. Return structured results with device inventory and error details
    """
    module_args = dict(
        es_host=dict(type='str', default='localhost'),
        es_port=dict(type='int', default=9200),
        es_timeout=dict(type='int', default=10),
        index_pattern=dict(type='str', default='*_device_en'),
        schema=dict(type='dict', default={
            'hostname': 'str',
            'nodegridhost': 'str',
            'status': 'str',
            'type': 'str',
            'mode': 'str',
            'groups': 'str'
        }),

        # Note: The schema defines minimum required fields. The module validates that
        # all records contain these fields with the correct types. Additional fields
        # beyond the schema are allowed and preserved in the output.
        # Validation uses field mappings to match OpenSearch data fields to expected names.
        # Devices with Type='Nodegrid' are automatically excluded.
        # Valid output records are flattened: nested dicts become underscore-prefixed keys.
        ca_cert=dict(type='str', default='/etc/opensearch/config/root-ca.pem'),
        client_cert=dict(type='str', default='/etc/opensearch/config/admin.pem'),
        client_key=dict(type='str', default='/etc/opensearch/config/admin-key.pem'),
        verify_ssl=dict(type='bool', default=False)
    )

    result = dict(
        changed=False,
        elasticsearch_status='unreachable',
        device_data=dict(
            valid=0,
            invalid=0,
            errors=[],
            devices=[]
        )
    )

    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=True
    )

    # Check if requests is available
    if not requests:
        module.fail_json(msg="This module requires the 'requests' Python library")

    # Extract parameters
    es_host = module.params['es_host']
    es_port = module.params['es_port']
    es_timeout = module.params['es_timeout']
    index_pattern = module.params['index_pattern']
    schema = module.params['schema']
    ca_cert = module.params['ca_cert']
    client_cert = module.params['client_cert']
    client_key = module.params['client_key']
    verify_ssl = module.params['verify_ssl']

    # Check OpenSearch connectivity
    try:
        es_status = check_elasticsearch(es_host, es_port, es_timeout, ca_cert, client_cert, client_key, verify_ssl=verify_ssl)
    except Exception as e:
        module.fail_json(msg=f"OpenSearch is not reachable at https://{es_host}:{es_port}. Error={e}", **result)

    result['elasticsearch_status'] = es_status

    try:
    # Retrieve device data
        devices, indices = get_device_data(es_host, es_port, index_pattern, es_timeout, ca_cert, client_cert, client_key, verify_ssl)
    except Exception as e:
        module.fail_json(msg=f"OpenSearch get device data failed. Error={e}", **result)

    # Validate data
    valid_records, invalid_records, errors = validate_data(devices, schema)

    # Populate result
    result['device_data'] = dict(
        valid=len(valid_records),
        invalid=len(invalid_records),
        errors=errors,
        devices=valid_records
    )

    module.exit_json(**result)


def main():
    run_module()


if __name__ == '__main__':
    main()
