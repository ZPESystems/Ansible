# Managed Devices Report: `nodegrid_elasticsearch_inventory`

This use case collects managed-devices inventory from local Nodegrid OpenSearch indices, validate and flatten the source rows, and load the result into a central report index on the designated Nodegrid device with `reports` role.

## Requirements

- Ansible with support for the built-in `uri`, `assert`, `set_fact`, and `include_vars` modules
- Access to the `zpe.nodegrid` collection modules used by this project, including `zpe.nodegrid.nodegrid_facts`
- OpenSearch reachable on the target Nodegrid reports host via `https://localhost:9200`
- Client certificate/key files present on the reports host for report-policy validation tasks

# Example 
The following example considers two Nodegrid devices, each manages multiple target devices.

## Inventory


### `ngmanager1.yaml`
Create the file `/etc/ansible/inventories/host_vars/ngmanager1.yaml` with the following content (adapt it accordingly): 

```yaml
ansible_host: 192.168.1.21
ansible_port: '22'
ansible_user: ansible
ansible_ssh_private_key_file: ~/.ssh/managed@zpesystems.com
nodegrid_roles:
  - reports
```

### `boldsr.yaml`
Create the file `/etc/ansible/inventories/host_vars/boldsr.yaml` with the following content (adapt it accordingly): 

```yaml
ansible_host: 192.168.1.22
ansible_port: '22'
ansible_user: ansible
ansible_ssh_private_key_file: ~/.ssh/managed@zpesystems.com
```
### `md_report.yaml`
Create the file `/etc/ansible/inventories/md_report.yaml` with the following content: 

```yaml
md_report:
  hosts:
    ngmanager1:
    boldsr:
```

Test the inventory:

```bash
ansible@ngmanager1:~$ ansible-inventory --graph md_report
@md_report:
  |--ngmanager1
  |--boldsr

```

## Playbook

```yaml
- name: Build the central Nodegrid device report
  hosts: all
  gather_facts: false
  roles:
  - role: nodegrid_elasticsearch_inventory
    vars:
      nodegrid_report_target_index: spconfig_system_report
      nodegrid_report_policy_id: system_report_keep_forever
      nodegrid_report_add_row_timestamps: true
      nodegrid_report_synced_timestamp_field: report_synced_at
```


# `nodegrid_elasticsearch_inventory` Role Variables

The role-level variables' defaults values are:

| Variable | Default | Purpose |
| --- | --- | --- |
| `nodegrid_report_target_index` | `spconfig_system_report` | Report index that receives the flattened inventory rows |
| `nodegrid_report_batch_size` | `1000` | Bulk API batch size used by the report-load module |
| `nodegrid_report_check_shard_capacity` | `true` | Pre-check shard capacity before index creation |
| `nodegrid_report_auto_increase_shard_limit` | `true` | Allow automatic `cluster.max_shards_per_node` increases when needed |
| `nodegrid_report_shard_limit_increment` | `100` | Minimum shard-limit increment when auto-increase is enabled |
| `nodegrid_report_shard_limit_hard_cap` | `1200` | Hard ceiling for automatic shard-limit updates |
| `nodegrid_report_purge_before_load` | `false` | Delete the existing report index before loading |
| `nodegrid_report_add_row_timestamps` | `true` | Stamp lifecycle timestamps on report rows |
| `nodegrid_report_created_timestamp_field` | `report_created_at` | First-seen timestamp field |
| `nodegrid_report_updated_timestamp_field` | `report_updated_at` | Field updated only when row content changes |
| `nodegrid_report_synced_timestamp_field` | `report_synced_at` | Field updated on every sync run |
| `nodegrid_report_protect_index` | `true` | Ensure the report index has a protective template and ISM policy |
| `nodegrid_report_validate_policy_attachment` | `true` | Validate that the expected report policy is attached |
| `nodegrid_report_policy_id` | `system_report_keep_forever` | ISM policy ID used for report-index protection |
| `nodegrid_report_client_cert` | `/etc/opensearch/config/admin.pem` | Client certificate for report-policy validation |
| `nodegrid_report_client_key` | `/etc/opensearch/config/admin-key.pem` | Client key for report-policy validation |
| `nodegrid_report_validate_certs` | `false` | TLS validation toggle used by validation tasks |

## Behavior notes

- The role discovers exactly one central reports host by looking for the `reports` role in `nodegrid_roles` or `nodegrid_role`.
- Inventory rows are loaded only when source OpenSearch is reachable.
- If `nodegrid_report_add_row_timestamps=true`, new rows get `report_created_at`, changed rows get `report_updated_at`, and every run updates `report_synced_at`.
- Timestamp field names and the report policy ID are fully configurable and are passed through to the load module.
- If a row contains a `coordinates` field in `lat,lon` form, the loader preserves it as text and also writes `coordinates_geo` as `geo_point`.

## Security Best Practices

- Keep the report index protected with `nodegrid_report_protect_index: true` and a dedicated policy such as `system_report_keep_forever`.
- Treat `nodegrid_report_auto_increase_shard_limit` as a privileged setting and enable it only when operationally necessary.
- The role includes structured audit events for critical operations (`inventory_start`, `inventory_complete`, `report_load_start`, `report_load_complete`) through `tasks/audit.yml`.
- Audit records are written to `/var/log/nodegrid/audit-*.log` and should be collected by your central logging pipeline.
- User-controlled field names and policy IDs are validated before OpenSearch API calls. Keep custom values within supported characters and lengths.
- Bulk writes include payload size safeguards (`MAX_PAYLOAD_BYTES`), request retries, and backoff to reduce overload risk.
- Error responses returned to playbooks are intentionally sanitized; use Ansible/controller logs for detailed troubleshooting.

## Dependencies

- No external Ansible role dependencies are declared in `meta/main.yml`
- This role depends on project-local custom modules in `library/`:
  - `nodegrid_elasticsearch_inventory`
  - `nodegrid_elasticsearch_report_load`

## Example Playbook

```yaml
- name: Build the central Nodegrid device report
  hosts: all
  gather_facts: false
  roles:
	- role: nodegrid_elasticsearch_inventory
	  vars:
		nodegrid_report_target_index: spconfig_system_report
		nodegrid_report_policy_id: system_report_keep_forever
		nodegrid_report_add_row_timestamps: true
		nodegrid_report_synced_timestamp_field: report_synced_at
```

## Tags

- `inventory_setup`: discover and validate the single central reports host
- `inventory_collect`: collect Nodegrid facts and source inventory from OpenSearch
- `inventory_load`: create/protect/load the report index
- `report_policy`: validate the report policy and policy attachment
- `policy_check`: run the report-policy existence and attachment assertions
- `inventory_summary`: publish the aggregated role fact and debug summary

## Exported Facts

The role exports a `nodegrid_elasticsearch_inventory` fact with:

- `nodegrid_version`
- `nodegrid_model`
- `elasticsearch_status`
- `device_data.valid`, `device_data.invalid`, `device_data.errors`, `device_data.devices`
- `report_load.target_host`, `report_load.target_index`
- row-write counts: `processed`, `created`, `updated`, `noop`, `failed`
- shard diagnostics: `shard_open`, `shard_available`, `max_shards_per_node`, `shard_limit_changed`, `shard_increase_error`, `shard_retry_create_error`
- protection state: `index_template_changed`, `policy_created`, `policy_attachment_changed`, `policy_expected`, `policy_attached`
- timestamp-field names used by the run

## Dashboard Import

- Saved objects are shipped in `files/nodegrid_device_report_kibana.ndjson`
- The data view uses `report_synced_at` as the time field
- The current dashboard intentionally excludes the geolocation/map panel
- Import instructions are documented in `files/README_kibana_import.md`

## License

GPL-3.0-or-later

## Author Information

Maintained for Nodegrid/OpenSearch reporting workflows by ZPE Systems.

