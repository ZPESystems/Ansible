# Library Support

These are the modules supported for the collection **zpe.nodegrid**:

<ins>Action modules:</ins>
- [facts](collections/ansible_collections/zpe/nodegrid/plugins/action/facts.py)
- [ping_nodegrid](collections/ansible_collections/zpe/nodegrid/plugins/action/ping_nodegrid.py)
- [setup](collections/ansible_collections/zpe/nodegrid/plugins/action/setup.py)
- [software_upgrade](collections/ansible_collections/zpe/nodegrid/plugins/action/software_upgrade.py)

<ins>Configuration modules - ( supported options ):</ins>
- [managed_devices](collections/ansible_collections/zpe/nodegrid/plugins/modules/managed_devices.py) - ( auto_discovery, device )
- [network](collections/ansible_collections/zpe/nodegrid/plugins/modules/network.py) - ( connection, settings )
- [security](collections/ansible_collections/zpe/nodegrid/plugins/modules/security.py) - ( authentication, authorization, local_account, password_rules )
- [system](collections/ansible_collections/zpe/nodegrid/plugins/modules/system.py) - ( date_and_time, license, preferences, ntp_authentication, ntp_server )

<ins>General purpose modules:</ins>
- [import_settings](collections/ansible_collections/zpe/nodegrid/plugins/modules/import_settings.py)
- [nodegrid_cmds](collections/ansible_collections/zpe/nodegrid/plugins/modules/nodegrid_cmds.py)
