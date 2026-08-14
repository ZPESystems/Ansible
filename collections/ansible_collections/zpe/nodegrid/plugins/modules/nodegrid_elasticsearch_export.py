#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2024, ZPE Systems <zpesystems.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from ansible.module_utils.basic import AnsibleModule
import json
import csv
import ssl
from urllib.request import Request, urlopen

def _build_base_url(host, port):
    return "https://{0}:{1}".format(host, port)


def make_request(url, method, client_cert, client_key, data=None):
    # Setup SSL context with client certificate authentication
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # Keeps it tolerant of self-signed cluster certs
    ctx.load_cert_chain(certfile=client_cert, keyfile=client_key) # Injects mTLS certs
    headers = {"Content-Type": "application/json"}
    req = Request(url, headers=headers, method=method)
    if data:
        req.data = json.dumps(data).encode('utf-8')
    with urlopen(req, context=ctx) as response:
        return json.loads(response.read().decode('utf-8'))


def run_module():
    module_args = dict(
        es_host=dict(type='str', default='localhost'),
        es_port=dict(type='int', default=9200),
        es_timeout=dict(type='int', default=60),
        es_index=dict(type='str', required=True),
        es_fields=dict(type='list', default={}),
        es_scroll_size=dict(type='int', default=5000),
        csv_file_path=dict(type='str', required=True),
        ca_cert=dict(type='str', default='/etc/opensearch/config/root-ca.pem'),
        client_cert=dict(type='str', default='/etc/opensearch/config/admin.pem'),
        client_key=dict(type='str', default='/etc/opensearch/config/admin-key.pem'),
        verify_ssl=dict(type='bool', default=False)
        )

    result = dict(
        changed=False,
        msg=''
    )

    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=True
    )

    # Extract parameters
    es_host = module.params['es_host']
    es_port = module.params['es_port']
    es_timeout = module.params['es_timeout']
    es_index = module.params['es_index']
    es_fields = module.params['es_fields']
    es_scroll_size = module.params['es_scroll_size']
    csv_file_path = module.params['csv_file_path']
    ca_cert = module.params['ca_cert']
    client_cert = module.params['client_cert']
    client_key = module.params['client_key']
    verify_ssl = module.params['verify_ssl']


    try:
        # 1. Initialize Scroll Context
        init_url = f"{_build_base_url(es_host,es_port)}/{es_index}/_search?scroll=1m"
        init_body = {
            "size": es_scroll_size,
            "_source": es_fields,
            "query": {"match_all": {}}
        }
    
        response = make_request(init_url, "POST", client_cert, client_key, data=init_body)
        scroll_id = response.get("_scroll_id")
        hits = response.get("hits", {}).get("hits", [])
        total_exported = 0
        # 2. Stream directly to CSV file
        with open(csv_file_path, mode='w', newline='', encoding='utf-8') as csv_file:
            writer = csv.writer(csv_file, quoting=csv.QUOTE_MINIMAL)
            # Write CSV Header
            writer.writerow(es_fields)
            
            while hits:
                # Write current batch
                for hit in hits:
                    source = hit.get("_source", {})
                    # Extract fields safely, handling missing values
                    row = [source.get(field, "") for field in es_fields]
                    writer.writerow(row)
                
                total_exported += len(hits)
                
                # Fetch next batch
                scroll_url = f"{_build_base_url(es_host,es_port)}/_search/scroll"
                scroll_body = {
                    "scroll": "1m",
                    "scroll_id": scroll_id
                }
                response = make_request(scroll_url, "POST", client_cert, client_key, data=scroll_body)
                scroll_id = response.get("_scroll_id")
                hits = response.get("hits", {}).get("hits", [])
    
        # 3. Clear Scroll Context
        if scroll_id:
            clear_url = f"{_build_base_url(es_host,es_port)}/_search/scroll"
            try:
                make_request(clear_url, "DELETE", client_cert, client_key, data={"scroll_id": [scroll_id]})
            except Exception:
                pass # Fail silently during cleanup if context expired
                
    except Exception as e:
        module.fail_json(msg=f"OpenSearch Export data failed. Error={e}", **result)

    result['msg'] = f"Records exported: {total_exported}. CSV file: {csv_file_path}"

    module.exit_json(**result)


def main():
    run_module()


if __name__ == '__main__':
    main()
