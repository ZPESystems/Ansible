#!/usr/bin/python3
# -*- coding: utf-8 -*-

import os

base_path = "collections/ansible_collections/zpe/"
output_path = "build/collections/"

if not os.path.exists(output_path):
    os.makedirs(output_path)

for item in os.listdir(base_path):
    if not os.path.isfile(f"{base_path}{item}"):
        os.system(f"ansible-galaxy collection build {base_path}{item}/ --output-path {output_path} --force")

requirements = ["collections:\r\n"]
for item in os.listdir(output_path):
    if os.path.isfile(f"{output_path}{item}") and item.endswith("tar.gz"):
        requirements.append(f"  - name: {output_path}{item}\r\n")
        requirements.append("    type: file\r\n")

f = open(f"{output_path}requirements.yml", "w")
f.writelines(requirements)
f.close()