# TTP template
def get_template():
  template = """
<group name="clusters.{{ cluster_name }}">
  {{ node_name | _start_ }}  Remote Peer  {{ cluster_name }}    {{ cluster_address }}
  {{ node_name | _start_ }}  Cluster  {{ node_status }}  {{ cluster_address }}   {{ cluster_peers }}  {{ cluster_name }}
  {{ node_name | _start_ }}  Cluster  {{ node_status }}  {{ cluster_address }}   {{ cluster_name }}
</group>
"""
  return template