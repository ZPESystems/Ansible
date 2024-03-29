def get_template():
  template = """
<group name="open_sessions_nodegrid.{{ user }}">
  {{ user | _start_ }}      {{ mode | notdigit }}  {{ source_ip | contains('.',':','none') }}   {{ type }}  {{ ref | isdigit }}    {{ session_start | notdigit | _line_ | strip() }}
</group>
<group name="open_sessions_device.{{ user }}">
  {{ user | _start_ }}      {{ mode | notdigit }}  {{ source_ip | contains('.',':','none') }}   {{ type }}  {{ device }}  {{ ref | isdigit }}    {{ session_start | notdigit | _line_ | strip() }}
</group>
"""
  return template