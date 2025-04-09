def get_template():
  template = """
<group name="device_sessions.{{ device }}">
  {{ device | _start_ }}      {{ number_of_sessions | isdigit }}  {{ user }}
</group>
"""
  return template