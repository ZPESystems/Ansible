def get_template():
  template = """
<group name="cpu_usage">
  {{ user | isdigit }}       {{ system }}         {{ idle }}      {{ waiting }}
</group>
"""
  return template