def get_template():
  template = """
<group name="disk_usage">
  {{ partition }}  {{ size | isdigit }}  {{ used_kb }}  {{ available_kb }}  {{ use }}  {{ description }}
</group>
"""
  return template