def get_template():
  template = """
<group name="memory_usage">
  {{ memory_type }}  {{ total_kb | isdigit }}  {{ used_kb }}  {{ free_kb }}
</group>
"""
  return template