def get_template():
  template = """
<group name="thermal">
  {{ name }}  {{ value | isdigit }}  {{ unit }}  {{ description | _line_ | strip() }}
</group>
"""
  return template