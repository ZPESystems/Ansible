def get_template():
  template = """
<group name="io_ports">
  {{ name }}  {{ value | contains('Low','Open')}}  {{ direction }}  {{ description | _line_ | strip() }}
</group>
"""
  return template