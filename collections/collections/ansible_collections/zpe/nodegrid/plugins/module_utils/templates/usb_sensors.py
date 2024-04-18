def get_template():
  template = """
<group name="usb_sensors">
  {{ name }}  {{ value | contains('.') }}  {{ unit }}  {{ description | _line_ | strip() }}
</group>
"""
  return template