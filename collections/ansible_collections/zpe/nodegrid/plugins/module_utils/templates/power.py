def get_template():
  template = """
<group name="power_supply">
  {{ name }}  {{ value | contains('ON','OFF')}}  {{ unit }}  {{ description | _line_ | strip() }}
</group>
<group name="power.{{ unit }}">
  {{ name }}  {{ value }}  {{ unit | contains('Watts','Amps') }}  {{ description | _line_ | strip() }}
</group>
"""
  return template