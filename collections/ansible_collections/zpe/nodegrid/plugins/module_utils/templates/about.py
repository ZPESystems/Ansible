def get_template():
    template = """
<group name="about">
system: {{ system | _line_ | strip() }}
licenses: {{ licenses }}
software: v{{ version }} {{ version_date | _line_ | strip() }}
cpu: {{ cpu | _line_ | strip() }}
cpu_cores: {{ cpu_cores }}
bogomips_per_core: {{ bogomips | _line_ | strip() }}
serial_number: {{ serial_number }}
uptime: {{ uptime_days }} days,  {{ uptime_hours }} hours,  {{ uptime_minutes }} minutes
boot mode: {{ boot_mode }}
secure boot: {{ secure_boot }}
model: {{ model }}
part_number: {{ part_number }}
bios_version: {{ bios_version }}
psu: {{ psu }}
revision tag: {{ revision_tag | _line_ | strip() }}
bios sed compatible: {{ bios_sed }}
ssd sed compatible: {{ ssd_sed }}
</group>
"""
    return template