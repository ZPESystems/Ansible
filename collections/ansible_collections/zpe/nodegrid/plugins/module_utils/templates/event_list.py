def get_template():
    template = """
<group name="event_list">
event_number  description                                               occurrences  category       {{ _headers_ | columns(4) }}
</group>
"""
    return template