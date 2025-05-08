from ansible.errors import AnsibleFilterError

def to_cmd(value):
    if not isinstance(value, str):
        raise AnsibleFilterError("The value must be a string")
    output = []
    for line in value.splitlines():
        output.append({'cmd': line})
    return output

def to_settings(value):
    if not isinstance(value, str):
        raise AnsibleFilterError("The value must be a string")
    return value.splitlines()

class FilterModule(object):
    def filters(self):
        return {
            'to_cmd': to_cmd,
            'to_settings': to_settings,
        }
