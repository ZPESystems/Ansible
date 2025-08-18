#!/usr/bin/python3
# -*- coding: utf-8 -*-

import pexpect
import re
from collections import OrderedDict
from datetime import datetime
import os
import uuid

def _get_import_process_timeout(import_text):
    ret_timeout = 1500 # arbitrary default timeout
    count = 0
    try:
        match = re.findall(r"^(\/settings\/.+) .+$", import_text, re.MULTILINE)
        if match:
            path_list = set(match)
            if (isinstance(path_list, list)):
                count = len(path_list)
            if count > 0:
                # 15 seconds to proccess each unique path
                ret_timeout = count * 15
    except:
        pass

    return ret_timeout

def run_cli_command(cmd):
    cli_cmd = f'cli -c {cmd}'
    output = pexpect.run(cli_cmd)
    return output.decode('UTF-8').strip()

def get_cli(timeout=30):
    cmd_cli = pexpect.spawn('cli', encoding='UTF-8', timeout=timeout)
    cmd_cli.setwinsize(500, 250)
    cmd_cli.expect_exact('/]# ')
    cmd_cli.sendline('.sessionpageout undefined=no')
    cmd_cli.expect_exact('/]# ')
    return cmd_cli


def get_shell(become=False):
    cmd_shell = pexpect.spawn('bash', encoding='UTF-8')
    cmd_shell.setwinsize(500, 250)
    cmd_shell.expect_exact(['$'])
    return cmd_shell

def close_cli(cmd_cli):
    cmd_cli.sendline('exit')
    cmd_cli.close()

def execute_cmd(cmd_cli, cmd):
    if 'cmd' in cmd.keys():
        cmd_cli.sendline(cmd['cmd'])
        if 'confirm' in cmd.keys() or 'restore' in cmd.keys():
            index = cmd_cli.expect_exact(['(yes, no)  :', ']# ', pexpect.EOF, pexpect.TIMEOUT])
            if index == 0:
                cmd_cli.sendline('yes')
                cmd_cli.expect_exact(']# ')
                cmd_cli.sendline('commit')
                cmd_cli.expect_exact(']# ')
            elif index == 1:
                cmd_cli.sendline('commit')
                cmd_cli.expect_exact(']# ')
        else:
            cmd_cli.expect_exact(']# ')
        output = cmd_cli.before
        output = output.replace('\r\r\n', '\r\n')
        output_dict = dict()
        if 'ignore_error' in cmd.keys():
            output_dict['error'] = False
            output_dict['stdout'] = output
            output_dict['json'] = convert_to_json(output)
            output_lines = output.splitlines()
            output_dict['stdout_lines'] = output_lines
        else:
            if "Error" in output or "error" in output:
                output_dict['error'] = True
                output_dict['json'] = convert_to_json(output)
                output_dict['stdout'] = output
            else:
                output_dict['error'] = False
                output_dict['stdout'] = output
                output_dict['json'] = convert_to_json(output)
                output_lines = output.splitlines()
                output_dict['stdout_lines'] = output_lines
    return output_dict

def get_nodegrid_os_details():
    """Returns details about the Nodegrid OS

    Returns:
        dict: Nodegrid OS details
    """
    output = run_cli_command("show /system/about")
    details = {}
    if "Error" in output or "error" in output:
        if "Error: Invalid argument:" in output:
            details["error"] = "Error getting system information"
        else:
            details["error"] = output
    for line in output.splitlines():
        if ":" in line:
            # output_dict[line] = line.split(':',1)
            key, value = line.split(':', 1)
            if key == 'software':
                version_details, version_date = value.split('(', 1)
                details['version'] = version_details.replace('v', '').strip()
                details['version_dates'] = version_date.replace(')', '').strip()
                try:
                    details['version_date'] = str(datetime.strptime(details["version_dates"], '%b %d %Y - %H:%M:%S'))
                except Exception:
                    details["error"] = "Error parsing Nodegrid version date."
                majorversion, minorversion, subversion = version_details.split('.')
                details['software_major'] = majorversion.replace('v', '').strip()
                details['software_minor'] = minorversion.strip()
                details['software_sub'] = subversion.strip()
            details[key.strip()] = value.strip()
    return details

def get_system_details():
    """Returns details about the Nodegrid System /system/about

    Returns:
        dict: Nodegrid System details
    """
    output = run_cli_command("show /system/about")
    details = {}
    if "Error" in output or "error" in output:
        if "Error: Invalid argument:" in output:
            details["error"] = "Error getting system information"
        else:
            details["error"] = output
        return details
    for line in output.splitlines():
        if ":" in line:
            key, value = line.split(':', 1)
            details[key.strip()] = value.strip()
    return details

def export_settings(cli_path):
    """Runs the export settings

    Args:
        cli_path (str): CLI Path

    Returns:
        str: Command result state: error or successful
        dict: Exported settings with empty values
        dict: All exported settings, including empty and hide values
    """
    output = run_cli_command(f'export_settings {cli_path} --plain-password --include-empty --not-enabled')
    settings = []
    all_settings = []
    state = 'error'
    if "error" in output.lower():
        return ["error",output.replace('\r\r\n', '\r\n')], settings, all_settings
    for line in output.splitlines():
        if "=" in line:
            keypath, value = line.split('=', 1)
            if line[0] != '#':
                settings.append(line.replace("\\r","").replace("\\n","").replace("\"","'").strip())
                all_settings.append(line.replace("\\r","").replace("\\n","").replace("\"","'").strip())
            else:
                if value == '':
                    settings.append(line[1:])   # add empty value
                all_settings.append(line[1:])
    return "successful", settings, all_settings

def import_settings(settings, use_config_start=True, timeout=60):
    """Runs the import settings.

    Args:
        settings (list of string): List of settings to import
        use_config_start (bool, optional): Flag to use the config_start CLI command. Defaults to True.

    Returns:
        dict: Import settings result
    """
    import_p_timeout = max([_get_import_process_timeout(("\n").join(settings)), timeout])
    output_buffer_flush_timeout = 5
    import_settings_file = f"/tmp/import_settings_{str(uuid.uuid4())}.cli"
    import_settings_log = f"/tmp/import_settings_log_{str(uuid.uuid4())}.txt"
    
    output_dict = {}
    import_status_details = []
    import_status = "succeeded"
    error_list = []

    with open(import_settings_file, "w") as f:
        for item in settings:
            f.write(item + "\n")

    failed_to_import_settings = False
    import_settings_error = None
    try:
        cmd_cli = pexpect.spawn('cli', encoding='UTF-8')
        cmd_cli.setwinsize(500, 250)
        cmd_cli.logfile = open(import_settings_log, "w")
        cmd_cli.expect_exact('/]# ', timeout=import_p_timeout)
        if use_config_start:
            cmd_cli.sendline("config_start\n")
            cmd_cli.expect_exact('/]# ', timeout=import_p_timeout)
        cmd_cli.sendline(f"import_settings --file {import_settings_file}")
        output_cmd = cmd_cli.before
        cmd_cli.expect_exact('/]# ', timeout=import_p_timeout)
    
        if use_config_start:
            cmd_cli.sendline("config_confirm")
            cmd_cli.expect_exact('/]# ', timeout=import_p_timeout)
        cmd_cli.sendline('exit')
    except pexpect.TIMEOUT as e:
        failed_to_import_settings = True
        import_settings_error = e
        output_dict['pexpect_timeout'] = f"{e}"
    except Exception as e:
        failed_to_import_settings = True
        import_settings_error = e
    finally:
        cmd_cli.close()
  
    try:
        file1 = open(import_settings_log, 'r')
        output = file1.readlines()
    except:
        output = output_cmd
        pass

    if failed_to_import_settings:
        output_dict["import_list"] = settings
        output_dict["import_status"] = "failed"
        output_dict["import_status_details"] = f"{output}"
        output_dict["import_log_file"] = f"{import_settings_log}"
        output_dict["error_list"] = [f"{import_settings_error}"]
        output_dict["import_timeout"] = [f"{import_p_timeout}"]
        return output_dict

    try:
        os.remove(import_settings_file)
        os.remove(import_settings_log)
    except OSError:
        pass

    if isinstance(output, str):
        lines = output.splitlines()
    elif isinstance(output, list):
        lines = output
    else:
        lines = []
    for line in lines: #output.splitlines():
        if "Error:" in line:
            error_list.append(line.strip().split(' ',1)[1])
        if "Result:" in line:
            settings_status = line.strip().split()
            if len(settings_status) == 4:
                import_status_details.append(dict(
                    path=settings_status[1],
                    result=settings_status[3]
                ))
                if settings_status[3] != "succeeded":
                    import_status = "failed"
                    import_status_details.append(settings_status)
            else:
                import_status = "unknown, result parsing error"
    if "Error" in output or "error" in output or len(error_list)>0:
        output_dict["state"] = 'error'
        import_status = "failed"
    else:
        output_dict["state"] = 'success'
#    output_dict["output_raw"] = output
    output_dict["import_list"] = settings
    output_dict["import_status"] = import_status
    output_dict["import_status_details"] = import_status_details
    output_dict["error_list"] = error_list
    return output_dict

def uncomment(line):
    if len(line) > 0:
        return line if line[0] != '#' else line[1:]
    return None

def settings_diff(exported_settings, new_settings, skip_keys):
    """Compares two sets of settings, returns what values were changed or were added

    Args:
        exported_settings (dict): Exported settings from Nodegrid
        new_settings (dict): New settings from the playbook
        skip_keys (dict): Keys to skip

    Returns:
        list: List of new settings
    """
    diff = []
    for line in new_settings:

        # lets skip keys which are not part of the config
        if line not in skip_keys:

            # Add unidentified field or changed values
            # the import_settings fails if this field doesn't exist
            if not any(line.strip() == uncomment(s.strip()) for s in exported_settings):
               diff.append(line.strip())

    return diff

def dict_diff(dict1, dict2):
    """Compares two dictionaries, returns what values were changed or were added
    Args:
        dict1 (dict): Primary dict, typically representing the desired state
        dict2 (dict): Secundary dict, typically representing the current state
    Returns:
        list: List of new settings
    """

    new_dict = {}
    for key, value in dict1.items():
        if key in dict2:
            # To avoid issues between numbers and strings to we convert everything to str
            if str(value) != str(dict2[key]):
                new_dict[key] = str(dict1[key])

    return new_dict


def compare_versions(version1, version2):
    """Compares semantic versions and returns the comparison result

    Args:
        version1 (str): First version to compare
        version2 (str): Second version to compare

    Returns:
        int: -1 (version1 < version2), 0 (version1 == version2), 1 (version1 > version2)
    """
    v1 = tuple(map(int, version1.split('.')))
    v2 = tuple(map(int, version2.split('.')))
    if v1 < v2:
        return -1
    elif v1 > v2:
        return 1
    else:
        return 0

def check_os_version_support():
    """Checks if the Nodegrid Os version supports this library

    Returns:
        str: The result string can be: 'error', 'unsupported', 'warning' or 'supported'
        dict: Nodegrid OS Details
    """
    nodegrid_os = get_nodegrid_os_details()
    if "error" in nodegrid_os:
        return "error","Error getting Nodegrid os details. Error: " + nodegrid_os['error'], nodegrid_os
    version = nodegrid_os['version']
    if compare_versions(version,'5.0.0') < 0:
        return "unsupported","Unsupported Nodegrid OS version. recommended 5.6.1 or higher. Current version: " + nodegrid_os['software'], nodegrid_os
    elif compare_versions(version,'5.6.0') <= 0:
        return "warning", "Not recommended and untested Nodegrid OS version, some features might not work. recommended 5.6.1 or higher. Current version: " + nodegrid_os['software'], nodegrid_os
    return "supported","", nodegrid_os

def to_list(value):
    return value if type(value) is list else [value]

def split_in_two(line, separator):
    result = [val.strip() for val in line.split(separator, 1)]
    if len(result) == 1:
        return result[0], ''
    else:
        return result

def convert_to_json(cli_output):
    # Detect if output is a table or not
    data = []

    if "===" in cli_output:     #Table content
        details = []
        lines = cli_output.strip().split('\n')
        # Find the separator line (assumed to be immediately after headers)
        separator = lines[2]
        # Determine the start and end indices of each column based on '===' spans
        header_indices = []
        last_pos = 0
        while last_pos < len(separator):
            try:
                start_index = separator.index('=', last_pos)
                end_index = start_index
                while separator[end_index] == '=':
                    end_index += 1
                header_indices.append((start_index, end_index))
                last_pos = end_index
            except ValueError as e:
                break
        # Extract headers for key names
        headers = []
        for start_index, end_index in header_indices:
            headers.append(lines[1][start_index:end_index].strip())

        # Extract path
        cmd, path = split_in_two(lines[0], ' ')

        for line in lines[3:]:  # Skip the header and separator lines
            record = {}
            try:
                if "@" not in line:
                    for idx, header in enumerate(headers):
                        start_index, end_index = header_indices[idx]
                        record[header] = line[start_index:end_index].strip()
                    details.append(record)
            except Exception as e:
                data.append({'error': str(e)})
                break

        data.append({'path': path, 'data': details})

    elif " = " in cli_output and "show" in cli_output:   # Settings Detected
        lines = cli_output.strip().split('\n')
        details = {}
        for line in lines:
            if '=' in line:
                key, value = split_in_two(line, '=')
                details[key] = value
            if ':' in line:
                key, value = split_in_two(line, ':')
                details[key] = value
            elif "show" in line:
                cmd, path = split_in_two(line, ' ')
        data.append({'path': path, 'data':details})
    elif ":" in cli_output and "show" in cli_output:   # Details Detected
        lines = cli_output.strip().split('\n')
        details = {}
        path = ''
        for line in lines:
            if ':' in line:
                key, value = split_in_two(line, ':')
                details[key] = value
            elif '=' in line:
                key, value = split_in_two(line, '=')
                details[key] = value
            elif "show" in line:
                cmd, path = split_in_two(line, ' ')
        data.append({'path': path, 'data':details})
    elif "export_settings" in cli_output:
        lines = cli_output.strip().split('\n')
        details = {}
        path = ''
        for line in lines[1:]:  # skip the first line which is a command line
            if '=' in line:
                path, content =  split_in_two(line, ' ')
                key, value = split_in_two(content, '=')
                details[key] = value
        data.append({'path': path, 'data':details})
    elif "set " in cli_output:
        lines = cli_output.strip().split('\n')
        for line in lines[1:]:
            if len(line.strip()) == 0 or "@" in line:
                continue
            data.append(line.strip())
    elif "ls" in cli_output:
        lines = cli_output.strip().split('\n')
        details = {}
        paths = []
        for line in lines[1:]:
            if "@" not in line:
                data.append({'path': line.strip()[:-1]})
    # #else:       # other output

    return data

def result_failed(msg):
    return {'failed': True, 'changed': False, 'msg': msg}

def field_not_exist(suboptions, field_name):
    return not field_exist(suboptions, field_name)

def field_exist(suboptions, field_name):
    if field_name in suboptions and len(suboptions[field_name]) > 0:
        return True
    return False

def run_option_adding_field_in_the_path_and_append_path(option, run_opt, field_name, append_path, delete_field_name=False):
    """Calls the function run_option adding the field name in the CLI path

    Args:
        option (dict): Option to apply
        run_opt (dict): Dictionary with extra import options
        field_name (str): Field name to add in th CLI path
        delete_field_name (bool): If True, the field_name will be deleted from the options

    Returns:
        dict: Result of import
    """
    suboptions = option['suboptions']
    if field_exist(suboptions, field_name):
        option['cli_path'] += f"/{suboptions[field_name]}/{append_path}"
        if delete_field_name:
            del option['suboptions'][field_name]
        return run_option(option, run_opt)
    else:
        return {'failed': True, 'changed': False, 'msg': f"Field '{field_name}' is required"}

def run_option_adding_field_in_the_path(option, run_opt, field_name, delete_field_name=False):
    """Calls the function run_option adding the field name in the CLI path

    Args:
        option (dict): Option to apply
        run_opt (dict): Dictionary with extra import options
        field_name (str): Field name to add in th CLI path
        delete_field_name (bool): If True, the field_name will be deleted from the options

    Returns:
        dict: Result of import
    """
    suboptions = option['suboptions']
    if field_exist(suboptions, field_name):
        option['cli_path'] += f"/{suboptions[field_name]}"
        if delete_field_name:
            del option['suboptions'][field_name]
        return run_option(option, run_opt)
    else:
        return {'failed': True, 'changed': False, 'msg': f"Field '{field_name}' is required"}

def run_option(option, run_opt):
    """Applies the option on the Nodegrid

    Applies the option on the Nodegrid following these steps:
        1. Convert the option in a list of settings
        2. Export the settings of the path
        3. Compare the settings to find the difference between them
        4. Import new setttings on the Nodegrid

    Args:
        option (dict): Option to apply
            - cli_path (str): CLI path to import the settings
            - settings (list of str): Optional field, with a list of settings (path key=value). If undefined the list of settings will be created based on the option 'cli_path'
        run_opt (dict): Dictionary with extra import options
            - skip_invalid_keys (bool): If True, ivalid field will be removed
            - check_mode (bool): If True, does not apply the diff
            - use_config_start_global (bool): If True, use the CLI feature config_start/config_end to apply the all settings if no error happened
            - no_diff (bool): If True, does not compare the new settings with the current, always apply the new ones

    Returns:
        dict: Result of import
    """
    suboptions = option['suboptions']
    cli_path = option['cli_path']
    skip_invalid_keys = run_opt['skip_invalid_keys']
    check_mode = run_opt['check_mode']
    use_config_start_global = run_opt['use_config_start_global']
    if 'no_diff' in run_opt and run_opt['no_diff']:
        no_diff = True
    else:
        no_diff = False

    result = dict(
        changed=False,
        failed=False,
        message='',
        export_result='',
        skip_keys = []
    )

    # Get or format settings
    new_settings = []
    if 'settings' in option:
        new_settings = option['settings']
    else:
        new_settings = format_settings(cli_path, suboptions)

    if no_diff:
        diff = new_settings
    else:
        # Lets export the settings to the cli path
        state, exported_settings, exported_all_settings = export_settings(cli_path)
        if "error" in state:
            result['export_result'] = state[1]
        else:
            result['export_result'] = state
            # Lets create a list of keys to skip
            if skip_invalid_keys:
                result['skip_keys'] = get_skip_keys(new_settings, exported_all_settings)

        # Lets compare the current config with the specified configuration
        diff = settings_diff(exported_settings, new_settings, result['skip_keys'] )

    # The module supports diff mode, which will display the configuration
    # changes which will be performed on the connection
    prepared_output = str()
    for item in diff:
        prepared_output += item + "\r\n"
    result['diff'] = prepared_output

    # if the user is working with this module in only check mode we do not
    # want to make any changes to the environment, just return the current
    # state with no modifications
    if check_mode:
        if len(diff) > 0:
            result['changed'] = True
        return result

    # manipulate or modify the state as needed (this is going to be the
    # part where your module will do what it needs to do)
    if len(diff) > 0:
        result['changed'] = True
        if 'import_func' in option:
            import_func = option['import_func']
            import_result = import_func(data=dict(
                option=option,
                run_opt=run_opt,
                exported_settings=exported_settings,
                diff=diff,
                use_config_start=use_config_start_global
            ))
        else:
            import_result = import_settings(diff, use_config_start=use_config_start_global, timeout=run_opt.get('timeout',60))

        result['import_result'] = import_result
        if import_result['import_status'] == 'succeeded':
            result['message'] = 'Import was successful'
        else:
            if len(import_result['error_list']) > 0:
                result['message'] = ', '.join(import_result['error_list'])
            result['msg'] = 'Import failed'
            result['failed'] = True
            result['import_settings_error'] = import_result
            return result
    else:
        result['changed'] = False
        result['message'] = 'No change required'
    return result

def run_option_no_diff(option, run_opt):
    """Applies the option on the Nodegrid

    Applies the option on the Nodegrid following these steps:
        1. Convert the option in a list of settings
        2. Import all the settings on the Nodegrid

    Args:
        option (dict): Option to apply
        run_opt (dict): Dictionary with extra import options

    Returns:
        dict: Result of import
    """
    run_opt['no_diff'] = True
    return run_option(option, run_opt)

def run_option_all_settings(option, run_opt, compare_path_func, get_next_path_func, remove_invalid_setting=False):
    """Applies the option on the Nodegrid

    Applies the option on the Nodegrid following these steps:
        1. Export the settings of the path
        2. (Optional) Remove invalid settings
        3. Update/Add the exported settings values with the new options values
        4. Import new setttings on the Nodegrid

    Args:
        option (dict): Option to apply
        run_opt (dict): Dictionary with extra import options

    Returns:
        dict: Result of import
    """
    suboptions = option['suboptions']
    copied_options = suboptions.copy()

    # Export current settings
    state, exported_settings, exported_all_settings = export_settings(option['cli_path'])
    if "error" in state:
        return result_failed(f"Failed exporting settings on {option['cli_path']}. Error: {state[1]}")

    # Remove invalid settings
    if remove_invalid_setting:
        for key, value in copied_options.items():
            if not any(key in item for item in exported_settings):
                del copied_options[key]

    # Update the exported settings values
    data = settings_to_dict(exported_settings)
    last_path = None
    changed = False
    for path, current_options in data.items():
        last_path = path
        if compare_path_func(path):
            for key, value in current_options.items():
                if key in copied_options:
                    if copied_options[key] != value:
                        current_options[key] = copied_options[key]
                        changed = True
                    del copied_options[key]
            # Add remaining fields
            if not remove_invalid_setting:
                for key, value in copied_options.items():
                    current_options[key] = value
                    changed = True
            copied_options = None
            break

    # Add new settings
    if copied_options is not None:
        next_path = get_next_path_func(last_path)
        if next_path is not None:
            data[next_path] = copied_options
            changed = True

    if changed:
        # Convert dict to  settings list keeping the settings order
        option['settings'] = dict_to_settings(data)
        return run_option_no_diff(option, run_opt)
    return result_nochanged()

def format_settings(path, in_dict):
    out_list = []
    if type(in_dict) in [dict, OrderedDict]:
        for key, value in in_dict.items():
            if type(value) is dict:
                out_list.extend( format_settings(f'{path}/{key}', value) )
            else:
                if type(value) is str and " " in value:
                    out_list.append(f"{path} {key}=\'{value}\'")
                else:
                    out_list.append(f"{path} {key}={value}")
    return out_list

def get_skip_keys(new_settings, exported_all_settings):
    skip_keys = []
    for line in new_settings:
        keypath, value = line.split('=')
        if not any(keypath in s for s in exported_all_settings):
            skip_keys.append(line)
    return skip_keys

def read_table(cli_path):
    cmd = f"show {cli_path}"
    cmd_cli = pexpect.spawn('cli', encoding='UTF-8')
    cmd_cli.setwinsize(500, 10000)
    cmd_cli.expect_exact('/]# ')
    cmd_cli.sendline('.sessionpageout undefined=no')
    cmd_cli.expect_exact('/]# ')
    cmd_cli.sendline(cmd)
    cmd_cli.expect_exact('/]# ')
    output = cmd_cli.before
    cmd_cli.close()
    if "Error" in output or "error" in output:
        return "error", output
    else:
        table = {
            "header": [],
            "rows": []
        }
        cnt = 0
        for line in output.splitlines()[1:-1]:
            if len(line) > 0:
                row = line.split()
                if cnt == 0:
                    table["header"].append(row)
                elif cnt > 1:
                    table["rows"].append(row)
                cnt += 1

    return "successful", table

def read_table_row(table, col_index, col_value):
    for row in table['rows']:
        if row[col_index] == col_value:
            return row
    return None

def read_path_option(cli_path, option, separators=[":","="]):
    cmd = f"show {cli_path} {option}"
    cmd_cli = pexpect.spawn('cli', encoding='UTF-8')
    cmd_cli.setwinsize(500, 10000)
    cmd_cli.expect_exact('/]# ')
    cmd_cli.sendline('.sessionpageout undefined=no')
    cmd_cli.expect_exact('/]# ')
    cmd_cli.sendline(cmd)
    cmd_cli.expect_exact('/]# ')
    output = cmd_cli.before
    cmd_cli.close()
    if "Error" in output or "error" in output:
        return "error", output
    else:
        result = {
            "path": cli_path,
            "option": option,
            "value": ""
        }

        for line in output.splitlines()[1:-1]:
            if len(line) > 0:
                for separator in separators:
                    row = line.split(separator)
                    if len(row) > 1:
                        result["value"] = row[1].strip()

    return "successful", result

def settings_to_dict(settings_string_list):
    groups = {}
    for item in settings_string_list:
        path, key_value = item.split(" ", 1)    # Split by the first space to get path and key=value
        path = uncomment(path.strip())
        # In Python 3.7 and later, dictionaries maintain the insertion order of items.
        # When you iterate over a dictionary using .items(), the items will appear
        # in the same order they were added.
        if path not in groups:
            groups[path] = {}
        key, value = key_value.strip().split('=',1)
        groups[path][key] = value
    return groups

def dict_to_settings(settings_dict):
    settings = []
    for path, options in settings_dict.items():
        for key, value in options.items():
            settings.append(f"{path} {key}={value}")
    return settings

def result_failed(msg):
    return {'failed': True, 'changed': False, 'msg': msg}

def result_nochanged(msg = 'No change required'):
    return {'failed': False, 'changed': False, 'msg': msg}
