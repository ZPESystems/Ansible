# -*- coding: utf-8 -*-

from ansible.plugins.action import ActionBase
import os
import re
from datetime import datetime, timedelta
from operator import itemgetter
from dateutil.relativedelta import relativedelta
from pathlib import Path
import shutil
from ansible.utils.display import Display

display = Display()

def get_timestamp(file_name, backup_file_extension=".tar.gz"):

    timestamp_str = file_name.split('-')[-1].removesuffix(backup_file_extension)
    timestamp = datetime.strptime(timestamp_str, "%Y%m%dT%H%M%SZ")
    return timestamp

def daily_backup(path, device_name, backup_file_extension=".tar.gz"):
    if not os.path.isdir(os.path.join(path,'daily',device_name)):
        return []
    #pattern = r"^\b" + re.escape(device_name) + r"-(\d{8})T(\d{6})Z\.tar\.gz\b$"
    pattern = r"^\b" + re.escape(device_name) + r"-(\d{8})T(\d{6})Z" + re.escape(backup_file_extension) + r"\b$"
    daily_files = [(file,get_timestamp(file, backup_file_extension=backup_file_extension)) for file in os.listdir(os.path.join(path,'daily',device_name)) if re.search(pattern, file)]
    if not daily_files:
        return []
    files_to_be_deleted = set()
    now = datetime.now()
    one_week_ago = now - timedelta(days=7)
    # Filter files older than 7 days
    list(map(files_to_be_deleted.add , [afile for afile in daily_files if afile[1] < one_week_ago]))
    
    #Filter files per each day for the last 7 days, keeping only 1 file per day
    current_date = one_week_ago
    files_set = set(daily_files) - files_to_be_deleted
    while current_date <= now:
        files_per_day = set()
        list(map(files_per_day.add, [file for file in files_set if file[1].date() == current_date.date()]))
        if len(files_per_day) > 1:
            todelete = sorted(files_per_day, key=itemgetter(1))
            list(map(files_to_be_deleted.add, todelete[:-1]))
        files_set -= files_per_day
        current_date += timedelta(days=1)
    current_week_start = now - timedelta(days=now.weekday())
    start_of_week = current_week_start - timedelta(weeks=1)
    end_of_week = start_of_week + timedelta(days=6)
    # 2. Change the day to the 1st of the current month
    first_day_this_month = now.replace(day=1)
    # 3. Subtract 1 day to roll back to the last day of the previous month
    last_day_prev_month = first_day_this_month - timedelta(days=1)

    for file in set(daily_files):
        #display.vvv(f"end_of_week: {end_of_week.date()}, end_of_month: {last_day_prev_month.date()}, file_date: {file[1].date()}")
        if file[1].date() == end_of_week.date() and not os.path.isfile(os.path.join(path,'weekly',device_name,file[0])):
            shutil.copy(os.path.join(path,'daily',device_name,file[0]), os.path.join(path,'weekly',device_name,file[0]))
        if file[1].date() == last_day_prev_month.date() and not os.path.isfile(os.path.join(path,'monthly',device_name,file[0])):
            shutil.copy(os.path.join(path,'daily',device_name,file[0]), os.path.join(path,'monthly',device_name,file[0]))
    return [file[0] for file in files_to_be_deleted]

def weekly_backup(path, device_name, backup_file_extension=".tar.gz"):
    # Define your directory path
    dir_path = Path(os.path.join(path,'weekly',device_name))
    # Create the directory if it doesn't exist
    dir_path.mkdir(parents=True, exist_ok=True)

    #pattern = r"^\b" + re.escape(device_name) + r"-(\d{8})T(\d{6})Z\.tar\.gz\b$"
    pattern = r"^\b" + re.escape(device_name) + r"-(\d{8})T(\d{6})Z" + re.escape(backup_file_extension) + r"\b$"
    weekly_files = [(file,get_timestamp(file, backup_file_extension=backup_file_extension)) for file in os.listdir(os.path.join(path,'weekly',device_name)) if re.search(pattern, file)]
    if not weekly_files:
        return []
    files_to_be_deleted = set()
    now = datetime.now()
    
    current_week_start = now - timedelta(days=now.weekday())
    one_month_ago =  current_week_start - timedelta(weeks=4)
    # Filter files older than 30 days
    list(map(files_to_be_deleted.add , [afile for afile in weekly_files if afile[1].date() < one_month_ago.date()]))
    files_set = set(weekly_files) - files_to_be_deleted
    for i in range(1,5):
        start_of_week = current_week_start - timedelta(weeks=i)
        end_of_week = start_of_week + timedelta(days=6)
        files_week = set([file for file in files_set if start_of_week.date() <= file[1].date() <= end_of_week.date()])
        if len(files_week) > 1:
            todelete = sorted(files_week, key=itemgetter(1))
            list(map(files_to_be_deleted.add, todelete[:-1]))
        files_set -= files_week
    return [file[0] for file in files_to_be_deleted]


def monthly_backup(path, device_name, backup_file_extension=".tar.gz"):
    # Define your directory path
    dir_path = Path(os.path.join(path,'monthly',device_name))
    # Create the directory if it doesn't exist
    dir_path.mkdir(parents=True, exist_ok=True)
    #pattern = r"^\b" + re.escape(device_name) + r"-(\d{8})T(\d{6})Z\.tar\.gz\b$"
    pattern = r"^\b" + re.escape(device_name) + r"-(\d{8})T(\d{6})Z" + re.escape(backup_file_extension) + r"\b$"
    monthly_files = [(file,get_timestamp(file, backup_file_extension=backup_file_extension)) for file in os.listdir(os.path.join(path,'monthly',device_name)) if re.search(pattern, file)]
    if not monthly_files:
        return []
    files_to_be_deleted = set()
    now = datetime.now()
    one_year_ago = now - relativedelta(months=12)
    # Filter files older than 30 days
    list(map(files_to_be_deleted.add , [afile for afile in monthly_files if afile[1] < one_year_ago]))
    
    #Filter files per each 7 days for the last 4 weeks, keeping only 1 file per week
    files_set = set(monthly_files) - files_to_be_deleted

    for month_number in range(12,-1,-1):
        target = now - relativedelta(months=month_number)
        files_month = set([file for file in files_set if file[1].year == target.year and file[1].month == target.month])
        if len(files_month) > 1:
            todelete = sorted(files_month, key=itemgetter(1))
            list(map(files_to_be_deleted.add, todelete[:-1]))
        files_set -= files_month
    return [file[0] for file in files_to_be_deleted]

# Function to validate if a file exists and if it is readable            
def validate_path(path, access_priv = os.F_OK | os.R_OK | os.W_OK):
    if not(os.path.isdir(path)):
        raise Exception(f"The path '{path}' does not exist.")
    elif not os.access(path, access_priv):
        raise Exception(f"The path '{path}' is not readable/writable.")

class ActionModule(ActionBase):
    # Action plugins must set BYPASS_HOST_LOOP to False if they need to run per host
    BYPASS_HOST_LOOP = False

    def run(self, tmp=None, task_vars=None):
        # Always invoke the parent run method first to initialize base tasks
        result = super(ActionModule, self).run(tmp, task_vars)
        
        try:
            backup_path = self._task.args.get('backup_path')
            backup_file_extension = self._task.args.get('backup_file_extension', ".tar.gz")
            inventory_hostname = task_vars.get('inventory_hostname')
            validate_path(backup_path)
            files_to_be_deleted = dict(daily=(),weekly=(),monthly=())
            files_to_be_deleted['daily'] = daily_backup(backup_path, inventory_hostname, backup_file_extension=backup_file_extension)
            files_to_be_deleted['weekly'] = weekly_backup(backup_path, inventory_hostname, backup_file_extension=backup_file_extension)
            files_to_be_deleted['monthly'] = monthly_backup(backup_path, inventory_hostname, backup_file_extension=backup_file_extension)
            result['debug'] = f"{files_to_be_deleted}"
            path = Path(backup_path)
            for freq, files in files_to_be_deleted.items():
                for file in files:
                    Path(path.joinpath(freq,inventory_hostname,file)).unlink(missing_ok=True)
            result['changed'] = True
        except Exception as e:
            result['failed'] = True
            result['msg'] = f"{e}"
        return result
