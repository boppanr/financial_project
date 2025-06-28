import os
import datetime
import re

# Directory where logs are stored
LOG_DIR = "./logs"
DAYS_TO_KEEP = 3

# Regular expression to match log filenames like debug_20250603_091033.log
LOG_FILE_PATTERN = re.compile(r"^(debug|info)_(\d{8})_\d{6}\.log$")

def is_older_than_days(file_date_str, days):
    try:
        file_date = datetime.datetime.strptime(file_date_str, "%Y%m%d")
        return (datetime.datetime.now() - file_date).days > days
    except ValueError:
        return False

def cleanup_logs():
    if not os.path.exists(LOG_DIR):
        print(f"No log directory found at: {LOG_DIR}")
        return

    for filename in os.listdir(LOG_DIR):
        match = LOG_FILE_PATTERN.match(filename)
        if match:
            _, date_str = match.groups()
            if is_older_than_days(date_str, DAYS_TO_KEEP):
                file_path = os.path.join(LOG_DIR, filename)
                try:
                    os.remove(file_path)
                    print(f"Deleted old log: {filename}")
                except Exception as e:
                    print(f"Failed to delete {filename}: {e}")
        else:
            print(f"Skipped non-log file: {filename}")

if __name__ == "__main__":
    cleanup_logs()
