# imports
import re
import os
from collections import Counter
from datetime import datetime

# Read all log files
try:
    log_data = ''
    log_files = os.listdir("logs")
    for file in log_files:
        file_path = os.path.join("logs", file)
        with open(file_path, 'r') as f:
            log_data += f.read()
except FileNotFoundError:
    print("File not found.")
    exit()

# Extract data using regex
failed_user_ip = re.findall(r"Failed password for (\w+) from (\d+\.\d+\.\d+\.\d+)", log_data)
successful_user_ip= re.findall(r"Accepted password for (\w+) from (\d+\.\d+\.\d+\.\d+)", log_data)

# Separate users and IPs
# 1. Failed Login Details
failed_user = [user for user, ip in failed_user_ip]
failed_ip = [ip for user, ip in failed_user_ip]

# 2. Successful Login Details
successful_user = [user for user, ip in successful_user_ip]
successful_ip = [ip for user, ip in successful_user_ip]

# Generate Counters
failed_ip_count = Counter(failed_ip)
failed_user_count = Counter(failed_user)

successful_ip_count = Counter(successful_ip)
successful_user_count = Counter(successful_user)

# Calculate statistics
failed_login_count = len(failed_ip)
successful_login_count = len(successful_ip)
most_target_user, target_count = failed_user_count.most_common(1)[0]
top_attacker, top_attack_count = failed_ip_count.most_common(1)[0]

# Detect suspicious IPs
ALERT_THRESHOLD = 5

# Generate report
if not os.path.exists("Reports"):
    os.makedirs("Reports")

report_path = os.path.join("Reports", "Report.txt")
generated_time = datetime.now().strftime("%Y-%m-%d %H:%M")
with open(report_path,'w') as f:
    f.write("=====================================================\n")
    f.write("SSH ACCESS & FAILED LOGIN ANALYZER\n")
    f.write("=====================================================\n")
    f.write("\n")
    f.write(f"Generated : {generated_time}\n")
    f.write("\nAnalyzed Files:\n")
    f.write("----------------\n")
    for i in log_files:
        f.write(f"{i:>12}\n")
    f.write("\n\n")

    f.write("=====================================================\n")
    f.write("SUSPICIOUS IPs\n")
    f.write("=====================================================\n")
    for ip, count in failed_ip_count.most_common():
        if count >= ALERT_THRESHOLD:
            f.write(f"{ip:<15} --> {count:>2} Attempts\n")
    f.write("\n\n")

    f.write("=====================================================\n")
    f.write("TOP ATTACKING IPs\n")
    f.write("=====================================================\n")
    for ip,count in failed_ip_count.most_common():
        f.write(f"{ip:<15} --> {count:>2} Attempts\n")
    f.write("\n\n")

    f.write("=====================================================\n")
    f.write("MOST TARGETED USERS\n")
    f.write("=====================================================\n")
    for user,count in failed_user_count.most_common():
        f.write(f"{user:<10} --> {count:>3} Attempts\n")
    f.write("\n\n")

    f.write("=====================================================\n")
    f.write("SUCCESSFUL LOGIN USERS\n")
    f.write("=====================================================\n")
    for user,count in successful_user_count.most_common():
        f.write(f"{user:<10} --> {count:>3} Logins\n")
    f.write("\n\n")

    f.write("=====================================================\n")
    f.write("SUMMARY\n")
    f.write("=====================================================\n")
    f.write("\n")
    f.write(f"Files Analyzed       : {len(log_files)}\n")
    f.write(f"Failed Logins        : {failed_login_count}\n")
    f.write(f"Successful Logins    : {successful_login_count}\n")
    f.write("\n")
    f.write(f"Unique Attacker IPs  : {len(failed_ip_count)}\n")
    f.write(f"Targeted Users       : {len(failed_user_count)}\n")
    f.write("\n")
    f.write(f"Top Attacking IP     : {top_attacker} ({top_attack_count} Attempts)\n")
    f.write(f"Most Targeted User   : {most_target_user} ({target_count} Attempts)\n")
