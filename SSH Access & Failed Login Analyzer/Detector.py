import re
from collections import Counter
from datetime import datetime

# Reading auth.log
try:
    with open("auth.log", 'r') as f:
        logs = f.read()
except FileNotFoundError:
    print("File 'auth.log' not found.")
    exit()

# Finding IP addresses of failed Login using Regex
ips = re.findall(r"Failed login from (\d+\.\d+\.\d+\.\d+)",logs)

# Counting number of attempts in each IP address
ips_count = Counter(ips)

# Setting the Threshold to 3 ( Editable )
alert_threshold = 3

# Splitting the IP address based on threshold into two arrays : alerts and normal
alerts = []
normal = []

# Counting total number of failed attempts
failed_count = sum(ips_count.values())

# sus_ip are the IP address that has count >= threshold, normal_ip are IP address below threshold
sus_ip_count = 0
normal_ip_count = 0

for ip,count in ips_count.items():
    if count >= alert_threshold:
        alerts.append((ip,count))
        sus_ip_count += 1
    else:
        normal.append((ip,count))
        normal_ip_count += 1

# Counting total number of IP addresses
unique_ip_count = sus_ip_count + normal_ip_count

# Sorting the arrays based on count value, so that greater value comes at top
alerts.sort(key=lambda x: x[1], reverse=True)
normal.sort(key=lambda x: x[1], reverse=True)

# Writing the Report
with open("report.txt","w") as f:
    f.write("================================\n")
    f.write("    Failed Login Detector v1    \n")
    f.write("================================\n")
    f.write(f"Report Generated at: {datetime.now().strftime("%d-%m-%y %H:%M")}\n")
    f.write("\n\n")
    f.write("-----------------------------\n")
    f.write("        Suspicious IPs       \n")
    f.write("-----------------------------\n")
    f.write("\n")
    for ip,count in alerts:
        f.write(f"{ip}\t --> {count} Attempts\n")
    f.write("\n\n")
    f.write("-----------------------------\n")
    f.write("          Normal IPs         \n")
    f.write("-----------------------------\n")
    f.write("\n")
    for ip,count in normal:
        f.write(f"{ip}\t --> {count} Attempts\n")
    f.write("\n\n")
    f.write("------------------------------\n")
    f.write("           Summary            \n")
    f.write("------------------------------\n")
    f.write(f"Suspicious IPs: {sus_ip_count} IPs\n")
    f.write(f"Normal IPs: {normal_ip_count} IPs\n")
    f.write(f"Unique IPs: {unique_ip_count} IPs\n")
    f.write(f"Total Failed Attempts: {failed_count} Attempts\n")