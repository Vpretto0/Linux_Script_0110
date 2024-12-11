Linux Security One-Liner Commands
General System Information
Retrieve OS Information
uname -a && cat /etc/*-release
Fetches detailed OS information to verify system integrity.

List Installed Packages and Versions
dpkg -l | less
Displays all installed packages and their versions for identifying outdated or vulnerable applications.

Process and Service Monitoring
List Processes Running as Root
ps aux | grep '^root'
Finds processes running with root privileges to identify unauthorized or suspicious services.

List Running Services
systemctl list-units --type=service
Displays all active services on the system for quick service status checks.

File and Directory Analysis
Find World-Writable Files
find / -type f -perm -0002 -exec ls -l {} \; 2>/dev/null
Identifies files with world-writable permissions, which could be a security risk.

Find SUID and SGID Files
find / -perm /6000 -type f -exec ls -l {} \; 2>/dev/null
Lists files with SUID/SGID permissions that could be exploited for privilege escalation.

Find Hidden Files and Directories
find / -type f -name ".*" -not -path "/proc/*" -exec ls -l {} \; 2>/dev/null
Searches for hidden files outside standard locations to uncover potentially malicious files.

Find Files Owned by No User or Group
find / -nouser -o -nogroup -exec ls -l {} \; 2>/dev/null
Detects orphaned files, which can be an indication of misconfiguration or tampering.

Find Recently Modified Files (Last 24 Hours)
find / -type f -mtime -1 -exec ls -lh {} \; 2>/dev/null
Lists files modified within the last 24 hours to detect recent suspicious activity.

Find Files Larger Than 100MB
find / -type f -size +100M -exec ls -lh {} \; 2>/dev/null
Identifies unusually large files, which could indicate unauthorized data storage.

Scheduled Jobs
List All Cron Jobs
for user in $(cut -f1 -d: /etc/passwd); do crontab -u $user -l 2>/dev/null; done
Displays scheduled tasks for all users to identify unauthorized or malicious jobs.
Network and Connection Monitoring
List Active Network Connections and Listening Ports
netstat -tuln
Lists all active network connections to detect unauthorized or suspicious activity.

Find Open Ports
ss -tuln
Shows all open ports on the system for monitoring unauthorized services.

User and Permission Management
List Users with UID 0 (Superusers)
awk -F: '($3 == 0) {print $1}' /etc/passwd
Identifies all superuser accounts on the system.

Check Password Policies
cat /etc/login.defs | grep -E 'PASS_MIN_DAYS|PASS_MAX_DAYS|PASS_WARN_AGE'
Displays password age policies to ensure they align with security best practices.

List Last Logins for All Users
lastlog
Provides an overview of user login history to detect unauthorized access.

Symbolic Links
Find Broken Symbolic Links
find / -xtype l -exec ls -l {} \; 2>/dev/null
Identifies broken symbolic links that may indicate tampered or misconfigured files.
Additional System Checks
Check for System Logs with Errors
journalctl -p 3 -xb
Displays recent logs with priority level 3 (errors) to troubleshoot issues.

Search for Unmounted Partitions
lsblk -f | grep -vE '(SWAP|Mounted)'
Lists unmounted partitions to detect unused or misconfigured disk space.

Identify Core Dumps (Large System Error Files)
find / -name core -exec ls -lh {} \; 2>/dev/null
Searches for core dump files which may indicate application crashes or vulnerabilities.

Usage Tips:
Redirect Output: Append > output.txt to save results to a file for later review.
Example: ps aux | grep '^root' > root_processes.txt
Filter Results: Use | grep to narrow down outputs to specific keywords.
Example: netstat -tuln | grep 'LISTEN'