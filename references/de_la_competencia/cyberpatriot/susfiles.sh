#!/bin/bash

REPORT_FILE="suspicious_files_report.txt"
MAX_RESULTS=10 # Limit results to reduce noise
EXCLUDE_PATHS="\( -path /proc -o -path /sys -o -path /run -o -path /usr/lib -o -path /boot \)"
touch "$REPORT_FILE"

# Logging function
log() {
    echo "[$(date)] $1" | tee -a "$REPORT_FILE"
}

log "Suspicious File Detection Script Started"

# 1. Find world-writable files
log "Scanning for world-writable files..."
find / -type f -perm -0002 $EXCLUDE_PATHS -prune -o -type f -perm -0002 -exec ls -l {} \; 2>/dev/null | head -n $MAX_RESULTS | tee -a "$REPORT_FILE"
log "World-writable files scan completed."

# 2. Find executable files in unusual directories
log "Scanning for executable files in unusual locations (e.g., /tmp, /var/tmp)..."
find /tmp /var/tmp /dev/shm -type f -perm -u+x -exec ls -l {} \; 2>/dev/null | head -n $MAX_RESULTS | tee -a "$REPORT_FILE"
log "Executable file scan in temporary directories completed."

# 3. Find hidden files and directories
log "Scanning for hidden files and directories..."
find / -name ".*" $EXCLUDE_PATHS -prune -o -name ".*" -exec ls -ld {} \; 2>/dev/null | head -n $MAX_RESULTS | tee -a "$REPORT_FILE"
log "Hidden files and directories scan completed."

# 4. Find files with suspicious extensions
log "Scanning for files with suspicious extensions (e.g., .exe, .bat, .tmp, .log)..."
find / -type f \( -name "*.exe" -o -name "*.bat" -o -name "*.tmp" -o -name "*.log" -o -name "*.js" \) $EXCLUDE_PATHS -prune -o -type f -exec ls -l {} \; 2>/dev/null | head -n $MAX_RESULTS | tee -a "$REPORT_FILE"
log "Suspicious extension scan completed."

# 5. Find files owned by no user or group
log "Scanning for files owned by no user or no group..."
find / -nouser -o -nogroup $EXCLUDE_PATHS -prune -o -exec ls -l {} \; 2>/dev/null | head -n $MAX_RESULTS | tee -a "$REPORT_FILE"
log "Orphaned file scan completed."

# 6. Find files larger than 100MB
log "Scanning for unusually large files (greater than 100MB)..."
find / -type f -size +100M $EXCLUDE_PATHS -prune -o -type f -size +100M -exec ls -lh {} \; 2>/dev/null | head -n $MAX_RESULTS | tee -a "$REPORT_FILE"
log "Large file scan completed."

# 7. Find broken symbolic links
log "Scanning for broken symbolic links..."
find / -xtype l $EXCLUDE_PATHS -prune -o -xtype l -exec ls -l {} \; 2>/dev/null | head -n $MAX_RESULTS | tee -a "$REPORT_FILE"
log "Broken symbolic link scan completed."

# 8. Check for SUID or SGID files
log "Scanning for SUID or SGID files (potential privilege escalation risk)..."
find / -perm /6000 -type f $EXCLUDE_PATHS -prune -o -perm /6000 -type f -exec ls -l {} \; 2>/dev/null | head -n $MAX_RESULTS | tee -a "$REPORT_FILE"
log "SUID and SGID file scan completed."

# 9. Find files in /root
log "Scanning for files in /root (potential privilege abuse)..."
find /root -type f -exec ls -l {} \; 2>/dev/null | head -n $MAX_RESULTS | tee -a "$REPORT_FILE"
log "Scan of /root directory completed."

# 10. Find recently modified files (last 24 hours)
log "Scanning for recently modified files (last 24 hours)..."
find / -type f -mtime -1 $EXCLUDE_PATHS -prune -o -type f -mtime -1 -exec ls -lh {} \; 2>/dev/null | head -n $MAX_RESULTS | tee -a "$REPORT_FILE"
log "Recently modified file scan completed."

log "Suspicious File Detection Script Completed"
echo "Report generated: $REPORT_FILE"
