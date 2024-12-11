#!/bin/bash

LOG_FILE="hardening_log.txt"
touch "$LOG_FILE"

# Logging function
log() {
    echo "[$(date)] $1" | tee -a "$LOG_FILE"
}

log "System Hardening Script Started"

# 1. Forensics Reminder
log "Reminder: Complete forensic questions first if required."

# 2. Install essential tools
log "Installing essential tools..."
sudo apt-get install -y libpam-pwquality ufw auditd clamav chkrootkit rkhunter libpam-cracklib

# 3. PAM: Enforce password policies
log "Configuring password policies..."
sudo sed -i '/pam_pwquality/d' /etc/pam.d/common-password
echo "password requisite pam_pwquality.so minlen=10 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1 retry=3" | sudo tee -a /etc/pam.d/common-password
echo "password requisite pam_unix.so remember=5" | sudo tee -a /etc/pam.d/common-password

# 4. Set login.defs policies
log "Configuring login.defs..."
sudo sed -i '/PASS_MIN_DAYS/d;/PASS_MAX_DAYS/d;/PASS_WARN_AGE/d' /etc/login.defs
echo -e "PASS_MIN_DAYS 10\nPASS_MAX_DAYS 90\nPASS_WARN_AGE 7" | sudo tee -a /etc/login.defs

# 5. Account lockout after 3 failed attempts
log "Setting account lockout policy..."
sudo sed -i '/pam_faillock.so/d' /etc/pam.d/common-auth
echo -e "auth required pam_faillock.so preauth silent deny=3 unlock_time=600\nauth required pam_faillock.so authfail deny=3 unlock_time=600" | sudo tee -a /etc/pam.d/common-auth

# 6. Disable SSH root login and password authentication
log "Securing SSH..."
sudo sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
sudo sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
sudo sed -i 's/^#*ChallengeResponseAuthentication.*/ChallengeResponseAuthentication no/' /etc/ssh/sshd_config
sudo sed -i 's/^#*PermitEmptyPasswords.*/PermitEmptyPasswords no/' /etc/ssh/sshd_config
sudo systemctl restart sshd

# 7. Disable guest account
log "Disabling guest account..."
sudo sed -i '/allow-guest/d' /etc/lightdm/lightdm.conf
echo "allow-guest=false" | sudo tee -a /etc/lightdm/lightdm.conf

# 8. Enable UFW
log "Enabling UFW..."
sudo ufw enable
sudo ufw default deny incoming
sudo ufw default allow outgoing

# 9. Set system services
log "Disabling unnecessary services..."
sudo systemctl disable --now nginx vsftpd apache2 samba

# 10. Set file permissions
log "Setting file permissions..."
sudo chmod 640 /etc/shadow
sudo chmod 750 /home/*

# 11. Enable security tools
log "Enabling rootkit detection..."
sudo chkrootkit
sudo rkhunter --update
sudo rkhunter --check
log "Running antivirus scan..."
sudo clamscan -r /

# 12. Network configurations
log "Configuring network security..."
sudo sysctl -w net.ipv4.tcp_syncookies=1
sudo sysctl -w net.ipv4.ip_forward=0
sudo sysctl -p

# Ensure changes are persistent
sudo sed -i '/net.ipv4.tcp_syncookies/d;/net.ipv4.ip_forward/d' /etc/sysctl.conf
echo -e "net.ipv4.tcp_syncookies=1\nnet.ipv4.ip_forward=0" | sudo tee -a /etc/sysctl.conf

# 13. Final update
log "Final system update..."
sudo apt-get update && sudo apt-get upgrade -y

# 14. Cleanup media and hacking tools
log "Removing unauthorized files and tools..."
sudo find / -type f \( -name "*.mp3" -o -name "*.jpg" -o -name "*.zip" -o -name "*.tar.gz" \) -delete
sudo apt-get purge -y nmap wireshark metasploit zenmap ophcrack netcat apache2 samba

log "System Hardening Script Completed"
echo "Log file created at: $LOG_FILE"