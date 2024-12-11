#!/bin/bash

LOG_FILE="hardening_log.txt"
touch "$LOG_FILE"

# Logging function
log() {
    echo "[$(date)] $1" | tee -a "$LOG_FILE"
}

log "System Hardening Script Started"

# 1. Ensure pam_pwquality is installed and enforce password policy
log "Checking and installing pam_pwquality if needed..."
if ! grep -q 'pam_pwquality' /etc/pam.d/common-password; then
    log "pam_pwquality module not found. Installing..."
    if sudo apt install -y libpam-pwquality; then
        log "pam_pwquality installed successfully."
    else
        log "Error: Failed to install pam_pwquality."
    fi
fi

log "Setting minimum password length to 10 characters..."
if grep -q 'pam_pwquality' /etc/pam.d/common-password; then
    sudo sed -i 's/^\(password.*pam_pwquality\.so.*\)$/\1 minlen=10/' /etc/pam.d/common-password
    log "Password length set to 10 characters."
else
    log "Error: pam_pwquality configuration not updated."
fi

log "Setting minimum password age to 2 days..."
if sudo grep -q '^PASS_MIN_DAYS' /etc/login.defs; then
    sudo sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS    2/' /etc/login.defs
    log "Minimum password age set to 2 days."
else
    echo "PASS_MIN_DAYS    2" | sudo tee -a /etc/login.defs
    log "PASS_MIN_DAYS added and set to 2 days."
fi

# 2. Enforce account lockout after 3 failed attempts
log "Configuring account lockout policy..."
if ! grep -q 'pam_faillock.so' /etc/pam.d/common-auth; then
    echo "auth required pam_faillock.so preauth silent audit deny=3 unlock_time=600" | sudo tee -a /etc/pam.d/common-auth
    echo "auth required pam_faillock.so authfail audit deny=3 unlock_time=600" | sudo tee -a /etc/pam.d/common-auth
    echo "account required pam_faillock.so" | sudo tee -a /etc/pam.d/common-account
    log "Account lockout policy set."
else
    log "Account lockout policy already configured."
fi

# 3. Disable null passwords
log "Disabling null passwords..."
if sudo sed -i '/pam_unix.so/s/nullok//' /etc/pam.d/common-auth; then
    log "Null passwords disabled."
else
    log "Error: Failed to disable null passwords."
fi

# 4. Disable SSH root login and password authentication
log "Securing SSH configuration..."
SSH_CONFIG="/etc/ssh/sshd_config"
if [ -f "$SSH_CONFIG" ]; then
    sudo sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/' "$SSH_CONFIG"
    sudo sed -i 's/^#*PermitEmptyPasswords.*/PermitEmptyPasswords no/' "$SSH_CONFIG"
    if sudo systemctl restart sshd; then
        log "SSH configuration updated and service restarted."
    else
        log "Error: Failed to restart SSH service."
    fi
else
    log "Error: SSH configuration file not found."
fi

# 5. Set permissions on /etc/shadow
log "Setting permissions on /etc/shadow..."
if sudo chmod 640 /etc/shadow; then
    log "Permissions set to 640 on /etc/shadow."
else
    log "Error: Failed to set permissions on /etc/shadow."
fi

# 6. Enable TCP SYN cookies to prevent SYN flood attacks
log "Enabling TCP SYN cookies..."
if sudo sysctl -w net.ipv4.tcp_syncookies=1 && sudo sysctl -p; then
    if ! grep -q "net.ipv4.tcp_syncookies=1" /etc/sysctl.conf; then
        echo "net.ipv4.tcp_syncookies=1" | sudo tee -a /etc/sysctl.conf
        log "TCP SYN cookies enabled persistently."
    else
        log "TCP SYN cookies already enabled persistently."
    fi
else
    log "Error: Failed to enable TCP SYN cookies."
fi

# 7. Disable IP forwarding to prevent unauthorized routing
log "Disabling IP forwarding..."
if sudo sysctl -w net.ipv4.ip_forward=0 && sudo sysctl -p; then
    if ! grep -q "net.ipv4.ip_forward=0" /etc/sysctl.conf; then
        echo "net.ipv4.ip_forward=0" | sudo tee -a /etc/sysctl.conf
        log "IP forwarding disabled persistently."
    else
        log "IP forwarding already disabled persistently."
    fi
else
    log "Error: Failed to disable IP forwarding."
fi

# 8. Enable Uncomplicated Firewall (UFW) if not already enabled
log "Checking if UFW is installed..."
if ! command -v ufw &>/dev/null; then
    log "UFW not found. Installing..."
    if sudo apt install -y ufw; then
        log "UFW installed successfully."
    else
        log "Error: Failed to install UFW."
    fi
fi

log "Enabling UFW..."
if sudo ufw enable; then
    log "UFW enabled successfully."
else
    log "Error: Failed to enable UFW. Investigating conflicts..."
    if sudo systemctl is-active --quiet firewalld; then
        log "Conflict: firewalld is running. Disabling firewalld..."
        if sudo systemctl stop firewalld && sudo systemctl disable firewalld; then
            log "firewalld disabled. Retrying UFW..."
            if sudo ufw enable; then
                log "UFW enabled successfully after resolving conflict."
            else
                log "Error: UFW still could not be enabled."
            fi
        else
            log "Error: Failed to disable firewalld."
        fi
    else
        log "No apparent conflicts found. UFW may require further troubleshooting."
    fi
fi

# 9. Disable unnecessary services (Nginx and FTP)
log "Disabling unnecessary services (Nginx, vsftpd)..."
if sudo systemctl disable --now nginx; then
    log "Nginx disabled."
else
    log "Error: Failed to disable Nginx."
fi
if sudo systemctl disable --now vsftpd; then
    log "FTP server disabled."
else
    log "Error: Failed to disable FTP server."
fi


# 11. Final system update
log "Updating system packages..."
if sudo apt update && sudo apt upgrade -y; then
    log "System packages updated."
else
    log "Error: Failed to update system packages."
fi

log "System Hardening Script Completed"
echo "Log file created at: $LOG_FILE"
