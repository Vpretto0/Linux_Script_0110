#!/bin/bash
echo "Sai Neela's Cyberpatriot Script"
echo "Cybersecurity is my dream"
echo "UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU "
echo "Script Starting......"
# Function to ask for confirmation
confirm() {
    read -p "$1 [y/n]: " choice
    case "$choice" in 
        y|Y ) return 0;;
        n|N ) return 1;;
        * ) echo "Invalid input"; return 1;;
    esac
}

# Disable SSH Root Login
disable_ssh_root_login() {
    if confirm "Do you want to disable SSH root login for added security?"; then
        echo "Disabling SSH root login..."
        sudo sed -i 's/#PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
        sudo sed -i 's/PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
        sudo systemctl restart sshd
        echo "SSH root login has been disabled."
    else
        echo "Skipping SSH root login disabling."
    fi
}

# Setup Fail2Ban
setup_fail2ban() {
    if confirm "Do you want to install and set up Fail2Ban?"; then
        echo "Installing and configuring Fail2Ban..."
        sudo apt-get install -y fail2ban

        # Enable and start Fail2Ban service
        sudo systemctl enable fail2ban
        sudo systemctl start fail2ban

        # Custom Fail2Ban configuration for SSH
        sudo tee /etc/fail2ban/jail.local > /dev/null <<EOF
[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 5
bantime = 10m
EOF

        echo "Fail2Ban installed and configured."
    else
        echo "Skipping Fail2Ban installation."
    fi
}

# Check for Backdoors
check_for_backdoors() {
    if confirm "Do you want to check for backdoors with chkrootkit and rkhunter?"; then
        echo "Installing and running chkrootkit and rkhunter..."
        sudo apt-get install -y chkrootkit rkhunter
        sudo chkrootkit
        sudo rkhunter --update && sudo rkhunter --check
    else
        echo "Skipping backdoor check."
    fi
}

# Main script

# Update and Upgrade System
if confirm "Would you like to update and upgrade the system?"; then
    echo "Updating and upgrading the system..."
    sudo apt-get update -y && sudo apt-get upgrade -y && sudo apt-get dist-upgrade -y
else
    echo "Skipping system update and upgrade."
fi

# Install and Enable UFW (Uncomplicated Firewall)
if confirm "Would you like to install and enable the UFW firewall?"; then
    echo "Installing and enabling UFW firewall..."
    sudo apt-get install -y ufw
    sudo ufw enable
    sudo ufw default deny incoming
    sudo ufw default allow outgoing
else
    echo "Skipping UFW firewall installation and enablement."
fi

# Change Password Policy in /etc/login.defs
if confirm "Would you like to set password policies for maximum and minimum days and warning age?"; then
    echo "Setting password policies in /etc/login.defs..."
    sudo sed -i 's/PASS_MAX_DAYS.*$/PASS_MAX_DAYS 90/' /etc/login.defs
    sudo sed -i 's/PASS_MIN_DAYS.*$/PASS_MIN_DAYS 10/' /etc/login.defs
    sudo sed -i 's/PASS_WARN_AGE.*$/PASS_WARN_AGE 7/' /etc/login.defs
else
    echo "Skipping password policy configuration."
fi

# Install and Enable Auditing
if confirm "Would you like to install and enable auditd for system auditing?"; then
    echo "Installing and enabling auditd..."
    sudo apt-get install -y auditd
    sudo auditctl -e 1
else
    echo "Skipping auditd installation and enablement."
fi

# Check for Unusual Administrators in the Sudo Group
if confirm "Would you like to check for unusual administrators in the sudo group?"; then
    echo "Checking for unusual administrators in the sudo group..."
    sudo mawk -F: '$1 == "sudo"' /etc/group
else
    echo "Skipping check for unusual administrators."
fi

# Check for Users with UID Greater than 999 (Non-System Accounts)
if confirm "Would you like to check for non-system users with UID greater than 999?"; then
    echo "Checking for non-system users..."
    sudo mawk -F: '$3 > 999 && $3 < 65534 {print $1}' /etc/passwd
else
    echo "Skipping check for non-system users."
fi

# Check for Accounts with Empty Passwords
if confirm "Would you like to check for accounts with empty passwords?"; then
    echo "Checking for accounts with empty passwords..."
    sudo mawk -F: '$2 == ""' /etc/passwd
else
    echo "Skipping check for accounts with empty passwords."
fi

# Check for Non-root UID 0 Accounts
if confirm "Would you like to check for non-root accounts with UID 0?"; then
    echo "Checking for non-root accounts with UID 0..."
    sudo mawk -F: '$3 == 0 && $1 != "root"' /etc/passwd
else
    echo "Skipping check for non-root accounts with UID 0."
fi

# Remove Samba and SMB Packages
if confirm "Would you like to remove any Samba-related packages?"; then
    echo "Removing Samba-related packages..."
    sudo apt-get remove -y .*samba.* .*smb.* 
else
    echo "Skipping removal of Samba-related packages."
fi

# Check for Blacklisted Programs
if confirm "Would you like to check for blacklisted programs (nmap, zenmap, apache2, nginx, lighttpd, wireshark, tcpdump, netcat-traditional, nikto, ophcrack)?"; then
    echo "Checking for blacklisted programs..."
    blacklisted_programs=("nmap" "zenmap" "apache2" "nginx" "lighttpd" "wireshark" "tcpdump" "netcat-traditional" "nikto" "ophcrack")
    found_programs=()
    
    # Loop through each blacklisted program and check if it is installed
    for program in "${blacklisted_programs[@]}"; do
        if dpkg -l | grep -qw "$program"; then
            found_programs+=("$program")
        fi
    done

    if [ ${#found_programs[@]} -gt 0 ]; then
        echo "The following blacklisted programs were found on the system:"
        echo "${found_programs[@]}"
        
        if confirm "Do you want to delete these blacklisted programs?"; then
            for program in "${found_programs[@]}"; do
                sudo apt-get remove -y "$program"
                echo "$program has been removed."
            done
        else
            echo "Blacklisted programs were not deleted."
        fi
    else
        echo "No blacklisted programs found."
    fi
else
    echo "Skipping check for blacklisted programs."
fi

# Run Fail2Ban setup
setup_fail2ban

# Check for Backdoors
check_for_backdoors

# Disable SSH Root Login
disable_ssh_root_login

# Final message
echo "Script execution completed."