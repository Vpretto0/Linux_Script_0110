#!/bin/bash
echo "Cyberpatriot 2024 Script for State Round"
echo "Cybersecurity is my dream"
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

# Function to scan for suspicious MP3 or media files
scan_for_media_files() {
    echo "Checking for MP3 or media files..."

    # Find all MP3 files and display details with full paths
    find / -type f -iname "*.mp3" -exec ls -l {} \; > mp3_files_found.txt

    # Check if any MP3 files were found
    if [ -s mp3_files_found.txt ]; then
        echo "Suspicious MP3 files found:"
        cat mp3_files_found.txt

        if confirm "Do you want to delete these MP3 files?"; then
            # Delete found MP3 files
            while read -r file; do
                sudo rm -f "$file"
                echo "Deleted: $file"
            done < mp3_files_found.txt
        else
            echo "MP3 files were not deleted."
        fi
    else
        echo "No MP3 files found."
    fi
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

# Install and Enable UFW (Uncomplicated Firewall)
setup_ufw() {
    if confirm "Would you like to install and enable the UFW firewall?"; then
        echo "Installing and enabling UFW firewall..."
        sudo apt-get install -y ufw
        sudo ufw enable
        sudo ufw default deny incoming
        sudo ufw default allow outgoing
    else
        echo "Skipping UFW firewall installation and enablement."
    fi
}

# Setup password policies
setup_password_policy() {
    if confirm "Would you like to set password policies for maximum and minimum days and warning age?"; then
        echo "Setting password policies in /etc/login.defs..."
        sudo sed -i 's/PASS_MAX_DAYS.*$/PASS_MAX_DAYS 90/' /etc/login.defs
        sudo sed -i 's/PASS_MIN_DAYS.*$/PASS_MIN_DAYS 10/' /etc/login.defs
        sudo sed -i 's/PASS_WARN_AGE.*$/PASS_WARN_AGE 7/' /etc/login.defs
    else
        echo "Skipping password policy configuration."
    fi
}

# Setup Auditing
setup_auditd() {
    if confirm "Would you like to install and enable auditd for system auditing?"; then
        echo "Installing and enabling auditd..."
        sudo apt-get install -y auditd
        sudo auditctl -e 1
    else
        echo "Skipping auditd installation and enablement."
    fi
}

# Check for Unusual Administrators in the Sudo Group
check_sudo_group() {
    if confirm "Would you like to check for unusual administrators in the sudo group?"; then
        echo "Checking for unusual administrators in the sudo group..."
        sudo mawk -F: '$1 == "sudo"' /etc/group
    else
        echo "Skipping check for unusual administrators."
    fi
}

# Check for Prohibited Software (e.g., Hydra)
check_for_prohibited_software() {
    if confirm "Do you want to check for prohibited software like Hydra?"; then
        echo "Checking for prohibited software..."
        if dpkg-query -l | grep -q "hydra"; then
            echo "Hydra found! Removing..."
            sudo apt-get remove --purge -y hydra
        else
            echo "Hydra not found."
        fi
    else
        echo "Skipping prohibited software check."
    fi
}

# Remove Samba and SMB Packages
remove_samba_packages() {
    if confirm "Would you like to remove any Samba-related packages?"; then
        echo "Removing Samba-related packages..."
        sudo apt-get remove -y .*samba.* .*smb.* 
    else
        echo "Skipping removal of Samba-related packages."
    fi
}

# Check for Blacklisted Programs
check_for_blacklisted_programs() {
    if confirm "Would you like to check for blacklisted programs (nmap, zenmap, apache2, nginx, lighttpd, wireshark, tcpdump, netcat-traditional, nikto, ophcrack)?"; then
        echo "Checking for blacklisted programs..."
        blacklisted_programs=("nmap" "zenmap" "apache2" "nginx" "lighttpd" "wireshark" "tcpdump" "netcat-traditional" "nikto" "ophcrack")
        
        # Loop through each blacklisted program and check if it is installed
        for program in "${blacklisted_programs[@]}"; do
            if dpkg -l | grep -qw "$program"; then
                echo "$program is installed."
                if confirm "Do you want to remove $program?"; then
                    sudo apt-get remove -y "$program"
                    echo "$program has been removed."
                else
                    echo "Skipping removal of $program."
                fi
            fi
        done
    else
        echo "Skipping check for blacklisted programs."
    fi
}

# Check Apache Configuration
check_apache_configuration() {
    if confirm "Do you want to configure Apache settings if Apache is installed?"; then
        if dpkg-query -l | grep -q apache2; then
            echo "Apache found. Disabling server signature and setting server tokens..."
            sudo sed -i 's/#ServerSignature On/ServerSignature Off/' /etc/apache2/conf-enabled/security.conf
            sudo sed -i 's/#ServerTokens Full/ServerTokens Prod/' /etc/apache2/conf-enabled/security.conf
            sudo systemctl restart apache2
        else
            echo "Apache not found."
        fi
    else
        echo "Skipping Apache configuration."
    fi
}

# Check for Python Backdoors
check_python_backdoors() {
    if confirm "Do you want to check for potential Python backdoors?"; then
        echo "Searching for suspicious Python scripts..."

        # Look for Python files with suspicious behavior (e.g., reverse shells)
        find / -type f -iname "*.py" -exec grep -i -H "import socket\|os.system\|subprocess" {} \; > python_backdoors.txt

        if [ -s python_backdoors.txt ]; then
            echo "Potential Python backdoors found:"
            cat python_backdoors.txt

            if confirm "Do you want to delete these Python backdoors?"; then
                while read -r file; do
                    sudo rm -f "$file"
                    echo "Deleted: $file"
                done < python_backdoors.txt
            else
                echo "Python backdoors were not deleted."
            fi
        else
            echo "No Python backdoors found."
        fi
    else
        echo "Skipping Python backdoor check."
    fi
}

# Install ClamAV Antivirus and Perform Scan
install_clamav() {
    if confirm "Do you want to install and run ClamAV for antivirus scanning?"; then
        echo "Installing ClamAV..."
        sudo apt-get install -y clamav
        sudo freshclam  # Update ClamAV database

        echo "Running ClamAV Scan..."
        sudo clamscan -r / --bell -i > clamav_scan_results.txt

        if [ -s clamav_scan_results.txt ]; then
            echo "ClamAV found potential threats:"
            cat clamav_scan_results.txt
            if confirm "Do you want to delete the detected threats?"; then
                sudo clamscan -r / --remove
            else
                echo "Threats were not deleted."
            fi
        else
            echo "No threats detected by ClamAV."
        fi
    else
        echo "Skipping ClamAV installation and scan."
    fi
}

# Main script execution

# Update and Upgrade System (In the background with only essential info shown)
if confirm "Would you like to update and upgrade the system?"; then
    echo "Updating and upgrading the system..."
    sudo apt-get update -y > /dev/null 2>&1 &
    sudo apt-get upgrade -y > /dev/null 2>&1 &
    sudo apt-get dist-upgrade -y > /dev/null 2>&1 &
    echo "System is being updated and upgraded in the background. Please wait..."
    wait  # Wait for all processes to complete
else
    echo "Skipping system update and upgrade."
fi

# Run Functions
scan_for_media_files
setup_fail2ban
check_for_backdoors
disable_ssh_root_login
setup_ufw
setup_password_policy
setup_auditd
check_sudo_group
check_for_prohibited_software
check_for_blacklisted_programs
check_apache_configuration
check_python_backdoors
install_clamav

# Final message
echo "Script execution completed."