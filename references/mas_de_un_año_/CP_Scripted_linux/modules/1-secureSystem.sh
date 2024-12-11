#!/usr/bin/env bash

# Many ideas taken (stolen) from: https://gist.github.com/bobpaw/a0b6828a5cfa31cfe9007b711a36082f

echo "** Do not run this more than 2 times! (First time, reboot, second time) **"
echo ""
read -p "Press enter to begin securing the system..."
echo ""

# Install updates
apt-get update && apt-get upgrade -y && apt-get dist-upgrade -y

# Check if rebooted
echo ""
read -p "** If you just updated all packages, reboot machine, otherwise press enter **"
echo ""

# Install ufw and openssh
apt-get purge openssh-server -y
apt-get install ufw openssh-server -y

# Configure ufw (firewall) and openssh
ufw allow ssh
ufw --force enable

# Configure ssh server
if grep -qF 'PermitRootLogin' /etc/ssh/sshd_config;
    then sed -i 's/^.*PermitRootLogin.*$/PermitRootLogin no/' /etc/ssh/sshd_config;
else echo 'PermitRootLogin no' >> /etc/ssh/sshd_config;
fi

# Lock root user
passwd -l root

# Remember 5 previous passwords (taken from practice answer key)
echo "" >> /etc/pam.d/common-password
echo "# CPScripted-Linux config" >> /etc/pam.d/common-password
echo "password	required	pam_unix.so	remember=5" >> /etc/pam.d/common-password

# Enable extra dictionary-based password strength tests
echo "password	requisite	pam_pwquality.so" >> /etc/pam.d/common-password

# Sudo requires authentication
sed -i 's/!authenticate/authenticate/' /etc/sudoers

# Disable IPV4 forwarding
sed -i 's/net\.ipv4\.ip_forward=1/net\.ipv4\.ip_forward=0/' /etc/sysctl.conf

# Change login requirements (i hope to god this works)
sed -i 's/PASS_MAX_DAYS.*$/PASS_MAX_DAYS 90/;s/PASS_MIN_DAYS.*$/PASS_MIN_DAYS 10/;s/PASS_WARN_AGE.*$/PASS_WARN_AGE 7/' /etc/login.defs

# Fix shadow permissions
chmod 640 /etc/shadow

# Disable avahi
systemctl disable avahi-daemon

# Disable guest account
echo "allow-guest=false" >> /etc/lightdm/lightdm.conf

# Check for non-root UID 0 users
echo ""
echo "Checking for non-root UID 0 users..."
mawk -F: '$3 == 0 && $1 != "root"' /etc/passwd