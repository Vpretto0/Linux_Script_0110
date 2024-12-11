#!/bin/sh

# Install updates
apt-get update && apt-get upgrade && apt-get dist-upgrade

# Firewall
apt-get install ufw && ufw enable

# No root login on sshd
if grep -qF 'PermitRootLogin' /etc/ssh/sshd_config; then {
  sed -i 's/^.*PermitRootLogin.*$/PermitRootLogin no/' /etc/ssh/sshd_config
} else {
  echo 'PermitRootLogin no' >> /etc/ssh/sshd_config
} fi

# Lock root user
passwd -l root

# Change login chances/age
sed -i 's/PASS_MAX_DAYS.*$/PASS_MAX_DAYS 90/;s/PASS_MIN_DAYS.*$/PASS_MIN_DAYS 10/;s/PASS_WARN_AGE.*$/PASS_WARN_AGE 7/' /etc/login.defs
echo 'auth required pam_tally2.so deny=5 onerr=fail unlock_time=1800' >> /etc/pam.d/common-auth
apt-get install libpam-cracklib
sed -i 's/\(pam_unix\.so.*\)$/\1 remember=5 minlen=8/' /etc/pam.d/common-password
sed -i 's/\(pam_cracklib\.so.*\)$/\1 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1/' /etc/pam.d/common-password
apt-get install auditd && auditctl -e 1
apt-get remove samba*
## Find music (probably in admin's Music folder)
    find /home/ -type f \( -name "*.mp3" -o -name "*.mp4" \)
## Remove any downloaded "hacking tools" packages
    find /home/ -type f \( -name "*.tar.gz" -o -name "*.tgz" -o -name "*.zip" -o -name "*.deb" \)

# Setup Firewall
ufw enable
ufw status verbose










# Install and configure Clam AV for virus scan 
#CLAM AV SHOULD RUN AT THE END OF THE PROGRAM, For it will take a LONG TIME
apt-get install clamav
freshclam
clamscan –i –r --remove=yes /