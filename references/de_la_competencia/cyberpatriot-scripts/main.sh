#!/bin/bash
printf "Only run this script if you know what it does!!!\n"
printf "Run this script? (y/n): "
read runyn
if [ "$runyn" = "n" ] || [ "$runyn" = "N" ]
then
  printf "Exiting...\n"
  exit
fi
if [ "$EUID" -ne 0 ]
  then printf "Current UID: $EUID\nPlease run as root\n"
  exit
fi
printf "Remove all aliases? (might cause issues if not) (y/n): "
read aliasyn
if [ "$aliasyn" = "y" ] || [ "$aliasyn" = "Y" ]
then
  printf "Unaliasing all aliases...\n"
  unalias -a
else
    printf "Skipping unaliasing...\n"
fi
printf "Update apt-get packages? (y/n): "
read aptyn
if [ "$aptyn" = "y" ] || [ "$aptyn" = "Y" ]
then
  printf "Updating apt-get...\n"
  apt-get update -y
  apt-get dist-upgrade -y
  apt-get install -f -y
  apt-get autoremove -y
  apt-get autoclean -y
else
  printf "Skipping apt-get update...\n"
fi
printf "Remove media files? (y/n): "
read mediayn
if [ "$mediayn" = "y" ] || [ "$mediayn" = "Y" ]
then
  printf "Removing media files...\n"
  find / -name '*.mp3' -type f -delete
  find / -name '*.mov' -type f -delete
    find / -name '*.mp4' -type f -delete
    find / -name '*.avi' -type f -delete
    find / -name '*.mpg' -type f -delete
    find / -name '*.mpeg' -type f -delete
    find / -name '*.flac' -type f -delete
    find / -name '*.m4a' -type f -delete
    find / -name '*.flv' -type f -delete
    find / -name '*.ogg' -type f -delete
    find /home -name '*.gif' -type f -delete
    find /home -name '*.png' -type f -delete
    find /home -name '*.jpg' -type f -delete
    find /home -name '*.jpeg' -type f -delete
else
  printf "Skipping removing media files...\n"
fi
if sudo ufw status | grep -q inactive$; then
  printf "UFW is detected as inactive. Would you like to enable it? (y/n): "
  read ufwyn
    if [ "$ufwyn" = "y" ] || [ "$ufwyn" = "Y" ]
    then
        printf "Enabling UFW...\n"
        ufw enable
    else
        printf "Leaving UFW as disabled...\n"
    fi
fi
printf "Run standard security checks? (y/n): "
read securityyn
if [ "$securityyn" = "y" ] || [ "$securityyn" = "Y" ]
then
  printf "Running standard security checks...\n"
  printf "Changing permissions of /etc/shadow...\n"
  chmod 744 /etc/shadow
else
  printf "Skipping security checks...\n"
fi
printf "Scan for rootkits? (y/n): "
read rootkityn
if [ "$rootkityn" = "y" ] || [ "$rootkityn" = "Y" ]
  printf "Installing rkhunter...\n"
  apt-get install rkhunter -y
  printf "Running rkhunter...\n"
  rkhunter --update
  rkhunter --propupd
  rkhunter -c --enable all --disable none
  printf "Installing chkrootkit...\n"
  apt-get install chkrootkit -y
  printf "Running chkrootkit...\n"
  chkrootkit -q
  printf "Installing LYNIS...\n"
  apt-get install lynis -y
  printf "Running LYNIS...\n"
  lynis update info
  lynis audit system
  printf "Installing clamav...\n"
  apt-get install clamav -y
  printf "Running clamav...\n"
  systemctl stop clamav-freshclam
  freshclam --stdout
  systemctl start clamav-freshclam
  clamscan -r -i --stdout --exclude-dir="^/sys" /
else
    printf "Skipping rootkit scans...\n"
fi
printf "Enter user management mode? (y/n): "
read useryn
if [ "$useryn" = "y" ] || [ "$useryn" = "Y" ]
then
  printf "Enter name of admin group (usually admin or sudo): "
  read admingroup
  printf "Members of the admin group:\n $(getent group $admingroup)\n"
  printf "Use the following command to add a user to the admin group:\n usermod -aG $admingroup <username>\n"
  printf "Use the following command to remove a user from the admin group:\n deluser <username> $admingroup\n"
fi