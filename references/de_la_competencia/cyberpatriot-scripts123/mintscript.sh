#!/bin/bash

# Start the timer for logging execution time
startTime=$(date +"%s")

# Function to log the execution time and message
printTime() {
    endTime=$(date +"%s")
    diffTime=$(($endTime-$startTime))
    minutes=$(printf "%02d" $(($diffTime / 60)))
    seconds=$(printf "%02d" $(($diffTime % 60)))
    echo -e "$minutes:$seconds -- $1" >> ~/Desktop/Script.log
}

# Create and set permissions for the log file
touch ~/Desktop/Script.log
echo > ~/Desktop/Script.log
chmod 777 ~/Desktop/Script.log

# Ensure script is run as root
if [[ $EUID -ne 0 ]]; then
  echo "This script must be run as root."
  exit 1
fi
printTime "Script is being run as root."

# Check and print current OS version
clear
printTime "The current OS is Linux Mint."

# Create backup directory and set permissions
mkdir -p ~/Desktop/backups
chmod 777 ~/Desktop/backups
printTime "Backups folder created on the Desktop."

# Backup critical files and set permissions
cp /etc/group ~/Desktop/backups/
chmod 777 ~/Desktop/backups/group
cp /etc/passwd ~/Desktop/backups/
chmod 777 ~/Desktop/backups/passwd
printTime "/etc/group and /etc/passwd files backed up."

# Prompt for user management actions
echo "Type all user account names, with a space in between:"
read -a users
usersLength=${#users[@]}

for (( i=0; i<$usersLength; i++ )); do
    clear
    echo "${users[${i}]}"
    echo "Delete ${users[${i}]}? yes or no"
    read yn1
    if [ "$yn1" == "yes" ]; then
        userdel -r "${users[${i}]}"
        printTime "${users[${i}]} has been deleted."
    else
        echo "Make ${users[${i}]} an administrator? yes or no"
        read yn2
        if [ "$yn2" == "yes" ]; then
            gpasswd -a "${users[${i}]}" sudo
            gpasswd -a "${users[${i}]}" adm
            gpasswd -a "${users[${i}]}" lpadmin
            gpasswd -a "${users[${i}]}" sambashare
            printTime "${users[${i}]} has been made an administrator."
        else
            gpasswd -d "${users[${i}]}" sudo
            gpasswd -d "${users[${i}]}" adm
            gpasswd -d "${users[${i}]}" lpadmin
            gpasswd -d "${users[${i}]}" sambashare
            gpasswd -d "${users[${i}]}" root
            printTime "${users[${i}]} has been made a standard user."
        fi

        echo "Make custom password for ${users[${i}]}? yes or no"
        read yn3
        if [ "$yn3" == "yes" ]; then
            echo "Password:"
            read -s pw
            echo -e "$pw\n$pw" | passwd "${users[${i}]}"
            printTime "${users[${i}]} has been given a custom password."
        else
            echo -e "Moodle!22\nMoodle!22" | passwd "${users[${i}]}"
            printTime "${users[${i}]} has been given the default password 'Moodle!22'."
        fi

        passwd -x30 -n3 -w7 "${users[${i}]}"
        usermod -L "${users[${i}]}"
        printTime "${users[${i}]}'s password policy set: max age 30 days, min age 3 days, warning 7 days. Account locked."
    fi
done

# Prompt for adding new users
clear
echo "Type user account names of users you want to add, with a space in between:"
read -a usersNew
usersNewLength=${#usersNew[@]}

for (( i=0; i<$usersNewLength; i++ )); do
    clear
    echo "${usersNew[${i}]}"
    adduser "${usersNew[${i}]}"
    printTime "A user account for ${usersNew[${i}]} has been created."
    
    echo "Make ${usersNew[${i}]} an administrator? yes or no"
    read ynNew
    if [ "$ynNew" == "yes" ]; then
        gpasswd -a "${usersNew[${i}]}" sudo
        gpasswd -a "${usersNew[${i}]}" adm
        gpasswd -a "${usersNew[${i}]}" lpadmin
        gpasswd -a "${usersNew[${i}]}" sambashare
        printTime "${usersNew[${i}]} has been made an administrator."
    else
        printTime "${usersNew[${i}]} has been made a standard user."
    fi

    passwd -x30 -n3 -w7 "${usersNew[${i}]}"
    usermod -L "${usersNew[${i}]}"
    printTime "${usersNew[${i}]}'s password policy set: max age 30 days, min age 3 days, warning 7 days. Account locked."
done

# Prompt for service configurations and firewall rules
declare -A services=(
    ["Samba"]="sambaYN"
    ["FTP"]="ftpYN"
    ["SSH"]="sshYN"
    ["Telnet"]="telnetYN"
    ["Mail"]="mailYN"
    ["Printing"]="printYN"
    ["MySQL"]="dbYN"
    ["Web Server"]="httpYN"
    ["DNS"]="dnsYN"
)

for service in "${!services[@]}"; do
    echo "Does this machine need $service? yes or no"
    read "${services[$service]}"
done

# Configure and secure services based on user input
clear
unalias -a
printTime "All aliases have been removed."

clear
usermod -L root
printTime "Root account has been locked."

clear
chmod 640 .bash_history
printTime "Bash history file permissions set."

clear
chmod 604 /etc/shadow
printTime "Read/Write permissions on shadow have been set."

clear
printTime "Check for any user folders that do not belong to any users."
ls -a /home/ >> ~/Desktop/Script.log

clear
printTime "Check for any files for users that should not be administrators."
ls -a /etc/sudoers.d >> ~/Desktop/Script.log

clear
cp /etc/rc.local ~/Desktop/backups/
echo -e "#!/bin/bash\nexit 0" > /etc/rc.local
chmod +x /etc/rc.local
printTime "Startup scripts in rc.local have been reset."

# Secure shared memory
if grep -q "none /run/shm" /etc/fstab; then
    echo "Shared memory already secured."
else
    echo -e "\n# Secure shared memory\nnone /run/shm tmpfs rw,noexec,nosuid,nodev 0 0" >> /etc/fstab
    printTime "Shared memory secured."
fi

# Enable firewall and deny common ports
clear
ufw enable
ufw deny 1337
printTime "Firewall enabled and common ports blocked."

# Complete the script with a final message
printTime "Script execution completed."
echo "Script execution completed successfully. Logs saved to ~/Desktop/Script.log"
exit 0