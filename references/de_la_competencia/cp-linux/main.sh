#!/bin/bash

# Unalias any existing aliases to avoid conflicts
unalias -a # Get rid of aliases
echo "unalias -a" >> ~/.bashrc
echo "unalias -a" >> /root/.bashrc

# Store the current directory path
PWDthi=$(pwd)

# Check if the required reference files directory exists
if [ ! -d $PWDthi/referenceFiles ]; then
    echo "Please Cd into this script's directory"
    exit
fi

# Ensure the script is running with root privileges
if [ "$EUID" -ne 0 ]; then
    echo "Run as Root"
    exit
fi

# Function to run all tasks
startFun() {
    clear # Clear the screen for readability

    # Execute each security function in sequence
    zeroUidFun
    rootCronFun
    apacheSecFun
    fileSecFun
    netSecFun
    aptUpFun
    aptInstFun
    deleteFileFun
    firewallFun
    sysCtlFun
    scanFun
    repoFun
    
    printf "\033[1;31mDone!\033[0m\n" # Display a completion message
}

# Function to prompt user to continue to the next task
cont() {
    printf "\033[1;31mI have finished this task. Continue to next Task? (Y/N)\033[0m\n"
    read contyn
    if [ "$contyn" = "N" ] || [ "$contyn" = "n" ]; then
        printf "\033[1;31mAborted\033[0m\n"
        exit
    fi
    clear
}

# Function to fix users with UID 0 (root) other than 'root' itself
zeroUidFun() {
    printf "\033[1;31mChecking for 0 UID users...\033[0m\n"
    touch /zerouidusers
    touch /uidusers

    # Find users with UID 0 (other than 'root') and save them to a file
    cut -d: -f1,3 /etc/passwd | egrep ':0$' | cut -d: -f1 | grep -v root > /zerouidusers

    # If any zero UID users are found, change their UID to a unique random number
    if [ -s /zerouidusers ]; then
        echo "There are Zero UID Users! I'm fixing it now!"
        while IFS='' read -r line || [[ -n "$line" ]]; do
            # Try assigning a random unused UID
            thing=1
            while true; do
                rand=$(( ( RANDOM % 999 ) + 1000))
                cut -d: -f1,3 /etc/passwd | egrep ":$rand$" | cut -d: -f1 > /uidusers
                if [ -s /uidusers ]; then
                    echo "Couldn't find unused UID. Trying Again... "
                else
                    break
                fi
            done
            # Change the user's UID and update /etc/passwd
            usermod -u $rand -g $rand -o $line
            touch /tmp/oldstring
            old=$(grep "$line" /etc/passwd)
            echo $old > /tmp/oldstring
            sed -i "s~0:0~$rand:$rand~" /tmp/oldstring
            new=$(cat /tmp/oldstring)
            sed -i "s~$old~$new~" /etc/passwd
            echo "ZeroUID User: $line"
            echo "Assigned UID: $rand"
        done < "/zerouidusers"
        update-passwd
        # Check again if any zero UID users remain
        cut -d: -f1,3 /etc/passwd | egrep ':0$' | cut -d: -f1 | grep -v root > /zerouidusers

        if [ -s /zerouidusers ]; then
            echo "WARNING: UID CHANGE UNSUCCESSFUL!"
        else
            echo "Successfully Changed Zero UIDs!"
        fi
    else
        echo "No Zero UID Users"
    fi
    cont
}

# Function to restrict cron jobs to root user only
rootCronFun() {
    printf "\033[1;31mChanging cron to only allow root access...\033[0m\n"
    crontab -r  # Remove current crontab
    cd /etc/  # Change to /etc directory

    # Remove any user from cron.allow and at.allow (deny list)
    /bin/rm -f cron.deny at.deny

    # Allow only the root user to access cron and at
    echo root > cron.allow
    echo root > at.allow
    /bin/chown root:root cron.allow at.allow  # Set the correct ownership
    /bin/chmod 644 cron.allow at.allow  # Set the correct permissions
    cont
}

# Function to enhance Apache security by restricting user directory access
apacheSecFun() {
    printf "\033[1;31mSecuring Apache...\033[0m\n"
    a2enmod userdir  # Enable Apache's userdir module

    # Set correct ownership for Apache configuration files
    chown -R root:root /etc/apache2
    chown -R root:root /etc/apache

    # Modify Apache config to secure directories and disable user directories
    if [ -e /etc/apache2/apache2.conf ]; then
        echo "<Directory />" >> /etc/apache2/apache2.conf
        echo "        AllowOverride None" >> /etc/apache2/apache2.conf
        echo "        Order Deny,Allow" >> /etc/apache2/apache2.conf
        echo "        Deny from all" >> /etc/apache2/apache2.conf
        echo "</Directory>" >> /etc/apache2/apache2.conf
        echo "UserDir disabled root" >> /etc/apache2/apache2.conf
    fi

    systemctl restart apache2.service  # Restart Apache to apply changes
    cont
}

# Function for automatic inspection and modification of certain files
fileSecFun() {
    printf "\033[1;31mSome automatic file inspection...\033[0m\n"
    
    # Find users with suspicious UID and save them to a list
    cut -d: -f1,3 /etc/passwd | egrep ':[0-9]{4}$' | cut -d: -f1 > /tmp/listofusers
    echo root >> /tmp/listofusers
    
    # Replace sources.list with a predefined secure mirror
    cat $PWDthi/referenceFiles/sources.list > /etc/apt/sources.list
    apt-get update  # Update package lists

    # Replace configuration files with more secure versions
    cat $PWDthi/referenceFiles/lightdm.conf > /etc/lightdm/lightdm.conf
    cat $PWDthi/referenceFiles/sshd_config > /etc/ssh/sshd_config
    /usr/sbin/sshd -t  # Test SSH configuration for errors
    systemctl restart sshd.service  # Restart SSH service to apply changes

    # Clean up some basic system files
    echo 'exit 0' > /etc/rc.local
    nano /etc/resolv.conf  # Edit DNS resolver
    nano /etc/hosts  # Edit hosts file
    visudo  # Edit sudoers file
    nano /tmp/listofusers  # Edit the list of users

    cont
}

# Function for basic network inspection
netSecFun() {
    printf "\033[1;31mSome manual network inspection...\033[0m\n"
    lsof -i -n -P  # List open files and network connections
    netstat -tulpn  # Show listening ports and associated processes
    cont
}

# Function to update and upgrade the system
aptUpFun() {
    printf "\033[1;31mUpdating computer...\033[0m\n"
    apt-get update  # Update package lists
    apt-get dist-upgrade -y  # Perform system upgrade
    apt-get install -f -y  # Fix broken dependencies
    apt-get autoremove -y  # Remove unnecessary packages
    apt-get autoclean -y  # Clean up cached packages
    apt-get check  # Check for broken dependencies
    cont
}

# Function to install essential security tools
aptInstFun() {
    printf "\033[1;31mInstalling programs...\033[0m\n"
    apt-get install -y chkrootkit clamav rkhunter apparmor apparmor-profiles  # Install security tools
    wget https://cisofy.com/files/lynis-2.5.5.tar.gz -O /lynis.tar.gz  # Download Lynis
    tar -xzf /lynis.tar.gz --directory /usr/share/  # Extract Lynis
    cont
}

# Function to delete unnecessary files (e.g., media files)
deleteFileFun() {
    printf "\033[1;31mDeleting dangerous files...\033[0m\n"
    # Delete common media and other unnecessary files
    find / -name '*.mp3' -type f -delete
    find / -name '*.mov' -type f -delete
    find / -name '*.mp4' -type f -delete
    cont
}

# Function to configure the system firewall
firewallFun() {
    printf "\033[1;31mConfiguring firewall...\033[0m\n"
    iptables -A INPUT -p tcp --dport 443 -j ACCEPT  # Allow HTTPS
    iptables -A INPUT -p tcp --dport 80 -j ACCEPT   # Allow HTTP
    iptables -A INPUT -p udp --dport 53 -j ACCEPT   # Allow DNS
    iptables -A OUTPUT -p udp --dport 53 -j ACCEPT  # Allow DNS
    iptables -A OUTPUT -p tcp --dport 53 -j ACCEPT  # Allow DNS
    iptables-save > /etc/iptables/rules.v4  # Save IPv4 rules
    ip6tables-save > /etc/iptables/rules.v6  # Save IPv6 rules
    systemctl enable iptables  # Enable iptables service
    systemctl start iptables   # Start iptables service
    systemctl enable ip6tables  # Enable IPv6 iptables service
    systemctl start ip6tables   # Start IPv6 iptables service
    cont
}

# Function to update sysctl configuration for better security
sysCtlFun() {
    printf "\033[1;31mUpdating Sysctl configurations...\033[0m\n"
    cp /etc/sysctl.conf /etc/sysctl.conf.bak  # Backup sysctl configuration
    sysctl -p  # Apply sysctl settings
    sysctl -w net.ipv4.tcp_syncookies=1  # Enable TCP syncookies to prevent SYN flood attacks
    sysctl -w net.ipv4.conf.all.accept_source_route=0  # Disable source routing
    sysctl -w net.ipv4.conf.default.accept_source_route=0  # Disable source routing for default interfaces
    sysctl -w net.ipv4.conf.all.rp_filter=1  # Enable reverse path filtering
    sysctl -w net.ipv4.conf.default.rp_filter=1  # Enable reverse path filtering for default interfaces
    sysctl -w net.ipv4.tcp_rmem='4096 87380 4194304'  # Adjust TCP read buffer sizes
    sysctl -w net.ipv4.tcp_wmem='4096 87380 4194304'  # Adjust TCP write buffer sizes
    sysctl -w net.ipv4.ip_forward=0  # Disable IP forwarding (useful for routers)
    sysctl -w net.ipv4.icmp_echo_ignore_all=1  # Ignore all ICMP echo requests (ping)
    sysctl -w net.ipv4.tcp_timestamps=0  # Disable TCP timestamps
    sysctl -w net.ipv4.tcp_fin_timeout=15  # Set TCP FIN timeout
    sysctl -w net.ipv4.tcp_keepalive_time=120  # Set TCP keepalive time
    sysctl -w net.ipv4.tcp_retries2=5  # Set TCP retries for unacknowledged connections
    sysctl -w net.core.rmem_max=16777216  # Set max receive buffer size
    sysctl -w net.core.wmem_max=16777216  # Set max send buffer size
    sysctl -w net.core.netdev_max_backlog=2500  # Set max backlog for incoming packets
    sysctl -w net.core.somaxconn=4096  # Set max number of connections in the listen queue
    sysctl -w kernel.msgmni=28816  # Set the maximum number of message queues
    sysctl -w kernel.sem='250 32000 32 128'  # Set semaphore settings
    sysctl -w fs.file-max=2097152  # Increase max number of open files
    sysctl -w fs.inotify.max_user_watches=524288  # Increase number of file watches
    cont
}

# Function to perform system scan using Lynis
scanFun() {
    printf "\033[1;31mScanning the system..\033[0m\n"
    lynis audit system  # Run the Lynis audit
    cont
}

# Function to configure package repositories
repoFun() {
    printf "\033[1;31mConfiguring repositories..\033[0m\n"
    # Replace default Ubuntu repositories with mirrors for better speed
    sed -i 's/http:\/\/archive.ubuntu.com/http:\/\/mirror.cse.iitk.ac.in/g' /etc/apt/sources.list
    sed -i 's/http:\/\/security.ubuntu.com/http:\/\/mirror.cse.iitk.ac.in/g' /etc/apt/sources.list
    cont
}

# Run the start function to begin the hardening process
startFun