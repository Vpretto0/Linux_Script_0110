#!/bin/bash

# Example function for securing vsftpd.conf
secure_vsftpd_conf() {
    config="/etc/vsftpd.conf"
    if [ -f "$config" ]; then
        sed -i 's/^anonymous_enable=.*/anonymous_enable=NO/' $config
        sed -i 's/^local_enable=.*/local_enable=YES/' $config
        sed -i 's/^write_enable=.*/write_enable=YES/' $config
        sed -i 's/^chroot_local_user=.*/chroot_local_user=YES/' $config
        sudo systemctl restart vsftpd
        echo "vsftpd.conf has been secured."
    else
        echo "$config not found"
    fi
}

# Disable Root Login (via SSH)
# Function to disable SSH root login
disable_root_login() {
    read -p "Do you want to disable SSH Root Login? (yes/no): " com
    com=$(echo "$com" | tr '[:upper:]' '[:lower:]')

    if [ "$com" == "yes" ]; then
        config='/etc/ssh/sshd_config'
        
        # Check if the configuration file exists
        if [ ! -f "$config" ]; then
            echo "$config not found."
            return
        fi

        # Backup the original config
        sudo cp "$config" "$config.bak"

        # Modify the SSH configuration
        sudo awk '{
            if ($1 == "PermitRootLogin") { print "PermitRootLogin no"; }
            else if ($1 == "LoginGraceTime") { print "LoginGraceTime 60"; }
            else if ($1 == "PermitEmptyPasswords") { print "PermitEmptyPasswords no"; }
            else if ($1 == "PasswordAuthentication") { print "PasswordAuthentication yes"; }
            else if ($1 == "X11Forwarding") { print "X11Forwarding no"; }
            else if ($1 == "UsePAM") { print "UsePAM yes"; }
            else if ($1 == "UsePrivilegeSeparation") { print "UsePrivilegeSeparation yes"; }
            else { print; }
        }' "$config" | sudo tee "$config" > /dev/null

        # Restart the SSH service to apply changes
        sudo systemctl restart sshd
        
        echo "SSH root login has been disabled."
    else
        echo "SSH root login remains enabled."
    fi
}

##Updates the operating system, kernel, firefox, and libre office and also installs 'clamtk'
update(){
		sudo add-apt-repository -y ppa:libreoffice/ppa
		sudo apt-get update
        sudo apt-get upgrade
        sudo apt-get autoremove -y -qq
        sudo apt-get autoclean -y -qq
        sudo apt-get clean -y -qq
        autoUpdate	
}

##Sets Automatic Updates on the machine.
autoUpdate() {
    echo "$LogTime uss: [$UserName]# Setting auto updates." >> output.log
        ##Set daily updates
            sed -i -e 's/APT::Periodic::Update-Package-Lists.*\+/APT::Periodic::Update-Package-Lists "1";/' /etc/apt/apt.conf.d/10periodic
            sed -i -e 's/APT::Periodic::Download-Upgradeable-Packages.*\+/APT::Periodic::Download-Upgradeable-Packages "0";/' /etc/apt/apt.conf.d/10periodic
        ##Sets default broswer
            sed -i 's/x-scheme-handler\/http=.*/x-scheme-handler\/http=firefox.desktop/g' /home/$UserName/.local/share/applications/mimeapps.list
        ##Set "install security updates"
            cat /etc/apt/sources.list | grep "deb http://security.ubuntu.com/ubuntu/ trusty-security universe main multiverse restricted"
            if [ $? -eq 1 ]
            then
                echo "deb http://security.ubuntu.com/ubuntu/ trusty-security universe main multiverse restricted" >> /etc/apt/sources.list
            fi

            echo "###Automatic updates###"
            cat /etc/apt/apt.conf.d/10periodic
            echo ""
            echo "###Important Security Updates###"
            cat /etc/apt/sources.list
            pause
}

##Creates copies of critical files
backup() {
	mkdir /BackUps
	##Backups the sudoers file
	sudo cp /etc/sudoers /Backups
	##Backups the home directory
	cp /etc/passwd /BackUps
	##Backups the log files
	cp -r /var/log /BackUps
	##Backups the passwd file
	cp /etc/passwd /BackUps
	##Backups the group file
	cp /etc/group /BackUps
	##Back ups the shadow file
	cp /etc/shadow /BackUps
	##Backing up the /var/spool/mail
	cp /var/spool/mail /Backups
	##backups all the home directories
	for x in `ls /home`
	do
		cp -r /home/$x /BackUps
	done

	pause
}

#Finds all prohibited files on the machine and deletes them
pFiles() {
    echo "$LogTime uss: [$UserName]# Deleting media files..." >> output.log
        #Media files
        echo "###MEDIA FILES###" >> pFiles.log
            find / -name "*.mov" -type f >> pFiles.log
            find / -name "*.mp4" -type f >> pFiles.log
        find / -name "*.mp3" -type f >> pFiles.log
        find / -name "*.wav" -type f >> pFiles.log
        #Pictures
        echo "###PICTURES###" >> pFiles.log
    #	find / -name "*.png" -type f >> pFiles.log
        find / -name "*.jpg" -type f >> pFiles.log
        find / -name "*.jpeg" -type f >> pFiles.log
    #	find / -name "*.gif" -type f >> pFiles.log
        ##Other Files
        echo "###OTHER###" >> pFiles.log
        find / -name "*.tar.gz" -type f >> pFiles.log
        find / -name "*.php" -type f >> pFiles.log
        find / -name "*backdoor*.*" -type f >> pFiles.log
        find / -name "*backdoor*.php" -type f >> pFiles.log
        ##Items without groups
        echo "###FILES WITHOUT GROUPS###" >> pFiles.log
        find / -nogroup >> pFiles.log
        echo "###GAMES###" >> pFiles.log
        dpkg -l | grep -i game

        ##Deletes audio files
        find / -name "*.mp3" -type f -delete
        ##Deletes Video files
        find / -name "*.mov" -type f -delete
        find / -name "*.mp4" -type f -delete
    #	find / -name "*.gif" -type f -delete
        ##Deletes pictures
    #	find / -name "*.png" -type f -delete
        find / -name "*.jpg" -type f -delete
        find / -name "*.jpeg" -type f -delete
    echo "$LogTime uss: [$UserName]# Media files deleted." >> output.log
        cat pFiles.log
        pause
}

ufw() {
    # Ask the user if they want to enable the firewall
    read -p "Do you want to enable the firewall? (yes/no): " confirm
    confirm=$(echo "$confirm" | tr '[:upper:]' '[:lower:]')

    if [ "$confirm" == "yes" ]; then
        # Ask if the user wants to allow SSH connections
        read -p "Do you want to enable SSH connections? (yes/no): " confirma
        confirma=$(echo "$confirma" | tr '[:upper:]' '[:lower:]')

        # Install ufw (Uncomplicated Firewall)
        sudo apt-get install ufw -y -qq

        # Allow SSH if the user confirmed
        if [ "$confirma" == "yes" ]; then
            sudo ufw allow ssh
            echo "SSH has been enabled"
        fi

        # Enable the firewall
        sudo ufw enable
        # Deny connections on port 1337
        sudo ufw deny 1337
        
        # Enable TCP SYN cookies
        sysctl -n net.ipv4.tcp_syncookies

        # Disable IP forwarding
        echo 0 | sudo tee /proc/sys/net/ipv4/ip_forward > /dev/null

        # Prevent IP spoofing
        echo 'nospoof on' | sudo tee -a /etc/host.conf > /dev/null

        echo "Firewall has been enabled"
    else
        echo "Firewall has not been changed"
    fi
}

sudoers() {

	cat /etc/sudoers | grep NOPASSWD.* >> /dev/null
	if [ $? -eq 0 ]
	then
		echo "## NOPASSWD VALUE HAS BEEN FOUND IN THE SUDOERS FILE, GO CHANGE IT." >> postScript.log
	fi
	##Looks for a timeout value and and delete is.
	cat /etc/sudoers | grep timestamp_timeout >> /dev/null
	if [ $? -eq 0 ]
	then
		TIME=`cat /etc/sudoers | grep timestamp_timeout | cut -f2 | cut -d= -f2`
		echo "## Time out value has been set to $TIME Please go change it or remove it." >> postScript
	fi

	pause
}

##Creates any missing users
createUser() {
	read -p "Are there any users you would like to add?[y/n]: " a
	while [ $a = y ]
	do
		read -p "Please enter the name of the user: " user
		useradd $user
		mkdir /home/$user
		read -p "Are there any more users you would like to add?[y/n]: " a
	done

	pause
}

##Changes all the user passwords
chgPasswd(){
    echo "$LogTime uss: [$UserName]# Changing all the user passwords to Cyb3rPatr!0t$." >> output.log
        ##Look for valid users that have different UID that not 1000+
        cut -d: -f1,3 /etc/passwd | egrep ':[0-9]{4}$' | cut -d: -f1 > users
        ##Looks for users with the UID and GID of 0
        hUSER=`cut -d: -f1,3 /etc/passwd | egrep ':[0]{1}$' | cut -d: -f1`
        echo "$hUSER is a hidden user"
        sed -i '/root/ d' users

        PASS='Cyb3rPatr!0t$'
        for x in `cat users`
        do
            echo -e "$PASS\n$PASS" | passwd $x >> output.log
            echo -e "Password for $x has been changed."
            ##Changes the USER password policy
            chage -M 90 -m 7 -W 15 $x
        done
    echo "$LogTime uss: [$UserName]# Passwords have been changed." >> output.log

        pause
}

sysctl() {
    local sysctl_conf_path='/etc/sysctl.conf'
    
    # Define the configurations to add
    local configurations=(
        "# Disable ICMP redirects"
        "net.ipv4.conf.all.accept_redirects = 0"
        "# Disable IP redirecting"
        "net.ipv4.ip_forward = 0"
        "net.ipv4.conf.all.send_redirects = 0"
        "net.ipv4.conf.default.send_redirects = 0"
        "# Disable IP spoofing"
        "net.ipv4.conf.all.rp_filter = 1"
        "# Disable IP source routing"
        "net.ipv4.conf.all.accept_source_route = 0"
        "# SYN Flood Protection"
        "net.ipv4.tcp_max_syn_backlog = 2048"
        "net.ipv4.tcp_synack_retries = 2"
        "net.ipv4.tcp_syn_retries = 5"
        "net.ipv4.tcp_syncookies = 1"
        "# Disable IPV6"
        "net.ipv6.conf.all.disable_ipv6 = 1"
        "net.ipv6.conf.default.disable_ipv6 = 1"
        "net.ipv6.conf.lo.disable_ipv6 = 1"
    )
    
    # Append configurations to sysctl.conf if not already present
    {
        # Check if each configuration is already in the file
        for config in "${configurations[@]}"; do
            if ! grep -qF "$config" "$sysctl_conf_path"; then
                echo "$config"
            fi
        done
    } | sudo tee -a "$sysctl_conf_path" > /dev/null
    sed -i '$a net.ipv6.conf.all.disable_ipv6 = 1' /etc/sysctl.conf 
	sed -i '$a net.ipv6.conf.default.disable_ipv6 = 1' /etc/sysctl.conf
	sed -i '$a net.ipv6.conf.lo.disable_ipv6 = 1' /etc/sysctl.conf 

	##Disables IP Spoofing
	sed -i '$a net.ipv4.conf.all.rp_filter=1' /etc/sysctl.conf

	##Disables IP source routing
	sed -i '$a net.ipv4.conf.all.accept_source_route=0' /etc/sysctl.conf

	##SYN Flood Protection
	sed -i '$a net.ipv4.tcp_max_syn_backlog = 2048' /etc/sysctl.conf
	sed -i '$a net.ipv4.tcp_synack_retries = 2' /etc/sysctl.conf
	sed -i '$a net.ipv4.tcp_syn_retries = 5' /etc/sysctl.conf
	sed -i '$a net.ipv4.tcp_syncookies=1' /etc/sysctl.conf

	##IP redirecting is disallowed
	sed -i '$a net.ipv4.ip_foward=0' /etc/sysctl.conf
	sed -i '$a net.ipv4.conf.all.send_redirects=0' /etc/sysctl.conf
	sed -i '$a net.ipv4.conf.default.send_redirects=0' /etc/sysctl.conf
    # Apply the new sysctl settings
    sudo sysctl -p
    echo "Sysctl settings have been updated and applied."
}

##Searches for netcat and its startup script and comments out the lines
nc(){

    #yum list | grep -i 'nc|netcat' 
    #if [ $? -eq 0 ]
    #then
        cat runningProcesses.log
            read -p "What is the name of the suspected netcat?[none]: " nc
                if [ $nc == "none"]
                then
                    echo "k xd"
                else
                    whereis $nc > Path
                    ALIAS=`alias | grep nc | cut -d' ' -f2 | cut -d'=' -f1`
                    PID=`pgrep $nc`
                    for path in `cat Path`
                    do
                            echo $path
                            if [ $? -eq 0 ]
                            then
                                    sed -i 's/^/#/' $path
                                    kill $PID
                            else
                                    echo "This is not a netcat process."
                            fi
                    done
                fi

                ls /etc/init | grep $nc.conf >> /dev/null
                if [ $? -eq 0 ]
                then
                        cat /etc/init/$nc.conf | grep -E -i 'nc|netcat|$ALIAS' >> /dev/null
                        if [ $? -eq 0 ]
                        then
                                sed -i 's/^/#/' /etc/init/$nc.conf
                                kill $PID
                        else
                                echo "This is not a netcat process."
                        fi
                fi

                ls /etc/init.d | grep $nc >>/dev/null
                if [ $? -eq 0 ]
                then
                        cat /etc/init.d/$nc | grep -E -i 'nc|netcat|$ALIAS' >> /dev/null
                        if [ $? -eq 0 ]
                        then
                                sed -i 's/^/#/' /etc/init.d/$nc
                                kill $PID
                        else
                                echo "This is not a netcat process."
                        fi
                fi

                ls /etc/cron.d | grep $nc >>/dev/null
                if [ $? -eq 0 ]
                then
                        cat /etc/cron.d/$nc | grep -E -i 'nc|netcat|$ALIAS' >> /dev/null
                        if [ $? -eq 0 ]
                        then
                                sed -i 's/^/#/' /etc/init.d/$nc
                                kill $PID
                        else
                                echo "This is not a netcat process."
                        fi
                fi

                ls /etc/cron.hourly | grep $nc >>/dev/null
                if [ $? -eq 0 ]
                then
                        cat /etc/cron.hourly/$nc | grep -E -i 'nc|netcat|$ALIAS' >> /dev/null
                        if [ $? -eq 0 ]
                        then
                                sed -i 's/^/#/' /etc/init.d/$nc
                                kill $PID
                        else
                                echo "This is not a netcat process."
                        fi
                fi

                for x in $(ls /var/spool/cron/crontabs)
                do
                    cat $x | grep '$nc|nc|netcat|$ALIAS'
                    if [ $? -eq 0 ]
                    then
                        sed -i 's/^/#/' /var/spool/cron/crontabs/$x
                        kill $PID
                    else
                        echo "netcat has not been found in $x crontabs."
                    fi
                done

                cat /etc/crontab | grep -i 'nc|netcat|$ALIAS'
                if [ $? -eq 0 ]
                then
                    echo "NETCAT FOUND IN CRONTABS! GO AND REMOVE!!!!!!!!!!"
                fi
                echo "Uninstalling netcat now."

    #			apt-get autoremove --purge netcat netcat-openbsd netcat-traditional
    #else
        #echo "Netcat is not installed"
    #fi
        pause
}

##Sets the password policy
passPol() 
{
    echo "$LogTime uss: [$UserName]# Setting password policy..." >> output.log
    echo "$LogTime uss: [$UserName]# Installing Craklib..." >> output.log
	apt-get install libpam-cracklib || yum install libpam-cracklib
	wait
    echo "$LogTime uss: [$UserName]# Cracklib installed." >> output.log
	sed -i.bak -e 's/PASS_MAX_DAYS\t[[:digit:]]\+/PASS_MAX_DAYS\t90/' /etc/login.defs
	sed -i -e 's/PASS_MIN_DAYS\t[[:digit:]]\+/PASS_MIN_DAYS\t10/' /etc/login.defs
	sed -i -e 's/PASS_WARN_AGE\t[[:digit:]]\+/PASS_WARN_AGE\t7/' /etc/login.defs
	sed -i -e 's/difok=3\+/difok=3 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1/' /etc/pam.d/common-password
    echo "$LogTime uss: [$UserName]# Password Policy." >> output.log
    configPassPolicy
    minlenpass
    update_pam_auth
	pause
    chgPasswd
}

secureShadow() {
    echo "$LogTime uss: [$UserName]# Securing /etc/shadow..." >> output.log
        chmod 640 /etc/shadow

        ls -l /etc/shadow
        pause
}

update_pam_auth() {
    local pam_auth_file='/etc/pam.d/common-auth'
    
    # Check if the PAM authentication file exists
    if [ ! -f "$pam_auth_file" ]; then
        echo "$pam_auth_file not found."
        return
    fi

    # Create a backup of the original PAM configuration file
    sudo cp "$pam_auth_file" "$pam_auth_file.bak"

    # Update the pam_tally2 configuration
    sudo awk -v OFS='\n' '
    {
        if ($0 ~ /pam_tally2.so/) {
            # Check if "deny=" or "unlock_time=" is present
            if ($0 ~ /deny=/ || $0 ~ /unlock_time=/) {
                # Update the line with deny and unlock_time
                sub(/deny=[0-9]+/, "deny=5");
                sub(/unlock_time=[0-9]+/, "unlock_time=1800");
            } else {
                # Append deny and unlock_time if not present
                $0 = $0 " deny=5 unlock_time=1800";
            }
        }
        print $0;
    }' "$pam_auth_file" | sudo tee "$pam_auth_file" > /dev/null

    echo "Updated pam_tally2 configuration in common-auth."
}

configPassPolicy() {
    # Install the required package
    sudo apt-get install libpam-cracklib -y -qq

    # Create a backup directory if it doesn't exist
    backup_dir=~/Desktop/backups
    mkdir -p "$backup_dir"

    # Backup common-auth and common-password files
    sudo cp /etc/pam.d/common-auth "$backup_dir/"
    sudo cp /etc/pam.d/common-password "$backup_dir/"

    # Check if the specific line exists in common-auth
    if ! grep -q "auth optional pam_tally.so deny=5 unlock_time=900 onerr=fail audit even_deny_root_account silent" /etc/pam.d/common-auth; then
        echo "auth optional pam_tally.so deny=5 unlock_time=900 onerr=fail audit even_deny_root_account silent" | sudo tee -a /etc/pam.d/common-auth > /dev/null
    fi

    # Append the password policy settings if not already present
    if ! grep -q "password requisite pam_cracklib.so" /etc/pam.d/common-password; then
        {
            echo -e "password requisite pam_cracklib.so retry=3 minlen=8 difok=3 reject_username minclass=3 maxrepeat=2 dcredit=1 ucredit=1 lcredit=1 ocredit=1"
            echo "password requisite pam_pwhistory.so use_authtok remember=24 enforce_for_root"
        } | sudo tee -a /etc/pam.d/common-password > /dev/null
    fi

    echo "Password policies have been set, editing /etc/login.defs and pam.d."
}

manage_users(filepath) {
    file_path=$1

    # Check if the file exists
    if [ ! -f "$file_path" ]; then
        echo "File $file_path not found."
        return
    fi

    # Step 1: Get the list of users with UID >= 1000
    all_users=$(cut -d: -f1,3 /etc/passwd | awk -F: '$2 >= 1000 {print $1}')
    
    # Step 2: Read users from the input file and store them in an array
    declare -A file_users
    while IFS=',' read -r user is_admin; do
        file_users["$user"]=$is_admin
    done < "$file_path"

    # Step 3: Remove users not present in the text file
    for system_user in $all_users; do
        if [[ -z "${file_users[$system_user]}" ]]; then
            echo "Removing user $system_user as they are not in the text file..."
            sudo userdel "$system_user"
        fi
    done

    # Step 4: Modify admin privileges for users in the text file
    for user in "${!file_users[@]}"; do
        if id "$user" &>/dev/null; then
            if [ "${file_users[$user]}" = "y" ]; then
                sudo usermod -aG sudo "$user"
                echo "Granted administrative privileges to $user."
            else
                sudo deluser "$user" sudo
                echo "Removed administrative privileges from $user."
            fi
        else
            echo "User $user does not exist on the system, skipping..."
        fi
    done
}

users_manager()
{
    echo "What is the exact filepath to the users text file?"
    read filepath
    manage_users(filepath)
}

# Function to remove a program
remove_program() {
    local program_name=$1
    sudo apt remove -y "$program_name"
    if [ $? -eq 0 ]; then
        echo "Package $program_name has been removed."
    else
        echo "There was an error removing $program_name."
    fi
}

# Function to list non-essential programs (this function needs to be defined)
list_nonessential_programs() {
    # Example command to list installed packages, modify as needed
    dpkg --get-selections | awk '{print $1}' | grep -v -E 'essential|core'  # Modify the filtering as needed
}

# Main program manager method
manage_nonessential_programs() {
    local programs
    programs=$(list_nonessential_programs)

    if [ -z "$programs" ]; then
        echo "No non-essential programs found."
        return
    fi

    # Iterate through the non-essential programs
    while IFS= read -r program; do
        echo "Program: $program"
        read -p "Do you want to remove '$program'? (yes/no): " response
        response=$(echo "$response" | tr '[:upper:]' '[:lower:]')

        if [ "$response" == "yes" ]; then
            remove_program "$program"
        else
            echo "Skipping $program."
        fi
    done <<< "$programs"

    read -p 'Do you need to secure vsftpd.conf? (yes/no): ' com
    com=$(echo "$com" | tr '[:upper:]' '[:lower:]')

    if [ "$com" == "yes" ]; then
        config='/etc/vsftpd.conf'
        if [ -f "$config" ]; then
            # Backup original config
            sudo cp "$config" "$config.bak"
            # Secure vsftpd.conf
            sudo awk '{
                if ($0 ~ /^anonymous_enable/) { print "anonymous_enable=YES"; }
                else if ($0 ~ /^local_enable/) { print "local_enable=YES"; }
                else if ($0 ~ /^write_enable/) { print "write_enable=YES"; }
                else if ($0 ~ /^chroot_local_user/) { print "chroot_local_user=YES"; }
                else { print; }
            }' "$config" | sudo tee "$config" > /dev/null

            # Restart vsftpd service
            sudo systemctl restart vsftpd
            echo "vsftpd configuration has been secured."
        else
            echo "$config not found."
        fi
    fi
}

minlenpass() {
    local com='/etc/pam.d/common-password'
    
    # Check if the PAM configuration file exists
    if [ ! -f "$com" ]; then
        echo "$com not found."
        return
    fi

    # Backup the original configuration
    sudo cp "$com" "$com.bak"

    # Modify the PAM configuration file
    sudo awk '{
        if ($0 ~ /^password \[success=1 default=ignore\] pam_unix.so obscure sha512/) {
            print "password [success=1 default=ignore] pam_unix.so obscure sha512 minlen=12";
        } else {
            print;
        }
    }' "$com" | sudo tee "$com" > /dev/null

    echo "Minimum password length has been set to 12."
}

lightDmStuff() {
    local lightdm_conf="/etc/lightdm/lightdm.conf"
    local gdm_conf="/etc/gdm3/greeter.dconf-defaults"
    
    # Change permissions to allow editing
    sudo chmod 777 "$lightdm_conf"
    
    read -p 'Debian or Ubuntu? (d/u): ' com
    com=$(echo "$com" | tr '[:upper:]' '[:lower:]')  # Normalize input to lowercase
    
    if [[ "$com" == "u" ]]; then
        if [[ -f "$lightdm_conf" ]]; then
            # Update lightdm.conf for Ubuntu
            sudo sed -i 's/^allows-guest=.*/allow-guest=false/' "$lightdm_conf"
            sudo sed -i 's/^greeter-show-manual-login=.*/greeter-show-manual-login=true/' "$lightdm_conf"
            sudo sed -i 's/^greeter-hide-users=.*/greeter-hide-users=true/' "$lightdm_conf"
            sudo sed -i 's/^autologin-user=.*/autologin-user=none/' "$lightdm_conf"
        else
            echo "No file found at $lightdm_conf"
        fi
    else
        if [[ -f "$lightdm_conf" ]]; then
            # Update lightdm.conf for Debian
            sudo sed -i 's/^Allows-guest=.*/Allow-guest=false/' "$lightdm_conf"
            sudo sed -i 's/^Greeter-show-manual-login=.*/Greeter-show-manual-login=true/' "$lightdm_conf"
            sudo sed -i 's/^Greeter-hide-users=.*/Greeter-hide-users=true/' "$lightdm_conf"
            sudo sed -i 's/^Autologin-user=.*/Autologin-user=none/' "$lightdm_conf"
        else
            echo "No file found at $lightdm_conf"
        fi
        
        # Update gdm3 settings
        if [[ -f "$gdm_conf" ]]; then
            sudo sed -i 's/^Allows-guest=.*/Allow-guest=false/' "$gdm_conf"
            sudo sed -i 's/^Disable-user-list=.*/Disable-user-list=true/' "$gdm_conf"
            sudo sed -i 's/^Disable-restart-buttons=.*/Disable-restart-buttons=true/' "$gdm_conf"
            sudo sed -i 's/^AutomaticLoginEnable=.*/AutomaticLoginEnable=false/' "$gdm_conf"
        else
            echo "No file found at $gdm_conf"
        fi
    fi
    
    # Restore permissions
    sudo chmod 644 "$lightdm_conf"
    
    echo "LightDM settings have been modified."
}

# Function to purge common packages
commonPurge() {
    local packages=(
        "netcat"
        "netcat-openbsd"
        "netcat-traditional"
        "ncat"
        "pnetcat"
        "socat"
        "sock"
        "socket"
        "sbd"
        "john"
        "john-data"
        "hydra"
        "hydra-gtk"
        "aircrack-ng"
        "fcrackzip"
        "lcrack"
        "ophcrack"
        "ophcrack-cli"
        "pdfcrack"
        "pyrit"
        "rarcrack"
        "sipcrack"
        "irpas"
    )

    for package in "${packages[@]}"; do
        if sudo apt-get purge -y "$package" -qq; then
            echo "$package has been removed."
        else
            echo "Failed to remove $package."
        fi
    done

    # Remove netcat symbolic link if it exists
    if [[ -L /usr/bin/nc ]]; then
        sudo rm /usr/bin/nc
        echo "Netcat and all other instances have been removed."
    else
        echo "No Netcat symbolic link found to remove."
    fi
}

# Housekeeping Function
housekeeping() {
    echo "Starting housekeeping..."

    # Remove all aliases
    unalias -a
    echo "All aliases have been removed."

    # Lock the root account
    sudo usermod -L root
    echo "Root account has been locked."

    # Set permissions on bash history
    chmod 640 ~/.bash_history
    echo "Bash history file permissions set."

    # Set permissions on shadow file
    sudo chmod 604 /etc/shadow
    echo "Read/Write permissions on shadow have been set."

    # Check user folders
    echo "Check for any user folders that do not belong to any users."
    ls -a /home/ >> ~/Desktop/Script.log

    # Check for files for users that should not be admins
    echo "Check for any files for users that should not be administrators."
    ls -a /etc/sudoers.d >> ~/Desktop/Script.log

    # Backup and clear rc.local
    sudo cp /etc/rc.local ~/Desktop/backups/
    echo > /etc/rc.local
    echo "exit 0" | sudo tee -a /etc/rc.local
    echo "Any startup scripts have been removed."

    # Remove scripts in /bin
    find /bin/ -name "*.sh" -type f -delete
    echo "Scripts in /bin have been removed."

    echo "Housekeeping done."
}

# Logging Function
logging() {
    echo "Starting logging..."

    logs_dir=~/Desktop/logs
    mkdir -p "$logs_dir"
    chmod 777 "$logs_dir"
    echo "Logs folder has been created on the Desktop."

    # Create logs for various system information
    cp /etc/services "$logs_dir/allports.log"
    chmod 777 "$logs_dir/allports.log"
    echo "All ports log has been created."

    dpkg -l > "$logs_dir/packages.log"
    chmod 777 "$logs_dir/packages.log"
    echo "All packages log has been created."

    apt-mark showmanual > "$logs_dir/manuallyinstalled.log"
    chmod 777 "$logs_dir/manuallyinstalled.log"
    echo "All manually installed packages log has been created."

    service --status-all > "$logs_dir/allservices.txt"
    chmod 777 "$logs_dir/allservices.txt"
    echo "All running services log has been created."

    ps ax > "$logs_dir/processes.log"
    chmod 777 "$logs_dir/processes.log"
    echo "All running processes log has been created."

    ss -l > "$logs_dir/socketconnections.log"
    chmod 777 "$logs_dir/socketconnections.log"
    echo "All socket connections log has been created."

    sudo netstat -tlnp > "$logs_dir/listeningports.log"
    chmod 777 "$logs_dir/listeningports.log"
    echo "All listening ports log has been created."

    cp /var/log/auth.log "$logs_dir/auth.log"
    chmod 777 "$logs_dir/auth.log"
    echo "Auth log has been created."

    cp /var/log/syslog "$logs_dir/syslog.log"
    chmod 777 "$logs_dir/syslog.log"
    echo "System log has been created."

    echo "Logging done."
}

##Removes basik hak tools
hakTools() {

    ##CHANGE TO GREP -i
    echo "$LogTime uss: [$UserName]# Removing hacking tools..." >> output.log
    ##Looks for apache web server
        dpkg -l | grep apache >> output.log
        if [ $? -eq 0 ];
        then
                read -p "Do you want apache installed on the system[y/n]: "
                if [ $a = n ];
                then
                        apt-get autoremove -y --purge apache2 >> output.log
                else
                        if [ -e /etc/apache2/apache2.conf ]
                    then
                        chown -R root:root /etc/apache2
                        chown -R root:root /etc/apache
                        echo \<Directory \> >> /etc/apache2/apache2.conf
                        echo -e ' \t AllowOverride None' >> /etc/apache2/apache2.conf
                        echo -e ' \t Order Deny,Allow' >> /etc/apache2/apache2.conf
                        echo -e ' \t Deny from all' >> /etc/apache2/apache2.conf
                        echo UserDir disabled root >> /etc/apache2/apache2.conf
                    else
                        ##Installs and configures apache
                        apt-get install apache2 -y
                            chown -R root:root /etc/apache2
                            chown -R root:root /etc/apache
                            echo \<Directory \> >> /etc/apache2/apache2.conf
                            echo -e ' \t AllowOverride None' >> /etc/apache2/apache2.conf
                            echo -e ' \t Order Deny,Allow' >> /etc/apache2/apache2.conf
                            echo -e ' \t Deny from all' >> /etc/apache2/apache2.conf
                            echo UserDir disabled root >> /etc/apache2/apache2.conf

                        ##Installs and configures sql
                        apt-get install mysql-server -y

                        ##Installs and configures php5
                        apt-get install php5 -y
                        chmod 640 /etc/php5/apache2/php.ini
                    fi
                fi
        else
            echo "Apache is not installed"
            sleep 1
        fi
    ##Looks for john the ripper
        dpkg -l | grep john >> output.log
        if [ $? -eq 0 ];
        then
                echo "JOHN HAS BEEEN FOUND! DIE DIE DIE"
                apt-get autoremove -y --purge john >> output.log
                echo "John has been ripped"
                sleep 1
        else
                echo "John The Ripper has not been found on the system"
                sleep 1
        fi
    ##Look for HYDRA
        dpkg -l | grep hydra >>output.log
        if [ $? -eq 0 ];
        then
            echo "HEIL HYDRA"
            apt-get autoremove -y --purge hydra >> output.log
        else
            echo "Hydra has not been found."
        fi
    ##Looks for nginx web server
        dpkg -l | grep nginx >> output.log
        if [ $? -eq 0 ];
        then
                echo "NGINX HAS BEEN FOUND! OHHHH NOOOOOO!"
                apt-get autoremove -y --purge nginx >> output.log
        else
                echo "NGINX has not been found"
                sleep 1
        fi
    ##Looks for samba
        if [ -d /etc/samba ];
        then
            read -p "Samba has been found on this system, do you want to remove it?[y/n]: " a
            if [ $a = y ];
            then
    echo "$LogTime uss: [$UserName]# Uninstalling samba..." >> output.log
                sudo apt-get autoremove --purge -y samba >> output.log
                sudo apt-get autoremove --purge -y samba >> output.log
    echo "$LogTime uss: [$UserName]# Samba has been removed." >> output.log
            else
                sed -i '82 i\restrict anonymous = 2' /etc/samba/smb.conf
                ##List shares
            fi
        else
            echo "Samba has not been found."
            sleep 1
        fi
    ##LOOK FOR DNS
        if [ -d /etc/bind ];
        then
            read -p "DNS server is running would you like to shut it down?[y/n]: " a
            if [ $a = y ];
            then
                apt-get autoremove -y --purge bind9 
            fi
        else
            echo "DNS not found."
            sleep 1
        fi
    ##Looks for FTP
        dpkg -l | grep -i 'vsftpd|ftp' >> output.log
        if [ $? -eq 0 ]
        then	
            read -p "FTP Server has been installed, would you like to remove it?[y/n]: " a
            if [ $a = y ]
            then
                PID = `pgrep vsftpd`
                sed -i 's/^/#/' /etc/vsftpd.conf
                kill $PID
                apt-get autoremove -y --purge vsftpd ftp
            else
                sed -i 's/anonymous_enable=.*/anonymous_enable=NO/' /etc/vsftpd.conf
                sed -i 's/local_enable=.*/local_enable=YES/' /etc/vsftpd.conf
                sed -i 's/#write_enable=.*/write_enable=YES/' /etc/vsftpd.conf
                sed -i 's/#chroot_local_user=.*/chroot_local_user=YES/' /etc/vsftpd.conf
            fi
        else
            echo "FTP has not been found."
            sleep 1
        fi
    ##Looks for TFTPD
        dpkg -l | grep tftpd >> output.log
        if [ $? -eq 0 ]
        then
            read -p "TFTPD has been installed, would you like to remove it?[y/n]: " a
            if [ $a = y ]
            then
                apt-get autoremove -y --purge tftpd
            fi
        else
            echo "TFTPD not found."
            sleep 1
        fi
    ##Looking for VNC
        dpkg -l | grep -E 'x11vnc|tightvncserver' >> output.log
        if [ $? -eq 0 ]
        then
            read -p "VNC has been installed, would you like to remove it?[y/n]: " a
            if [ $a = y ]
            then
                apt-get autoremove -y --purge x11vnc tightvncserver 
            ##else
                ##Configure VNC
            fi
        else
            echo "VNC not found."
            sleep 1
        fi

    ##Looking for NFS
        dpkg -l | grep nfs-kernel-server >> output.log
        if [ $? -eq 0 ]
        then	
            read -p "NFS has been found, would you like to remove it?[y/n]: " a
            if [ $a = 0 ]
            then
                apt-get autoremove -y --purge nfs-kernel-server
            ##else
                ##Configure NFS
            fi
        else
            echo "NFS has not been found."
            sleep 1
        fi
    ##Looks for snmp
        dpkg -l | grep snmp >> output.log
        if [ $? -eq 0 ]
        then	
            echo "SNMP HAS BEEN LOCATED!"
            apt-get autoremove -y --purge snmp
        else
            echo "SNMP has not been found."
            sleep 1
        fi
    ##Looks for sendmail and postfix
        dpkg -l | grep -E 'postfix|sendmail' >> output.log
        if [ $? -eq 0 ]
        then
            echo "Mail servers have been found."
            apt-get autoremove -y --purge postfix sendmail
        else
            echo "Mail servers have not been located."
            sleep 1
        fi
    ##Looks xinetd
        dpkg -l | grep xinetd >> output.log
        if [ $? -eq 0 ]
        then
            echo "XINIT HAS BEEN FOUND!"
            apt-get autoremove -y --purge xinetd
        else
            echo "XINETD has not been found."
            sleep 1
        fi
        pause
}

cron() {
    #	Listing all the cronjobs
        echo "###CRONTABS###" > cron.log
        for x in $(cat users); do crontab -u $x -l; done >> cron.log
        echo "###CRON JOBS###" >> cron.log
        ls /etc/cron.* >> cron.log
        ls /var/spool/cron/crontabs/.* >> cron.log
        ls /etc/crontab >> cron.log

    #	Listing the init.d/init files
        echo "###Init.d###" >> cron.log
        ls /etc/init.d >> cron.log

        echo "###Init###" >> cron.log
        ls /etc/init >> cron.log
        cat cron.log
        pause
}

main() {
    # 1. Set up the firewall
    ufw
    # 2. Disable root login for SSH
    disable_root_login
    # 3. Manage non-essential programs and clean up
    manage_nonessential_programs
    # 4. User management: List and create users
    users_manager
    createUser
    # 5. Configure password policies
    passPol
    # 6. Set up system-wide configurations
    sysctl
    lightDmStuff
    # 7. Purge unnecessary packages and scripts
    commonPurge
    hakTools
    nc
    # 8. Perform housekeeping tasks
    housekeeping
    secureShadow
    cron
    # 9. Create logs for tracking changes and system status
    logging
    sudoers
    # 10. Backup system configurations
    backup
    # 11. Update the system and secure vsftpd configuration
    update
    secure_vsftpd_conf
    # Final messages to the user
    echo "Done!"
    echo "System Settings>Software & Updates>Updates>Turn on Automatic Updates"
}
#Cyb3rPatr!0t$
main