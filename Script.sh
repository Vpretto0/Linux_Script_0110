#ANTES DE EMPEZAR: verificar la lista de excpciones de cypath en README 

echo " ____                        _ _                  _         ____ _ _               
|  _ \ __ _ _ __   __ _  ___(_) |_ ___  ___    __| | ___   / ___(_) |__   ___ _ __ 
| |_) / _\` | '_ \ / _\` |/ __| | __/ _ \/ __|  / _\` |/ _ \ | |   | | '_ \ / _ \ '__|
|  __/ (_| | |_) | (_| | (__| | || (_) \__ \ | (_| |  __/ | |___| | |_) |  __/ |   
|_|   \__,_| .__/ \__,_|\___|_|\__\___/|___/  \__,_|\___|  \____|_|_.__/ \___|_|   
           |_|                                                                     " 

#!/usr/bin/env bash
{
 l_mname="cramfs" # set module name
 l_mtype="fs" # set module type
 l_mpath="/lib/modules/**/kernel/$l_mtype"
 l_mpname="$(tr '-' '_' <<< "$l_mname")"
 l_mndir="$(tr '-' '/' <<< "$l_mname")"
 module_loadable_fix()
 {
 # If the module is currently loadable, add "install {MODULE_NAME} /bin/false" to a file in
"/etc/modprobe.d"
 l_loadable="$(modprobe -n -v "$l_mname")"
 [ "$(wc -l <<< "$l_loadable")" -gt "1" ] && l_loadable="$(grep -P --
"(^\h*install|\b$l_mname)\b" <<< "$l_loadable")"
 if ! grep -Pq -- '^\h*install \/bin\/(true|false)' <<< "$l_loadable"; then
 echo -e "\n - setting module: \"$l_mname\" to be not loadable"
 echo -e "install $l_mname /bin/false" >> /etc/modprobe.d/"$l_mpname".conf
 fi
 }
 module_loaded_fix()
 {
 # If the module is currently loaded, unload the module
 if lsmod | grep "$l_mname" > /dev/null 2>&1; then
 echo -e "\n - unloading module \"$l_mname\""
 modprobe -r "$l_mname"
 fi
 }
 module_deny_fix()
 {
 # If the module isn't deny listed, denylist the module
 if ! modprobe --showconfig | grep -Pq -- "^\h*blacklist\h+$l_mpname\b"; then
 echo -e "\n - deny listing \"$l_mname\""
 echo -e "blacklist $l_mname" >> /etc/modprobe.d/"$l_mpname".conf
 fi
 }
 # Check if the module exists on the system
 for l_mdir in $l_mpath; do
 if [ -d "$l_mdir/$l_mndir" ] && [ -n "$(ls -A $l_mdir/$l_mndir)" ]; then
 echo -e "\n - module: \"$l_mname\" exists in \"$l_mdir\"\n - checking if disabled..."
 module_deny_fix
 if [ "$l_mdir" = "/lib/modules/$(uname -r)/kernel/$l_mtype" ]; then
 module_loadable_fix
 module_loaded_fix
 fi
 else
 echo -e "\n - module: \"$l_mname\" doesn't exist in \"$l_mdir\"\n"
 fi
 done
 echo -e "\n - remediation of module: \"$l_mname\" complete\n"
}
{
 l_mname="freevxfs" # set module name
 l_mtype="fs" # set module type
 l_mpath="/lib/modules/**/kernel/$l_mtype"
 l_mpname="$(tr '-' '_' <<< "$l_mname")"
 l_mndir="$(tr '-' '/' <<< "$l_mname")"
 module_loadable_fix()
 {
 # If the module is currently loadable, add "install {MODULE_NAME} /bin/false" to a file in
"/etc/modprobe.d"
 l_loadable="$(modprobe -n -v "$l_mname")"
 [ "$(wc -l <<< "$l_loadable")" -gt "1" ] && l_loadable="$(grep -P --
"(^\h*install|\b$l_mname)\b" <<< "$l_loadable")"
 if ! grep -Pq -- '^\h*install \/bin\/(true|false)' <<< "$l_loadable"; then
 echo -e "\n - setting module: \"$l_mname\" to be not loadable"
 echo -e "install $l_mname /bin/false" >> /etc/modprobe.d/"$l_mpname".conf
 fi
 }
 module_loaded_fix()
 {
 # If the module is currently loaded, unload the module
 if lsmod | grep "$l_mname" > /dev/null 2>&1; then
 echo -e "\n - unloading module \"$l_mname\""
 modprobe -r "$l_mname"
 fi
 }
 module_deny_fix()
 {
 # If the module isn't deny listed, denylist the module
 if ! modprobe --showconfig | grep -Pq -- "^\h*blacklist\h+$l_mpname\b"; then
 echo -e "\n - deny listing \"$l_mname\""
 echo -e "blacklist $l_mname" >> /etc/modprobe.d/"$l_mpname".conf
 fi
 }
 # Check if the module exists on the system
 for l_mdir in $l_mpath; do
 if [ -d "$l_mdir/$l_mndir" ] && [ -n "$(ls -A $l_mdir/$l_mndir)" ]; then
 echo -e "\n - module: \"$l_mname\" exists in \"$l_mdir\"\n - checking if disabled..."
 module_deny_fix
 if [ "$l_mdir" = "/lib/modules/$(uname -r)/kernel/$l_mtype" ]; then
 module_loadable_fix
 module_loaded_fix
 fi
 else
 echo -e "\n - module: \"$l_mname\" doesn't exist in \"$l_mdir\"\n"
 fi
 done
 echo -e "\n - remediation of module: \"$l_mname\" complete\n"
}
{
 l_mname="hfs" # set module name
 l_mtype="fs" # set module type
 l_mpath="/lib/modules/**/kernel/$l_mtype"
 l_mpname="$(tr '-' '_' <<< "$l_mname")"
 l_mndir="$(tr '-' '/' <<< "$l_mname")"
 module_loadable_fix()
 {
 # If the module is currently loadable, add "install {MODULE_NAME} /bin/false" to a file in
"/etc/modprobe.d"
 l_loadable="$(modprobe -n -v "$l_mname")"
 [ "$(wc -l <<< "$l_loadable")" -gt "1" ] && l_loadable="$(grep -P --
"(^\h*install|\b$l_mname)\b" <<< "$l_loadable")"
 if ! grep -Pq -- '^\h*install \/bin\/(true|false)' <<< "$l_loadable"; then
 echo -e "\n - setting module: \"$l_mname\" to be not loadable"
 echo -e "install $l_mname /bin/false" >> /etc/modprobe.d/"$l_mpname".conf
 fi
 }
 module_loaded_fix()
 {
 # If the module is currently loaded, unload the module
 if lsmod | grep "$l_mname" > /dev/null 2>&1; then
 echo -e "\n - unloading module \"$l_mname\""
 modprobe -r "$l_mname"
 fi
 }
 module_deny_fix()
 {
 # If the module isn't deny listed, denylist the module
 if ! modprobe --showconfig | grep -Pq -- "^\h*blacklist\h+$l_mpname\b"; then
 echo -e "\n - deny listing \"$l_mname\""
 echo -e "blacklist $l_mname" >> /etc/modprobe.d/"$l_mpname".conf
 fi
 }
 # Check if the module exists on the system
 for l_mdir in $l_mpath; do
 if [ -d "$l_mdir/$l_mndir" ] && [ -n "$(ls -A $l_mdir/$l_mndir)" ]; then
 echo -e "\n - module: \"$l_mname\" exists in \"$l_mdir\"\n - checking if disabled..."
 module_deny_fix
 if [ "$l_mdir" = "/lib/modules/$(uname -r)/kernel/$l_mtype" ]; then
 module_loadable_fix
 module_loaded_fix
 fi
 else
 echo -e "\n - module: \"$l_mname\" doesn't exist in \"$l_mdir\"\n"
 fi
 done
 echo -e "\n - remediation of module: \"$l_mname\" complete\n"
}
{
 l_mname="hfsplus" # set module name
 l_mtype="fs" # set module type
 l_mpath="/lib/modules/**/kernel/$l_mtype"
 l_mpname="$(tr '-' '_' <<< "$l_mname")"
 l_mndir="$(tr '-' '/' <<< "$l_mname")"
 module_loadable_fix()
 {
 # If the module is currently loadable, add "install {MODULE_NAME} /bin/false" to a file in
"/etc/modprobe.d"
 l_loadable="$(modprobe -n -v "$l_mname")"
 [ "$(wc -l <<< "$l_loadable")" -gt "1" ] && l_loadable="$(grep -P --
"(^\h*install|\b$l_mname)\b" <<< "$l_loadable")"
 if ! grep -Pq -- '^\h*install \/bin\/(true|false)' <<< "$l_loadable"; then
 echo -e "\n - setting module: \"$l_mname\" to be not loadable"
 echo -e "install $l_mname /bin/false" >> /etc/modprobe.d/"$l_mpname".conf
 fi
 }
 module_loaded_fix()
 {
 # If the module is currently loaded, unload the module
 if lsmod | grep "$l_mname" > /dev/null 2>&1; then
 echo -e "\n - unloading module \"$l_mname\""
 modprobe -r "$l_mname"
 fi
 }
 module_deny_fix()
 {
 # If the module isn't deny listed, denylist the module
 if ! modprobe --showconfig | grep -Pq -- "^\h*blacklist\h+$l_mpname\b"; then
 echo -e "\n - deny listing \"$l_mname\""
 echo -e "blacklist $l_mname" >> /etc/modprobe.d/"$l_mpname".conf
 fi
 }
 # Check if the module exists on the system
 for l_mdir in $l_mpath; do
 if [ -d "$l_mdir/$l_mndir" ] && [ -n "$(ls -A $l_mdir/$l_mndir)" ]; then
 echo -e "\n - module: \"$l_mname\" exists in \"$l_mdir\"\n - checking if disabled..."
 module_deny_fix
 if [ "$l_mdir" = "/lib/modules/$(uname -r)/kernel/$l_mtype" ]; then
 module_loadable_fix
 module_loaded_fix
 fi
 else
 echo -e "\n - module: \"$l_mname\" doesn't exist in \"$l_mdir\"\n"
 fi
 done
 echo -e "\n - remediation of module: \"$l_mname\" complete\n"
}
{
 l_mname="jffs2" # set module name
 l_mtype="fs" # set module type
 l_mpath="/lib/modules/**/kernel/$l_mtype"
 l_mpname="$(tr '-' '_' <<< "$l_mname")"
 l_mndir="$(tr '-' '/' <<< "$l_mname")"
 module_loadable_fix()
 {
 # If the module is currently loadable, add "install {MODULE_NAME} /bin/false" to a file in
"/etc/modprobe.d"
 l_loadable="$(modprobe -n -v "$l_mname")"
 [ "$(wc -l <<< "$l_loadable")" -gt "1" ] && l_loadable="$(grep -P --
"(^\h*install|\b$l_mname)\b" <<< "$l_loadable")"
 if ! grep -Pq -- '^\h*install \/bin\/(true|false)' <<< "$l_loadable"; then
 echo -e "\n - setting module: \"$l_mname\" to be not loadable"
 echo -e "install $l_mname /bin/false" >> /etc/modprobe.d/"$l_mpname".conf
 fi
 }
 module_loaded_fix()
 {
 # If the module is currently loaded, unload the module
 if lsmod | grep "$l_mname" > /dev/null 2>&1; then
 echo -e "\n - unloading module \"$l_mname\""
 modprobe -r "$l_mname"
 fi
 }
 module_deny_fix()
 {
 # If the module isn't deny listed, denylist the module
 if ! modprobe --showconfig | grep -Pq -- "^\h*blacklist\h+$l_mpname\b"; then
 echo -e "\n - deny listing \"$l_mname\""
 echo -e "blacklist $l_mname" >> /etc/modprobe.d/"$l_mpname".conf
 fi
 }
 # Check if the module exists on the system
 for l_mdir in $l_mpath; do
 if [ -d "$l_mdir/$l_mndir" ] && [ -n "$(ls -A $l_mdir/$l_mndir)" ]; then
 echo -e "\n - module: \"$l_mname\" exists in \"$l_mdir\"\n - checking if disabled..."
 module_deny_fix
 if [ "$l_mdir" = "/lib/modules/$(uname -r)/kernel/$l_mtype" ]; then
 module_loadable_fix
 module_loaded_fix
 fi
 else
 echo -e "\n - module: \"$l_mname\" doesn't exist in \"$l_mdir\"\n"
 fi
 done
 echo -e "\n - remediation of module: \"$l_mname\" complete\n"
}
{
 l_mname="squashfs" # set module name
 l_mtype="fs" # set module type
 l_mpath="/lib/modules/**/kernel/$l_mtype"
 l_mpname="$(tr '-' '_' <<< "$l_mname")"
 l_mndir="$(tr '-' '/' <<< "$l_mname")"
 module_loadable_fix()
 {
 # If the module is currently loadable, add "install {MODULE_NAME} /bin/false" to a file in
"/etc/modprobe.d"
 l_loadable="$(modprobe -n -v "$l_mname")"
 [ "$(wc -l <<< "$l_loadable")" -gt "1" ] && l_loadable="$(grep -P --
"(^\h*install|\b$l_mname)\b" <<< "$l_loadable")"
 if ! grep -Pq -- '^\h*install \/bin\/(true|false)' <<< "$l_loadable"; then
 echo -e "\n - setting module: \"$l_mname\" to be not loadable"
 echo -e "install $l_mname /bin/false" >> /etc/modprobe.d/"$l_mpname".conf
 fi
 }
 module_loaded_fix()
 {
 # If the module is currently loaded, unload the module
 if lsmod | grep "$l_mname" > /dev/null 2>&1; then
 echo -e "\n - unloading module \"$l_mname\""
 modprobe -r "$l_mname"
 fi
 }
 module_deny_fix()
 {
 # If the module isn't deny listed, denylist the module
 if ! modprobe --showconfig | grep -Pq -- "^\h*blacklist\h+$l_mpname\b"; then
 echo -e "\n - deny listing \"$l_mname\""
 echo -e "blacklist $l_mname" >> /etc/modprobe.d/"$l_mpname".conf
 fi
 }
 # Check if the module exists on the system
 for l_mdir in $l_mpath; do
 if [ -d "$l_mdir/$l_mndir" ] && [ -n "$(ls -A $l_mdir/$l_mndir)" ]; then
 echo -e "\n - module: \"$l_mname\" exists in \"$l_mdir\"\n - checking if disabled..."
 module_deny_fix
 if [ "$l_mdir" = "/lib/modules/$(uname -r)/kernel/$l_mtype" ]; then
 module_loadable_fix
 module_loaded_fix
 fi
 else
 echo -e "\n - module: \"$l_mname\" doesn't exist in \"$l_mdir\"\n"
 fi
 done
 echo -e "\n - remediation of module: \"$l_mname\" complete\n"
}
{
 l_mname="udf" # set module name
 l_mtype="fs" # set module type
 l_mpath="/lib/modules/**/kernel/$l_mtype"
 l_mpname="$(tr '-' '_' <<< "$l_mname")"
 l_mndir="$(tr '-' '/' <<< "$l_mname")"
 module_loadable_fix()
 {
 # If the module is currently loadable, add "install {MODULE_NAME} /bin/false" to a file in
"/etc/modprobe.d"
 l_loadable="$(modprobe -n -v "$l_mname")"
 [ "$(wc -l <<< "$l_loadable")" -gt "1" ] && l_loadable="$(grep -P --
"(^\h*install|\b$l_mname)\b" <<< "$l_loadable")"
 if ! grep -Pq -- '^\h*install \/bin\/(true|false)' <<< "$l_loadable"; then
 echo -e "\n - setting module: \"$l_mname\" to be not loadable"
 echo -e "install $l_mname /bin/false" >> /etc/modprobe.d/"$l_mpname".conf
 fi
 }
 module_loaded_fix()
 {
 # If the module is currently loaded, unload the module
 if lsmod | grep "$l_mname" > /dev/null 2>&1; then
 echo -e "\n - unloading module \"$l_mname\""
 modprobe -r "$l_mname"
 fi
 }
 module_deny_fix()
 {
 # If the module isn't deny listed, denylist the module
 if ! modprobe --showconfig | grep -Pq -- "^\h*blacklist\h+$l_mpname\b"; then
 echo -e "\n - deny listing \"$l_mname\""
 echo -e "blacklist $l_mname" >> /etc/modprobe.d/"$l_mpname".conf
 fi
 }
 # Check if the module exists on the system
 for l_mdir in $l_mpath; do
 if [ -d "$l_mdir/$l_mndir" ] && [ -n "$(ls -A $l_mdir/$l_mndir)" ]; then
 echo -e "\n - module: \"$l_mname\" exists in \"$l_mdir\"\n - checking if disabled..."
 module_deny_fix
 if [ "$l_mdir" = "/lib/modules/$(uname -r)/kernel/$l_mtype" ]; then
 module_loadable_fix
 module_loaded_fix
 fi
 else
 echo -e "\n - module: \"$l_mname\" doesn't exist in \"$l_mdir\"\n"
 fi
 done
 echo -e "\n - remediation of module: \"$l_mname\" complete\n"
}
{
 l_mname="usb-storage" # set module name
 l_mtype="drivers" # set module type
 l_mpath="/lib/modules/**/kernel/$l_mtype"
 l_mpname="$(tr '-' '_' <<< "$l_mname")"
 l_mndir="$(tr '-' '/' <<< "$l_mname")"
 module_loadable_fix()
 {
 # If the module is currently loadable, add "install {MODULE_NAME} /bin/false" to a file in
"/etc/modprobe.d"
 l_loadable="$(modprobe -n -v "$l_mname")"
 [ "$(wc -l <<< "$l_loadable")" -gt "1" ] && l_loadable="$(grep -P --
"(^\h*install|\b$l_mname)\b" <<< "$l_loadable")"
 if ! grep -Pq -- '^\h*install \/bin\/(true|false)' <<< "$l_loadable"; then
 echo -e "\n - setting module: \"$l_mname\" to be not loadable"
 echo -e "install $l_mname /bin/false" >> /etc/modprobe.d/"$l_mpname".conf
 fi
 }
 module_loaded_fix()
 {
 # If the module is currently loaded, unload the module
 if lsmod | grep "$l_mname" > /dev/null 2>&1; then
 echo -e "\n - unloading module \"$l_mname\""
 modprobe -r "$l_mname"
 fi
 }
 module_deny_fix()
 {
 # If the module isn't deny listed, denylist the module
 if ! modprobe --showconfig | grep -Pq -- "^\h*blacklist\h+$l_mpname\b"; then
 echo -e "\n - deny listing \"$l_mname\""
 echo -e "blacklist $l_mname" >> /etc/modprobe.d/"$l_mpname".conf
 fi
 }
 # Check if the module exists on the system
 for l_mdir in $l_mpath; do
 if [ -d "$l_mdir/$l_mndir" ] && [ -n "$(ls -A $l_mdir/$l_mndir)" ]; then
 echo -e "\n - module: \"$l_mname\" exists in \"$l_mdir\"\n - checking if disabled..."
 module_deny_fix
 if [ "$l_mdir" = "/lib/modules/$(uname -r)/kernel/$l_mtype" ]; then
 module_loadable_fix
 module_loaded_fix
 fi
 else
 echo -e "\n - module: \"$l_mname\" doesn't exist in \"$l_mdir\"\n"
 fi
 done
 echo -e "\n - remediation of module: \"$l_mname\" complete\n"
}
audit_tmp_mount() {
    echo "Auditing /tmp mount..."
    findmnt -kn /tmp
}

# Function to check if systemd is correctly configured
audit_systemd_tmp_mount() {
    echo "Checking systemd tmp.mount status..."
    systemctl is-enabled tmp.mount
}

# Function to unmask and enable tmp.mount if needed
remediate_systemd_tmp_mount() {
    echo "Ensuring systemd is configured to mount /tmp at boot time..."
    
    # Unmask tmp.mount if it's masked
    if systemctl is-enabled tmp.mount | grep -q "masked"; then
        echo "tmp.mount is masked, unmasking..."
        sudo systemctl unmask tmp.mount
    fi
    
    # Enable tmp.mount
    echo "Enabling tmp.mount..."
    sudo systemctl enable tmp.mount
}


# Main function to perform the audit and remediation
audit_noexec_option

echo "Audit and remediation complete."
#!/bin/bash

# Function to check if AppArmor is installed
check_apparmor_installed() {
    echo "Checking if AppArmor is installed..."

    # Check if AppArmor package is installed
    if dpkg-query -s apparmor &>/dev/null; then
        echo "AppArmor is already installed."
    else
        echo "AppArmor is not installed."
        install_apparmor
    fi

    # Check if apparmor-utils package is installed
    if dpkg-query -s apparmor-utils &>/dev/null; then
        echo "AppArmor-utils is already installed."
    else
        echo "AppArmor-utils is not installed."
        install_apparmor_utils
    fi
}

# Function to install AppArmor
install_apparmor() {
    echo "Installing AppArmor..."
    sudo apt-get update
    sudo apt-get install -y apparmor
}

# Function to install apparmor-utils
install_apparmor_utils() {
    echo "Installing apparmor-utils..."
    sudo apt-get install -y apparmor-utils
}

# Main function to perform the audit and remediation
check_apparmor_installed

echo "Audit and remediation complete."
#!/bin/bash

# Function to check if AppArmor boot parameters are set in grub.cfg
check_apparmor_enabled_in_bootloader() {
    echo "Checking if AppArmor is enabled in bootloader configuration..."

    # Check if apparmor=1 is present in the bootloader configuration
    if grep -q "^\s*linux" /boot/grub/grub.cfg | grep -v "apparmor=1"; then
        echo "AppArmor boot parameter 'apparmor=1' is missing."
        enable_apparmor_in_bootloader
    else
        echo "AppArmor boot parameter 'apparmor=1' is correctly set."
    fi

    # Check if security=apparmor is present in the bootloader configuration
    if grep -q "^\s*linux" /boot/grub/grub.cfg | grep -v "security=apparmor"; then
        echo "AppArmor boot parameter 'security=apparmor' is missing."
        enable_apparmor_in_bootloader
    else
        echo "AppArmor boot parameter 'security=apparmor' is correctly set."
    fi
}

# Function to enable AppArmor in the bootloader configuration
enable_apparmor_in_bootloader() {
    echo "Enabling AppArmor in the bootloader configuration..."

    # Edit the GRUB_CMDLINE_LINUX line in /etc/default/grub to include apparmor=1 and security=apparmor
    sudo sed -i 's/GRUB_CMDLINE_LINUX="\(.*\)"/GRUB_CMDLINE_LINUX="\1 apparmor=1 security=apparmor"/' /etc/default/grub

    # Update GRUB configuration
    sudo update-grub

    echo "AppArmor parameters have been added to the bootloader configuration and GRUB has been updated."
}

# Main function to check and ensure AppArmor is enabled at boot time
check_apparmor_enabled_in_bootloader

echo "Audit and remediation complete."
#!/bin/bash

# Function to audit AppArmor profiles status
audit_apparmor_profiles() {
    echo "Auditing AppArmor profiles..."

    # Check if AppArmor profiles are loaded and in enforce or complain mode
    profiles_status=$(apparmor_status | grep -i 'profiles')

    # Ensure profiles are in either enforce or complain mode
    enforce_count=$(echo "$profiles_status" | grep -o "enforce" | wc -l)
    complain_count=$(echo "$profiles_status" | grep -o "complain" | wc -l)

    # Check for unconfined processes
    unconfined_processes=$(apparmor_status | grep "unconfined" | wc -l)

    # Output profile status for auditing
    echo "Profiles in enforce mode: $enforce_count"
    echo "Profiles in complain mode: $complain_count"
    echo "Unconfined processes: $unconfined_processes"

    # If there are unconfined processes, print a message to take action
    if [ "$unconfined_processes" -gt 0 ]; then
        echo "Warning: There are unconfined processes that need attention."
    fi

    # Ensure there are no unconfined profiles (if any, need to create or activate)
    if [ "$unconfined_processes" -gt 0 ]; then
        echo "Please ensure that any unconfined processes have an AppArmor profile activated and restart them."
    fi

    # If all profiles are in enforce or complain mode and no unconfined processes, proceed with remediation
    if [ "$unconfined_processes" -eq 0 ]; then
        echo "All profiles are loaded and in enforce or complain mode."
    else
        echo "There are unconfined processes that require remediation."
    fi
}

# Function to remediate by setting all profiles to enforce mode
remediate_apparmor_profiles() {
    echo "Remediating AppArmor profiles..."

    # Set all AppArmor profiles to enforce mode
    echo "Setting all AppArmor profiles to enforce mode..."
    sudo aa-enforce /etc/apparmor.d/*

    # Verify after remediation
    echo "Verifying AppArmor profiles status..."
    apparmor_status | grep -i 'profiles'
}

# Function to remediate by setting all profiles to complain mode
set_profiles_to_complain() {
    echo "Setting all AppArmor profiles to complain mode..."

    # Set all AppArmor profiles to complain mode
    sudo aa-complain /etc/apparmor.d/*

    # Verify after remediation
    echo "Verifying AppArmor profiles status..."
    apparmor_status | grep -i 'profiles'
}

# Main function to perform audit and remediation
audit_apparmor_profiles

# Optionally remediate by setting profiles to enforce mode
remediate_apparmor_profiles

# Or set all profiles to complain mode instead (comment the above line to use this)
# set_profiles_to_complain

echo "Audit and remediation complete."
#!/bin/bash

# Function to audit AppArmor profiles status
audit_apparmor_profiles() {
    echo "Auditing AppArmor profiles..."

    # Check if AppArmor profiles are loaded and verify they are in enforce mode
    profiles_status=$(apparmor_status | grep -i 'profiles')

    # Count profiles in enforce mode and complain mode
    enforce_count=$(echo "$profiles_status" | grep -o "enforce" | wc -l)
    complain_count=$(echo "$profiles_status" | grep -o "complain" | wc -l)

    # Check for unconfined processes
    unconfined_processes=$(apparmor_status | grep "unconfined" | wc -l)

    # Output profile status for auditing
    echo "Profiles in enforce mode: $enforce_count"
    echo "Profiles in complain mode: $complain_count"
    echo "Unconfined processes: $unconfined_processes"

    # If there are unconfined processes, print a message to take action
    if [ "$unconfined_processes" -gt 0 ]; then
        echo "Warning: There are unconfined processes that need attention."
    fi

    # Ensure there are no unconfined processes (if any, need to create or activate profiles)
    if [ "$unconfined_processes" -gt 0 ]; then
        echo "Please ensure that any unconfined processes have an AppArmor profile activated and restart them."
    fi

    # Check if all profiles are in enforce mode
    if [ "$complain_count" -gt 0 ]; then
        echo "Warning: There are profiles in complain mode. These should be set to enforce mode."
    else
        echo "All profiles are in enforce mode."
    fi
}

# Function to remediate by setting all profiles to enforce mode
remediate_apparmor_profiles() {
    echo "Remediating AppArmor profiles..."

    # Set all AppArmor profiles to enforce mode
    echo "Setting all AppArmor profiles to enforce mode..."
    sudo aa-enforce /etc/apparmor.d/*

    # Verify after remediation
    echo "Verifying AppArmor profiles status..."
    apparmor_status | grep -i 'profiles'
}

# Function to verify no unconfined processes are running
verify_no_unconfined_processes() {
    echo "Verifying there are no unconfined processes..."
    
    unconfined_processes=$(apparmor_status | grep "unconfined" | wc -l)

    if [ "$unconfined_processes" -gt 0 ]; then
        echo "There are unconfined processes that need to be addressed."
    else
        echo "No unconfined processes found."
    fi
}

# Main function to perform audit and remediation
audit_apparmor_profiles

# Remediate by setting all profiles to enforce mode if needed
remediate_apparmor_profiles

# Verify there are no unconfined processes
verify_no_unconfined_processes

echo "Audit and remediation complete."
#!/bin/bash

#!/bin/bash

# Define the GRUB configuration file path
GRUB_CFG="/boot/grub/grub.cfg"

# Check if the GRUB configuration file exists
if [ ! -f "$GRUB_CFG" ]; then
  echo "ERROR: GRUB configuration file '$GRUB_CFG' not found!"
 
 
fi

# Audit the current ownership and permissions of the GRUB configuration file
current_permissions=$(stat -c "%a" "$GRUB_CFG")
current_owner=$(stat -c "%U" "$GRUB_CFG")
current_group=$(stat -c "%G" "$GRUB_CFG")

echo "Current permissions of '$GRUB_CFG': $current_permissions"
echo "Current owner: $current_owner"
echo "Current group: $current_group"

# Check if the ownership is correct (root:root)
if [ "$current_owner" != "root" ] || [ "$current_group" != "root" ]; then
  echo "Setting ownership to root:root for '$GRUB_CFG'..."
  sudo chown root:root "$GRUB_CFG"
else
  echo "Ownership is already correct."
fi

# Check if the permissions are correct (0600)
if [ "$current_permissions" != "600" ]; then
  echo "Setting permissions to 0600 for '$GRUB_CFG'..."
  sudo chmod 600 "$GRUB_CFG"
else
  echo "Permissions are already set to 0600."
fi

# Verify the changes
echo "Updated permissions and ownership of '$GRUB_CFG':"
stat -c "Access: (%a) Uid: (%u/%U) Gid: (%g/%G)" "$GRUB_CFG"
#!/bin/bash

# Define the sysctl configuration file
SYSCTL_FILE="/etc/sysctl.d/60-kernel_sysctl.conf"

# Check if the configuration already exists
if ! grep -q "kernel.randomize_va_space = 2" "$SYSCTL_FILE"; then
  echo "Setting kernel.randomize_va_space = 2 in $SYSCTL_FILE"
  printf "%s\n" "kernel.randomize_va_space = 2" | sudo tee -a "$SYSCTL_FILE"
else
  echo "kernel.randomize_va_space = 2 is already set in $SYSCTL_FILE"
fi

# Apply the setting immediately
echo "Applying kernel.randomize_va_space = 2"
sudo sysctl -w kernel.randomize_va_space=2

# Verify the setting
echo "Verifying kernel.randomize_va_space"
sysctl kernel.randomize_va_space
#!/bin/bash

# Define the sysctl configuration file
SYSCTL_FILE="/etc/sysctl.d/60-kernel_sysctl.conf"

# Check if the configuration already exists
if ! grep -q "kernel.yama.ptrace_scope = 1" "$SYSCTL_FILE"; then
  echo "Setting kernel.yama.ptrace_scope = 1 in $SYSCTL_FILE"
  printf "%s\n" "kernel.yama.ptrace_scope = 1" | sudo tee -a "$SYSCTL_FILE"
else
  echo "kernel.yama.ptrace_scope = 1 is already set in $SYSCTL_FILE"
fi

# Apply the setting immediately
echo "Applying kernel.yama.ptrace_scope = 1"
sudo sysctl -w kernel.yama.ptrace_scope=1

# Verify the setting
echo "Verifying kernel.yama.ptrace_scope"
sysctl kernel.yama.ptrace_scope
#!/bin/bash

# Step 1: Set hard limit for core dumps
echo "Setting hard limit for core dumps..."
echo "* hard core 0" | sudo tee -a /etc/security/limits.d/60-security.conf

# Step 2: Set fs.suid_dumpable to 0
echo "Setting fs.suid_dumpable to 0..."
echo "fs.suid_dumpable = 0" | sudo tee -a /etc/sysctl.d/60-fs_sysctl.conf
sudo sysctl -w fs.suid_dumpable=0

# Step 3: Verify the system limits
echo "Verifying core dump limits..."
grep -Ps -- '^\h*\*\h+hard\h+core\h+0\b' /etc/security/limits.conf /etc/security/limits.d/*

# Step 4: Check if systemd-coredump is installed and disable if necessary
echo "Checking if systemd-coredump is installed..."
if systemctl list-unit-files | grep -q coredump; then
    echo "Disabling systemd-coredump..."
    echo -e "[Coredump]\nStorage=none\nProcessSizeMax=0" | sudo tee -a /etc/systemd/coredump.conf
    sudo systemctl daemon-reload
else
    echo "systemd-coredump is not installed or not enabled."
fi

# Final verification
echo "Final verification of kernel parameter fs.suid_dumpable..."
sysctl fs.suid_dumpable
#!/bin/bash

# Check if prelink is installed
if dpkg-query -s prelink &>/dev/null; then
    echo "Prelink is installed, proceeding with remediation..."

    # Restore binaries to their normal state
    echo "Restoring binaries to normal state..."
    sudo prelink -ua

    # Uninstall prelink
    echo "Uninstalling prelink..."
    sudo apt purge -y prelink

    # Verify prelink is no longer installed
    if ! dpkg-query -s prelink &>/dev/null; then
        echo "Prelink has been successfully removed from the system."
    else
        echo "Failed to remove prelink."
    fi
else
    echo "Prelink is not installed on this system."
fi
#!/bin/bash

# Check if Apport is installed and enabled
if dpkg-query -s apport &>/dev/null; then
    echo "Apport is installed, checking if it is enabled..."

    # Check if Apport is enabled
    if grep -Pqi '^\h*enabled\h*=\h*[^0]\b' /etc/default/apport; then
        echo "Apport is enabled, proceeding to disable it..."

        # Disable Apport by modifying the /etc/default/apport file
        sudo sed -i 's/^enabled=.*$/enabled=0/' /etc/default/apport
        echo "Set 'enabled=0' in /etc/default/apport"

        # Stop the Apport service
        sudo systemctl stop apport.service
        echo "Stopped Apport service"

        # Mask the Apport service to prevent it from starting on boot
        sudo systemctl mask apport.service
        echo "Masked Apport service"

        # Verify that Apport is now disabled
        if ! systemctl is-active --quiet apport.service; then
            echo "Apport service is successfully disabled."
        else
            echo "Failed to disable Apport service."
        fi
    else
        echo "Apport is already disabled in /etc/default/apport."
    fi

    # Optionally, remove the Apport package (uncomment to use)
    # sudo apt purge -y apport
    # echo "Removed Apport package from the system."
else
    echo "Apport is not installed on this system."
fi
#!/bin/bash

# Check if gdm3 is installed
if dpkg-query -s gdm3 &>/dev/null; then
    echo "Removing gdm3..."

    # Uninstall gdm3
    sudo apt purge -y gdm3

    # Remove unused dependencies
    sudo apt autoremove -y

    echo "gdm3 and unused dependencies have been removed."
else
    echo "gdm3 is not installed, nothing to remove."
fi

# Optionally, prevent future installation of gdm3
# sudo apt-mark hold gdm3
#!/usr/bin/env bash
{
    l_pkgoutput=""
    if command -v dpkg-query &> /dev/null; then
        l_pq="dpkg-query -s"
    elif command -v rpm &> /dev/null; then
        l_pq="rpm -q"
    fi

    l_pcl="gdm gdm3"  # Space-separated list of packages to check
    for l_pn in $l_pcl; do
        $l_pq "$l_pn" &> /dev/null && l_pkgoutput="$l_pkgoutput\n - Package: \"$l_pn\" exists on the system\n - checking configuration"
    done

    if [ -n "$l_pkgoutput" ]; then
        l_gdmprofile="gdm"  # Set this to desired profile name
        l_bmessage="'Authorized uses only. All activity may be monitored and reported.'"  # Set desired banner message

        # Create profile if it doesn't exist
        if [ ! -f "/etc/dconf/profile/$l_gdmprofile" ]; then
            echo "Creating profile \"$l_gdmprofile\""
            echo -e "user-db:user\nsystem-db:$l_gdmprofile\nfiledb:/usr/share/$l_gdmprofile/greeter-dconf-defaults" > /etc/dconf/profile/$l_gdmprofile
        fi
        
        # Create dconf database directory if it doesn't exist
        if [ ! -d "/etc/dconf/db/$l_gdmprofile.d/" ]; then
            echo "Creating dconf database directory \"/etc/dconf/db/$l_gdmprofile.d/\""
            mkdir /etc/dconf/db/$l_gdmprofile.d/
        fi
        
        # Enable the banner message
        if ! grep -Piq '^\h*banner-message-enable\h*=\h*true\b' /etc/dconf/db/$l_gdmprofile.d/*; then
            echo "Creating gdm keyfile for machine-wide settings"
            l_kfile="/etc/dconf/db/$l_gdmprofile.d/01-banner-message"
            echo -e "\n[org/gnome/login-screen]\nbanner-message-enable=true" >> "$l_kfile"
        fi
        
        # Set the banner message text
        if ! grep -Piq "^\h*banner-message-text=[\'\"]+\S+" "$l_kfile"; then
            sed -ri "/^\s*banner-message-enable/ a\banner-message-text=$l_bmessage" "$l_kfile"
        fi

        # Update the dconf database
        dconf update
    else
        echo -e "\n\n - GNOME Desktop Manager isn't installed\n - Recommendation is Not Applicable\n - No remediation required\n"
    fi
}
#!/usr/bin/env bash
{
    l_gdmprofile="gdm"  # Change this profile name if desired (according to local policy)
    
    # Create the profile if it doesn't exist
    if [ ! -f "/etc/dconf/profile/$l_gdmprofile" ]; then
        echo "Creating profile \"$l_gdmprofile\""
        echo -e "user-db:user\nsystem-db:$l_gdmprofile\nfiledb:/usr/share/$l_gdmprofile/greeter-dconf-defaults" > /etc/dconf/profile/$l_gdmprofile
    fi

    # Create the dconf database directory if it doesn't exist
    if [ ! -d "/etc/dconf/db/$l_gdmprofile.d/" ]; then
        echo "Creating dconf database directory \"/etc/dconf/db/$l_gdmprofile.d/\""
        mkdir /etc/dconf/db/$l_gdmprofile.d/
    fi

    # Check if the 'disable-user-list' setting is already in place, otherwise add it
    if ! grep -Piq '^\h*disable-user-list\h*=\h*true\b' /etc/dconf/db/$l_gdmprofile.d/*; then
        echo "Creating gdm keyfile for machine-wide settings"
        
        if ! grep -Piq -- '^\h*\[org/gnome/login-screen\]' /etc/dconf/db/$l_gdmprofile.d/*; then
            echo -e "\n[org/gnome/login-screen]\n# Do not show the user list\ndisable-user-list=true" >> /etc/dconf/db/$l_gdmprofile.d/00-loginscreen
        else
            # Append the setting if the section exists
            sed -ri '/^\s*\[org/gnome/login-screen\]/ a\# Do not show the user list\ndisable-user-list=true' $(grep -Pil -- '^\h*\[org/gnome/login-screen\]' /etc/dconf/db/$l_gdmprofile.d/*)
        fi
    fi
    
    # Update the dconf database to apply changes
    dconf update
}
#!/usr/bin/env bash
{
    # Set lock-delay to 5 seconds and idle-delay to 900 seconds
    gsettings set org.gnome.desktop.screensaver lock-delay 5
    gsettings set org.gnome.desktop.session idle-delay 900

    # Create or edit the user profile in /etc/dconf/profile/
    l_dconf_profile="local"  # Replace with appropriate profile name if different
    if [ ! -f "/etc/dconf/profile/$l_dconf_profile" ]; then
        echo "Creating profile \"$l_dconf_profile\""
        echo -e "user-db:user\nsystem-db:$l_dconf_profile" > /etc/dconf/profile/$l_dconf_profile
    fi

    # Create the dconf database directory if it doesn't exist
    if [ ! -d "/etc/dconf/db/$l_dconf_profile.d/" ]; then
        echo "Creating dconf database directory \"/etc/dconf/db/$l_dconf_profile.d/\""
        mkdir -p /etc/dconf/db/$l_dconf_profile.d/
    fi

    # Create the key file /etc/dconf/db/local.d/00-screensaver
    if [ ! -f "/etc/dconf/db/$l_dconf_profile.d/00-screensaver" ]; then
        echo "Creating screensaver key file"
        echo -e "[org/gnome/desktop/session]\n# Number of seconds of inactivity before the screen goes blank\nidle-delay=uint32 180" > /etc/dconf/db/$l_dconf_profile.d/00-screensaver
        echo -e "[org/gnome/desktop/screensaver]\n# Number of seconds after the screen is blank before locking the screen\nlock-delay=uint32 5" >> /etc/dconf/db/$l_dconf_profile.d/00-screensaver
    fi

    # Update dconf settings
    dconf update
}
#!/usr/bin/env bash
{
    # Create the locks directory if it doesn't exist
    if [ ! -d "/etc/dconf/db/local.d/locks" ]; then
        mkdir -p /etc/dconf/db/local.d/locks
    fi

    # Create the screensaver lockdown file
    echo -e "# Lock desktop screensaver settings\n/org/gnome/desktop/session/idle-delay\n/org/gnome/desktop/screensaver/lock-delay" > /etc/dconf/db/local.d/locks/screensaver

    # Update the system databases
    dconf update
}
#!/usr/bin/env bash
{
    l_pkgoutput=""
    l_gpname="local" # Set to desired dconf profile name (default is local)

    # Check if GNOME Desktop Manager is installed. If package isn't installed, recommendation is Not Applicable
    if command -v dpkg-query > /dev/null 2>&1; then
        l_pq="dpkg-query -s"
    elif command -v rpm > /dev/null 2>&1; then
        l_pq="rpm -q"
    fi

    # Check if GDM is installed
    l_pcl="gdm gdm3" # Space-separated list of packages to check
    for l_pn in $l_pcl; do
        $l_pq "$l_pn" > /dev/null 2>&1 && l_pkgoutput="$l_pkgoutput\n - Package: \"$l_pn\" exists on the system\n - checking configuration"
    done

    # Check configuration (If applicable)
    if [ -n "$l_pkgoutput" ]; then
        echo -e "$l_pkgoutput"
        
        # Look for existing settings and set variables if they exist
        l_kfile="$(grep -Prils -- '^\h*automount\b' /etc/dconf/db/*.d)"
        l_kfile2="$(grep -Prils -- '^\h*automount-open\b' /etc/dconf/db/*.d)"

        # Set profile name based on dconf db directory ({PROFILE_NAME}.d)
        if [ -f "$l_kfile" ]; then
            l_gpname="$(awk -F\/ '{split($(NF-1),a,".");print a[1]}' <<< "$l_kfile")"
            echo " - updating dconf profile name to \"$l_gpname\""
        elif [ -f "$l_kfile2" ]; then
            l_gpname="$(awk -F\/ '{split($(NF-1),a,".");print a[1]}' <<< "$l_kfile2")"
            echo " - updating dconf profile name to \"$l_gpname\""
        fi

        # check for consistency (Clean up configuration if needed)
        if [ -f "$l_kfile" ] && [ "$(awk -F\/ '{split($(NF-1),a,".");print a[1]}' <<< "$l_kfile")" != "$l_gpname" ]; then
            sed -ri "/^\s*automount\s*=/s/^/# /" "$l_kfile"
            l_kfile="/etc/dconf/db/$l_gpname.d/00-media-automount"
        fi
        if [ -f "$l_kfile2" ] && [ "$(awk -F\/ '{split($(NF-1),a,".");print a[1]}' <<< "$l_kfile2")" != "$l_gpname" ]; then
            sed -ri "/^\s*automount-open\s*=/s/^/# /" "$l_kfile2"
        fi

        [ -z "$l_kfile" ] && l_kfile="/etc/dconf/db/$l_gpname.d/00-media-automount"

        # Check if profile file exists
        if grep -Pq -- "^\h*system-db:$l_gpname\b" /etc/dconf/profile/*; then
            echo -e "\n - dconf database profile exists in: \"$(grep -Pl -- "^\h*system-db:$l_gpname\b" /etc/dconf/profile/*)\""
        else
            if [ ! -f "/etc/dconf/profile/user" ]; then
                l_gpfile="/etc/dconf/profile/user"
            else
                l_gpfile="/etc/dconf/profile/user2"
            fi
            echo -e " - creating dconf database profile"
            {
                echo -e "\nuser-db:user"
                echo "system-db:$l_gpname"
            } >> "$l_gpfile"
        fi

        # create dconf directory if it doesn't exist
        l_gpdir="/etc/dconf/db/$l_gpname.d"
        if [ -d "$l_gpdir" ]; then
            echo " - The dconf database directory \"$l_gpdir\" exists"
        else
            echo " - creating dconf database directory \"$l_gpdir\""
            mkdir "$l_gpdir"
        fi

        # check automount-open setting
        if grep -Pqs -- '^\h*automount-open\h*=\h*false\b' "$l_kfile"; then
            echo " - \"automount-open\" is set to false in: \"$l_kfile\""
        else
            echo " - creating \"automount-open\" entry in \"$l_kfile\""
            ! grep -Psq -- '\^\h*\[org\/gnome\/desktop\/media-handling\]\b' "$l_kfile" && echo '[org/gnome/desktop/media-handling]' >> "$l_kfile"
            sed -ri '/^\s*\[org\/gnome\/desktop\/media-handling\]/a \\nautomount-open=false' "$l_kfile"
        fi

        # check automount setting
        if grep -Pqs -- '^\h*automount\h*=\h*false\b' "$l_kfile"; then
            echo " - \"automount\" is set to false in: \"$l_kfile\""
        else
            echo " - creating \"automount\" entry in \"$l_kfile\""
            ! grep -Psq -- '\^\h*\[org\/gnome\/desktop\/media-handling\]\b' "$l_kfile" && echo '[org/gnome/desktop/media-handling]' >> "$l_kfile"
            sed -ri '/^\s*\[org\/gnome\/desktop\/media-handling\]/a \\nautomount=false' "$l_kfile"
        fi

        # update dconf database
        dconf update
    else
        echo -e "\n - GNOME Desktop Manager package is not installed on the system\n - Recommendation is not applicable"
    fi
}
#!/usr/bin/env bash
{
    l_pkgoutput=""
    l_gpname="local" # Set to desired dconf profile name (default is local)

    # Check if GNOME Desktop Manager is installed.
    if command -v dpkg-query &> /dev/null; then
        l_pq="dpkg-query -s"
    elif command -v rpm &> /dev/null; then
        l_pq="rpm -q"
    fi
    l_pcl="gdm gdm3"  # Space-separated list of packages to check
    for l_pn in $l_pcl; do
        $l_pq "$l_pn" &> /dev/null && l_pkgoutput="$l_pkgoutput\n - Package: \"$l_pn\" exists on the system\n - Checking configuration"
    done

    # Check configuration (If applicable)
    if [ -n "$l_pkgoutput" ]; then
        echo -e "$l_pkgoutput"
        
        # Look for existing settings and set variables if they exist
        l_kfile="$(grep -Prils -- '^\h*automount\b' /etc/dconf/db/*.d)"
        l_kfile2="$(grep -Prils -- '^\h*automount-open\b' /etc/dconf/db/*.d)"

        # Set profile name based on dconf db directory ({PROFILE_NAME}.d)
        if [ -f "$l_kfile" ]; then
            l_gpname="$(awk -F\/ '{split($(NF-1),a,".");print a[1]}' <<< "$l_kfile")"
            echo " - updating dconf profile name to \"$l_gpname\""
        elif [ -f "$l_kfile2" ]; then
            l_gpname="$(awk -F\/ '{split($(NF-1),a,".");print a[1]}' <<< "$l_kfile2")"
            echo " - updating dconf profile name to \"$l_gpname\""
        fi

        # Check for consistency (Clean up configuration if needed)
        if [ -f "$l_kfile" ] && [ "$(awk -F\/ '{split($(NF-1),a,".");print a[1]}' <<< "$l_kfile")" != "$l_gpname" ]; then
            sed -ri "/^\s*automount\s*=/s/^/# /" "$l_kfile"
            l_kfile="/etc/dconf/db/$l_gpname.d/00-media-automount"
        fi
        if [ -f "$l_kfile2" ] && [ "$(awk -F\/ '{split($(NF-1),a,".");print a[1]}' <<< "$l_kfile2")" != "$l_gpname" ]; then
            sed -ri "/^\s*automount-open\s*=/s/^/# /" "$l_kfile2"
        fi

        [ -z "$l_kfile" ] && l_kfile="/etc/dconf/db/$l_gpname.d/00-media-automount"

        # Create dconf directory if it doesn't exist
        l_gpdir="/etc/dconf/db/$l_gpname.d"
        if [ -d "$l_gpdir" ]; then
            echo " - The dconf database directory \"$l_gpdir\" exists"
        else
            echo " - creating dconf database directory \"$l_gpdir\""
            mkdir "$l_gpdir"
        fi

        # Check automount-open setting
        if grep -Pqs -- '^\h*automount-open\h*=\h*false\b' "$l_kfile"; then
            echo " - \"automount-open\" is set to false in: \"$l_kfile\""
        else
            echo " - creating \"automount-open\" entry in \"$l_kfile\""
            ! grep -Psq -- '^\h*\[org\/gnome\/desktop\/media-handling\]\b' "$l_kfile" && echo '[org/gnome/desktop/media-handling]' >> "$l_kfile"
            sed -ri '/^\s*\[org\/gnome\/desktop\/media-handling\]/a \nautomount-open=false' "$l_kfile"
        fi

        # Check automount setting
        if grep -Pqs -- '^\h*automount\h*=\h*false\b' "$l_kfile"; then
            echo " - \"automount\" is set to false in: \"$l_kfile\""
        else
            echo " - creating \"automount\" entry in \"$l_kfile\""
            ! grep -Psq -- '^\h*\[org\/gnome\/desktop\/media-handling\]\b' "$l_kfile" && echo '[org/gnome/desktop/media-handling]' >> "$l_kfile"
            sed -ri '/^\s*\[org\/gnome\/desktop\/media-handling\]/a \nautomount=false' "$l_kfile"
        fi

        # Update dconf database
        dconf update
    else
        echo -e "\n - GNOME Desktop Manager package is not installed on the system\n - Recommendation is not applicable"
    fi
}
#!/usr/bin/env bash
{
 l_pkgoutput="" l_output="" l_output2=""
 # Check if GNOME Desktop Manager is installed. If package isn't
installed, recommendation is Not Applicable\n
 # determine system's package manager
 if command -v dpkg-query &> /dev/null; then
 l_pq="dpkg-query -s"
 elif command -v rpm &> /dev/null; then
 l_pq="rpm -q"
 fi
 # Check if GDM is installed
 l_pcl="gdm gdm3" # Space separated list of packages to check
 for l_pn in $l_pcl; do
 $l_pq "$l_pn" &> /dev/null && l_pkgoutput="$l_pkgoutput\n - Package:
\"$l_pn\" exists on the system\n - checking configuration"
 echo -e "$l_pkgoutput"
 done
 # Check configuration (If applicable)
 if [ -n "$l_pkgoutput" ]; then
 echo -e "$l_pkgoutput"
 # Look for existing settings and set variables if they exist
 l_kfile="$(grep -Prils -- '^\h*autorun-never\b' /etc/dconf/db/*.d)"
 # Set profile name based on dconf db directory ({PROFILE_NAME}.d)
 if [ -f "$l_kfile" ]; then
 l_gpname="$(awk -F\/ '{split($(NF-1),a,".");print a[1]}' <<<
"$l_kfile")"
 fi
 # If the profile name exist, continue checks
 if [ -n "$l_gpname" ]; then
 l_gpdir="/etc/dconf/db/$l_gpname.d"
 # Check if profile file exists
 if grep -Pq -- "^\h*system-db:$l_gpname\b" /etc/dconf/profile/*;
then
 l_output="$l_output\n - dconf database profile file \"$(grep -Pl
-- "^\h*system-db:$l_gpname\b" /etc/dconf/profile/*)\" exists"
 else
 l_output2="$l_output2\n - dconf database profile isn't set"
 fi
 # Check if the dconf database file exists
 if [ -f "/etc/dconf/db/$l_gpname" ]; then
 l_output="$l_output\n - The dconf database \"$l_gpname\" exists"
 else
 l_output2="$l_output2\n - The dconf database \"$l_gpname\"
doesn't exist"
 fi
 # check if the dconf database directory exists
 if [ -d "$l_gpdir" ]; then
 l_output="$l_output\n - The dconf directory \"$l_gpdir\" exitst"
 else
 l_output2="$l_output2\n - The dconf directory \"$l_gpdir\"
doesn't exist"
 fi
 # check autorun-never setting
 if grep -Pqrs -- '^\h*autorun-never\h*=\h*true\b' "$l_kfile"; then
 l_output="$l_output\n - \"autorun-never\" is set to true in:
Page 207
Internal Only - General
\"$l_kfile\""
 else
 l_output2="$l_output2\n - \"autorun-never\" is not set correctly"
 fi
 else
 # Settings don't exist. Nothing further to check
 l_output2="$l_output2\n - \"autorun-never\" is not set"
 fi
 else
 l_output="$l_output\n - GNOME Desktop Manager package is not installed
on the system\n - Recommendation is not applicable"
 fi
 # Report results. If no failures output in l_output2, we pass
 if [ -z "$l_output2" ]; then
 echo -e "\n- Audit Result:\n ** PASS **\n$l_output\n"
 else
 echo -e "\n- Audit Result:\n ** FAIL **\n - Reason(s) for audit
failure:\n$l_output2\n"
 [ -n "$l_output" ] && echo -e "\n- Correctly set:\n$l_output\n"
 fi
}
#!/usr/bin/env bash
{
 # Check if GNOME Desktop Manager is installed. If package isn't
installed, recommendation is Not Applicable\n
 # determine system's package manager
 l_pkgoutput=""
 if command -v dpkg-query &> /dev/null; then
 l_pq="dpkg-query -s"
 elif command -v rpm &> /dev/null; then
 l_pq="rpm -q"
 fi
 # Check if GDM is installed
 l_pcl="gdm gdm3" # Space separated list of packages to check
 for l_pn in $l_pcl; do
 $l_pq "$l_pn" &> /dev/null && l_pkgoutput="$l_pkgoutput\n - Package:
\"$l_pn\" exists on the system\n - checking configuration"
 done
 # Search /etc/dconf/db/ for [org/gnome/desktop/media-handling] settings)
 l_desktop_media_handling=$(grep -Psir -- '^\h*\[org/gnome/desktop/mediahandling\]' /etc/dconf/db/*)
 if [[ -n "$l_desktop_media_handling" ]]; then
 l_output="" l_output2=""
 l_autorun_setting=$(grep -Psir -- '^\h*autorun-never=true\b'
/etc/dconf/db/local.d/*)
 # Check for auto-run setting
 if [[ -n "$l_autorun_setting" ]]; then
 l_output="$l_output\n - \"autorun-never\" setting found"
 else
 l_output2="$l_output2\n - \"autorun-never\" setting not found"
 fi
 else
 l_output="$l_output\n - [org/gnome/desktop/media-handling] setting
not found in /etc/dconf/db/*"
 fi
 # Report results. If no failures output in l_output2, we pass
[ -n "$l_pkgoutput" ] && echo -e "\n$l_pkgoutput"
 if [ -z "$l_output2" ]; then
 echo -e "\n- Audit Result:\n ** PASS **\n$l_output\n"
 else
 echo -e "\n- Audit Result:\n ** FAIL **\n - Reason(s) for audit
failure:\n$l_output2\n"
 [ -n "$l_output" ] && echo -e "\n- Correctly set:\n$l_output\n"
 fi
}
#!/usr/bin/env bash
{
    # List of configuration files to check
    files=$(grep -Psil -- '^\h*\[xdmcp\]' /etc/{gdm3,gdm}/{custom,daemon}.conf)

    # Loop through each file returned by the audit
    while IFS= read -r l_file; do
        echo "Processing file: $l_file"
        
        # Check if the file contains the 'Enable=true' line under [xdmcp] block
        if grep -Pq -- '^\s*Enable\s*=\s*true' "$l_file"; then
            # Remove or comment out the Enable=true line
            sed -i '/^\s*Enable\s*=\s*true/s/^/# /' "$l_file"
            echo " - Disabled XDMCP in file: \"$l_file\" by commenting out 'Enable=true'"
        else
            echo " - No changes needed in file: \"$l_file\""
        fi
    done <<< "$files"
}

#!/bin/bash

# Ensure the script is run with superuser privileges
if [[ "$EUID" -ne 0 ]]; then
    echo "Please run as root."
    
fi


# 2.1.1 Ensure autofs services are not in use                                           [✓]
systemctl stop autofs
systemctl disable autofs

# 2.1.2 Ensure avahi daemon services are not in use                                     [✓]
systemctl stop avahi-daemon
systemctl disable avahi-daemon

# 2.1.3 Ensure dhcp server services are not in use                                      [✓]
systemctl stop dhcpd
systemctl disable dhcpd

# 2.1.4 Ensure dns server services are not in use                                       [✓]
systemctl stop named
systemctl disable named

# 2.1.5 Ensure dsnmasq services are not in use                                          [✓]
systemctl stop dnsmasq
systemctl disable dnsmasq

# 2.1.6 Ensure ftp server services are not in use                                       [✓]
systemctl stop vsftpd
systemctl disable vsftpd

# 2.1.7 Ensure ldap server services are not in use                                      [✓]
systemctl stop slapd
systemctl disable slapd

# 2.1.8(new) Ensure message access server servicesa are not in use                      [✓]
systemctl stop dovecot.socket dovecot.service
systemctl mask dovecot-imapd dovecot-pop3d #cambié purge por disable
    #nothing shoud be returned

# 2.1.9(.8 before) Ensure nfs server services are not in use                            [✓]
systemctl stop nfs-server
systemctl disable nfs-server

# 2.1.10(new) Ensure nis server services are not in use                                 [✓]
systemctl stop ypserv.service
systemctl mask ypserv.service

# 2.1.11(new) Ensure print services are not in use                                      [x]
# systemctl stop cups.socket cups.service
# systemctl mask cups.socket cups.service
        #dehabilitado, porque es un servicio para acceder a impresoras en red, 
                                                                    #pero puedo

# 2.1.12(.9 before) Ensure rpcbind services are not in use                              [✓]
systemctl stop rpcbind
systemctl disable rpcbind

# 2.1.13(.11 before) Ensure rsync server services are not in use                        [✓]
systemctl stop rsyncd
systemctl disable rsyncd

# 2.1.14(.10 before) Ensure samba file server services are not in use                   [✓]
systemctl stop smb
systemctl disable smb

# 2.1.15(.12 before) Ensure snmp services are not in use                                [✓]
systemctl stop snmpd
systemctl disable snmpd

# 2.1.16(.13 before) Ensure tftp server services are not in use                         [✓]
systemctl stop tftp
systemctl disable tftp

# 2.1.17(new) Ensure web proxy services are not in use                                  [✓]
systemctl stop squid.service
apt purge squid

# 2.1.18(.14 before) Ensure web server services are not in use                          [✓]
systemctl stop httpd
systemctl disable httpd

# 2.1.19(.15 before) Ensure xinetd services are not in use                              [✓]
systemctl stop xinetd
systemctl disable xinetd

# 2.1.20(.16 before) Ensure X window server services are not in use                     [✓]
systemctl stop x11-common
systemctl disable x11-common

# 2.1.21(.17 before) Ensure mail transfer agent is configured for local-only mode       [✓]
        # Configuring postfix to only listen on the loopback interface (localhost)
if systemctl is-active --quiet postfix; then
    postconf -e 'inet_interfaces = loopback-only'
    systemctl restart postfix
fi

#INTENTO DE MÓDULO 2.2
#Configure client services:

# 2.2.1 Ensure NIS Client is not installed                                              [ ]
apt purge nis

# 2.2.2 Ensure rsh client is not installed                                              [ ]
apt purge rsh-client

# 2.2.3 Ensure talk client is not installed                                             [ ]
apt purge talk

# 2.2.4 Ensure telnet client is not installed                                           [ ]
apt purge telnet

# 2.2.5 Ensure ldap client is not installed                                             [ ]
apt purge ldap-utils

# 2.2.6 Ensure ftp client is not installed                                              [ ]
apt purge ldap-utils


sudo apt install -y ubuntu-desktop

echo "Service hardening complete. Disabled all unnecessary services."
#!/usr/bin/env bash

# Check if system is physical or virtual with host-based time sync
is_virtual=$(systemd-detect-virt)
if [[ "$is_virtual" == "none" ]]; then
    echo "System is physical or no host-based sync available, continuing with remediation."
else
    echo "Virtual system with possible host-based time synchronization. Please verify host sync settings. Exiting."
    
fi

# Check if chrony or systemd-timesyncd is installed and active
#confirmando que solo uno esté activo
chrony_status=$(systemctl is-active chrony 2>/dev/null)
timesyncd_status=$(systemctl is-active systemd-timesyncd 2>/dev/null)

if [[ "$chrony_status" == "active" && "$timesyncd_status" == "active" ]]; then
    echo "Both chrony and systemd-timesyncd are active. Disabling systemd-timesyncd."
    systemctl stop systemd-timesyncd.service
    systemctl mask systemd-timesyncd.service
elif [[ "$chrony_status" != "active" && "$timesyncd_status" != "active" ]]; then
    echo "No time synchronization daemon is active. Installing and enabling chrony."
    apt update && apt install -y chrony
    systemctl enable --now chrony
elif [[ "$chrony_status" == "active" ]]; then
    echo "Only chrony is active. Ensuring systemd-timesyncd is disabled."
    systemctl stop systemd-timesyncd.service
    systemctl mask systemd-timesyncd.service
elif [[ "$timesyncd_status" == "active" ]]; then
    echo "Only systemd-timesyncd is active. Removing chrony if installed."
    apt purge -y chrony && apt autoremove -y
fi

# Verification
chrony_status=$(systemctl is-active chrony 2>/dev/null)
timesyncd_status=$(systemctl is-active systemd-timesyncd 2>/dev/null)

if [[ "$chrony_status" == "active" && "$timesyncd_status" != "active" ]]; then
    echo "Chrony is active and systemd-timesyncd is disabled. Remediation complete."
elif [[ "$timesyncd_status" == "active" && "$chrony_status" != "active" ]]; then
    echo "Systemd-timesyncd is active and chrony is uninstalled. Remediation complete."
else
    echo "Remediation failed. Please check time sync configuration manually."
fi
#!/usr/bin/env bash

# Ensure that only one time synchronization daemon is in use
chrony_status=$(systemctl is-active chrony 2>/dev/null)
timesyncd_status=$(systemctl is-active systemd-timesyncd 2>/dev/null)

if [[ "$chrony_status" == "active" ]]; then
    echo "Chrony is active; stopping and masking systemd-timesyncd."
    systemctl stop systemd-timesyncd.service
    systemctl mask systemd-timesyncd.service
  
elif [[ "$timesyncd_status" == "inactive" ]]; then
    echo "systemd-timesyncd is inactive; ensuring it is configured correctly."
fi

# Install and enable systemd-timesyncd if not already active
if [[ "$timesyncd_status" != "active" ]]; then
    echo "Enabling systemd-timesyncd as the time synchronization method."
    apt update && apt install -y systemd-timesyncd
    systemctl enable --now systemd-timesyncd
fi

# Configure systemd-timesyncd
CONFIG_FILE="/etc/systemd/timesyncd.conf"
mkdir -p /etc/systemd/timesyncd.conf.d

# Apply custom configuration
cat <<EOL > "$CONFIG_FILE"
[Time]
NTP=time1.google.com time2.google.com
FallbackNTP=ntp.ubuntu.com
EOL

echo "Custom NTP servers configured in $CONFIG_FILE."

# Restart systemd-timesyncd to apply changes
systemctl restart systemd-timesyncd

# Verification
if systemctl is-active --quiet systemd-timesyncd; then
    echo "systemd-timesyncd is active and configured. Remediation complete."
else
    echo "Failed to start systemd-timesyncd. Please check manually."
fi
#!/usr/bin/env bash

# Define the authorized time servers
AUTHORIZED_NTP="time.nist.gov"
AUTHORIZED_FALLBACK_NTP="time-a-g.nist.gov time-b-g.nist.gov time-c-g.nist.gov"

# Create the drop-in directory if it doesn't exist
if [ ! -d /etc/systemd/timesyncd.conf.d/ ]; then
    mkdir -p /etc/systemd/timesyncd.conf.d/
    echo "Created /etc/systemd/timesyncd.conf.d/ directory for configuration overrides."
fi

# Write the authorized NTP servers to a drop-in configuration file
cat <<EOL > /etc/systemd/timesyncd.conf.d/60-timesyncd.conf
[Time]
NTP=$AUTHORIZED_NTP
FallbackNTP=$AUTHORIZED_FALLBACK_NTP
EOL

echo "Configured systemd-timesyncd with authorized NTP servers."

# Restart systemd-timesyncd to apply the changes
systemctl restart systemd-timesyncd

# Verification
ntp_configured=$(grep "^NTP=" /etc/systemd/timesyncd.conf.d/60-timesyncd.conf | awk -F= '{print $2}' | xargs)
fallback_ntp_configured=$(grep "^FallbackNTP=" /etc/systemd/timesyncd.conf.d/60-timesyncd.conf | awk -F= '{print $2}' | xargs)

if [[ "$ntp_configured" == "$AUTHORIZED_NTP" && "$fallback_ntp_configured" == "$AUTHORIZED_FALLBACK_NTP" ]]; then
    echo "systemd-timesyncd is configured with the authorized time servers. Remediation complete."
else
    echo "Failed to configure authorized NTP servers. Please check the configuration manually."
fi
#!/usr/bin/env bash

# Define the authorized NTP servers
AUTHORIZED_SERVERS=(
    "pool time.nist.gov iburst maxsources 4"
    "server time-a-g.nist.gov iburst"
    "server 132.163.97.3 iburst"
    "server time-d-b.nist.gov iburst"
)

# Define the chrony configuration file path
CHRONY_CONF="/etc/chrony/chrony.conf"
CHRONY_SOURCES_DIR="/etc/chrony/sources.d"
CHRONY_SOURCES_FILE="$CHRONY_SOURCES_DIR/authorized.sources"

# Ensure chrony sources directory exists
if [ ! -d "$CHRONY_SOURCES_DIR" ]; then
    mkdir -p "$CHRONY_SOURCES_DIR"
    echo "Created $CHRONY_SOURCES_DIR for authorized sources."
fi

# Add authorized servers to a sources file
echo "# Authorized NTP servers" > "$CHRONY_SOURCES_FILE"
for server in "${AUTHORIZED_SERVERS[@]}"; do
    echo "$server" >> "$CHRONY_SOURCES_FILE"
done
echo "Configured authorized NTP servers in $CHRONY_SOURCES_FILE."

# Ensure 'sourcedir' directive is in the main chrony.conf file
if ! grep -q "^sourcedir $CHRONY_SOURCES_DIR" "$CHRONY_CONF"; then
    echo "sourcedir $CHRONY_SOURCES_DIR" >> "$CHRONY_CONF"
    echo "Added 'sourcedir $CHRONY_SOURCES_DIR' to $CHRONY_CONF."
fi

# Restart chronyd to apply changes
systemctl restart chronyd

# Verification
if systemctl is-active --quiet chronyd; then
    echo "chronyd is running with authorized NTP servers configured. Remediation complete."
else
    echo "Failed to apply changes. Please check chrony configuration manually."
fi
#!/usr/bin/env bash

# Define chrony configuration path
CHRONY_CONF="/etc/chrony/chrony.conf"
CHRONY_CONF_D="/etc/chrony/conf.d"
CHRONY_USER="_chrony"

# Check if chronyd is running as _chrony
if ps -ef | awk '(/[c]hronyd/ && $1!="_chrony") { print $1 }' | grep -q '.'; then
    echo "chronyd is not running as user $CHRONY_USER. Applying configuration."

    # Ensure the chrony configuration directory exists
    [ ! -d "$CHRONY_CONF_D" ] && mkdir -p "$CHRONY_CONF_D"

    # Configure chronyd to run as _chrony user
    if ! grep -q "^user $CHRONY_USER" "$CHRONY_CONF" "$CHRONY_CONF_D"/*.conf 2>/dev/null; then
        echo "user $CHRONY_USER" >> "$CHRONY_CONF"
        echo "Added 'user $CHRONY_USER' to $CHRONY_CONF."
    fi

    # Restart chronyd to apply the user configuration
    systemctl restart chronyd

    # Verify if chronyd is now running as _chrony
    if ps -ef | awk '(/[c]hronyd/ && $1!="_chrony") { print $1 }' | grep -q '.'; then
        echo "Failed to configure chronyd to run as $CHRONY_USER. Please check configuration."
    else
        echo "chronyd is now running as $CHRONY_USER."
    fi
else
    echo "chronyd is already running as $CHRONY_USER. No action needed."
fi
#!/usr/bin/env bash

# Check if chrony service is installed and in use
if systemctl list-unit-files | grep -q '^chrony\.service'; then
    echo "chrony service is installed."

    # Check if chrony service is enabled
    if systemctl is-enabled chrony.service | grep -q 'enabled'; then
        echo "chrony service is already enabled."
    else
        echo "Enabling chrony service..."
        systemctl unmask chrony.service
        systemctl enable chrony.service
    fi

    # Check if chrony service is active
    if systemctl is-active chrony.service | grep -q 'active'; then
        echo "chrony service is already running."
    else
        echo "Starting chrony service..."
        systemctl start chrony.service
    fi
    echo "chrony service is enabled and running."

else
    echo "chrony service is not installed or another time synchronization service is in use."
    echo "Please install chrony or ensure the correct time synchronization service is in place."
fi
#!/usr/bin/env bash

# Check if cron is installed and enabled
cron_service=$(systemctl list-unit-files | awk '$1~/^crond?\.service/{print $1}')

if [ -n "$cron_service" ]; then
    echo "Cron service is installed."

    # Check if cron service is enabled
    cron_enabled=$(systemctl list-unit-files | awk '$1~/^crond?\.service/{print $2}')
    if [[ "$cron_enabled" == "enabled" ]]; then
        echo "Cron service is already enabled."
    else
        echo "Enabling cron service..."
        systemctl unmask "$cron_service"
        systemctl --now enable "$cron_service"
    fi

    # Check if cron service is active
    cron_active=$(systemctl list-units | awk '$1~/^crond?\.service/{print $3}')
    if [[ "$cron_active" == "active" ]]; then
        echo "Cron service is already active."
    else
        echo "Starting cron service..."
        systemctl start "$cron_service"
    fi

    echo "Cron service is enabled and running."

else
    echo "Cron service is not installed or another job scheduler is in use."
    echo "Please install cron or use an alternative scheduling method as per your local policy."
fi
#!/usr/bin/env bash

# Path to the cron.monthly directory
cron_monthly_dir="/etc/cron.monthly"

# Check current permissions and ownership of /etc/cron.monthly
current_permissions=$(stat -Lc 'Access: (%a/%A) Uid: (%u/%U) Gid: (%g/%G)' "$cron_monthly_dir")

# Define the expected permissions and ownership
expected_permissions="Access: (700/drwx------) Uid: (0/root) Gid: (0/root)"

# Output the current state of the cron.monthly directory
echo "Current permissions on $cron_monthly_dir:"
echo "$current_permissions"

# Check if permissions and ownership are as expected
if [[ "$current_permissions" == "$expected_permissions" ]]; then
    echo "Permissions and ownership are correctly set."
else
    echo "Permissions or ownership are incorrect. Applying correct settings..."
    
    # Set correct ownership and permissions
    chown root:root "$cron_monthly_dir"
    chmod og-rwx "$cron_monthly_dir"

    echo "Permissions and ownership have been corrected."
fi
#!/usr/bin/env bash

# Path to the cron.d directory
cron_d_dir="/etc/cron.d"

# Check current permissions and ownership of /etc/cron.d
current_permissions=$(stat -Lc 'Access: (%a/%A) Uid: (%u/%U) Gid: (%g/%G)' "$cron_d_dir")

# Define the expected permissions and ownership
expected_permissions="Access: (700/drwx------) Uid: (0/root) Gid: (0/root)"

# Output the current state of the cron.d directory
echo "Current permissions on $cron_d_dir:"
echo "$current_permissions"

# Check if permissions and ownership are as expected
if [[ "$current_permissions" == "$expected_permissions" ]]; then
    echo "Permissions and ownership are correctly set."
else
    echo "Permissions or ownership are incorrect. Applying correct settings..."
    
    # Set correct ownership and permissions
    chown root:root "$cron_d_dir"
    chmod og-rwx "$cron_d_dir"

    echo "Permissions and ownership have been corrected."
fi
#!/usr/bin/env bash

# Check and configure /etc/cron.allow
if [ ! -e "/etc/cron.allow" ]; then
    # Create /etc/cron.allow if it doesn't exist
    touch /etc/cron.allow
    echo "/etc/cron.allow file created."
fi

# Set ownership and permissions for /etc/cron.allow
chown root:root /etc/cron.allow
chmod 640 /etc/cron.allow
echo "/etc/cron.allow permissions set to 640 and ownership set to root:root."

# Check and configure /etc/cron.deny if it exists
if [ -e "/etc/cron.deny" ]; then
    # Set ownership and permissions for /etc/cron.deny
    chown root:root /etc/cron.deny
    chmod 640 /etc/cron.deny
    echo "/etc/cron.deny permissions set to 640 and ownership set to root:root."
else
    echo "/etc/cron.deny does not exist, no action required."
fi

# Check if both files exist and ensure cron.allow takes precedence
if [ -e "/etc/cron.allow" ] && [ -e "/etc/cron.deny" ]; then
    echo "/etc/cron.allow takes precedence over /etc/cron.deny."
else
    echo "Only /etc/cron.allow or no deny file exists, cron.allow will control access."
fi
#!/usr/bin/env bash
{
    # Check if group 'daemon' exists, otherwise use 'root'
    grep -Pq -- '^daemon\b' /etc/group && l_group="daemon" || l_group="root"

    # Ensure /etc/at.allow exists
    if [ ! -e "/etc/at.allow" ]; then
        touch /etc/at.allow
        echo "/etc/at.allow file created."
    fi

    # Set ownership and permissions for /etc/at.allow
    chown root:"$l_group" /etc/at.allow
    chmod 640 /etc/at.allow
    echo "/etc/at.allow permissions set to 640 and ownership set to root:$l_group."

    # Check if /etc/at.deny exists
    if [ -e "/etc/at.deny" ]; then
        # Set ownership and permissions for /etc/at.deny
        chown root:"$l_group" /etc/at.deny
        chmod 640 /etc/at.deny
        echo "/etc/at.deny permissions set to 640 and ownership set to root:$l_group."
    else
        echo "/etc/at.deny does not exist, no action required."
    fi
}
#!/usr/bin/env bash
{
 module_fix()
 {
 if ! modprobe -n -v "$l_mname" | grep -P -- '^\h*install
\/bin\/(true|false)'; then
 echo -e " - setting module: \"$l_mname\" to be un-loadable"
 echo -e "install $l_mname /bin/false" >>/etc/modprobe.d/"$l_mname".conf
 fi
 if lsmod | grep "$l_mname" > /dev/null 2>&1; then
 echo -e " - unloading module \"$l_mname\""
 modprobe -r "$l_mname"
 fi
 if ! grep -Pq -- "^\h*blacklist\h+$l_mname\b" /etc/modprobe.d/*; then
 echo -e " - deny listing \"$l_mname\""
 echo -e "blacklist $l_mname" >> /etc/modprobe.d/"$l_mname".conf
 fi
 }
 if [ -n "$(find /sys/class/net/*/ -type d -name wireless)" ]; then
 l_dname=$(for driverdir in $(find /sys/class/net/*/ -type d -name
wireless | xargs -0 dirname); do basename "$(readlink -f
"$driverdir"/device/driver/module)";done | sort -u)
 for l_mname in $l_dname; do
 module_fix
 done
 fi
 }
#!/usr/bin/env bash

# Check if the 'bluez' package is installed
if dpkg-query -s bluez &>/dev/null; then
    echo "The 'bluez' package is installed."

    # Check if 'bluetooth.service' is enabled
    if systemctl is-enabled bluetooth.service &>/dev/null && systemctl is-enabled bluetooth.service | grep -q 'enabled'; then
        echo "The 'bluetooth.service' is enabled. Disabling it..."
        # Stop and mask bluetooth.service if enabled
        systemctl stop bluetooth.service
        systemctl mask bluetooth.service
        echo "'bluetooth.service' has been stopped and masked."
    else
        echo "'bluetooth.service' is not enabled."
    fi

    # Check if 'bluetooth.service' is active
    if systemctl is-active bluetooth.service &>/dev/null && systemctl is-active bluetooth.service | grep -q '^active'; then
        echo "'bluetooth.service' is active. Stopping it..."
        # Stop bluetooth.service if active
        systemctl stop bluetooth.service
        echo "'bluetooth.service' has been stopped."
    fi

    # Remove bluez package if it is not required by any other dependencies
    apt-get remove --purge -y bluez
    echo "'bluez' package has been removed."

else
    echo "'bluez' package is not installed on the system."
fi
#!/usr/bin/env bash
{
 l_mname="dccp" # set module name
 l_mtype="net" # set module type
 l_mpath="/lib/modules/**/kernel/$l_mtype"
 l_mpname="$(tr '-' '_' <<< "$l_mname")"
 l_mndir="$(tr '-' '/' <<< "$l_mname")"
 module_loadable_fix()
 {
 # If the module is currently loadable, add "install {MODULE_NAME} /bin/false" to a file in
"/etc/modprobe.d"
 l_loadable="$(modprobe -n -v "$l_mname")"
 [ "$(wc -l <<< "$l_loadable")" -gt "1" ] && l_loadable="$(grep -P --
"(^\h*install|\b$l_mname)\b" <<< "$l_loadable")"
 if ! grep -Pq -- '^\h*install \/bin\/(true|false)' <<< "$l_loadable"; then
 echo -e "\n - setting module: \"$l_mname\" to be not loadable"
 echo -e "install $l_mname /bin/false" >> /etc/modprobe.d/"$l_mpname".conf
 fi
 }
 module_loaded_fix()
 {
 # If the module is currently loaded, unload the module
 if lsmod | grep "$l_mname" > /dev/null 2>&1; then
 echo -e "\n - unloading module \"$l_mname\""
 modprobe -r "$l_mname"
 fi
 }
 module_deny_fix()
 {
 # If the module isn't deny listed, denylist the module
 if ! modprobe --showconfig | grep -Pq -- "^\h*blacklist\h+$l_mpname\b"; then
 echo -e "\n - deny listing \"$l_mname\""
 echo -e "blacklist $l_mname" >> /etc/modprobe.d/"$l_mpname".conf
 fi
 }
 # Check if the module exists on the system
 for l_mdir in $l_mpath; do
 if [ -d "$l_mdir/$l_mndir" ] && [ -n "$(ls -A $l_mdir/$l_mndir)" ]; then
 echo -e "\n - module: \"$l_mname\" exists in \"$l_mdir\"\n - checking if disabled..."
 module_deny_fix
 if [ "$l_mdir" = "/lib/modules/$(uname -r)/kernel/$l_mtype" ]; then
 module_loadable_fix
 module_loaded_fix
 fi
 else
 echo -e "\n - module: \"$l_mname\" doesn't exist in \"$l_mdir\"\n"
 fi
 done
 echo -e "\n - remediation of module: \"$l_mname\" complete\n"
}
#!/usr/bin/env bash
{
 l_mname="tipc" # set module name
 l_mtype="net" # set module type
 l_mpath="/lib/modules/**/kernel/$l_mtype"
 l_mpname="$(tr '-' '_' <<< "$l_mname")"
 l_mndir="$(tr '-' '/' <<< "$l_mname")"
 module_loadable_fix()
 {
 # If the module is currently loadable, add "install {MODULE_NAME} /bin/false" to a file in
"/etc/modprobe.d"
 l_loadable="$(modprobe -n -v "$l_mname")"
 [ "$(wc -l <<< "$l_loadable")" -gt "1" ] && l_loadable="$(grep -P --
"(^\h*install|\b$l_mname)\b" <<< "$l_loadable")"
 if ! grep -Pq -- '^\h*install \/bin\/(true|false)' <<< "$l_loadable"; then
 echo -e "\n - setting module: \"$l_mname\" to be not loadable"
 echo -e "install $l_mname /bin/false" >> /etc/modprobe.d/"$l_mpname".conf
 fi
 }
 module_loaded_fix()
 {
 # If the module is currently loaded, unload the module
 if lsmod | grep "$l_mname" > /dev/null 2>&1; then
 echo -e "\n - unloading module \"$l_mname\""
 modprobe -r "$l_mname"
 fi
 }
 module_deny_fix()
 {
 # If the module isn't deny listed, denylist the module
 if ! modprobe --showconfig | grep -Pq -- "^\h*blacklist\h+$l_mpname\b"; then
 echo -e "\n - deny listing \"$l_mname\""
 echo -e "blacklist $l_mname" >> /etc/modprobe.d/"$l_mpname".conf
 fi
 }
 # Check if the module exists on the system
 for l_mdir in $l_mpath; do
 if [ -d "$l_mdir/$l_mndir" ] && [ -n "$(ls -A $l_mdir/$l_mndir)" ]; then
 echo -e "\n - module: \"$l_mname\" exists in \"$l_mdir\"\n - checking if disabled..."
 module_deny_fix
 if [ "$l_mdir" = "/lib/modules/$(uname -r)/kernel/$l_mtype" ]; then
 module_loadable_fix
 module_loaded_fix
 fi
 else
 echo -e "\n - module: \"$l_mname\" doesn't exist in \"$l_mdir\"\n"
 fi
 done
 echo -e "\n - remediation of module: \"$l_mname\" complete\n"
}
#!/usr/bin/env bash
{
 l_mname="rds" # set module name
 l_mtype="net" # set module type
 l_mpath="/lib/modules/**/kernel/$l_mtype"
 l_mpname="$(tr '-' '_' <<< "$l_mname")"
 l_mndir="$(tr '-' '/' <<< "$l_mname")"
 module_loadable_fix()
 {
 # If the module is currently loadable, add "install {MODULE_NAME} /bin/false" to a file in
"/etc/modprobe.d"
 l_loadable="$(modprobe -n -v "$l_mname")"
 [ "$(wc -l <<< "$l_loadable")" -gt "1" ] && l_loadable="$(grep -P --
"(^\h*install|\b$l_mname)\b" <<< "$l_loadable")"
 if ! grep -Pq -- '^\h*install \/bin\/(true|false)' <<< "$l_loadable"; then
 echo -e "\n - setting module: \"$l_mname\" to be not loadable"
 echo -e "install $l_mname /bin/false" >> /etc/modprobe.d/"$l_mpname".conf
 fi
 }
 module_loaded_fix()
 {
 # If the module is currently loaded, unload the module
 if lsmod | grep "$l_mname" > /dev/null 2>&1; then
 echo -e "\n - unloading module \"$l_mname\""
 modprobe -r "$l_mname"
 fi
 }
 module_deny_fix()
 {
 # If the module isn't deny listed, denylist the module
 if ! modprobe --showconfig | grep -Pq -- "^\h*blacklist\h+$l_mpname\b"; then
 echo -e "\n - deny listing \"$l_mname\""
 echo -e "blacklist $l_mname" >> /etc/modprobe.d/"$l_mpname".conf
 fi
 }
 # Check if the module exists on the system
 for l_mdir in $l_mpath; do
 if [ -d "$l_mdir/$l_mndir" ] && [ -n "$(ls -A $l_mdir/$l_mndir)" ]; then
 echo -e "\n - module: \"$l_mname\" exists in \"$l_mdir\"\n - checking if disabled..."
 module_deny_fix
 if [ "$l_mdir" = "/lib/modules/$(uname -r)/kernel/$l_mtype" ]; then
 module_loadable_fix
 module_loaded_fix
 fi
 else
 echo -e "\n - module: \"$l_mname\" doesn't exist in \"$l_mdir\"\n"
 fi
 done
 echo -e "\n - remediation of module: \"$l_mname\" complete\n"
}

#!/usr/bin/env bash
{
 l_mname="sctp" # set module name
 l_mtype="net" # set module type
 l_mpath="/lib/modules/**/kernel/$l_mtype"
 l_mpname="$(tr '-' '_' <<< "$l_mname")"
 l_mndir="$(tr '-' '/' <<< "$l_mname")"
 module_loadable_fix()
 {
 # If the module is currently loadable, add "install {MODULE_NAME} /bin/false" to a file in
"/etc/modprobe.d"
 l_loadable="$(modprobe -n -v "$l_mname")"
 [ "$(wc -l <<< "$l_loadable")" -gt "1" ] && l_loadable="$(grep -P --
"(^\h*install|\b$l_mname)\b" <<< "$l_loadable")"
 if ! grep -Pq -- '^\h*install \/bin\/(true|false)' <<< "$l_loadable"; then
 echo -e "\n - setting module: \"$l_mname\" to be not loadable"
 echo -e "install $l_mname /bin/false" >> /etc/modprobe.d/"$l_mpname".conf
 fi
 }
 module_loaded_fix()
 {
 # If the module is currently loaded, unload the module
 if lsmod | grep "$l_mname" > /dev/null 2>&1; then
 echo -e "\n - unloading module \"$l_mname\""
 modprobe -r "$l_mname"
 fi
 }
 module_deny_fix()
 {
 # If the module isn't deny listed, denylist the module
 if ! modprobe --showconfig | grep -Pq -- "^\h*blacklist\h+$l_mpname\b"; then
 echo -e "\n - deny listing \"$l_mname\""
 echo -e "blacklist $l_mname" >> /etc/modprobe.d/"$l_mpname".conf
 fi
 }
 # Check if the module exists on the system
 for l_mdir in $l_mpath; do
 if [ -d "$l_mdir/$l_mndir" ] && [ -n "$(ls -A $l_mdir/$l_mndir)" ]; then
 echo -e "\n - module: \"$l_mname\" exists in \"$l_mdir\"\n - checking if disabled..."
 module_deny_fix
 if [ "$l_mdir" = "/lib/modules/$(uname -r)/kernel/$l_mtype" ]; then
 module_loadable_fix
 module_loaded_fix
 fi
 else
 echo -e "\n - module: \"$l_mname\" doesn't exist in \"$l_mdir\"\n"
 fi
 done
 echo -e "\n - remediation of module: \"$l_mname\" complete\n"
}
#!/usr/bin/env bash

{
    l_output="" l_output2=""
    a_parlist=("net.ipv4.ip_forward=0" "net.ipv6.conf.all.forwarding=0")
    l_ufwscf="$([ -f /etc/default/ufw ] && awk -F= '/^\s*IPT_SYSCTL=/ {print $2}' /etc/default/ufw)"

    kernel_parameter_chk() {
        l_krp="$(sysctl "$l_kpname" | awk -F= '{print $2}' | xargs)"  # Check running configuration
        if [ "$l_krp" = "$l_kpvalue" ]; then
            l_output="$l_output\n - \"$l_kpname\" is correctly set to \"$l_krp\" in the running configuration"
        else
            l_output2="$l_output2\n - \"$l_kpname\" is incorrectly set to \"$l_krp\" in the running configuration and should have a value of: \"$l_kpvalue\""
        fi

        unset A_out
        declare -A A_out  # Check durable setting (files)

        while read -r l_out; do
            if [ -n "$l_out" ]; then
                if [[ $l_out =~ ^\s*# ]]; then
                    l_file="${l_out//# /}"
                else
                    l_kpar="$(awk -F= '{print $1}' <<< "$l_out" | xargs)"
                    [ "$l_kpar" = "$l_kpname" ] && A_out+=(["$l_kpar"]="$l_file")
                fi
            fi
        done < <(/usr/lib/systemd/systemd-sysctl --cat-config | grep -Po '^\h*([^#\n\r]+|#\h*\/[^#\n\r\h]+\.conf\b)')

        if [ -n "$l_ufwscf" ]; then
            l_kpar="$(grep -Po "^\h*$l_kpname\b" "$l_ufwscf" | xargs)"
            l_kpar="${l_kpar//\//.}"
            [ "$l_kpar" = "$l_kpname" ] && A_out+=(["$l_kpar"]="$l_ufwscf")
        fi

        if (( ${#A_out[@]} > 0 )); then  # Assess output from files and generate output
            while IFS="=" read -r l_fkpname l_fkpvalue; do
                l_fkpname="${l_fkpname// /}"; l_fkpvalue="${l_fkpvalue// /}"
                if [ "$l_fkpvalue" = "$l_kpvalue" ]; then
                    l_output="$l_output\n - \"$l_kpname\" is correctly set to \"$l_fkpvalue\" in \"$(printf '%s' "${A_out[@]}")\"\n"
                else
                    l_output2="$l_output2\n - \"$l_kpname\" is incorrectly set to \"$l_fkpvalue\" in \"$(printf '%s' "${A_out[@]}")\" and should have a value of: \"$l_kpvalue\"\n"
                fi
            done < <(grep -Po -- "^\h*$l_kpname\h*=\h*\H+" "${A_out[@]}")
        else
            l_output2="$l_output2\n - \"$l_kpname\" is not set in an included file\n ** Note: \"$l_kpname\" May be set in a file that's ignored by load procedure **\n"
        fi
    }

    while IFS="=" read -r l_kpname l_kpvalue; do  # Assess and check parameters
        l_kpname="${l_kpname// /}"; l_kpvalue="${l_kpvalue// /}"
        if ! grep -Pqs '^\h*0\b' /sys/module/ipv6/parameters/disable && grep -q '^net.ipv6.' <<< "$l_kpname"; then
            l_output="$l_output\n - IPv6 is disabled on the system, \"$l_kpname\" is not applicable"
        else
            kernel_parameter_chk
        fi
    done < <(printf '%s\n' "${a_parlist[@]}")

    if [ -z "$l_output2" ]; then  # Provide output from checks
        echo -e "\n- Audit Result:\n ** PASS **\n$l_output\n"
    else
        echo -e "\n- Audit Result:\n ** FAIL **\n - Reason(s) for audit failure:\n$l_output2\n"
        [ -n "$l_output" ] && echo -e "\n- Correctly set:\n$l_output\n"
    fi
}  

sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1
sysctl -w net.ipv4.route.flush=1
echo "net.ipv4.icmp_echo_ignore_broadcasts = 1" >> /etc/sysctl.d/60-netipv4_sysctl.conf

sysctl -w net.ipv4.conf.all.accept_redirects=0
sysctl -w net.ipv4.conf.default.accept_redirects=0
sysctl -w net.ipv4.route.flush=1

sysctl -w net.ipv6.conf.all.accept_redirects=0
sysctl -w net.ipv6.conf.default.accept_redirects=0
sysctl -w net.ipv6.route.flush=1

sysctl -w net.ipv4.conf.all.secure_redirects=0
sysctl -w net.ipv4.conf.default.secure_redirects=0
sysctl -w net.ipv4.route.flush=1

sysctl -w net.ipv4.conf.all.rp_filter=1
sysctl -w net.ipv4.conf.default.rp_filter=1
sysctl -w net.ipv4.route.flush=1

sysctl -w net.ipv4.conf.all.accept_source_route=0
sysctl -w net.ipv4.conf.default.accept_source_route=0
sysctl -w net.ipv4.route.flush=1

sysctl -w net.ipv4.conf.all.log_martians=1
sysctl -w net.ipv4.conf.default.log_martians=1
sysctl -w net.ipv4.route.flush=1

sysctl -w net.ipv4.tcp_syncookies=1
sysctl -w net.ipv4.route.flush=1
sysctl -w net.ipv4.ip_forward=0

sysctl -w net.ipv6.conf.all.accept_ra=0
sysctl -w net.ipv6.conf.default.accept_ra=0
sysctl -w net.ipv6.route.flush=1



apt install ufw
 apt purge iptables-persistent
  ufw allow proto tcp from any to any port 22
  systemctl unmask ufw.service
  systemctl --now enable ufw.service
  ufw enable
  ufw allow in on lo
 ufw allow out on lo
 ufw deny in from 127.0.0.0/8
 ufw deny in from ::1
ufw allow out on all
#ufw allow in <port>/<tcp or udp protocol>
 #ufw deny in <port>/<tcp or udp protocol>
  ufw default deny incoming
 ufw default deny outgoing
 ufw default deny routed
 
#!/bin/bash

# Ensure nftables is installed (uncomment if needed)
# sudo apt update && sudo apt install -y nftables

#!/bin/bash

#!/bin/bash

# Ensure nftables is installed (uncomment if needed)
# sudo apt update && sudo apt install -y nftables

# Enable and start nftables service
sudo systemctl enable nftables
sudo systemctl start nftables

# Flush all current nftables rules to start fresh
sudo nft flush ruleset

# Create main inet table (for both IPv4 and IPv6)
sudo nft add table inet filter

# INPUT Chain: Incoming traffic, with default drop policy
sudo nft add chain inet filter input { type filter hook input priority 0 \; policy drop \; }

# Allow loopback traffic for localhost (IPv4 and IPv6)
sudo nft add rule inet filter input iifname "lo" accept

# Allow established and related incoming connections (all protocols)
sudo nft add rule inet filter input ct state established,related accept

# Allow incoming SSH (port 22)
sudo nft add rule inet filter input tcp dport 22 accept

# Allow incoming HTTP/HTTPS (ports 80, 443)
sudo nft add rule inet filter input tcp dport {80, 443} accept

# Allow incoming DNS (UDP port 53)
sudo nft add rule inet filter input udp dport 53 accept

# Allow essential ICMP types for IPv4
sudo nft add rule inet filter input ip protocol icmp icmp type echo-request accept
sudo nft add rule inet filter input ip protocol icmp icmp type echo-reply accept
sudo nft add rule inet filter input ip protocol icmp icmp type destination-unreachable accept
sudo nft add rule inet filter input ip protocol icmp icmp type time-exceeded accept
sudo nft add rule inet filter input ip protocol icmp icmp type parameter-problem accept

# Allow essential ICMPv6 types for IPv6
sudo nft add rule inet filter input ip6 nexthdr icmpv6 icmpv6 type echo-request accept
sudo nft add rule inet filter input ip6 nexthdr icmpv6 icmpv6 type echo-reply accept
sudo nft add rule inet filter input ip6 nexthdr icmpv6 icmpv6 type destination-unreachable accept
sudo nft add rule inet filter input ip6 nexthdr icmpv6 icmpv6 type packet-too-big accept
sudo nft add rule inet filter input ip6 nexthdr icmpv6 icmpv6 type time-exceeded accept
sudo nft add rule inet filter input ip6 nexthdr icmpv6 icmpv6 type parameter-problem accept

# Save the ruleset to persist changes
sudo nft list ruleset > /etc/nftables.rules

# Include the ruleset in nftables.conf for persistence on reboot
echo "include \"/etc/nftables.rules\"" | sudo tee -a /etc/nftables.conf > /dev/null



# 4.3 - iptables
# apt install iptables iptables-persistent


#5#!/usr/bin/env bash

# Secure sshd_config file and directory permissions
{
    chmod u-x,og-rwx /etc/ssh/sshd_config
    chown root:root /etc/ssh/sshd_config

    # Secure all files within /etc/ssh/sshd_config.d
    while IFS= read -r -d $'\0' l_file; do
        if [ -e "$l_file" ]; then
            chmod u-x,og-rwx "$l_file"
            chown root:root "$l_file"
        fi
    done < <(find /etc/ssh/sshd_config.d -type f -print0 2>/dev/null)
}

#!/usr/bin/env bash

# Initialize outputs and determine SSH group name
{
    l_output=""
    l_output2=""
    l_ssh_group_name="$(awk -F: '($1 ~ /^(ssh_keys|_?ssh)$/) {print $1}' /etc/group)"

    # Function to fix file access
    FILE_ACCESS_FIX() {
        while IFS=: read -r l_file_mode l_file_owner l_file_group; do
            echo "File: \"$l_file\" mode: \"$l_file_mode\" owner: \"$l_file_owner\" group: \"$l_file_group\""
            l_out2=""
            
            # Determine permission mask and maximum permissions based on group
            [ "$l_file_group" = "$l_ssh_group_name" ] && l_pmask="0137" || l_pmask="0177"
            l_maxperm="$(printf '%o' $((0777 & ~$l_pmask)))"

            # Update file mode if needed
            if [ $((l_file_mode & l_pmask)) -gt 0 ]; then
                l_out2="$l_out2\n - Mode: \"$l_file_mode\" should be mode: \"$l_maxperm\" or more restrictive\n - Updating to mode: \"$l_maxperm\""
                [ "$l_file_group" = "$l_ssh_group_name" ] && chmod u-x,g-wx,o-rwx "$l_file" || chmod u-x,go-rwx "$l_file"
            fi

            # Update owner if needed
            if [ "$l_file_owner" != "root" ]; then
                l_out2="$l_out2\n - Owned by: \"$l_file_owner\" should be owned by \"root\"\n - Changing ownership to \"root\""
                chown root "$l_file"
            fi

            # Update group if needed
            if [[ ! "$l_file_group" =~ ($l_ssh_group_name|root) ]]; then
                l_new_group="${l_ssh_group_name:-root}"
                l_out2="$l_out2\n - Owned by group \"$l_file_group\" should be group owned by: \"$l_new_group\"\n - Changing group ownership to \"$l_new_group\""
                chgrp "$l_new_group" "$l_file"
            fi

            # Append results to output
            if [ -n "$l_out2" ]; then
                l_output2="$l_output2\n - File: \"$l_file\"$l_out2"
            else
                l_output="$l_output\n - File: \"$l_file\"\n - Correct: mode: \"$l_file_mode\", owner: \"$l_file_owner\", and group owner: \"$l_file_group\" configured"
            fi
        done < <(stat -Lc '%#a:%U:%G' "$l_file")
    }

    # Apply file access fixes
    while IFS= read -r -d $'\0' l_file; do
        if ssh-keygen -lf &>/dev/null "$l_file"; then
            file "$l_file" | grep -Piq -- '\bopenssh\h+([^#\n\r]+\h+)?private\h+key\b' && FILE_ACCESS_FIX
        fi
    done < <(find -L /etc/ssh -xdev -type f -print0 2>/dev/null)

    # Display results
    if [ -z "$l_output2" ]; then
        echo -e "\n- No access changes required\n"
    else
        echo -e "\n- Remediation results:\n$l_output2\n"
    fi
}

#!/usr/bin/env bash

# Define variables and permission mask for sshd_config files
{
    l_output=""
    l_output2=""
    l_pmask="0133"
    l_maxperm="$(printf '%o' $((0777 & ~$l_pmask)))"

    # Function to enforce file access policies
    FILE_ACCESS_FIX() {
        while IFS=: read -r l_file_mode l_file_owner l_file_group; do
            l_out2=""

            # Check and update file mode
            if [ $((l_file_mode & l_pmask)) -gt 0 ]; then
                l_out2="$l_out2\n - Mode: \"$l_file_mode\" should be mode: \"$l_maxperm\" or more restrictive\n - Updating to mode: \"$l_maxperm\""
                chmod u-x,go-wx "$l_file"
            fi

            # Check and update owner
            if [ "$l_file_owner" != "root" ]; then
                l_out2="$l_out2\n - Owned by: \"$l_file_owner\" should be owned by \"root\"\n - Changing ownership to \"root\""
                chown root "$l_file"
            fi

            # Check and update group ownership
            if [ "$l_file_group" != "root" ]; then
                l_out2="$l_out2\n - Owned by group \"$l_file_group\" should be group owned by: \"root\"\n - Changing group ownership to \"root\""
                chgrp root "$l_file"
            fi

            # Output results
            if [ -n "$l_out2" ]; then
                l_output2="$l_output2\n - File: \"$l_file\"$l_out2"
            else
                l_output="$l_output\n - File: \"$l_file\"\n - Correct: mode: \"$l_file_mode\", owner: \"$l_file_owner\", and group owner: \"$l_file_group\" configured"
            fi
        done < <(stat -Lc '%#a:%U:%G' "$l_file")
    }

    # Apply fixes to SSH-related files
    while IFS= read -r -d $'\0' l_file; do
        if ssh-keygen -lf &>/dev/null "$l_file"; then
            file "$l_file" | grep -Piq -- '\bopenssh\h+([^#\n\r]+\h+)?public\h+key\b' && FILE_ACCESS_FIX
        fi
    done < <(find -L /etc/ssh -xdev -type f -print0 2>/dev/null)

    # Display results
    if [ -z "$l_output2" ]; then
        echo -e "\n- No access changes required\n"
    else
        echo -e "\n- Remediation results:\n$l_output2\n"
    fi
}

#!/bin/bash

# Backup the original sshd_config file
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak

# Define the changes to be made
{
  # Set Banner parameter above any Include and Match entries
  echo "Banner /etc/issue.net"

  # Set Ciphers to unapproved weak Ciphers
  echo "Ciphers -3des-cbc,aes128-cbc,aes192-cbc,aes256-cbc,chacha20-poly1305@openssh.com"

  # Set ClientAliveInterval and ClientAliveCountMax parameters
  echo "ClientAliveInterval 15"
  echo "ClientAliveCountMax 3"

  # Set DisableForwarding to yes
  echo "DisableForwarding yes"

  # Set GSSAPIAuthentication to no
  echo "GSSAPIAuthentication no"

  # Set HostbasedAuthentication to no
  echo "HostbasedAuthentication no"

  # Set IgnoreRhosts to yes
  echo "IgnoreRhosts yes"

  # Set KexAlgorithms to unapproved weak algorithms
  echo "KexAlgorithms -diffie-hellman-group1-sha1,diffie-hellman-group14-sha1,diffie-hellman-group-exchange-sha1"

  # Set LoginGraceTime to 60 seconds
  echo "LoginGraceTime 60"

  # Set LogLevel to VERBOSE or INFO
  echo "LogLevel VERBOSE"

  # Set MACs to unapproved weak MACs
  echo "MACs -hmac-md5,hmac-md5-96,hmac-ripemd160,hmac-sha1-96,umac64@openssh.com,hmac-md5-etm@openssh.com,hmac-md5-96-etm@openssh.com,hmacripemd160-etm@openssh.com,hmac-sha1-96-etm@openssh.com,umac-64-etm@openssh.com,umac-128-etm@openssh.com"

  # Set MaxAuthTries to 4 or less
  echo "MaxAuthTries 4"

  # Set MaxSessions to 10 or less
  echo "MaxSessions 10"

  # Set MaxStartups to 10:30:60 or more restrictive
  echo "MaxStartups 10:30:60"

  # Set PermitEmptyPasswords to no
  echo "PermitEmptyPasswords no"

  # Set PermitRootLogin to no
  echo "PermitRootLogin no"

  # Set PermitUserEnvironment to no
  echo "PermitUserEnvironment no"

  # Set UsePAM to yes
  echo "UsePAM yes"

} >> /etc/ssh/sshd_config

# Restart SSH service to apply changes
systemctl restart sshd

echo "Changes applied successfully."

#!/bin/bash

# Define the sudoers file path (it could be /etc/sudoers or a file in /etc/sudoers.d/)
SUDOERS_FILE="/etc/sudoers"

# Use visudo to safely edit the sudoers file with the following changes:

# Add Defaults use_pty
echo "Adding Defaults use_pty..."
visudo -cf "$SUDOERS_FILE" && echo 'Defaults use_pty' | sudo tee -a "$SUDOERS_FILE" > /dev/null

# Add Defaults logfile="/var/log/sudo.log"
echo "Adding Defaults logfile=\"/var/log/sudo.log\"..."
visudo -cf "$SUDOERS_FILE" && echo 'Defaults logfile="/var/log/sudo.log"' | sudo tee -a "$SUDOERS_FILE" > /dev/null

# Check if timestamp_timeout is greater than 15 minutes and modify it
echo "Checking and modifying timestamp_timeout if needed..."
CURRENT_TIMEOUT=$(sudo grep -E '^Defaults.*timestamp_timeout=' "$SUDOERS_FILE" | awk -F'=' '{print $2}')
if [[ -n "$CURRENT_TIMEOUT" && "$CURRENT_TIMEOUT" -gt 15 ]]; then
  # If timestamp_timeout is larger than 15, update it to 15
  sudo sed -i 's/Defaults.*timestamp_timeout=[0-9]*/Defaults timestamp_timeout=15/' "$SUDOERS_FILE"
  echo "timestamp_timeout modified to 15 minutes."
else
  # If no timestamp_timeout entry, or it's already <= 15, ensure it's set correctly
  if [[ -z "$CURRENT_TIMEOUT" || "$CURRENT_TIMEOUT" -le 15 ]]; then
    echo "Defaults timestamp_timeout=15" | sudo tee -a "$SUDOERS_FILE" > /dev/null
    echo "timestamp_timeout set to 15 minutes."
  fi
fi

echo "Changes applied successfully."
#!/bin/bash

# Define group name
GROUP_NAME="sugroup"

# Step 1: Create an empty group for su command usage
if ! grep -q "^${GROUP_NAME}:" /etc/group; then
    echo "Creating group: ${GROUP_NAME}"
    groupadd $GROUP_NAME
else
    echo "Group ${GROUP_NAME} already exists."
fi

# Step 2: Modify /etc/pam.d/su to restrict access to users in ${GROUP_NAME}
PAM_FILE="/etc/pam.d/su"
if ! grep -q "auth required pam_wheel.so use_uid group=${GROUP_NAME}" $PAM_FILE; then
    echo "Configuring /etc/pam.d/su to restrict access to group ${GROUP_NAME}"
    # Make a backup of the original PAM configuration file
    cp $PAM_FILE $PAM_FILE.bak

    # Add the line to the PAM file
    sed -i '/^auth.*pam_wheel.so/ a auth required pam_wheel.so use_uid group='${GROUP_NAME}'' $PAM_FILE
else
    echo "PAM configuration already restricted to group ${GROUP_NAME}."
fi

# Step 3: Ensure the group is empty (no users assigned)
if [ -z "$(grep ${GROUP_NAME} /etc/group | cut -d: -f4)" ]; then
    echo "The group ${GROUP_NAME} is empty."
else
    echo "WARNING: The group ${GROUP_NAME} is not empty. Please ensure no users are added to this group."
fi

# Final message
echo "Access to the 'su' command is now restricted to users in the group ${GROUP_NAME}."

sudo apt upgrade -y libpam-runtime

apt upgrade -y libpam-modules
apt install -y libpam-pwquality
pam-auth-update --enable unix


#!/bin/bash

echo "Starting CIS Ubuntu 22.04 LTS Benchmark Extended Configuration..."

# Basic variables for paths
PWQUALITY_CONF_DIR="/etc/security/pwquality.conf.d"
FAILLOCK_CONF="/etc/security/faillock.conf"
PAM_CONFIGS="/usr/share/pam-configs"

# Ensure pam_unix is enabled for account, session, auth, and password
echo "Enabling pam_unix..."
pam-auth-update --enable unix

# --- Section 1: User Authentication and Lockout Policies ---

# Configure and enable pam_faillock for account lockout
echo "Configuring pam_faillock for lockout policies..."
{
    printf "Name: Enable pam_faillock to deny access\n"
    printf "Default: yes\n"
    printf "Priority: 0\n"
    printf "Auth-Type: Primary\n"
    printf "Auth: [default=die] pam_faillock.so authfail\n"
} > $PAM_CONFIGS/faillock

{
    printf "Name: Notify of failed login attempts and reset count upon success\n"
    printf "Default: yes\n"
    printf "Priority: 1024\n"
    printf "Auth-Type: Primary\n"
    printf "Auth: requisite pam_faillock.so preauth\n"
    printf "Account-Type: Primary\n"
    printf "Account: required pam_faillock.so\n"
} > $PAM_CONFIGS/faillock_notify

pam-auth-update --enable faillock
pam-auth-update --enable faillock_notify

# Configure pam_pwquality for password quality enforcement
echo "Setting password quality requirements with pam_pwquality..."
mkdir -p $PWQUALITY_CONF_DIR
{
    printf "Name: Pwquality password strength checking\n"
    printf "Default: yes\n"
    printf "Priority: 1024\n"
    printf "Conflicts: cracklib\n"
    printf "Password-Type: Primary\n"
    printf "Password: requisite pam_pwquality.so retry=3 minlen=14 difok=2 dcredit=-1 ucredit=-1 lcredit=-1 ocredit=-1 maxrepeat=3 maxsequence=3 dictcheck=1 enforcing=1\n"
} > $PAM_CONFIGS/pwquality

pam-auth-update --enable pwquality

# Apply password policies in pwquality configuration files
echo "Configuring additional password policies in pwquality.conf..."
{
    printf "difok = 2\n"
    printf "minlen = 14\n"
    printf "dcredit = -1\n"
    printf "ucredit = -1\n"
    printf "lcredit = -1\n"
    printf "ocredit = -1\n"
    printf "maxrepeat = 3\n"
    printf "maxsequence = 3\n"
    printf "dictcheck = 1\n"
    printf "enforcing = 1\n"
} > $PWQUALITY_CONF_DIR/cis_pwquality.conf

# Ensure account lockout policies
echo "Setting lockout policies in faillock.conf..."
{
    printf "deny = 5\n"
    printf "unlock_time = 900\n"
    printf "even_deny_root\n"
    printf "root_unlock_time = 60\n"
} > $FAILLOCK_CONF

# --- Section 2: Network Configuration ---

# Disable IPv6 if not required
echo "Disabling IPv6..."
sysctl -w net.ipv6.conf.all.disable_ipv6=1
sysctl -w net.ipv6.conf.default.disable_ipv6=1
sysctl -w net.ipv6.conf.lo.disable_ipv6=1
echo "net.ipv6.conf.all.disable_ipv6 = 1" >> /etc/sysctl.conf
echo "net.ipv6.conf.default.disable_ipv6 = 1" >> /etc/sysctl.conf
echo "net.ipv6.conf.lo.disable_ipv6 = 1" >> /etc/sysctl.conf

# Set IP forwarding to be disabled
echo "Disabling IP forwarding..."
sysctl -w net.ipv4.ip_forward=0
echo "net.ipv4.ip_forward = 0" >> /etc/sysctl.conf

# Ensure TCP SYN Cookies are enabled to prevent SYN flood attacks
echo "Enabling TCP SYN Cookies..."
sysctl -w net.ipv4.tcp_syncookies=1
echo "net.ipv4.tcp_syncookies = 1" >> /etc/sysctl.conf

# --- Section 3: Auditing Configuration ---

# Install auditd if not already installed
echo "Installing and configuring auditd..."
apt-get install -y auditd audispd-plugins

# Configure audit rules
echo "Setting audit rules for login/logout events..."
echo "-w /var/log/lastlog -p wa -k logins" >> /etc/audit/rules.d/cis.rules
echo "-w /var/run/faillock/ -p wa -k faillock" >> /etc/audit/rules.d/cis.rules

# Configure audit rules for process execution
echo "-a always,exit -F arch=b64 -S execve -C uid!=euid -F euid=0 -k privilege_exec" >> /etc/audit/rules.d/cis.rules

# Apply audit rules
augenrules --load

# Enable auditd service
systemctl enable auditd
systemctl start auditd

# --- Section 4: Filesystem and Permission Settings ---

# Disable unused filesystem mounting
echo "Disabling mounting of USB storage devices..."
echo "install usb-storage /bin/true" > /etc/modprobe.d/disable-usb-storage.conf

# Ensure permissions on sensitive files
echo "Setting permissions for sensitive system files..."
chown root:root /etc/passwd /etc/shadow /etc/gshadow /etc/group
chmod 644 /etc/passwd
chmod 000 /etc/shadow
chmod 000 /etc/gshadow
chmod 644 /etc/group

# --- Section 5: SSH Configuration ---

echo "Configuring SSH settings for enhanced security..."
sed -i 's/^#PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
sed -i 's/^#Protocol.*/Protocol 2/' /etc/ssh/sshd_config
sed -i 's/^#LogLevel.*/LogLevel VERBOSE/' /etc/ssh/sshd_config
sed -i 's/^#MaxAuthTries.*/MaxAuthTries 4/' /etc/ssh/sshd_config
sed -i 's/^#IgnoreRhosts.*/IgnoreRhosts yes/' /etc/ssh/sshd_config
sed -i 's/^#HostbasedAuthentication.*/HostbasedAuthentication no/' /etc/ssh/sshd_config
sed -i 's/^#PermitEmptyPasswords.*/PermitEmptyPasswords no/' /etc/ssh/sshd_config
sed -i 's/^#PermitUserEnvironment.*/PermitUserEnvironment no/' /etc/ssh/sshd_config
sed -i 's/^#ClientAliveInterval.*/ClientAliveInterval 300/' /etc/ssh/sshd_config
sed -i 's/^#ClientAliveCountMax.*/ClientAliveCountMax 0/' /etc/ssh/sshd_config

# Restart SSH to apply changes
systemctl restart sshd

# --- Section 6: Password Policies ---

echo "Configuring additional password aging policies..."
{
    echo "PASS_MAX_DAYS 90"
    echo "PASS_MIN_DAYS 7"
    echo "PASS_WARN_AGE 14"
} >> /etc/login.defs

# Ensure inactive password lock
echo "Applying inactive password lock policy..."
useradd -D -f 30

# --- Section 7: System Updates and Firewall ---

# Enable automatic updates
echo "Enabling unattended upgrades..."
apt-get install -y unattended-upgrades
dpkg-reconfigure -plow unattended-upgrades

# Configure UFW (Uncomplicated Firewall)
echo "Setting up UFW..."
ufw default deny incoming
ufw default allow outgoing
ufw allow OpenSSH
ufw enable

echo "CIS Ubuntu 22.04 LTS Benchmark Extended Configuration Completed."
#!/bin/bash

echo "Starting Additional CIS Ubuntu 22.04 LTS Benchmark Configuration..."

# --- Section 1: System Logging Configuration ---

# Ensure rsyslog is installed
echo "Installing rsyslog..."
apt-get install -y rsyslog

# Configure rsyslog to capture important logs
echo "Configuring rsyslog for secure logging..."
{
    echo "*.emerg :omusrmsg:*"
    echo "auth,authpriv.* /var/log/auth.log"
    echo "*.*;auth,authpriv.none -/var/log/syslog"
    echo "daemon.* -/var/log/daemon.log"
    echo "kern.* -/var/log/kern.log"
    echo "user.* -/var/log/user.log"
} > /etc/rsyslog.d/50-default.conf

# Enable and start rsyslog service
systemctl enable rsyslog
systemctl start rsyslog

# --- Section 2: Configuring System Accounts ---

# Disable root login
echo "Disabling direct root login..."
passwd -l root

# Lock inactive user accounts
echo "Locking inactive accounts..."
useradd -D -f 30

# Set permissions on user directories
echo "Setting user directory permissions..."
chmod 750 /home/*

# --- Section 3: System Hardening ---

# Disable core dumps to prevent exposure of sensitive data
echo "Disabling core dumps..."
echo "* hard core 0" >> /etc/security/limits.conf
echo "fs.suid_dumpable = 0" >> /etc/sysctl.conf
sysctl -w fs.suid_dumpable=0

# Prevent IP spoofing
echo "Configuring IP spoofing protection..."
{
    echo "nospoof on"
} >> /etc/host.conf

# Secure shared memory
echo "Securing shared memory..."
echo "tmpfs /run/shm tmpfs defaults,noexec,nosuid 0 0" >> /etc/fstab
mount -o remount,noexec,nosuid /run/shm

# Restrict access to cron and at
echo "Restricting access to cron and at..."
echo "root" > /etc/cron.allow
chmod 600 /etc/cron.allow
rm -f /etc/cron.deny
rm -f /etc/at.deny

# Ensure only root can edit crontab
echo "Ensuring only root can edit crontab..."
chmod 600 /etc/crontab

# --- Section 4: File and Process Auditing ---

# Ensure system audit configurations are set
echo "Configuring additional audit rules..."
{
    echo "-a always,exit -F arch=b64 -S adjtimex -S settimeofday -S stime -k time-change"
    echo "-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change"
    echo "-w /etc/localtime -p wa -k time-change"
    echo "-w /etc/group -p wa -k identity"
    echo "-w /etc/passwd -p wa -k identity"
    echo "-w /etc/gshadow -p wa -k identity"
    echo "-w /etc/shadow -p wa -k identity"
    echo "-w /etc/security/opasswd -p wa -k identity"
} >> /etc/audit/rules.d/cis.rules

# Apply the audit rules
augenrules --load

# --- Section 5: System Security Settings ---

# Configure login banners
echo "Setting login banners for security notice..."
{
    echo "Authorized users only. All activity may be monitored and reported."
} > /etc/issue
echo "Authorized users only. All activity may be monitored and reported." > /etc/issue.net

# Set permissions for banner files
chmod 644 /etc/issue
chmod 644 /etc/issue.net

# Enable AppArmor for additional security
echo "Enabling AppArmor for process confinement..."
apt-get install -y apparmor apparmor-utils
systemctl enable apparmor
systemctl start apparmor

# Configure AppArmor to enforce security profiles
aa-enforce /etc/apparmor.d/*

# --- Section 6: File Integrity Checking ---



# --- Section 7: Kernel Hardening ---

# Enable ExecShield and address space randomization
echo "Enabling kernel protection mechanisms..."
echo "kernel.exec-shield = 1" >> /etc/sysctl.conf
echo "kernel.randomize_va_space = 2" >> /etc/sysctl.conf
sysctl -w kernel.exec-shield=1
sysctl -w kernel.randomize_va_space=2

# Restrict access to dmesg to prevent information leaks
echo "Restricting access to dmesg..."
sysctl -w kernel.dmesg_restrict=1
echo "kernel.dmesg_restrict = 1" >> /etc/sysctl.conf

# Apply sysctl changes
sysctl -p

echo "Additional CIS Ubuntu 22.04 LTS Benchmark Configuration Completed."
#!/bin/bash

echo "Starting Further Extended CIS Ubuntu 22.04 LTS Benchmark Configuration..."

# --- Section 1: Additional Service Hardening ---

# Disable unnecessary services
echo "Disabling unnecessary services..."
systemctl disable avahi-daemon
systemctl disable cups
systemctl disable bluetooth
systemctl disable nfs-kernel-server rpcbind
systemctl disable slapd
systemctl disable bind9
systemctl disable vsftpd
systemctl disable apache2
systemctl disable dovecot  #(2.1.8)
systemctl disable smbd nmbd
systemctl disable squid
systemctl disable snmpd

# --- Section 2: Log Retention and Management ---

# Configure logrotate to retain logs for 90 days
echo "Configuring log rotation for 90-day retention..."
sed -i 's/^rotate [0-9]*/rotate 12/' /etc/logrotate.conf
sed -i 's/^weekly/monthly/' /etc/logrotate.conf

# Configure journald for persistent storage and 90-day retention
echo "Configuring journald for persistent log storage..."
mkdir -p /var/log/journal
sed -i 's/^#Storage.*/Storage=persistent/' /etc/systemd/journald.conf
sed -i 's/^#SystemMaxUse=.*/SystemMaxUse=1G/' /etc/systemd/journald.conf
sed -i 's/^#SystemMaxFileSize=.*/SystemMaxFileSize=100M/' /etc/systemd/journald.conf
sed -i 's/^#MaxRetentionSec=.*/MaxRetentionSec=90d/' /etc/systemd/journald.conf
systemctl restart systemd-journald

# --- Section 3: Secure Boot Settings ---

# Ensure secure boot is enabled (requires system support and UEFI)
echo "Checking if Secure Boot is enabled..."
if [ -d /sys/firmware/efi ]; then
    if [ "$(mokutil --sb-state | grep 'SecureBoot enabled')" ]; then
        echo "Secure Boot is enabled."
    else
        echo "Secure Boot is not enabled. Enable it in BIOS/UEFI settings."
    fi
else
    echo "System does not support UEFI; skipping Secure Boot check."
fi

# --- Section 4: Kernel and Filesystem Security Settings ---

# Disable uncommon filesystems
echo "Disabling uncommon filesystems..."
for fs in cramfs freevxfs jffs2 hfs hfsplus squashfs udf; do
    echo "install $fs /bin/true" >> /etc/modprobe.d/CIS-uncommon-filesystems.conf
done

# Restrict core dumps for all users
echo "Disabling core dumps for all users..."
echo "* hard core 0" >> /etc/security/limits.conf
sysctl -w fs.suid_dumpable=0
echo "fs.suid_dumpable=0" >> /etc/sysctl.conf

# Restrict mounting of USB storage
echo "Restricting mounting of USB storage devices..."
echo "install usb-storage /bin/true" >> /etc/modprobe.d/usb-storage.conf

# Enable auditing for all successful and unsuccessful privileged commands
echo "Enabling auditing for all privileged commands..."
for file in $(find / -xdev \( -perm -4000 -o -perm -2000 \)); do
    echo "-a always,exit -F path=$file -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged" >> /etc/audit/rules.d/privileged.rules
done

# Reload auditd rules
augenrules --load

# --- Section 5: Network Security Settings ---

# Disable IPv6 if not required
echo "Disabling IPv6..."
sysctl -w net.ipv6.conf.all.disable_ipv6=1
sysctl -w net.ipv6.conf.default.disable_ipv6=1
echo "net.ipv6.conf.all.disable_ipv6 = 1" >> /etc/sysctl.conf
echo "net.ipv6.conf.default.disable_ipv6 = 1" >> /etc/sysctl.conf

# Enable reverse path filtering to protect against spoofed packets
echo "Enabling reverse path filtering..."
sysctl -w net.ipv4.conf.all.rp_filter=1
sysctl -w net.ipv4.conf.default.rp_filter=1
echo "net.ipv4.conf.all.rp_filter = 1" >> /etc/sysctl.conf
echo "net.ipv4.conf.default.rp_filter = 1" >> /etc/sysctl.conf

# Disable ICMP redirects to prevent route hijacking
echo "Disabling ICMP redirects..."
sysctl -w net.ipv4.conf.all.accept_redirects=0
sysctl -w net.ipv4.conf.default.accept_redirects=0
echo "net.ipv4.conf.all.accept_redirects = 0" >> /etc/sysctl.conf
echo "net.ipv4.conf.default.accept_redirects = 0" >> /etc/sysctl.conf

# Enable TCP SYN cookies to protect against SYN flood attacks
echo "Enabling TCP SYN cookies..."
sysctl -w net.ipv4.tcp_syncookies=1
echo "net.ipv4.tcp_syncookies = 1" >> /etc/sysctl.conf

# Apply sysctl configurations
sysctl -p

# --- Section 6: Additional User Restrictions and System Settings ---

# Disable guest account for login
echo "Disabling guest account in login settings..."
if [ -f /etc/lightdm/lightdm.conf ]; then
    echo "[Seat:*]" >> /etc/lightdm/lightdm.conf
    echo "allow-guest=false" >> /etc/lightdm/lightdm.conf
fi

# Lock non-root user accounts with UID 0
echo "Checking for non-root users with UID 0..."
for user in $(awk -F: '($3 == 0) {print $1}' /etc/passwd); do
    if [ "$user" != "root" ]; then
        echo "Locking user $user with UID 0..."
        passwd -l $user
    fi
done

# --- Section 7: Miscellaneous Security Hardening ---

# Enforce strong password expiration policies
echo "Setting password expiration policies..."
{
    echo "PASS_MAX_DAYS 90"
    echo "PASS_MIN_DAYS 7"
    echo "PASS_WARN_AGE 14"
} >> /etc/login.defs

# Enforce session timeout for SSH and TTY sessions
echo "Configuring SSH and TTY session timeouts..."
echo "export TMOUT=900" >> /etc/profile.d/cis_timeout.sh
echo "ClientAliveInterval 300" >> /etc/ssh/sshd_config
echo "ClientAliveCountMax 0" >> /etc/ssh/sshd_config
systemctl restart sshd

# Enable audit for session initiation
echo "Adding audit rule for session initiation..."
echo "-w /var/run/utmp -p wa -k session" >> /etc/audit/rules.d/session.rules
echo "-w /var/log/wtmp -p wa -k logins" >> /etc/audit/rules.d/logins.rules
echo "-w /var/log/btmp -p wa -k failed_logins" >> /etc/audit/rules.d/failed_logins.rules

# Reload audit rules
augenrules --load

echo "Further Extended CIS Ubuntu 22.04 LTS Benchmark Configuration Completed."
#!/bin/bash

echo "Starting Final Extension of CIS Ubuntu 22.04 LTS Benchmark Configuration..."

# --- Section 1: Advanced System Hardening ---

# Disable Prelink to prevent prelinked binaries (often unnecessary and a security risk)
echo "Disabling Prelink..."
apt-get remove -y prelink

# Remove xinetd, telnet, and rsh-client to prevent remote management services
echo "Removing insecure remote services (xinetd, telnet, rsh-client)..."
apt-get remove -y xinetd telnet rsh-client

# Ensure only root has access to the su command
echo "Restricting access to the 'su' command..."
dpkg-statoverride --update --add root sudo 4750 /bin/su

# Disable IPv6 Router Advertisements (RA) to prevent rogue RA attacks
echo "Disabling IPv6 Router Advertisements..."
sysctl -w net.ipv6.conf.all.accept_ra=0
sysctl -w net.ipv6.conf.default.accept_ra=0
echo "net.ipv6.conf.all.accept_ra = 0" >> /etc/sysctl.conf
echo "net.ipv6.conf.default.accept_ra = 0" >> /etc/sysctl.conf

# --- Section 2: Enhanced Logging and Auditing Policies ---

# Enable audit rules for changes to system date and time
echo "Enabling audit rules for time-change events..."
{
    echo "-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change"
    echo "-a always,exit -F arch=b32 -S adjtimex -S settimeofday -k time-change"
    echo "-a always,exit -F arch=b64 -S clock_settime -k time-change"
    echo "-a always,exit -F arch=b32 -S clock_settime -k time-change"
    echo "-w /etc/localtime -p wa -k time-change"
} >> /etc/audit/rules.d/time-change.rules

# Enable audit logging for user/group modifications
echo "Configuring audit rules for identity changes (user/group modifications)..."
{
    echo "-w /etc/group -p wa -k identity"
    echo "-w /etc/passwd -p wa -k identity"
    echo "-w /etc/gshadow -p wa -k identity"
    echo "-w /etc/shadow -p wa -k identity"
    echo "-w /etc/security/opasswd -p wa -k identity"
} >> /etc/audit/rules.d/identity.rules

# Enable audit rules for privileged command execution
echo "Enabling audit rules for privileged command executions..."
find / -xdev \( -perm -4000 -o -perm -2000 \) -type f | while read -r file; do
    echo "-a always,exit -F path=$file -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged" >> /etc/audit/rules.d/privileged.rules
done

# Apply audit rules
augenrules --load

# --- Section 3: User Account and Session Hardening ---

# Enforce session timeout for all users
echo "Enforcing session timeout for all users..."
echo "export TMOUT=600" >> /etc/profile.d/timeout.sh

# Set default umask for users
echo "Setting default umask for all users..."
echo "umask 027" >> /etc/profile.d/umask.sh

# Disable shell access for system accounts
echo "Disabling shell access for system accounts..."
for user in `awk -F: '($3 < 1000) {print $1}' /etc/passwd`; do
    if [ "$user" != "root" ]; then
        usermod -s /usr/sbin/nologin $user
    fi
done

# Restrict permissions on sensitive files and directories
echo "Restricting permissions on sensitive files and directories..."
chmod 600 /etc/ssh/sshd_config
chmod 600 /etc/rsyslog.conf
chmod 600 /etc/audit/audit.rules
chmod 640 /var/log/auth.log
chmod 640 /var/log/syslog

# --- Section 4: Additional Kernel Hardening ---

# Configure kernel parameters for enhanced security
echo "Configuring additional kernel parameters for security..."
sysctl -w net.ipv4.conf.all.accept_source_route=0
sysctl -w net.ipv4.conf.default.accept_source_route=0
echo "net.ipv4.conf.all.accept_source_route = 0" >> /etc/sysctl.conf
echo "net.ipv4.conf.default.accept_source_route = 0" >> /etc/sysctl.conf

sysctl -w net.ipv4.conf.all.send_redirects=0
sysctl -w net.ipv4.conf.default.send_redirects=0
echo "net.ipv4.conf.all.send_redirects = 0" >> /etc/sysctl.conf
echo "net.ipv4.conf.default.send_redirects = 0" >> /etc/sysctl.conf

# Prevent sysrq key-based debugging
echo "Disabling sysrq key-based debugging..."
sysctl -w kernel.sysrq=0
echo "kernel.sysrq = 0" >> /etc/sysctl.conf

# Apply kernel settings
sysctl -p

# --- Section 5: Advanced Network Security Settings ---

# Disable source-routed packets to prevent spoofing
echo "Disabling source-routed packets..."
sysctl -w net.ipv4.conf.all.accept_source_route=0
sysctl -w net.ipv4.conf.default.accept_source_route=0
echo "net.ipv4.conf.all.accept_source_route = 0" >> /etc/sysctl.conf
echo "net.ipv4.conf.default.accept_source_route = 0" >> /etc/sysctl.conf

# Enable packet forwarding logging to detect spoofed packets
echo "Enabling packet forwarding logging..."
sysctl -w net.ipv4.conf.all.log_martians=1
sysctl -w net.ipv4.conf.default.log_martians=1
echo "net.ipv4.conf.all.log_martians = 1" >> /etc/sysctl.conf
echo "net.ipv4.conf.default.log_martians = 1" >> /etc/sysctl.conf

# --- Section 6: System Maintenance and Monitoring ---

# Schedule regular updates
echo "Configuring unattended upgrades..."
apt-get install -y unattended-upgrades
dpkg-reconfigure -plow unattended-upgrades

# Configure system daily check for package updates
echo "Setting up daily check for system package updates..."
{
    echo "#!/bin/bash"
    echo "apt-get update && apt-get -s upgrade | grep -i 'not upgraded'"
} > /etc/cron.daily/package_updates
chmod +x /etc/cron.daily/package_updates

# Configure automatic cleanup of old kernels and packages
echo "Configuring automatic cleanup of old kernels and packages..."
{
    echo "APT::Periodic::AutocleanInterval \"7\";"
    echo "APT::Periodic::Unattended-Upgrade \"1\";"
} > /etc/apt/apt.conf.d/10periodic

# Ensure NTP synchronization for accurate system time
echo "Installing and configuring NTP..."
apt-get install -y chrony
systemctl enable chrony
systemctl start chrony

# --- Section 7: Additional File Integrity Monitoring ---

# Install and configure Tripwire for additional file integrity monitoring
echo "Installing Tripwire..."
apt-get install -y tripwire

# Initialize Tripwire database
echo "Initializing Tripwire database..."
tripwire --init

# Schedule daily Tripwire integrity check
echo "Scheduling daily Tripwire integrity check..."
{
    echo "0 6 * * * /usr/sbin/tripwire --check | /usr/bin/mail -s \"Tripwire Integrity Check\" root"
} > /etc/cron.daily/tripwire_check
chmod +x /etc/cron.daily/tripwire_check

echo "Final Extended CIS Ubuntu 22.04 LTS Benchmark Configuration Completed."


#!/bin/bash

echo "Starting CIS Benchmark 6.2: System Logging Configuration..."

# --- Section 6.2.1: Configure journald ---

# Configure journald to ensure persistent storage of logs and secure logging settings
echo "Configuring journald settings..."

# Ensure journald service is enabled and active
echo "Enabling and starting systemd-journald service..."
systemctl enable systemd-journald
systemctl start systemd-journald

# Configure journald settings in /etc/systemd/journald.conf
echo "Applying journald configurations..."
sed -i 's/^#*Storage=.*/Storage=persistent/' /etc/systemd/journald.conf
sed -i 's/^#*Compress=.*/Compress=yes/' /etc/systemd/journald.conf
sed -i 's/^#*SystemMaxUse=.*/SystemMaxUse=1G/' /etc/systemd/journald.conf
sed -i 's/^#*SystemMaxFileSize=.*/SystemMaxFileSize=200M/' /etc/systemd/journald.conf
sed -i 's/^#*MaxRetentionSec=.*/MaxRetentionSec=1month/' /etc/systemd/journald.conf
sed -i 's/^#*ForwardToSyslog=.*/ForwardToSyslog=no/' /etc/systemd/journald.conf

# Restart journald to apply changes
echo "Restarting journald to apply new settings..."
systemctl restart systemd-journald

# --- Section 6.2.2: Configure Logfiles ---

# Ensure access permissions are restricted for all log files
echo "Restricting access to log files in /var/log..."
find /var/log -type f -exec chmod 640 {} \;
find /var/log -type f -exec chown root:adm {} \;

# Set ownership and permissions for system logs and configuration files
echo "Setting ownership and permissions on key logging configuration files..."
chmod 640 /etc/systemd/journald.conf
chown root:root /etc/systemd/journald.conf
chmod 640 /var/log/syslog /var/log/auth.log
chown root:adm /var/log/syslog /var/log/auth.log

# Rotate logs by ensuring logrotate configuration is set for proper retention and compression
echo "Configuring log rotation with logrotate..."
{
    echo "/var/log/syslog {"
    echo "    daily"
    echo "    rotate 14"
    echo "    compress"
    echo "    delaycompress"
    echo "    missingok"
    echo "    notifempty"
    echo "    create 640 root adm"
    echo "}"
} > /etc/logrotate.d/syslog

echo "CIS Benchmark 6.2: System Logging Configuration completed."
#!/bin/bash

echo "Starting CIS Benchmark 6.3.1: Configure auditd Service..."

# --- Section 6.3.1.1: Ensure auditd packages are installed ---

# Install auditd if it is not already installed
echo "Checking if auditd is installed..."
if ! command -v auditctl > /dev/null; then
    echo "Installing auditd..."
    apt-get update -y && apt-get install -y auditd audispd-plugins
else
    echo "auditd is already installed."
fi

# --- Section 6.3.1.2: Ensure auditd service is enabled and active ---

# Enable and start auditd service to ensure it is running on startup
echo "Enabling and starting auditd service..."
systemctl enable auditd
systemctl start auditd

# Verify auditd service status
systemctl is-active --quiet auditd && echo "auditd service is running." || echo "Error: auditd service failed to start."

# --- Section 6.3.1.3: Ensure auditing for processes that start prior to auditd is enabled ---

# Modify GRUB to add 'audit=1' to enable auditing at boot for early processes
echo "Enabling auditing for processes that start prior to auditd..."
if ! grep -q "audit=1" /etc/default/grub; then
    sed -i 's/GRUB_CMDLINE_LINUX="/&audit=1 /' /etc/default/grub
    update-grub
    echo "Reboot required to apply audit=1 setting."
else
    echo "Audit parameter already set in GRUB."
fi

# --- Section 6.3.1.4: Ensure audit_backlog_limit is sufficient ---

# Set audit_backlog_limit to ensure the system can handle a high volume of audit messages
echo "Configuring audit_backlog_limit..."
if ! grep -q "audit_backlog_limit=" /etc/default/grub; then
    sed -i 's/GRUB_CMDLINE_LINUX="/&audit_backlog_limit=8192 /' /etc/default/grub
    update-grub
    echo "Reboot required to apply audit_backlog_limit setting."
else
    echo "audit_backlog_limit already set in GRUB."
fi

echo "CIS Benchmark 6.3.1: Configure auditd Service completed."
#!/bin/bash

echo "Starting CIS Benchmark 6.3.2: Configure Data Retention..."

# --- Section 6.3.2.1: Ensure audit log storage size is configured ---

# Set a maximum log file size of 100 MB and keep up to 10 rotated logs
echo "Configuring audit log storage size..."
sed -i 's/^max_log_file = .*/max_log_file = 100/' /etc/audit/auditd.conf
sed -i 's/^num_logs = .*/num_logs = 10/' /etc/audit/auditd.conf

# --- Section 6.3.2.2: Ensure audit logs are not automatically deleted ---

# Prevent automatic deletion of audit logs by disabling 'max_log_file_action'
echo "Disabling automatic audit log deletion..."
sed -i 's/^max_log_file_action = .*/max_log_file_action = keep_logs/' /etc/audit/auditd.conf

# --- Section 6.3.2.3: Ensure system is disabled when audit logs are full ---

# Set 'space_left_action' to 'email' and 'action_mail_acct' to root
echo "Configuring actions when disk space for logs is low..."
sed -i 's/^space_left_action = .*/space_left_action = email/' /etc/audit/auditd.conf
sed -i 's/^action_mail_acct = .*/action_mail_acct = root/' /etc/audit/auditd.conf

# Set 'admin_space_left_action' to halt the system when logs reach critical space
sed -i 's/^admin_space_left_action = .*/admin_space_left_action = halt/' /etc/audit/auditd.conf

# --- Section 6.3.2.4: Ensure system warns when audit logs are low on space ---

# Set thresholds for low space warnings at 75% capacity
echo "Setting low space warning threshold for audit logs..."
sed -i 's/^space_left = .*/space_left = 75/' /etc/audit/auditd.conf
sed -i 's/^admin_space_left = .*/admin_space_left = 50/' /etc/audit/auditd.conf

# Restart auditd to apply new configurations
echo "Restarting auditd to apply changes..."
systemctl restart auditd

echo "CIS Benchmark 6.3.2: Configure Data Retention completed."
#!/bin/bash

# 6.3.3.1 Ensure changes to system administration scope (sudoers) are collected
echo "-w /etc/sudoers -p wa -k scope" >> /etc/audit/rules.d/audit.rules

# 6.3.3.2 Ensure actions as another user are always logged
echo "-w /var/log/sudo.log -p wa -k actions" >> /etc/audit/rules.d/audit.rules

# 6.3.3.3 Ensure events that modify the sudo log file are collected
echo "-w /var/log/sudo.log -p wa -k sudo_log_modification" >> /etc/audit/rules.d/audit.rules

# 6.3.3.4 Ensure events that modify date and time information are collected
echo "-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change" >> /etc/audit/rules.d/audit.rules

# 6.3.3.5 Ensure events that modify the system’s network environment are collected
echo "-a always,exit -F arch=b64 -S sethostname -S setdomainname -k network_environment" >> /etc/audit/rules.d/audit.rules

# 6.3.3.6 Ensure use of privileged commands are collected
echo "-a always,exit -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged" >> /etc/audit/rules.d/audit.rules

# 6.3.3.7 Ensure unsuccessful file access attempts are collected
echo "-a always,exit -F arch=b64 -S open,openat,creat -F exit=-EACCES -k access" >> /etc/audit/rules.d/audit.rules
echo "-a always,exit -F arch=b64 -S open,openat,creat -F exit=-EPERM -k access" >> /etc/audit/rules.d/audit.rules

# 6.3.3.8 Ensure events that modify user/group information are collected
echo "-w /etc/group -p wa -k identity" >> /etc/audit/rules.d/audit.rules
echo "-w /etc/passwd -p wa -k identity" >> /etc/audit/rules.d/audit.rules
echo "-w /etc/gshadow -p wa -k identity" >> /etc/audit/rules.d/audit.rules

# 6.3.3.9 Ensure discretionary access control permission modification events are collected
echo "-a always,exit -F arch=b64 -S chmod,chown,fchmod,fchmodat -k permission_modification" >> /etc/audit/rules.d/audit.rules

# 6.3.3.10 Ensure successful file system mounts are collected
echo "-a always,exit -F arch=b64 -S mount -k mounts" >> /etc/audit/rules.d/audit.rules

# 6.3.3.11 Ensure session initiation information is collected
echo "-w /var/run/utmp -p wa -k session" >> /etc/audit/rules.d/audit.rules
echo "-w /var/log/wtmp -p wa -k session" >> /etc/audit/rules.d/audit.rules
echo "-w /var/log/btmp -p wa -k session" >> /etc/audit/rules.d/audit.rules

# 6.3.3.12 Ensure login and logout events are collected
echo "-w /var/log/faillog -p wa -k logins" >> /etc/audit/rules.d/audit.rules
echo "-w /var/log/lastlog -p wa -k logins" >> /etc/audit/rules.d/audit.rules

# 6.3.3.13 Ensure file deletion events by users are collected
echo "-a always,exit -F arch=b64 -S unlink,unlinkat -k delete" >> /etc/audit/rules.d/audit.rules

# 6.3.3.14 Ensure events that modify the system’s Mandatory Access Controls are collected
echo "-w /etc/selinux/ -p wa -k MAC-policy" >> /etc/audit/rules.d/audit.rules

# 6.3.3.15 Ensure successful and unsuccessful attempts to use the chcon command are recorded
echo "-a always,exit -F arch=b64 -S chcon -k chcon" >> /etc/audit/rules.d/audit.rules

# 6.3.3.16 Ensure successful and unsuccessful attempts to use the setfacl command are recorded
echo "-a always,exit -F arch=b64 -S setfacl -k setfacl" >> /etc/audit/rules.d/audit.rules

# 6.3.3.17 Ensure successful and unsuccessful attempts to use the chacl command are recorded
echo "-a always,exit -F arch=b64 -S chacl -k chacl" >> /etc/audit/rules.d/audit.rules

# 6.3.3.18 Ensure successful and unsuccessful attempts to use the usermod command are recorded
echo "-a always,exit -F arch=b64 -S usermod -k usermod" >> /etc/audit/rules.d/audit.rules

# 6.3.3.19 Ensure kernel module loading, unloading, and modification is collected
echo "-w /sbin/insmod -p x -k module-change" >> /etc/audit/rules.d/audit.rules
echo "-w /sbin/rmmod -p x -k module-change" >> /etc/audit/rules.d/audit.rules
echo "-w /sbin/modprobe -p x -k module-change" >> /etc/audit/rules.d/audit.rules

# 6.3.3.20 Ensure the audit configuration is immutable
echo "-e 2" >> /etc/audit/rules.d/audit.rules

# 6.3.3.21 Ensure the running and on-disk configuration is the same
auditctl -l | diff - /etc/audit/audit.rules
#!/bin/bash

# 6.3.4.1 Ensure audit log files mode is configured
chmod 0640 /var/log/audit/*

# 6.3.4.2 Ensure audit log files owner is configured
chown root /var/log/audit/*

# 6.3.4.3 Ensure audit log files group owner is configured
chgrp root /var/log/audit/*

# 6.3.4.4 Ensure the audit log file directory mode is configured
chmod 0750 /var/log/audit

# 6.3.4.5 Ensure audit configuration files mode is configured
chmod 0640 /etc/audit/auditd.conf
chmod 0640 /etc/audit/rules.d/*.rules

# 6.3.4.6 Ensure audit configuration files owner is configured
chown root /etc/audit/auditd.conf
chown root /etc/audit/rules.d/*.rules

# 6.3.4.7 Ensure audit configuration files group owner is configured
chgrp root /etc/audit/auditd.conf
chgrp root /etc/audit/rules.d/*.rules

# 6.3.4.8 Ensure audit tools mode is configured
chmod 0755 /sbin/auditctl
chmod 0755 /sbin/audispd

# 6.3.4.9 Ensure audit tools owner is configured
chown root /sbin/auditctl
chown root /sbin/audispd

# 6.3.4.10 Ensure audit tools group owner is configured
chgrp root /sbin/auditctl
chgrp root /sbin/audispd
#!/bin/bash

# 7.1.1 Ensure permissions on /etc/passwd are configured
chmod 644 /etc/passwd
chown root:root /etc/passwd

# 7.1.2 Ensure permissions on /etc/passwd- are configured
chmod 600 /etc/passwd-
chown root:root /etc/passwd-

# 7.1.3 Ensure permissions on /etc/group are configured
chmod 644 /etc/group
chown root:root /etc/group

# 7.1.4 Ensure permissions on /etc/group- are configured
chmod 600 /etc/group-
chown root:root /etc/group-

# 7.1.5 Ensure permissions on /etc/shadow are configured
chmod 640 /etc/shadow
chown root:shadow /etc/shadow

# 7.1.6 Ensure permissions on /etc/shadow- are configured
chmod 600 /etc/shadow-
chown root:shadow /etc/shadow-

# 7.1.7 Ensure permissions on /etc/gshadow are configured
chmod 640 /etc/gshadow
chown root:shadow /etc/gshadow

# 7.1.8 Ensure permissions on /etc/gshadow- are configured
chmod 600 /etc/gshadow-
chown root:shadow /etc/gshadow-

# 7.1.9 Ensure permissions on /etc/shells are configured
chmod 644 /etc/shells
chown root:root /etc/shells

# 7.1.10 Ensure permissions on /etc/security/opasswd are configured
chmod 600 /etc/security/opasswd
chown root:root /etc/security/opasswd

# 7.1.11 Ensure world writable files and directories are secured
find / -xdev -type f -perm -002 -exec chmod o-w {} \;
find / -xdev -type d -perm -002 -exec chmod o-w {} \;

# 7.1.12 Ensure no files or directories without an owner and a group exist
find / -xdev \( -nouser -o -nogroup \) -exec chown root:root {} \;

# 7.1.13 Ensure SUID and SGID files are reviewed (Manual Step)
echo "Reviewing SUID and SGID files"
find / -xdev \( -perm -4000 -o -perm -2000 \) -type f
#!/bin/bash

# Function to check and set permissions for specific files
check_permissions() {
    local file=$1
    local perms=$2
    local owner=$3
    local group=$4

    # Check current permissions
    current_perms=$(stat -c "%a" "$file" 2>/dev/null)
    current_owner=$(stat -c "%U" "$file" 2>/dev/null)
    current_group=$(stat -c "%G" "$file" 2>/dev/null)

    # Set permissions if they don't match the required ones
    if [[ "$current_perms" != "$perms" ]]; then
        chmod "$perms" "$file" && echo "Set permissions $perms on $file"
    fi
    if [[ "$current_owner" != "$owner" ]]; then
        chown "$owner" "$file" && echo "Set owner $owner on $file"
    fi
    if [[ "$current_group" != "$group" ]]; then
        chgrp "$group" "$file" && echo "Set group $group on $file"
    fi
}

# 7.1.x - Ensure permissions on key system files
check_permissions "/etc/passwd" 644 root root
check_permissions "/etc/passwd-" 644 root root
check_permissions "/etc/group" 644 root root
check_permissions "/etc/group-" 644 root root
check_permissions "/etc/shadow" 640 root shadow
check_permissions "/etc/shadow-" 640 root shadow
check_permissions "/etc/gshadow" 640 root shadow
check_permissions "/etc/gshadow-" 640 root shadow
check_permissions "/etc/shells" 644 root root
check_permissions "/etc/security/opasswd" 600 root root

# 7.1.11 - Secure world-writable files and directories
echo "Securing world-writable files and directories..."
find / -xdev -type f -perm -0002 ! -path "/proc/*" ! -path "/sys/*" ! -path "/run/*" ! -path "/dev/*" -exec chmod o-w {} \; -print
find / -xdev -type d -perm -0002 ! -path "/proc/*" ! -path "/sys/*" ! -path "/run/*" ! -path "/dev/*" -exec chmod o-w {} \; -print

# 7.1.12 - Remove files and directories without an owner or group
echo "Removing files and directories without an owner or group..."
find / -xdev \( -nouser -o -nogroup \) -exec rm -rf {} \; -print

# 7.1.13 - Review SUID and SGID files
echo "Listing SUID and SGID files for review..."
find / -xdev \( -perm -4000 -o -perm -2000 \) -type f -exec ls -l {} \;
#!/bin/bash

# Function to print status messages
print_status() {
    echo "Checking $1..."
}

# 7.2.1 Ensure accounts in /etc/passwd use shadowed passwords
print_status "Accounts in /etc/passwd using shadowed passwords"
awk -F: '($2 != "x") { print "User \"" $1 "\" is not using shadowed passwords" }' /etc/passwd
pwconv  # Migrate passwords to shadow if needed

# 7.2.2 Ensure /etc/shadow password fields are not empty
print_status "/etc/shadow password fields are not empty"
awk -F: '($2 == "" ) { print "User \"" $1 "\" has an empty password field in /etc/shadow" }' /etc/shadow

# 7.2.3 Ensure all groups in /etc/passwd exist in /etc/group
print_status "All groups in /etc/passwd exist in /etc/group"
for group in $(cut -s -d: -f4 /etc/passwd | sort -u); do
    if ! grep -q -P "^.*?:x?:${group}:" /etc/group; then
        echo "Group ID $group referenced by /etc/passwd not found in /etc/group"
    fi
done

# 7.2.4 Ensure shadow group is empty
print_status "Shadow group is empty"
if [ "$(awk -F: '/^shadow/ { print $4 }' /etc/group)" ]; then
    echo "Shadow group is not empty"
else
    echo "Shadow group is empty"
fi

# 7.2.5 Ensure no duplicate UIDs exist
print_status "No duplicate UIDs"
cut -d: -f3 /etc/passwd | sort | uniq -d | while read -r uid; do
    echo "Duplicate UID $uid found"
done

# 7.2.6 Ensure no duplicate GIDs exist
print_status "No duplicate GIDs"
cut -d: -f3 /etc/group | sort | uniq -d | while read -r gid; do
    echo "Duplicate GID $gid found"
done

# 7.2.7 Ensure no duplicate usernames exist
print_status "No duplicate usernames"
cut -d: -f1 /etc/passwd | sort | uniq -d | while read -r user; do
    echo "Duplicate username $user found"
done

# 7.2.8 Ensure no duplicate group names exist
print_status "No duplicate group names"
cut -d: -f1 /etc/group | sort | uniq -d | while read -r group; do
    echo "Duplicate group name $group found"
done

# 7.2.9 Ensure local interactive user home directories are configured
print_status "Local interactive user home directories are configured"
awk -F: '($3 >= 1000 && $7 !~ /nologin|false/) { print $1 " " $6 }' /etc/passwd | while read -r user dir; do
    if [ ! -d "$dir" ]; then
        echo "User \"$user\" has no home directory \"$dir\""
    fi
    if [ ! -O "$dir" ]; then
        echo "User \"$user\" does not own home directory \"$dir\""
    fi
    dir_perms=$(stat -L -c "%A" "$dir")
    if [[ "$dir_perms" != drwx------ ]]; then
        echo "User \"$user\" home directory \"$dir\" permissions are not secure: $dir_perms"
    fi
done

# 7.2.10 Ensure local interactive user dot files access is configured
print_status "Local interactive user dot files access is configured"
for home_dir in $(awk -F: '($3 >= 1000 && $7 !~ /nologin|false/) { print $6 }' /etc/passwd); do
    if [ -d "$home_dir" ]; then
        for file in "$home_dir"/.[A-Za-z0-9]*; do
            if [ -f "$file" ]; then
                file_perms=$(stat -L -c "%A" "$file")
                if [[ "$file_perms" != "-rw-------" && "$file_perms" != "-rw-r--r--" ]]; then
                    echo "File \"$file\" in \"$home_dir\" has permissions \"$file_perms\""
                fi
            fi
        done
    fi
done
#!/bin/bash

# Function to print status messages
print_status() {
    echo "Checking $1..."
}

# 5.4.1 Configure Shadow Password Suite Parameters
# 5.4.1.1 Ensure password expiration is configured
print_status "Password expiration settings"
sed -i '/^PASS_MAX_DAYS/d' /etc/login.defs
echo "PASS_MAX_DAYS 365" >> /etc/login.defs

# 5.4.1.2 Ensure minimum password age is configured
sed -i '/^PASS_MIN_DAYS/d' /etc/login.defs
echo "PASS_MIN_DAYS 7" >> /etc/login.defs

# 5.4.1.3 Ensure password expiration warning days is configured
sed -i '/^PASS_WARN_AGE/d' /etc/login.defs
echo "PASS_WARN_AGE 7" >> /etc/login.defs

# 5.4.1.4 Ensure strong password hashing algorithm is configured
print_status "Strong password hashing algorithm configuration"
if ! grep -q "ENCRYPT_METHOD SHA512" /etc/login.defs; then
    echo "ENCRYPT_METHOD SHA512" >> /etc/login.defs
fi

# 5.4.1.5 Ensure inactive password lock is configured
print_status "Inactive password lock configuration"
useradd -D -f 30

# 5.4.1.6 Ensure all users last password change date is in the past
print_status "Ensuring all users' last password change is in the past"
while IFS=: read -r username _; do
    last_change_date=$(chage --list "$username" | grep '^Last password change' | cut -d: -f2)
    if [ "$last_change_date" == "never" ]; then
        echo "User $username has never changed their password."
    fi
done < <(getent passwd | awk -F: '($3 >= 1000 && $3 < 65534) { print $1 }')

# 5.4.2 Configure Root and System Accounts and Environment
# 5.4.2.1 Ensure root is the only UID 0 account
print_status "Ensuring root is the only UID 0 account"
awk -F: '($3 == 0) {print $1}' /etc/passwd | grep -vx "root" && echo "Non-root UID 0 accounts found."

# 5.4.2.2 Ensure root is the only GID 0 account
print_status "Ensuring root is the only GID 0 account"
awk -F: '($4 == 0) {print $1}' /etc/passwd | grep -vx "root" && echo "Non-root GID 0 accounts found."

# 5.4.2.3 Ensure group root is the only GID 0 group
print_status "Ensuring group root is the only GID 0 group"
awk -F: '($3 == 0) {print $1}' /etc/group | grep -vx "root" && echo "Non-root GID 0 groups found."

# 5.4.2.4 Ensure root password is set
print_status "Ensuring root password is set"
passwd -S root | grep -q "NP" && echo "Root password is not set."

# 5.4.2.5 Ensure root path integrity
print_status "Ensuring root PATH integrity"
IFS=: read -ra PATHS <<<"$PATH"
for path in "${PATHS[@]}"; do
    if [ "$path" == "" ] || [ ! -d "$path" ] || [[ "$path" != /* ]]; then
        echo "Path $path is not secure or absolute in root's PATH."
    fi
done

# 5.4.2.6 Ensure root user umask is configured
print_status "Configuring root user umask"
echo "umask 077" >> /root/.bashrc

# 5.4.2.7 Ensure system accounts do not have a valid login shell
print_status "Ensuring system accounts do not have valid login shells"
awk -F: '($3 < 1000) {print $1}' /etc/passwd | while read -r user; do
    if [ "$(getent passwd "$user" | cut -d: -f7)" != "/usr/sbin/nologin" ]; then
        usermod -s /usr/sbin/nologin "$user"
    fi
done

# 5.4.2.8 Ensure accounts without a valid login shell are locked
print_status "Ensuring accounts without a valid login shell are locked"
awk -F: '($3 >= 1000 && $7 == "/usr/sbin/nologin") {print $1}' /etc/passwd | while read -r user; do
    usermod -L "$user"
done

# 5.4.3 Configure User Default Environment
# 5.4.3.1 Ensure nologin is not listed in /etc/shells
print_status "Checking for nologin in /etc/shells"
sed -i '/\/nologin/d' /etc/shells

# 5.4.3.2 Ensure default user shell timeout is configured
print_status "Configuring default user shell timeout"
echo "readonly TMOUT=600" >> /etc/profile.d/tmout.sh
echo "export TMOUT" >> /etc/profile.d/tmout.sh

# 5.4.3.3 Ensure default user umask is configured
print_status "Configuring default user umask"
echo "umask 027" >> /etc/profile
