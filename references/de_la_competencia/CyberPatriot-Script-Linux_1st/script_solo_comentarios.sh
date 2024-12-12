#!/usr/bin/env bash
            
            # set module name
                 # set module type
 # If the module is currently loadable, add "install {MODULE_NAME} /bin/false" to a file in
 # If the module is currently loaded, unload the module
 # If the module isn't deny listed, denylist the module
 # Check if the module exists on the system
                    # set module name
                # set module type
 # If the module is currently loadable, add "install {MODULE_NAME} /bin/false" to a file in
 # If the module is currently loaded, unload the module
 # If the module isn't deny listed, denylist the module
 # Check if the module exists on the system
                     # set module name
                 # set module type
 # If the module is currently loadable, add "install {MODULE_NAME} /bin/false" to a file in
 # If the module is currently loaded, unload the module
 # If the module isn't deny listed, denylist the module
 # Check if the module exists on the system
                 # set module name
                # set module type
 # If the module is currently loadable, add "install {MODULE_NAME} /bin/false" to a file in
 # If the module is currently loaded, unload the module
 # If the module isn't deny listed, denylist the module
 # Check if the module exists on the system

             # set module name
                # set module type
 # If the module is currently loadable, add "install {MODULE_NAME} /bin/false" to a file in
 # If the module is currently loaded, unload the module
 # If the module isn't deny listed, denylist the module
 # Check if the module exists on the system
            # set module name
            # set module type
 # If the module is currently loadable, add "install {MODULE_NAME} /bin/false" to a file in
 # If the module is currently loaded, unload the module
 # If the module isn't deny listed, denylist the module
 # Check if the module exists on the system
            # set module name
            # set module type
 # If the module is currently loadable, add "install {MODULE_NAME} /bin/false" to a file in
 # If the module is currently loaded, unload the module
 # If the module isn't deny listed, denylist the module
 # Check if the module exists on the system
                        # set module name
                     # set module type
 # If the module is currently loadable, add "install {MODULE_NAME} /bin/false" to a file in
 # If the module is currently loaded, unload the module
 # If the module isn't deny listed, denylist the module
 # Check if the module exists on the system

# Function to check if systemd is correctly configured

# Function to unmask and enable tmp.mount if needed
    
    # Unmask tmp.mount if it's masked
    
    # Enable tmp.mount


# Main function to perform the audit and remediation

#!/bin/bash

# Function to check if AppArmor is installed

    # Check if AppArmor package is installed

    # Check if apparmor-utils package is installed

# Function to install AppArmor

# Function to install apparmor-utils

# Main function to perform the audit and remediation

#!/bin/bash

# Function to check if AppArmor boot parameters are set in grub.cfg

    # Check if apparmor=1 is present in the bootloader configuration

    # Check if security=apparmor is present in the bootloader configuration

# Function to enable AppArmor in the bootloader configuration

    # Edit the GRUB_CMDLINE_LINUX line in /etc/default/grub to include apparmor=1 and security=apparmor

    # Update GRUB configuration

# Main function to check and ensure AppArmor is enabled at boot time
#!/bin/bash

# Function to audit AppArmor profiles status

    # Check if AppArmor profiles are loaded and in enforce or complain mode

    # Ensure profiles are in either enforce or complain mode

    # Check for unconfined processes

    # Output profile status for auditing

    # If there are unconfined processes, print a message to take action

    # Ensure there are no unconfined profiles (if any, need to create or activate)

    # If all profiles are in enforce or complain mode and no unconfined processes, proceed with remediation

# Function to remediate by setting all profiles to enforce mode

    # Set all AppArmor profiles to enforce mode

    # Verify after remediation

# Function to remediate by setting all profiles to complain mode

    # Set all AppArmor profiles to complain mode

    # Verify after remediation

# Main function to perform audit and remediation

# Optionally remediate by setting profiles to enforce mode

# Or set all profiles to complain mode instead (comment the above line to use this)
# set_profiles_to_complain

#!/bin/bash

# Function to audit AppArmor profiles status

    # Check if AppArmor profiles are loaded and verify they are in enforce mode

    # Count profiles in enforce mode and complain mode

    # Check for unconfined processes

    # Output profile status for auditing

    # If there are unconfined processes, print a message to take action

    # Ensure there are no unconfined processes (if any, need to create or activate profiles)

    # Check if all profiles are in enforce mode

# Function to remediate by setting all profiles to enforce mode

    # Set all AppArmor profiles to enforce mode

    # Verify after remediation

# Function to verify no unconfined processes are running
    


# Main function to perform audit and remediation

# Remediate by setting all profiles to enforce mode if needed

# Verify there are no unconfined processes

#!/bin/bash

#!/bin/bash

# Define the GRUB configuration file path

# Check if the GRUB configuration file exists
 
 

# Audit the current ownership and permissions of the GRUB configuration file


# Check if the ownership is correct (root:root)

# Check if the permissions are correct (0600)

# Verify the changes
#!/bin/bash

# Define the sysctl configuration file

# Check if the configuration already exists

# Apply the setting immediately

# Verify the setting
#!/bin/bash

# Define the sysctl configuration file

# Check if the configuration already exists

# Apply the setting immediately

# Verify the setting
#!/bin/bash

# Step 1: Set hard limit for core dumps

# Step 2: Set fs.suid_dumpable to 0

# Step 3: Verify the system limits

# Step 4: Check if systemd-coredump is installed and disable if necessary

# Final verification
#!/bin/bash

# Check if prelink is installed

    # Restore binaries to their normal state

    # Uninstall prelink

    # Verify prelink is no longer installed
#!/bin/bash

# Check if Apport is installed and enabled

    # Check if Apport is enabled

        # Disable Apport by modifying the /etc/default/apport file

        # Stop the Apport service

        # Mask the Apport service to prevent it from starting on boot

        # Verify that Apport is now disabled

    # Optionally, remove the Apport package (uncomment to use)
    # sudo apt purge -y apport
    # echo "Removed Apport package from the system."
#!/bin/bash

# Check if gdm3 is installed

    # Uninstall gdm3

    # Remove unused dependencies

# Optionally, prevent future installation of gdm3
# sudo apt-mark hold gdm3
#!/usr/bin/env bash



                        # Space-separated list of packages to check


                        # Set this to desired profile name

        # Create profile if it doesn't exist
        
        # Create dconf database directory if it doesn't exist
        
        # Enable the banner message
        
        # Set the banner message text

        # Update the dconf database
#!/usr/bin/env bash

                    # Change this profile name if desired (according to local policy)
    
    # Create the profile if it doesn't exist

    # Create the dconf database directory if it doesn't exist

    # Check if the 'disable-user-list' setting is already in place, otherwise add it
        
            # Append the setting if the section exists
    
    # Update the dconf database to apply changes

#!/usr/bin/env bash
    # Set lock-delay to 5 seconds and idle-delay to 900 seconds

    # Create or edit the user profile in /etc/dconf/profile/
                        # Replace with appropriate profile name if different

    # Create the dconf database directory if it doesn't exist

    # Create the key file /etc/dconf/db/local.d/00-screensaver

    # Update dconf settings
#!/usr/bin/env bash
    # Create the locks directory if it doesn't exist

    # Create the screensaver lockdown file

    # Update the system databases
#!/usr/bin/env bash

                    # Set to desired dconf profile name (default is local)

    # Check if GNOME Desktop Manager is installed. If package isn't installed, recommendation is Not Applicable


    # Check if GDM is installed
                    # Space-separated list of packages to check

    # Check configuration (If applicable)
        
        # Look for existing settings and set variables if they exist

        # Set profile name based on dconf db directory ({PROFILE_NAME}.d)

        # check for consistency (Clean up configuration if needed)


        # Check if profile file exists

        # create dconf directory if it doesn't exist
        # check automount-open setting

        # check automount setting

        # update dconf database

#!/usr/bin/env bash

                    # Set to desired dconf profile name (default is local)

    # Check if GNOME Desktop Manager is installed.
    
    # Space-separated list of packages to check

    # Check configuration (If applicable)
        
        # Look for existing settings and set variables if they exist

        # Set profile name based on dconf db directory ({PROFILE_NAME}.d)

        # Check for consistency (Clean up configuration if needed)


        # Create dconf directory if it doesn't exist

        # Check automount-open setting

        # Check automount setting

        # Update dconf database
#!/usr/bin/env bash
 # Check if GNOME Desktop Manager is installed. If package isn't
 
 # determine system's package manager
 
 # Check if GDM is installed
                # Space separated list of packages to check
 # Check configuration (If applicable)
 # Look for existing settings and set variables if they exist
 # Set profile name based on dconf db directory ({PROFILE_NAME}.d)
 # If the profile name exist, continue checks
 # Check if profile file exists
 # Check if the dconf database file exists
 # check if the dconf database directory exists
 # check autorun-never setting
 # Settings don't exist. Nothing further to check
 # Report results. If no failures output in l_output2, we pass
#!/usr/bin/env bash
 # Check if GNOME Desktop Manager is installed. If package isn't
 # determine system's package manager
 # Check if GDM is installed
                 # Space separated list of packages to check
 # Search /etc/dconf/db/ for [org/gnome/desktop/media-handling] settings)
 # Check for auto-run setting
 # Report results. If no failures output in l_output2, we pass
#!/usr/bin/env bash
    # List of configuration files to check

    # Loop through each file returned by the audit
        

#!/bin/bash

# Ensure the script is run with superuser privileges

# 2.1.1 Ensure autofs services are not in use

# 2.1.2 Ensure avahi daemon services are not in use

# 2.1.3 Ensure dhcp server services are not in use

# 2.1.4 Ensure dns server services are not in use

# 2.1.5 Ensure dsnmasq services are not in use

# 2.1.6 Ensure ftp server services are not in use

# 2.1.7 Ensure ldap server services are not in use

# 2.1.8 Ensure nfs server services are not in use

# 2.1.9 Ensure rpcbind services are not in use

# 2.1.10 Ensure samba file server services are not in use

# 2.1.11 Ensure rsync server services are not in use

# 2.1.12 Ensure snmp services are not in use

# 2.1.13 Ensure tftp server services are not in use

# 2.1.14 Ensure web server services are not in use

# 2.1.15 Ensure xinetd services are not in use

# 2.1.16 Ensure X window server services are not in use

# 2.1.17 Ensure mail transfer agent is configured for local-only mode
# Configuring postfix to only listen on the loopback interface (localhost)

#!/usr/bin/env bash

# Check if system is physical or virtual with host-based time sync
    

# Check if chrony or systemd-timesyncd is installed and active


# Verification

#!/usr/bin/env bash

# Ensure that only one time synchronization daemon is in use

  

# Install and enable systemd-timesyncd if not already active

# Configure systemd-timesyncd

# Apply custom configuration


# Restart systemd-timesyncd to apply changes

# Verification
#!/usr/bin/env bash

# Define the authorized time servers

# Create the drop-in directory if it doesn't exist

# Write the authorized NTP servers to a drop-in configuration file


# Restart systemd-timesyncd to apply the changes

# Verification

#!/usr/bin/env bash

# Define the authorized NTP servers

# Define the chrony configuration file path

# Ensure chrony sources directory exists

# Add authorized servers to a sources file

# Ensure 'sourcedir' directive is in the main chrony.conf file

# Restart chronyd to apply changes

# Verification
#!/usr/bin/env bash

# Define chrony configuration path

# Check if chronyd is running as _chrony

    # Ensure the chrony configuration directory exists

    # Configure chronyd to run as _chrony user

    # Restart chronyd to apply the user configuration

    # Verify if chronyd is now running as _chrony
#!/usr/bin/env bash

# Check if chrony service is installed and in use

    # Check if chrony service is enabled

    # Check if chrony service is active

#!/usr/bin/env bash

# Check if cron is installed and enabled


    # Check if cron service is enabled

    # Check if cron service is active

#!/usr/bin/env bash

# Path to the cron.monthly directory

# Check current permissions and ownership of /etc/cron.monthly

# Define the expected permissions and ownership

# Output the current state of the cron.monthly directory

# Check if permissions and ownership are as expected
    
    # Set correct ownership and permissions
#!/usr/bin/env bash

# Path to the cron.d directory

# Check current permissions and ownership of /etc/cron.d

# Define the expected permissions and ownership

# Output the current state of the cron.d directory

# Check if permissions and ownership are as expected

    # Set correct ownership and permissions
#!/usr/bin/env bash

# Check and configure /etc/cron.allow
    # Create /etc/cron.allow if it doesn't exist

# Set ownership and permissions for /etc/cron.allow

# Check and configure /etc/cron.deny if it exists
    # Set ownership and permissions for /etc/cron.deny

# Check if both files exist and ensure cron.allow takes precedence
#!/usr/bin/env bash
    # Check if group 'daemon' exists, otherwise use 'root'

    # Ensure /etc/at.allow exists

    # Set ownership and permissions for /etc/at.allow

    # Check if /etc/at.deny exists
        # Set ownership and permissions for /etc/at.deny
#!/usr/bin/env bash
#!/usr/bin/env bash

# Check if the 'bluez' package is installed

    # Check if 'bluetooth.service' is enabled
        # Stop and mask bluetooth.service if enabled
    
    # Check if 'bluetooth.service' is active
        # Stop bluetooth.service if active

    # Remove bluez package if it is not required by any other dependencies

#!/usr/bin/env bash
# If the module is currently loadable, add "install {MODULE_NAME} /bin/false" to a file in
 # If the module is currently loaded, unload the module
 # If the module isn't deny listed, denylist the module
 
 # Check if the module exists on the system
 
#!/usr/bin/env bash

                # set module name
                # set module type
 # If the module is currently loadable, add "install {MODULE_NAME} /bin/false" to a file in
 # If the module is currently loaded, unload the module
 # If the module isn't deny listed, denylist the module
 # Check if the module exists on the system
#!/usr/bin/env bash

                # set module name
                # set module type
 # If the module is currently loadable, add "install {MODULE_NAME} /bin/false" to a file in
 # If the module is currently loaded, unload the module
 # If the module isn't deny listed, denylist the module
 # Check if the module exists on the system

#!/usr/bin/env bash

                # set module name
                # set module type
 # If the module is currently loadable, add "install {MODULE_NAME} /bin/false" to a file in
 # If the module is currently loaded, unload the module
 # If the module isn't deny listed, denylist the module
 # Check if the module exists on the system
#!/usr/bin/env bash



#ufw allow in <port>/<tcp or udp protocol>
 #ufw deny in <port>/<tcp or udp protocol>
 
#!/bin/bash

# Ensure nftables is installed (uncomment if needed)
# sudo apt update && sudo apt install -y nftables

#!/bin/bash

#!/bin/bash

# Ensure nftables is installed (uncomment if needed)
# sudo apt update && sudo apt install -y nftables

# Enable and start nftables service

# Flush all current nftables rules to start fresh

# Create main inet table (for both IPv4 and IPv6)

# INPUT Chain: Incoming traffic, with default drop policy

# Allow loopback traffic for localhost (IPv4 and IPv6)

# Allow established and related incoming connections (all protocols)

# Allow incoming SSH (port 22)

# Allow incoming HTTP/HTTPS (ports 80, 443)

# Allow incoming DNS (UDP port 53)

# Allow essential ICMP types for IPv4

# Allow essential ICMPv6 types for IPv6

# Save the ruleset to persist changes

# Include the ruleset in nftables.conf for persistence on reboot



# 4.3 - iptables
# apt install iptables iptables-persistent


#5#!/usr/bin/env bash

# Secure sshd_config file and directory permissions

    # Secure all files within /etc/ssh/sshd_config.d

#!/usr/bin/env bash

# Initialize outputs and determine SSH group name

    # Function to fix file access
            
            # Determine permission mask and maximum permissions based on group

            # Update file mode if needed

            # Update owner if needed

            # Update group if needed

            # Append results to output

    # Apply file access fixes

    # Display results

#!/usr/bin/env bash

# Define variables and permission mask for sshd_config files

    # Function to enforce file access policies

            # Check and update file mode

            # Check and update owner

            # Check and update group ownership

            # Output results

    # Apply fixes to SSH-related files

    # Display results

#!/bin/bash

# Backup the original sshd_config file

# Define the changes to be made
  # Set Banner parameter above any Include and Match entries

  # Set Ciphers to unapproved weak Ciphers

  # Set ClientAliveInterval and ClientAliveCountMax parameters

  # Set DisableForwarding to yes

  # Set GSSAPIAuthentication to no

  # Set HostbasedAuthentication to no

  # Set IgnoreRhosts to yes

  # Set KexAlgorithms to unapproved weak algorithms

  # Set LoginGraceTime to 60 seconds

  # Set LogLevel to VERBOSE or INFO

  # Set MACs to unapproved weak MACs

  # Set MaxAuthTries to 4 or less

  # Set MaxSessions to 10 or less

  # Set MaxStartups to 10:30:60 or more restrictive

  # Set PermitEmptyPasswords to no

  # Set PermitRootLogin to no

  # Set PermitUserEnvironment to no

  # Set UsePAM to yes


# Restart SSH service to apply changes

#!/bin/bash

# Define the sudoers file path (it could be /etc/sudoers or a file in /etc/sudoers.d/)

# Use visudo to safely edit the sudoers file with the following changes:

# Add Defaults use_pty

# Add Defaults logfile="/var/log/sudo.log"

# Check if timestamp_timeout is greater than 15 minutes and modify it
  # If timestamp_timeout is larger than 15, update it to 15
  # If no timestamp_timeout entry, or it's already <= 15, ensure it's set correctly
#!/bin/bash

# Define group name

# Step 1: Create an empty group for su command usage

# Step 2: Modify /etc/pam.d/su to restrict access to users in ${GROUP_NAME}
    # Make a backup of the original PAM configuration file

    # Add the line to the PAM file

# Step 3: Ensure the group is empty (no users assigned)

# Final message


#!/bin/bash


# Basic variables for paths

# Ensure pam_unix is enabled for account, session, auth, and password

# --- Section 1: User Authentication and Lockout Policies ---

# Configure and enable pam_faillock for account lockout

# Configure pam_pwquality for password quality enforcement

# Apply password policies in pwquality configuration files

# Ensure account lockout policies

# --- Section 2: Network Configuration ---

# Disable IPv6 if not required

# Set IP forwarding to be disabled

# Ensure TCP SYN Cookies are enabled to prevent SYN flood attacks

# --- Section 3: Auditing Configuration ---

# Install auditd if not already installed

# Configure audit rules

# Configure audit rules for process execution

# Apply audit rules

# Enable auditd service

# --- Section 4: Filesystem and Permission Settings ---

# Disable unused filesystem mounting

# Ensure permissions on sensitive files

# --- Section 5: SSH Configuration ---

# Restart SSH to apply changes

# --- Section 6: Password Policies ---


# Ensure inactive password lock

# --- Section 7: System Updates and Firewall ---

# Enable automatic updates

# Configure UFW (Uncomplicated Firewall)
#!/bin/bash


# --- Section 1: System Logging Configuration ---

# Ensure rsyslog is installed

# Configure rsyslog to capture important logs

# Enable and start rsyslog service

# --- Section 2: Configuring System Accounts ---

# Disable root login

# Lock inactive user accounts

# Set permissions on user directories

# --- Section 3: System Hardening ---

# Disable core dumps to prevent exposure of sensitive data

# Prevent IP spoofing

# Secure shared memory

# Restrict access to cron and at

# Ensure only root can edit crontab

# --- Section 4: File and Process Auditing ---

# Ensure system audit configurations are set

# Apply the audit rules

# --- Section 5: System Security Settings ---

# Configure login banners

# Set permissions for banner files

# Enable AppArmor for additional security

# Configure AppArmor to enforce security profiles

# --- Section 6: File Integrity Checking ---



# --- Section 7: Kernel Hardening ---

# Enable ExecShield and address space randomization

# Restrict access to dmesg to prevent information leaks

# Apply sysctl changes

#!/bin/bash


# --- Section 1: Additional Service Hardening ---

# Disable unnecessary services

# --- Section 2: Log Retention and Management ---

# Configure logrotate to retain logs for 90 days

# Configure journald for persistent storage and 90-day retention

# --- Section 3: Secure Boot Settings ---

# Ensure secure boot is enabled (requires system support and UEFI)

# --- Section 4: Kernel and Filesystem Security Settings ---

# Disable uncommon filesystems

# Restrict core dumps for all users

# Restrict mounting of USB storage

# Enable auditing for all successful and unsuccessful privileged commands

# Reload auditd rules

# --- Section 5: Network Security Settings ---

# Disable IPv6 if not required

# Enable reverse path filtering to protect against spoofed packets

# Disable ICMP redirects to prevent route hijacking

# Enable TCP SYN cookies to protect against SYN flood attacks

# Apply sysctl configurations

# --- Section 6: Additional User Restrictions and System Settings ---

# Disable guest account for login

# Lock non-root user accounts with UID 0

# --- Section 7: Miscellaneous Security Hardening ---

# Enforce strong password expiration policies

# Enforce session timeout for SSH and TTY sessions

# Enable audit for session initiation

# Reload audit rules
#!/bin/bash


# --- Section 1: Advanced System Hardening ---

# Disable Prelink to prevent prelinked binaries (often unnecessary and a security risk)

# Remove xinetd, telnet, and rsh-client to prevent remote management services

# Ensure only root has access to the su command

# Disable IPv6 Router Advertisements (RA) to prevent rogue RA attacks

# --- Section 2: Enhanced Logging and Auditing Policies ---

# Enable audit rules for changes to system date and time

# Enable audit logging for user/group modifications

# Enable audit rules for privileged command execution

# Apply audit rules

# --- Section 3: User Account and Session Hardening ---

# Enforce session timeout for all users

# Set default umask for users

# Disable shell access for system accounts

# Restrict permissions on sensitive files and directories

# --- Section 4: Additional Kernel Hardening ---

# Configure kernel parameters for enhanced security

# Prevent sysrq key-based debugging

# Apply kernel settings

# --- Section 5: Advanced Network Security Settings ---

# Disable source-routed packets to prevent spoofing

# Enable packet forwarding logging to detect spoofed packets

# --- Section 6: System Maintenance and Monitoring ---

# Schedule regular updates

# Configure system daily check for package updates

# Configure automatic cleanup of old kernels and packages

# Ensure NTP synchronization for accurate system time

# --- Section 7: Additional File Integrity Monitoring ---

# Install and configure Tripwire for additional file integrity monitoring

# Initialize Tripwire database

# Schedule daily Tripwire integrity check

#!/bin/bash


# --- Section 6.2.1: Configure journald ---

# Configure journald to ensure persistent storage of logs and secure logging settings

# Ensure journald service is enabled and active

# Configure journald settings in /etc/systemd/journald.conf

# Restart journald to apply changes

# --- Section 6.2.2: Configure Logfiles ---

# Ensure access permissions are restricted for all log files

# Set ownership and permissions for system logs and configuration files

# Rotate logs by ensuring logrotate configuration is set for proper retention and compression

#!/bin/bash


# --- Section 6.3.1.1: Ensure auditd packages are installed ---

# Install auditd if it is not already installed

# --- Section 6.3.1.2: Ensure auditd service is enabled and active ---

# Enable and start auditd service to ensure it is running on startup

# Verify auditd service status

# --- Section 6.3.1.3: Ensure auditing for processes that start prior to auditd is enabled ---

# Modify GRUB to add 'audit=1' to enable auditing at boot for early processes

# --- Section 6.3.1.4: Ensure audit_backlog_limit is sufficient ---

# Set audit_backlog_limit to ensure the system can handle a high volume of audit messages

#!/bin/bash


# --- Section 6.3.2.1: Ensure audit log storage size is configured ---

# Set a maximum log file size of 100 MB and keep up to 10 rotated logs

# --- Section 6.3.2.2: Ensure audit logs are not automatically deleted ---

# Prevent automatic deletion of audit logs by disabling 'max_log_file_action'

# --- Section 6.3.2.3: Ensure system is disabled when audit logs are full ---

# Set 'space_left_action' to 'email' and 'action_mail_acct' to root

# Set 'admin_space_left_action' to halt the system when logs reach critical space

# --- Section 6.3.2.4: Ensure system warns when audit logs are low on space ---

# Set thresholds for low space warnings at 75% capacity

# Restart auditd to apply new configurations

#!/bin/bash

# 6.3.3.1 Ensure changes to system administration scope (sudoers) are collected

# 6.3.3.2 Ensure actions as another user are always logged

# 6.3.3.3 Ensure events that modify the sudo log file are collected

# 6.3.3.4 Ensure events that modify date and time information are collected

# 6.3.3.5 Ensure events that modify the system’s network environment are collected

# 6.3.3.6 Ensure use of privileged commands are collected

# 6.3.3.7 Ensure unsuccessful file access attempts are collected

# 6.3.3.8 Ensure events that modify user/group information are collected

# 6.3.3.9 Ensure discretionary access control permission modification events are collected

# 6.3.3.10 Ensure successful file system mounts are collected

# 6.3.3.11 Ensure session initiation information is collected

# 6.3.3.12 Ensure login and logout events are collected

# 6.3.3.13 Ensure file deletion events by users are collected

# 6.3.3.14 Ensure events that modify the system’s Mandatory Access Controls are collected

# 6.3.3.15 Ensure successful and unsuccessful attempts to use the chcon command are recorded

# 6.3.3.16 Ensure successful and unsuccessful attempts to use the setfacl command are recorded

# 6.3.3.17 Ensure successful and unsuccessful attempts to use the chacl command are recorded

# 6.3.3.18 Ensure successful and unsuccessful attempts to use the usermod command are recorded

# 6.3.3.19 Ensure kernel module loading, unloading, and modification is collected

# 6.3.3.20 Ensure the audit configuration is immutable

# 6.3.3.21 Ensure the running and on-disk configuration is the same
#!/bin/bash

# 6.3.4.1 Ensure audit log files mode is configured

# 6.3.4.2 Ensure audit log files owner is configured

# 6.3.4.3 Ensure audit log files group owner is configured

# 6.3.4.4 Ensure the audit log file directory mode is configured

# 6.3.4.5 Ensure audit configuration files mode is configured

# 6.3.4.6 Ensure audit configuration files owner is configured

# 6.3.4.7 Ensure audit configuration files group owner is configured

# 6.3.4.8 Ensure audit tools mode is configured


# 6.3.4.9 Ensure audit tools owner is configured

# 6.3.4.10 Ensure audit tools group owner is configured

#!/bin/bash

# 7.1.1 Ensure permissions on /etc/passwd are configured


# 7.1.2 Ensure permissions on /etc/passwd- are configured


# 7.1.3 Ensure permissions on /etc/group are configured


# 7.1.4 Ensure permissions on /etc/group- are configured

# 7.1.5 Ensure permissions on /etc/shadow are configured


# 7.1.6 Ensure permissions on /etc/shadow- are configured


# 7.1.7 Ensure permissions on /etc/gshadow are configured


# 7.1.8 Ensure permissions on /etc/gshadow- are configured


# 7.1.9 Ensure permissions on /etc/shells are configured


# 7.1.10 Ensure permissions on /etc/security/opasswd are configured


# 7.1.11 Ensure world writable files and directories are secured


# 7.1.12 Ensure no files or directories without an owner and a group exist


# 7.1.13 Ensure SUID and SGID files are reviewed (Manual Step)

#!/bin/bash

# Function to check and set permissions for specific files


    # Check current permissions
    

    # Set permissions if they don't match the required ones
    

# 7.1.x - Ensure permissions on key system files

# 7.1.11 - Secure world-writable files and directories

# 7.1.12 - Remove files and directories without an owner or group

# 7.1.13 - Review SUID and SGID files

#!/bin/bash

# Function to print status messages

# 7.2.1 Ensure accounts in /etc/passwd use shadowed passwords
     # Migrate passwords to shadow if needed

# 7.2.2 Ensure /etc/shadow password fields are not empty

# 7.2.3 Ensure all groups in /etc/passwd exist in /etc/group

# 7.2.4 Ensure shadow group is empty

# 7.2.5 Ensure no duplicate UIDs exist

# 7.2.6 Ensure no duplicate GIDs exist

# 7.2.7 Ensure no duplicate usernames exist

# 7.2.8 Ensure no duplicate group names exist

# 7.2.9 Ensure local interactive user home directories are configured

# 7.2.10 Ensure local interactive user dot files access is configured

#!/bin/bash

# Function to print status messages


# 5.4.1 Configure Shadow Password Suite Parameters
# 5.4.1.1 Ensure password expiration is configured
=
# 5.4.1.2 Ensure minimum password age is configured

# 5.4.1.3 Ensure password expiration warning days is configured

# 5.4.1.4 Ensure strong password hashing algorithm is configured

# 5.4.1.5 Ensure inactive password lock is configured

# 5.4.1.6 Ensure all users last password change date is in the past

# 5.4.2 Configure Root and System Accounts and Environment
# 5.4.2.1 Ensure root is the only UID 0 account

# 5.4.2.2 Ensure root is the only GID 0 account

# 5.4.2.3 Ensure group root is the only GID 0 group

# 5.4.2.4 Ensure root password is set

# 5.4.2.5 Ensure root path integrity

# 5.4.2.6 Ensure root user umask is configured

# 5.4.2.7 Ensure system accounts do not have a valid login shell


# 5.4.2.8 Ensure accounts without a valid login shell are locked

# 5.4.3 Configure User Default Environment
# 5.4.3.1 Ensure nologin is not listed in /etc/shells

# 5.4.3.2 Ensure default user shell timeout is configured

# 5.4.3.3 Ensure default user umask is configured
