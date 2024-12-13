#!/usr/bin/env bash


if [ ! "$BASH_VERSION" ] ; then
	exec /bin/bash "$0" "$@"
fi
# Set global variables
BDIR="$(dirname "$(readlink -f "$0")")"
FDIR=$BDIR/functions
RECDIR="$FDIR"/recommendations
GDIR="$FDIR"/general
LDIR=$BDIR/logs
RDIR=$BDIR/backup
DTG=$(date +%m_%d_%Y_%H%M)
mkdir $LDIR/$DTG
mkdir $RDIR/$DTG
LOGDIR=$LDIR/$DTG
BKDIR=$RDIR/$DTG
LOG=$LOGDIR/CIS-LBK_verbose.log
SLOG=$LOGDIR/CIS-LBK.log
ELOG=$LOGDIR/CIS-LBK_error.log
FRLOG=$LOGDIR/CIS-LBK_failed.log
MANLOG=$LOGDIR/CIS-LBK_manual.log
passed_recommendations="0"
failed_recommendations="0"
remediated_recommendations="0"
not_applicable_recommendations="0"
excluded_recommendations="0"
manual_recommendations="0"
skipped_recommendations="0"
total_recommendations="0"
# Load functions (Order matters)
for func in "$GDIR"/*.sh; do
	[ -e "$func" ] || break
	. "$func"
done
for func in "$RECDIR"/*.sh; do
	[ -e "$func" ] || break
	. "$func"
done
#Clear the screen for output
clear
# Display the build kit banner
BANR
# Ensure script is being run as root
ROOTUSRCK
# Display the terms of use
# terms_of_use
# Display CIS Linux Build Kit warning banner
WARBNR
#run_profile=L2S # Uncomment this line to provide profile to be run manually
# Profile Options:
# L1S - For Level 1 Server
# L1W - For Level 1 Workstation
# L2S - For Level 2 Server
# L2W - For Level 2 Workstation
# Have user select profile to run
select_profile
# Recommediations This is where a BM specific script begins.

# Generated for specific Benchmark

#
# 1 Initial Setup
#
#
# 1.1 Filesystem Configuration
#
#
# 1.1.1 Disable unused filesystems
#
RN="1.1.1.1"
RNA="Ensure mounting of cramfs filesystems is disabled"
profile="L1S L1W"
REC="cramfs_filesystem_disabled_rec"
total_recommendations=$((total_recommendations+1))
runrec

RN="1.1.1.2"
RNA="Ensure mounting of squashfs filesystems is disabled"
profile="L2S L2W"
REC="squashfs_filesystem_disabled"
total_recommendations=$((total_recommendations+1))
runrec

RN="1.1.1.3"
RNA="Ensure mounting of udf filesystems is disabled"
profile="L1S L1W"
REC="udf_filesystem_disabled_rec"
total_recommendations=$((total_recommendations+1))
runrec

#
# 1.2 Configure Software Updates
#
RN="1.2.1"
RNA="Ensure GPG keys are configured"
profile="L1S L1W"
REC="ensure_gpg_keys_configured"
total_recommendations=$((total_recommendations+1))
runrec

RN="1.2.2"
RNA="Ensure package manager repositories are configured"
profile="L1S L1W"
REC="ensure_package_manager_repositories_configured"
total_recommendations=$((total_recommendations+1))
runrec

RN="1.2.3"
RNA="Ensure gpgcheck is globally activated"
profile="L1S L1W"
REC="fed28_ensure_gpgcheck_globally_activated"
total_recommendations=$((total_recommendations+1))
runrec

RN="1.2.5"
RNA="Disable the rhnsd Daemon"
profile="L2S L2W"
REC="rh_disable_rhnsd_daemon"
total_recommendations=$((total_recommendations+1))
runrec

#
# 1.4 Filesystem Integrity Checking
#
RN="1.4.1"
RNA="Ensure AIDE is installed"
profile="L1S L1W"
REC="ensure_aide_installed"
total_recommendations=$((total_recommendations+1))
runrec

RN="1.4.2"
RNA="Ensure filesystem integrity is regularly checked"
profile="L1S L1W"
REC="fed_ensure_filesystem_integrity_checked"
total_recommendations=$((total_recommendations+1))
runrec

#
# 1.7 Mandatory Access Control
#
#
# 1.7.1 Configure SELinux
#
RN="1.7.1.1"
RNA="Ensure SELinux is installed"
profile="L1S L1W"
REC="fed_ensure_selinux_installed"
total_recommendations=$((total_recommendations+1))
runrec

RN="1.7.1.3"
RNA="Ensure SELinux policy is configured"
profile="L1S L1W"
REC="fed_ensure_selinux_policy_configured"
total_recommendations=$((total_recommendations+1))
runrec

RN="1.7.1.4"
RNA="Ensure the SELinux mode is enforcing or permissive"
profile="L1S L1W"
REC="fed_ensure_selinux_state_enforcing_or_permissive"
total_recommendations=$((total_recommendations+1))
runrec

RN="1.7.1.5"
RNA="Ensure the SELinux mode is enforcing"
profile="L2S L2W"
REC="fed_ensure_selinux_state_enforcing"
total_recommendations=$((total_recommendations+1))
runrec

#
# 1.8 Warning Banners
#
#
# 1.8.1 Command Line Warning Banners
#
RN="1.8.1.1"
RNA="Ensure message of the day is configured properly"
profile="L1S L1W"
REC="nix_ensure_motd_configured"
total_recommendations=$((total_recommendations+1))
runrec

#
# 2 Services
#
#
# 2.1 inetd Services
#
RN="2.1.2"
RNA="Ensure xinetd is not installed"
profile="L1S L1W"
REC="fed_ensure_xinetd_not_installed"
total_recommendations=$((total_recommendations+1))
runrec

#
# 2.2 Special Purpose Services
#
#
# 2.2.1 Time Synchronization
#
RN="2.2.1.1"
RNA="Ensure time synchronization is in use"
profile="L1S L1W"
REC="fed_ensure_time_synchronization_in_use"
total_recommendations=$((total_recommendations+1))
runrec

RN="2.2.1.2"
RNA="Ensure chrony is configured"
profile="L1S L1W"
REC="fed_chrony_configured"
total_recommendations=$((total_recommendations+1))
runrec

RN="2.2.1.3"
RNA="Ensure ntp is configured"
profile="L1S L1W"
REC="nix_fed_ensure_ntp_configured"
total_recommendations=$((total_recommendations+1))
runrec

RN="2.2.17"
RNA="Ensure rsync is not installed or the rsyncd service is masked"
profile="L1S L1W"
REC="fed_ensure_rsync_not_installed_or_rsync_service_masked"
total_recommendations=$((total_recommendations+1))
runrec

RN="2.2.19"
RNA="Ensure telnet-server is not installed"
profile="L1S L1W"
REC="fed_ensure_telnet_server_not_installed"
total_recommendations=$((total_recommendations+1))
runrec

#
# 2.3 Service Clients
#
RN="2.3.1"
RNA="Ensure NIS Client is not installed"
profile="L1S L1W"
REC="fed_ensure_nis_client_not_installed"
total_recommendations=$((total_recommendations+1))
runrec

RN="2.3.4"
RNA="Ensure telnet client is not installed"
profile="L1S L1W"
REC="fed_ensure_telnet_client_not_installed"
total_recommendations=$((total_recommendations+1))
runrec

#
# 3 Network Configuration
#
#
# 3.1 Disable unused network protocols and devices
#
RN="3.1.1"
RNA="Disable IPv6"
profile="L2S L2W"
REC="disable_ipv6"
total_recommendations=$((total_recommendations+1))
runrec

#
# 3.2 Network Parameters (Host Only)
#
RN="3.2.1"
RNA="Ensure IP forwarding is disabled"
profile="L1S L1W"
REC="ip_forwarding_disabled"
total_recommendations=$((total_recommendations+1))
runrec

RN="3.2.2"
RNA="Ensure packet redirect sending is disabled"
profile="L1S L1W"
REC="packet_redirect_sending_disabled"
total_recommendations=$((total_recommendations+1))
runrec

#
# 3.3 Network Parameters (Host and Router)
#
RN="3.3.1"
RNA="Ensure source routed packets are not accepted"
profile="L1S L1W"
REC="ensure_source_routed_packets_not_accepted"
total_recommendations=$((total_recommendations+1))
runrec

RN="3.3.3"
RNA="Ensure secure ICMP redirects are not accepted"
profile="L1S L1W"
REC="ensure_secure_icmp_redirects_not_accepted"
total_recommendations=$((total_recommendations+1))
runrec

RN="3.3.4"
RNA="Ensure suspicious packets are logged"
profile="L1S L1W"
REC="ensure_suspicious_packets_logged"
total_recommendations=$((total_recommendations+1))
runrec

#
# 4 Logging and Auditing
#
#
# 4.1 Configure System Accounting (auditd)
#
#
# 4.1.1 Ensure auditing is enabled
#
RN="4.1.1.1"
RNA="Ensure auditd is installed"
profile="L2S L2W"
REC="fed_ensure_auditd_installed"
total_recommendations=$((total_recommendations+1))
runrec

RN="4.1.1.2"
RNA="Ensure auditd service is enabled and running"
profile="L2S L2W"
REC="ensure_auditd_service_enabled_running"
total_recommendations=$((total_recommendations+1))
runrec

RN="4.1.1.3"
RNA="Ensure auditing for processes that start prior to auditd is enabled"
profile="L2S L2W"
REC="ensure_auditing_processes_start_prior_auditd_enabled"
total_recommendations=$((total_recommendations+1))
runrec

#
# 4.1.2 Configure Data Retention
#

RN="4.1.2.2"
RNA="Ensure audit logs are not automatically deleted"
profile="L2S L2W"
REC="ensure_audit_logs_not_automatically_deleted"
total_recommendations=$((total_recommendations+1))
runrec

RN="4.1.2.3"
RNA="Ensure system is disabled when audit logs are full"
profile="L2S L2W"
REC="ensure_system_disabled_audit_logs_full"
total_recommendations=$((total_recommendations+1))
runrec

RN="4.1.2.4"
RNA="Ensure audit_backlog_limit is sufficient"
profile="L2S L2W"
REC="ensure_audit_backlog_limit_sufficient"
total_recommendations=$((total_recommendations+1))
runrec

RN="4.1.3"
RNA="Ensure events that modify date and time information are collected"
profile="L2S L2W"
REC="ensure_events_modify_date_time_information_collected"
total_recommendations=$((total_recommendations+1))
runrec

RN="4.1.4"
RNA="Ensure events that modify user/group information are collected"
profile="L2S L2W"
REC="ensure_events_modify_user_group_information_collected"
total_recommendations=$((total_recommendations+1))
runrec

RN="4.1.5"
RNA="Ensure events that modify the systems network environment are collected"
profile="L2S L2W"
REC="ensure_events_modify_systems_network_environment_collected"
total_recommendations=$((total_recommendations+1))
runrec

#
# 5 "Access
#
#
# 5.1 Configure time-based job schedulers
#
RN="5.1.1"
RNA="Ensure cron daemon is enabled and running"
profile="L1S L1W"
REC="fed_ensure_cron_daemon_enabled_running"
total_recommendations=$((total_recommendations+1))
runrec

RN="5.1.2"
RNA="Ensure permissions on /etc/crontab are configured"
profile="L1S L1W"
REC="ensure_permissions_crontab_configured"
total_recommendations=$((total_recommendations+1))
runrec

RN="5.1.3"
RNA="Ensure permissions on /etc/cron.hourly are configured"
profile="L1S L1W"
REC="ensure_permissions_cron_hourly_configured"
total_recommendations=$((total_recommendations+1))
runrec

RN="5.1.7"
RNA="Ensure permissions on /etc/cron.d are configured"
profile="L1S L1W"
REC="ensure_permissions_cron_d_configured"
total_recommendations=$((total_recommendations+1))
runrec

RN="5.1.8"
RNA="Ensure cron is restricted to authorized users"
profile="L1S L1W"
REC="ensure_cron_restricted_authorized_users"
total_recommendations=$((total_recommendations+1))
runrec

#
# 5.2 Configure SSH Server
#
RN="5.2.1"
RNA="Ensure permissions on /etc/ssh/sshd_config are configured"
profile="L1S L1W"
REC="ensure_permissions_sshd_config_configured"
total_recommendations=$((total_recommendations+1))
runrec

RN="5.2.2"
RNA="Ensure permissions on SSH private host key files are configured"
profile="L1S L1W"
REC="ensure_permissions_ssh_private_hostkey_files_configured"
total_recommendations=$((total_recommendations+1))
runrec

RN="5.2.5"
RNA="Ensure SSH LogLevel is appropriate"
profile="L1S L1W"
REC="ensure_ssh_loglevel_appropriate"
total_recommendations=$((total_recommendations+1))
runrec

RN="5.2.10"
RNA="Ensure SSH root login is disabled"
profile="L1S L1W"
REC="ensure_ssh_root_login_disabled"
total_recommendations=$((total_recommendations+1))
runrec

RN="5.2.11"
RNA="Ensure SSH PermitEmptyPasswords is disabled"
profile="L1S L1W"
REC="ensure_ssh_permitemptypasswords_disabled"
total_recommendations=$((total_recommendations+1))
runrec

RN="5.2.12"
RNA="Ensure SSH PermitUserEnvironment is disabled"
profile="L1S L1W"
REC="ensure_ssh_permituserenvironment_disabled"
total_recommendations=$((total_recommendations+1))
runrec

RN="5.2.13"
RNA="Ensure only strong Ciphers are used"
profile="L1S L1W"
REC="ssh7_ensure_strong_ciphers_used"
total_recommendations=$((total_recommendations+1))
runrec

RN="5.2.16"
RNA="Ensure SSH Idle Timeout Interval is configured"
profile="L1S L1W"
REC="fed28_ensure_ssh_idle_timeout_interval_configured"
total_recommendations=$((total_recommendations+1))
runrec

RN="5.2.17"
RNA="Ensure SSH LoginGraceTime is set to one minute or less"
profile="L1S L1W"
REC="ensure_ssh_logingracetime_one_minute_or_less"
total_recommendations=$((total_recommendations+1))
runrec

RN="5.2.19"
RNA="Ensure SSH PAM is enabled"
profile="L1S L1W"
REC="ensure_ssh_pam_enabled"
total_recommendations=$((total_recommendations+1))
runrec

#
# 5.3 Configure PAM
#
RN="5.3.1"
RNA="Ensure password creation requirements are configured"
profile="L1S L1W"
REC="fed_ensure_password_creation_requirements_configured"
total_recommendations=$((total_recommendations+1))
runrec

RN="5.3.2"
RNA="Ensure lockout for failed password attempts is configured"
profile="L1S L1W"
REC="fed_ensure_lockout_failed_password_attempts_configured"
total_recommendations=$((total_recommendations+1))
runrec

RN="5.3.3"
RNA="Ensure password hashing algorithm is SHA-512"
profile="L1S L1W"
REC="fed_ensure_password_hashing_algorithm_sha512"
total_recommendations=$((total_recommendations+1))
runrec

RN="5.3.4"
RNA="Ensure password reuse is limited"
profile="L1S L1W"
REC="fed_ensure_password_reuse_limited"
total_recommendations=$((total_recommendations+1))
runrec

#
# 6 System Maintenance
#

#
# 6.2 User and Group Settings
#
RN="6.2.1"
RNA="Ensure accounts in /etc/passwd use shadowed passwords"
profile="L1S L1W"
REC="ensure_accounts_etc_passwd_use_shadowed_passwords"
total_recommendations=$((total_recommendations+1))
runrec

RN="6.2.2"
RNA="Ensure /etc/shadow password fields are not empty"
profile="L1S L1W"
REC="ensure_accounts_etc_shadow_password_fields_not_empty"
total_recommendations=$((total_recommendations+1))
runrec

RN="6.2.5"
RNA="Ensure all users home directories exist"
profile="L1S L1W"
REC="ensure_users_home_directories_exist"
total_recommendations=$((total_recommendations+1))
runrec

RN="6.2.7"
RNA="Ensure users own their home directories"
profile="L1S L1W"
REC="ensure_users_own_their_home_directories"
total_recommendations=$((total_recommendations+1))
runrec

#
#  
#
# End of generation for specific Benchmark
#End of recommendations

# Provide summery report
summery_report
