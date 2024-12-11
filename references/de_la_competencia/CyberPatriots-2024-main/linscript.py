#!/bin/bash
import os

# sudo python3 manage_packages.py
# Run using the above

# Gets user list

def get_user_list():
    users = []
    try:
        with open('/etc/passwd', 'r') as f:
            for line in f:
                fields = line.split(':')
                # Filter out system users (typically UID < 1000)
                if int(fields[2]) >= 1000:
                    users.append(fields[0])
        return users
    except Exception as e:
        print('Unable to get User List error')
        return users

# Removing users from System

def remove_user_from_system(username):
    try:
        passwd_file = '/etc/passwd'
        shadow_file = '/etc/shadow'

        lines=[]

        with open(passwd_file, 'r') as f:
            lines = f.readlines()
        with open(passwd_file, 'w') as f:
            for line in lines:
                if not line.startswith(username + ":"):
                    f.write(line+'\n')
        lines=[]
        with open(shadow_file, 'r') as f:
            lines = f.readlines()
        with open(shadow_file, 'w') as f:
            for line in lines:
                if not line.startswith(username + ":"):
                    f.write(line+'\n')
        
        print(f"User {username} has been removed from the system.")
    except Exception as e:
        print(f"User {username} has not been removed from the system due to an error. (removeuser error)")

# Editing admin privileges for a given user

def modify_admin_privileges(username, grant_admin):
    try:
        group_file = '/etc/group'
        lines=[]
        with open(group_file, 'r') as f:
            lines = f.readlines()
        
        # Modify the sudo group
        for i, line in enumerate(lines):
            if line.startswith('sudo:'):
                parts = line.strip().split(':')
                if grant_admin:
                    if username not in parts[-1]:
                        parts[-1] = parts[-1] + ',' + username if parts[-1] else username
                        print(f"Granted administrative privileges to {username}.")
                else:
                    if username in parts[-1]:
                        users = parts[-1].split(',')
                        users.remove(username)
                        parts[-1] = ','.join(users)
                        print(f"Removed administrative privileges from {username}.")
                lines[i] = ':'.join(parts) + '\n'
                break
        with open(group_file, 'w') as f:
            f.writelines(lines+'\n')
    except Exception as e:
        print('adminpriveldges error')

# Main method for Users

def manage_users():
    try:
        users = get_user_list()
        for user in users:
            print(f"User: {user}")
            delete = input(f"Do you want to delete the user '{user}'? (yes/no): ").strip().lower()
            
            if delete == 'yes':
                remove_user_from_system(user)
            else:
                modify_privileges = input(f"Should the user '{user}' have administrative privileges? (yes/no): ").strip().lower()
                if modify_privileges == 'yes':
                    modify_admin_privileges(user, True)
                elif modify_privileges == 'no':
                    modify_admin_privileges(user, False)
                else:
                    print(f"Invalid response for user '{user}', skipping privilege modification.")
    except Exception as e:
        print('manageUsers() error')

# Updating

def upd():
    try:
        os.system("sudo apt-get update")
        os.system("sudo apt-get upgrade")
        print("System has been updated")
        os.system('sudo apt-get autoremove -y -qq')
        os.system('sudo apt-get autoclean -y -qq')
        os.system('sudo apt-get clean -y -qq')
        print("All unused packages have been removed.")
    except Exception as e:
        print("update error")

# Install antivirus

def antivirus():
    try:
        os.system('sudo apt-get install apparmor apparmor-profiles -y -qq')
        print("AppArmor has been installed.")
    except Exception as e:
        print('antivirus error')

# Firewall

def fire():
    try:
        confirm = input("Do you want to enable firewall? (yes/no)").strip().lower()
        if(confirm == "yes"):
            confirma = input("Do you want to enable SSH connections?").strip().lower()
            os.system('sudo apt-get install ufw -y -qq')
            if(confirma == "yes"):
                os.system("sudo ufw allow ssh")
                print("SSH has been enabled")
            os.system("sudo ufw enable")
            os.system('ufw deny 1337')
            os.system("sysctl -n net.ipv4.tcp_syncookies")
            os.system("echo 0 | sudo tee /proc/sys/net/ipv4/ip_forward")
            os.system("echo 'nospoof on' | sudo  tee -a /etc/host.conf")
            print("Firewall has been enabled")
        else:
            print("Firewall has not been changed")
    except Exception as e:
        print('firewall change error')

# Listing Programs

def list_nonessential_programs():
    status_file = '/var/lib/dpkg/status'
    nonessential_programs = []
    try:
        with open(status_file, 'r') as f:
            current_package = {}
            for line in f:
                if line.startswith("Package: "):
                    current_package['name'] = line.split()[1]
                elif line.startswith("Priority: "):
                    current_package['priority'] = line.split()[1]
                elif line == "\n":
                    if 'priority' in current_package and current_package['priority'] in ['optional', 'extra']:
                        nonessential_programs.append(current_package['name'])
                    current_package = {}

        return nonessential_programs
    except Exception as e:
        print('error finding nonessential programs')
        return nonessential_programs


# Removing Programs

def remove_program(program_name):
    try:
        os.system(f"sudo apt remove -y {program_name}")
        print(f"Package {program_name} has been removed.")
    except Exception as e:
        print(f"there was an error removing {program_name}")

# Main Program Manager Method

def manage_nonessential_programs():
    programs = list_nonessential_programs()
    
    if programs.size() == 0:
        print("No non-essential programs found.")
        return
    try:
        for program in programs:
            print(f"Program: {program}")
            response = input(f"Do you want to remove '{program}'? (yes/no): ").strip().lower()
            if response == 'yes':
                remove_program(program)
            else:
                print(f"Skipping {program}.")

        com = input('Do you need to secure vsftpd.conf? (yes/no)').strip().lower()
        lines=[]
        if(com == 'yes'):
            config = '/etc/vstfpd.conf'
            try:
                with open(config, "r") as f:
                    lines = f.readlines()
                with open(config, "w") as g:
                    for curr in lines:
                        if curr.startswith("anonymous_enable"):
                            g.write("anonymous_enable=ON\n")
                        elif curr.startswith("local_enable"):
                            g.write("local_enable=YES\n")
                        elif curr.startswith("write_enable"):
                            g.write("write_enable=YES\n")
                        elif curr.startswith("chroot_local_user"):
                            g.write("chroot_local_user=YES\n")
                        else:
                            g.write(curr + '\n')
                os.system('sudo systemctl restart vsftpd')
            except Exception as e:
                print(f'{config} not found')
    except Exception as e:
        print('error removing a program or securing vsftpd')

# Disable Root Login

def disable_root_login():
    com = input("Do you want to disable SSH Root Login? (yes/no)").strip().lower()
    lines=[]
    try:
        if(com == "yes"):
            config = '/etc/ssh/sshd_config'
            with open(config, "r") as f:
                lines = f.readlines()
            with open(config, "w") as g:
                for curr in lines:
                    if curr.startswith("PermitRootLogin"):
                        g.write("PermitRootLogin no\n")
                    elif curr.startswith("LoginGraceTime"):
                        g.write("LoginGraceTime 60\n")
                    elif curr.startswith("PermitEmptyPasswords"):
                        g.write("PermitEmptyPasswords no\n")
                    elif curr.startswith("PasswordAuthentication"):
                        g.write("PasswordAuthentication yes\n")
                    elif curr.startswith("X11Fowarding"):
                        g.write("X11Fowarding no\n")
                    elif curr.startswith("UsePAM"):
                        g.write("UsePAM yes\n")
                    elif curr.startswith("UsePrivilegeSeparation"):
                        g.write("UsePrivilegeSeparation yes\n")
                    else:
                        g.write(curr + '\n')
    except Exception as e:
        print('error disabling root login')

# Passwords Min Len

def minlenpass():
    try:
        com = '/etc/pam.d/common-password'
        lines=[]
        with open(com, 'r') as f:
            lines = f.readLines()
        with open(com, 'w') as g:
            for curr in lines:
                if curr.startswith("password [success=1 default=ignore] pam_unix.so obscure sha512"):
                    g.write("password [success=1 default=ignore] pam_unix.so obscure sha512 minlen=12\n")
                else:
                    g.write(curr+'\n')
    except Exception as e:
        print('error changing min pass len')

# Change Min and Max Num Days for Password

def minpassdays():
    try:
        fil = '/etc/login.defs'
        lines=[]
        with open(fil, 'r') as f:
            lines = f.readLines()
        with open(fil, 'w') as g:
            for curr in lines:
                if curr.startswith("PASS_MAX_DAYS"):
                    g.write("PASS_MAX_DAYS 30\n")
                elif curr.startswith("PASS_MIN_DAYS"):
                    g.write("PASS_MIN_DAYS 1\n")
                elif curr.startswith("FAILLOG_ENAB"):
                    g.write("FAILLOG_ENAB YES\n")
                elif curr.startswith("LOG_UNKFAIL_ENAB"):
                    g.write("LOG_UNKFAIL_ENAB YES\n")
                elif curr.startswith("SYSLOG_SU_ENAB"):
                    g.write("SYSLOG_SU_ENAB YES\n")
                elif curr.startswith("SYSLOG_SG_ENAB"):
                    g.write("SYSLOG_SG_ENAB YES\n")
                elif curr.startswith("PASS_WARN_AGE"):
                    g.write("PASS_WARN_AGE 7\n")
                else:
                    g.write(curr)
    except Exception as e:
        print('minpassdays() error')

# Configure pass policies

def configPassPolicy():
    try:
        os.system('sudo apt-get install libpam-cracklib -y -qq')
        os.system('cp /etc/pam.d/common-auth ~/Desktop/backups/')
        os.system('cp /etc/pam.d/common-password ~/Desktop/backups/')
        result = os.system('grep "auth optional pam_tally.so deny=5 unlock_time=900 onerr=fail audit even_deny_root_account silent" /etc/pam.d/common-auth')
        if result == 1:
            os.system('echo "auth optional pam_tally.so deny=5 unlock_time=900 onerr=fail audit even_deny_root_account silent" >> /etc/pam.d/common-auth')
            os.system('echo -e "password requisite pam_cracklib.so retry=3 minlen=8 difok=3 reject_username minclass=3 maxrepeat=2 dcredit=1 ucredit=1 lcredit=1 ocredit=1\npassword requisite pam_pwhistory.so use_authtok remember=24 enforce_for_root" >> /etc/pam.d/common-password')

        print("Password policies have been set, editing /etc/login.defs and pam.d.")
    except Exception as e:
        print('error configpasspolicy')

# Update PAM Authority

def update_pam_auth():
    try:
        pam_auth_file = '/etc/pam.d/common-auth'
        with open(pam_auth_file, 'r') as file:
            lines = file.readlines()
        for i, line in enumerate(lines):
            if 'pam_tally2.so' in line:
                if 'deny=' in line or 'unlock_time=' in line:
                    lines[i] = line.rstrip() + ' deny=5 unlock_time=1800\n'
                else:
                    lines[i] = line.rstrip() + ' deny=5 unlock_time=1800\n'
                break  # Exit the loop after modifying the line
        with open(pam_auth_file, 'w') as file:
            file.writelines(lines)
        print("Updated pam_tally2 configuration in common-auth.")
    except Exception as e:
        print('error update_pam_auth')


# Changes all current passwords to a new secure one

def changeAll():
    try:
        new_password = "eyE4kt%RTwa#XmGA"
        with open('/etc/passwd', 'r') as f:
            users = [line.split(':')[0] for line in f if int(line.split(':')[2]) >= 1000]

        for user in users:
            command = f'echo "{user}:{new_password}" | sudo chpasswd'
            os.system(command)
            print(f"Password for user '{user}' has been changed.")
    except Exception as e:
        print('error changeall')

# Passwords

def pas():
    try:
        changeAll()
        minlenpass()
        minpassdays()
        configPassPolicy()
    except Exception as e:
        print('pas error')
        

# Finds bad files (mp3, mp4, mov, avi)

def remove_audio_files():
    try:
        audio_extensions = [
            "*.midi", "*.mid", "*.mod", "*.mp3", "*.mp2", "*.mpa",
            "*.abs", "*.mpega", "*.au", "*.snd", "*.wav", "*.aiff",
            "*.aif", "*.sid", "*.flac", "*.ogg"
        ]
        
        for ext in audio_extensions:
            os.system(f'find / -name "{ext}" -type f -delete')
        print("Audio files removed.")
    except Exception as e:
        print('remove_audio_files error')

def remove_video_files():
    try:
        video_extensions = [
            "*.mpeg", "*.mpg", "*.mpe", "*.dl", "*.movie", "*.movi",
            "*.mv", "*.iff", "*.anim5", "*.anim3", "*.anim7", "*.avi",
            "*.vfw", "*.avx", "*.fli", "*.flc", "*.mov", "*.qt",
            "*.spl", "*.swf", "*.dcr", "*.dir", "*.dxr", "*.rpm",
            "*.rm", "*.smi", "*.ra", "*.ram", "*.rv", "*.wmv",
            "*.asf", "*.asx", "*.wma", "*.wax", "*.wmv", "*.wmx",
            "*.3gp", "*.mov", "*.mp4", "*.avi", "*.swf", "*.flv",
            "*.m4v"
        ]
        
        for ext in video_extensions:
            os.system(f'find / -name "{ext}" -type f -delete')
        print("Video files removed.")
    except Exception as e:
        print('remove_video_files error')

def remove_image_files():
    try:
        image_extensions = [
            "*.tiff", "*.tif", "*.rs", "*.im1", "*.gif", "*.jpeg",
            "*.jpg", "*.jpe", "*.png", "*.rgb", "*.xwd", "*.xpm",
            "*.ppm", "*.pbm", "*.pgm", "*.pcx", "*.ico", "*.svg",
            "*.svgz"
        ]
        
        for ext in image_extensions:
            os.system(f'find /home -name "{ext}" -type f -delete')
        print('Images Removed')
    except Exception as e:
        print('remove_image_files error')

# Main function to remove all specified files
def remove_files():
    try:
        remove_audio_files()
        remove_video_files()
        remove_image_files()
    except Exception as e:
        print('remove files error')

# Editing Light DM Configuration File

def lightDmStuff():
    try:
        os.system('chmod 777 /etc/lightdm/lightdm.conf')
        com = input('Debian or Ubuntu? (d/u)').strip().lower()    
        lines=[]
        mon = '/etc/lightdm/lightdm.conf'
        if(com == 'u'):
            try:
                with open('mon', 'r') as f:
                    lines = f.readlines()
                with open('mon', 'w') as g:
                    for line in lines:
                        if(line.startswith('allows-guest')):
                            g.write('allow-guest=false\n')
                        elif(line.startswith('greeter0hide-users')):
                            g.write('greeter0hide-users=true\n')
                        elif(line.startswith('greeter-show-manual-login')):
                            g.write('greeter-show-manual-login=true\n')
                        elif(line.startswith('autologin-user')):
                            g.write('autologin-user=none\n')
                        else:
                            g.write(line+"\n")
            except Exception as e:
                print(f'No File found at {mon} error')
        else:
            try:
                with open(mon, 'r') as f:
                    lines = f.readlines()
                with open(mon, 'w') as g:
                    for line in lines:
                        if(line.startswith('Allows-guest')):
                            g.write('Allow-guest=false\n')
                        elif(line.startswith('Greeter-hide-users')):
                            g.write('Greeter-hide-users=true\n')
                        elif(line.startswith('Greeter-allow-guest')):
                            g.write('Greeter-allows-guest=false\n')
                        elif(line.startswith('Greeter-show-manual-login')):
                            g.write('Greeter-show-manual-login=true\n')
                        elif(line.startswith('Autologin-user')):
                            g.write('Autologin-user=none\n')
                        else:
                            g.write(line+'\n')
                lines=[]
                mon = '/etc/gdm3/greeter.dconf-defaults'
                with open(mon, 'r') as f:
                    lines = f.readlines()
                with open(mon, 'w') as g:
                    for line in lines:
                        if(line.startswith('Allows-guest')):
                            g.write('Allow-guest=false\n')
                        elif(line.startswith('Disable-user-list')):
                            g.write('Disable-user-list=true\n')
                        elif(line.startswith('Disable-restart-buttons')):
                            g.write('Disable-restart-buttons=true\n')
                        elif(line.startswith('AutomaticLoginEnable')):
                            g.write('AutomaticLoginEnable=false\n')
                        else:
                            g.write(line+'\n')
            except Exception as e:
                print(f'No File found at {mon} error')
        os.system('chmod 644 /etc/lightdm/lightdm.conf')
    except Exception as e:
        print('lightdmstuff error')

# User Creator

def createUsers():
    try:
        while True:
            username = input("Enter the username to create (type 'timmyisshort' to stop): ").strip()
            if username == 'timmyisshort':
                print("Stopping user creation process.")
                break
            try:
                os.system(f'sudo useradd -m {username}')
                print(f"User '{username}' has been created.")
                password = "eyE4kt%RTwa#XmGA"
                os.system(f'echo "{username}:{password}" | sudo chpasswd')
                print(f"Password for user '{username}' has been set.")
            except Exception as e:
                print(f"Failed to create user '{username}': {e}")
    except Exception as e:
        print('createusers error')

# Secure shadow file

def sdw():
    try:
        os.system('chmod 640 /etc/shadow')
    except Exception as e:
        print('sdw (securing shadow file) error')

# Conifguring sysctl confirguration file

def sysctl():
    try:
        sysctl_conf_path = '/etc/sysctl.conf'
        configurations = [
            "# Disable ICMP redirects",
            "net.ipv4.conf.all.accept_redirects = 0",
            "# Disable IP redirecting",
            "net.ipv4.ip_forward = 0",
            "net.ipv4.conf.all.send_redirects = 0",
            "net.ipv4.conf.default.send_redirects = 0",
            "# Disable IP spoofing",
            "net.ipv4.conf.all.rp_filter = 1",
            "# Disable IP source routing",
            "net.ipv4.conf.all.accept_source_route = 0",
            "# SYN Flood Protection",
            "net.ipv4.tcp_max_syn_backlog = 2048",
            "net.ipv4.tcp_synack_retries = 2",
            "net.ipv4.tcp_syn_retries = 5",
            "net.ipv4.tcp_syncookies = 1",
            "# Disable IPV6",
            "net.ipv6.conf.all.disable_ipv6 = 1",
            "net.ipv6.conf.default.disable_ipv6 = 1",
            "net.ipv6.conf.lo.disable_ipv6 = 1"
        ]
        with open(sysctl_conf_path, 'a+') as f:
            f.seek(0)
            existing_lines = f.readlines()
            for config in configurations:
                if config + '\n' not in existing_lines:
                    f.write(config + '\n')
        os.system('sudo sysctl -p')
    except Exception as e:
        print('sysctl error')

# Common Program Remover

def commonPurge():
    try:
        packages = [
            "netcat",
            "netcat-openbsd",
            "netcat-traditional",
            "ncat",
            "pnetcat",
            "socat",
            "sock",
            "socket",
            "sbd",
            "john",
            "john-data",
            "hydra",
            "hydra-gtk",
            "aircrack-ng",
            "fcrackzip",
            "lcrack",
            "ophcrack",
            "ophcrack-cli",
            "pdfcrack",
            "pyrit",
            "rarcrack",
            "sipcrack",
            "irpas"
        ]
        for package in packages:
            os.system(f'sudo apt-get purge {package} -y -qq')
            print(f"{package} has been removed.")
        os.system('rm /usr/bin/nc')
        print("Netcat and all other instances have been removed.")
    except Exception as e:
        print('commonPurge error')

# Housekeeping

def hk():
    try:
        os.system('unalias -a')
        print("All aliases have been removed.")
        os.system('sudo usermod -L root')
        print("Root account has been locked.")
        os.system('chmod 640 .bash_history')
        print("Bash history file permissions set.")
        os.system('sudo chmod 604 /etc/shadow')
        print("Read/Write permissions on shadow have been set.")
        print("Check for any user folders that do not belong to any users.")
        os.system('ls -a /home/ >> ~/Desktop/Script.log')
        print("Check for any files for users that should not be administrators.")
        os.system('ls -a /etc/sudoers.d >> ~/Desktop/Script.log')
        os.system('cp /etc/rc.local ~/Desktop/backups/')
        os.system('echo > /etc/rc.local')
        os.system('echo "exit 0" >> /etc/rc.local')
        print("Any startup scripts have been removed.")
        os.system('find /bin/ -name "*.sh" -type f -delete')
        print("Scripts in /bin have been removed.")
        print('housekeeping done')
    except Exception as e:
        print('housekeeping error')

# Logs

def lg():
    try:
        logs_dir = os.path.expanduser("~/Desktop/logs")
        os.makedirs(logs_dir, exist_ok=True)
        os.system(f"chmod 777 {logs_dir}")
        print("Logs folder has been created on the Desktop.")
        os.system(f"cp /etc/services {logs_dir}/allports.log")
        os.system(f"chmod 777 {logs_dir}/allports.log")
        print("All ports log has been created.")
        os.system(f"dpkg -l > {logs_dir}/packages.log")
        os.system(f"chmod 777 {logs_dir}/packages.log")
        print("All packages log has been created.")
        os.system(f"apt-mark showmanual > {logs_dir}/manuallyinstalled.log")
        os.system(f"chmod 777 {logs_dir}/manuallyinstalled.log")
        print("All manually installed packages log has been created.")
        os.system(f"service --status-all > {logs_dir}/allservices.txt")
        os.system(f"chmod 777 {logs_dir}/allservices.txt")
        print("All running services log has been created.")
        os.system(f"ps ax > {logs_dir}/processes.log")
        os.system(f"chmod 777 {logs_dir}/processes.log")
        print("All running processes log has been created.")
        os.system(f"ss -l > {logs_dir}/socketconnections.log")
        os.system(f"chmod 777 {logs_dir}/socketconnections.log")
        print("All socket connections log has been created.")
        os.system(f"sudo netstat -tlnp > {logs_dir}/listeningports.log")
        os.system(f"chmod 777 {logs_dir}/listeningports.log")
        print("All listening ports log has been created.")
        os.system(f"cp /var/log/auth.log {logs_dir}/auth.log")
        os.system(f"chmod 777 {logs_dir}/auth.log")
        print("Auth log has been created.")
        os.system(f"cp /var/log/syslog {logs_dir}/syslog.log")
        os.system(f"chmod 777 {logs_dir}/syslog.log")
        print("System log has been created.")
    except Exception as e:
        print('log error')

# Main Method
def mainer():
    try:       
        fire()
        pas()
        disable_root_login()
        manage_users()
        # Not Working atm and is breaking the program
        #manage_nonessential_programs()
        sysctl()
        remove_files()
        lightDmStuff()
        sdw()
        createUsers()
        antivirus()
        lg()
        hk()
        upd()
        commonPurge()
        print('Done!')
        print('System Settings>software * updates>Updates and turn on Automatically Updates')
        os.system('sudo restart lightdm')
    except Exception as e:
        print('main error')

mainer()