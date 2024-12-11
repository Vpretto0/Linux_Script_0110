import os
import pwd
import subprocess
import tempfile

from LoggerClass import Logger


def is_user_in_group(user, group):
    result = subprocess.run(['getent', 'group', group], capture_output=True, text=True)
    if result.returncode == 0:
        group_info = result.stdout.strip()
        users_in_group = group_info.split(':')[3]
        return user in users_in_group.split(',')
    else:
        return False


def user_audit(user_path, admin_path, logger: Logger):
    logger.logH1("USER AUDITING")
    # Initialize paths
    with open(user_path, 'r') as file:
        users = set(file.read().splitlines())
        users.add('nobody')
    with open(admin_path, 'r') as file:
        lines = file.read().splitlines()
        admins = set(lines)
        sudo_user = lines[0]
    with open('/etc/passwd', 'r') as file:
        passwd_lines = file.readlines()

    # Filter out system users and collect information about users, include us
    system_users = set()
    normal_users = set()
    for line in passwd_lines:
        if not line.startswith('#'):
            username = line.split(':')[0]
            if int(line.split(':')[2]) >= 1000:
                normal_users.add(username)
            else:
                system_users.add(username)
    normal_users.remove('nobody')
    system_users.add('nobody')
    # Check user home directories and shells
    for user in normal_users:
        try:
            # Fetch the user entry using pwd module
            user_info = pwd.getpwnam(user)
            home_directory = user_info.pw_dir
            user_shell = user_info.pw_shell
            correct_home_directory = f"/home/{user}"
            correct_shell = "/bin/bash"

            # Check if the home directory is correct
            if home_directory != correct_home_directory:
                logger.logChange(f"Home directory for {user} is incorrect. Correcting to {correct_home_directory}.")
                subprocess.run(['usermod', '-d', correct_home_directory, user], stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL)

            # Check if the user shell is correct
            if user_shell != correct_shell:
                logger.logChange(f"Shell for {user} is incorrect. Changing to {correct_shell}.")
                subprocess.run(['usermod', '-s', correct_shell, user], stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL)

        except KeyError:
            # This means the user doesn't exist in the pwd database
            continue

    logger.logHEnd()

    # Find unauthorized users and comment out their lines in /etc/passwd
    logger.logH2("Removing unauthorized users...")
    unauthorized_users = normal_users - users - admins
    if unauthorized_users:
        # Create a temporary file
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as temp_file:
            for line in passwd_lines:
                username = line.split(':')[0]
                if username in unauthorized_users:
                    temp_file.write('#' + line)
                    normal_users.remove(username)
                    logger.logChange(f"Disabled unauthorized user: {username}")
                else:
                    temp_file.write(line)

            temp_filename = temp_file.name
            os.chmod(temp_filename, 0o644)
            os.chown(temp_filename, 0, 0)
        # Rename the temporary file to replace the original /etc/passwd
        os.rename(temp_filename, '/etc/passwd')
    logger.logHEnd()

    # Audit admin permissions
    # NOT WORKING, PASSWORD DOESNT CHANGE
    logger.logH2("Checking user permissions...")
    for user in normal_users:
        if user in users:
            # Check if user is in adm group before removing
            if is_user_in_group(user, 'adm'):
                subprocess.run(['gpasswd', '-d', user, 'adm'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                logger.logChange(f"Removed {user} from adm group")

            # Check if user is in sudo group before removing
            if is_user_in_group(user, 'sudo'):
                subprocess.run(['gpasswd', '-d', user, 'sudo'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                logger.logChange(f"Removed {user} from sudo group")

        if user in admins:
            # Check if admin is not in adm group before adding
            if not is_user_in_group(user, 'adm'):
                subprocess.run(['gpasswd', '-a', user, 'adm'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                logger.logChange(f"Added {user} to adm group")

            # Check if admin is not in sudo group before adding
            if not is_user_in_group(user, 'sudo'):
                subprocess.run(['gpasswd', '-a', user, 'sudo'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                logger.logChange(f"Added {user} to sudo group")
    logger.logHEnd()

    # Change to secure password
    logger.logH2("Changing passwords...")
    password = 'Cyb3rPatri0t!'
    all_users = users.union(admins)
    all_users.add('root')
    all_users.remove('nobody')
    all_users.remove(sudo_user)
    for user in all_users:
        user_password_pair = f"{user}:{password}"
        result = subprocess.run(
            ['chpasswd'],
            input=user_password_pair.encode(),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )
        if result.returncode == 0:
            logger.logChange(f"Password changed for {user}")
        else:
            logger.logChange(f"Failed to change password for {user}. Error: {result.stderr.decode()}")
    logger.logHEnd()