import os
import subprocess
from termcolor import colored

# Helper function to run shell commands
def run_command(command):
    try:
        result = subprocess.run(command, shell=True, text=True, capture_output=True)
        return result.stdout.strip(), result.returncode
    except Exception as e:
        return str(e), 1

# Helper function to print results with color
def print_result(task, status, message):
    if status == "Secure":
        print(colored(f"[SECURE] {task}: {message}", "green"))
    elif status == "Insecure":
        print(colored(f"[INSECURE] {task}: {message}", "red"))
    else:
        print(colored(f"[ERROR] {task}: {message}", "yellow"))

def verify_password_policy():
    print("\nVerifying Password Policies...")
    # Check minimum password length
    stdout, _ = run_command("grep 'minlen=10' /etc/pam.d/common-password")
    if "minlen=10" in stdout:
        print_result("Password Length", "Secure", "Minimum password length is set to 10.")
    else:
        print_result("Password Length", "Insecure", "Minimum password length is not set to 10.")

    # Check null password disabled
    stdout, _ = run_command("grep 'nullok' /etc/pam.d/common-auth")
    if "nullok" in stdout:
        print_result("Null Passwords", "Insecure", "Null passwords are allowed.")
    else:
        print_result("Null Passwords", "Secure", "Null passwords are disabled.")

    # Check account lockout policy
    stdout, _ = run_command("grep 'pam_faillock.so' /etc/pam.d/common-auth")
    if "deny=3" in stdout and "unlock_time=600" in stdout:
        print_result("Account Lockout", "Secure", "Account lockout policy is enforced.")
    else:
        print_result("Account Lockout", "Insecure", "Account lockout policy is not enforced.")

def verify_ssh_configuration():
    print("\nVerifying SSH Configuration...")
    # Check if PermitRootLogin is set to no
    stdout, _ = run_command("grep '^PermitRootLogin no' /etc/ssh/sshd_config")
    if "PermitRootLogin no" in stdout:
        print_result("SSH Root Login", "Secure", "Root login is disabled.")
    else:
        print_result("SSH Root Login", "Insecure", "Root login is not disabled.")

    # Check if empty passwords are disabled
    stdout, _ = run_command("grep '^PermitEmptyPasswords no' /etc/ssh/sshd_config")
    if "PermitEmptyPasswords no" in stdout:
        print_result("SSH Empty Passwords", "Secure", "Empty passwords are disabled for SSH.")
    else:
        print_result("SSH Empty Passwords", "Insecure", "Empty passwords are allowed for SSH.")

def verify_file_permissions():
    print("\nVerifying File Permissions...")
    # Check permissions on /etc/shadow
    stdout, _ = run_command("stat -c '%a' /etc/shadow")
    if stdout.strip() == "640":
        print_result("/etc/shadow Permissions", "Secure", "Permissions are set to 640.")
    else:
        print_result("/etc/shadow Permissions", "Insecure", f"Permissions are {stdout}, expected 640.")

def verify_network_settings():
    print("\nVerifying Network Settings...")
    # Check TCP SYN cookies
    stdout, _ = run_command("sysctl net.ipv4.tcp_syncookies")
    if "net.ipv4.tcp_syncookies = 1" in stdout:
        print_result("TCP SYN Cookies", "Secure", "TCP SYN cookies are enabled.")
    else:
        print_result("TCP SYN Cookies", "Insecure", "TCP SYN cookies are not enabled.")

    # Check IP forwarding
    stdout, _ = run_command("sysctl net.ipv4.ip_forward")
    if "net.ipv4.ip_forward = 0" in stdout:
        print_result("IP Forwarding", "Secure", "IP forwarding is disabled.")
    else:
        print_result("IP Forwarding", "Insecure", "IP forwarding is enabled.")

def verify_services():
    print("\nVerifying Services...")
    # Check if Nginx is disabled
    stdout, _ = run_command("systemctl is-enabled nginx")
    if "disabled" in stdout:
        print_result("Nginx Service", "Secure", "Nginx is disabled.")
    else:
        print_result("Nginx Service", "Insecure", "Nginx is enabled.")

    # Check if vsftpd is disabled
    stdout, _ = run_command("systemctl is-enabled vsftpd")
    if "disabled" in stdout:
        print_result("FTP Service (vsftpd)", "Secure", "FTP server is disabled.")
    else:
        print_result("FTP Service (vsftpd)", "Insecure", "FTP server is enabled.")

def verify_firewall():
    print("\nVerifying Firewall...")
    # Check if UFW is enabled
    stdout, _ = run_command("sudo ufw status")
    if "Status: active" in stdout:
        print_result("UFW Firewall", "Secure", "UFW is active and enabled.")
    elif "inactive" in stdout:
        print_result("UFW Firewall", "Insecure", "UFW is inactive.")
    else:
        print_result("UFW Firewall", "Error", f"Unexpected UFW status output: {stdout}")

def main():
    print(colored("System Hardening Verification Script", "blue", attrs=["bold"]))
    verify_password_policy()
    verify_ssh_configuration()
    verify_file_permissions()
    verify_network_settings()
    verify_services()
    verify_firewall()

if __name__ == "__main__":
    main()
