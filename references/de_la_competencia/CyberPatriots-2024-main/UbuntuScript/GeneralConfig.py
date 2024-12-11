import subprocess
import os
from LoggerClass import Logger
from Util import backup_then_clean_file


def general_config(logger: Logger):
    logger.logH1("GENERAL CONFIG")
    # enable ipv4, ipv6 hardening
    if os.path.exists("/etc/sysctl.conf"):
        backup_then_clean_file(abs_path="/etc/sysctl.conf", file_name="sysctl.conf")
        logger.logChange(f"Clean sysctl.conf")

    if os.path.exists("/etc/sysctl.d/10-network-security.conf"):
        backup_then_clean_file(abs_path="/etc/sysctl.d/10-network-security.conf", file_name="10-network-security.conf")
        logger.logChange(f"Clean 10-network-security.conf")

    subprocess.call("sysctl --system", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    # disable guest account
    subprocess.call("usermod -L guest", shell=True)
    logger.logChange("Disabled guest account")

    # lightdm stuff
    if os.path.isfile("/etc/lightdm/lightdm.conf"):
        with open("/etc/lightdm/lightdm.conf", "a") as file:
            file.write("autologin-guest=false\n")
            file.write("allow-guest=false\n")
            file.write("greeter-hide-users=true\n")
        logger.logChange("Secured lightdm")

    logger.logHEnd()


if __name__ == "__main__":
    log = Logger('logs/log.txt')
    general_config(log)