import os
from LoggerClass import Logger
from Util import backup_then_clean_file


def sshd_harden(logger):
    if os.path.exists("/etc/ssh/sshd_config"):
        backup_then_clean_file(abs_path="/etc/ssh/sshd_config", file_name="sshd_config")
        logger.logChange(f"Clean sshd_config")


if __name__ == "__main__":
    log = Logger('logs/log.txt')
    sshd_harden(log)