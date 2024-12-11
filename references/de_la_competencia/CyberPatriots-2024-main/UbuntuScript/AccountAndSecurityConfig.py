from LoggerClass import Logger
from Util import backup_then_clean_file


def password_config(logger: Logger):
    logger.logH1("PASSWORD CONFIG")

    logger.logH2("Login Defs")
    backup_then_clean_file(abs_path="/etc/login.defs", file_name="login.defs")
    logger.logHEnd()