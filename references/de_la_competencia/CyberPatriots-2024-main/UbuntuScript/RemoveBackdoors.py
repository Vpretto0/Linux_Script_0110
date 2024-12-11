import os
import subprocess

import psutil

from LoggerClass import Logger


def remove_backdoors(logger: Logger):
    logger.logH1("BACKDOORS")

    logger.logH2("Remove netcat backdoors")
    for proc in psutil.process_iter(['name', 'pid', 'exe', 'connections']):
        if proc.name() in ["nc", "netcat", "ncat"]:
            name = proc.info['name']
            pid = str(proc.info['pid'])
            exe = proc.info['exe']
            ports = []
            # Iterate over each connection object and extract the port
            for conn in proc.net_connections():
                if conn.laddr:
                    ports.append(str(conn.laddr.port))
            ports_str = ', '.join(ports)  # Create a string from the list of ports
            subprocess.call(str("cp " + exe + " backups/" + exe.rsplit('/')[-1]), shell=True)
            subprocess.call("rm " + exe, shell=True)
            subprocess.call("kill -9 " + pid, shell=True)
            # Include the ports in the log
            logger.logChange(f"Removed and backed up {name} (PID: {pid}) - {exe} - Ports: {ports_str}")
    logger.logHEnd()

    logger.logH2("Remove cronjobs")
    for file in os.listdir("/etc/cron.d"):
        if file != "README":
            subprocess.call("mv /etc/cron.d/" + file + " backups/crontab/" + file, shell=True)
            logger.logChange(f"Moved {file} cronjob")
    logger.logHEnd()