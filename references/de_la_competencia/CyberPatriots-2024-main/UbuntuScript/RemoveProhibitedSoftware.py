import subprocess

from LoggerClass import Logger
from Util import ask


def remove_prohibited(logger: Logger):
    logger.logH1("REMOVING PROHIBITED SOFTWARE")

    def check_software_installed(pkg):
        try:
            subprocess.run(["dpkg", "-l", pkg], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            return True
        except subprocess.CalledProcessError:
            return False

    def purge_software(pkgs):
        try:
            subprocess.run(["sudo", "apt-get", "purge", "-y"] + pkgs, check=True)
            logger.logChange(f"Packages {' '.join(pkgs)} have been purged from the system.")
        except subprocess.CalledProcessError as e:
            logger.logChange(f"An error occurred while trying to remove packages {' '.join(pkgs)}: {e}")

    package_arr = {
        "john": ["john", "john-data"],
        "telnetd": ["openbsd-inetd", "telnetd"],
        "logkeys": ["logkeys"],
        "hydra": ["hydra-gtk", "hydra"],
        "fakeroot": ["fakeroot"],
        "nmap": ["nmap", "zenmap"],
        "crack": ["crack", "crack-common"],
        "medusa": ["libssh2-1", "medusa"],
        "nikto": ["nikto"],
        "tightvnc": ["xtightvncviewer"],
        "bind9": ["bind9", "bind9utils"],
        "avahi": ["avahi-autoipd", "avahi-daemon", "avahi-utils"],
        "cups": ["cups", "cups-core-drivers", "printer-driver-hpcups", "indicator-printers", "printer-driver-splix",
                 "hplip", "printer-driver-gutenprint", "bluez-cups", "printer-driver-postscript-hp",
                 "cups-server-common",
                 "cups-browsed", "cups-bsd", "cups-client", "cups-common", "cups-daemon", "cups-ppdc", "cups-filters",
                 "cups-filters-core-drivers", "printer-driver-pxljr", "printer-driver-foo2zjs", "foomatic-filters",
                 "cups-pk-helper"],
        "postfix": ["postfix"],
        "nginx": ["nginx", "nginx-core", "nginx-common"],
        "frostwire": ["frostwire"],
        "vuze": ["azureus", "vuze"],
        "samba": ["samba", "samba-common", "samba-common-bin"],
        "apache2": ["apache2", "apache2.2-bin"],
        "ftp": ["ftp"],
        "vsftpd": ["vsftpd"],
        "netcat": ["netcat-traditional", "netcat-openbsd"],
        "openssh": ["openssh-server", "openssh-client", "ssh"],
        "weplab": ["weplab"],
        "pyrit": ["pyrit"],
        "mysql": ["mysql-server", "php5-mysql"],
        "php5": ["php5"],
        "proftpd-basic": ["proftpd-basic"],
        "filezilla": ["filezilla"],
        "postgresql": ["postgresql"],
        "irssi": ["irssi"],
        "wireshark": ["wireshark", "wireshark-common", "wireshark-qt", "wireshark-gtk", "libwireshark-data",
                      "libwireshark13"],
        "libpcap": ["libpcap-dev", "libpcap0.8", "libpcap0.8-dev", "libpcap0.9", "libpcap0.9-dev"],
        "metasploit": ["metasploit-framework"],
        "dirb": ["dirb"],
        "aircrack-ng": ["aircrack-ng"],
        "sqlmap": ["sqlmap"],
        "wifite": ["wifite"],
        "autopsy": ["autopsy"],
        "setoolkit": ["setoolkit"],
        "ncrack": ["ncrack"],
        "nmap-ncat": ["nmap-ncat"],
        "skipfish": ["skipfish"],
        "maltego": ["maltego"],
        "maltegoce": ["maltegoce"],
        "nessus": ["nessus"],
        "beef": ["beef"],
        "apktool": ["apktool"],
        "snort": ["snort"],
        "suricata": ["suricata"],
        "yersinia": ["yersinia"],
        "freeciv": ["freeciv"],
        "oph-crack": ["ophcrack"],
        "kismet": ["kismet"],
        "minetest": ["minetest"],
        "isc-dhcp-server": ["isc-dhcp-server"],
        "dhcp3-server": ["dhcp3-server"],
        "slapd": ["slapd"],
        "nfs-kernel-server": ["nfs-kernel-server"],
        "dovecot-imapd": ["dovecot-imapd"],
        "dovecot-pop3d": ["dovecot-pop3d"],
        "dovecot-common": ["dovecot-common"],
        "squid": ["squid"],
        "snmp": ["snmp"],
        "nis": ["nis"],
        "rsh-client": ["rsh-client"],
        "talk": ["talk"],
        "telnet": ["telnet"],
        "ldap-utils": ["ldap-utils"],
        "rpcbind": ["rpcbind"],
        "rsync": ["rsync", "backuppc-rsync"],
        "deluge": ["deluge-common", "deluge-gtk"]
    }

    for software_name, packages in package_arr.items():
        packages_to_remove = []
        for package in packages:
            if check_software_installed(package):
                packages_to_remove.append(package)

        if packages_to_remove:
            logger.logChange(
                f"The following packages related to {software_name} are installed: {', '.join(packages_to_remove)}")
            if ask(f"Do you want to remove {software_name}?"):
                purge_software(packages_to_remove)
        else:
            logger.logChange(f"No packages related to {software_name} are installed.")
    logger.logHEnd()