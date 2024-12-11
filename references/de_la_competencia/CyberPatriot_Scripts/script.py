from colorama import Fore, Back, Style
import os, subprocess, errno, grp, pwd
from math import *
from time import sleep

printLog = ""

def reprint(limit=True):
    os.system("clear")
    
    num = int(os.get_terminal_size()[0])
    
    print("\033[4m" + Style.BRIGHT + Style.DIM + "ᶜʸᵇᵉʳᵖᵃᵗʳᶦᵒᵗˢ ˢᶜʳᶦᵖᵗ" +("·" * (num - 30)) + "ᵇʸ ʳᶦˢʰᵃᵇʰ" + Style.RESET_ALL)
    
    if limit == True:
        try:

            print('\n'.join(printLog.split("\n")[-os.get_terminal_size()[1] + 3:]) + Style.RESET_ALL)
            return
        except IndexError as e:
            pass
    print(printLog + Style.RESET_ALL)

def breakL():
    global printLog
    printLog += "\n"
    reprint()

def warn(text, tab=0):
    global printLog
    printLog += Style.BRIGHT + Fore.LIGHTYELLOW_EX + "  " * tab + "[-] " + Style.RESET_ALL + Fore.LIGHTYELLOW_EX + text + "\n"
    reprint()
    
def error(text, tab=0):
    global printLog
    printLog += Style.BRIGHT + Fore.LIGHTRED_EX + "  " * tab + "[#] " + Style.RESET_ALL + Fore.LIGHTRED_EX + text + "\n"
    reprint()
    
def success(text, tab=0):
    global printLog
    printLog += Style.BRIGHT + Fore.GREEN + "  " * tab + "[!] " + Style.RESET_ALL + Fore.GREEN + text + "\n"
    reprint()
    
def info(text, tab=0):
    global printLog
    printLog += Style.BRIGHT + Fore.CYAN + "  " * tab + "[~] " + Style.RESET_ALL + Fore.CYAN + text + "\n"
    reprint()
    
def request(text, tab=0):
    global printLog
    text = Style.BRIGHT + Fore.YELLOW + "  " * tab + "[?] " + Style.RESET_ALL + Fore.YELLOW + text + Style.RESET_ALL

    result = input("\033[F" + text + " ")
    printLog += text + " " + result + "\n"
    return result
    
if os.geteuid() != 0:
    error("Run as root!")
else:

    success("Read the README while doing this, and PLEASE do not do anything terminal related (unless deleting files that i say to delete).")
    error("KEEP THIS OPEN IT WILL ASK FOR RESPONSES FROM YOU OFTEN", tab=1)
    breakL()

    ### UFW ###

    info("Checking if UFW is installed...")

    try:
        subprocess.call(["ufw"], stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
        success("UFW is installed!", tab=1)
    except FileNotFoundError as e:

        if e.errno == errno.ENOENT:
            warn("UFW is not installed, will install..", tab=1)
            subprocess.call(["sudo", "apt", "install", "ufw", "-y"], stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
            success("Installed UFW!", tab=2)

    info("Enabling UFW..")

    subprocess.call(["sudo", "ufw", "enable"], stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
    success("Enabled!", tab=1)
    breakL()

    ### SSH ###

    info("Installing ssh...")


    subprocess.call(["sudo", "apt", "get", "install", "openssh-server", "openssh-client", "-y"], stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
    success("SSH is installed!", tab=1)

    info("Disabling root access to ssh...")

    nfile = ""

    with open("/etc/ssh/sshd_config", 'r+') as f:
        f.seek(0)
        
        for line in f.readlines():
            if "PermitRootLogin" in line.strip():
                line = "PermitRootLogin no\n"
            nfile += line
            
            
    with open("/etc/ssh/sshd_config", "w") as f:
        f.seek(0)
        f.write(nfile)

    success("Done!", tab=1)
    breakL()
    ### SERVICES ###
    doS = request("Do services?")

    if len(doS) > 0 and doS.lower()[0] == "y":

        info("Getting services...")

        serviceList = subprocess.run(["service", "--status-all"], stdout=subprocess.PIPE).stdout.decode("utf-8")
        serviceList = ("".join(serviceList.split(" "))).split("\n")
        serviceList = serviceList[:-1]

        for i in range(len(serviceList)):
            service = serviceList[i]
            status = service.split("]")[0].replace("[", "")
            serviceName = service.split("[" + status + "]")[-1]
            info(serviceName, tab=1)
            out = request("Remove" + ("? (default=no)" if i == 0 else "?"), tab=2)
            
            if len(out) > 0 and out.lower()[0] == "y":

                packageNames = subprocess.run("dpkg -s " + serviceName + " | grep '^Package: '", stdout=subprocess.PIPE, shell=True).stdout.decode("utf-8")

                packageNames = packageNames.strip().split("\n")
                fn = "Possible package names: "
                for ii in range(len(packageNames)):
                    package = packageNames[ii]
                    packageName = package.split("Package: ")[-1]
                    fn += packageName + ", "
                fn = fn[:-2]
                success(fn, tab=3)
                info("Please manually remove (for safety)!", tab=3)
    breakL()
                

    ### ASSETS ###

    info("Searching for unauthorized files...")
    def run_fast_scandir(dir, ext): 
        subfolders, files = [], []

        for f in os.scandir(dir):
            if f.is_dir():
                subfolders.append(f.path)
            if f.is_file():
                if os.path.splitext(f.name)[1].lower() in ext:
                    files.append(f.path)


        for dir in list(subfolders):
            sf, f = run_fast_scandir(dir, ext)
            subfolders.extend(sf)
            files.extend(f)
            
        return subfolders, files

    sleep(1) # rest buddy
    files = run_fast_scandir("/home/", [".jpg", ".png", ".gif", ".webp", ".mp4", ".mp3", ".wav", ".mkv"])[1]

    if len(files) == 0:
        success("None found", tab=2)

    for i in range(len(files)):
        success(files[i], tab=1)
        
    breakL()

    ### USERS ###

    info("Installing dependencies for this part...")

    info("Searching for unauthorized files...")
    subprocess.Popen(["sudo", "apt-get", "install", "xclip", "xsel", "-y"], stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT).wait()
    success("Done!", tab=1)
    breakL()

    info("Copy user data into clipboard (including Authorized Administrators...")
    error("DO NOT PASTE IT, JUST COPY", tab=1)
    request("Done?", tab=1)


    p = subprocess.Popen(['xclip','-selection', 'clipboard', '-o'], stdout=subprocess.PIPE)
    retcode = p.wait()
    usersS = p.stdout.read().decode("utf-8")

    admins = []
    users = []

    userSplit = usersS.split("\n")

    lastUser = ""
    me = ""
    sec = "admin"

    for i in range(len(userSplit)):
        user = userSplit[i]

        if len(user.strip()) == 0: continue
        if "authorized administrators:" in user.lower(): continue
        
        if "authorized users" in user.lower():
            sec = "users"
            continue
            
        if "(you)" in user:
            lastUser = False
            me = user.split(" (")[0]
            continue

        if "password" in user:
            if lastUser == False: continue
            admins.append((lastUser, user.split("password: ")[-1]))
        else:
            if sec == "admin":
                lastUser = user.split(" (")[0]
                users.append(lastUser)
            else:
                users.append(user)

    p = subprocess.Popen(["awk -F: '($3>=1000)&&($3<60000)&&($1!=\"nobody\"){print $1}' /etc/passwd"], shell=True, stdout=subprocess.PIPE)
    retcode = p.wait()
    allUsers = p.stdout.read().decode("utf-8").split("\n")

    info("Promoting admins...")

    for i in range(len(admins)):
        subprocess.call("sudo adduser " + admins[i][0] + " sudo", shell=True)
        subprocess.call("sudo adduser " + admins[i][0] + " adm", shell=True)
        success(admins[i][0], tab=1)

        
    info("Changing all user passwords...")
        
    for i in range(len(users)):
        process = subprocess.Popen("sudo passwd " + users[i], shell=True, stdin=subprocess.PIPE)
        
        process.stdin.write((u'%(p)s\n%(p)s\n' % { 'p': "CyberPatriotsUbuntu!!"}).encode('utf-8'))
        process.stdin.flush()
        
        success(users[i], tab=1)
        
        
    error("All user passwords (except you) is (CyberPatriotsUbuntu!!)", tab=1)
    info("There are no parenthesis in the password. And yes, both exclamations.", tab=2)

    info("Removing/Demoting invalid accounts...")

    for i in range(len(allUsers)):
        aUser = allUsers[i].strip()
        
        if not aUser in users:
            if aUser == me or len(aUser) == 0: continue
            error("Removed " + allUsers[i], tab=1)
            continue
        
        ad = subprocess.run("id -Gn " + aUser, shell=True, stdout=subprocess.PIPE).stdout.decode("utf-8")
        
        if not "sudo" in ad:
            subprocess.run("sudo deluser " + aUser + " sudo", shell=True)
            error("Demoted " + aUser, tab=1)
        
        
    ### CLOSING ###

    breakL()
    breakL()
        
    error("Please TRY do this (unreliable with script/or too simple:")
    info("Update (temporarily makes apt unusable, hard to detect)", tab=1)
    info("PAM (if I can't do without bricking it regularly, I have no faith in a script)", tab=1)
    info("Disable guest account (depends on display manager)", tab=1)
    info("Auto-updates (depends on flavor)", tab=1)

    breakL()
    breakL()
    success("GL and <3 from rishboobies")

    reprint(limit=False)