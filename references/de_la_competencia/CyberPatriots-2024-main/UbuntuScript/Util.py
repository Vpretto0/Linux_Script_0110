import os
import shutil


# confirm yes or no with user before doing something
def ask(question):
    reply = str(input(question + ' (y/n): ')).lower().strip()
    if reply[0] == 'y':
        return True
    if reply[0] == 'n':
        return False
    else:
        return ask(question)


# replace line in file with a new line
def replace_line(file_path, to_replace, replace_with):
    with open(file_path, 'r') as f:
        lines = f.readlines()
    with open(file_path, 'w') as f:
        for line in lines:
            f.write(line.replace(to_replace, replace_with))


def backup_then_clean_file(abs_path, file_name):
    dest_stat = os.stat(abs_path)
    dest_perms = dest_stat.st_mode
    dest_uid = dest_stat.st_uid
    dest_gid = dest_stat.st_gid

    shutil.copy(abs_path, f"backups/{file_name}")
    shutil.copy(f"clean_files/{file_name}", abs_path)

    os.chmod(abs_path, dest_perms)
    os.chown(abs_path, dest_uid, dest_gid)