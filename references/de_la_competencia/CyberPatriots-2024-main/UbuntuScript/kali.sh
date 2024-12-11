#!/bin/bash

## login.defs
sed -i 's/PASS_MAX_DAYS.*/PASS_MAX_DAYS\o01130/' /etc/login.defs
sed -i 's/PASS_MIN_DAYS.*/PASS_MIN_DAYS\o0113/' /etc/login.defs
sed -i 's/PASS_MIN_LEN.*/PASS_MIN_LEN\o0118/' /etc/login.defs
sed -i 's/PASS_WARN_AGE.*/PASS_WARN_AGE\o0117/' /etc/login.defs

## common-password
sed -i 's/password.*\[success.*/password\o011[success=1 default=ignore]\o011pam_unix.so obscure sha512 minlen=10 remember=5/' /etc/pam.d/common-password
#sed -i '/auth.*\[success/i auth\o011required\o011\o011\o011pam_tally2.so deny=4 unlock_time=60' /etc/pam.d/common-auth

## passwords
getent passwd | while IFS=: read -r name password uid gid gecos home shell; do
    # only users that own their home directory
    if [ -d "$home" ] && [ "$(stat -c %u "$home")" = "$uid" ]; then
        # only users that have a shell, and a shell is not equal to /bin/false or /usr/sbin/nologin
        if [ "$name" != "root" ] && [ ! -z "$shell" ] && [ "$shell" != "/bin/false" ] && [ "$shell" != "/usr/sbin/nologin" ]; then
            top=${home#/}; top=${top%%/*}
            case $top in
              bin|dev|etc|lib*|no*|proc|sbin|usr|var) echo "";;
              *) echo "User $name password updated to HappyMonkey123!"
                 echo "$name:HappyMonkey123!" | chpasswd
            esac
        fi
    fi
done

