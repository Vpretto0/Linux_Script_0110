#!/usr/bin/env bash

# Get users on system
allUsersString=$(getent passwd | grep -P '^(?=.*\/bin\/bash)(?=.*\/home\/)' | cut -d: -f1)

# Turn users string into array
IFS=$'\n'
while read -r line; do
    allUsers+=("$line")
done <<< "$allUsersString"
IFS=' '

# Get valid users
read -p "Enter which accounts should exist on the system. Example: account1,account2: " response
validUsers=($(echo $response | tr "," "\n"))

for userName in "${allUsers[@]}"; do
    # Check if account should exist on the system
    if [[ ! ${validUsers[@]} =~ $userName ]]
    then
        # Delete user from system
        sudo userdel -r $userName

        echo ""
        echo "- User has been deleted: $userName"
        echo ""
    fi
done