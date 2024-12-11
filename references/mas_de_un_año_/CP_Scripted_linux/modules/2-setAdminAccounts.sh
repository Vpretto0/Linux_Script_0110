#!/usr/bin/env bash

# Get users on system
allUsersString=$(getent passwd | grep -P '^(?=.*\/bin\/bash)(?=.*\/home\/)' | cut -d: -f1)

# Turn users string into array
IFS=$'\n'
while read -r line; do
    allUsers+=("$line")
done <<< "$allUsersString"
IFS=' '

# Get valid admin users
read -p "Enter which accounts should be admin. Example: account1,account2: " response
adminsList=($(echo $response | tr "," "\n"))

for userName in "${allUsers[@]}"; do
    # Remove all users from outdated "admins" list
    deluser $userName admin

    # Check if account should exist on the system
    if [[ ${adminsList[@]} =~ $userName ]]
    then
        sudo adduser $userName sudo

        echo ""
        echo "+ Admin has been given to: $userName"
        echo ""
    else
        sudo deluser $userName sudo

        echo ""
        echo "- Admin has been revoked from: $userName"
        echo ""
    fi
done