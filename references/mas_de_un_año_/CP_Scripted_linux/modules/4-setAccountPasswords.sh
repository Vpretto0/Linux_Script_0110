#!/usr/bin/env bash

# Get account names and passwords
read -p "Enter which passwords accounts should have. Example: account1;password1,account2;password2: " response
usersToChange=($(echo $response | tr "," "\n"))

for userData in "${usersToChange[@]}"; do
    # Parse name and password
    parsedUserData=($(echo $userData | tr ";" "\n"))
    userToChange=${parsedUserData[0]}
    passwordToChange=${parsedUserData[1]}

    # Set user password
    echo -e "$passwordToChange\n$passwordToChange\n$passwordToChange" | sudo passwd $userToChange

    echo ""
    echo "+ User named \"${userToChange}\" has been given the password: \"${passwordToChange}\""
    echo ""
done