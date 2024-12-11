#!/usr/bin/env bash

# Check for proper elevation
test -f "./BypassAdmin" && shouldBypassAdminCheck=true || shouldBypassAdminCheck=false

if [[ $EUID > 0 ]] && ! $shouldBypassAdminCheck; then
    sudo "$0" "$@"
    exit $?
fi

function showMenu {
    clear

    echo "======================================================
===  CyberPatriot Team Strawberry - Linux Scripts  ===
======================================================

1) Secure system
2) Set Admin Accounts
3) Delete forbidden users
4) Set account passwords
5) Search for files
6) Scan for malware
7) Set correct display resolution
8) Show programs using ports
"
}

# Interactive Menu
while true
do
    showMenu
    read -p "Please make a selection: " choice
    echo ""
    echo "--------------------------------------------------------"
    echo ""

    case $choice in
        1) bash ./modules/1-secureSystem.sh ;;
        2) bash ./modules/2-setAdminAccounts.sh ;;
        3) bash ./modules/3-removeForbiddenUsers.sh ;;
        4) bash ./modules/4-setAccountPasswords.sh ;;
        5) bash ./modules/5-searchForFiles.sh ;;
        6) bash ./modules/6-scanForMalware.sh ;;
        7) bash ./modules/7-SetCorrectDisplayRes.sh ;;
        8) bash ./modules/8-ShowProgramsPorts.sh ;;
        q) exit ;;
        *) echo "Invalid selection. Please try again." ;;
    esac

    echo ""
    read -p "Press enter to continue...:"
done