#!/bin/bash

FILENAME=${1:-users.txt}

# Users to keep in system.
KEEP_USERS=(root sys network service daemon bin sync shutdown halt mail ftp nobody)

# To generate random passwords.
function generate_password() {
    local PASSWORD_LEN=20
    cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w $PASSWORD_LEN | head -n 1
}

# Create a new user or change the password of existing user.
function create_or_update_user() {
    local USERNAME=${1}
    local PASSWORD=$(generate_password)
    if id -u "$USERNAME" >/dev/null 2>&1; then
        echo "User $USERNAME exists, changing password."
        echo "$USERNAME:$PASSWORD" | sudo chpasswd
    else
        echo "User $USERNAME does not exist, creating user with new password."
        sudo useradd -m "$USERNAME"
        echo "$USERNAME:$PASSWORD" | sudo chpasswd
    fi
}

while IFS= read -r line; do
    if [ ! -z "$line" ]; then
        create_or_update_user "$line"
    fi
done < "$FILENAME"

# Remove users not in the file, or the KEEP_USERS array.
for u in $(awk -F':' '{ print $1}' /etc/passwd); do
    if ! grep -q $u $FILENAME && id -u $u >/dev/null 2>&1 && ! printf '%s\n' ${KEEP_USERS[@]} | grep -q -P '^'$u'$'; then
        echo "Removing user $u."
        sudo userdel -r $u
    fi
done

sudo apt-get remove wireshark
sudo apt-get remove ophcrack
sudo apt-get autoremove

sudo apt update
sudo apt upgrade

sudo reboot
