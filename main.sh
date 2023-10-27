#!/bin/bash

FILENAME=${1:-users.txt}

function generate_password() {
    local PASSWORD_LEN=20
    cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w $PASSWORD_LEN | head -n 1
}

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

for u in $(awk -F':' '{ print $1}' /etc/passwd); do
    if ! grep -q $u $FILENAME && id -u $u >/dev/null 2>&1; then
        echo "Removing user $u."
        sudo userdel -r $u
    fi
done
