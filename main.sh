#!/bin/bash

FILENAME=${1:-users.txt}

# Users to keep in system.
KEEP_USERS=(root sys network service daemon bin sync shutdown halt mail ftp nobody _apt sudo messagebus man)

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

firewallFun(){
	printf "\033[1;31mSetting up firewall...\033[0m\n"
	#--------- Setup Firewall ----------------
	#Please verify that the firewall wont block any services, such as an Email server, when defaulted.
	#I will back up iptables for you in and put it in /iptables/rules.v4.bak and /iptables/rules.v6.bak
	#Uninstall UFW and install iptables
	apt-get remove -y ufw
	apt-get install -y iptables
	apt-get install -y iptables-persistent
	#Backup
	mkdir /iptables/
	touch /iptables/rules.v4.bak
	touch /iptables/rules.v6.bak
	iptables-save > /iptables/rules.v4.bak
	ip6tables-save > /iptables/rules.v6.bak
	#Clear out and default iptables
	iptables -t nat -F
	iptables -t mangle -F
	iptables -t nat -X
	iptables -t mangle -X
	iptables -F
	iptables -X
	iptables -P INPUT DROP
	iptables -P FORWARD DROP
	iptables -P OUTPUT ACCEPT
	ip6tables -t nat -F
	ip6tables -t mangle -F
	ip6tables -t nat -X
	ip6tables -t mangle -X
	ip6tables -F
	ip6tables -X
	ip6tables -P INPUT DROP
	ip6tables -P FORWARD DROP
	ip6tables -P OUTPUT DROP
	#Block Bogons
	printf "\033[1;31mEnter primary internet interface: \033[0m\n"
	read interface
	#Blocks bogons going into the computer
	iptables -A INPUT -s 127.0.0.0/8 -i $interface -j DROP
	iptables -A INPUT -s 0.0.0.0/8 -j DROP
	iptables -A INPUT -s 100.64.0.0/10 -j DROP
	iptables -A INPUT -s 169.254.0.0/16 -j DROP
	iptables -A INPUT -s 192.0.0.0/24 -j DROP
	iptables -A INPUT -s 192.0.2.0/24 -j DROP
	iptables -A INPUT -s 198.18.0.0/15 -j DROP
	iptables -A INPUT -s 198.51.100.0/24 -j DROP
	iptables -A INPUT -s 203.0.113.0/24 -j DROP
	iptables -A INPUT -s 224.0.0.0/3 -j DROP
	#Blocks bogons from leaving the computer
	iptables -A OUTPUT -d 127.0.0.0/8 -o $interface -j DROP
	iptables -A OUTPUT -d 0.0.0.0/8 -j DROP
	iptables -A OUTPUT -d 100.64.0.0/10 -j DROP
	iptables -A OUTPUT -d 169.254.0.0/16 -j DROP
	iptables -A OUTPUT -d 192.0.0.0/24 -j DROP
	iptables -A OUTPUT -d 192.0.2.0/24 -j DROP
	iptables -A OUTPUT -d 198.18.0.0/15 -j DROP
	iptables -A OUTPUT -d 198.51.100.0/24 -j DROP
	iptables -A OUTPUT -d 203.0.113.0/24 -j DROP
	iptables -A OUTPUT -d 224.0.0.0/3 -j DROP
	#Blocks outbound from source bogons - A bit overkill
	iptables -A OUTPUT -s 127.0.0.0/8 -o $interface -j DROP
	iptables -A OUTPUT -s 0.0.0.0/8 -j DROP
	iptables -A OUTPUT -s 100.64.0.0/10 -j DROP
	iptables -A OUTPUT -s 169.254.0.0/16 -j DROP
	iptables -A OUTPUT -s 192.0.0.0/24 -j DROP
	iptables -A OUTPUT -s 192.0.2.0/24 -j DROP
	iptables -A OUTPUT -s 198.18.0.0/15 -j DROP
	iptables -A OUTPUT -s 198.51.100.0/24 -j DROP
	iptables -A OUTPUT -s 203.0.113.0/24 -j DROP
	iptables -A OUTPUT -s 224.0.0.0/3 -j DROP
	#Block receiving bogons intended for bogons - Super overkill
	iptables -A INPUT -d 127.0.0.0/8 -i $interface -j DROP
	iptables -A INPUT -d 0.0.0.0/8 -j DROP
	iptables -A INPUT -d 100.64.0.0/10 -j DROP
	iptables -A INPUT -d 169.254.0.0/16 -j DROP
	iptables -A INPUT -d 192.0.0.0/24 -j DROP
	iptables -A INPUT -d 192.0.2.0/24 -j DROP
	iptables -A INPUT -d 198.18.0.0/15 -j DROP
	iptables -A INPUT -d 198.51.100.0/24 -j DROP
	iptables -A INPUT -d 203.0.113.0/24 -j DROP
	iptables -A INPUT -d 224.0.0.0/3 -j DROP
	iptables -A INPUT -i lo -j ACCEPT
	#Least Strict Rules
	#iptables -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
	#Strict Rules -- Only allow well known ports (1-1022)
	#iptables -A INPUT -p tcp --match multiport --sports 1:1022 -m conntrack --ctstate ESTABLISHED -j ACCEPT
	#iptables -A INPUT -p udp --match multiport --sports 1:1022 -m conntrack --ctstate ESTABLISHED -j ACCEPT
	#iptables -A OUTPUT -p tcp --match multiport --dports 1:1022 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
	#iptables -A OUTPUT -p udp --match multiport --dports 1:1022 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
	#iptables -A OUTPUT -o lo -j ACCEPT
	#iptables -P OUTPUT DROP
	#Very Strict Rules - Only allow HTTP/HTTPS, NTP and DNS
	iptables -A INPUT -p tcp --sport 80 -m conntrack --ctstate ESTABLISHED -j ACCEPT
	iptables -A INPUT -p tcp --sport 443 -m conntrack --ctstate ESTABLISHED -j ACCEPT
	iptables -A INPUT -p tcp --sport 53 -m conntrack --ctstate ESTABLISHED -j ACCEPT
	iptables -A INPUT -p udp --sport 53 -m conntrack --ctstate ESTABLISHED -j ACCEPT
	iptables -A OUTPUT -p tcp --dport 80 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
	iptables -A OUTPUT -p tcp --dport 443 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
	iptables -A OUTPUT -p tcp --dport 53 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
	iptables -A OUTPUT -p udp --dport 53 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
	iptables -A OUTPUT -o lo -j ACCEPT
	iptables -P OUTPUT DROP
	mkdir /etc/iptables/
	touch /etc/iptables/rules.v4
	touch /etc/iptables/rules.v6
	iptables-save > /etc/iptables/rules.v4
	ip6tables-save > /etc/iptables/rules.v6
	cont
}

firewallFun

printf "\033[1;31mMaking Sysctl Secure...\033[0m\n"
#--------- Secure /etc/sysctl.conf ----------------
sysctl -w net.ipv4.tcp_syncookies=1
sysctl -w net.ipv4.ip_forward=0
sysctl -w net.ipv4.conf.all.send_redirects=0
sysctl -w net.ipv4.conf.default.send_redirects=0
sysctl -w net.ipv4.conf.all.accept_redirects=0
sysctl -w net.ipv4.conf.default.accept_redirects=0
sysctl -w net.ipv4.conf.all.secure_redirects=0
sysctl -w net.ipv4.conf.default.secure_redirects=0
sysctl -p
cont

printf "\033[1;31mDeleting dangerous files...\033[0m\n"
#--------- Delete Dangerous Files ----------------
find / -name '*.mp3' -type f -delete
find / -name '*.mov' -type f -delete
find / -name '*.mp4' -type f -delete
find / -name '*.avi' -type f -delete
find / -name '*.mpg' -type f -delete
find / -name '*.mpeg' -type f -delete
find / -name '*.flac' -type f -delete
find / -name '*.m4a' -type f -delete
find / -name '*.flv' -type f -delete
find / -name '*.ogg' -type f -delete
find /home -name '*.gif' -type f -delete
find /home -name '*.png' -type f -delete
find /home -name '*.jpg' -type f -delete
find /home -name '*.jpeg' -type f -delete
cd / && ls -laR 2> /dev/null | grep rwxrwxrwx | grep -v "lrwx" &> /tmp/777s
cont
printf "\033[1;31m777 (Full Permission) Files : \033[0m\n"
printf "\033[1;31mConsider changing the permissions of these files\033[0m\n"
cat /tmp/777s
cont

sudo reboot
