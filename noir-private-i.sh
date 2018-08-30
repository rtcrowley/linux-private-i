#!/bin/sh


brk=$(echo "----------------------------------------------------------------------")

title=$(echo "----------------------Linux PrivEsc Private-i-------------------------")

echo "$title"

#============
# FUNCTIONS *
#============

#==========
# Basic OS
#==========

f_os() { os=$(cat /etc/lsb-release |grep "DESCRIPTION" |cut -d '=' -f2 |tr -d '"'); echo "$os"; }

f_krel() { krel=$(uname -r); echo "$krel"; }

#=================
# Basic Networking
#=================

f_ifconfig() { interface=$(/sbin/ifconfig |grep -v TX |grep -v RX); echo "$interface"; }

f_netantp() { net_antp=$(netstat -antp); echo "$net_antp"; }

f_nettul() { net_tul=$(netstat -tul); echo "$net_tul"; }

#======
# More
#======

f_shadow_world() {
	perm_shadow=$(ls -la /etc/shadow |cut -c 7-10)
	case "$perm_shadow" in
		rw*)
		   echo "$yes - /etc/shadow is World R & W"
		   ;;
		*r*)
		   echo "$yes - /etc/shadow is World-Readable"
	   	   ;;
		*w*)
		   echo "$yes - /etc/shadow is World-Writable"
		   ;;
		*)
		   echo "$no - /etc/shadow is neither world readable nor writable"
		   ;;
	   	esac
}


f_pass_world() {
	perm_pass=$(ls -la /etc/passwd |cut -c 7-10)
	case "$perm_pass" in
		rw*)
		   echo "$yes - /etc/passwd is World R & W"
		   ;;
		*r*)
		   echo "$no - /etc/passwd is World-Readable"
	   	   ;;
		*w*)
		   echo "$yes - /etc/passwd is World-Writable"
		   ;;
		*)
		   echo "$no - /etc/passwd is neither world readable nor writable"
		   ;;
	   	esac
}



f_sudo_world() {
	perm_sudoers=$(ls -la /etc/sudoers |cut -c 7-10)
	case "$perm_sudoers" in
		rw*)
		   echo "$yes - /etc/sudoers is World R & W"
		   ;;
		*r*)
		   echo "$yes - /etc/sudoers is World-Readable"
	   	   ;;
		*w*)
		   echo "$yes - /etc/sudoers is World-Writable"
		   ;;
		*)
		   echo "$no - /etc/sudoers is neither world readable nor writable"
		   ;;
	   	esac
}

f_conf_world() {
	perm_conf=$(find /etc -type f \( -perm -o+w \) -exec ls -adl {} \; 2> /dev/null)

	     if [ -z "$perm_conf" ]; then
		   echo "$no - Nothing in /etc/ is World Writable"
	     else
		   echo "$yes - Found something in /etc/ that's World-Writable"
		   echo "$perm_conf"
	     fi

}

f_mail_world() {
	perm_mail=$(ls -l /var/mail/ |cut -c 7-10)
	case "$perm_mail" in
		rw*)
		   echo "$yes - Mail in /var/mail/ is World R & W"
		   ;;
		*r*)
		   echo "$yes - Mail in /var/mail/ is World-Readable"
	   	   ;;
		*w*)
		   echo "$yes - Mail in /var/mail/ is World-Writable"
		   ;;
		*)
		   echo "$no - Mail in /var/mail/ is neither world readable nor writable"
		   ;;
	   	esac
}


no=$(echo "[-]")
yes=$(echo "[+]")

	   echo "----------------------------OS info----------------------------------"
	   f_os
	   f_krel
	   whoami
	   id
	   echo "\nSuper users"
	   awk -F: '($3 == "0") {print}' /etc/passwd
	   echo "--------------------------Networking---------------------------------"
	   echo "ifconfig"
	   f_ifconfig
	   echo "$brk"
	   echo "TCP and UDP"
	   f_netantp
	   f_nettul
	   echo "-------------------------Vital Checks--------------------------------"
	   f_pass_world
	   f_shadow_world
	   f_sudo_world
	   f_mail_world
	   f_conf_world
	   echo "-----------------------------Misc.-----------------------------------"
	   echo "Bash history - tail"
	   tail ~/.bash_history
	   echo "\n-----------------------------Crontab-----------------------------------"
	   cat /etc/crontab |grep -v '#'
	   echo "\n---------------------------Mount Info---------------------------------"
	   df -h
	   echo "\nfstab"
	   cat /etc/fstab |grep -v '#'	   
	   
	   echo "-------------------World-Writable Directories------------------------"
	   echo "PLEASE STAND BY ..."
	   find / -xdev -type d \( -perm -0002 -a ! -perm -1000 \) -print 2> /dev/null |grep -v vmware

	   echo "---------------------World-Writable Files----------------------------"
	   find / -xdev -type f \( -perm -0002 -a ! -perm -1000 \) -print 2> /dev/null |grep -v vmware

	   
	   echo "---------Searching string 'password' in common areas-----------------"
	   grep -iRl "password" /var/www/ 2>/dev/null
	   grep -iRl "password" /var/log/ 2>/dev/null
	   grep -iRl "password" /home/ 2>/dev/null
	   grep -iRl "password" /etc/httpd/ 2>/dev/null

	   echo "---------------------Do Your Due Diligence----------------------------"
