#!/bin/bash

noco='\033[0m'
blk='\033[0;30m'
red='\033[0;31m'
grn='\033[0;32m'
blu='\033[0;34m'
purp='\033[0;35m'
cyn='\033[0;36m'
gray='\033[00;37m'
wht='\033[01;37m'
yel='\033[01;33m'

brk=$(echo -e ${blu}"----------------------------------------------------------------------"${noco})

title=$(
	echo "$brk"
	echo -e "${blu}----------------------${cyn}Linux PrivEsc Private-i${blu}-------------------------${noco}"
	echo "$brk")

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
	perm_conf=$(find /etc -type f \( -perm -o+w \) -exec ls -adl {} \;)

	     if [ -z "$perm_conf" ]; then
		   echo "$no - Nothing in /etc/ is World Writable"
	     else
		   echo "$yes - Found something in /etc/ that's World-Writable"
		   echo -e ${grn}"$perm_conf"${noco}
	     fi

}

# Fix this
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

f_log_world(){
                la=$(ls -l /var/log |awk '/syslog$/')
                lb=$(ls -l /var/log |awk '/auth.log$/')
		lc=$(ls -l /var/log |awk '/messages$/')
		ld=$(ls -l /var/log |awk '/secure$/')
		le=$(ls -l /var/log |awk '/mail.log$/')
		lf=$(ls -l /var/log |awk '/maillog$/')

                test=("$la" "$lb" "$lc" "$ld" "$le" "$lf")
                for i in "${test[@]}"; do
                   if [ -z "$i" ]; then
                        :
                   else
                    iy=$(echo "$i" |rev |cut -d ' ' -f1 |rev)
                    iz=$(echo "$i" |cut -c 7-10)
                        case "$iz" in
                        rw*)
                           echo "$yes - $iy is World R and W"
                           ;;
                        *r*)
                           echo "$yes - $iy is World-Readable"
                           ;;
                        *w*)
                           echo "$yes - $iy is World-Writable"
                           ;;
                        *)
                           echo "$no - $iy is neither world readable nor writable"
                           ;;
                        esac

                   fi
                done

}


f_ssh_world(){
                sa=$(ls -l /etc |awk '/ssh$/')
		if [ -z "$sa" ]; then
			:
		else
                  sb=$(ls -l /etc/ssh |awk '/ssh_host_rsa_key$/')
		  sc=$(ls -l /etc/ssh |awk '/ssh_host_ed25519_key$/')
		  sd=$(ls -l /etc/ssh |awk '/ssh_host_ecdsa_key$/')
		  se=$(ls -l /etc/ssh |awk '/ssh_host_dsa_key$/')

                  test=("$sb" "$sc" "$sd" "$se")
                  for i in "${test[@]}"; do
                     if [ -z "$i" ]; then
                        :
                     else
                     	  iy=$(echo "$i" |rev |cut -d ' ' -f1 |rev)
                          iz=$(echo "$i" |cut -c 7-10)
                          case "$iz" in
                          rw*)
                             echo "$yes - $iy is World R and W"
                             ;;
                          *r*)
                             echo "$yes - $iy is World-Readable"
                             ;;
                          *w*)
                             echo "$yes - $iy is World-Writable"
                             ;;
                          *)
                             echo "$no - $iy is neither world readable nor writable"
                             ;;
                          esac

                     fi
                  done
		fi
	
		sz=$(ls -la ~/ |awk '/.ssh$/')
		if [ -z "$sz" ]; then
			echo "$no - No .ssh directory found in home"
		else
			sx=$(echo "$sz" |cut -c 7-10)
			case "$sx" in
                        rw*)
                           echo "$yes - ~/.ssh is World R and W"
                           ;;
                        *r*)
                           echo "$yes - ~/.ssh is World-Readable"
                           ;;
                        *w*)
                           echo "$yes - ~/.ssh is World-Writable"
                           ;;
                        *)
                           echo "$no - ~./ssh is neither world readable nor writable"
                           ;;
                        esac

		fi
}


f_passwd_search(){
	passwd_search=("/var/www/" "/var/apache2/" "/var/log/" "/home/" "/opt")
    	  for i in "${passwd_search[@]}"; do
	    iv=$(grep -iRl "password" "${i}" 2>/dev/null)
	     if [ -z "$iv" ]; then
		   echo "$no - No passwords observed in: "$i" "
	     
	     else
		   echo "$yes - Found 'password' string in "$i" "
	     	   echo -e ${purp}"$iv"${noco}
	     fi
	  done

}


#======
# Apps
#======

f_basic_apps(){
	basic_apps=("Samba" "Perl" "Ruby" "Python" "Netcat")
    	  for i in "${basic_apps[@]}"; do
	    iv=$(
	    ls /bin |grep -wi "$i"
	    ls /usr/bin |grep -wi "$i"
	    ls /usr/sbin |grep -wi "$i"
	    ls /sbin |grep -wi "$i"
	    )
	     if [ -z "$iv" ]; then
		   echo "$no - Unable to confirm if "$i" is installed"
	     else
		   echo "$yes - "$i" is installed"
	     fi
	   done
}

f_db_apps(){
	db_apps=("PostgreSQL" "MySQL" "MariaDB" "MongoDB" "SQLite" "Oracle")
          for i in "${db_apps[@]}"; do
	    iv=$(
	    ls /bin |grep -wi "$i"
	    ls /usr/bin |grep -wi "$i"
	    ls /usr/sbin |grep -wi "$i"
	    ls /sbin |grep -wi "$i"
	    ls /etc |grep -wi "$i"
	    )
	     if [ -z "$iv" ]; then
		   echo "$no - Unable to confirm if "$i" is installed"
	     else
		   echo "$yes - "$i" is installed"
	     fi
	   done

}

f_mail_apps(){
	mail_apps=("Postfix" "Dovecot" "Exim" "SquirrelMail" "Cyrus" "Sendmail" "Courier")

          for i in "${mail_apps[@]}"; do
	    iv=$(
	    ls /bin |grep -wi "$i"
	    ls /usr/bin |grep -wi "$i"
	    ls /usr/sbin |grep -wi "$i"
	    ls /sbin |grep -wi "$i"
	    ls /etc |grep -wi "$i"
	    )
	     if [ -z "$iv" ]; then
		   echo "$no - Unable to confirm if "$i" is installed"
	     else
		   echo "$yes - "$i" is installed"
	     fi
	   done

}



pea=$(echo -e "${cyn}Full Scope${noco}		- Non-Targeted approach with verbose results")
peb=$(echo -e "${cyn}Quick Canvas${noco}		- Brief System Investigation")
pec=$(echo -e "${cyn}Sleuths Special${noco}	- Search for unique perms, sensitive files, passwords, etc")  
ped=$(echo -e "${cyn}Kernel Tip-off${noco}	- Lists possible Kernel exploits")

priv=("$pea" "$peb" "$pec" "$ped")

no=$(echo -e "${red}[-]${noco}")
yes=$(echo -e "${grn}[+]${noco}")

prompt="Selection: "
PS3="$prompt"

select opt in "${priv[@]}" "Exit"; do
	case "$REPLY" in	

	1) 
	   echo "$brk"
	   echo -e "${gray}   ,--..${red}Y   ${noco}"
	   echo -e "${gray}   \   /'.  ${noco}   Running ${cyn}Full Scope ${noco}Investigation" 
	   echo -e "${gray}    \.    \ ${noco}"
	   echo -e "${gray}     '''--' ${noco}"
	   echo "$brk"
	   echo -e "${blu}----------------------------${cyn}OS info${blu}----------------------------------${noco}"
	   f_os
	   f_krel
	   whoami
	   id
	   echo -e "${cyn}\nSuper users${noco}"
	   awk -F: '($3 == "0") {print}' /etc/passwd
	   echo -e "${blu}--------------------------${cyn}Networking${blu}---------------------------------${noco}"
	   echo -e ${cyn}ifconfig${noco}
	   f_ifconfig
	   echo "$brk"
	   echo -e ${cyn}TCP and UDP${noco}
	   f_netantp
	   f_nettul
	   echo -e ${blu}-----------------${cyn}File, Directory and App Quick Checks${blu}-----------------${noco}
	   echo -e ${cyn}Vital checks${noco}
	   f_shadow_world
	   f_sudo_world
	   f_mail_world
	   f_conf_world
	   echo -e ${cyn}/var/log/ Detection${noco}
	   f_log_world
	   echo -e ${cyn}App Research${noco}
	   f_basic_apps
	  
	   echo -e "${blu}\n----------------------------${cyn}SSH Info${blu}----------------------------------${noco}"
	   f_ssh_world
	   echo -e "${blu}\n----------------------------${cyn}Database${blu}----------------------------------${noco}"
	   f_db_apps
	   echo -e "${blu}\n----------------------------${cyn}Mail${blu}----------------------------------${noco}"
	   f_mail_apps
	   echo -e "${blu}-----------------------------${cyn}Misc.${blu}-----------------------------------${noco}"
	   echo -e ${cyn}Bash history - tail${noco}
	   tail ~/.bash_history
	   echo -e "${blu}\n-----------------------------${cyn}Crontab${blu}-----------------------------------${noco}"
	   cat /etc/crontab |grep -v '#'
	   echo -e "${blu}\n---------------------------${cyn}Mount Info${blu}---------------------------------${noco}"
	   df -h
	   echo -e "${cyn}\nfstab${noco}"
	   cat /etc/fstab |grep -v '#'	   
	   
	   exit;;

	2) 
	   echo "$brk"
	   echo -e "${red}         ____   _____${noco}"
	   echo -e "${red}   _..-'     'Y'      '-.${noco}"
	   echo -e "${red}    \ ${gray}Dossier:${red} | ~~ ~ ~  /${noco}    Running ${cyn}Quick Canvas${noco}"
	   echo -e "${red}    \\  ${wht}LINUX${red}   | ~ ~ ~~ //${noco}"
	   echo -e "${red}     \\ _..---. |.--.._ //${noco}"
	   echo "$brk"

	   echo -e "${blu}--------------------------${cyn}Basic OS info${blu}------------------------------${noco}"
	   f_os
	   f_krel
	   whoami
	   id
	   echo -e "${blu}--------------------------${cyn}Networking${blu}---------------------------------${noco}"
	   echo -e ${cyn}ifconfig${noco}
	   f_ifconfig
	   echo "$brk"
	   echo -e ${cyn}TCP and UDP....${noco}
	   f_netantp
	   f_nettul
	   echo -e ${blu}-----------------${cyn}File, Directory and App Quick Checks${blu}-----------------${noco}
	   echo -e ${cyn}Vital checks${noco}
	   f_shadow_world
	   f_sudo_world
	   f_mail_world
	   f_conf_world
	   echo -e ${cyn}Log Detection${noco}
	   f_log_world
	   echo -e ${cyn}Quick App Research${noco}
	   f_basic_apps

	   exit;;

	3) 
           echo "$brk"   
	   echo -e "  _________" 
	   echo -e " ||${red}  TOP ${noco} ||      ('^-'-/^).___..---'-'-._"
	   echo -e " ||${red} SECRET${noco}||      '${grn}6${noco}_ ${grn}6${noco}  )   '-.  (     ).'-.__.')" 
	   echo -e " ||_______||      (_${purp}Y${noco}_.)'  ._   )  '._ '. '--..-'" 
	   echo -e " |${gray}  _____${noco}  |    _..${wht}'${noco}--${wht}'${noco}_..-_/  /--'_.' ,' "
	   echo -e " | ${gray}|  |_||${noco} |  (il),-''  (li),'  ((!.-'    Running ${cyn}Sleuth Scan${noco}"
	   echo -e " '-${gray}|_____|${noco}-'"
	   echo "$brk"
	   echo -e ${blu}-------------------------${cyn}Detecting R or W Logs${blu}----------------------${noco}
	   f_log_world
	   echo -e ${blu}----------------------------${cyn}Vital Checks${blu}----------------------------${noco}
	   f_shadow_world
	   f_sudo_world
	   f_mail_world

	   echo -e "${blu}-------------------${cyn}World-Writable Directories${blu}------------------------${noco}"
	   echo -e "${cyn}PLEASE STAND BY ...${noco}"
	   find / -xdev -type d \( -perm -0002 -a ! -perm -1000 \) -print

	   echo -e "${blu}---------------------${cyn}World-Writable Files${blu}----------------------------${noco}"
	   find / -xdev -type f \( -perm -0002 -a ! -perm -1000 \) -print
	   
	   echo -e "${blu}---------${cyn}Searching string 'password' in common areas${blu}-----------------${noco}"
	   f_passwd_search
	   
	   exit;;

	4)
	   echo "$brk"
	   echo -e "${gray}         ,--.${yel}!,"${noco}
	   echo -e "${gray}       __/   ${yel}-*-"${noco}
	   echo -e "${gray}     ,d08b.  ${yel}'|'${noco}    Running ${cyn}Kernel Tip-off${noco} "
	   echo -e "${gray}     0088MM     "${noco}
	   echo -e "${gray}     '9MMP'     "${noco}
	   echo "$brk"
	   
	   kern=$(uname -r |cut -d '.' -f1-2) 
	   sploits=(	   
	   "PE -- Linux Kernel < 4.10 4.10.6 -- AF_PACKET CVE-2017-7308"
	   "PE -- Linux Kernel 4.3.3 Ubuntu 14.04 15.10 -- overlayfs CVE-2015-8660"
	   "PE -- Linux Kernel 2.6.22 < 3.9 -- Dirty Cow CVE-2016-5195"
	   "PE -- Linux Kernel 2.4/5.3 CentOS RHEL 4.8/5.3 -- ldso_hwcap CVE-2017-1000370"
	   "PE -- Linux Kernel 2.6 2.4 Ubuntu 8.10 -- sock_sendpage() CVE-2009-2692"
	   "PE -- Linux Kernel 2.6 3.2 Ubuntu  -- mempodipper"
	   "PE -- Linux Kernel 2.6 Debian 4.0 -- Ubuntu UDEV < 1.4.1"
	   "PE -- Linux Kernel 3.13 3.16 3.19 Ubuntu 12.04 14.04 14.10 15.04 -- overlayfs CVE-2015-1328"
 	   "PE -- Linux Kernel < 3.15.4 -- ptrace CVE-2014-4699"
	   "PE -- Linux Kernel < = 2.6.37 2.6 RHEL / Ubuntu 10.04 -- Full-Nelson CVE-2010-3849"
	   "PE -- Linux Kernel 2.6.0 < 2.6.36 2.6 RHEL -- compat CVE-2010-3081"
	   "PE -- Linux Kernel 2.6.8 < 2.6.16 2.6 -- h00lyshit CVE-2006-3626"
	   "PE -- Linux Kernel 2.44 < 2.4.37 & 2.6.15 < 2.6.13 2.4 2.6 -- pipe.c CVE-2009-3547"
	   "PE -- Linux Kernel 2.6.0 < 2.6.36 2.6 Ubuntu 9.10 10.04 -- half-nelson CVE-2010-4073"
	   "PE -- Linux Ubunutu 9.04 Debian 4.0-- pulseaudio CVE-2009-1894"
   	   )

	   echo -e "${blu}-----------------${cyn}Listing ${kern} Kernel Exploits${blu}-------------------------${noco}"
	   echo -e "${blu}---------------------${cyn}Do Your Due Diligence${blu}----------------------------${noco}"
	   for i in "${sploits[@]}"; do
             if [[ "$i" != *"$kern"* ]]; then
		:
	     else
		echo "$i"
             fi
	   done

	   
	   exit;;



   $(( ${#priv[@]}+1 )) ) echo "...."; exit;;
   *) echo "Invalid"; continue;;

   esac
done
