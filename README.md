# Linux Private-i
A Linux Privilege Escalation script to automate the basic enumeration steps and display results in an easily readable format. Using Bash, execute private-i.sh on the local low privileged user and select option. The script does not write or auto-exploit in any way.

___

### Private-i Usage:

```
low@victim:/# ./private-i.sh
----------------------------------------------------------------------
--------------------------Linux Private-i-----------------------------
----------------------------------------------------------------------
1) Full Scope       - Non-Targeted approach with verbose results
2) Quick Canvas     - Brief System Investigation
3) Sleuths Special  - Search for unique perms, sensitive files, passwords, etc
4) Kernel Tip-off   - Lists possible Kernel exploits
5) Exit
Selection: 
```

Also included is the portable **noir** version. Although less verbose without option selection, it can be ran without a Bash shell.

### Noir-Private-i Usage:

```
low@victim:/# ./noir-private-i.sh
```

___

### Example:

Here's a sample output running the **Full Scope Investigation** on a Kali lab machine. Keep in mind output is in color to more easily decipher results.

```
root@kali:/opt/linux-private-i# ./private-i.sh 
----------------------------------------------------------------------
----------------------Linux PrivEsc Private-i-------------------------
----------------------------------------------------------------------
1) Full Scope		- Non-Targeted approach with verbose results
2) Quick Canvas		- Brief System Investigation
3) Sleuths Special	- Search for unique perms, sensitive files, passwords, etc
4) Kernel Tip-off	- Lists possible Kernel exploits
5) Exit
Selection: 1
----------------------------------------------------------------------
   ,--..Y   
   \   /'.     Running Full Scope Investigation
    \.    \ 
     '''--' 
----------------------------------------------------------------------
----------------------------OS info----------------------------------
Kali GNU/Linux Rolling
4.16.0-kali2-amd64
root
uid=0(root) gid=0(root) groups=0(root)

Super users
root:x:0:0:root:/root:/bin/bash
--------------------------Networking---------------------------------
ifconfig
eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.0.2.15  netmask 255.255.255.0  broadcast 10.0.2.255
        inet6 fe80::a00:27ff:fe74:3bb8  prefixlen 64  scopeid 0x20<link>
        ether 08:00:27:74:3b:b8  txqueuelen 1000  (Ethernet)

eth1: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 172.28.128.7  netmask 255.255.255.0  broadcast 172.28.128.255
        inet6 fe80::a00:27ff:fe85:4f9  prefixlen 64  scopeid 0x20<link>
        ether 08:00:27:85:04:f9  txqueuelen 1000  (Ethernet)

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10<host>
        loop  txqueuelen 1000  (Local Loopback)
----------------------------------------------------------------------
TCP and UDP
Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 127.0.0.1:5432          0.0.0.0:*               LISTEN      559/postgres        
tcp6       0      0 ::1:5432                :::*                    LISTEN      559/postgres        
tcp6       0      0 :::80                   :::*                    LISTEN      772/apache2         
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State      
tcp        0      0 localhost:postgresql    0.0.0.0:*               LISTEN     
tcp6       0      0 localhost:postgresql    [::]:*                  LISTEN     
tcp6       0      0 [::]:http               [::]:*                  LISTEN     
udp        0      0 0.0.0.0:bootpc          0.0.0.0:*                          
-----------------File, Directory and App Quick Checks-----------------
Vital checks
[-] - /etc/shadow is neither world readable nor writable
[-] - /etc/sudoers is neither world readable nor writable
[-] - Mail in /var/mail/ is neither world readable nor writable
[+] - Found something in /etc/ that's World-Writable
-rwxrwxrwx 1 root root 0 Jun 14 18:32 /etc/test.conf
/var/log/ Detection
[-] - syslog is neither world readable nor writable
[-] - auth.log is neither world readable nor writable
[-] - messages is neither world readable nor writable
App Research
[+] - Samba is installed
[+] - Perl is installed
[+] - Ruby is installed
[+] - Python is installed
[+] - Netcat is installed

----------------------------SSH Info----------------------------------
[-] - ssh_host_rsa_key is neither world readable nor writable
[-] - ssh_host_ed25519_key is neither world readable nor writable
[-] - ssh_host_ecdsa_key is neither world readable nor writable
[-] - ~./ssh is neither world readable nor writable

----------------------------Database----------------------------------
[+] - PostgreSQL is installed
[+] - MySQL is installed
[+] - MariaDB is installed
[-] - Unable to confirm if MongoDB is installed
[-] - Unable to confirm if SQLite is installed
[-] - Unable to confirm if Oracle is installed

----------------------------Mail----------------------------------
[-] - Unable to confirm if Postfix is installed
[-] - Unable to confirm if Dovecot is installed
[+] - Exim is installed
[-] - Unable to confirm if SquirrelMail is installed
[-] - Unable to confirm if Cyrus is installed
[+] - Sendmail is installed
[-] - Unable to confirm if Courier is installed
-----------------------------Misc.-----------------------------------
Bash history - tail
clear
clear
exit
cd /home/scripts/
ls
vim ok.py 
exit

-----------------------------Crontab-----------------------------------

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

17 *	* * *	root    cd / && run-parts --report /etc/cron.hourly
25 6	* * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6	* * 7	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6	1 * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )

---------------------------Mount Info---------------------------------
Filesystem      Size  Used Avail Use% Mounted on
udev            1.5G     0  1.5G   0% /dev
tmpfs           301M  5.1M  296M   2% /run
/dev/sda1        18G   16G  882M  95% /
tmpfs           1.5G     0  1.5G   0% /dev/shm
tmpfs           5.0M     0  5.0M   0% /run/lock
tmpfs           1.5G     0  1.5G   0% /sys/fs/cgroup
tmpfs           301M   12K  301M   1% /run/user/131
tmpfs           301M   32K  301M   1% /run/user/0
/dev/sr0         56M   56M     0 100% /media/cdrom0

fstab
UUID=ca4abe47-c6d5-4e77-a46c-ca822fd15732 /               ext4    errors=remount-ro 0       1
UUID=248114c8-b7a0-4675-94f9-5183cd29d41d none            swap    sw              0       0
/dev/sr0        /media/cdrom0   udf,iso9660 user,noauto     0       0
```


**Add any new Kernel Exploits in the kernel tip off array. Format however you'd like - just make sure the kernel version is listed.**


