# Linux Private-i
A Linux Enumeration & Privilege Escalation tool that automates the basic enumeration steps and displays the results in an easily readable format. The script comes loaded with a variety of **4 Options** to choose from. 

Using Bash, execute private-i.sh on the local low privileged user.

![alt text](https://rtcrowley.github.io/start.png?raw=true "execute")

Select an option, execute & watch the show. Each mode uses common Linux binaries to enumerate the local system (find, grep, ps, etc). If you have a non-bash shell such as **sh**, use [Noir-Private-i](#noir-private-i). **Either script will not write or auto-exploit in any way**.

## Full Scope Investigation

Very Verbose option. 
* Vital checks such as OS info and permissions on common files.
* Search for common applications while checking versions, file permissions and possible user credentials.
  + **Common Apps:** Apache/HTTPD, Tomcat, Netcat, Perl, Ruby, Python, WordPress, Samba
  + **Database Apps:** SQLite, Postgres, MySQL/MariaDB, MongoDB, Oracle, Redis, CouchDB
  + **Mail Apps:** Postfix, Dovecot, Exim, SquirrelMail, Cyrus, Sendmail, Courier
* Checks Networking info - netstat, ifconfig.
* Basic mount info, crontab and bash history.

Here's a snippet when running the Full Scope. This box has purposely misconfigured files and permissions. 
![alt text](https://rtcrowley.github.io/pi_full.png?raw=true "Full")

___

## Quick Canvas

Looking to gain some quick intel without information overload? Running a Quick Canvas against the system will output the basic OS info, Networking, Apps and common file permissions. A simple non-verbose version of the Full Scope option.

![alt text](https://rtcrowley.github.io/pi_quick.png?raw=true "special")

___

## Sleuths Special

Runs basic vital checks, then searches the filesystem for world-writable permissions & 'password' strings in common directories. Depending on the size of the filesystem, this option may take a while to complete. 

![alt text](https://rtcrowley.github.io/pi_sspecial.png?raw=true "special")

## Kernel Tip-Off

Compares the first two octets of the Kernel version (```uname -r```) to an array of exploits. Does not auto-exploit.

**Feel free to add any new Kernel Exploits in the kernel tip off array. Format however you'd like - just make sure the kernel version is listed.**

___

# Noir-Private-i

Also included is the portable **noir** version. Although less verbose without option selection, it can be ran without a Bash shell. Simply execute without any additions.

```
low@victim:/# ./noir-private-i.sh
```

