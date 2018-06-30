# Linux Private-i
A Linux Privilege Escalation script to automate the basic enumeration steps and display results in an easily readable format.

Execute script on the local low privileged user and select option. It's best to have a bash shell, but this has been designed for portability.

___

### Usage:

```
low@victim:/# ./private-i.sh
----------------------------------------------------------------------
--------------------------Linux Private-i-----------------------------
----------------------------------------------------------------------
1) Full Scope		    - Non-Targeted approach with verbose results
2) Quick Canvas		  - Brief System Investigation
3) Sleuths Special	- Search for unique perms, sensitive files, passwords, etc
4) Kernel Tip-off	  - Lists possible Kernel exploits
5) Exit
Selection: 
```

**Add any new Kernel Exploits in the kernel tip off array. Format however you'd like - just make sure the kernel version is listed.**
