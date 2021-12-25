## **Machine ip** 
> 10.129.1.27
## **Inference**
	-Only port 80 open (server running)
	Problem loading on target ip directing to ignition.htb
	Added `10.129.1.27 ignition.htb` to /etc/hosts
	Gives error 302 (Not found)
	Used gobuster | Important directory found:- admin
	Admin login panel found but the panel is made by a company named mogento which has anti-brute 
	force method use random usernames and passwords:
		`admin admin123`
		`admin root123`
	`admin password1`
	`admin administrator1`
	`admin changeme1`
	`admin password123`
	`admin qwerty123`
	`admin administrator123`
	`admin changeme123`
##**RESULT** 
> *password* and *usernmae* revived,i.e. ,*qwerty123* and *admin*
