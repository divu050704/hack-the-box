## **Machine IP**
> 10.129.233.99
## **Inference**
1. Nmap scan shows smbclient open on port 445.
2. `smbclient -L 10.129.233.99 -U Administrator` shows admin$ share and no password required.
3. On connection with C$ by `smbclient \\\\10.129.233.99\\C$ -U Administrator`.
4. Found flag in `\Users\Administrator\Desktop\flag.txt`
5. Could also get a reverse shell by loading `PSexec.py`.
6. Saved flag.txt as `get flag.txt`
## **Result** 
- Root Flag - f751c19eda8f61ce81827e6930a1f40c
- Add password to your smclient