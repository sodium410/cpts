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











