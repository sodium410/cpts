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

hashid -j xxxxxxxxx  


**John The Ripper**: aka john  
john --single passwd.txt   //single crack mode - rule based, good for cracking linux pass - file to include passwd full line not just hash  
john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt  //wordlist mode  
john --incremental hash.txt  //brute-force style, most time consuming, defined in: /etc/john/john.conf  
john --format=krb4 hash.txt --wordlist=wordlist.txt  //specify format  
ssh2john ssh.privatekey > file.hash  //converts password protected file into john hash  
locate *2john*   //list all the supported conversions of pasword protected files  








