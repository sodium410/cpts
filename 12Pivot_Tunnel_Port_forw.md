The initial compromised system -- Can be called jump host, pivot host, proxy, foothold  
**Lateral Movement**: . We used the credentials to move laterally to that other device, enabling us to compromise the domain further !!  
**Pivoting**:  more than one nic, cross network boundaries you would not usually have access to  
**Tunneling**: Sending traffic over other protocols ssh, dns, https -- common is ssh tunnel to reach web server  

SOCKS proxies are currently of two types: SOCKS4 and SOCKS5.  
SOCKS4 doesn't provide any authentication and UDP support, whereas SOCKS5 does provide that  

**SSH Local Port forwarding**: reach target sql service over ssh when sql port is not reachable directly !!  
ssh -L 1234:SQLSERVERIP:3306 ubuntu@10.129.202.64      //now interact with local port 1234 to interact with remote SQL.  
ssh -L 1234:SQLSERVERIP:3306 -L 8080:WEBSERVERIP:80 ubuntu@10.129.202.64     //multiple ports  
nmap -v -sV -p1234 localhost    //scan localport  

**SSH Dynamic port forwarding**: send all port traffic over proxychains .. to reach other network interfaces    
ssh -D 9090 ubuntu@10.129.202.64     //allows to reach second network  
cat /etc/proxychains4.conf  // add socks4 127.0.0.1 9050  
proxychains nmap -v -sn 172.16.5.1-200  //reach second network from kali Full TCP connect works no sS use sT  
Proxychains msfconsole  
Proxychains xfreerdp /v:172.16.1.1 /u:victor /p:pass@123  
Proxychains GetUserSPNS.py marvel.local/fcastle:Password1 –dc-ip 10.1.1.1 -request  

**LigoloNG**   

**Sshuttle**  

**Chisel**  

**Labs**:  
Enterprise, Inception, REddish, Dante, Offshore, Rasta, Ascension  

