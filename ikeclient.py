#IKEForce
#Created by Daniel Turner
#Copyright (C) 2014 Trustwave Holdings, Inc.
#This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
#This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
#You should have received a copy of the GNU General Public License along with this program. If not, see <http://www.gnu.org/licenses/>.

import socket,OpenSSL,sys,struct
try:
        import udp
except:
        print "Missing 'udp' library: install it with 'pip install pyip' then run again.\nExiting..."
        exit()
import array
import dh
import crypto

#IKE/ISAKMP client classes

port = 500

class IKEv1Client(object):
    #List some protocol processing values, reserved space and some others omitted
    dicPayloads = {'0':'NONE','1':'Security Association (SA)','2':'Proposal (P)','3':'Transform (T)','4':'Key Exchange (KE)','5':'Identification (ID)','6':'Certificate (CERT)','7':'Certificate Request (CR)','8':'Hash (HASH)','9':'Signature (SIG)','10':'Nonce (NONCE)','11':'Notification (N)','12':'Delete (D)','13':'Vendor ID (VID)','14':'Mode CFG Attirbutes','15':'SA KEK Payload (SAK)','16':'SA TEK Payload (SAT)','17':'Key Download (KD)','18':'Sequence Number (SEQ)','19':'Proof of Possession (POP)','20':'NAT Discovery (NAT-D)','21':'NAT Original Address (NAT-OA)','22':'Group Associated Policy (GAP)','23-127':'Unassigned','130':'NAT-D','128-255':'Reserved for private use'}
    dicXTypes = {'0':'NONE','1':'Base','2':'Identity Protection','3':'Authentication Only','4':'Aggressive','5':'Informational','6':'Transaction (MODE-CFG)','32':'Quick Mode (QM)','33':'New Group Mode (NGM)'}
    dicAtts = {'1':'Encryption Algorithm','2':'Hash Algorithm','3':'Authentication Method','4':'Group Description','5':'Group Type','6':'Group Prime/Irreducible Polynomial','7':'Group Generator One','8':'Group Generator Two','9':'Group Curve A','10':'Group Curve B','11':'Life Type','12':'Life Duration','13':'PRF','14':'Key Length','15':'Field Size','16':'Group Order','17-16383':'Unassigned','16384-32767':'Reserved'}
    dicEType = {'0':'Reserved','1':'DES-CBC','2':'IDEA-CBC','3':'Blowfish-CBC','4':'RC5-R16-B64-CBC','5':'3DES-CBC','6':'CAST-CBC','7':'AES-CBC','8':'CAMELLIA-CBC'}
    dicAType = {'1':'PSK','2':'DSS-Sig','3':'RSA-Sig','4':'RSA-Enc','5':'Revised RSA-Enc','64221':'Hybrid Mode','65001':'XAUTHInitPreShared'}
    dicHType = {'0':'Reserved','1':'MD5','2':'SHA','3':'Tiger','4':'SHA2-256','5':'SHA2-384','6':'SHA2-512'}
    dicDHGroup = {'0':'Reserved','1':'default 768-bit MODP group','2':'alternate 1024-bit MODP group','3':'EC2N group on GP[2^155]','4':'EC2N group on GP[2^185]','5':'1536-bit MODP group','6':'EC2N group over GF[2^163](see Note)','7':'EC2N group over GF[2^163](see Note)','8':'EC2N group over GF[2^283](see Note)','9':'EC2N group over GF[2^283](see Note)','10':'EC2N group over GF[2^409](see Note)','11':'EC2N group over GF[2^409](see Note)','12':'EC2N group over GF[2^571](see Note)','13':'EC2N group over GF[2^571](see Note)','14':'2048-bit MODP group','15':'3072-bit MODP group','16':'4096-bit MODP group','17':'6144-bit MODP group','18':'8192-bit MODP group','19':'256-bit random ECP group','20':'384-bit random ECP group','21':'521-bit random ECP group','22':'1024-bit MODP Group with 160-bit Prime Order Subgroup','23':'2048-bit MODP Group with 224-bit Prime Order Subgroup','24':'2048-bit MODP Group with 256-bit Prime Order Subgroup','25':'192-bit Random ECP Group','26':'224-bit Random ECP Group','27':'224-bit Brainpool ECP group','28':'256-bit Brainpool ECP group','29':'384-bit Brainpool ECP group','30':'512-bit Brainpool ECP group'}
    dicLType = {'1':'seconds','2':'kilobytes'}
    dicMCFGType = {'0':'RESERVED','1':'ISAKMP_CFG_REQUEST','2':'ISAKMP_CFG_REPLY','3':'ISAKMP_CFG_SET','4':'ISAKMP_CFG_ACK','5-127':'Reserved for Future Use','128-255':'Reserved for Private Use'}
    dicMCFGAtt = {'0':'RESERVED','1':'INTERNAL_IP4_ADDRESS','2':'INTERNAL_IP4_NETMASK','3':'INTERNAL_IP4_DNS','4':'INTERNAL_IP4_NBNS','5':'INTERNAL_ADDRESS_EXPIRY','6':'INTERNAL_IP4_DHCP','7':'APPLICATION_VERSION','13':'INTERNAL_IP4_SUBNET','14':'SUPPORTED_ATTRIBUTES'}#missing ipv6 values
    dicXAUTHAtts = {'16520':'XAUTH_TYPE','16521':'XAUTH_USER_NAME','16522':'XAUTH_USER_PASSWORD','16523':'XAUTH_PASSCODE','16524':'XAUTH_MESSAGE','16525':'XAUTH_CHALLENGE','16526': 'XAUTH_DOMAIN','16527':'XAUTH_STATUS'}
    dicXAUTHTypes = {'0':'Generic','1':'RADIUS-CHAP','2':'OTP','3':'S/KEY','4-32767':'Reserved for future use','32768-65535':'Reserved for private use'}
    dicNotType = {'1':'INVALID-PAYLOAD-TYPE','2':'DOI-NOT-SUPPORTED','3':'SITUATION-NOT-SUPPORTED','4':'INVALID-COOKIE','5':'INVALID-MAJOR-VERSION','6':'INVALID-MINOR-VERSION','7':'INVALID-EXCHANGE-TYPE','8':'INVALID-FLAGS','9':'INVALID-MESSAGE-ID','10':'INVALID-PROTOCOL-ID','11':'INVALID-SPI','12':'INVALID-TRANSFORM-ID','13':'ATTRIBUTES-NOT-SUPPORTED','14':'NO-PROPOSAL-CHOSEN','15':'BAD-PROPOSAL-SYNTAX','16':'PAYLOAD-MALFORMED','17':'INVALID-KEY-INFORMATION','18':'INVALID-ID-INFORMATION','19':'INVALID-CERT-ENCODING','20':'INVALID-CERTIFICATE','21':'CERT-TYPE-UNSUPPORTED','22':'INVALID-CERT-AUTHORITY','23':'INVALID-HASH-INFORMATION','24':'AUTHENTICATION-FAILED','25':'INVALID-SIGNATURE','26':'ADDRESS-NOTIFICATION','27':'NOTIFY-SA-LIFETIME','28':'CERTIFICATE-UNAVAILABLE','29':'UNSUPPORTED-EXCHANGE-TYPE','30':'UNEQUAL-PAYLOAD-LENGTHS','36136':'R-U-THERE','36137':'R-U-THERE-ACK'}


    def __init__(self,debug):
	self.debug = debug


    def secRandom(self, bytes):
	#Creates selected number of random bytes
	#Provide the number of bytes required as input, method will return raw bytes
	randomBytes = OpenSSL.rand.bytes(bytes)
	return randomBytes

    def ikeHeader(self,payNext,iCookie,rCookie,flags,xType,msgID,prevpayLen): #Input the payload length to this method for now, need to figure out a calculation for this later
        #Build the IKE HDR
	#Provide next payload, initiator cookie, responder cookie, flags, exchange type, and length of all data being sent not including the header
        version = '10'
	payLen = int(prevpayLen) + 28 #28 byte ike header
	fullpayLen = hex(payLen)[2:].zfill(8)	
	strPayload = iCookie+rCookie+payNext+version+xType+flags+msgID+fullpayLen
	arrayPayload = array.array('B', strPayload.decode("hex"))
	if self.debug > 0:
                print "Processing IKE Header:"
                print "iCookie: %s"%iCookie
                print "rCookie: %s"%rCookie
                try:
                        print "Next Payload: %s"%self.dicPayloads[str(int(payNext))]
                except TypeError:
                        print "Next Payload: %s"%self.dicPayloads[str(payNext)]
                print "Version: %s"%version
                print "Exchange Type: %s (%s)"%(xType,self.dicXTypes[str(int(xType))])
                print "Flags: %s"%flags
                print "Message ID: %s"%msgID
                print "Payload Length: %s"%fullpayLen

	return arrayPayload
	
	
    def ikeSA(self,prevpayLen):
	#Process SA payload
	payNext = "04"
	padding = "00" #padding here (reserved space)
        payLen = "0000"
        doi = "00000001"
        sit = "00000001"
        
        strPayload = payNext+padding+payLen+doi+sit
        arrayPayload = array.array('B', strPayload.decode("hex"))
        payLen = len(arrayPayload)
        fullpayLen = hex(prevpayLen+payLen)[2:].zfill(4)
        arraypayLen = array.array('B', fullpayLen.decode("hex"))
	arrayPacket = arrayPayload[:2]+arraypayLen+arrayPayload[4:]
        if self.debug > 0:
                print "Processing SA payload:"
                print "Next Payload: %s"%self.dicPayloads[str(int(payNext,16))]
                print "Payload Length: %s"%fullpayLen
                print "Domain of Interpretation: %s"%doi
                print "Situation: %s"%sit
        return arrayPacket


    def ikeProposal(self, prevpayLen):
	#Process IKE proposal payload
        payNext = "00" #(NONE)
	padding = "00"#padding (reserved space)
	payLen = "0000"
	propNum = "01"
	protID = "01"
	spiSize = "00"
	propTrans = "01"

	#Payload length calculation - maybe make this a method?
        strPayload = payNext+padding+payLen+propNum+protID+spiSize+propTrans
        arrayPayload = array.array('B', strPayload.decode("hex"))
        payLen = len(arrayPayload)
        fullpayLen = hex(payLen+prevpayLen)[2:].zfill(4)
        arraypayLen = array.array('B', fullpayLen.decode("hex"))
        arrayPacket = arrayPayload[:2]+arraypayLen+arrayPayload[4:]        

        if self.debug > 0:
                print "Processing Proposal:"
                print "Next Payload: %s"%self.dicPayloads[str(int(payNext,16))]
                print "Payload Length: %s"%fullpayLen
                print "SPI Size: %s"%spiSize
                print "Proposal Transforms: %s"%int(propTrans,16) #just one transform set for now

	return arrayPacket,int(fullpayLen,16)

    def ikeTransform(self,et,ht,at,gd,lt_,ld,prevpayLen,*arg):
	#Takes 6 transform attributes as arguments: encryption algorithm, hash algorithm, authentication type, life type, life duration
	#Check if key length is specified
	if arg:
		keyLen = int(arg[0]*8)
		keyLen = "800e" + str(hex(keyLen)[2:]).zfill(4)
	else:
		pass
	#Transform header
	payNext = "00"#(NONE)
	padding = "00" #padding (reserved space)
	payLen = "0000"#temp payload length before calculating size
	transNum = "01"
	transID = "01"
	padding1 = "0000" #more padding

	#Transform payload
	try:
		encType = "800100" + str(et)
        except: 
                for i in self.dicHType:
                        if self.dicHType[str(i)] == et.upper():
                                et = i.zfill(2)
                encType = "800200" + et
	try:
	        hashType = "800200" + int(ht).zfill(2)
	except:
		for i in self.dicHType:
			if self.dicHType[str(i)] == ht.upper():
				ht = i.zfill(2)
		hashType = "800200" + ht
	authType = "8003" + str(at)
	groupType = "800400" + str(gd)
	lifeType = "800b00" + str(lt_)
	lifeDur = "000c0004" + str(ld) # need to handle this better

        #Payload length calculation - maybe make this a method?
	try:
	        strPayload = payNext+padding+payLen+transNum+transID+padding1+encType+authType+hashType+groupType+lifeType+lifeDur+keyLen
	except:
		strPayload = payNext+padding+payLen+transNum+transID+padding1+encType+authType+hashType+groupType+lifeType+lifeDur

        arrayPayload = array.array('B', strPayload.decode("hex"))
        payLen = len(arrayPayload)
        fullpayLen = hex(prevpayLen+payLen)[2:].zfill(4)
        arraypayLen = array.array('B', fullpayLen.decode("hex"))
        arrayPacket = arrayPayload[:2]+arraypayLen+arrayPayload[4:]

	if self.debug > 0:
                print "Processing Transform payload:"
                try:   
                        print "Next Payload: %s"%self.dicPayloads[str(int(payNext,16))]
                except TypeError:
                        print "Next Payload: %s"%self.dicPayloads[str(payNext)]
                print "Payload Length: %s"%fullpayLen
                print "Transform Number: %s"%transNum
                print "Encryption Type: %s"%encType
		print "Hash Type: %s"%hashType
		print "Auth Type: %s"%authType
		print "DHGroup Type: %s"%groupType
		print "Life Type: %s"%lifeType
		print "Life Duration: %s"%lifeDur
		try:
			print "Key Length: %s"%keyLen
		except:
			pass
	return arrayPacket,int(fullpayLen,16)


    def ikeKE(self, pubKey):
	payNext = "0a" #(Nonce)
	padding = "00" # padding (reserved space)
	payload = pubKey
	payLen = "0000" # Temp for payload length
	#Payload length calculation - maybe make this a method?
        strPayload = payNext+padding+payLen+payload
        arrayPayload = array.array('B', strPayload.decode("hex"))	
	payLen = len(arrayPayload)
	fullpayLen = hex(payLen)[2:].zfill(4)
        arraypayLen = array.array('B', fullpayLen.decode("hex"))
        arrayPacket = arrayPayload[:2]+arraypayLen+arrayPayload[4:]

        if self.debug > 0:
                print "Processing KE payload:"
                try:   
                        print "Next Payload: %s"%self.dicPayloads[str(int(payNext,16))]
                except TypeError:
                        print "Next Payload: %s"%self.dicPayloads[str(payNext)]
                print "Payload Length: %s"%fullpayLen
                print "KE Payload: %s\n"%payload
	return arrayPacket

    def ikeNonce(self):
	#Process Nonce payload
	#returns array
	payNext = "05"
	padding = "00"
	nonce = self.secRandom(21).encode('hex')
	payLen = "0000"

        #Payload length calculation - maybe make this a method?
        strPayload = payNext+padding+payLen+nonce
        arrayPayload = array.array('B', strPayload.decode("hex"))
        payLen = len(arrayPayload)
        fullpayLen = hex(payLen)[2:].zfill(4)
        arraypayLen = array.array('B', fullpayLen.decode("hex"))
        arrayPacket = arrayPayload[:2]+arraypayLen+arrayPayload[4:]

        if self.debug > 0:
                print "Processing Nonce payload:"
                try:   
                        print "Next Payload: %s"%self.dicPayloads[str(int(payNext,16))]
                except TypeError:
                        print "Next Payload: %s"%self.dicPayloads[str(payNext)]
                print "Payload Length: %s"%fullpayLen
                print "Nonce Payload: %s\n"%nonce

	return arrayPacket,nonce

    def ikeID(self,idData,idType):
	#Processing IKE ID payload
	#returns array
        payNext = "00" #(NONE)
	padding = "00" #padding (reserved space)
        payLen = "0000"
        protID = "11"#static value for now
	port = "01f4" #static value of 500 for now, this may need to be dynamic for non-default port functionality

        #Payload length calculation - maybe make this a method?
        strPayload = payNext+padding+payLen+idType+protID+port+idData.encode('hex')
        arrayPayload = array.array('B', strPayload.decode("hex"))
        payLen = len(arrayPayload)
        fullpayLen = hex(payLen)[2:].zfill(4)
        arraypayLen = array.array('B', fullpayLen.decode("hex"))
        arrayPacket = arrayPayload[:2]+arraypayLen+arrayPayload[4:]

        if self.debug > 0:
                print "Processing Identification Payload:"
                try:   
                        print "Next Payload: %s"%self.dicPayloads[str(int(payNext,16))]
                except TypeError:
                        print "Next Payload: %s"%self.dicPayloads[str(payNext)]
                print "Payload Length = %s"%payLen
                print "ID Type: %s"%idType
                print "Group ID: %s"%idData

	ID_i = strPayload[8:]
	return arrayPacket,ID_i

    def ikeHash(self,payNext,hash):
	padding = "00"
	payLen = "0000"
        strPayload = payNext+padding+payLen+hash
	arrayPayload = array.array('B', strPayload.decode("hex"))
        payLen = len(arrayPayload)
        fullpayLen = hex(payLen)[2:].zfill(4)
        arraypayLen = array.array('B', fullpayLen.decode("hex"))
        arrayPacket = arrayPayload[:2]+arraypayLen+arrayPayload[4:]

        if self.debug > 0:
                print "Processing Hash Payload:"
                try:   
                        print "Next Payload: %s"%self.dicPayloads[str(int(payNext,16))]
                except TypeError:
                        print "Next Payload: %s"%self.dicPayloads[str(payNext)]
                print "Payload Length: %s"%payLen
		
	return arrayPacket
	
    def ikeNot(self,payNext,msgType,spi,notData):
	padding = "00"
	payLen = "0000"
	doi = "00000001"
        protID = "01"
        spiSize = "10"
	
	try:
		strPayload = payNext+padding+payLen+doi+protID+spiSize+msgType+spi+notData
	except TypeError:
		msgType = hex(msgType)[2:].zfill(4)
		strPayload = payNext+padding+payLen+doi+protID+spiSize+msgType+spi+notData

        arrayPayload = array.array('B', strPayload.decode("hex"))
        payLen = len(arrayPayload)
        fullpayLen = hex(payLen)[2:].zfill(4)
        arraypayLen = array.array('B', fullpayLen.decode("hex"))
        arrayPacket = arrayPayload[:2]+arraypayLen+arrayPayload[4:]

        if self.debug > 0:
                print "Processing Notification Payload:"
                try:
                        print "Next Payload: %s"%self.dicPayloads[str(int(payNext,16))]
                except TypeError:
                        print "Next Payload: %s"%self.dicPayloads[str(payNext)]
                print "Payload Length: %s"%payLen
		print "DOI: %s"%doi
		print "Protocol ID: %s"%protID
		print "SPI Size: %s"%spiSize
                try:
                        print "Notify Message Type: %s"%self.dicNotType[str(msgType)]
                except: 
                        print "Notify Message Type: %s (Unknown Type)"%msgType
                print "Notification Data: %s\n"%notData

        return arrayPacket

    def ikeVID(self,payNext,VIDdata):
	#Provide the VID data
	#returns an array
        padding = "00"
        payLen = "0000"
        try:   
                payNext = hex(payNext)[2:].zfill(2)
                strPayload = payNext+padding+payLen+hash

        except:
                strPayload = payNext+padding+payLen+VIDdata

        arrayPayload = array.array('B', strPayload.decode("hex"))
        payLen = len(arrayPayload)
        fullpayLen = hex(payLen)[2:].zfill(4)
        arraypayLen = array.array('B', fullpayLen.decode("hex"))
        arrayPacket = arrayPayload[:2]+arraypayLen+arrayPayload[4:]

        if self.debug > 0:
                print "Processing VID Payload:"
                try:
                        print "Next Payload: %s"%self.dicPayloads[str(int(payNext,16))]
                except TypeError:
                        print "Next Payload: %s"%self.dicPayloads[str(payNext)]
                print "Payload Length: %s"%payLen
                print "VID Data: %s\n"%VIDdata

	return arrayPacket 

    def ikeXAUTH(self,typeXAUTH,attXAUTH,attXAUTHValue,*args):
	#Provide xauth type integer and xauth attribute and value as strings
	#if cisco change 4080 to c080
	padding = "0000"
	if len(args) > 1:
		print "Only 1 optional argument (vendor) required if responder is Cisco. Exiting..."
		exit()
	try:
	        attXAUTH = int(attXAUTH,16)
        except:
		pass
	if attXAUTH == 16527 or attXAUTH == 16520:
        	#no variable length for status or type attributes
        	if self.debug > 0:
        		print "Mode Config Attribute Type: %s"%self.dicXAUTHAtts[str(attXAUTH)]
        		print "Mode Config Attribute Value: %s"%attXAUTHValue
		try:
			payloadXAUTH = hex(attXAUTH)[2:].zfill(4)+hex(attXAUTHValue)[2:].zfill(4)
		except:
			payloadXAUTH = hex(attXAUTH)[2:].zfill(4)+attXAUTHValue[2:].zfill(4)
		if args and args[0] == "cisco":
			if self.debug > 0:
				print "Responder is a Cisco device"
			payloadXAUTH = "c"+payloadXAUTH[1:]
		else:
			pass

	#Some requests need to have a blank value, to request IP address etc
	elif attXAUTHValue == "blank":
		attLen = "00"
		if self.debug > 0:
			print "Mode Config Attribute Type: %s"%attXAUTH
                        print "Mode Config Attribute Length: %s"%attLen
                        print "Mode Config Attribute Value: ()"

		payloadXAUTH = hex(attXAUTH)[2:].zfill(4)+attLen
                if args and args[0] == "cisco":
                        if self.debug > 0:
                                print "Responder is a Cisco device"
                        payloadXAUTH = "c"+payloadXAUTH[1:]
		else:
			pass

        else:   
	        attLen = len(attXAUTHValue)
                if self.debug > 0:
			try:
				print "Mode Config Attribute Type: %s"%self.dicXAUTHAtts[str(attXAUTH)]
			except:
				print "Mode Config Attribute Type: %s"%attXAUTH
                	print "Mode Config Attribute Length: %s"%attLen
                	print "Mode Config Attribute Value: %s"%attXAUTHValue

		payloadXAUTH = hex(attXAUTH)[2:].zfill(4)+hex(attLen)[2:].zfill(4)+attXAUTHValue.encode('hex')

                if args and args[0] == "cisco":
                        if self.debug > 0:
                                print "Responder is a Cisco device"
                        payloadXAUTH = "c"+payloadXAUTH[1:]
                else:
                        pass

        return payloadXAUTH


    def ikeModeCFG(self,payNext,mcfgType,mcfgAtts):
        #Process ModeCFG payload (XAUTH)
	#run ikeXAUTH first to get the mcfgAtts payload
        padding = "00"
        payLen = "0000"
	#Convert int to hex in case value is supplied as int
        try:
		mcfgType = hex(mcfgType)[2:].zfill(2)
	except:
		pass
        mcfgID = "0000"

        strPayload = payNext+padding+payLen+mcfgType+padding+mcfgID+mcfgAtts
        arrayPayload = array.array('B', strPayload.zfill(2).decode("hex"))
        payLen = len(arrayPayload)
        fullpayLen = hex(payLen)[2:].zfill(4)
        arraypayLen = array.array('B', fullpayLen.decode("hex"))
        arrayPacket = arrayPayload[:2]+arraypayLen+arrayPayload[4:]

        if self.debug > 0:
                print "Processing Mode Config Payload:"
                try:
                        print "Next Payload: %s"%self.dicPayloads[str(int(payNext,16))]
                except:
                        print "Next Payload: %s"%self.dicPayloads[str(payNext)]
                print "Payload Length: %s"%payLen
                print "Mode Config Message Type: %s"%self.dicMCFGType[str(int(mcfgType,16))]
                print "Mode Config ID: %s\n"%mcfgID


        return arrayPacket


    def ikeDelete(self,payNext,iCookie,rCookie):
        #Provide the initiator cookie and responder cookie
        #returns an array
        padding = "00"
        payLen = "0000"
	DOI = "00000000" # zero for ISAKMP
	protID = "01"
	spi = iCookie+rCookie
	sizeSPI = hex(len(spi)/2)[2:].zfill(2)
	numSPIs = "0001" #static for now

        try:   
                payNext = hex(payNext)[2:].zfill(2)
                strPayload = payNext+padding+payLen+DOI+protID+sizeSPI+numSPIs+spi

        except:
                strPayload = payNext+padding+payLen+DOI+protID+sizeSPI+numSPIs+spi

        arrayPayload = array.array('B', strPayload.decode("hex"))
        payLen = len(arrayPayload)
        fullpayLen = hex(payLen)[2:].zfill(4)
        arraypayLen = array.array('B', fullpayLen.decode("hex"))
        arrayPacket = arrayPayload[:2]+arraypayLen+arrayPayload[4:]

        if self.debug > 0:
                print "Processing Delete Payload:"
                try:
                        print "Next Payload: %s"%self.dicPayloads[str(int(payNext,16))]
                except TypeError: 
                        print "Next Payload: %s"%self.dicPayloads[str(payNext)]
                print "Payload Length: %s"%payLen
                print "SPI: %s\n"%spi

        return arrayPacket	


    def packPacket(self,arrayBytes,arrayLen):
	#Pack bytes ready for sending to socket
	packedBytes = struct.pack(("B"*arrayLen),*arrayBytes)
	return packedBytes

    def sendPacket(self,bytes,target,sport,port):
	#Build raw UPD packet to avoid duplicate port/socket issues
	udpPacket = udp.Packet()
	udpPacket.sport = sport
	udpPacket.dport = port   
	udpPacket.data = bytes
	packet = udp.assemble(udpPacket, 0)
	sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
	sock.sendto(packet, (target, port))
	if self.debug > 0:
		print "UDP target IP: %s"%target
		print "UDP target port: %s"%port
		print "UDP source port: %s"%sport
		print "Sending: %s"%bytes.encode('hex')



    def main(self,iCookie,rCookie,eType,hashType,authType,DHGroup,IDdata,flags,target,idType,sport,prevpayLen,keyLen):
	ikeneg = IKEv1Client(self.debug)
	#IKE initialization packet
	#Process transform before proposal to get payload length and then SA
	#Tranform
	if eType == "07" or int(eType) == 7 or eType == "AES":
		arrayTrans,paylenTrans = ikeneg.ikeTransform(eType,hashType,authType,DHGroup,"01","00007080",prevpayLen,keyLen)#static lifetime values for now
	else:
		arrayTrans,paylenTrans = ikeneg.ikeTransform(eType,hashType,authType,DHGroup,"01","00007080",prevpayLen)
	lenTrans = len(arrayTrans)
	bytesTrans = struct.pack(("B"*lenTrans),*arrayTrans)

	#Proposal
	arrayProposal,paylenProp = ikeneg.ikeProposal(paylenTrans)
	lenProposal = len(arrayProposal)
	bytesProposal = struct.pack(("B"*lenProposal),*arrayProposal)

	#SA
	arraySA = ikeneg.ikeSA(lenProposal+lenTrans)#SA payload length is the length of the transform and proposal payloads combined
	lenSA = len(arraySA)
	bytesSA = struct.pack(("B"*lenSA),*arraySA)
	
	arraySA_i = arraySA[4:]+arrayProposal+arrayTrans
	lenSA_i = len(arraySA_i)
	bytesSA_i = struct.pack(("B"*lenSA_i),*arraySA_i)
	SA_i = bytesSA_i.encode('hex')
	
	#Key Exchange
	ikeDH = dh.DiffieHellman(DHGroup)
	privKey = ikeDH.genPrivateKey(1024)
	pubKey = ikeDH.genPublicKey(privKey)
	hexPrivKey = '{0:x}'.format(privKey)#using new formating to deal with long
	hexPubKey = '{0:x}'.format(pubKey)
	if len(hexPubKey) % 2 != 0:
		hexPubKey = "0" + hexPubKey

	if self.debug > 0:
		print "Initiator DH Private Key: %s"%privKey
		print "Initiator DH Private Key (hex): %s"%hexPrivKey
		print "Initiator DH Public Key: %s"%pubKey
		print "Initiator DH Public Key (hex): %s"%hexPubKey

	arrayKE = ikeneg.ikeKE(hexPubKey)
	lenKE = len(arrayKE) 
	bytesKE = struct.pack(("B"*lenKE),*arrayKE)

	#Nonce payload
	arrayNonce,nonce = ikeneg.ikeNonce()
	lenNonce = len(arrayNonce)
	bytesNonce = struct.pack(("B"*lenNonce),*arrayNonce)

	#ID payload
	arrayID,ID_i = ikeneg.ikeID(IDdata,idType)
	lenID = len(arrayID)
	bytesID = struct.pack(("B"*lenID),*arrayID)

	#Header
	lenHDR = len(bytesSA+bytesProposal+bytesTrans+bytesKE+bytesNonce+bytesID)
	arrayHDR = ikeneg.ikeHeader("01",iCookie,rCookie,flags,"04","00000000",lenHDR) #exchange type statically 4 (aggressive) here
	lenHDR = len(arrayHDR)
	bytesHDR = struct.pack(("B"*lenHDR),*arrayHDR)


	#Process full packet to determine payload length for correctly formed header
	bytesIKE = bytesHDR+bytesSA+bytesProposal+bytesTrans+bytesKE+bytesNonce+bytesID
	payLen = (len(bytesIKE) + 8) / 2
	fullpayLen = hex(payLen)[2:].zfill(8)
	arraypayLen = array.array('B', fullpayLen.decode("hex"))
	
	lenpayLen = len(arraypayLen)
	bytespayLen = struct.pack(("B"*lenpayLen),*arraypayLen)
	bytesIKE = bytesHDR+bytesSA+bytesProposal+bytesTrans+bytesKE+bytesNonce+bytesID
	ikeneg.sendPacket(bytesIKE,target,sport,port)

	#Gather any details required for later processing of crypto etc
	dicCrypto = {"iCookie":iCookie,"rCookie":rCookie,"eType":eType,"hashType":hashType,"authType":authType,"DHGroup":DHGroup,"nonce_i":nonce,"SA_i":SA_i,"ID_i":ID_i,"privKey":privKey,"DHPubKey_i":hexPubKey}
	return dicCrypto
