#IKEForce
#Created by Daniel Turner
#Copyright (C) 2014 Trustwave Holdings, Inc.
#This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
#This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
#You should have received a copy of the GNU General Public License along with this program. If not, see <http://www.gnu.org/licenses/>.

import traceback
import sys
import crypto

#IKE/ISAKMP packet handler classes

dicCrypto = {}
listVIDs = []

class IKEv1Handler(object):

    #List some protocol processing values, reserved space and some others omitted
    dicPayloads = {'0':'NONE','1':'Security Association (SA)','2':'Proposal (P)','3':'Transform (T)','4':'Key Exchange (KE)','5':'Identification (ID)','6':'Certificate (CERT)','7':'Certificate Request (CR)','8':'Hash (HASH)','9':'Signature (SIG)','10':'Nonce (NONCE)','11':'Notification (N)','12':'Delete (D)','13':'Vendor ID (VID)','14':'Mode CFG Attributes','15':'SA KEK Payload (SAK)','16':'SA TEK Payload (SAT)','17':'Key Download (KD)','18':'Sequence Number (SEQ)','19':'Proof of Possession (POP)','20':'NAT Discovery (NAT-D)','21':'NAT Original Address (NAT-OA)','22':'Group Associated Policy (GAP)','23-127':'Unassigned','130':'NAT-D','128-255':'Reserved for private use'}
    dicXTypes = {'0':'NONE','1':'Base','2':'Identity Protection','3':'Authentication Only','4':'Aggressive','5':'Informational','6':'Transaction (MODE-CFG)','32':'Quick Mode (QM)','33':'New Group Mode (NGM)'}
    dicAtts = {'1':'Encryption Algorithm','2':'Hash Algorithm','3':'Authentication Method','4':'Group Description','5':'Group Type','6':'Group Prime/Irreducible Polynomial','7':'Group Generator One','8':'Group Generator Two','9':'Group Curve A','10':'Group Curve B','11':'Life Type','12':'Life Duration','13':'PRF','14':'Key Length','15':'Field Size','16':'Group Order','17-16383':'Unassigned','16384-32767':'Reserved'}
    dicEType = {'0':'Reserved','1':'DES-CBC','2':'IDEA-CBC','3':'Blowfish-CBC','4':'RC5-R16-B64-CBC','5':'3DES-CBC','6':'CAST-CBC','7':'AES-CBC','8':'CAMELLIA-CBC'}
    dicAType = {'1':'PSK','2':'DSS-Sig','3':'RSA-Sig','4':'RSA-Enc','5':'Revised RSA-Enc','64221':'Hybrid Mode','65001':'XAUTHInitPreShared','65002':'XAUTHRespPreShared','65003':'XAUTHInitDSS','65004':'XAUTHRespDSS','65005':'XAUTHInitRSA','65006':'XAUTHRespRSA','65007':'XAUTHInitRSAEncryption','65008':'XAUTHRespRSAEncryption','65009':'XAUTHInitRSARevisedEncryption','65010':'XAUTHRespRSARevisedEncryption'}
    dicHType = {'0':'Reserved','1':'MD5','2':'SHA','3':'Tiger','4':'SHA2-256','5':'SHA2-384','6':'SHA2-512'}
    dicDHGroup = {'0':'Reserved','1':'default 768-bit MODP group','2':'alternate 1024-bit MODP group','3':'EC2N group on GP[2^155]','4':'EC2N group on GP[2^185]','5':'1536-bit MODP group','6':'EC2N group over GF[2^163](see Note)','7':'EC2N group over GF[2^163](see Note)','8':'EC2N group over GF[2^283](see Note)','9':'EC2N group over GF[2^283](see Note)','10':'EC2N group over GF[2^409](see Note)','11':'EC2N group over GF[2^409](see Note)','12':'EC2N group over GF[2^571](see Note)','13':'EC2N group over GF[2^571](see Note)','14':'2048-bit MODP group','15':'3072-bit MODP group','16':'4096-bit MODP group','17':'6144-bit MODP group','18':'8192-bit MODP group','19':'256-bit random ECP group','20':'384-bit random ECP group','21':'521-bit random ECP group','22':'1024-bit MODP Group with 160-bit Prime Order Subgroup','23':'2048-bit MODP Group with 224-bit Prime Order Subgroup','24':'2048-bit MODP Group with 256-bit Prime Order Subgroup','25':'192-bit Random ECP Group','26':'224-bit Random ECP Group','27':'224-bit Brainpool ECP group','28':'256-bit Brainpool ECP group','29':'384-bit Brainpool ECP group','30':'512-bit Brainpool ECP group'}
    dicLType = {'1':'seconds','2':'kilobytes'}
    dicIDType = {'0':'ID_IPV4_ADDR','1': 'ID_IPV4_ADDR_SUBNET','2':'ID_IPV6_ADDR','3':'ID_IPV6_ADDR_SUBNET','36136':'R-U-THERE','36137':'R-U-THERE-ACK'}
    dicNotType = {'1':'INVALID-PAYLOAD-TYPE','2':'DOI-NOT-SUPPORTED','3':'SITUATION-NOT-SUPPORTED','4':'INVALID-COOKIE','5':'INVALID-MAJOR-VERSION','6':'INVALID-MINOR-VERSION','7':'INVALID-EXCHANGE-TYPE','8':'INVALID-FLAGS','9':'INVALID-MESSAGE-ID','10':'INVALID-PROTOCOL-ID','11':'INVALID-SPI','12':'INVALID-TRANSFORM-ID','13':'ATTRIBUTES-NOT-SUPPORTED','14':'NO-PROPOSAL-CHOSEN','15':'BAD-PROPOSAL-SYNTAX','16':'PAYLOAD-MALFORMED','17':'INVALID-KEY-INFORMATION','18':'INVALID-ID-INFORMATION','19':'INVALID-CERT-ENCODING','20':'INVALID-CERTIFICATE','21':'CERT-TYPE-UNSUPPORTED','22':'INVALID-CERT-AUTHORITY','23':'INVALID-HASH-INFORMATION','24':'AUTHENTICATION-FAILED','25':'INVALID-SIGNATURE','26':'ADDRESS-NOTIFICATION','27':'NOTIFY-SA-LIFETIME','28':'CERTIFICATE-UNAVAILABLE','29':'UNSUPPORTED-EXCHANGE-TYPE','30':'UNEQUAL-PAYLOAD-LENGTHS'}
    dicMCFGType = {'0':'RESERVED','1':'ISAKMP_CFG_REQUEST','2':'ISAKMP_CFG_REPLY','3':'ISAKMP_CFG_SET','4':'ISAKMP_CFG_ACK','5-127':'Reserved for Future Use','128-255':'Reserved for Private Use'}
    dicMCFGAtt = {'0':'RESERVED','1':'INTERNAL_IP4_ADDRESS','2':'INTERNAL_IP4_NETMASK','3':'INTERNAL_IP4_DNS','4':'INTERNAL_IP4_NBNS','5':'INTERNAL_ADDRESS_EXPIRY','6':'INTERNAL_IP4_DHCP','7':'APPLICATION_VERSION','13':'INTERNAL_IP4_SUBNET','14':'SUPPORTED_ATTRIBUTES'}#missing ipv6 values
    dicXAUTHAtts = {'16520':'XAUTH_TYPE','16521':'XAUTH_USER_NAME','16522':'XAUTH_USER_PASSWORD','16523':'XAUTH_PASSCODE','16524':'XAUTH_MESSAGE','16525':'XAUTH_CHALLENGE','16526':'XAUTH_DOMAIN','16527':'XAUTH_STATUS'}
    dicXAUTHTypes = {'0':'Generic','1':'RADIUS-CHAP','2':'OTP','3':'S/KEY','4-32767':'Reserved for future use','32768-65535':'Reserved for private use'}

    retData = [] #List of data to return, things required for future crypto

    def __init__(self,debug):
        self.debug = debug

    def transformCalculations(self, hexPacket, prevPayLen):
	transAtts = []
	###***This method needs to be cleaned up
	numAtts = prevPayLen + 56#56 = sa and proposal payloads + transform payload header, static value for now but may need to be dynamic if these are variable length which I don't think they are
        transAtts.append(hexPacket[numAtts:numAtts+8])
	payLen = int(hexPacket[prevPayLen+44:prevPayLen+48],16)
	finByte = numAtts - 16  + payLen*2# 16 is the length of the transform payload header (8 bytes)
	#Check the type of value (fixed or long unsigned), fixed byte length or a non-fixed value
	while numAtts < finByte:
		for i in xrange(0,16):#16 is the limit set in the IKE RFC but this is not explicitly followed by all vendors
			if hexPacket[numAtts:numAtts+2] == "80":
				transAtts.append(hexPacket[numAtts:numAtts+8])
				if self.debug > 0:
					print "Value type has fixed size"
				numAtts += 8

			elif hexPacket[numAtts:numAtts+2] == "00":
				#Take transform length and add number of bytes to numAtts to avoid it being processed as an 8 byte payload
                                transLen = int(hexPacket[numAtts+4:numAtts+8],16)
				transAtts.append(hexPacket[numAtts:numAtts+8+(transLen * 2)])#8 = the 4 bytes used for the length value
                                if self.debug > 0:
                                        print "Value type not fixed"
                                        print "Transform length: %s"%transLen	
				numAtts += 8 + (transLen * 2)
			else:
				if self.debug > 0:
					print "End of transform set"
					break


        #Find number of transforms, parse them and add them to a human readable dictionary for later use
	###***There is duplication here this next bit can probably be removed and processed in the above loop
        numTrans = len(transAtts)
	if self.debug > 0:
                print "Transforms attributes to process: %s"%numTrans
		print "Full Transforms dictionary: %s"%transAtts
	atts = {}
	for i in xrange(0,numTrans):
		if transAtts[i][0:2] == "80":
			attType = int(transAtts[i][2:4],16)
			attValue = int(transAtts[i][4:8],16)
			atts[attType] = attValue
		elif transAtts[i][0:2] == "00":
			attType = int(transAtts[i][2:4],16)
			attLen = int(transAtts[i][4:8],16)*2
                        attValue = int(transAtts[i][8:8+attLen],16)
                        atts[attType] = attValue
		else:
			print "Invalid transform attribute, something went wrong"
			exit()
	attDict = {}
	#Process the transform according to it's attribute class/type
	for i in atts:
		att = atts[i]
		attType = self.dicAtts[str(i)]
		if attType == "Encryption Algorithm":
			attValue = self.dicEType[str(att)]
			attDict[attType] = attValue
			if self.debug > 0:
                                print "%s : %s"%(attType,attValue)
			pass
		elif attType == "Hash Algorithm":
                        attValue = self.dicHType[str(att)]
                        attDict[attType] = attValue
                        if self.debug > 0:
                                print "%s : %s"%(attType,attValue)
			pass
                elif attType == "Authentication Method":
                        attValue = self.dicAType[str(att)]
                        attDict[attType] = attValue
                        if self.debug > 0:
                                print "%s : %s"%(attType,attValue)
                        pass
                elif attType == "Group Description":
                        attValue = self.dicDHGroup[str(att)]
                        attDict[attType] = attValue
                        if self.debug > 0:
                                print "%s : %s"%(attType,attValue)
                        pass
                elif attType == "Life Type":
                        attValue = self.dicLType[str(att)]
                        attDict[attType] = attValue
                        if self.debug > 0:
                                print "%s : %s"%(attType,attValue)
                        pass
                elif attType == "Life Duration":
                        attDict[attType] = att
                        if self.debug > 0:
                                print "%s : %s"%(attType,att)
                        pass
		elif attType == "Key Length":
			attDict[attType] = att
			if self.debug > 0:
				print "%s : %s"%(attType,att)
			pass
		else:
			if self.debug > 0:
				print "Unsupported Transform attribute type received. Continuing anyway...\n"

	return attDict,finByte

    def transformParsing(self, hexPacket, prevPayLen, propTrans, saPayLen, saFinByte):
	#Requires hex packet data, previous payload length, the length up to the end of the last payload processed, number of transforms to process, 
        payNext = int(hexPacket[prevPayLen+40:prevPayLen+42],16) #padded an extra 2 bytes (reserved space
        payLen = int(hexPacket[prevPayLen+44:prevPayLen+48],16)
	transNum = hexPacket[prevPayLen+48:prevPayLen+50]
        transId = hexPacket[prevPayLen+50:prevPayLen+52]
	padding = hexPacket[prevPayLen+52:prevPayLen+56]#padded 4 bytes to +16

        if self.debug > 0:
		print "Parsing Transform Payloads:"
                print "Next Payload: %s"%self.dicPayloads[str(payNext)]
                print "Payload Length: %s"%payLen
                print "Transform Number: %s"%transNum
                print "Transform ID: %s"%transId

	for i in range(1,propTrans+1):
                if self.debug > 0:
                        print "Parsing Transform Set %s:"%i
		transCalc = self.transformCalculations(hexPacket, prevPayLen) #sa payload length plus 4 bytes of padding is where the transform payload begins?# + 12 bytes for the proposal header, not sure if this will cover all scenarios

	#need these to do every transform, at the moment only processes the first over and over
	return transCalc #dictionary of accepted transform set and final byte of the proposal/transform payload
    

    def parseHeader(self,hexPacket):
        #IKE HDR 28 bytes
        iCookie = hexPacket[0:16]
        rCookie = hexPacket[16:32]
        payNext = int(hexPacket[32:34], 16)
        version = hexPacket[34:36]
        xType = int(hexPacket[36:38],16)
        flags = hexPacket[38:40]
        msgID = hexPacket[40:48]
        payLen = int(hexPacket[48:56], 16)
	finByte = 56 #Final byte position of payload (static value of 56 for the header)
        if self.debug > 0:
                print "Parsing IKE Header:"
                print "Initiator Cookie: %s"%iCookie
                print "Responder Cookie: %s"%rCookie
                print "Next Payload: %s "%self.dicPayloads[str(payNext)]
                print "Version: %s"%version
                print "Exchange Type: %s (%s)"%(xType,self.dicXTypes[str(xType)])
		if flags == "01":
			print "Flags: %s (Encrypted)"%flags
		else:
	                print "Flags: %s (Plain)"%flags
                print "Message ID: %s"%msgID
                print "Payload Length: %s\n"%payLen

	return payNext,iCookie,rCookie,version,xType,msgID,payLen,flags,finByte

    def parseSA(self, hexPacket, prevPayLen):
        #Process SA payload
	#Requires hexlified packet and previous payload length as a starting point for the current payload
        #Begin with the SA header
	saPayNext = int(hexPacket[prevPayLen:prevPayLen+2], 16) #Padding 2 bytes after this (reserved space)
        saPayLen = int(hexPacket[prevPayLen+4:prevPayLen+8], 16)
        doi = hexPacket[prevPayLen+8:prevPayLen+16]
        sit = hexPacket[prevPayLen+16:prevPayLen+24]
	saFinByte = saPayLen + prevPayLen

	if self.debug > 0:
		print "Parsing SA payload:"
		print "Next Payload: %s"%self.dicPayloads[str(saPayNext)]
                print "Domain of Interpretation: %s"%doi
                print "Situation: %s"%sit
		print "Full SA Payload: %s\n"%hexPacket[prevPayLen:prevPayLen+(saPayLen*2)]

	#Then process the proposal header
        propPayNext = int(hexPacket[prevPayLen+24:prevPayLen+26],16)#Padding 2 bytes after this (reserved space)
        propPayLen = int(hexPacket[prevPayLen+28:prevPayLen+32],16)
        propNum = hexPacket[prevPayLen+32:prevPayLen+34]
        protId = hexPacket[prevPayLen+34:prevPayLen+36]
        spiSize = hexPacket[prevPayLen+36:prevPayLen+38]
        propTrans = int(hexPacket[prevPayLen+38:prevPayLen+40],16)

        #Finally process the Transform payload
        SA = self.transformParsing(hexPacket, prevPayLen, propTrans, saPayLen, saFinByte)#use sa payload length plus 4 bytes of pad as starting point for the transform attributes?
        transform = SA[0]
        finByte = SA[-1]

        if self.debug > 0:
                print "Parsing Proposal Payload:"
                print "Next Payload: %s"%self.dicPayloads[str(propPayNext)]
                print "Payload Length: %s"%propPayLen
                print "SPI Size: %s"%spiSize
                print "Proposal Transforms: %s\n"%propTrans
	return saPayNext,transform,saPayLen,finByte


    def parseKE(self,hexPacket,prevPayLen):
        #Process KE payload
        #Requires hexlified packet and previous payload length as a starting point for the current payload
	payNext = int(hexPacket[prevPayLen:prevPayLen+2], 16)#Padding with 2 bytes (reserved space)
	payLen = int(hexPacket[prevPayLen+4:prevPayLen+8], 16)
        KEData = hexPacket[prevPayLen+8:prevPayLen+(payLen * 2)]
	finByte = prevPayLen + (payLen * 2)

        if self.debug > 0:
		print "Parsing Key Exchange Payload:"
                print "Next Payload: %s"%self.dicPayloads[str(payNext)]
                print "Payload Length: %s"%payLen
		print "KE data: %s\n"%KEData
	return payNext,KEData,payLen,finByte

    def NonceProcessing(self,hexPacket,prevPayLen):
	#Process Nonce payload
        #Requires hexlified packet and previous payload le?ngth as a starting point for the current payload
	payNext = int(hexPacket[prevPayLen:prevPayLen+2], 16)#Padding with 2 bytes (reserved space)
	payLen = int(hexPacket[prevPayLen+4:prevPayLen+8], 16)
    	nonce = hexPacket[prevPayLen+8:prevPayLen+(payLen * 2)]
	finByte = prevPayLen + (payLen * 2)

        if self.debug > 0:
		print "Parsing Nonce Payload:"
		print "Next Payload: %s"%payNext
		print "Payload Length: %s"%payLen
		print "Nonce: %s\n"%nonce

	return payNext,nonce,payLen,finByte

    def IDProcessing(self,hexPacket,prevPayLen):
        #Process ID payload
        #Requires hexlified packet and previous payload length as a starting point for the curr
        payNext = int(hexPacket[prevPayLen:prevPayLen+2], 16)#Padding with 2 bytes (reserved space)
        payLen = int(hexPacket[prevPayLen+4:prevPayLen+8], 16)
        IDtype = hexPacket[prevPayLen+8:prevPayLen+10]
	IDprot = hexPacket[prevPayLen+10:prevPayLen+12]
	port = hexPacket[prevPayLen+12:prevPayLen+16]
        finByte = prevPayLen + (payLen * 2)
	IDdata = hexPacket[prevPayLen+16:finByte]

        if self.debug > 0:
                print "Parsing ID Payload:"
                print "Next Payload: %s"%self.dicPayloads[str(payNext)]
                print "Payload Length: %s"%payLen
                print "ID Type: %s"%self.dicIDType[str(int(IDtype,16))]
                print "ID Data: %s\n"%IDdata
		
	ID_r = IDtype+IDprot+port+IDdata
	return payNext,ID_r,finByte

    def parseHash(self,hexPacket,prevPayLen):
        #Process Hash payload
        #Requires hexlified packet and previous payload length as a starting point for the current payload
        payNext = int(hexPacket[prevPayLen:prevPayLen+2], 16)#Padding with 2 bytes (reserved space)
        payLen = int(hexPacket[prevPayLen+4:prevPayLen+8], 16)
        hashData = hexPacket[prevPayLen+8:prevPayLen+(payLen*2)]
        finByte = prevPayLen + (payLen * 2)

        if self.debug > 0:
                print "Parsing Hash Payload:"
		try:
			print "Next Payload: %s"%self.dicPayloads[str(int(payNext,16))]
		except:
                	print "Next Payload: %s"%self.dicPayloads[str(payNext)]
                print "Payload Length: %s"%payLen
                print "Hash Data: %s\n"%hashData

        return payNext,hashData,payLen,finByte

    def parseXAUTH(self, hexPacket, firstByte, finByte):
	attsXAUTH = {}
	atts = firstByte
	if self.debug > 0:
		print "XAUTH Payload: %s"%hexPacket[firstByte:]
        while atts < finByte:
		#Parse attribute type and length then store type and value as dictionary 
		attXAUTH = hexPacket[atts:atts+4]
		#Workaround for cisco nuance
		if attXAUTH[0] !=4:
			attXAUTH = "4"+attXAUTH[1::]
		attXAUTH = int(attXAUTH,16)
                if attXAUTH == 16527 or attXAUTH == 16520:
			#no variable length for status or type attributes
			attXAUTHValue = int(hexPacket[atts+4:atts+8],16)
		        if self.debug > 0:
                                print "Mode Config Attribute Type: %s (%s)"%(self.dicXAUTHAtts[str(attXAUTH)],attXAUTH)
                                print "Mode Config Attribute Value: %s"%attXAUTHValue
			if attXAUTH == 16527 and attXAUTHValue == 0:
				if self.debug > 0:
					print "XAUTH Authentication Unsuccessful"
                        elif attXAUTH == 16527 and attXAUTHValue == 1:
				if self.debug > 0:
	                                print "XAUTH Authentication Successful"
				
		else:
                	attLen = int(hexPacket[atts+4:atts+8],16)*2
			attXAUTHValue = hexPacket[atts+8:atts+8+attLen]
                	if self.debug > 0:
				try:
		                	print "Mode Config Attribute Type: %s (%s)"%(self.dicXAUTHAtts[str(attXAUTH)],attXAUTH)
				except:
					print "Mode Config Attribute Type: Unknown (%s)"%attXAUTH
				print "Mode Config Attribute Length: %s"%attLen
				print "Mode Config Attribute Value: %s (%s)"%(attXAUTHValue.decode('hex'), attXAUTHValue)

			atts += attLen
		atts += 8
		attsXAUTH[attXAUTH] = attXAUTHValue
	return attsXAUTH

    def parseModeCFG(self,hexPacket,prevPayLen):
	#Process ModeCFG payload
        #Requires hexlified packet and previous payload length as a starting point for the current payload)
	payNext = int(hexPacket[prevPayLen:prevPayLen+2], 16)#Padding with 2 bytes (reserved space)
	payLen = int(hexPacket[prevPayLen+4:prevPayLen+8], 16)
        mcfgType = int(hexPacket[prevPayLen+8:prevPayLen+10], 16)#Padding with 2 bytes (reserved space) 
	mcfgID = int(hexPacket[prevPayLen+12:prevPayLen+14], 16)
	
	mcfgAtt = hexPacket[prevPayLen+16:prevPayLen+(payLen * 2)]
        finByte = prevPayLen + (payLen * 2)
	firstByte = prevPayLen+16

        if self.debug > 0:
                print "Parsing Mode Config Payload:"
                print "Next Payload: %s"%self.dicPayloads[str(payNext)]
                print "Payload Length: %s"%payLen
                print "Mode Config Message Type: %s"%self.dicMCFGType[str(mcfgType)]
                print "Mode Config ID: %s\n"%mcfgID

	
	attsXAUTH = self.parseXAUTH(hexPacket, firstByte, finByte)
        return payNext,mcfgType,mcfgID,mcfgAtt,attsXAUTH,finByte

    def parseVID(self,hexPacket,prevPayLen):
        #Process VID payload
        #Requires hexlified packet and previous payload length as a starting point for the current payload)
        payNext = int(hexPacket[prevPayLen:prevPayLen+2], 16)#Padding with 2 bytes (reserved space)
        payLen = int(hexPacket[prevPayLen+4:prevPayLen+8], 16)
        VIDData = hexPacket[prevPayLen+8:prevPayLen+(payLen * 2)]
        finByte = prevPayLen + (payLen * 2)

        if self.debug > 0:
                print "Parsing VID Payload;"
                print "Next Payload: %s"%self.dicPayloads[str(payNext)]
                print "Payload Length: %s"%payLen
                print "VID Data: %s\n"%VIDData

        return payNext,VIDData,payLen,finByte


    def parseNATD(self,hexPacket,prevPayLen):
        #Process NAT-D payload
        #Requires hexlified packet and previous payload length as a starting point for the current payload)
        payNext = int(hexPacket[prevPayLen:prevPayLen+2], 16)#Padding with 2 bytes (reserved space)
        payLen = int(hexPacket[prevPayLen+4:prevPayLen+8], 16)
        NATDData = hexPacket[prevPayLen+8:prevPayLen+(payLen * 2)]
        finByte = prevPayLen + (payLen * 2)

        if self.debug > 0:
                print "Parsing NAT-D Payload:"
                print "Next Payload: %s"%self.dicPayloads[str(payNext)]
                print "Payload Length: %s"%payLen
                print "Hash of the address and port: %s\n"%NATDData

        return payNext,NATDData,payLen,finByte


    def parseNot(self,hexPacket,prevPayLen):
        #Process Notification payload
        #Requires hexlified packet and previous payload length as a starting point for the curre$
        payNext = int(hexPacket[prevPayLen:prevPayLen+2], 16)#Padding with 2 bytes (reserved spa$
        payLen = int(hexPacket[prevPayLen+4:prevPayLen+8], 16)
        doi = hexPacket[prevPayLen+8:prevPayLen+16]
        protID = hexPacket[prevPayLen+16:prevPayLen+18]
        spiSize = hexPacket[prevPayLen+18:prevPayLen+20]
        msgType = int(hexPacket[prevPayLen+20:prevPayLen+24],16)
        spi = hexPacket[prevPayLen+24:prevPayLen+24 + (int(spiSize,16)*2)]
        finByte = prevPayLen + (payLen * 2)
        notData = hexPacket[prevPayLen+24 + (int(spiSize,16)*2):finByte]
        if self.debug > 0:
                print "Parsing Notification Payload:"
                print "Next Payload: %s"%self.dicPayloads[str(payNext)]
                print "Payload Length: %s"%payLen
		print "DOI: %s"%doi
		print "Protocol ID: %s"%protID
                print "SPI Size: %s (%s)"%(spiSize, int(spiSize,16))
		try:
	                print "Notify Message Type: %s"%self.dicNotType[str(msgType)]
		except:
			print "Notify Message Type: %s (Unknown Type)"%msgType
                print "SPI: %s"%spi
                print "Notification Data: %s\n"%notData 

        return payNext,msgType,notData,payLen,finByte


    def parseDel(self,hexPacket,prevPayLen): 
        #Process Delete payload
        #Requires hexlified packet and previous payload length as a starting point for the current payloaf
        payNext = int(hexPacket[prevPayLen:prevPayLen+2], 16)#Padding with 2 bytes (reserved space)
        payLen = int(hexPacket[prevPayLen+4:prevPayLen+8], 16)
        doi = hexPacket[prevPayLen+8:prevPayLen+16]
        protID = hexPacket[prevPayLen+16:prevPayLen+18]
        spiSize = hexPacket[prevPayLen+18:prevPayLen+20]
        spiNum = int(hexPacket[prevPayLen+20:prevPayLen+24],16)
	spi = hexPacket[prevPayLen+24:prevPayLen+(payLen * 2)]
        finByte = prevPayLen + (payLen * 2)

        if self.debug > 0:
                print "Parsing Delete Payload:"
                print "Next Payload: %s"%self.dicPayloads[str(payNext)]
                print "Payload Length: %s"%payLen
                print "DOI: %s"%doi
                print "Protocol ID: %s"%protID
                print "SPI Size: %s"%spiSize
                print "Number of SPI's: %s"%spiNum 
                print "SPI('s): %s\n"%spi

        return payNext,payLen,finByte

    def parsePayload(self,hexPacket,nextPay,flags,finByte):
	#Process payload according to 'next payload' type received from previous payload
	#Provide the hexlified packet data and the next payload, flag and final byte
	while nextPay != 0:
		if nextPay == 1:
			#Process SA -> Proposal -> transform payloads
			ikeSA = self.parseSA(hexPacket,finByte)
                	finByte = ikeSA[-1]
			SATransform = ikeSA[1]#will need to return the transform values eventually
	                nextPay = ikeSA[0]
			try:
				dicCrypto["keyLen"] = SATransform["Key Length"]
				pass
			except:
				pass

        	elif nextPay == 2:
			print "Next Payload %s - Support for this payload is not supported yet"%self.dicPayloads[str(nextPay)]
			exit()

        	elif nextPay == 3:
			print "Next Payload %s - Support for this payload is not supported yet"%self.dicPayloads[str(nextPay)]
			exit()

		elif nextPay == 4:
			#Process KE payload
			ikeKE = self.parseKE(hexPacket,finByte)
			KEData = ikeKE[1]
	                finByte = ikeKE[-1]
	                nextPay = ikeKE[0]
			dicCrypto["DHPubKey_r"] = KEData

        	elif nextPay == 5:
			#Process ID payload
			ikeID = self.IDProcessing(hexPacket,finByte)
			ID_r = ikeID[1]
	                finByte = ikeID[-1]
        	        nextPay = ikeID[0]
			dicCrypto["ID_r"] = ID_r

        	elif nextPay == 6:
			print "Next Payload (%s) - Support for this payload is not supported yet"%self.dicPayloads[str(nextPay)]

	        elif nextPay == 7:
			print "Next Payload (%s) - Support for this payload is not supported yet"%self.dicPayloads[str(nextPay)]

        	elif nextPay == 8:
			#Process Hash payload
			ikeHash = self.parseHash(hexPacket,finByte)
			HashData = ikeHash[1]
	                finByte = ikeHash[-1]
			nextPay = ikeHash[0]
			#Don't see the need to check for a valid hash yet

	       	elif nextPay == 9:
			print "Next Payload %s - Support for this payload is not supported yet"%self.dicPayloads[str(nextPay)]
			exit()

		elif nextPay == 10:
			#Process Nonce payload
			ikeNonce = self.NonceProcessing(hexPacket,finByte)
			nonce_r = ikeNonce[1]
	                finByte = ikeNonce[-1]
			nextPay = ikeNonce[0]
			dicCrypto["nonce_r"] = nonce_r

                elif nextPay == 11:
                        #Process Notification payload
                        ikeNot = self.parseNot(hexPacket,finByte)
                        finByte = ikeNot[-1]
                        nextPay = ikeNot[0]
			dicCrypto["notmsgType"] = ikeNot[1]
	
        	elif nextPay == 12:
                        #Parse Delete payload
                        ikeNot = self.parseDel(hexPacket,finByte)
                        finByte = ikeNot[-1]
                        nextPay = ikeNot[0]
			exit()

        	elif nextPay == 13:
			#Process VID payload
			ikeVID = self.parseVID(hexPacket,finByte)
			ikeVIDdata = ikeVID[1]
			listVIDs.append(ikeVIDdata)
			finByte = ikeVID[-1]
			nextPay = ikeVID[0]

                elif nextPay == 14:
                        #Process Mode CFG payload
                        ikeMCFG = self.parseModeCFG(hexPacket,finByte)
                        finByte = ikeMCFG[-1]
                        nextPay = ikeMCFG[0]
			dicCrypto["mcfgType"] = ikeMCFG[1]
			attsXAUTH = ikeMCFG[-2]
			for key, value in attsXAUTH.iteritems():
				if key == 16527:
					dicCrypto["XAUTH_STATUS"] = value
                elif nextPay == 20:
                        #Process NAT-D payload
                        ikeNATD = self.parseNATD(hexPacket,finByte)
                        ikeNATDdata = ikeNATD[1]
                        finByte = ikeNATD[-1]
                        nextPay = ikeNATD[0]

        	elif nextPay == 130:
                	#Process VID payload (NAT-D)
                	ikeVID = self.parseVID(hexPacket,finByte)
                	ikeVIDdata = ikeVID[1]
                	listVIDs.append(ikeVIDdata)
                	finByte = ikeVID[-1]
                	nextPay = ikeVID[0]

		else:
			print "Error: Invalid 'next payload', something went wrong. Perhaps an invalid next payload type or support for this payload is not added yet?\nThis could also be caused by an invalid payload decryption due to invalid IV or key.\nMost common cause for this is multiple instances of the tool being run in short succession causing confusion. For now just wait 30-60 seconds and restart.\nDebug output:\n%s"%nextPay
			exit()

	return self.retData


    def main(self,hexPacket,encType,hashType,*args):
	if len(args) != 0 and len(args) !=3:
		print "ikeHandler needs either packet, encryption type, hash type, or all of those with encryption Key, initial IV, last Current IV arguments. Exiting..."
		exit()
	elif len(args) == 3:
		encKey,initIV,curIV = args
	else:
		pass

	#Run IKE handler class
	ikeHandling = IKEv1Handler(self.debug)
	#Process IKE Header
	ikeHDR = ikeHandling.parseHeader(hexPacket)
	#Returns payNext,iCookie,rCookie,version,msgID,payLen,flags,finByte
	finByte = ikeHDR[-1]
	nextPay = ikeHDR[0]
	iCookie = ikeHDR[1]
	rCookie = ikeHDR[2]
	version = ikeHDR[3]
	xType = ikeHDR[4]
	msgID = ikeHDR[5]
	payLen = ikeHDR[6]
	flags = ikeHDR[7]
	if encType == "AES" or int(encType) == 7 or encType == "07":
		IVlen = 32
	else:
		IVlen = 16

	#Check we are talking IKE version 1
	if version != "10":
		print "Not IKEv1"
		print "IKEv2 is not supported yet\nExiting..."
		exit()

        #Check for encrypted payload
        if flags == "01":
                encPayload = hexPacket[56:int(payLen)*2]
		rawencPayload = encPayload.decode('hex')

                if self.debug > 0:
                        print "Encrypted payload received."
                        print "Encrypted Payload: %s"%encPayload
		if msgID == "00000000":
			#If the message ID is null then initial IV is used
			ikeCrypto = crypto.ikeCrypto()
			ikeDecrypt = ikeCrypto.ikeCipher(encKey, initIV.decode('hex'), encType)
        		ikePlain = ikeDecrypt.decrypt(rawencPayload).encode('hex')		
			if self.debug > 0:
				print "Decrypted payload: %s"%ikePlain
			ikeHandling.parsePayload(ikePlain,nextPay,flags,0)
			p2IV = encPayload[len(encPayload)-IVlen:]
			if self.debug > 0:
				print "Phase 2 IV: %s"%p2IV
			dicCrypto["p2IV"] = p2IV
			#need to return the phase 2 IV if proceeding to phase 2 later?
			return dicCrypto, listVIDs


		elif msgID != "00000000":
                	ikeCrypto = crypto.ikeCrypto()
                	try:
                        	if self.debug > 0:
                        	        print "Current IV: %s"%curIV.encode('hex')
                        	ikeDecrypt = ikeCrypto.ikeCipher(encKey, curIV, encType)
                        	ikePlain = ikeDecrypt.decrypt(rawencPayload).encode('hex')
				if self.debug > 0:
	                        	print "Decrypted payload: %s"%ikePlain
				ikePlain = ikeCrypto.stripPadding(encType, ikePlain)
				if self.debug > 0:
					print "Stripped decrypted payload: %s"%ikePlain
				#Parse the plaintext payloads
				if xType == "04" or xType ==4:
                                	ikeHandling.parsePayload(ikePlain,nextPay,flags,0)
                                	dicCrypto["rCookie"] = rCookie
                                	dicCrypto["xType"] = xType
                                	dicCrypto["iCookie"] = iCookie
                                	dicCrypto["msgID"] = msgID
                                	return dicCrypto,listVIDs


				elif xType == "05" or xType == 5:
                                	ikeHandling.parsePayload(ikePlain,nextPay,flags,0)
                                	dicCrypto["rCookie"] = rCookie
                                	dicCrypto["xType"] = xType
                                	dicCrypto["iCookie"] = iCookie
                                	dicCrypto["msgID"] = msgID
                                	return dicCrypto,listVIDs

                        	elif xType == "06" or xType == 6:
                                	ikeHandling.parsePayload(ikePlain,nextPay,flags,0)
                                	dicCrypto["rCookie"] = rCookie
                                	dicCrypto["xType"] = xType
                                	dicCrypto["iCookie"] = iCookie
                                	dicCrypto["msgID"] = msgID
                                	return dicCrypto

                        	else:
                                	print "This exchange type %s is not included yet. Exiting..."%xType
                                	exit()

			except Exception,e:
				print "Decryption Failed with error: %s"%e
				traceback.print_exc()
				exit()



	if xType == "04" or xType ==4:
		ikeHandling.parsePayload(hexPacket,nextPay,flags,finByte)
                dicCrypto["rCookie"] = rCookie
                dicCrypto["xType"] = xType
                dicCrypto["iCookie"] = iCookie
                dicCrypto["msgID"] = msgID
		return dicCrypto,listVIDs#Returns dictionary of useful value for crypto and state, Also a list of VIDs for fingerprinting in the first exchange packet.

	elif xType == "05" or xType == 5:
                ikeHandling.parsePayload(hexPacket,nextPay,flags,finByte)
                dicCrypto["rCookie"] = rCookie
                dicCrypto["xType"] = xType
                dicCrypto["iCookie"] = iCookie
                dicCrypto["msgID"] = msgID
                return dicCrypto,listVIDs

	elif xType == "06" or xType == 6:
                ikeHandling.parsePayload(hexPacket,nextPay,flags,finByte)
                dicCrypto["rCookie"] = rCookie
                dicCrypto["xType"] = xType
                dicCrypto["iCookie"] = iCookie
                dicCrypto["msgID"] = msgID
                return dicCrypto


	else:
                print "This exchange type %s is not included yet. Exiting..."%xType
                exit()


    if __name__ == '__main__':
	main(hexPacket,encType,hashType,debug)
