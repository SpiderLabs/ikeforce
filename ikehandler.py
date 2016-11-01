#IKEForce
#Created by Daniel Turner
#Copyright (C) 2014 Trustwave Holdings, Inc.
#This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
#This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
#You should have received a copy of the GNU General Public License along with this program. If not, see <http://www.gnu.org/licenses/>.

import traceback
import sys
import ikecrypto

#IKE/ISAKMP packet handler classes
#Declare global dictionary and list for VIDs and crypto operations
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
    dicNotType = {'1':'INVALID-PAYLOAD-TYPE','2':'DOI-NOT-SUPPORTED','3':'SITUATION-NOT-SUPPORTED','4':'INVALID-COOKIE','5':'INVALID-MAJOR-VERSION','6':'INVALID-MINOR-VERSION','7':'INVALID-EXCHANGE-TYPE','8':'INVALID-FLAGS','9':'INVALID-MESSAGE-ID','10':'INVALID-PROTOCOL-ID','11':'INVALID-SPI','12':'INVALID-TRANSFORM-ID','13':'ATTRIBUTES-NOT-SUPPORTED','14':'NO-PROPOSAL-CHOSEN','15':'BAD-PROPOSAL-SYNTAX','16':'PAYLOAD-MALFORMED','17':'INVALID-KEY-INFORMATION','18':'INVALID-ID-INFORMATION','19':'INVALID-CERT-ENCODING','20':'INVALID-CERTIFICATE','21':'CERT-TYPE-UNSUPPORTED','22':'INVALID-CERT-AUTHORITY','23':'INVALID-HASH-INFORMATION','24':'AUTHENTICATION-FAILED','25':'INVALID-SIGNATURE','26':'ADDRESS-NOTIFICATION','27':'NOTIFY-SA-LIFETIME','28':'CERTIFICATE-UNAVAILABLE','29':'UNSUPPORTED-EXCHANGE-TYPE','30':'UNEQUAL-PAYLOAD-LENGTHS', '24576': 'STATUS_RESP_LIFETIME', '36136':'R-U-THERE','36137':'R-U-THERE-ACK'}
    dicMCFGType = {'0':'RESERVED','1':'ISAKMP_CFG_REQUEST','2':'ISAKMP_CFG_REPLY','3':'ISAKMP_CFG_SET','4':'ISAKMP_CFG_ACK','5-127':'Reserved for Future Use','128-255':'Reserved for Private Use'}
    dicMCFGAtt = {'0':'RESERVED','1':'INTERNAL_IP4_ADDRESS','2':'INTERNAL_IP4_NETMASK','3':'INTERNAL_IP4_DNS','4':'INTERNAL_IP4_NBNS','5':'INTERNAL_ADDRESS_EXPIRY','6':'INTERNAL_IP4_DHCP','7':'APPLICATION_VERSION','13':'INTERNAL_IP4_SUBNET','14':'SUPPORTED_ATTRIBUTES'}#missing ipv6 values
    dicXAUTHAtts = {'16520':'XAUTH_TYPE','16521':'XAUTH_USER_NAME','16522':'XAUTH_USER_PASSWORD','16523':'XAUTH_PASSCODE','16524':'XAUTH_MESSAGE','16525':'XAUTH_CHALLENGE','16526':'XAUTH_DOMAIN','16527':'XAUTH_STATUS'}
    dicXAUTHTypes = {'0':'Generic','1':'RADIUS-CHAP','2':'OTP','3':'S/KEY','4-32767':'Reserved for future use','32768-65535':'Reserved for private use'}
    dicIDESP = {'0':'Reserved','1':'ENCR_DES_IV64','2':'ENCR_DES','3':'ENCR_3DES','4':'ENCR_RC5','5':'ENCR_IDEA','6':'ENCR_CAST','7':'ENCR_BLOWFISH','8':'ENCR_3IDEA','9':'ENCR_DES_IV32','10':'Reserved','11':'ENCR_NULL','12':'ENCR_AES_CBC','13':'ENCR_AES_CTR','14':'ENCR_AES-CCM_8','15':'ENCR-AES-CCM_12','16':'ENCR-AES-CCM_16','17':'Unassigned'}
    dicAttsESP = {'0':'Reserved','1':'SA Life Type','2':'SA Life Duration','3':'Group Description','4':'Encapsulation Mode','5':'Authentication Algorithm','6':'Key Length','7':'Key Rounds'}
    dicEncModeTypeESP = {'0':'Reserved', '1':'Tunnel', '2':'Transport'}
    dicATypeESP = {'0':'Reserved', '1':'HMAC-MD5', '2':'HMAC-SHA', '3':'DES-MAC', '4':'KPDK'}
    dicCertType = {'0':'NONE','1':'PKCS7 wrapped X.509 certificate','2':'PGP Certificate','3':'DNS Signed Key','4':'X.509 Certificate - Signature','5':'X.509 Certificate - Key Exchange','6':'Kerberos Tokens','7':'Certificate Revocation List CRL','8':'Authority Revocation List ARL','9':'SPKI Certificate','10':'X.509 Certificate - Attribute'}
    retData = [] #List of data to return, things required for future crypto

    def __init__(self,debug):
        self.debug = debug

    def transformCalculations(self, hexPacket, payLen, phase):
	transAtts = []
	numAtts = 0 # 16 (8 bytes) = transform header length
	finByte = payLen
	#Check the type of value (fixed or long unsigned), fixed byte length or a non-fixed value
	atts = {}
	while numAtts < finByte:
		###***add whilte paynext != 0 here?
			if hexPacket[numAtts:numAtts+2] == "80":
				###***should be able to remove this list and just go with the dictionary only
				transAtts.append(hexPacket[numAtts:numAtts+8])
				if self.debug > 0:
					print "Value type has fixed size"
	                        attType = int(hexPacket[numAtts+2:numAtts+4],16)
                        	attValue = int(hexPacket[numAtts+4:numAtts+8],16)
                        	atts[attType] = attValue
				numAtts += 8

			elif hexPacket[numAtts:numAtts+2] == "00":
				#Take transform length and add number of bytes to numAtts to avoid it being processed as an 8 byte payload
                                transLen = int(hexPacket[numAtts+4:numAtts+8],16)
				transAtts.append(hexPacket[numAtts:numAtts+8+(transLen * 2)])#8 = the 4 bytes used for the length value
                                if self.debug > 0:
                                        print "Value type not fixed"
                                        print "Transform length: %s"%transLen	
	                        attType = int(hexPacket[numAtts+2:numAtts+4],16)
	                        attLen = int(hexPacket[numAtts+4:numAtts+8],16)*2
	                        attValue = hexPacket[numAtts+8:numAtts+8+attLen]
	                        atts[attType] = attValue
				numAtts = numAtts + (transLen * 2) + 8# 8 = attributes header
			else:
				try:
					payNext = int(hexPacket[numAtts:numAtts+2],16)
					if payNext == 3:
						numAtts = numAtts+16  # 16 = transform header
					
					if self.debug > 0:
						print "End of transform set"
						break
				except:
                                        if self.debug > 0:
                                                print "End of transform set"
					break

				else:
					break

								

        #Find number of transforms, parse them and add them to a human readable dictionary for later use
        numTrans = len(transAtts)
	attDict = {}
	#Process the transform according to it's attribute class/type
	if phase == 1:
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
				try:
	        	                attValue = self.dicHType[str(att)]
				except:
					attValue = str(att)
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
			elif attType == "Group Prime/Irreducible Polynomial":
                	        attDict[attType] = att
                        	if self.debug > 0:
                                	print "%s : %s"%(attType,att)
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
	elif phase == 2:
                for i in atts:
                        att = atts[i]
                        attType = self.dicAttsESP[str(i)]
                        if attType == "SA Life Type":
                                attDict[attType] = att
                                if self.debug > 0:
                                        print "%s : %s"%(attType,att)
				pass
			elif attType == "SA Life Duration":
                                attDict[attType] = att
                                if self.debug > 0:
                                        print "%s : %s"%(attType,att)
                                pass
                        elif attType == "Group Description":
                                attDict[attType] = att
                                if self.debug > 0:
                                        print "%s : %s"%(attType,att)
                                pass
                        elif attType == "Encapsulation Mode":
                                attValue = self.dicEncModeTypeESP[str(att)]
                                attDict[attType] = attValue
                                if self.debug > 0:
                                        print "%s : %s"%(attType,attValue)
                                pass
                        elif attType == "Authentication Algorithm":
                                attValue = self.dicATypeESP[str(att)]
                                attDict[attType] = attValue
                                if self.debug > 0:
                                        print "%s : %s"%(attType,attValue)
                                pass
                        elif attType == "Key Length":
                                attDict[attType] = att
                                if self.debug > 0:
                                        print "%s : %s"%(attType,att)
                                pass
                        elif attType == "Key Rounds":
                                attDict[attType] = att
                                if self.debug > 0:
                                        print "%s : %s"%(attType,att)
                                pass
                        elif attType == "Compress Dictionary Size":
                                attDict[attType] = att
                                if self.debug > 0:
                                        print "%s : %s"%(attType,att)
                                pass
                        elif attType == "Compress Private Algorithm":
                                attDict[attType] = att
                                if self.debug > 0:
                                        print "%s : %s"%(attType,att)
                                pass

                        else:
                                if self.debug > 0:
                                        print "Unsupported Transform attribute type received. Continuing anyway...\n"
		
	return attDict,finByte

    def transformParsing(self, hexPacket, propTrans, propHdrSize, phase):
	#Requires hex packet data, previous payload length, the length up to the end of the last payload processed, number of transforms to process, 
        payNext = int(hexPacket[:2],16) #padded an extra 2 bytes (reserved space)
        payLen = int(hexPacket[4:8],16)
        transNum = hexPacket[8:10]
        transId = hexPacket[10:12]
        padding = hexPacket[12:16]#padded 4 bytes to +16
	finByte = (payLen*2)# + 16 # 16 = transform payload header 
	transPayload = hexPacket[propHdrSize+16:finByte]#40 = proposal header + transform header
        if self.debug > 0:
		print "Parsing Transform Payloads:"
                print "Next Payload: %s"%self.dicPayloads[str(payNext)]
                print "Payload Length: %s"%payLen
                print "Transform Number: %s"%transNum
		if phase == 2:
			print "Transform ID: %s"%self.dicIDESP[str(int(transId, 16))]
		elif phase == 1:
	                print "Transform ID: %s"%transId

	lenTrans = finByte
	transCalc = self.transformCalculations(transPayload, finByte, phase)
	if phase == 2:
		transCalc[0]["Encryption Type"] = self.dicIDESP[str(int(transId, 16))]
	return transCalc, lenTrans, payNext#dictionary of accepted transform set and final byte of the proposal/transform payload

    
    def parseProposal(self, hexPacket, phase):
        #Process the proposal header
	#this method needs to be fed only the proposal payload with no sa header
        payNext = int(hexPacket[:2],16)#Padding 2 bytes after this (reserved space)
        payLen = int(hexPacket[4:8],16)
        propNum = hexPacket[8:10]
        protId = int(hexPacket[10:12], 16)
        spiSize = int(hexPacket[12:14],16)
        propTrans = int(hexPacket[14:16],16)
	if spiSize != 0:
        	spi = hexPacket[16:16+(spiSize*2)]
	else:
		spi = 0
        hdrfinByte = 16 + (spiSize*2) #header plus spi payload
        if self.debug > 0:
                print "Parsing Proposal Payload:"
                print "Next Payload: %s"%self.dicPayloads[str(payNext)]
                print "Payload Length: %s"%payLen
                print "Proposal Number: %s"%int(propNum, 16)
		print "Protocol ID: %s"%protId
                print "SPI Size: %s"%spiSize
                print "Proposal Transforms: %s"%propTrans
                print "SPI: %s\n"%spi

	SA = self.transformParsing(hexPacket, propTrans, hdrfinByte, phase)
        transform = SA[0]
	###***tidy this lot up a bit, eventually remove most of the finByte crap
	finByte = (payLen*2)
	
	if int(protId) == 3:
		phase = 2
	else:
		phase = 1
	
	if phase == 2:
	        return payNext,transform,propTrans,hdrfinByte,spi,finByte
	elif phase == 1:
		return payNext,transform,propTrans,hdrfinByte,finByte

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

    def parseSA(self, hexPacket, phase):
        #Process SA payload
	#Requires hexlified whole SA payload including header and which phase we are negotiating
        #Begin with the SA header
	payNext = int(hexPacket[:2], 16) #Padding 2 bytes after this (reserved space)
        payLen = int(hexPacket[4:8], 16)
        doi = hexPacket[8:16]
        sit = hexPacket[16:24]
	fullSAPayload = hexPacket[:payLen*2]
	if self.debug > 0:
		print "Parsing SA payload:"
		print "Next Payload: %s"%self.dicPayloads[str(payNext)]
		print "Payload length: %s"%payLen
                print "Domain of Interpretation: %s"%doi
                print "Situation: %s"%sit
		print "Full SA Payload: %s\n"%fullSAPayload
	fullPropPayload = fullSAPayload[24:] #minus SA header
	ikeProp = self.parseProposal(fullPropPayload, phase)
	payNextSA = payNext
	payNext = ikeProp[0]
	transform = ikeProp[1]
	propTrans = ikeProp[2]
	if phase == 1:
		propHdrSize = ikeProp[-2]
	elif phase == 2:
		propHdrSize = ikeProp[-3]
		spi = ikeProp[-2]
	if phase == 1:
		finByte = payLen*2 + propHdrSize + 16 + 24
		return payNextSA,payNext,transform,payLen,finByte
	elif phase ==2:
		finByte = propHdrSize + ikeProp[-1]
		return payNextSA,payNext,transform,payLen,spi,finByte


    def parseCR(self,hexPacket,prevPayLen):  
        #Process Certificate Request payload
        #Requires hexlified packet and previous payload length as a starting point for the current payload
        payNext = int(hexPacket[prevPayLen:prevPayLen+2], 16)#Padding with 2 bytes (reserved space)
        payLen = int(hexPacket[prevPayLen+4:prevPayLen+8], 16)
	cType = hexPacket[prevPayLen+8:prevPayLen+10]
        caData = hexPacket[prevPayLen+10:prevPayLen+(payLen * 2)] 
        finByte = prevPayLen + (payLen * 2)

        if self.debug > 0:
                print "Parsing Certificate Request Payload:"
                print "Next Payload: %s"%self.dicPayloads[str(payNext)]
                print "Payload Length: %s"%payLen
                print "Certificate Type: %s (%s)"%(cType,self.dicCertType[str(int(cType))])
		print "Certificate Authority: %s\n"%caData
        return payNext,cType,caData,payLen,finByte


    def parseC(self,hexPacket,prevPayLen):
        #Process Certificate payload
        #Requires hexlified packet and previous payload length as a starting point for the current payload
        payNext = int(hexPacket[prevPayLen:prevPayLen+2], 16)#Padding with 2 bytes (reserved space)
        payLen = int(hexPacket[prevPayLen+4:prevPayLen+8], 16)
        cType = hexPacket[prevPayLen+8:prevPayLen+10]
        caData = hexPacket[prevPayLen+10:prevPayLen+(payLen * 2)]
        finByte = prevPayLen + (payLen * 2)

        if self.debug > 0:
                print "Certificate Request  Payload:"
                print "Next Payload: %s"%self.dicPayloads[str(payNext)]
                print "Payload Length: %s"%payLen
                print "Certificate Type: %s\n"%cType 
                print "Certificate Authority: %s\n"%caData
        return payNext,cType,caData,payLen,finByte



    def parseSig(self,hexPacket,prevPayLen):
        #Process Signature payload
        #Requires hexlified packet and previous payload length as a starting point for the current payload
        payNext = int(hexPacket[prevPayLen:prevPayLen+2], 16)#Padding with 2 bytes (reserved space)
        payLen = int(hexPacket[prevPayLen+4:prevPayLen+8], 16)
        sigData = hexPacket[prevPayLen+10:prevPayLen+(payLen * 2)]
        finByte = prevPayLen + (payLen * 2)   

        if self.debug > 0:
                print "Parsing Signature Payload:"
                print "Next Payload: %s"%self.dicPayloads[str(payNext)]
                print "Payload Length: %s"%payLen
                print "Signature Data: %s\n"%sigData
        return payNext,sigData,payLen,finByte


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

    def parseID(self,hexPacket,prevPayLen):
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
		try:
	                print "ID Type: %s (%s)"%(self.dicIDType[str(int(IDtype,16))],int(IDtype,16))
		except:
			print "ID Type: %s"%int(IDtype,16)
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

    def parseQMHash(self,hexPacket,hashType):
        #Process Quick Mode Hash payload
	#payNext = 1
        payNext = int(hexPacket[prevPayLen:prevPayLen+2], 16)#Padding with 2 bytes (reserved space)
        payLen = int(hexPacket[prevPayLen+4:prevPayLen+8], 16)
	if hashType == "md5":
        	hashData = hexPacket[:32]
        	finByte = 32
        elif hashType == "sha":
                hashData = hexPacket[:40]
                finByte = 40
	else:
		print "Unsupported hash type. Exiting..."
		exit()


        if self.debug > 0:
                print "Parsing Hash Payload:"
                try:
                        print "Next Payload: %s"%self.dicPayloads[str(int(payNext,16))]
                except:
                        print "Next Payload: %s"%self.dicPayloads[str(payNext)]
                print "Payload Length: %s"%payLen
                print "Hash Data: %s\n"%hashData

        return payNext,hashData,finByte


    def parseXAUTH(self, hexPacket, firstByte, finByte):
	attsXAUTH = {}
	atts = firstByte
	if self.debug > 0:
		print "Mode CFG Payload: %s"%hexPacket[firstByte:]
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

		elif attXAUTH == 16385:
			attLen = int(hexPacket[atts+4:atts+8],16)*2
			attXAUTHValue = hexPacket[atts+8:atts+8+attLen]
                        if self.debug > 0:				
                                try:
                                        print "Mode Config Attribute Type: %s (%s)"%(self.dicXAUTHAtts[str(attXAUTH)],attXAUTH)
                                except:
                                        print "Mode Config Attribute Type: Unknown (%s)"%attXAUTH
                                print "Mode Config Attribute Length: %s"%attLen
                                print "Mode Config Attribute Value: %s (%s)"%(attXAUTHValue.decode('hex'), attXAUTHValue)
			if len(attXAUTHValue) == 8:
                        	dicCrypto["MCFG_IPi"] = attXAUTHValue
                        	ip = str(int(attXAUTHValue[:2], 16)) + "." + str(int(attXAUTHValue[2:4], 16)) + "." + str(int(attXAUTHValue[4:6], 16)) + "." + str(int(attXAUTHValue[6:8], 16))
                                print "Received IP address: %s"%ip
				atts += 8
				
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

    def parsePayload(self,hexPacket,nextPay,flags,finByte, phase):
	#Process payload according to 'next payload' type received from previous payload
	#Provide the hexlified packet data and the next payload, flag and final byte
	while nextPay != 0:
		if nextPay == 1:
			#Process SA -> Proposal -> transform payloads
			ikeSA = self.parseSA(hexPacket[finByte:], phase)
                        if phase == 1:
                                finByte = ikeSA[-1]
                                SATransform = ikeSA[2]#will need to return the transform values eventually
                                nextPay = ikeSA[0]
                        if phase == 2:
                                finByte = ikeSA[-1]+finByte
                                SATransform = ikeSA[2]#will need to return the transform values eventually
                                nextPay = ikeSA[0]
                                spi = ikeSA[-2]
				dicCrypto["p2spi"] = spi
                                for l in SATransform[0]:
                                        dicCrypto[l] = SATransform[0][l]

			try:
				dicCrypto["keyLen"] = SATransform["Key Length"]
			except:
				pass

        	elif nextPay == 2:
                        #Process Proposal -> transform payloads
                        ikeProp = self.parseProposal(hexPacket[finByte:],phase)
			if phase == 1:
                        	finByte = ikeProp[-1]
                        	SATransform = ikeProp[1]#will need to return the transform values eventually
                        	nextPay = ikeProp[0]
                        if phase == 2:
                                finByte = ikeProp[-1]
                                SATransform = ikeProp[1]#will need to return the transform values eventually
                                nextPay = ikeProp[0]
				spi = ikeProp[-3]
				dicCrypto["p2spi"] = spi
				for l in SATransform:
					dicCrypto[l] = SATransform[l]
                        try:
                                dicCrypto["keyLen"] = SATransform["Key Length"]
                                pass
                        except:
                                pass

        	elif nextPay == 3:
			print "Next Payload %s - Support for multiple transform sets not added yet"%self.dicPayloads[str(nextPay)]
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
			ikeID = self.parseID(hexPacket,finByte)
			ID_r = ikeID[1]
	                finByte = ikeID[-1]
        	        nextPay = ikeID[0]
			dicCrypto["ID_r"] = ID_r

        	elif nextPay == 6:
                        #Process Certificate payload
                        ikeC = self.parseC(hexPacket,finByte)
                        Cencoding = ikeC[1]
                        Cdata = ikeC[2]
                        finByte = ikeC[-1]
                        nextPay = ikeC[0]

	        elif nextPay == 7:
                        #Process Certificate Request payload
                        ikeCR = self.parseCR(hexPacket,finByte)
                        CRencoding = ikeCR[1]
                        CRdata = ikeCR[2]
                        finByte = ikeCR[-1]
                        nextPay = ikeCR[0]

        	elif nextPay == 8:
			#Process Hash payload
			ikeHash = self.parseHash(hexPacket,finByte)
			HashData = ikeHash[1]
	                finByte = ikeHash[-1]
			nextPay = ikeHash[0]
			#Don't see the need to check for a valid hash yet

	       	elif nextPay == 9:
                        #Process Signature payload
                        ikeSig = self.parseSig(hexPacket,finByte)
                        ikeSigData = ikeSig[1]
                        finByte = ikeSig[-1]
                        nextPay = ikeSig[0]

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
			notData = ikeNot[2]
			dicCrypto["notmsgType"] = ikeNot[1]
			dicCrypto["notData"] = notData
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
			#dicCrypto["MCFG_IPi"] = 0
			#dicCrypto["MCFG_IPr"] = 0
			attsXAUTH = ikeMCFG[-2]
			for key, value in attsXAUTH.iteritems():
				if key == 16527:
					dicCrypto["XAUTH_STATUS"] = value
				###***clean this up
				#elif key == 16385 and value != 0:
				#	dicCrypto["MCFG_IPi"] = value
				elif key == 16385 and value == 0:
					dicCrypto["MCFG_IPr"] = value
				elif key == 16386:
					dicCrypto["MCFG_subnet"] = value
                elif nextPay == 15:
                        #Process NAT-D payload
                        ikeNATD = self.parseNATD(hexPacket,finByte)
                        ikeNATDdata = ikeNATD[1]
                        finByte = ikeNATD[-1]
                        nextPay = ikeNATD[0]

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
			print "Error: Invalid 'next payload', something went wrong. Perhaps an invalid next payload type or support for this payload is not added yet.\nThis is usually caused by an invalid payload decryption due to invalid IV or key.\nDebug output:\nNext Payload: %s"%nextPay
			print "Whole packet: %s"%hexPacket
			print "Crypto values: %s"%dicCrypto
			###***remove exit from below to prevent bug? Maybe add break
			###EDIT
			exit()
			###/EDIT
	return


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
	if xType == 32:
		phase = 2
	else:
		phase = 1

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
			ikeHandling.parsePayload(ikePlain,nextPay,flags,0,phase)
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
                                	ikeHandling.parsePayload(ikePlain,nextPay,flags,0,phase)
                                	dicCrypto["rCookie"] = rCookie
                                	dicCrypto["xType"] = xType
                                	dicCrypto["iCookie"] = iCookie
                                	dicCrypto["msgID"] = msgID
                                	return dicCrypto,listVIDs


				elif xType == "05" or xType == 5:
                                	ikeHandling.parsePayload(ikePlain,nextPay,flags,0,phase)
                                	dicCrypto["rCookie"] = rCookie
                                	dicCrypto["xType"] = xType
                                	dicCrypto["iCookie"] = iCookie
                                	dicCrypto["msgID"] = msgID
                                	return dicCrypto,listVIDs

                        	elif xType == "06" or xType == 6:
                                	ikeHandling.parsePayload(ikePlain,nextPay,flags,0,phase)
                                	dicCrypto["rCookie"] = rCookie
                                	dicCrypto["xType"] = xType
                                	dicCrypto["iCookie"] = iCookie
                                	dicCrypto["msgID"] = msgID
                                	return dicCrypto

                                elif xType == "32" or xType == 32:
					ikeHandling.parsePayload(ikePlain,nextPay,flags,0,phase)
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
				###***added debug output here for bug fix
				traceback.print_exc()
				###***brute mode breaks here when incorrect IV is used
				###EDIT
				exit()
				#break
				###/EDIT



	if xType == "04" or xType ==4:
		ikeHandling.parsePayload(hexPacket,nextPay,flags,finByte,phase)
                dicCrypto["rCookie"] = rCookie
                dicCrypto["xType"] = xType
                dicCrypto["iCookie"] = iCookie
                dicCrypto["msgID"] = msgID
		return dicCrypto,listVIDs#Returns dictionary of useful value for crypto and state, Also a list of VIDs for fingerprinting in the first exchange packet.

	elif xType == "05" or xType == 5:
                ikeHandling.parsePayload(hexPacket,nextPay,flags,finByte,phase)
                dicCrypto["rCookie"] = rCookie
                dicCrypto["xType"] = xType
                dicCrypto["iCookie"] = iCookie
                dicCrypto["msgID"] = msgID
                return dicCrypto,listVIDs

	elif xType == "06" or xType == 6:
                ikeHandling.parsePayload(hexPacket,nextPay,flags,finByte,phase)
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
