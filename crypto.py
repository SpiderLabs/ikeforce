#!/usr/bin/python

#IKEForce
#Created by Daniel Turner
#Copyright (C) 2014 Trustwave Holdings, Inc.
#This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
#This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
#You should have received a copy of the GNU General Public License along with this program. If not, see <http://www.gnu.org/licenses/>.

import hmac
import binascii
import hashlib
from Crypto.Cipher import *

debug = 0

class ikeCrypto(object):

    def calcSKEYID(self, psk, rawNonce_i, rawNonce_r, hashType):
	#Supply nonces as raw bytes and psk as string
	#Returns SKEYID bytes
	if hashType == "md5" or hashType == "01":
                skeyid = hmac.new(psk,rawNonce_i+rawNonce_r).hexdigest()
                if debug > 0:
                        print "SKEYID: %s"%skeyid
                SKEYID = skeyid.decode('hex')
	
        elif hashType == "sha" or hashType == "02":
		skeyid = hmac.new(psk,rawNonce_i+rawNonce_r,hashlib.sha1).hexdigest()
                if debug > 0:
                        print "SKEYID: %s"%skeyid
                SKEYID = skeyid.decode('hex')

	else:   
        	print "Invalid hashtype specified.\nExiting..."
                exit()
	return SKEYID

    def calcHASH(self, SKEYID, rawDHPub_r, rawDHPub_i, rawCookie_r, rawCookie_i, rawSA_i, rawID_r, rawID_i, riHash, hashType):
	##Supply all values as raw bytes (decoded hex string), except last value which should be 'i' or 'r' for initiator or responder hash to calculate	
	if hashType == "md5" or hashType == "01":
		if riHash == "r":
			HASH_R = hmac.new(SKEYID, rawDHPub_r+rawDHPub_i+rawCookie_r+rawCookie_i+rawSA_i+rawID_r).hexdigest()
			if debug > 0:
				print 'HASH_R: %s'%HASH_R
			return HASH_R

		elif riHash == "i": 
			HASH_I = hmac.new(SKEYID, rawDHPub_i+rawDHPub_r+rawCookie_i+rawCookie_r+rawSA_i+rawID_i).hexdigest()
			if debug > 0:
				print 'HASH_I: %s'%HASH_I
			return HASH_I
		

		else:
			print "Invalid hash type specified, value should be 'i'(initiator) or 'r'(responder)\nExiting..."
			exit()

	elif hashType == "sha" or hashType == "02":
		if riHash == "r":
			HASH_R = hmac.new(SKEYID, rawDHPub_r+rawDHPub_i+rawCookie_r+rawCookie_i+rawSA_i+rawID_r,hashlib.sha1).hexdigest()
			if debug > 0:
				print 'HASH_R: %s'%HASH_R
                	return HASH_R

	        elif riHash == "i":
	                HASH_I = hmac.new(SKEYID, rawDHPub_i+rawDHPub_r+rawCookie_i+rawCookie_r+rawSA_i+rawID_i,hashlib.sha1).hexdigest()
        	        if debug > 0:
				print 'HASH_I: %s'%HASH_I
                	return HASH_I

	        else:   
        	        print "Invalid hash type specified, value should be 'i'(initiator) or 'r'(responder)\nExiting..."
        	        exit()

	else:   
                print "Invalid hashtype specified.\nExiting..."
                exit()



    def calcHASHmcfg(self, SKEYID_a, msgID, mcfgAttr, hashType):
        ##Supply all values as raw bytes
        if hashType == "md5" or hashType == "01":
                mcfgHASH = hmac.new(SKEYID_a, msgID+mcfgAttr).hexdigest()
                if debug > 0:
                        print 'Mode Config HASH: %s'%mcfgHASH
                return mcfgHASH
        elif hashType == "sha" or hashType == "02":
                mcfgHASH = hmac.new(SKEYID_a, msgID+mcfgAttr,hashlib.sha1).hexdigest()
                if debug > 0:
                        print 'Mode Config HASH: %s'%mcfgHASH
                return mcfgHASH
        else:
                print "Invalid hashtype specified.\nExiting..."
                exit()



    def calcHASHQM(self, SKEYID_a, msgID, data, hashType, hashNum):
        ##Supply all values as raw bytes, except hashNum which is the hash number 1-3
	#HASH(1) = prf(SKEYID_a, M-ID | SA | Ni [ | KE ] [ | IDci | IDcr )
   	#HASH(2) = prf(SKEYID_a, M-ID | Ni_b | SA | Nr [ | KE ] [ | IDci | IDcr )
	#HASH(3) = prf(SKEYID_a, 0 | M-ID | Ni_b | Nr_b)

	if hashType == "md5" or int(hashType) == 1:
		if hashNum == 1:
		        qmHASH = hmac.new(SKEYID_a, msgID+data).hexdigest()
	       		if debug > 0:
				print 'Quick Mode HASH1: %s'%qmHASH
        		return qmHASH
	elif hashType == "sha" or int(hashType) == 2:
                if hashNum == 1:
                        qmHASH = hmac.new(SKEYID_a, msgID+data,hashlib.sha1).hexdigest()
                        if debug > 0:
                                print 'Quick Mode HASH1: %s'%qmHASH
                        return qmHASH
        if hashType == "md5" or int(hashType) == 1:
                if hashNum == 3:
                        qmHASH = hmac.new(SKEYID_a, "\x00"+msgID+data).hexdigest()#where data = Ni_b | Nr_b
                        if debug > 0:
                                print 'Quick Mode HASH3: %s'%qmHASH
                        return qmHASH
        elif hashType == "sha" or int(hashType) == 2:
                if hashNum == 3:
                        qmHASH = hmac.new(SKEYID_a, "\x00"+msgID+data,hashlib.sha1).hexdigest()#where data = Ni_b | Nr_b
                        if debug > 0:
                                print 'Quick Mode HASH3: %s'%qmHASH
                        return qmHASH

        else:
                print "Invalid hashtype specified.\nExiting..."
                exit()


    def calcHASHgen(self, SKEYID, rawData, hashType):
	#Generic hash generation supplying all following payloads as the data in raw bytes
	if hashType == "md5" or hashType == "01":
		HASH_I = hmac.new(SKEYID, rawData).hexdigest()
		if debug > 0:
			print 'HASH: %s'%HASH_I
		return HASH
		
	elif hashType == "sha" or hashType == "02":
		HASH = hmac.new(SKEYID, rawData,hashlib.sha1).hexdigest()
		if debug > 0:
			print 'HASH: %s'%HASH
                return HASH

	else:   
                print "Invalid hashtype specified.\nExiting..."
                exit()


    def calcSKEYID_d(self, SKEYID, rawDHShared, rawCookie_i, rawCookie_r, hashType):
        #Provide values as raw decoded hex strings
        #SKEYID_d = prf(SKEYID, g^xy | CKY-I | CKY-R | 0)
	if hashType == "md5" or hashType == "01":
	        skeyid_d = hmac.new(SKEYID, rawDHShared+rawCookie_i+rawCookie_r+"\x00").hexdigest()
        	SKEYID_d = skeyid_d.decode('hex')
        	if debug > 0:
			print 'SKEYID_d %s'%skeyid_d
        	return SKEYID_d
	elif hashType == "sha" or hashType == "02":
                skeyid_d = hmac.new(SKEYID, rawDHShared+rawCookie_i+rawCookie_r+"\x00",hashlib.sha1).hexdigest()
                SKEYID_d = skeyid_d.decode('hex')
                if debug > 0:
			print 'SKEYID_d %s'%skeyid_d
                return SKEYID_d
        else:   
                print "Invalid hashtype specified.\nExiting..."
                exit()

    def calcSKEYID_a(self, SKEYID, SKEYID_d, rawDHShared, rawCookie_i, rawCookie_r, hashType):
	#Provide values as raw decoded hex strings
	if hashType == "md5" or hashType == "01":
	        skeyid_a = hmac.new(SKEYID, SKEYID_d+rawDHShared+rawCookie_i+rawCookie_r+"\x01").hexdigest()
        	SKEYID_a = skeyid_a.decode('hex')
        	if debug > 0:
			print 'SKEYID_a %s'%skeyid_a
		return SKEYID_a
	elif hashType == "sha" or hashType == "02":
                skeyid_a = hmac.new(SKEYID, SKEYID_d+rawDHShared+rawCookie_i+rawCookie_r+"\x01",hashlib.sha1).hexdigest()
                SKEYID_a = skeyid_a.decode('hex')
                if debug > 0:
			print 'SKEYID_a %s'%skeyid_a
                return SKEYID_a
        else:   
                print "Invalid hashtype specified.\nExiting..."
                exit()

    def calcSKEYID_e(self, SKEYID, SKEYID_a, rawDHShared, rawCookie_i, rawCookie_r, hashType):
        #Provide values as raw decoded hex strings
	if hashType == "md5" or hashType == "01":
	        skeyid_e = hmac.new(SKEYID, SKEYID_a+rawDHShared+rawCookie_i+rawCookie_r+"\x02").hexdigest()
        	SKEYID_e = skeyid_e.decode('hex')
        	if debug > 0:
			print 'SKEYID_e: %s'%skeyid_e
        	return SKEYID_e
	elif hashType == "sha" or hashType == "02":
                skeyid_e = hmac.new(SKEYID, SKEYID_a+rawDHShared+rawCookie_i+rawCookie_r+"\x02",hashlib.sha1).hexdigest()
                SKEYID_e = skeyid_e.decode('hex')
                if debug > 0:
			print 'SKEYID_e: %s'%skeyid_e
                return SKEYID_e
        else:   
                print "Invalid hashtype specified.\nExiting..."
                exit()

    def calcKa(self, SKEYID_e, keyLen, hashType):
	#Calculate the encryption key
        #Provide SKEYID_e as raw bytes and keLen as integer
	keyLen = keyLen * 2
        if hashType == "md5" or hashType == "01":
	        k1 = hmac.new(SKEYID_e, "\x00").hexdigest()
		K1 = k1.decode('hex')
        	if debug > 0:
                	print "K1: %s"%k1
		if len(k1) < keyLen:
			k2 = hmac.new(SKEYID_e, K1).hexdigest()
			k2List = (k1,k2)
        		ka = ''.join(k2List)
			K2 = k2.decode('hex')
			if debug > 0:
        	        	print "K2: %s"%k2
        	        if len(ka) < keyLen:
        	                k3 = hmac.new(SKEYID_e, K2).hexdigest()
                        	if debug > 0:
                                	print "K3: %s"%k3
				k3List = (k1,k2,k3) 
				ka = ''.join(k3List)
				K3 = k3.decode('hex')
				Ka = ka[:keyLen]
				if debug > 0:
        	                	print "Ka: %s"%ka
				return Ka.decode('hex')
			else:
				Ka = ka[:keyLen]
				if debug > 0:
	       		         	print "Ka (Encryption Key): %s"%Ka
				return Ka.decode('hex')
		
		else:
			Ka = k1[:keyLen]
			return Ka.decode('hex')


        elif hashType == "sha" or hashType == "02":
                k1 = hmac.new(SKEYID_e, "\x00", hashlib.sha1).hexdigest()
                K1 = k1.decode('hex')
                if debug > 0:
                        print "K1: %s"%k1
                if len(k1) < keyLen:
                        k2 = hmac.new(SKEYID_e, K1, hashlib.sha1).hexdigest()
                        k2List = (k1,k2)
                        ka = ''.join(k2List)
                        K2 = k2.decode('hex')
                        if debug > 0:
                                print "K2: %s"%k2
                        if len(ka) < keyLen:
                                k3 = hmac.new(SKEYID_e, K2, hashlib.sha1).hexdigest()
                        	if debug > 0:
                                	print "K3: %s"%k3
                                k3List = (k1,k2,k3)
                                ka = ''.join(k3List)
                                K3 = k3.decode('hex')
                                Ka = ka[:keyLen]
                                if debug > 0:
                                        print "Ka: %s"%ka
                                return Ka.decode('hex')
                        else:
                                Ka = ka[:keyLen]
                                if debug > 0:
                                        print "Ka (Encryption Key): %s"%Ka
                                return Ka.decode('hex')

                else:
                        Ka = k1[:keyLen]
                        return Ka.decode('hex')

        else:   
                print "Invalid hashtype specified.\nExiting..."
                exit()


    def calcIV(self, input1, input2, IVLen, hashType):
        #Calculate the IV for the first message of phase 2 encryption
        #Provide provide either the DH values as bytes(DHPub_i & DHPub_r) or the message ID and final bytes of previous encrypted block, length as an integer and hash type as a string (currently 'md5' or 'sha')
        if hashType == "md5" or int(hashType) == 1:
		iv = hashlib.md5()
		iv.update(input1)
		iv.update(input2)
		iv = iv.hexdigest()[:IVLen]
		if debug > 0:
               		print "IV: %s"%iv
		IV = iv.decode('hex')

        elif hashType == "sha" or int(hashType) == 2:
                iv = hashlib.sha1()
                iv.update(input1)
                iv.update(input2)
                iv = iv.hexdigest()[:IVLen]
                if debug > 0:
                        print "IV: %s"%iv
                IV = iv.decode('hex')	
	
	else:
		print "Invalid hashtype specified.\nExiting..."
		exit()
	return IV


    def ikeCipher(self, encKey, IV, encType):
	#Decrypt ISAKMP encrypted payload
	#Provide the encrypted payload as bytes
	if encType == "3DES-CBC" or encType == "05" or encType == 5:

        	if debug > 0:
                	print "Encrypting/Decrypting 3DES ISAKMP payload"	
        	crypt = DES3.new(encKey, DES.MODE_CBC, IV)
		return crypt

        if encType == "DES-CBC" or encType == "01" or encType == 1:

                if debug > 0:
                        print "Encrypting/Decrypting DES ISAKMP payload"
                crypt = DES.new(encKey, DES.MODE_CBC, IV)
                return crypt

        if encType == "AES-CBC" or encType == "07" or encType == 7:

                if debug > 0:
                        print "Encrypting/Decrypting AES ISAKMP payload"
                crypt = AES.new(encKey, AES.MODE_CBC, IV)
                return crypt


	else:
		print "Invalid or unsupported encryption type selected\nExiting..."
		exit()


    def calcPadding(self, encType, data):
	#Calculate padding required and padd supplied data with zero's
	#Provide plain-text payload as bytes
	if encType == "3DES-CBC" or int(encType) == 5:
		blockSize = 8
        	if len(data) % blockSize != 0:
                	padding = blockSize - len(data) % blockSize
        	else:
                	padding = 0
	        data = data + ("\x00" * padding)
	        return data
		

        if encType == "DES-CBC" or int(encType) == 1:
                blockSize = 8
                if len(data) % blockSize != 0:
                        padding = blockSize - len(data) % blockSize
                else:
                        padding = 0
                data = data + ("\x00" * padding)
                return data

        if encType == "AES-CBC" or int(encType) == 7:
                blockSize = 16
                if len(data) % blockSize != 0:
                        padding = blockSize - len(data) % blockSize
                else:
                        padding = 0
                data = data + ("\x00" * padding)
                return data

	else:
                print "Invalid or unsupported encryption type selected\nExiting..."
		print int(encType)
                exit()

	if debug > 0:
		print "Padding plain-text payload to block size of: %s"%blockSize
 		print "Padding: %s"%padding


    def stripPadding(self, encType, data):
	#Strip padding from decrypted payload
	#Provide encrypted payload as bytes
        if debug > 0:
                        print "Stripping padding from plain-text payload"
	data[0:-ord(data[-1])]
	return data

    def calcKEYMAT(self, hashType, keyLen, SKEYID_d, prot, SPI, nonce_i, nonce_r, *arg):
	#Provide all values as raw bytes, if PFS is required provide the new shared secret as the 8th argument otherwise don't
	#KEYMAT = prf(SKEYID_d, protocol | SPI | Ni_b | Nr_b).
	keyLen = keyLen*2 # using hex strings instead of bytes
	try:
		arg[0]
		print "PFS Enabled, using new shared secret"
                if hashType == "md5" or int(hashType) == 1:
                        keymat = hmac.new(SKEYID_d, arg+prot+SPI+nonce_i+nonce_r).hexdigest()
                        if debug > 0:
                                print 'Phase 2 Key: %s'%keymat
                elif hashType == "sha" or int(hashType) == 2:
                        keymat = hmac.new(SKEYID_d, arg+prot+SPI+nonce_i+nonce_r, hashlib.sha1).hexdigest()
                        if debug > 0:
                                print 'Phase 2 Key: %s'%keymat
                else:
                        print "Invalid hash type specified"

	except:
		if hashType == "md5" or int(hashType) == 1:
			keymat = hmac.new(SKEYID_d, prot+SPI+nonce_i+nonce_r).hexdigest()
        	elif hashType == "sha" or int(hashType) == 2:
                	keymat = hmac.new(SKEYID_d, prot+SPI+nonce_i+nonce_r, hashlib.sha1).hexdigest()
		else:
			print "Invalid hash type specified"
		#keyLen = keyLen/8
		if debug > 0:
			print "Key Length: %s (bytes)"%keyLen
		###***make this a method
		if len(keymat.decode('hex')) < keyLen:
			k1 = keymat
			k2 = hmac.new(SKEYID_d, k1.decode('hex')).hexdigest()
        		ka = k1+k2
			if debug > 0:
        	        	print "K2: %s"%k2
        	        if len(ka.decode('hex')) < keyLen:
        	                k3 = hmac.new(SKEYID_d, k2.decode('hex')).hexdigest()
                        	if debug > 0:
                                	print "K3: %s"%k3
				ka = k1+k2+k3
				ka = ka[:keyLen]
				if debug > 0:
					print "Ka (Encryption Key):: %s"%ka
				keymat = ka.decode('hex')

			else:
				ka = ka[:keyLen]
				if debug > 0:
	       		         	print "Ka (Encryption Key): %s"%ka
				keymat = ka.decode('hex')
		
		else:
			ka = keymat[:keyLen]
			if debug > 0:
				print "Ka (Encryption Key): %s"%ka
			keymat = ka.decode('hex')
	if debug > 0:
		print 'Phase 2 Key: %s'%keymat.encode('hex')
	return keymat

def main():
	#Declare static values for testing
	psk = 'cisco1'
	DHPub_r = "49b776c2f31803e9eb2f49750ce881fd1d4dfce1c82fa5d5168c4ddcddadeef235db4bb5ec822f0ac4030a9dba31eea7f0b358e919f341a6c2865515f4c571bd50c0fc5912aa8e4b594894ab0f551709e4c26fa60bf2d993f068aadd5152e9bf0d21dcfcda990c71cf38ee3dd250fd2b894bedbbdeca13f22d10b640141a2a64"
	rawDHPub_r = DHPub_r.decode('hex')
	DHPub_i = "7cfb56f64e1a1068413577c6e1fc06a22b2abe6684d3e54c814e16f1c87143d39b0763c246c981aec3e3684ec8503ee031c7fe177909d2fa79c9db7eb9b8acc9d012c5cd3d4fcae62af2b7a849d0ebb661091d7d82e067924e8e88d506967793caa2f829c010e023ca35c1903fbf15326eedae8332cdad5b44c9c45c08c726c2"
	rawDHPub_i = DHPub_i.decode('hex')
	SA_i = "000000010000000100000398000100180300002800010000800e01008001000780020002800400028003fde9800b0001000c00040020c49b0300002801010000800e01008001000780020001800400028003fde9800b0001000c00040020c49b0300002802010000800e00c08001000780020002800400028003fde9800b0001000c00040020c49b0300002803010000800e00c08001000780020001800400028003fde9800b0001000c00040020c49b0300002804010000800e00808001000780020002800400028003fde9800b0001000c00040020c49b0300002805010000800e00808001000780020001800400028003fde9800b0001000c00040020c49b03000024060100008001000580020002800400028003fde9800b0001000c00040020c49b03000024070100008001000580020001800400028003fde9800b0001000c00040020c49b03000024080100008001000180020002800400028003fde9800b0001000c00040020c49b03000024090100008001000180020001800400028003fde9800b0001000c00040020c49b030000240a0100008001000080020002800400028003fde9800b0001000c00040020c49b030000240b0100008001000080020001800400028003fde9800b0001000c00040020c49b030000280c010000800e010080010007800200028004000280030001800b0001000c00040020c49b030000280d010000800e010080010007800200018004000280030001800b0001000c00040020c49b030000280e010000800e00c080010007800200028004000280030001800b0001000c00040020c49b030000280f010000800e00c080010007800200018004000280030001800b0001000c00040020c49b0300002810010000800e008080010007800200028004000280030001800b0001000c00040020c49b0300002811010000800e008080010007800200018004000280030001800b0001000c00040020c49b030000241201000080010005800200028004000280030001800b0001000c00040020c49b030000241301000080010005800200018004000280030001800b0001000c00040020c49b030000241401000080010001800200028004000280030001800b0001000c00040020c49b030000241501000080010001800200018004000280030001800b0001000c00040020c49b030000241601000080010000800200028004000280030001800b0001000c00040020c49b000000241701000080010000800200018004000280030001800b0001000c00040020c49b"
        rawSA_i = SA_i.decode('hex')
	cookie_r = "25c250397161ddf3"
	rawCookie_r = cookie_r.decode('hex')
	cookie_i = "1dc509539bb7fcbc"
	rawCookie_i = cookie_i.decode('hex')
	ID_r = "01110000c0a83965"
	rawID_r = ID_r.decode('hex')
	ID_i = "0b1101f476706e"
	rawID_i = ID_i.decode('hex')
	nonce_r = "2b9d2a46590f8764a09c5f09b08f10d2cfb3f918"
	rawNonce_r = nonce_r.decode('hex')
	nonce_i = "1b8f8ccb5f4ea7a42e8736bf07bfc3b95952f0ce"
	rawNonce_i = nonce_i.decode('hex')
	protocol = "01".decode('hex')#(ISAKMP)
	cookies = (rawCookie_i,rawCookie_r)
	SPI = ''.join(cookies)
	#dh shared key
	DHShared = "87c9227fef61f00fc1ef177bc6ad7525da9f8be352d85e1e6881c677cdf4d995154c9ac27b5c233e4bb442f11e5f3a58d6ddb6048457202f13ea6adf40be1bf6e033b52dbd6639b4969add6a190f397e888df9a731163c41fbe13aee366cba374a6701ee4301b843463ad3958cfd340c5714f56d0c1d4458314d7b9377d6cde3"
	rawDHShared = DHShared.decode('hex')
	HASH_RX = "fdeccaf17df52da84ff5d90732dc590a"
        print "Resulting hash should be: ", HASH_RX
	SKEYID_RX = "819dfcd8958a54c4392201b07104f0a9"
	print "Resulting SKEYID should be: ", SKEYID_RX
	SKEYID_D_RX = "d2fe08df8a8afe704f5f4adc699d7506"
	print "Resulting SKEYID_d should be: ", SKEYID_D_RX
	SKEYID_A_RX = "1f043c7f300ef7ebfce877cbf8043556"
	print "Resulting SKEYID_a should be: ", SKEYID_A_RX
	SKEYID_E_RX = "5cb806c1a0b3c95266960d537a2546bf"
	print "Resulting SKEYID_e should be: ", SKEYID_E_RX
	ENCKEY_RX = "12a7b18b59eb8ed2b5e2f2495e31ec19e6077b6c1d4e4c9a"
	print "Resulting Encryption Key should be ", ENCKEY_RX
	IV_RX = "a415214e85050bef"
	print "Resulting IV should be ", IV_RX
        lastBlock = "e17b19a405fb38bc"

	IVLen = 16
	keyLen = 48
	hashType = "md5"
	encType = "3DES-CBC"
	ikePayload = "ace343b2a8048664f3f595f78bee289bdeb7751231ea2dd6e3c40aa610723b73204aa0e866314426"
	msgID = "b11f6d9b"
	mcfgAttr = "f00000001401000000c088000040890000408a0000"

	#Run through main function
	testCrypt = ikeCrypto()   
	SKEYID = testCrypt.calcSKEYID(psk, rawNonce_i, rawNonce_r, hashType)
	HASH_R = testCrypt.calcHASH(SKEYID, rawDHPub_r, rawDHPub_i, rawCookie_r, rawCookie_i, rawSA_i, rawID_r, rawID_i, "r", hashType)
	HASH_I = testCrypt.calcHASH(SKEYID, rawDHPub_r, rawDHPub_i, rawCookie_r, rawCookie_i, rawSA_i, rawID_r, rawID_i, "i", hashType)
	SKEYID_d = testCrypt.calcSKEYID_d(SKEYID, rawDHShared, rawCookie_i, rawCookie_r, hashType)
	SKEYID_a = testCrypt.calcSKEYID_a(SKEYID, SKEYID_d, rawDHShared, rawCookie_i, rawCookie_r, hashType)
	SKEYID_e = testCrypt.calcSKEYID_e(SKEYID, SKEYID_a, rawDHShared, rawCookie_i, rawCookie_r, hashType)
	#KEYMAT = testCrypt.calcKEYMAT(SKEYID_d, rawDHShared, protocol, SPI, raw		
	"""
		HASH(1) = prf(SKEYID_a, M-ID | SA | Ni [ | KE ] [ | IDci | IDcr )
		   HASH(2) = prf(SKEYID_a, M-ID | Ni_b | SA | Nr [ | KE ] [ | IDci |
		   IDcr )
		   HASH(3) = prf(SKEYID_a, 0 | M-ID | Ni_b | Nr_b)
	"""

	encKey = testCrypt.calcKa(SKEYID_e, keyLen, hashType)
	initIV = testCrypt.calcIV(rawDHPub_i, rawDHPub_r, IVLen, hashType)
	curIV = testCrypt.calcIV(lastBlock.decode('hex'), msgID.decode('hex'), IVLen, hashType)

	if msgID == "00000000":
		cipher = testCrypt.ikeCipher(encKey, initIV, encType)
		print cipher.decrypt(ikePayload).encode('hex')
	else:
                cipher = testCrypt.ikeCipher(encKey, curIV, encType)
                print cipher.decrypt(ikePayload).encode('hex')


	HASHmcfg = testCrypt.calcHASHmcfg(SKEYID_a, msgID.decode('hex'), mcfgAttr.decode('hex'), hashType)

if __name__ == '__main__':
        main()

