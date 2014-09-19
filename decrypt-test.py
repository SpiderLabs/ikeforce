import sys
import ikehandler
import crypto

#Test decryption and packet handling from a hex stream. Edit out the comments to read from raw packet file exported form Wireshark for example

"""
#load packet bytes from file
file = open(sys.argv[1],"r")
rawencPayload = file.read().encode('hex')[56:]
file.seek(0)
rawPacket = file.read().encode('hex')
"""

#Load packet hex stream
hexStream = sys.argv[1]
rawencPayload = hexStream[56:]
rawPacket = hexStream

#Declare some variables. This needs to be extracted from the debug logs.
IVlen = 32
hashType = "sha"
debug = 1
encType = "07"
nextPay = 8
flags = "01"
encKey = "9fdcc741c2468cb47cf9544827d6403b"


#initIV = "41761b266f986223b77860669f51bceb"
initIV = "e1745e46e47c9a2e9d1d4876bb514dc0"



#lastBlock = "e141257409fae7d9c5cde52d8700103f"
lastBlock = "c8c5714355f61130c0fc3285dcf4950e"

msgID = rawPacket[40:48]

#lastBlock = "bdf25ac1c30047f777db1751f3490d7b"
#lastBlock = "3aa023c54ce5a3f7ce5797a1c15b671f"

ikeHandler = ikehandler.IKEv1Handler(debug)
ikeCrypto = crypto.ikeCrypto()

curIV = ikeCrypto.calcIV(initIV.decode('hex'),msgID.decode('hex'), IVlen, hashType)

print "encKey ",encKey
print "initIV ",initIV
print "msgID ",msgID
#print "lastBlock ",lastBlock
print "rawencPayload ",rawencPayload
print "curIV ",curIV.encode('hex')
print rawPacket

try:
	lastBlock
	print "Trying lastBlock: ",lastBlock
	ikeDecrypt = ikeCrypto.ikeCipher(encKey.decode('hex'), lastBlock.decode('hex'), encType)
	ikeHandler.main(rawPacket,encType,hashType,encKey.decode('hex'),initIV.decode('hex'),lastBlock.decode('hex'))
	
except:
	ikeDecrypt = ikeCrypto.ikeCipher(encKey.decode('hex'), curIV, encType)
	ikeHandler.main(rawPacket,encType,hashType,encKey.decode('hex'),initIV.decode('hex'),curIV)
