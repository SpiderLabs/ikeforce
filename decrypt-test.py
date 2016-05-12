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
IVlen = 16
hashType = "02"
debug = 1
encType = "05"
keyLen = 128
#nextPay = 8
#flags = "01"
#encKey = "97ed2e26b2502660a13360824bcc583328a21244e5df0457"
#encKey = "84a89f8bb9f7b9d9dddf732be144dfae"
#encKey = "adefc0d9e9cd5aede7c0f8a2248724e6ac0700579d299bc7"


################################
#details for cookie_i 619634d13cc3d654, 3des sha
#encKey = "177df705dca26dc464c2be2ba97d2aa507bfad4a7a220166"
encKey = 'tL\xde\xac\xcb0F\xb1\x9b\xf9\x8f\x8c\x11\xc74\x11\xae<\xa5aWy\x9b\x9b'.encode('hex')
skeyid_a = "c4069fa5a55aae3c"
skeyid_d = "14164e9546f73114dac9a110b954faa545333d01"
#p2IV = "9ed503bd2605176c"
p2IV = "115a440db7158086"
lastBlock = "c4069fa5a55aae3c".decode('hex')
#lastBlock = "81cedc6b9426b374".decode('hex')
#p2IV = "149ed503bd2605176c"
correctHash = "6d0a26147d27c02c7a098531850d0826"# QM hash_1
################################



"""
################################
#details for cookie_i, aes/128 sha
encKey = "ca9f1534ae8fe8ba0080ed09e3d005dc"
skeyid_a = "b9874438c22483c845062b4e94dae6efd86bf85e"
skeyid_d = "14164e9546f73114dac9a110b954faa545333d01"
p2IV = "115a440db7158086"
#p2IV = "149ed503bd2605176c"
correctHash = "6d0a26147d27c02c7a098531850d0826"# QM hash_1
################################
"""



"""
################################
#details for cookie_i, 3des, md5
encKey = "ea0c36ff11dd49661565f84e6f5d49d95a6798a9e71cc9cb"
skeyid_a = "dd996afdac771b5561143b97d3d4a17c"
skeyid_d = "b05fadd6c264451622b2c139d09bdd22"
p2IV = "1b8432d089be6ff6"
correctHash = "6d0a26147d27c02c7a098531850d0826"# QM hash_1
################################

###############################
#details for cookie_i 7a46fcdfc258e929 md5 3des
encKey = "ae59089abfe174251277cdbee29d17cbda9d67c7bc545fab"
p2IV = "0036ddd309b7283d"
##############################

###############################
#details for cookie_i 36aed8a5fad960a7 md5 3des
encKey = "d74266a68b0e32213e5c4518a2b6437603b289835f77e47a"
p2IV = "6139be47fccb962a"
###############################
"""
"""
###############################
#details for cookie_i 1ffdd25445bde2b4 md5 3des
encKey = "01a53301251b943e7000ed17ee34c8e58723b338d7305a66"
p2IV = "b4f3fba614813d44"
###############################
"""
"""
###############################
#details for cookie_i 166c9fb7331e157d md5 3des
encKey = "a5b2463e4c3f3312caefef6369d491080b81036731c3a09e"
p2IV = "7afae434834d2a29"
###############################
"""

"""
###############################
#details for cookie_i 5ca41efe07bede8c md5 3des
encKey = "a49cde2dd4f89b80b992447962af2a9cc4f132981d3c1ea2"
p2IV = "e869516e068aae60"
###############################
"""

"""
###############################
#details for cookie_i 04e58ee88fa81529 md5 3des
encKey = "5a3b5f488b3d0cae5f82fbe8e3df3a78723f1c23d3a6b2b2"
#p2IV = "bf3b72c878c8032d"
p2IV = "12ed57758e4b41ad"
###############################
"""


#lastBlock for QM should be the last block of the 3rd aggressive mode handshake packet
msgID = rawPacket[40:48]
ikeCrypto = crypto.ikeCrypto()

#initIV = "c4069fa5a55aae3c".decode('hex')
initIV = p2IV.decode('hex')
#curIV = "c4069fa5a55aae3c".decode('hex')
#initIV = "6139be47fccb962a".decode('hex')
#initIV = "cea46a34198827badf97eecbc3288ffb".decode('hex')

ikeHandler = ikehandler.IKEv1Handler(debug)
ikeCrypto = crypto.ikeCrypto()

#curIV = ikeCrypto.calcIV(lastBlock.decode('hex'),msgID.decode('hex'), IVlen, hashType)

#curIV = curIV[8:]
#curIV = "310b9f65dfb2542b".decode('hex')

print "encKey ",encKey
print "initIV ",initIV
print "msgID ",msgID
#print "lastBlock ",lastBlock
print "rawencPayload ",rawencPayload
#print "curIV ",curIV.encode('hex')
#print rawPacket


"""
try:
	lastBlock
	print "Trying lastBlock: ",lastBlock
	ikeDecrypt = ikeCrypto.ikeCipher(encKey.decode('hex'), lastBlock.decode('hex'), encType)
	ikeHandler.main(rawPacket,encType,hashType,encKey.decode('hex'),initIV,lastBlock.decode('hex'))
	
except:
	ikeDecrypt = ikeCrypto.ikeCipher(encKey.decode('hex'), initIV, encType)
	ikeHandler.main(rawPacket,encType,hashType,encKey.decode('hex'),initIV,curIV)

"""

#WORKING
lastBlock = ikeCrypto.calcIV(p2IV.decode('hex'),msgID.decode('hex'), IVlen, hashType)


#lastBlock = "1cbbce6832c70a07".decode('hex')
#lastBlock = "973f7cff51e45446".decode('hex')
#lastBlock = "68ba32de94a5c98b".decode('hex')

#lastBlock = "10e3e8e1ee65c655".decode('hex')
#bb323ef80e56e133c7669733e8c73d6917a11ad5af0d1cad361363074bb88311755caf6fb92843ce5a060df7be6c2b79584e399f47b2332216862c6b3896ed0cc58004d8f06b76d76bab1e30211508c27221783a09b2a3f9ca769b486e744ac04a62007ef562e1d0654b7cc5e63f2c093af4ae46c6c3649a0141594223225ec5ce559323a2f03fa8
#10e3e8e1ee65c655
#lastBlock = ikeCrypto.calcIV(initIV.decode('hex'),msgID.decode('hex'), IVlen, hashType)
print "lastBlock: %s"%lastBlock.encode('hex')

cipher = ikeCrypto.ikeCipher(encKey.decode('hex'), lastBlock, encType)
ikePlain = cipher.decrypt(rawencPayload.decode('hex')).encode('hex')
print ikePlain
ikeHandler.main(rawPacket,encType,hashType,encKey.decode('hex'),initIV,lastBlock)

#print "Trying lastBlock: ",lastBlock
#ikeDecrypt = ikeCrypto.ikeCipher(encKey.decode('hex'), lastBlock.decode('hex'), encType)
#decryptPacket = ikeDecrypt.decrypt(rawPacket)
#print decryptPacket.encode('hex')
#ikeHandler.main(rawPacket,encType,hashType,encKey.decode('hex'),initIV,lastBlock.decode('hex'))


#ikeDecrypt = ikeCrypto.ikeCipher(encKey.decode('hex'), curIV, encType)

#ikeHandler.main(rawPacket,encType,hashType,encKey.decode('hex'),initIV,curIV)

