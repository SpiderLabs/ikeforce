#Homebrew Diffie hellman calculation based on pyDHE by Mark Loiseau: 
#https://github.com/lowazo/pyDHE
#Not to be considered secure for full IPSEC usage
#!/usr/bin/env python

from binascii import hexlify
import hashlib

#Check for secure random number generator
try:
	import Crypto.Random.random
	secure_random = Crypto.Random.random.getrandbits
except ImportError:
	import OpenSSL
	secure_random = lambda x: long(hexlify(OpenSSL.rand.bytes(x>>3)), 16)


class DiffieHellman(object):
	#Diffie-Hellman
	#Requires a group number as an argument
        def __init__(self, DHGroup):
                """
                Generate the public and private keys.
                """

                if int(DHGroup) == 1:
			self.prime = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A63A3620FFFFFFFFFFFFFFFF
		
		elif int(DHGroup) == 2:
			self.prime = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF

		elif int(DHGroup) == 5:
			self.prime = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF
	
		else:
			print "Unsupported Diffie-Hellman group specified. Only 1,2 & 5 supported.\nExiting..."
			exit()

		self.generator = 2


	def genPrivateKey(self, bits):
		"""
		Generate a private key using a secure random number generator.
		"""
		return secure_random(bits)

	def genPublicKey(self,privateKey):
		"""
		Generate a public key X with g**x % p.
		"""
		return pow(self.generator, privateKey, self.prime)

	def checkPublicKey(self, otherKey):
		"""
		Check the other party's public key to make sure it's valid.
		Since a safe prime is used, verify that the Legendre symbol is equal to one.
		"""
		if(otherKey > 2 and otherKey < self.prime - 1):
			if(pow(otherKey, (self.prime - 1)/2, self.prime) == 1):
				return True
		return False

	def genSecret(self, privateKey, otherKey):
		"""
		Check to make sure the public key is valid, then combine it with the
		private key to generate a shared secret.
		"""
		if(self.checkPublicKey(otherKey) == True):
			sharedSecret = pow(otherKey, privateKey, self.prime)
			return sharedSecret
		else:
			raise Exception("Invalid public key.")

	def genKey(self, otherKey):
		"""
		Derive the shared secret, then hash it to obtain the shared key.
		"""
		self.sharedSecret = self.genSecret(self.privateKey, otherKey)
		s = hashlib.sha256()
		s.update(str(self.sharedSecret))
		self.key = s.digest()

	def getKey(self):
		"""
		Return the shared secret key
		"""
		return self.key

	def showParams(self):
		"""
		Show the parameters of the Diffie Hellman agreement.
		"""
		print "Prime: ", self.prime
		print "Generator: ", self.generator
		print "Private key: ", self.privateKey
		print "Public key: ", self.publicKey

	def showResults(self):
		"""
		Show the results of a Diffie-Hellman exchange.
		"""
		print "Results:"
		print
		print "Shared secret: ", self.sharedSecret
		print "Shared key: ", hexlify(self.key)
		print

if __name__=="__main__":
	"""
	Run an example Diffie-Hellman exchange 
	"""

	a = DiffieHellman()
	b = DiffieHellman()
	a.showParams()
	a.genKey(b.publicKey)
	b.genKey(a.publicKey)

	if(a.getKey() == b.getKey()):
		print "Shared keys match."
		print "Key:", hexlify(a.key)
	else:
		print "Shared secrets didn't match!"
		print "Shared secret: ", a.genSecret(b.publicKey)
		print "Shared secret: ", b.genSecret(a.publicKey)

