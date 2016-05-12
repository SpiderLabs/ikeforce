IKEForce  
Dan Turner <dturner@trustwave.com>  
http://www.spiderlabs.com  

INTRODUCTION
============

IKEForce is a command line IPSEC VPN brute forcing tool for Linux that allows group name/ID enumeration and XAUTH brute forcing capabilities.  
Guides can be found here:  
http://blog.spiderlabs.com/2013/03/cracking-ike-aggressive-mode-hashes-part-1.html  
http://blog.spiderlabs.com/2013/04/cracking-ike-missionimprobable-part-2.html  
http://blog.spiderlabs.com/2014/09/cracking-ike-missionimprobable-part3.html  


INSTALL
=======
Requires the pyip, crypto and openssl modules installed, but other than that it's only standard libs.
pyip is the most likely lib that you won't have, install it with 'pip install pyip'

USAGE
=====

./ikeforce.py [target] [mode] -w /path-to/wordlist.txt [optional] -t 5 1 1 2  

**Example (enum mode):**  
./ikeforce.py 192.168.1.110 -e -w groupnames.txt -s 1  

**Example (brute mode):**  
./ikeforce.py 192.168.1.110 -b -i groupid -u dan -k psk123 -w groupnames.txt -s 1  

**Options:**   
                        
	  -h, --help            show this help message and exit
	  -w WORDLIST, --wordlist=WORDLIST
	                        Path to wordlist file
	  -t TRANS, --trans=TRANS
	                        [OPTIONAL] Transform set: encryption type, hash type,
	                        authentication type, dh group (5 1 1 2)
	  -e, --enum            Set Enumeration Mode
	  -b, --brute           Set XAUTH Brute Force Mode
	  -k PSK, --psk=PSK     Pre Shared Key to be used with Brute Force Mode
	  -i ID, --id=ID        ID or group name. To be used with Brute Force Mode
	  -u USERNAME, --username=USERNAME
	                        XAUTH username to be used with Brute Force Mode
	  -U USERLIST, --userlist=USERLIST
	                        [OPTIONAL] XAUTH username list to be used with Brute
	                        Force Mode
	  -p PASSWORD, --password=PASSWORD
	                        XAUTH password to be used with Connect Mode
	  --sport=SPORT         Source port to use, default is 500
	  -d, --debug           Set debug on
	  -c, --connect         Set Connect Mode (test a connection)
	  -y IDTYPE, --idtype=IDTYPE
	                        [OPTIONAL] ID Type for Identification payload. Default
	                        is 2 (FQDN)
	  -s SPEED, --speed=SPEED
	                        [OPTIONAL] Speed of guessing attempts. A numerical
	                        value between 1 - 5 where 1 is faster and 5 is slow.
	                        Default is 3
	  -l KEYLEN, --keylen=KEYLEN
	                        [OPTIONAL] Key Length, for use with AES encryption
	                        types
                        
**Transform Set Helper (Non-exhautive):**

|Enc Type (1)   |Hash Type (2) |Auth Type (3)             |DH Group (4)                   |
|---------------|--------------|--------------------------|----------------------------|	
|1 = DES        |1 = HMAC-MD5  |1 = PSK                   |1 = 768-bit MODP group      |
|2 = IDEA       |2 = HMAC-SHA  |2 = DSS-Sig               |2 = 1024-bit MODP group     |
|3 = Blowfish   |3 = TIGER     |3 = RSA-Sig               |3 = EC2N group on GP[2^155] |
|4 = RC5-R16-B64|4 = SHA2-256  |4 = RSA-Enc               |4 = EC2N group on GP[2^185] |
|5 = 3DES       |5 = SHA2-384  |5 = Revised RSA-Sig       |5 = 1536-bit MODP group     |
|6 = CAST       |6 = SHA2-512  |64221 = Hybrid Mode       |                            |
|7 = AES        |              |65001 = XAUTHInitPreShared|                            |




TO DO
=====

- [ ] add rsa, hybrid etc support
- [ ] edit the packet processing to be more specific to milestones instead of just going by the number of packets in the received box
- [ ] add RADIUS support and add exception for OTP until it's supported
- [ ] add multiple transform sets to first packet to catch more device responses, particularly fqdn_user_id (03) and fqdn (02)
- [ ] add xauth brute force mode for watchguard devices, currently doesn't work

