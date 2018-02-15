import AES as aes
import sys
import string

#from binascii import hexlify

def test_AES (mode, PT, Key, IV):
	#print "\n"
	#if len(sys.argv) < 4:
	#print "python AES.py <mode (ECB, CBC, or OFB)> <palint_text> <master_key> <IV (if needed)>"
	#else:
	#mode = sys.argv[1]
	
	PT_int = int(PT, 16)
	Key_int = int(Key, 16)
	#print(hex(PT_int))
	#print(hex(Key_int))
	if mode == "ECB":
		CT = hex(aes.AES(PT_int, Key_int))

	elif mode == "CBC":
		IV_int = int(IV, 16)
		CT = hex(aes.AES(PT_int^IV_int, Key_int))
	
	elif mode == "OFB":
		IV_int = int(IV, 16)
		OP = aes.AES(IV_int, Key_int)
		CT = hex(OP ^ PT_int)
	
	else:
		print "Unsupported Mode"

	#print "Ciphertext: ",CT
	return CT
