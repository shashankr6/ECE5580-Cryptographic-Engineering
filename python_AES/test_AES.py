import AES as aes
import sys
import string

#from binascii import hexlify

def test_AES (mode, PT, Key, IV):
	if len(sys.argv) < 4:
		print "\n"
		print "python AES.py <mode (ECB, CBC, or OFB)> <palint_text> <master_key> <IV (if needed)>"
	else:
		mode = sys.argv[1]
	
	numOfBlocks = int(len(PT) / 32)
	
	PT_int_arr = [0 for x in range(0,numOfBlocks)]
	CT_int_arr = [0 for x in range(0,numOfBlocks)]
	CT_arr = ["" for x in range(0,numOfBlocks)]
	
	for i in range(0,numOfBlocks):
		PT_int_arr[i] = int(PT[i*32:i*32+32], 16)
	
	#PT_int = int(PT, 16)
	Key_int = int(Key, 16)
	#print(hex(PT_int))
	#print(hex(Key_int))
	if mode == "ECB":
		for i in range(0,numOfBlocks):
			CT_arr[i] = hex(aes.AES(PT_int_arr[i], Key_int))

	elif mode == "CBC":
		IV_int = int(IV, 16)
		CT_int_arr[0] = aes.AES(PT_int_arr[0]^IV_int, Key_int)
		for i in range(1, numOfBlocks):
			CT_int_arr[i] = aes.AES(PT_int_arr[i]^CT_int_arr[i-1], Key_int)
	
	elif mode == "OFB":
		IV_int = int(IV, 16)
		OP = aes.AES(IV_int, Key_int)
		CT_int_arr[0] = OP ^ PT_int_arr[0]
		for i in range(1, numOfBlocks):
			OP = aes.AES(OP, Key_int)
			CT_int_arr[i] = OP ^ PT_int_arr[i]
			
	else:
		print "Unsupported Mode"
	
	CT = ""
	for i in range(0, numOfBlocks):
		CT = CT + hex(CT_int_arr[i])
	
	#print "Ciphertext: ",CT
	return CT