import AES as aes
import sys

print "\n"
if len(sys.argv) < 4:
	print "python AES.py <mode (ECB, CBC, or OFB)> <palint_text> <master_key> <IV (if needed)>"
else:
	mode = sys.argv[1]
	PT = int(sys.argv[2], 16)
	Key = int(sys.argv[3], 16)
	
	if mode == "ECB":
		print "Cipher Text = ", hex(aes.AES(PT, Key))
	elif mode == "CBC":
		IV = int(sys.argv[4], 16)
		print "Cipher Text = ", hex(aes.AES(PT^IV, Key))
	elif mode == "OFB":
		IV = int(sys.argv[4], 16)
		OP = aes.AES(IV, Key)
		print "Cipher Text = ", hex(OP ^ PT)
	else:
		print "Unsupported Mode"
		#return
