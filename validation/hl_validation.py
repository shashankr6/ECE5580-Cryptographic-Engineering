#!/usr/bin/env python

import sys
import os
import string
import re

# Add path
sys.path.append("../python_AES")

# Import test AES
import test_AES as test_AES

response_files_loc = "./response_files/rsp/"
output_file = "./validation_result.txt"
out_fp = open(output_file,'w')
out_fp.write("AESAVS Validation Results\n\n")

for dir,subdirs,files in os.walk(response_files_loc):
	if ((dir.split('/')[-1] == "aesmct")): # or (dir.split('/')[-1] == "aesmmt")):
		out_fp.write("------")
		out_fp.write("\n"+dir.split('/')[-1]+"\n")
		out_fp.write("------")
		out_fp.write("\n")

		for file in files:	
			correct_count = 0
			incorrect_count = 0

			if (("128" in file) and not("CFB" in file) ):	
				rsp_fp = open(os.path.join(dir,file),"r")
				aes_mode = file[:3]	# Extract the mode - first 3 characters of filename
		
				out_fp.write("\n\nMode: "+ aes_mode+"\n")
				
				count = "";
                                plaintext = ""
                                key = ""
                                IV = ""
                                ciphertext_exp = "" # Ciphertext expected
                                ciphertext_obt = "" # Ciphertext obtained


				for line in rsp_fp.readlines():
					# Split the line contents
					line_contents = line.split()

					if ("DECRYPT" in line):
						break
					elif ("COUNT" in line):
						count = line_contents[-1]# extract conut from the line
					elif ("KEY" in line):	
		 				key = line_contents[-1]
					elif ("IV" in line):
						IV = line_contents[-1]
					elif ("PLAINTEXT" in line):
						plaintext = line_contents[-1]
					elif ("CIPHERTEXT" in line):
						ciphertext_exp = line_contents[-1]
						ciphertext_obt = test_AES.test_AES(aes_mode, plaintext, key, IV) 
					
						ciphertext_obt = ciphertext_obt[2:-1]
						if (ciphertext_exp == ciphertext_obt):
							correct_count += 1
						else:
							incorrect_count += 1

						out_fp.write ("\n"+count + " Expected: " + ciphertext_exp + " Obtained: " + ciphertext_obt) 
				
				out_fp.write("\n\nTest: "+dir.split('/')[-1]+" Mode: "+file[:3]+" Correct: "+str(correct_count)+" Incorrect: "+str(incorrect_count))

				print "Test: "+dir.split('/')[-1]+" Mode: "+file[:3]+" Correct: "+str(correct_count)+" Incorrect: "+str(incorrect_count)

out_fp.close()
