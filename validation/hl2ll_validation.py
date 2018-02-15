#!/usr/bin/env python

import sys
import os
import string
import re
import serial
import string
from time import sleep

sys.path.append("../python_AES")

import test_AES as test_AES

def hl_ciphertext (aes_mode, pt, key, IV):
	ct = test_AES.test_AES(aes_mode, plaintext, key, IV)
	ct = ct[2:-1]
	if (len(ct)==len(pt)-1):
		ct = '0'+ct
	elif (len(ct)==len(pt)-2):
		ct = '00'+ct
	return ct

def ll_ciphertext (pt, key, ser):
	for i in pt:
	        sleep (0.5)
        	ser.write(i)

	for i in key:
        	sleep(0.5)
        	ser.write(i)
	ct = ""
	while True:
        	ct += ser.read()
        	if (len(ct) == len(pt)):
                	print "\n"+ct
                	break

	return ct

response_files_loc = "./response_files/rsp/"
output_file = "./hl2ll_validation_result.txt"
out_fp = open(output_file,'w')
out_fp.write("AESAVS Validation Results\n\n")

ser = serial.Serial()
ser.baudrate = 57600
ser.bytesize=serial.EIGHTBITS
ser.parity=serial.PARITY_NONE
ser.stopbits=serial.STOPBITS_ONE
ser.xonxoff=0
ser.timeout=20
ser.port="/dev/ttyACM1"
ser.close()
ser.open()

for dir,subdirs,files in os.walk(response_files_loc):
        if ((dir.split('/')[-1] == "aesmct")): # or (dir.split('/')[-1] == "aesmmt")):
                out_fp.write("------")
		out_fp.write("\n"+dir.split('/')[-1]+"\n")
                out_fp.write("------")
                out_fp.write("\n")

                for file in files:
                        correct_count = 0
                        incorrect_count = 0
			
                        if (("128" in file) and ("ECB" in file) ):
                        	rsp_fp = open(os.path.join(dir,file),"r")
                                aes_mode = file[:3]     # Extract the mode - first 3 characters of filename

                                out_fp.write("\n\nMode: "+ aes_mode+"\n")

                                count = "";
                                plaintext = ""
                                key = ""
                                IV = ""
                                ciphertext_hl = "" # Ciphertext expected
                                ciphertext_ll = "" # Ciphertext obtained


                                for line in rsp_fp.readlines():
                                        if (correct_count + incorrect_count == 25):
						break

					# Split the line contents
                                        line_contents = line.split()

                                        if ("DECRYPT" in line):
                                                break
                                        elif ("COUNT" in line):
                                                count = line_contents[-1]# extract count from the line
                                        elif ("KEY" in line):
                                                key = line_contents[-1]
                                        elif ("IV" in line):
                                                IV = line_contents[-1]
                                        elif ("PLAINTEXT" in line):
                                                plaintext = line_contents[-1]
                                        elif ("CIPHERTEXT" in line):
                                                ciphertext_hl = hl_ciphertext (aes_mode, plaintext, key, IV)
						ciphertext_ll = ll_ciphertext (plaintext, key, ser)
							
						if (ciphertext_hl==ciphertext_ll):
							print "Count = "+count+" Ciphertexts match"
							correct_count+=1
						else:
							print "\n"+count+" HL: "+ciphertext_hl+" LL: "+ciphertext_ll 
							incorrect_count+=1
						out_fp.write ("\n"+count + " HL ciphertext: " + ciphertext_hl + " LL ciphertext: " + ciphertext_ll)
					
                                out_fp.write("\n\nTest: "+dir.split('/')[-1]+" Mode: "+file[:3]+" Correct: "+str(correct_count)+" Incorrect: "+str(incorrect_count))


                                                

