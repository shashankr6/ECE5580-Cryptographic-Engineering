#!/usr/bin/env python

import os 
from os.path import isfile, join
import numpy as np 
from numpy import genfromtxt
import sys
import matplotlib.pyplot as plt

#NSAMPLES = 50
SAMPLES_START = 2000
SAMPLES_END = 2700
NSAMPLES = SAMPLES_END-SAMPLES_START+1
TRACEFILE_SKIPLINES = 24 # Do not read from line #1 to line #TRACEFILE_SKIPLINES
NTRACES = 3500	# default no. of traces
NBYTES = 16		# Number of bytes in key and plaintext
NGUESSES = 256	# No. of guesses for each key byte
NKEYS = 8

# Take number of traces as user input
if (len(sys.argv) == 2):
	NTRACES = int(sys.argv[1])

# Replace with directory of trace files
traceLoc = '/home/shashank/Downloads/DPA_contest2_public_base_diff_vcc_a128_2009_12_23/'
# Replace with directory of index file
indexFile = './DPA_contest2_public_base_index_file'
#File containing correct keys
keyFile = './keys.txt'
#File containing correct last round keys
lastRoundKeyFile = './lastRoundKeys.txt'

#==========================================================#
correctLastRoundKey = ''
correctKey = ''

# Get specified number of trace file names from index file
def getTraceFiles(fdIndexFile, ntraces):
	lines = fdIndexFile.readlines()
    # create a dictionary
	traceInfo = {}
	print len(lines)
	print correctKey
	plaintext = [line.split()[1] for line in lines if line.split()[0]==correctKey][:ntraces]
	traceInfo['plaintext'] = plaintext
	ciphertext = [line.split()[2] for line in lines if line.split()[0]==correctKey][:ntraces]
	traceInfo['ciphertext'] = ciphertext
	filenames = [line.split()[-1] for line in lines if line.split()[0]==correctKey][:ntraces]
	traceInfo['filenames'] = filenames
	fdIndexFile.seek(0)
	return traceInfo

# Function to Calculate Hamming Weight
def hammingWeight(value):
	hw = 0
	while value!=0:
		hw += value & 0x01
		value >>= 1

	return hw	

# SBOX
sbox = [0x63 ,0x7c ,0x77 ,0x7b ,0xf2 ,0x6b ,0x6f ,0xc5 ,
  		0x30 ,0x01 ,0x67 ,0x2b ,0xfe ,0xd7 ,0xab ,0x76 ,
  		0xca ,0x82 ,0xc9 ,0x7d ,0xfa ,0x59 ,0x47 ,0xf0 ,
  		0xad ,0xd4 ,0xa2 ,0xaf ,0x9c ,0xa4 ,0x72 ,0xc0 ,
  		0xb7 ,0xfd ,0x93 ,0x26 ,0x36 ,0x3f ,0xf7 ,0xcc ,
 	 	0x34 ,0xa5 ,0xe5 ,0xf1 ,0x71 ,0xd8 ,0x31 ,0x15 ,
  		0x04 ,0xc7 ,0x23 ,0xc3 ,0x18 ,0x96 ,0x05 ,0x9a ,
  		0x07 ,0x12 ,0x80 ,0xe2 ,0xeb ,0x27 ,0xb2 ,0x75 ,
  		0x09 ,0x83 ,0x2c ,0x1a ,0x1b ,0x6e ,0x5a ,0xa0 ,
  		0x52 ,0x3b ,0xd6 ,0xb3 ,0x29 ,0xe3 ,0x2f ,0x84 ,
 		0x53 ,0xd1 ,0x00 ,0xed ,0x20 ,0xfc ,0xb1 ,0x5b ,
  		0x6a ,0xcb ,0xbe ,0x39 ,0x4a ,0x4c ,0x58 ,0xcf ,
  		0xd0 ,0xef ,0xaa ,0xfb ,0x43 ,0x4d ,0x33 ,0x85 ,
  		0x45 ,0xf9 ,0x02 ,0x7f ,0x50 ,0x3c ,0x9f ,0xa8 ,
  		0x51 ,0xa3 ,0x40 ,0x8f ,0x92 ,0x9d ,0x38 ,0xf5 ,
  		0xbc ,0xb6 ,0xda ,0x21 ,0x10 ,0xff ,0xf3 ,0xd2 ,
  		0xcd ,0x0c ,0x13 ,0xec ,0x5f ,0x97 ,0x44 ,0x17 ,
  		0xc4 ,0xa7 ,0x7e ,0x3d ,0x64 ,0x5d ,0x19 ,0x73 ,
  		0x60 ,0x81 ,0x4f ,0xdc ,0x22 ,0x2a ,0x90 ,0x88 ,
  		0x46 ,0xee ,0xb8 ,0x14 ,0xde ,0x5e ,0x0b ,0xdb ,
  		0xe0 ,0x32 ,0x3a ,0x0a ,0x49 ,0x06 ,0x24 ,0x5c ,
  		0xc2 ,0xd3 ,0xac ,0x62 ,0x91 ,0x95 ,0xe4 ,0x79 ,
  		0xe7 ,0xc8 ,0x37 ,0x6d ,0x8d ,0xd5 ,0x4e ,0xa9 ,
  		0x6c ,0x56 ,0xf4 ,0xea ,0x65 ,0x7a ,0xae ,0x08 ,
  		0xba ,0x78 ,0x25 ,0x2e ,0x1c ,0xa6 ,0xb4 ,0xc6 ,
  		0xe8 ,0xdd ,0x74 ,0x1f ,0x4b ,0xbd ,0x8b ,0x8a ,
  		0x70 ,0x3e ,0xb5 ,0x66 ,0x48 ,0x03 ,0xf6 ,0x0e ,
  		0x61 ,0x35 ,0x57 ,0xb9 ,0x86 ,0xc1 ,0x1d ,0x9e ,
  		0xe1 ,0xf8 ,0x98 ,0x11 ,0x69 ,0xd9 ,0x8e ,0x94 ,
  		0x9b ,0x1e ,0x87 ,0xe9 ,0xce ,0x55 ,0x28 ,0xdf ,
  		0x8c ,0xa1 ,0x89 ,0x0d ,0xbf ,0xe6 ,0x42 ,0x68 ,
  		0x41 ,0x99 ,0x2d ,0x0f ,0xb0 ,0x54 ,0xbb ,0x16]

invSbox = [
#	  0		1	  2		3	  4		5	  6		7	  8		9	  A 	B 	  C     D     E     F
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB, #	0
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB, #	1
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E, #	2
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25, #	3
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92, #	4
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84, #	5
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06, #	6
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B, #	7
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73, #	8
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E, #	9
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B, #	A
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4, #	B
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F, #	C
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF, #	D
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61, #	E
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D] #	F

def getPrevByte(byte):
	prevByte = 0
	if (byte%4==0):
		prevByte = byte
	elif (byte==1):
		prevByte = 13
	elif (byte==2):
		prevByte = 10
	elif (byte==3):
		prevByte = 7
	elif (byte==5):
		prevByte = 1
	elif (byte==6):
		prevByte = 14
	elif (byte==7):
		prevByte = 11
	elif (byte==9):
		prevByte = 5
	elif (byte==10):
		prevByte = 2
	elif (byte==11):
		prevByte = 15
	elif (byte==13):
		prevByte = 9
	elif (byte==14):
		prevByte = 6
	elif (byte==15):
		prevByte = 3
	
	return prevByte

#=====================================================#	

# Open index file
fdIndex = open(indexFile, "r")
fdKeys = open(keyFile,"r")
fdlastRoundKeys = open(lastRoundKeyFile,"r")

keys = fdKeys.readlines()
lastRoundKeys = fdlastRoundKeys.readlines()

# Initialize correlation array 
correlation = np.empty([NGUESSES, NSAMPLES])
#Initialize delta: max-second max
delta = np.empty(NGUESSES);
# initialize correct count 
correctCount = np.empty([1,NKEYS])
extractedKey = np.empty([1,NBYTES])

traces = [3500, 5000, 6000, 7500, 9000, 10000, 15000, 20000]
byteSuccess = np.zeros([NBYTES, len(traces)])
# file to write extracted keys
fdExtracted = open('extractedKeys.txt','a')
fdByteSuccess = open('ByteSuccess.txt','w')

for numtraces in traces:
	fdExtracted.write("No. of traces: "+str(numtraces)+"\n")
	print ("No. of traces: "+str(numtraces))
	
	# create an empty numpy array to store samples first
	samples = np.empty([numtraces,NSAMPLES])
	# Initialize empty array for sensitive data
	sensitiveData = np.empty([NGUESSES, numtraces])
	
	for keynum in range(NKEYS):
		fdExtracted.write("Key number "+str(keynum)+"\n")
		print "Key number "+str(keynum)

		correctKey = keys[keynum][:-1]	# to avoid newline
		correctLastRoundKey = lastRoundKeys[keynum][:-1]
		#print correctLastRoundKey
		# get trace details (key, pt, filenames)
		traceInfo = getTraceFiles(fdIndex, numtraces)
		#print "Obtained trace files"
		# get the plaintext, key, ciphertext, and filenames from the dictionary obtained above
		plaintext = traceInfo['plaintext']
		ciphertext = traceInfo['ciphertext']
		filenames = traceInfo['filenames']
#		print len(filenames)
		print len(plaintext)
			
		# Store power samples from files
		for trace in range(numtraces):
			file = filenames[trace]
			fp = open(join(traceLoc,file),"r")
			# convert list into numpy array
			samples[trace] = np.loadtxt(fp, skiprows=TRACEFILE_SKIPLINES)[SAMPLES_START:SAMPLES_END+1]

		#plt.plot(samples[0])
		#plt.show()
		print "Stored samples"

		# find mean and standard deviation of power samples across traces
		samplesMean = samples.mean(axis=0)
		samplesStd = np.reshape(samples.std(axis=0),(1,NSAMPLES))
		# repeat std deviation values along row for easier multiplication and division later
		samplesStdMat = samplesStd.repeat(NGUESSES, axis=0)

		#print "Calculated mean and std deviation of samples"

		# Initialize extracted key 
		curCorrectCount = 0
		# Start loop
		for byte in range(NBYTES):
			print "Attacking byte "+str(byte)
			
			# Obtain sensitive data
			for trace in range(numtraces):
				ciphertextByte = int(ciphertext[trace][2*byte:2*(byte+1)],16)			
				for guess in range(NGUESSES):
					finalValue = ciphertextByte
					prevCTByte = int(ciphertext[trace][2*getPrevByte(byte):2*(getPrevByte(byte)+1)],16)
					initialValue = invSbox[prevCTByte ^ guess]
					sensitiveData[guess, trace] = hammingWeight(initialValue ^ finalValue)

#			print "Obtained sensitive data"		
			# find mean and standard deviation of sensitive data
			sensitiveDataMean = np.reshape(sensitiveData.mean(axis=1),(NGUESSES,1))
			sensitiveDataStd = np.reshape(sensitiveData.std(axis=1),(NGUESSES,1))	
			# repeat std deviation values along row for easier multiplication and division later
			sensitiveDataStdMat = np.repeat(sensitiveDataStd,NSAMPLES, axis=1)

			# Calculate covariance and correlation
			covarxy = np.divide(np.matmul((sensitiveData-sensitiveDataMean), (samples-samplesMean)),numtraces) 
			correlation = np.divide(covarxy,np.multiply(sensitiveDataStdMat, samplesStdMat))
	
#			maxCorr = np.sort(np.absolute(correlation), axis=0)[-1,:]	# Last row
			maxCorr = np.sort(correlation, axis=0)[-1,:]	# Last row
		
#			secondMaxCorr = np.sort(np.absolute(correlation), axis=0)[-2,:] # Second last row 
#			secondMaxCorr = np.sort(correlation, axis=0)[-2,:] # Second last row 
	
#			delta = maxCorr-secondMaxCorr

#			maxCorrIndex = np.argsort(np.absolute(correlation),axis=0)[-1,:]
			maxCorrIndex = np.argsort(correlation,axis=0)[-1,:]
	
#			winningGuessPos = delta.argmax()
			winningGuessPos = maxCorr.argmax()
	
			winningGuess = maxCorrIndex[winningGuessPos]
	
#			winningGuess = np.argmax(maxCorr)
			print "Winning guess " + hex(winningGuess)
			print "expected key " + correctLastRoundKey[2*getPrevByte(byte):2*(getPrevByte(byte)+1)]
#			print "expected key int " + str(int(correctLastRoundKey[2*getPrevByte(byte):2*(getPrevByte(byte)+1)],16))
		
#			plt.show()
			extractedKey[0,getPrevByte(byte)] = winningGuess
			
			if (winningGuess == int(correctLastRoundKey[2*getPrevByte(byte):2*(getPrevByte(byte)+1)],16)):
				curCorrectCount = curCorrectCount+1
				byteSuccess[getPrevByte(byte),traces.index(numtraces)] = byteSuccess[getPrevByte(byte),traces.index(numtraces)]+1

		print "correctly extracted: "+str(curCorrectCount)
		np.savetxt(fdExtracted,extractedKey,fmt='%x', delimiter='')
		fdExtracted.write("correctly extracted: "+str(curCorrectCount)+'\n')

		correctCount[0,keynum] = curCorrectCount

	np.savetxt(fdByteSuccess,byteSuccess,fmt='%u',newline='\n')
	print correctCount
	np.savetxt(fdExtracted, correctCount, fmt='%u')

fdExtracted.close()
fdIndex.close()
fdByteSuccess.close()