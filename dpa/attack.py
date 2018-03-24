#!/usr/bin/env python

import os 
from os.path import isfile, join
import numpy as np 
from numpy import genfromtxt
import sys
import matplotlib.pyplot as plt

NSAMPLES = 3253
MAX_SAMPLES = NSAMPLES
TRACEFILE_SKIPLINES = 24 # Do not read from line #1 to line #TRACEFILE_SKIPLINES
NTRACES = 3500	# default no. of traces
NBYTES = 2		# Number of bytes in key and plaintext
NGUESSES = 256	# No. of guesses for each key byte

# Take number of traces as user input
if (len(sys.argv) == 2):
	NTRACES = int(sys.argv[1])

# Replace with directory of trace files
traceLoc = '/home/shashank/Downloads/DPA_contest2_public_base_diff_vcc_a128_2009_12_23/'
# Replace with directory of index file
indexFile = './DPA_contest2_public_base_index_file'

# Get specified number of trace file names from index file
def getTraceFiles(fdIndexFile, ntraces):
	lines = fdIndexFile.readlines()
    # create a dictionary
	traceInfo = {}
	key = lines[0].split()[0]
	traceInfo['key'] = key
	plaintext = [int(line.split()[1],16) for line in lines if line.split()[0]==key][:ntraces]
	traceInfo['plaintext'] = plaintext
	filenames = [line.split()[-1] for line in lines if line.split()[0]==key][:ntraces]
	traceInfo['filenames'] = filenames
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

# create an empty numpy array to store samples first
samples = np.empty([NTRACES,MAX_SAMPLES])
# Open index file
fdIndex = open(indexFile, "r")

# get trace details (key, pt, filenames)
traceInfo = getTraceFiles(fdIndex, NTRACES)
print "Obtained trace files"
# get the plaintext, key, and filenames from the dictionary obtained above
plaintext = np.asarray(traceInfo['plaintext'])
correctKey = int(traceInfo['key'],16)	# Will be used at the end for verification
filenames = traceInfo['filenames']

plt.figure()

# Store power samples from files
for file in filenames:
	fp = open(join(traceLoc,file),"r")
	# convert list into numpy array
	samples[filenames.index(file)] = np.loadtxt(fp, skiprows=TRACEFILE_SKIPLINES)

print samples[0,0:49]
print "Stored samples"

# find mean and standard deviation of power samples across traces
samplesMean = samples.mean(axis=0)
print np.shape(samplesMean)
samplesStd = np.reshape(samples.std(axis=0),(1,NSAMPLES))
# repeat std deviation values along row for easier multiplication and division later
samplesStdMat = samplesStd.repeat(NGUESSES, axis=0)
print np.shape(samplesStdMat)

# Initialize empty array for sensitive data
sensitiveData = np.empty([NTRACES, NGUESSES])

# Initialize correlation array 
correlation = np.empty([NGUESSES, MAX_SAMPLES])

#Initialize delta: max-second max
delta = np.empty(NGUESSES);

# Initialize extracted key 
extractedKey = 0


# Start loop
for byte in range(NBYTES):
	print "correct key: "+hex(correctKey).zfill(2*NBYTES)
	print "Attacking byte "+str(byte)
	# First, store Sensitive data
	for trace in range(NTRACES):
		plaintextByte = (plaintext[trace]>>(8*byte)) & 0xFF
#		if (trace < 10):
#			print hex(plaintextByte)
		for guess in range(NGUESSES):
#			if ((trace < 10) and (guess < 2)):
#				print hex(guess)
#				print hex(plaintextByte^guess)
#				print hex(sbox[plaintextByte^guess])
			initialValue = plaintextByte^guess
			finalValue = sbox[initialValue]
			sensitiveData[trace, guess] = hammingWeight(sbox[initialValue^finalValue])

	print "Obtained sensitive data"		
	# find mean and standard deviation of sensitive data
	sensitiveDataMean = sensitiveData.mean(axis=0)
	print np.shape(sensitiveDataMean)
	sensitiveDataStd = np.reshape(sensitiveData.std(axis=0),(1,NGUESSES))
	# repeat std deviation values along row for easier multiplication and division later
	sensitiveDataStdMat = sensitiveDataStd.transpose().repeat(MAX_SAMPLES, axis=1)

	covarxy = np.matmul((sensitiveData-sensitiveDataMean).transpose(), (samples-samplesMean)) 
	correlation = np.absolute(np.divide(covarxy,np.multiply(samplesStdMat, sensitiveDataStdMat)))

#	plt.subplot(NBYTES/2, 2, byte+1)
	plt.plot(correlation)
	plt.ylabel('Byte '+str(byte)+' correlation')

	maxCorr = np.sort(correlation, axis=1)[:,-1]	# Last column
	secondMaxCorr = np.sort(correlation, axis=1)[:,-2] # Second last column 
	delta = maxCorr-secondMaxCorr

	winningGuess = delta.argmax()&0xFF
	print "Winning guess" + hex(winningGuess)
	extractedKey += (winningGuess << (8*byte))
	plt.show()
	print "Byte " + str(byte) +" Guess : " + hex(winningGuess).zfill(2*NBYTES)


