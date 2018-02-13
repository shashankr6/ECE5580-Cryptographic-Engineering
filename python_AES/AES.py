import random
import numpy as np
import math
import sys

blockSize = 128

def GFmult (a, b):
	if (a==1):
		c = b
	elif (a==2):
		c = b<<1
	elif (a==3):
		c = (b<<1) ^ b
	elif (a==4):
		c = b<<2
	elif (a==5):
		c = (b<<2) ^ b 
	elif (a==6):
		c = (b<<2) ^ (b<<1)
	elif (a==7):
		c = (b<<2) ^ (b<<1) ^ b
	elif (a==8):
		c = b<<3
	elif (a==9):
		c = (b<<3) ^ b
	elif (a==10):
		c = (b<<3) ^ (b<<1)
	elif (a==11):
		c = (b<<3) ^ (b<<1) ^ b
	elif (a==12):
		c = (b<<3) ^ (b<<2)
	elif (a==13):
		c = (b<<3) ^ (b<<2) ^ b
	elif (a==14):
		c = (b<<3) ^ (b<<2) ^ (b<<1)
	elif (a==15):
		c = (b<<3) ^ (b<<2) ^ (b<<1) ^ b
	else:
		c = 0
	while c >= 0x0100:
		c = c - 0x0100
		c = c ^ 0x01b
	return c

Sbox = (
#	  0		1	  2		3	  4		5	  6		7	  8		9	  A 	B 	  C     D     E     F
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76, #	0
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0, #	1
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15, #	2
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75, #	3
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84, #	4
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF, #	5
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8, #	6
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2, #	7
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73, #	8
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB, #	9
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79, #	A
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08, #	B
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A, #	C
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E, #	D
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF, #	E
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16, #	F
)

InvSbox = (
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
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D, #	F
)

RC = [0,0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]

w = [0 for x in range(0,44)]	

def rowCol(block):
	mask =  0xFFFFFFFF000000000000000000000000
	temp = []
	col = [0,0,0,0]
	
	line = hex(block)
	line = line[2:len(line)-1]
	line = line.zfill(32)
		
	n = 2
	dumbVariable = [line[i:i+n] for i in range(0, len(line), n)]
	
	someRandomMatrix = np.asarray(dumbVariable).reshape([4,4])
	
	transposed = np.transpose(someRandomMatrix)
	listRan = transposed.reshape(16).tolist()
	back = "".join(listRan)
	
	result = int(back, 16)
	
	return result
	
def Rcon(j):
	return (RC[j] << 24)

def SBOX_key(word):
	maskrow = 0xF0000000
	maskCol = 0x0F000000
	result =  0x00000000
	for i in range(0,4):
		result = result << 8 
		rowNum = (word & (maskrow >> (8*i))) >> 4*(8-(2*i+1))
		colNum = (word & (maskCol >> (8*i))) >> 4*(8-(2*i+2))
		result = result | Sbox[rowNum*16 + colNum]
	return result
		
def g(word, j):
	mask = 0xFF000000
	higherB = (mask & word) >> 24
	rotated = (((0x00FFFFFF) & word) << 8) ^ higherB
	sub = SBOX_key(rotated)
	result = sub ^ Rcon(j)
	return result


def keyExpansion(key):
	mask = 0xFFFFFFFF000000000000000000000000
	for i in range(0,4):
		w[i] = ((mask >> (32*i)) & key) >> ((3-i)*32)
	
	for i in range(4,44):
		if (i%4) == 0:
			w[i] = w[i-4] ^ g(w[i-1], i/4)
		else:
			w[i] = w[i-4] ^ w[i-1]

def addRoundKey(block, key):
	return block ^ key
	
def substituteBytes(block):
	return SBOX(block)
	
def Inv_substituteBytes(block):
	return InvSBOX(block)
	
def SBOX(block):
	maskrow = 0xF0000000000000000000000000000000
	maskCol = 0x0F000000000000000000000000000000
	result =  0x00000000000000000000000000000000
	for i in range(0,blockSize/8):
		result = result << 8
		rowNum = (block & (maskrow >> (8*i))) >> (128 - 4*(2*i+1))
		colNum = (block & (maskCol >> (8*i))) >> (128 - 4*(2*i+2))
		result = result | Sbox[rowNum*16 + colNum]
	return result
	
def InvSBOX(block):
	maskrow = 0xF0000000000000000000000000000000
	maskCol = 0x0F000000000000000000000000000000
	result =  0x00000000000000000000000000000000
	for i in range(0,blockSize/8):
		result = result << 8
		rowNum = (block & (maskrow >> (8*i))) >> (128 - 4*(2*i+1))
		colNum = (block & (maskCol >> (8*i))) >> (128 - 4*(2*i+2))
		result = result | InvSbox[rowNum*16 + colNum]
	return result
	
def shiftRows(block):
	mask =  0xFFFFFFFF000000000000000000000000
	result = 0x00000000000000000000000000000000
	row = [0,0,0,0]
	
	temp = rowCol(block)
	
	for i in range (0,4):
		row[i] = (temp & (mask >> 32*i)) >> (32*(3-i))
	
	row[1] = ((0x00FFFFFF & row[1]) << 8)  | ((0xFF000000 & row[1]) >> 24)
	row[2] = ((0x0000FFFF & row[2]) << 16) | ((0xFFFF0000 & row[2]) >> 16)
	row[3] = ((0x000000FF & row[3]) << 24) | ((0xFFFFFF00 & row[3]) >> 8)
	temp = (row[0] << 96) | (row[1] << 64) | (row[2] << 32) | (row[3])
	
	result = rowCol(temp)
	
	return result

	
def Inv_shiftRows(block):
	mask =   0xFFFFFFFF000000000000000000000000
	result = 0x00000000000000000000000000000000
	row = [0,0,0,0]
	
	temp = rowCol(block)
	
	for i in range (0,4):
		row[i] = (temp & (mask >> 32*i)) >> (32*(3-i))
	
	row[1] = ((0xFFFFFF00 & row[1]) >> 8)  | ((0x000000FF & row[1]) << 24)
	row[2] = ((0xFFFF0000 & row[2]) >> 16) | ((0x0000FFFF & row[2]) << 16)
	row[3] = ((0xFF000000 & row[3]) >> 24) | ((0x00FFFFFF & row[3]) << 8)
	temp = (row[0] << 96) | (row[1] << 64) | (row[2] << 32) | (row[3])
	
	result = rowCol(temp)
	
	return result	
	

def mixColumns(block):
	w, h = 4, 4;
	Matrix = [[0 for x in range(w)] for y in range(h)] 
	Block = [[0 for x in range(w)] for y in range(h)] 
	Product = [[0 for x in range(w)] for y in range(h)] 
	
	Matrix[0][0] = 2
	Matrix[0][1] = 3
	Matrix[0][2] = 1
	Matrix[0][3] = 1
	Matrix[1][0] = 1
	Matrix[1][1] = 2
	Matrix[1][2] = 3
	Matrix[1][3] = 1
	Matrix[2][0] = 1
	Matrix[2][1] = 1
	Matrix[2][2] = 2
	Matrix[2][3] = 3
	Matrix[3][0] = 3
	Matrix[3][1] = 1
	Matrix[3][2] = 1
	Matrix[3][3] = 2
	
	mask =   0xFFFFFFFF000000000000000000000000
	result = 0x00000000000000000000000000000000
	row = [0,0,0,0]
	
	temp = rowCol(block)
	
	for i in range (0,4):
		row[i] = (temp & (mask >> 32*i)) >> (32*(3-i))
	
	for i in range (0,4):
		Block[i][0] = (row[i]&0xFF000000)>>24
		Block[i][1] = (row[i]&0x00FF0000)>>16
		Block[i][2] = (row[i]&0x0000FF00)>>8
		Block[i][3] = (row[i]&0x000000FF)
	
	for i in range(0,4):
		for j in range(0,4):
			for k in range(0,4):
				Product[i][j] = Product[i][j] ^ GFmult(Matrix[i][k],Block[k][j])
	
	for i in range(0,4):
		for j in range(0,4):
			result = result << 8
			result = result | Product[i][j]
	
	result = rowCol(result)
	
	return result

def Inv_mixColumns(block):
	w, h = 4, 4;
	Matrix = [[0 for x in range(w)] for y in range(h)] 
	Block = [[0 for x in range(w)] for y in range(h)] 
	Product = [[0 for x in range(w)] for y in range(h)] 
	
	Matrix[0][0] = 0x0E
	Matrix[0][1] = 0x0B
	Matrix[0][2] = 0x0D
	Matrix[0][3] = 0x09
	Matrix[1][0] = 0x09
	Matrix[1][1] = 0x0E
	Matrix[1][2] = 0x0B
	Matrix[1][3] = 0x0D
	Matrix[2][0] = 0x0D
	Matrix[2][1] = 0x09
	Matrix[2][2] = 0x0E
	Matrix[2][3] = 0x0B
	Matrix[3][0] = 0x0B
	Matrix[3][1] = 0x0D
	Matrix[3][2] = 0x09
	Matrix[3][3] = 0x0E
	
	mask =   0xFFFFFFFF000000000000000000000000
	result = 0x00000000000000000000000000000000
	row = [0,0,0,0]
	
	temp = rowCol(block)
	
	for i in range (0,4):
		row[i] = (temp & (mask >> 32*i)) >> (32*(3-i))
	
	for i in range (0,4):
		Block[i][0] = (row[i]&0xFF000000)>>24
		Block[i][1] = (row[i]&0x00FF0000)>>16
		Block[i][2] = (row[i]&0x0000FF00)>>8
		Block[i][3] = (row[i]&0x000000FF)
	
	for i in range(0,4):
		for j in range(0,4):
			for k in range(0,4):
				Product[i][j] = Product[i][j] ^ GFmult(Matrix[i][k],Block[k][j])
		print "[",i,"]""[",j,"] = ",hex(Product[i][j])
	
	for i in range(0,4):
		for j in range(0,4):
			result = result << 8
			result = result | Product[i][j]
			
	result = rowCol(result)
	
	return result	
	
def AES(PT, Key):
	# making round keys
	keyExpansion(Key)
	roundKey = [0 for x in range(0,11)]
	for i in range(0,11):
		roundKey[i] = (w[4*i] << (3*32)) ^ (w[4*i+1] << (2*32)) ^ (w[4*i+2] << 32) ^ (w[4*i+3]) 
	
	# round 0:
	intermedPT = addRoundKey(PT, roundKey[0])
	
	# rounds 1 to 10:
	for round in range(1,11):
		intermedPT = substituteBytes(intermedPT)
		intermedPT = shiftRows(intermedPT)
		if round!=10:
			intermedPT = mixColumns(intermedPT)
		intermedPT = addRoundKey(intermedPT, roundKey[round])
	CT = intermedPT
	
	return CT
	
# checking mixColumns and Inv_mixColumns --> Inv_mixColumns doesn't work
'''
block = 0x87F24D976E4C90EC46E74AC3A68CD895
result = Inv_mixColumns(mixColumns(block))
if block != result:
	print "mixColumns and its inverse worng!"
'''
#checking key expansion
'''
key = 0x0F1571C947D9E8590CB7ADD6AF7F6798
keyExpansion(key)
'''
'''
for i in range(0,10000):
	b = random.getrandbits(128)
	result = Inv_mixColumns(mixColumns(b))
	if b != result:
		print "WRONG!!"
		break
'''

# testing SBOX and InvSBOX
'''
for i in range (0,10000):
	# k = random.getrandbits(128)
	# print(hex(k))
	b = random.getrandbits(128)
	#print(hex(b))
	# result = addRoundKey(b,k)
	# print(result)
	result = Inv_substituteBytes(substituteBytes(b))
	#print(hex(result))
	
	if b!=result:
		print "WRONG!!!"
		break
'''

# testing shiftRows and Inv_shiftRows
'''
for i in range (0,10000):
	b = random.getrandbits(128)
	result = Inv_shiftRows(shiftRows(b))
	
	if b!=result:
		print "WRONG!!!"
		break
'''
