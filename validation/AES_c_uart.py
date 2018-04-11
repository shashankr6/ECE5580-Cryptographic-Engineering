#!/usr/bin/env python

import serial
import string
from time import sleep

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

pt = "d7c3ffac9031238650901e157364c386"
key = "c459caeebf2c42586c01666a9334b97b"

for i in pt:
	sleep (0.5)
	ser.write(i)

for i in key:
	sleep(0.5)
	ser.write(i)
ct = ""
while True:
	ct += ser.read()
	if (len(ct) == 32):
		print ct
		break

return ct
			
