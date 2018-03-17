//----------------------------------------------------------

  Hardware Security: Building Tamper-Resistant Cryptography
  Side Channel Analysis on AES

  Patrick Schaumont, Virginia Tech
 
//----------------------------------------------------------

In this assignment, you need to develop a correlation loop
for a Differential Fault Analysis on set of power traces.

These power traces have been collected from AES executing on a
microcontroller (a LEON-3 Sparc configured on an FPGA). The Data
format of the traces is listed below.

To start, you have a sample program 'attack.cpp' that will perform
most of the work for you.


1. Data format
--------------

Data format waveform: 

5120 traces of 1000 samples each of 1 byte each stored in order:

	 waveform[0]    = trace index 0, sample index 0
	 waveform[1]    = trace index 0, sample index 1
	 waveform[2]    = trace index 0, sample index 2
	 ...	         ...
	 waveform[999]  = trace index 0, sample index 999
	 waveform[1000] = trace index 1, sample index 0
	 ...		 ...
	 waveform[1999] = trace index 1, sample index 999
	 waveform[2000] = trace index 2, sample index 0
	 ...
	 waveform[5120000] = trace index 5120, sample index 999

Data format plaintext:

The file plaintext contains a 5120x16 matrix

    	 line 1 plaintext = sample index 0, byte index 0
    	 line 2 plaintext = sample index 0, byte index 1
    	 line 3 plaintext = sample index 0, byte index 3
	 ...
	 line 16 plaintext = sample index 0, byte index 15
	 line 17 plaintext = sample index 1, byte index 0
	 ..
	 line 32 plaintext = sample index 1, byte index 0
	 ...
	 line 48 plaintext = sample index 2, byte index 0
	 ...

2. Side-channel Analysis
------------------------

Study the program attack.cpp, which performs the side-channel
analysis in three steps:

     1/ read the waveform file and organize the data structure
     2/ perform the correlation
     3/ post-process the correlation results to find the
        correlation peaks

Step 1/ and 3/ are already filled out in attack.cpp.
Step 2/ needs to be developed, using the following template

  for each keybyte (0 .. 15)
    for each keyguess (0 .. 255)
      for each trace (0 .. 5119)
        estimate_power[trace] = 
           HW(sbox(plaintextbyte[trace, keybyte] xor keyguess))
      for each sample_position (0 .. 999)
        acc[keybyte][keyguess][sample_position] = 
           correlate(sample_position, estimate_power, samples)

(Note that this is one way to do it; the correlation loop can be
written in different ways).

If everything is implemented correctly, the program will find that the
AES key used consists of the 16 bytes {0, 1, 2, 3, 4, 5, 6, 7, 8, 9,
10, 11, 12, 13, 14, 15}.
