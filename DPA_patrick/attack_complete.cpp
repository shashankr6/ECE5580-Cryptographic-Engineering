//----------------------------------------------------------
//  Hardware Security: Building Tamper-Resistant Cryptography
//  Hands-on Assignment 3, Session 1
//  Side Channel Analysis on AES
//
//  Patrick Schaumont, Virginia Tech 
//----------------------------------------------------------

#include <string>
#include <sstream>
#include <fstream>
#include <iostream>
#include <iomanip>
#include <assert.h>
#include <math.h>

static unsigned char const sbox[] =  {
  0x63 ,0x7c ,0x77 ,0x7b ,0xf2 ,0x6b ,0x6f ,0xc5 ,
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
  0x41 ,0x99 ,0x2d ,0x0f ,0xb0 ,0x54 ,0xbb ,0x16};

using namespace std;

unsigned hammingweight(unsigned char k) {
  unsigned w = 0;
  if (k & 0x80) w++;
  if (k & 0x40) w++;
  if (k & 0x20) w++;
  if (k & 0x10) w++;
  if (k & 0x08) w++;
  if (k & 0x04) w++;
  if (k & 0x02) w++;
  if (k & 0x01) w++;
  return w;
}

double d_abs(double p) {
  if (p < 0.0) 
    return -p;
  return p;
}

//===================================================
// You can modify the parameters below to implement
// variations on the differential power analysis
//
// KEYBYTES  number of bytes in AES key. do not modify this.
// KEYRANGE  number of values that a single byte can take. do not modify this.
// TRACELEN  number of samples in a trace. do no modify this.
//
// TRACEOFS  start index of the correlation analysis. 
//           Minimum value is 0. Maximum value is TRACELEN.
//
// TRACESPAN number of samples over which correlation is done.
//           Miminum value is 1. Maximum value is TRACELEN - TRACEOFS.

// FILES     number of files to process samples from
//           Minimum value is 1. Maximum value is 5120.

#define KEYBYTES        16
#define KEYRANGE       256
#define TRACELEN      1000
#define TRACEOFS         0
#define TRACESPAN TRACELEN
#define FILES         3500

#define FLOATTYPE float

//=================================================
// Global variables to be used by correlation analysis
//
// acc[][][] stores the correlation accumulators
// acc[i][j][k] is the jth accumulator for byte i
// at sample position k
//
// pbytes[][] stores the observable data (plaintext)
// pbytes[i][j] is the jth plaintext byte from trace i
//
// samples[][] stores the sampled-data waveform
// samples[i][j] stores sample j from trace i

FLOATTYPE acc[KEYBYTES][KEYRANGE][TRACELEN];
unsigned char pbytes[FILES][KEYBYTES];
unsigned char samples[FILES][TRACELEN];

//==================================================
// correlate() evaluates the correlation coefficient
// between X and Y, where
//
//   X = estimate[]
//   Y = samples[][samplenum]
//
// i.e. Y is the samplenum-th sample from each trace

FLOATTYPE correlate(unsigned samplenum, 
		    unsigned char estimate[FILES],
		    unsigned char samples[FILES][TRACELEN]) {
  FLOATTYPE exp_estimate;
  FLOATTYPE exp_samples;
  FLOATTYPE x, y, covxy, covxx, covyy, deltax, deltay;
  unsigned i;
  exp_estimate = 0.0;
  exp_samples  = 0.0;
  for (i=0; i<FILES; i++) {
    exp_estimate += (FLOATTYPE) estimate[i];
    exp_samples  += (FLOATTYPE) samples[i][samplenum];
  }
  exp_estimate /= FILES;
  exp_samples /= FILES;

  covxy = 0.0;
  covxx = 0.0;
  covyy = 0.0;
  for (i=0; i<FILES; i++) {
    x = ((FLOATTYPE) estimate[i]           - exp_estimate);
    y = ((FLOATTYPE) samples[i][samplenum] - exp_samples);
    covxy += x*y;
    covxx += x*x;
    covyy += y*y;
  }
  if (covxx < 1e-6)
    return 0.;
  if (covyy < 1e-6)
    return 0.;
  return covxy / (sqrtf(covxx) * sqrtf(covyy));
}

//=====================================================
// Steps in a Differential Power Analysis
//
// 1. Read data (this is given)
//     - 5120 trace files of 1000 samples => samples[][]
//     - 5120 * 16 plaintext bytes => pbytes[][]
//
// 2. Perform correlation loop
//    -- You have to write this
//    => produces acc[][][]
//
// 3. Postprocess acc[][][] (this is given)
//    For each keybyte
//      Fpr each keybyte value
//         For each trace
//             Find max, second max
//         delta[keybyte-value] = max - second max
//
//      keybyte = max(delta[])

int main() {
  ifstream tracefile;
  unsigned i, j, k;
  unsigned samplenum;
  unsigned bytenum;
  unsigned tracenum;
  unsigned keyguess;
  unsigned sampleacc;

  //=====================================================
  // Step 1

  // clear correlations
  for (i=0; i<KEYBYTES; i++)
    for (j=0; j<KEYRANGE; j++)
      for (k=TRACEOFS; k<(TRACEOFS+TRACESPAN); k++)
	acc[i][j][k] = 0.0;

  // read plaintext bytes
  ifstream plaintext;
  plaintext.open("plaintext",ifstream::in);

  bytenum = 0;
  while ((bytenum < FILES*16) && (!plaintext.eof())) {
    unsigned p;
    plaintext >> p;
    if (plaintext.fail())
      continue;
    pbytes[bytenum >> 4][bytenum & 0xF] = p;
    bytenum++;
  }
  plaintext.close();
  cerr << "Read " << bytenum << " plaintext bytes\n";

  // read trace file
  tracefile.open("waveform", ios::in | ios::binary);
  if (tracefile.fail()) {
    cout << "Error opening waveform\n";
    return 0;
  }
  if (!tracefile.read((char *)samples, TRACELEN*FILES)) {
    cout << "Read error on trace input\n";
    return 0;
  }
  tracefile.close();

  //=====================================================
  // Step 2
  //
  // You have to fill this out.
  // Input: pbytes[][], samples[][]
  // Output: acc[][][]
  // FLOATTYPE acc[KEYBYTES][KEYRANGE][TRACELEN];
  // unsigned char pbytes[FILES][KEYBYTES];
  // unsigned char samples[FILES][TRACELEN];
  unsigned char hw[FILES];

  for (bytenum=0; bytenum<KEYBYTES; bytenum++){
    for (keyguess=0; keyguess<KEYBYTES; keyguess++){
      for (tracenum=0;tracenum<FILES;tracenum++){
        hw[tracenum] = hammingweight(sbox[pbytes[tracenum][bytenum]^keyguess]);
      }

      for (samplenum=0;samplenum<TRACEOFS+TRACESPAN; samplenum++){
        acc[bytenum][keyguess][samplenum] = correlate(samplenum, hw, samples);
      }
    }
  }
  //=====================================================
  // Step 3
  //

  // dump correlation result
  for (bytenum=0; bytenum<KEYBYTES; bytenum++) {
    ofstream corrfile;
    ostringstream n;
    string name;
    n << "corr" << bytenum << ".txt";
    name = n.str();
    cout << "Dumping File " << n.str() << "\n";
    corrfile.open(name.c_str(), ofstream::out);
    for (samplenum=TRACEOFS; samplenum<(TRACEOFS+TRACESPAN); samplenum++) {
      for (keyguess=0; keyguess<KEYRANGE; keyguess++) {
	corrfile << acc[bytenum][keyguess][samplenum] << " ";
      }
      corrfile << "\n";
    }
  }

  FLOATTYPE max  = 0;
  FLOATTYPE max2 = 0;
  unsigned  keypos = 0;
  FLOATTYPE delta[TRACELEN];
  unsigned  keyselect[TRACELEN];
  unsigned  peakpos;
  unsigned  searchdir;
  unsigned  pos;
  unsigned keypos2;

  // search for max_abs(peak - 2nd_peak)
  for (bytenum=0; bytenum<KEYBYTES; bytenum++) {

    for (samplenum=TRACEOFS; samplenum<(TRACEOFS+TRACESPAN); samplenum++) {

      // determine max position
      max    = d_abs(acc[bytenum][0][samplenum]);
      keypos = 0;
      for (keyguess=1; keyguess<KEYRANGE; keyguess++)
	if (d_abs(acc[bytenum][keyguess][samplenum]) > max) {
	  max    = d_abs(acc[bytenum][keyguess][samplenum]);
	  keypos = keyguess;
	}

      // determine max and second max position
      // search direction depends on position of max
      searchdir = (keypos == 0) ? 0 : 1; // backward : forward
      max  = d_abs(acc[bytenum][searchdir ? 0 : (KEYRANGE-1)][samplenum]);
      max2 = d_abs(acc[bytenum][searchdir ? 0 : (KEYRANGE-1)][samplenum]);
      keypos  = searchdir ? 0 : (KEYRANGE-1);
      keypos2 = searchdir ? 0 : (KEYRANGE-1);
      for (keyguess=1; keyguess<KEYRANGE; keyguess++) {
      	pos = searchdir ? keyguess : ((KEYRANGE-1) - keyguess);
      	if (d_abs(acc[bytenum][pos][samplenum]) > max) {
      	  max2    = max;
      	  max     = d_abs(acc[bytenum][pos][samplenum]);
	  keypos2 = keypos;
      	  keypos  = pos;
      	}
      }
      delta[samplenum]     = max - max2;
      keyselect[samplenum] = keypos;

    }

    // search for max_abs(peak - 2nd_peak) over all samples
    max     = delta[TRACEOFS];
    keypos  = keyselect[TRACEOFS];
    peakpos = TRACEOFS;
    for (samplenum=TRACEOFS+1; samplenum<(TRACEOFS+TRACESPAN); samplenum++) {
      if (delta[samplenum] > max) {
	max     = delta[samplenum];
	keypos  = keyselect[samplenum];
	peakpos = samplenum;
      }
    }
    
    cout << "Key byte " << setw(2) << bytenum << ": ";
    cout << std::setbase(16) << setw(2) << keypos;
    cout << " Position " << std::setbase(10) << setw(5) << peakpos;
    cout << " SNRd " << scientific << max << "\n";

  }
    
  return 0;
}
