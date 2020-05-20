#include <iostream>
#include "ecb.cpp"
#include "cbc.cpp"
#include "cmac.cpp"
//#include "svdpi.h"

using namespace std;

int main(){
	
  uint8_t data [16] = {0xc6, 0x61, 0xf5, 0x3d, 0x74, 0x79, 0x10, 0x83, 0x78, 0xa8, 0xe3, 0x45, 0x4a, 0xe4, 0x7a, 0xf8};
  uint8_t authBlk [16] = {0xfa, 0xd0, 0x9c, 0xde, 0x15, 0xa7, 0x33, 0xb9, 0xfc, 0xa2, 0x5b, 0xde, 0x44, 0xb8, 0xee, 0x5e};
  uint8_t ivData[16] = {0xbb, 0xb2, 0xa0, 0x91, 0x0b, 0xf2, 0x31, 0x24, 0xc1, 0x56, 0xbe, 0xb8, 0xf2, 0x7f, 0x84, 0x63};
  uint8_t key[16] = {0x6b, 0x93, 0x3e, 0xb2, 0xb3, 0x0a, 0xd8, 0xdb, 0x26, 0x62, 0x5c, 0x74, 0x38, 0x88, 0xe2, 0xee};


  uint8_t cipher [16];
	uint8_t ciphercbc[16];
	uint8_t cmaccipher[12];
  //svBit asda;

	
	



	//ECB routine
	cout << "*****************************************************************" << endl;
	cout << "!!!!!!!!!!!!!!!!!!!!!!!!!!ECB routine !!!!!!!!!!!!!!!!!!!!!!!!!!!" << endl;
	cout << "*****************************************************************" << endl;

	ECB ECBC(data, key);
	ECBC.crypt();
	ECBC.getCipher(cipher);
	cout << "Encrypt Phase: " << endl;
	cout << "Data: " << endl;
	for(int i = 0; i < 16; i++)
		printf("%x - ", data[i]);
	cout << endl << "Key: " << endl;
	for(int i = 0; i < 16; i++)
		printf("%x - ", key[i]);
	cout << endl <<"Cipher ECB:" << endl;
	for(int i = 0; i < 16; i++)
		printf("%x - ", cipher[i]);

	ECB ECBD(cipher, key);
	ECBD.decrypt();
	ECBD.getCipher(cipher);

	cout << endl << "Decrypt Phase: " << endl;
	cout << endl <<"Decipher ECB:" << endl;
	for(int i = 0; i < 16; i++)
		printf("%x - ", cipher[i]);
	cout << endl;

//CBC routine
	cout << "*****************************************************************" << endl;
	cout << "!!!!!!!!!!!!!!!!!!!!!!!!!!CBC routine !!!!!!!!!!!!!!!!!!!!!!!!!!!" << endl;
	cout << "*****************************************************************" << endl;

	CBC CBCC(data, key, ivData);
	CBCC.cbcCrypt();
	CBCC.getCipher(ciphercbc);
	cout << "Encrypt Phase: " << endl;
	cout << "Data: " << endl;
	for(int i = 0; i < 16; i++)
		printf("%x - ", data[i]);
	cout << endl << "Key: " << endl;
	for(int i = 0; i < 16; i++)
		printf("%x - ", key[i]);
	cout << endl << "ivData: " << endl;
	for(int i = 0; i < 16; i++)
		printf("%x - ", ivData[i]);
	cout << endl <<"Cipher CBC:" << endl;
	for(int i = 0; i < 16; i++)
		printf("%x - ", ciphercbc[i]);

	CBC CBCD(ciphercbc, key, ivData);
	CBCD.cbcDecrypt();
	CBCD.getCipher(ciphercbc);

	cout << endl << "Decrypt Phase: " << endl;
	cout << endl <<"Decipher CBC:" << endl;
	for(int i = 0; i < 16; i++)
		printf("%x - ", ciphercbc[i]);
	cout << endl;

	//ECB routine
	cout << "*****************************************************************" << endl;
	cout << "!!!!!!!!!!!!!!!!!!!!!!!!!CMAC routine !!!!!!!!!!!!!!!!!!!!!!!!!!!" << endl;
	cout << "*****************************************************************" << endl;

	CMAC cmac(data, key, authBlk);
	cmac.cmacCrypt();
	cmac.getCmac(cmaccipher);
	cout << "Encrypt Phase: " << endl;
	cout << "Data: " << endl;
	for(int i = 0; i < 16; i++)
		printf("%x - ", data[i]);
	cout << endl << "Key: " << endl;
	for(int i = 0; i < 16; i++)
		printf("%x - ", key[i]);
	cout << endl << "authBlk: " << endl;
	for(int i = 0; i < 16; i++)
		printf("%x - ", authBlk[i]);
	cout << endl <<"Cipher CMAC:" << endl;
	for(int i = 0; i < 12; i++)
		printf("%x - ", cmaccipher[i]);
	cout << endl;

	return 0;
}	
