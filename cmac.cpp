//***************************************************************************************************
//*                                                                                                 *
//*            *@@@@@@@@@@@@@*         *********************************************************    *
//*         @@@~*           *@@@;      * File: cmac.cpp                                        *    *
//*      *@@*                   @@*    * Author: João Pedro Melquiades Gomes                   *    *
//*    *@@    *@*            @@;       * Description: Implementation of CMAC class             *    *
//*   ;@      @@@@*        :@@0~       *********************************************************    *
//*  ;@         @@@@      @@@S                                                                      *
//* *@           ;@@@*   @@@;                                                                       *
//* @*            *@@@@  *@*        @@@          @@@@    @@@@@@@@@@@   @@@@       @@                *
//* F*              @@@@*           @@@@        @@@@@                  @@@@@*     @@                *
//* s*              @@@@@i          @@*@@      @@@@@@                  @@@@@@@    @@                *
//* @*            *@@@;@@@@:        @@ *@@    @@@ @@@    @@@@@@@@@@    @@@  @@@   @@                * 
//* *@           @@@@*  *@@@@       @@  @@@  @@@  @@@    *********     @@@   @@@* @@                *
//*  @@        *@@@;      @@@@*     @@   @@@@@*   @@@                  @@@     @@@@@                *
//*   :@*     @6@@*        **@@@    @@    *@@b    @@@    @@@@@@@@@@@   @@@      @@@@                *
//*    *@+*   ***            ****   **     **      **    ***********   ***        **                *
//*     *@@@                  *@@;                                                                  *
//*        *+@@@*         *@@@@*   Laboratório de Excelência em microeletrônica do Nordeste         *
//*            *@@@@i@@@i@~*       Universidade Federal de Campina Grande                           * 
//***************************************************************************************************  

#include "cmac.h"

CMAC::CMAC(uint8_t dt[], uint8_t k[], uint8_t auth[]):ECB(dt, k){
	for(int i = 0; i < 16; i++){
		authBlk[i] = auth[i];
		subKey[i] = 0x00;
	}

}


void CMAC::cmacCrypt(){

	//************************
	//Geração da sub chave
	//************************

	ECB subKeygen(subKey, key);
	uint8_t carry;
	uint8_t k1 [16];
	subKeygen.crypt();

	subKeygen.getCipher(subKey);

	for(int j = 15; j >= 0; j--){
		k1[j] = subKey[j] << 1;
		k1[j] |= carry;
		carry = (subKey[j] & 0x80) ? 0x01 : 0x00;
	}

	if(subKey[0] >= 0x80){
		k1[15] ^= 0x87;
	}
		

	//************************
	//Primeira encriptação
	//************************

	ECB firstPhase(authBlk, key);
	uint8_t cipherFirst[NB * 4];
	firstPhase.crypt();

	firstPhase.getCipher(cipherFirst);

	//**********************************
	//Xor do resultado com dado e subKey
	//**********************************

	for(int i = 0; i < 16; i++)
		data[i] = data[i] ^ k1[i] ^ cipherFirst[i];


	//******************************
	//Segunda encriptação
	//******************************

	crypt();
}

void CMAC::getCmac(uint8_t cmacCipher[]){
	for(int i = 0; i < 12; i++)
		cmacCipher[i] = cipher[i];
}
