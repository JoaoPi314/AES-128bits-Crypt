//***************************************************************************************************
//*                                                                                                 *
//*            *@@@@@@@@@@@@@*         *********************************************************    *
//*         @@@~*           *@@@;      * Arquivo: ecb.cpp                                      *    *
//*      *@@*                   @@*    * Autor: João Pedro Melquiades Gomes                    *    *
//*    *@@    *@*            @@;       * Descrição: Implementação da classe ECB                *    *
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
   

#include "ecb.h"
#include <iostream>
using namespace std;
ECB::ECB(uint8_t dt [], uint8_t k []){
	
	for(int i = 0; i < 44; i++)
		roundKey[i] = 0x00;

	for(int i = 0; i < 16; i++){
		data[i] = dt[i];
		key[i] = k[i];
		cipher[i] = 0x00;
	}


}

//************************************
//rotWord() rotaciona uma palavra de 
//4 bytes da seguinte forma:
// 0a bb cc da -> bb cc da 0a
//************************************
uint32_t ECB::rotWord(uint32_t w){
	uint32_t tmp;
	tmp = w >> 24;
	w = w << 8;
	w = tmp | w;
	return w;
}

//************************************
//subByte() substitui um byte infor-
//mado por um byte da tabela sbox
//byte: 0a-> byte = sbox[0][a]
//************************************
uint8_t ECB::subByte(uint8_t b, bool crypto){
	uint8_t sbox[16] [16] = {{0x63 ,0x7c ,0x77 ,0x7b ,0xf2 ,0x6b ,0x6f ,0xc5 ,0x30 ,0x01 ,0x67 ,0x2b ,0xfe ,0xd7 ,0xab ,0x76},
						  {0xca ,0x82 ,0xc9 ,0x7d ,0xfa ,0x59 ,0x47 ,0xf0 ,0xad ,0xd4 ,0xa2 ,0xaf ,0x9c ,0xa4 ,0x72 ,0xc0},
						  {0xb7 ,0xfd ,0x93 ,0x26 ,0x36 ,0x3f ,0xf7 ,0xcc ,0x34 ,0xa5 ,0xe5 ,0xf1 ,0x71 ,0xd8 ,0x31 ,0x15},
						  {0x04 ,0xc7 ,0x23 ,0xc3 ,0x18 ,0x96 ,0x05 ,0x9a ,0x07 ,0x12 ,0x80 ,0xe2 ,0xeb ,0x27 ,0xb2 ,0x75},
						  {0x09 ,0x83 ,0x2c ,0x1a ,0x1b ,0x6e ,0x5a ,0xa0 ,0x52 ,0x3b ,0xd6 ,0xb3 ,0x29 ,0xe3 ,0x2f ,0x84},
						  {0x53 ,0xd1 ,0x00 ,0xed ,0x20 ,0xfc ,0xb1 ,0x5b ,0x6a ,0xcb ,0xbe ,0x39 ,0x4a ,0x4c ,0x58 ,0xcf},
						  {0xd0 ,0xef ,0xaa ,0xfb ,0x43 ,0x4d ,0x33 ,0x85 ,0x45 ,0xf9 ,0x02 ,0x7f ,0x50 ,0x3c ,0x9f ,0xa8},
						  {0x51 ,0xa3 ,0x40 ,0x8f ,0x92 ,0x9d ,0x38 ,0xf5 ,0xbc ,0xb6 ,0xda ,0x21 ,0x10 ,0xff ,0xf3 ,0xd2},
						  {0xcd ,0x0c ,0x13 ,0xec ,0x5f ,0x97 ,0x44 ,0x17 ,0xc4 ,0xa7 ,0x7e ,0x3d ,0x64 ,0x5d ,0x19 ,0x73},
						  {0x60 ,0x81 ,0x4f ,0xdc ,0x22 ,0x2a ,0x90 ,0x88 ,0x46 ,0xee ,0xb8 ,0x14 ,0xde ,0x5e ,0x0b ,0xdb},
						  {0xe0 ,0x32 ,0x3a ,0x0a ,0x49 ,0x06 ,0x24 ,0x5c ,0xc2 ,0xd3 ,0xac ,0x62 ,0x91 ,0x95 ,0xe4 ,0x79},
						  {0xe7 ,0xc8 ,0x37 ,0x6d ,0x8d ,0xd5 ,0x4e ,0xa9 ,0x6c ,0x56 ,0xf4 ,0xea ,0x65 ,0x7a ,0xae ,0x08},
						  {0xba ,0x78 ,0x25 ,0x2e ,0x1c ,0xa6 ,0xb4 ,0xc6 ,0xe8 ,0xdd ,0x74 ,0x1f ,0x4b ,0xbd ,0x8b ,0x8a},
						  {0x70 ,0x3e ,0xb5 ,0x66 ,0x48 ,0x03 ,0xf6 ,0x0e ,0x61 ,0x35 ,0x57 ,0xb9 ,0x86 ,0xc1 ,0x1d ,0x9e},
						  {0xe1 ,0xf8 ,0x98 ,0x11 ,0x69 ,0xd9 ,0x8e ,0x94 ,0x9b ,0x1e ,0x87 ,0xe9 ,0xce ,0x55 ,0x28 ,0xdf},
						  {0x8c ,0xa1 ,0x89 ,0x0d ,0xbf ,0xe6 ,0x42 ,0x68 ,0x41 ,0x99 ,0x2d ,0x0f ,0xb0 ,0x54 ,0xbb ,0x16}};

	uint8_t invSbox[16] [16] = {{0x52 ,0x09 ,0x6a ,0xd5 ,0x30 ,0x36 ,0xa5 ,0x38 ,0xbf ,0x40 ,0xa3 ,0x9e ,0x81 ,0xf3 ,0xd7 ,0xfb},
						  		{0x7c ,0xe3 ,0x39 ,0x82 ,0x9b ,0x2f ,0xff ,0x87 ,0x34 ,0x8e ,0x43 ,0x44 ,0xc4 ,0xde ,0xe9 ,0xcb},
							  	{0x54 ,0x7b ,0x94 ,0x32 ,0xa6 ,0xc2 ,0x23 ,0x3d ,0xee ,0x4c ,0x95 ,0x0b ,0x42 ,0xfa ,0xc3 ,0x4e},
							  	{0x08 ,0x2e ,0xa1 ,0x66 ,0x28 ,0xd9 ,0x24 ,0xb2 ,0x76 ,0x5b ,0xa2 ,0x49 ,0x6d ,0x8b ,0xd1 ,0x25},
							  	{0x72 ,0xf8 ,0xf6 ,0x64 ,0x86 ,0x68 ,0x98 ,0x16 ,0xd4 ,0xa4 ,0x5c ,0xcc ,0x5d ,0x65 ,0xb6 ,0x92},
								{0x6c ,0x70 ,0x48 ,0x50 ,0xfd ,0xed ,0xb9 ,0xda ,0x5e ,0x15 ,0x46 ,0x57 ,0xa7 ,0x8d ,0x9d ,0x84},
								{0x90 ,0xd8 ,0xab ,0x00 ,0x8c ,0xbc ,0xd3 ,0x0a ,0xf7 ,0xe4 ,0x58 ,0x05 ,0xb8 ,0xb3 ,0x45 ,0x06},
								{0xd0 ,0x2c ,0x1e ,0x8f ,0xca ,0x3f ,0x0f ,0x02 ,0xc1 ,0xaf ,0xbd ,0x03 ,0x01 ,0x13 ,0x8a ,0x6b},
							  	{0x3a ,0x91 ,0x11 ,0x41 ,0x4f ,0x67 ,0xdc ,0xea ,0x97 ,0xf2 ,0xcf ,0xce ,0xf0 ,0xb4 ,0xe6 ,0x73},
							  	{0x96 ,0xac ,0x74 ,0x22 ,0xe7 ,0xad ,0x35 ,0x85 ,0xe2 ,0xf9 ,0x37 ,0xe8 ,0x1c ,0x75 ,0xdf ,0x6e},
							  	{0x47 ,0xf1 ,0x1a ,0x71 ,0x1d ,0x29 ,0xc5 ,0x89 ,0x6f ,0xb7 ,0x62 ,0x0e ,0xaa ,0x18 ,0xbe ,0x1b},
							  	{0xfc ,0x56 ,0x3e ,0x4b ,0xc6 ,0xd2 ,0x79 ,0x20 ,0x9a ,0xdb ,0xc0 ,0xfe ,0x78 ,0xcd ,0x5a ,0xf4},
							  	{0x1f ,0xdd ,0xa8 ,0x33 ,0x88 ,0x07 ,0xc7 ,0x31 ,0xb1 ,0x12 ,0x10 ,0x59 ,0x27 ,0x80 ,0xec ,0x5f},
							  	{0x60 ,0x51 ,0x7f ,0xa9 ,0x19 ,0xb5 ,0x4a ,0x0d ,0x2d ,0xe5 ,0x7a ,0x9f ,0x93 ,0xc9 ,0x9c ,0xef},
							  	{0xa0 ,0xe0 ,0x3b ,0x4d ,0xae ,0x2a ,0xf5 ,0xb0 ,0xc8 ,0xeb ,0xbb ,0x3c ,0x83 ,0x53 ,0x99 ,0x61},
							  	{0x17 ,0x2b ,0x04 ,0x7e ,0xba ,0x77 ,0xd6 ,0x26 ,0xe1 ,0x69 ,0x14 ,0x63 ,0x55 ,0x21 ,0x0c ,0x7d}};


	
	uint8_t row;
	uint8_t collumn;
		
	row = b >> 4;
	collumn = (b << 4);
	collumn = collumn >> 4;

	return crypto ? sbox[row][collumn] : invSbox[row][collumn];
}

//************************************
//subWord() substitui os 4 bytes de
//uma palavra pelos respectivos bytes
//da tabela sbox
//************************************
uint32_t ECB::subWord(uint32_t w, bool crypto){

	uint8_t b[4];
	uint8_t row;
	uint8_t collumn;
	uint32_t conv = 0x00000000;


	for(int i = 0; i < 4; i++){
		b[i] = (w >> i*8);
		b[i] = subByte(b[i], crypto);
	}

	for(int i = 3; i > 0; i--){
		conv |= b[i];
		conv = conv << 8;
	}
	conv |= b[0];

	return conv;
}

//************************************
//keyExpand() utiliza uma chave de 16
//bytes e gera 10 chaves a partir dela
//Essas chaves serão usadas cada uma
//em um round da encriptação
//************************************
void ECB::keyExpand(bool crypto){

	uint32_t temp;

	int i = 0;
	while(i < NK){
		for(int j = 0; j < 3; j++){
			roundKey[i] |= key[4*i+j];
			roundKey[i]  = roundKey[i] << 8;
		}
		roundKey[i] |= key[4*i+3];
		i++;
	}

	i = NK;
	uint32_t rConfirst = 0x01000000;
	while(i < (NB*(NR + 1))){
		temp = roundKey[i-1];
		if(!(i % NK)){
			temp = subWord(rotWord(temp), crypto);
			rConfirst = (i/NK == 1) ? rConfirst : rConfirst << 1;
			if(i/NK >= 9)
				rConfirst = (i/NK == 9) ? 0x1b000000 : 0x36000000;
			temp ^= rConfirst;
		}else if(NK > 6 && i%4 == 4)
			temp = subWord(temp, crypto);

		roundKey[i] = roundKey[i - NK] ^ temp;
		i++;
	}
}

//************************************
//Para cada round, addRoundKey() faz
//uma xor do dado atual com a chave
//daquele round. Cada coluna é xorada
//com 4 bytes da chave
//************************************
void ECB::addRoundKey(uint8_t state [][4], int min){
	uint8_t actual;


	for(int j = 0; j < 4; j++)
		for(int i = 0; i < 4; i++){
			actual = roundKey[min + j] >> (3 - i)*8;
			state [i][j] ^= actual;
		}
}

//*************************************
//subBytes substitui todos os 16 bytes
//do dado pelos respectivos bytes da 
//tabela sbox
//*************************************
void ECB::subBytes(uint8_t state [][4], bool crypto){
	for(int i = 0; i < 4; i++)
		for(int j = 0; j < 4; j++){
			state[i][j] = subByte(state[i][j], crypto);
		}
}

//*************************************
//shiftRows() faz a seguinte operação:
// 00 01 02 03       00 01 02 03
// 04 05 06 07  - \  05 06 07 04
// 08 09 0a 0b  - /  0a 0b 08 09
// 0c 0d 0e 0f       0f 0c 0d 0e
//*************************************
void ECB::shiftRows(uint8_t state [][4]){
	uint8_t temp [4][4];
	for(int i = 0; i < 4; i++)
		for(int j = 0; j < 4; j++)
			temp[i][j] = state[i][j];

	for(int i = 0; i < 4; i++){
		for(int j = 0; j < NB; j++){
			state[i][j] = temp[i][(j + i)%NB];
		}
	}
}

//***************************************
//invShiftRows() faz a seguinte operação:
// 00 01 02 03       00 01 02 03
// 04 05 06 07  - \  07 04 05 06
// 08 09 0a 0b  - /  0a 0b 08 09
// 0c 0d 0e 0f       0d 0e 0f 0c
//***************************************

void ECB::invShiftRows(uint8_t state [][4]){
	uint8_t temp [4][4];
	for(int i = 0; i < 4; i++)
		for(int j = 0; j < 4; j++)
			temp[i][j] = state[i][j];

	for(int i = 0; i < 4; i++){
		for(int j = 0; j < NB; j++){
			state[i][(j + i)%NB] = temp[i][j];
		}
	}
}

//**************************************
//multiply() faz a o produto de 2 bytes
//usando aritmética de campos finitos
//**************************************
uint8_t ECB::multiply(uint8_t b1, uint8_t b2){

	uint8_t res = 0x00;
	
	while(b1 && b2){
		if(b2 & 1)
			res ^= b1;
		if(b1 & 0x80)
			b1 = (b1 << 1) ^ 0x11b;
		else
			b1 <<= 1;
		b2 >>=1;
	}


	return res;
}

//**************************************
//mixCollumns() multiplica uma matriz A
//por cada coluna do dado
// [d0']   [02 03 01 01]   [d0]
// [d1'] = [01 02 03 01] * [d1]
// [d2'] = [01 01 02 03] * [d2]
// [d3']   [03 01 01 02]   [d3]
//**************************************
void ECB::mixCollumns(uint8_t state [][4]){
	uint8_t tmp [4][4];
	for(int i = 0; i < 4; i++)
		for(int j = 0; j < 4; j++)
			tmp[i][j] = state[i][j];

	for(int j = 0; j < 4; j++){
		state[0][j] = multiply(0x02, tmp[0][j]) ^ multiply(0x03, tmp[1][j]) ^ tmp[2][j] ^ tmp[3][j];
		state[1][j] = tmp[0][j] ^ multiply(0x02, tmp[1][j]) ^ multiply(0x03, tmp[2][j]) ^ tmp[3][j];
		state[2][j] = tmp[0][j] ^ tmp[1][j] ^ multiply(0x02, tmp[2][j]) ^ multiply(0x03, tmp[3][j]);
		state[3][j] = multiply(0x03, tmp[0][j]) ^ tmp[1][j] ^ tmp[2][j] ^ multiply(0x02, tmp[3][j]);
	}}

//*****************************************
//invMixCollumns() multiplica uma matriz B
//por cada coluna do dado
// [d0']   [0e 0b 0d 09]   [d0]
// [d1'] = [09 0e 0b 0d] * [d1]
// [d2'] = [0d 09 0e 0b] * [d2]
// [d3']   [0b 0d 09 0e]   [d3]
//****************************************
void ECB::invMixCollumns(uint8_t state [][4]){
	uint8_t tmp [4][4];
	for(int i = 0; i < 4; i++)
		for(int j = 0; j < 4; j++)
			tmp[i][j] = state[i][j];

	for(int j = 0; j < 4; j++){
		state[0][j] = multiply(0x0e, tmp[0][j]) ^ multiply(0x0b, tmp[1][j]) ^ multiply(0x0d, tmp[2][j]) ^multiply(0x09, tmp[3][j]);
		state[1][j] = multiply(0x09, tmp[0][j]) ^ multiply(0x0e, tmp[1][j]) ^ multiply(0x0b, tmp[2][j]) ^multiply(0x0d, tmp[3][j]);
		state[2][j] = multiply(0x0d, tmp[0][j]) ^ multiply(0x09, tmp[1][j]) ^ multiply(0x0e, tmp[2][j]) ^multiply(0x0b, tmp[3][j]);
		state[3][j] = multiply(0x0b, tmp[0][j]) ^ multiply(0x0d, tmp[1][j]) ^ multiply(0x09, tmp[2][j]) ^multiply(0x0e, tmp[3][j]);
		
	}}



//**************************************
//crypt() realiza a encriptação de um
//dado de 16 bytes utilizando uma chave
//de 16 bytes.
//**************************************
void ECB::crypt(){

	keyExpand(true);

	//declaration of state
	uint8_t state[4][4];

	//state = data_in
	for(int i =0; i < 4; i++){
			state[0][i] = data[4*i + 0];
			state[1][i] = data[4*i + 1];
			state[2][i] = data[4*i + 2];
			state[3][i] = data[4*i + 3];
	}

	//Primeiro round: Faz a xor da chave expandida [0]
	//com o dado recebido
	addRoundKey(state, 0);

	//Do segundo até o nono round, essas operações são feitas,
	//criptografando o dado
	for(int round = 1; round < NR; round ++){
		subBytes(state, true);
		shiftRows(state);
		mixCollumns(state);
		addRoundKey(state, round * NB);
	}

	//No último round, a operação de mixCollumns não é realizada
	subBytes(state, true);
	shiftRows(state);
	addRoundKey(state, NR*NB);
	
	for(int i =0; i < 4; i++){
		cipher [4*i + 0] = state[0][i];
		cipher [4*i + 1] = state[1][i];
		cipher [4*i + 2] = state[2][i];
		cipher [4*i + 3] = state[3][i];
	}
}


//**************************************
//crypt() realiza a encriptação de um
//dado de 16 bytes utilizando uma chave
//de 16 bytes.
//**************************************
void ECB::decrypt(){

	keyExpand(true);

	//declaration of state
	uint8_t state[4][4];

	//state = data_in
	for(int i =0; i < 4; i++){
			state[0][i] = data[4*i + 0];
			state[1][i] = data[4*i + 1];
			state[2][i] = data[4*i + 2];
			state[3][i] = data[4*i + 3];
	}
	addRoundKey(state, NR*NB);
	//Do segundo até o nono round, essas operações são feitas,
	//criptografando o dado
	for(int round = NR - 1; round > 0; round --){
		invShiftRows(state);
		subBytes(state, false);
		addRoundKey(state, round * NB);
		invMixCollumns(state);
	}

	//No último round, a operação de mixCollumns não é realizada
	invShiftRows(state);
	subBytes(state, false);
	addRoundKey(state, 0);
	
	for(int i =0; i < 4; i++){
		cipher [4*i + 0] = state[0][i];
		cipher [4*i + 1] = state[1][i];
		cipher [4*i + 2] = state[2][i];
		cipher [4*i + 3] = state[3][i];
	}
}

void ECB::getCipher(uint8_t dt[]){
	for(int i = 0; i < 16; i++)
		dt[i] = cipher [i];
}