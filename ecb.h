//***************************************************************************************************
//*                                                                                                 *
//*            *@@@@@@@@@@@@@*         *********************************************************    *
//*         @@@~*           *@@@;      * Arquivo: ecb.h                                        *    *
//*      *@@*                   @@*    * Autor: João Pedro Melquiades Gomes                    *    *
//*    *@@    *@*            @@;       * Descrição: Cabeçalho da classe ECB                    *    *
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



#ifndef ECB_H
#define ECB_H

#include <cstdint>

#define NB 4
#define NR 10
#define NK 4

class ECB{
protected:
	uint8_t key [4 * NK];
	uint8_t data[4 * NB];
	uint8_t cipher [ 4 * NB];
	uint32_t roundKey [NB * (NR + 1)] ;

	void addRoundKey(uint8_t [][4], int);
	uint8_t subByte(uint8_t, bool);
	void subBytes(uint8_t[][4], bool);
	void shiftRows(uint8_t[][4]);
	void invShiftRows(uint8_t[][4]);
	void mixCollumns(uint8_t[][4]);
	void invMixCollumns(uint8_t[][4]);
	void keyExpand(bool);
	uint32_t rotWord(uint32_t);
	uint32_t subWord(uint32_t, bool);
	uint8_t multiply(uint8_t, uint8_t);
public:
	ECB(uint8_t*, uint8_t*);
	void crypt();
	void decrypt();
	void getCipher(uint8_t []);

};

#endif
