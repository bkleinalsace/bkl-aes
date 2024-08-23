/*IMPLEMENTATION of AES Algorythm by Björn Klein
The goal was to understand how AES works (I learned the working of AES Algorithm with the youtube videos from NESO Academy on AES https://www.youtube.com/watch?v=3MPkc-PFSRI&t=258s, where he explains the theorie about AES algorithm)
After understanding the theory of how it works, I  created my own AES Implementation without using anything else beside standard c libraries to be used on my Arduino/ESP32 Projects.
The project is a proof of concept and is not fine tuned / optimized now also structure is right now all in one file as it is easyer to use in ESP32. I will maybe create a library later
*/

#include "stdlib.h"
#include "stdio.h"
#include "stdint.h"
#include <string.h>
#include <time.h> //used to generate the random bytes for the initialization vector


typedef unsigned char  BYTE;

int keyLength = 256;

int globalSize = 0;
 

BYTE expandedKeyWords[60][4] = {};

BYTE rConst[15] = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D, 0x9A};

BYTE resultWord[4] = {};

int blockSize = 1024;




//SUBSTITUTION BOX

BYTE getSboxResult(BYTE x){
        BYTE sBox[16][16] = {
        {0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76},
        {0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0},
        {0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15},
        {0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75},
        {0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84},
        {0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf},
        {0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8},
        {0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2},
        {0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73},
        {0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb},
        {0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79},
        {0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08},
        {0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a},
        {0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e},
        {0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf},
        {0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16},
    };

    BYTE highNibble = (BYTE)(x >> 4 & 0xF);
    BYTE lowNibble = (BYTE) (x & 0xF);
    return sBox[highNibble][lowNibble];
}

//INVESE SUBSTITUTION BOX

BYTE getInvertSBoxResult(BYTE x){
    BYTE invertedSbox[16][16] = {
    {0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb},
    {0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb},
    {0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e},
    {0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25},
    {0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92},
    {0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84},
    {0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06},
    {0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b},
    {0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73},
    {0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e},
    {0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b},
    {0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4},
    {0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f},
    {0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef},
    {0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61},
    {0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d},
};
    BYTE highNibble = (BYTE)(x >> 4 & 0xF);
    BYTE lowNibble = (BYTE) (x & 0xF);

    return invertedSbox[highNibble][lowNibble];
}

BYTE state[4][4] = {{0x48, 0x61, 0x6c, 0x6c}, {0x6f, 0x49, 0x68, 0x72}, {0x20, 0x4c, 0x69, 0x65}, {0x62, 0x65, 0x6e, 0x20}};
BYTE cypherKey[16] = {0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C};
BYTE cypherKey2[32] = {0x60, 0x3D, 0xEB, 0x10, 0x15, 0xCA, 0x71, 0xBE, 0x2B, 0x73, 0xAE, 0xF0, 0x85, 0x7D, 0x77, 0x81,0x1F, 0x35, 0x2C, 0x07, 0x3B, 0x61, 0x08, 0xD7,0x2D, 0x98, 0x10, 0xA3, 0x09, 0x14, 0xDF, 0xF4};


void mixColumn(BYTE column[4]) {
    BYTE ba[4];
    BYTE bb[4];
    BYTE bc;
    BYTE bh;



    for (bc = 0; bc < 4; bc++) {
        ba[bc] = column[bc];
        bh = column[bc] >> 7;   //shifting bits to the right (adding in zero bits)
        bb[bc] = column[bc] << 1; //this removes the high nible
        bb[bc] ^= bh * 0x1B; 
    }
    column[0] = bb[0] ^ ba[3] ^ ba[2] ^ bb[1] ^ ba[1]; //xoring to mix columns
    column[1] = bb[1] ^ ba[0] ^ ba[3] ^ bb[2] ^ ba[2]; 
    column[2] = bb[2] ^ ba[1] ^ ba[0] ^ bb[3] ^ ba[3]; 
    column[3] = bb[3] ^ ba[2] ^ ba[1] ^ bb[0] ^ ba[0]; 
}

unsigned char galoisMultiplication(BYTE a, BYTE b)
{
    BYTE p = 0;
    BYTE counter;
    BYTE highBitSet;
    for (counter = 0; counter < 8; counter++)
    {
        if ((b & 1) == 1)
            p ^= a;
        highBitSet = (a & 0x80);
        a <<= 1;
        if (highBitSet == 0x80)
            a ^= 0x1b;
        b >>= 1;
    }
    return p;
}

void invMixColumn(BYTE column[4])
{
    BYTE newByte[4];
    int i;
    for (i = 0; i < 4; i++)
    {
        newByte[i] = column[i];
    }
    column[0] = galoisMultiplication(newByte[0], 14) ^
                galoisMultiplication(newByte[3], 9) ^
                galoisMultiplication(newByte[2], 13) ^
                galoisMultiplication(newByte[1], 11);
    column[1] = galoisMultiplication(newByte[1], 14) ^
                galoisMultiplication(newByte[0], 9) ^
                galoisMultiplication(newByte[3], 13) ^
                galoisMultiplication(newByte[2], 11);
    column[2] = galoisMultiplication(newByte[2], 14) ^
                galoisMultiplication(newByte[1], 9) ^
                galoisMultiplication(newByte[0], 13) ^
                galoisMultiplication(newByte[3], 11);
    column[3] = galoisMultiplication(newByte[3], 14) ^
                galoisMultiplication(newByte[2], 9) ^
                galoisMultiplication(newByte[1], 13) ^
                galoisMultiplication(newByte[0], 11);
}

void invMixColumns(BYTE myState[4][4])
{
    int i, j;
    BYTE column[4];

    // iterate over the 4 columns
    for (i = 0; i < 4; i++)
    {
        // construct one column by iterating over the 4 rows
        for (j = 0; j < 4; j++)
        {
            column[j] = myState[i][j];
        }

        // apply the invMixColumn on one column
        invMixColumn(column);

        // put the values back into the state
        for (j = 0; j < 4; j++)
        {
            myState[i][j] = column[j];
        }
    }
}

//print actual state in hex form

void printState(BYTE myState[4][4]){
    for (int y= 0; y < 4; y++){
        for (int x = 0; x < 4; x++){
            printf("%02x ", myState[x][y]);
           
        }
            printf("\n");         
    }
    printf("\n");
}

//printactual state in text form

void printStateAsText(BYTE state[4][4]){
    for (int x= 0; x < 4; x++){
        for (int y = 0; y < 4; y++){
            printf("%c", state[x][y]);
           
        }       
    }
    printf("\n");
}


//substitute bytes with substitution table

void subBytes(BYTE state[4][4]){
    for (int y = 0; y < 4; y++){
        for (int x = 0; x < 4; x++){
            state[y][x] = getSboxResult(state[y][x]);
        }
    }
}

//substitute bytes with inverse substitution table

void inverseSubBytes(BYTE cState[4][4]){
    for (int y = 0; y < 4; y++){
        for (int x = 0; x < 4; x++){
            cState[y][x] = getInvertSBoxResult(cState[y][x]);
        }
    }
}   


//AES shift rows operation
//leave first row untouched
//circular shift second row one byte to the left
//circular shift third row two bytes to the left
//circular shift fourth row three bytes to the left

void shiftRows(BYTE state[4][4]){
    BYTE tempByte;

        tempByte = state[0][1];
        state[0][1] = state[1][1];
        state[1][1] = state[2][1];
        state[2][1] = state[3][1];
        state[3][1] = tempByte;
        
        for(int i = 0; i < 2; i++){
            tempByte = state[0][2];
            state[0][2] = state[1][2];
            state[1][2] = state[2][2];
            state[2][2] = state[3][2];
            state[3][2] = tempByte;
        }
        
        for(int i = 0; i < 3; i++){
            tempByte = state[0][3];
            state[0][3] = state[1][3];
            state[1][3] = state[2][3];
            state[2][3] = state[3][3];
            state[3][3] = tempByte;
        }        
}

//AES inverseshift rows operation
//leave first row untouched
//circular shift second row one byte to the right
//circular shift third row two bytes to the right
//circular shift fourth row three bytes to the right

void inverseShiftRows(BYTE myState[4][4]){
    BYTE tempByte;
        tempByte = myState[3][1];
        myState[3][1] = myState[2][1];        
        myState[2][1] = myState[1][1];
        myState[1][1] = myState[0][1];
        myState[0][1] = tempByte;
        
        for(int i = 0; i < 2; i++){
            tempByte = myState[3][2];
            myState[3][2] = myState[2][2];
            myState[2][2] = myState[1][2];
            myState[1][2] = myState[0][2];
            myState[0][2] = tempByte;
        }
        
        for(int i = 0; i < 3; i++){
            tempByte = myState[3][3];
            myState[3][3] = myState[2][3];
            myState[2][3] = myState[1][3];
            myState[1][3] = myState[0][3];
            myState[0][3] = tempByte;
        }        
}   


//performs AES mixColumn operation

void mixColumns( BYTE state[4][4]){
    BYTE column[4]= {state[0][0], state[0][1], state[0][2], state[0][3]};
    
    for (int x = 0; x < 4; x++){
        for (int y = 0; y < 4; y++){
            column[y] = state[x][y];
        }

        mixColumn(column);

        for (int y = 0; y < 4; y++){
            state[x][y] = column[y];
        } 
    }
} 

//set all expandedKeys to 0x00
void initializeExpandedKeys(){
    for (int k = 0; k < 60; k++){
        for (int b = 0; b < 4; b++){
            expandedKeyWords[k][b] = 0x00;
        }
    }
}

//create initial round key with the cypher key

void createInitialRoundKey256(){
    expandedKeyWords[0][0] = cypherKey2[0];
    expandedKeyWords[0][1] = cypherKey2[1];
    expandedKeyWords[0][2] = cypherKey2[2];
    expandedKeyWords[0][3] = cypherKey2[3];

    expandedKeyWords[1][0] = cypherKey2[4];
    expandedKeyWords[1][1] = cypherKey2[5];
    expandedKeyWords[1][2] = cypherKey2[6];
    expandedKeyWords[1][3] = cypherKey2[7];

    expandedKeyWords[2][0] = cypherKey2[8];
    expandedKeyWords[2][1] = cypherKey2[9];
    expandedKeyWords[2][2] = cypherKey2[10];
    expandedKeyWords[2][3] = cypherKey2[11];

    expandedKeyWords[3][0] = cypherKey2[12];
    expandedKeyWords[3][1] = cypherKey2[13];
    expandedKeyWords[3][2] = cypherKey2[14];
    expandedKeyWords[3][3] = cypherKey2[15];

    expandedKeyWords[4][0] = cypherKey2[16];
    expandedKeyWords[4][1] = cypherKey2[17];
    expandedKeyWords[4][2] = cypherKey2[18];
    expandedKeyWords[4][3] = cypherKey2[19];

    expandedKeyWords[5][0] = cypherKey2[20];
    expandedKeyWords[5][1] = cypherKey2[21];
    expandedKeyWords[5][2] = cypherKey2[22];
    expandedKeyWords[5][3] = cypherKey2[23];

    expandedKeyWords[6][0] = cypherKey2[24];
    expandedKeyWords[6][1] = cypherKey2[25];
    expandedKeyWords[6][2] = cypherKey2[26];
    expandedKeyWords[6][3] = cypherKey2[27];

    expandedKeyWords[7][0] = cypherKey2[28];
    expandedKeyWords[7][1] = cypherKey2[29];
    expandedKeyWords[7][2] = cypherKey2[30];
    expandedKeyWords[7][3] = cypherKey2[31]; 

  
}

//create initial round key with the cypher key


void createInitialRoundKey(){
    expandedKeyWords[0][0] = cypherKey[0];
    expandedKeyWords[0][1] = cypherKey[1];
    expandedKeyWords[0][2] = cypherKey[2];
    expandedKeyWords[0][3] = cypherKey[3];

    expandedKeyWords[1][0] = cypherKey[4];
    expandedKeyWords[1][1] = cypherKey[5];
    expandedKeyWords[1][2] = cypherKey[6];
    expandedKeyWords[1][3] = cypherKey[7];

    expandedKeyWords[2][0] = cypherKey[8];
    expandedKeyWords[2][1] = cypherKey[9];
    expandedKeyWords[2][2] = cypherKey[10];
    expandedKeyWords[2][3] = cypherKey[11];

    expandedKeyWords[3][0] = cypherKey[12];
    expandedKeyWords[3][1] = cypherKey[13];
    expandedKeyWords[3][2] = cypherKey[14];
    expandedKeyWords[3][3] = cypherKey[15];
}


void gFunction(int numOfInputWord, int numOfRound){
    //Circular Shift
    BYTE tempByte;
    tempByte = expandedKeyWords[numOfInputWord][0];
    resultWord[0] = expandedKeyWords[numOfInputWord][1];
    resultWord[1] = expandedKeyWords[numOfInputWord][2];
    resultWord[2] = expandedKeyWords[numOfInputWord][3];
    resultWord[3] = tempByte;

    //Substitution

    resultWord[0] = getSboxResult(resultWord[0]);
    resultWord[1] = getSboxResult(resultWord[1]);
    resultWord[2] = getSboxResult(resultWord[2]);
    resultWord[3] = getSboxResult(resultWord[3]);

    //xoring

    resultWord[0] = expandedKeyWords[numOfInputWord - 3][0] ^ resultWord[0] ^ rConst[numOfRound];
    resultWord[1] = expandedKeyWords[numOfInputWord - 3][1] ^ resultWord[1];
    resultWord[2] = expandedKeyWords[numOfInputWord - 3][2] ^ resultWord[2];
    resultWord[3] = expandedKeyWords[numOfInputWord - 3][3] ^ resultWord[3];
}

void gFunction256(int numOfInputWord, int numOfRound){
    //Circular Shift
    BYTE tempByte;
    tempByte = expandedKeyWords[numOfInputWord][0];
    resultWord[0] = expandedKeyWords[numOfInputWord][1];
    resultWord[1] = expandedKeyWords[numOfInputWord][2];
    resultWord[2] = expandedKeyWords[numOfInputWord][3];
    resultWord[3] = tempByte;

    //Substitution

    resultWord[0] = getSboxResult(resultWord[0]);
    resultWord[1] = getSboxResult(resultWord[1]);
    resultWord[2] = getSboxResult(resultWord[2]);
    resultWord[3] = getSboxResult(resultWord[3]);

    //xoring

    resultWord[0] = expandedKeyWords[numOfInputWord - 7][0] ^ resultWord[0] ^ rConst[numOfRound ];;
    resultWord[1] = expandedKeyWords[numOfInputWord - 7][1] ^ resultWord[1];
    resultWord[2] = expandedKeyWords[numOfInputWord - 7][2] ^ resultWord[2];
    resultWord[3] = expandedKeyWords[numOfInputWord - 7][3] ^ resultWord[3];
}

//g2 fuhnction is only used in AES256
//fourth key is substituted with substitution box

void g2Function256(int numOfInputWord, int numOfRound){
    //Substitution

    resultWord[0] = getSboxResult(expandedKeyWords[numOfInputWord][0]);
    resultWord[1] = getSboxResult(expandedKeyWords[numOfInputWord][1]);
    resultWord[2] = getSboxResult(expandedKeyWords[numOfInputWord][2]);
    resultWord[3] = getSboxResult(expandedKeyWords[numOfInputWord][3]);    
}


//AES key expansion AES128

void keyExpansion128(){

    int numOfRounds = 0;
    int actualRound = 0;
    numOfRounds = 11;
    initializeExpandedKeys();
    createInitialRoundKey();


    for (int numOfWordsWorkingOn = 4; numOfWordsWorkingOn < (numOfRounds * 4); numOfWordsWorkingOn +=1)
    {
        //every 4 words go through gFunction
        if (numOfWordsWorkingOn % 4 == 0){
            gFunction((numOfWordsWorkingOn - 1), actualRound);
            expandedKeyWords[numOfWordsWorkingOn][0] = resultWord[0];
            expandedKeyWords[numOfWordsWorkingOn][1] = resultWord[1];
            expandedKeyWords[numOfWordsWorkingOn][2] = resultWord[2];
            expandedKeyWords[numOfWordsWorkingOn][3] = resultWord[3];
            actualRound++;
        } else {
            //all other words are the resut f word[-4] XOR word[-1]
            expandedKeyWords[numOfWordsWorkingOn][0] = expandedKeyWords[numOfWordsWorkingOn - 4][0] ^ expandedKeyWords[numOfWordsWorkingOn - 1][0];
            expandedKeyWords[numOfWordsWorkingOn][1] = expandedKeyWords[numOfWordsWorkingOn - 4][1] ^ expandedKeyWords[numOfWordsWorkingOn - 1][1];
            expandedKeyWords[numOfWordsWorkingOn][2] = expandedKeyWords[numOfWordsWorkingOn - 4][2] ^ expandedKeyWords[numOfWordsWorkingOn - 1][2];
            expandedKeyWords[numOfWordsWorkingOn][3] = expandedKeyWords[numOfWordsWorkingOn - 4][3] ^ expandedKeyWords[numOfWordsWorkingOn - 1][3];
        }

    }

}

//AES key expansion AES256

void keyExpansion256(){
    int printWordNum = 8;    
    int numOfRounds = 0;
    int actualRound = 0;
    numOfRounds = 15;
    
    initializeExpandedKeys();
    createInitialRoundKey256();


    for (int numOfWordsWorkingOn = 8; numOfWordsWorkingOn < (numOfRounds * 4); numOfWordsWorkingOn +=1)
    {
        //every 8th word  go through gFunction
        if (numOfWordsWorkingOn % 8 == 0){
            gFunction256((numOfWordsWorkingOn - 1), actualRound);
            expandedKeyWords[numOfWordsWorkingOn][0] = resultWord[0];
            expandedKeyWords[numOfWordsWorkingOn][1] = resultWord[1];
            expandedKeyWords[numOfWordsWorkingOn][2] = resultWord[2];
            expandedKeyWords[numOfWordsWorkingOn][3] = resultWord[3];
            actualRound++;
        }
        //every other 4 words go through g2 function
        else if ((numOfWordsWorkingOn % 4 == 0) && (numOfWordsWorkingOn % 8 != 0)) {
            g2Function256((numOfWordsWorkingOn - 1), actualRound);
            expandedKeyWords[numOfWordsWorkingOn][0] = resultWord[0] ^ expandedKeyWords[numOfWordsWorkingOn - 8][0];
            expandedKeyWords[numOfWordsWorkingOn][1] = resultWord[1] ^ expandedKeyWords[numOfWordsWorkingOn - 8][1];
            expandedKeyWords[numOfWordsWorkingOn][2] = resultWord[2] ^ expandedKeyWords[numOfWordsWorkingOn - 8][2];
            expandedKeyWords[numOfWordsWorkingOn][3] = resultWord[3] ^ expandedKeyWords[numOfWordsWorkingOn - 8][3];           
        }
        //all other words are reslt of xor  word[-8] with word[-1]
        else {
            expandedKeyWords[numOfWordsWorkingOn][0] = expandedKeyWords[numOfWordsWorkingOn - 8][0] ^ expandedKeyWords[numOfWordsWorkingOn - 1][0];
            expandedKeyWords[numOfWordsWorkingOn][1] = expandedKeyWords[numOfWordsWorkingOn - 8][1] ^ expandedKeyWords[numOfWordsWorkingOn - 1][1];
            expandedKeyWords[numOfWordsWorkingOn][2] = expandedKeyWords[numOfWordsWorkingOn - 8][2] ^ expandedKeyWords[numOfWordsWorkingOn - 1][2];
            expandedKeyWords[numOfWordsWorkingOn][3] = expandedKeyWords[numOfWordsWorkingOn - 8][3] ^ expandedKeyWords[numOfWordsWorkingOn - 1][3];
        }

        printWordNum += 1;

    }

}

//AES add round key (XOR)

void addRoundKey(BYTE myState[4][4], int n){
    //XOR the state with the round key
    myState[0][0] = myState[0][0 ] ^ expandedKeyWords[( n * 4) + 0][0];
    myState[0][1] = myState[0][1 ] ^ expandedKeyWords[( n * 4) + 0][1];
    myState[0][2] = myState[0][2 ] ^ expandedKeyWords[( n * 4) + 0][2];
    myState[0][3] = myState[0][3 ] ^ expandedKeyWords[( n * 4) + 0][3];


    myState[1][0] = myState[1][0 ] ^ expandedKeyWords[( n * 4) + 1][0];
    myState[1][1] = myState[1][1 ] ^ expandedKeyWords[( n * 4) + 1][1];
    myState[1][2] = myState[1][2 ] ^ expandedKeyWords[( n * 4) + 1][2];
    myState[1][3] = myState[1][3 ] ^ expandedKeyWords[( n * 4) + 1][3];

    myState[2][0] = myState[2][0 ] ^ expandedKeyWords[( n * 4) + 2][0];
    myState[2][1] = myState[2][1 ] ^ expandedKeyWords[( n * 4) + 2][1];
    myState[2][2] = myState[2][2 ] ^ expandedKeyWords[( n * 4) + 2][2];
    myState[2][3] = myState[2][3 ] ^ expandedKeyWords[( n * 4) + 2][3];

    myState[3][0] = myState[3][0 ] ^ expandedKeyWords[( n * 4) + 3][0];
    myState[3][1] = myState[3][1 ] ^ expandedKeyWords[( n * 4) + 3][1];
    myState[3][2] = myState[3][2 ] ^ expandedKeyWords[( n * 4) + 3][2];
    myState[3][3] = myState[3][3 ] ^ expandedKeyWords[( n * 4) + 3][3];
}

//initial round for encryption only does addroundkey (round 0)

void initialEncryptRound(BYTE data [4][4]){
    addRoundKey(data,0);
}

void middleEncryptRounds(BYTE data[4][4]){
    for (int n = 1; n <10; n++){
        subBytes(data);
        shiftRows(data);
        mixColumns(data);
        addRoundKey(data, n);
    }
}

//in round 1 to 13 we do subBytes / shift rows/ mixColumns / addRoundkey

void middleEncryptRounds256(BYTE data[4][4]){
    for (int n = 1; n <14; n++){
        subBytes(data);
        shiftRows(data);
        mixColumns(data);
        addRoundKey(data, n);
    }
}

//in the final round we do subBytes/ shiftRows/ addRoundKey (no mix columns)

void finalEncryptRound(BYTE data[4][4]){
    subBytes(data);
    shiftRows(data);
    addRoundKey(data, 10);
}

//in the final round we do subBytes/ shiftRows/ addRoundKey (no mix columns)

void finalEncryptRound256(BYTE data[4][4]){
    subBytes(data);
    shiftRows(data);
    addRoundKey(data, 14);
}

//in the initialDecyptAddRound we do only addRoundKey

void InitialDecryptAddRound(BYTE data[4][4]){
    addRoundKey(data,10);
}


//in the initialDecyptAddRound we do only addRoundKey

void InitialDecryptAddRound256(BYTE data[4][4]){
    addRoundKey(data,14);
}

//in the middleDecryptRound we do inverseShiftRows / inverseSubbytes/ addRoundKey/ inverse mix columns

void middleDecryptRounds(BYTE data [4][4]){
    for (int n = 1; n < 10; n++){
        inverseShiftRows(data);
        inverseSubBytes(data);
        addRoundKey(data, 10 - n);
        invMixColumns(data);  
    }
}

//in the middleDecryptRound we do inverseShiftRows / inverseSubbytes/ addRoundKey/ inverse mix columns


void middleDecryptRounds256(BYTE data [4][4]){
    for (int n = 1; n < 14; n++){
        inverseShiftRows(data);
        inverseSubBytes(data);
        addRoundKey(data, 14 - n);
        invMixColumns(data); 
    }
}


//in the finalDecryptROund we do inverseShiftRows, inerseSubbytes, addRoundKey (no inverseMixColumns)

void finalDecryptRound(BYTE data [4][4]){
    inverseShiftRows(data);
    inverseSubBytes(data);
    addRoundKey(data,0);
}


//pseud random generato isgenerating randomly 255 Bytes. This bytes will be added at the start of every Message
//16 of this bytes will be chosen to be the IV for CBC

void generateRandomIV(BYTE *randIv){
    srand(time(NULL));

    for (int i = 0; i < 255; i++){
        randIv[i]= rand() & 255;
    }
}

//data is zeroed out with 0x00

void zeroData(BYTE *data){
    for (int i = 0; i < 255; i++){
        data[i] = 0x00;
    }
}

//iv is zeroed out

void zeroIv(BYTE iv[4][4]){
    for (int x = 0; x < 4; x++){
        for (int y = 0; y < 4; y++){
            iv[x][y] = 0x00;
        }
    }
}

//from the 255 random bytes we choose 16 to be our IV

void populateIV(BYTE *rIv, BYTE ivec[4][4]){
    ivec[0][0] = rIv[120];
    ivec[0][1] = rIv[240];
    ivec[0][2] = rIv[22];
    ivec[0][3] = rIv[201];
    ivec[1][0] = rIv[2];
    ivec[1][1] = rIv[55];                    
    ivec[1][2] = rIv[131];
    ivec[1][3] = rIv[243];
    ivec[2][0] = rIv[19];
    ivec[2][1] = rIv[31];
    ivec[2][2] = rIv[77];
    ivec[2][3] = rIv[101];
    ivec[3][0] = rIv[204];
    ivec[3][1] = rIv[7];
    ivec[3][2] = rIv[99];
    ivec[3][3] = rIv[152]; 

    for (int x = 0; x < 4; x++){
        for (int y = 0; y < 4; y++){
        }
    }                                       

}

//AES Encrypt with 128 Bit key -----right now not functional , cbc has to be implemented------


int aesEncrypt128(BYTE* dataTE, BYTE* dataENC, int size, BYTE *ivec){
    int dataToEncryptPosition = 0;
    BYTE data [4][4] = {};    
    int numOfRounds = size / 16;
    for (int round = 0; round < numOfRounds; round++){
        for (int i = 0; i < 4; i++){
            for (int j = 0; j < 4; j++){
                data[i][j] = dataTE[(round * 16) + (i * 4) + j];
            }
        }  

        keyExpansion128();
        initialEncryptRound(data);
        middleEncryptRounds(data);
        finalEncryptRound(data);
        
        for (int x = 0; x < 4; x++){
            for (int y = 0; y < 4; y++){
                dataENC[dataToEncryptPosition] = data[x][y];
                dataToEncryptPosition += 1;
            }
        }               
    }  
    return dataToEncryptPosition;
}

//AES Decrypt with 128 Bit key -----right now not functional , cbc has to be implemented------

void aesDecrypt128(BYTE *encrypted, BYTE *decrypted, int size, BYTE *ivec){
    int dataToDecryptPosition = 0;
    int numOfRounds = 0;

    BYTE data [4][4];
    numOfRounds = size / 16;
    for (int round = 0; round < numOfRounds; round ++){
        for (int i = 0; i < 4; i++){
            for (int j = 0; j < 4; j++){
                data[i][j] = encrypted[(round * 16) + (i * 4) + j];
            }
        }
        
        keyExpansion128();
        InitialDecryptAddRound(data);
        middleDecryptRounds(data);
        finalDecryptRound(data); 
        
        for (int x = 0; x < 4; x++){
            for (int y = 0; y < 4; y++){
                decrypted[dataToDecryptPosition] = data[x][y];
                dataToDecryptPosition += 1;
            }
        }                      
    }
}

//AES Encrypt with 256 Bit Key

int aesEncrypt256(BYTE* dataTE, BYTE* dataENC, int size){
    BYTE *randomIV = NULL;
    randomIV = malloc(sizeof(BYTE) * 255); //pseudo random 256 Bit
    zeroData(randomIV); 
    generateRandomIV(randomIV);              
    BYTE iv[4][4] = {};
    zeroIv(iv);    
    populateIV(randomIV, iv); //iv = 16 Bytes chosen from pseudo randomIv
    int dataToEncryptPosition = 0;
    BYTE data [4][4] = {};  
    BYTE previousCypherTextData[4][4] = {};  //in cbc the iv is used the first time to xor , then the last cyphertext is used to xor the data
                                    //this prevents that the same block of data encryted twice will reult in the same cyphertext
    int numOfRounds = size / 16;        //one round = 1 state = 16 Bytes
        for (int i = 0; i < 255; i++){ //put the pseudo random bytes at the begining of the encrypted message
            dataENC[i] = randomIV[i];
            dataToEncryptPosition += 1;
        }    
    for (int round = 0; round < numOfRounds; round++){    //do for every 16 Bytes

        for (int i = 0; i < 4; i++){
            for (int j = 0; j < 4; j++){
                data[i][j] = dataTE[(round * 16) + (i * 4) + j];
            }
        }

        //CBC

        for (int x = 0; x < 4; x++){
            for (int y = 0; y < 4; y++){
                if (round == 0){
                    data[x][y] = data[x][y] ^ iv[x][y];
                } else {
                    data[x][y] = data[x][y] ^ previousCypherTextData[x][y];
                }
            }
        } 

        keyExpansion256();
        initialEncryptRound(data);
        middleEncryptRounds256(data);
        finalEncryptRound256(data);

        

        //write encrypted data to dataENC
        for (int x = 0; x < 4; x++){
            for (int y = 0; y < 4; y++){
                previousCypherTextData[x][y] = data[x][y];
                dataENC[dataToEncryptPosition] = data[x][y];
                dataToEncryptPosition += 1;
            }
        }               
    } 

    //clean up
    for (int x = 0; x < 4; x++){
        for (int y = 0; y < 4 ; y ++){
            previousCypherTextData[x][y] = 0x00;
        }
    }

    zeroData(randomIV);
    free(randomIV); 
    return dataToEncryptPosition;
}

void aesDecrypt256(BYTE *encrypted, BYTE *decrypted, int size){
    BYTE iv[4][4] = {};
    zeroIv(iv); 
    populateIV(encrypted, iv);   //populate iv given the first 255 bytes of cyphertext and choosing 16 of it

    int dataToDecryptPosition = 0;
    int numOfRounds = 0;

    BYTE previousCypherTextData [10][4][4] = {}; //keeping track of previous cypher text for CBC
  

    BYTE data [4][4];
    numOfRounds = size / 16;
    for (int round = 0; round < numOfRounds; round ++){             //for every round of 16 Bytes
        for (int i = 0; i < 4; i++){
            for (int j = 0; j < 4; j++){
                data[i][j] = encrypted[(round * 16) + (i * 4) + j + 255];
            }
        }

        for (int x = 0; x < 4; x++){
            for (int y = 0; y < 4; y++){
                previousCypherTextData[round][x][y] = data[x][y];   //keep track of previous cypherText data (16 Bytes) for CBC
            }
        }

        keyExpansion256();
        InitialDecryptAddRound256(data);
        middleDecryptRounds256(data);
        finalDecryptRound(data); 

        
    //CBC

       for (int x = 0; x < 4; x++){
            for (int y = 0; y < 4; y++){
                if (round == 0){
                    data[x][y] = data[x][y] ^ iv[x][y];
                } else {
                    data[x][y] = data[x][y] ^ previousCypherTextData[round - 1][x][y];
                }
            }
        }
    
    //write decrypted data to decrypted

        for (int x = 0; x < 4; x++){
            for (int y = 0; y < 4; y++){
                decrypted[dataToDecryptPosition] = data[x][y];
                dataToDecryptPosition += 1;
            }
        }                      
    }

    //cleaning up
    for (int r = 0; r < numOfRounds; r++){
        for (int x = 0; x < 4; x++){
            for (int y = 0; y < 4 ; y ++){
                previousCypherTextData[r][x][y] = 0x00;
            }
        }
    }
}


void readDataToEncrypt(BYTE *dte, int* sizeOfData){
    printf("Please enter the phrase you want to encrypt: ");
    scanf( "%[^\n]", dte );
    
    int numOfChars = strlen((const char*)dte) + 1;  // numOf chars = strlen + terminating \0
    int terminatorAtPosition = numOfChars - 1;
    int numOfCharsToFill = 0;
    

    //if numOfChars < 16 add numofCharsToFill times padding
    
    if (numOfChars <= 16){          
        numOfCharsToFill = 16 - numOfChars;
    } else {
        numOfCharsToFill = 16 -  ((numOfChars - ((int)numOfChars / 16) * 16));
    }

    //add padding
    if (numOfCharsToFill > 0){
        for (int i = 0; i < numOfCharsToFill; i++){
            int position = numOfChars + i;
            dte[position] = 0x00;
        }
    }
    numOfChars += numOfCharsToFill;
    *sizeOfData =  numOfChars;              //size of data in message (including padding, it is always a multiple of 16 Bytes)
}

//This was a test with fixed plaintext
void generateTestPlainText(BYTE *dte, int *sizeOfData){
    char* myTestString = "Hallo Lieber Björn, wie arbeitest Du heute ?";
    for (int i = 0; i < strlen(myTestString); i++){
        dte[i] = (BYTE)myTestString[i];
    }

    int numOfChars = strlen((const char*)dte) + 1;  // numOf chars = strlen + terminating \0
    int terminatorAtPosition = numOfChars - 1;
    int numOfCharsToFill = 0;
    

    //if numOfChars < 16 add numofCharsToFill times padding
    
    if (numOfChars <= 16){          
        numOfCharsToFill = 16 - numOfChars;
    } else {
        numOfCharsToFill = 16 -  ((numOfChars - ((int)numOfChars / 16) * 16));
    }

    //add padding
    if (numOfCharsToFill > 0){
        for (int i = 0; i < numOfCharsToFill; i++){
            int position = numOfChars + i;
            dte[position] = 0x00;
        }
    }
    numOfChars += numOfCharsToFill;
    *sizeOfData =  numOfChars;         
}


void testAES(){
    BYTE *plainData = NULL;
    BYTE *encryptedData = NULL;
    BYTE *decryptedData = NULL;

    plainData = malloc (sizeof(BYTE) * blockSize);
    encryptedData = malloc(sizeof(BYTE) * blockSize);
    decryptedData = malloc(sizeof(BYTE) * blockSize);

    zeroData(plainData);  //initialize plainData with 0x00's
    zeroData(encryptedData); //initialize encrypted with 0x00's
    zeroData(decryptedData); //initialize decrypted with 0x00's

    int sizeOfdata = 0; 
    
    printf("\n\n");
    readDataToEncrypt(plainData, &sizeOfdata); 
    printf("\n\n");

    aesEncrypt256(plainData, encryptedData, sizeOfdata);  
    zeroData(plainData); //clear the plaindata to 0x00's

    printf("The ENCRYPTED Data is : ");
    printf("%s\n\n\n", encryptedData); // As  CBC is used with a random initial initalization vector, the encrypted data differs every time, even with the same plaintext
    printf("(THIS OBVIOUSLY WILL SHOW RUBISH AS NOT ALL BYTES THAT MAKE UP THE CYPHERTEXT ARE IN THE ASCI TABLE) it also will be different every time even with te same plaintext as cbc is used with random iv\n\n\n");

    aesDecrypt256(encryptedData, decryptedData, sizeOfdata);
    zeroData(encryptedData);

    printf("The DECRYPTED data is: %s\n", decryptedData);
    zeroData(decryptedData);
    
    free(plainData);
    free(encryptedData);
    free(decryptedData);
}

  
int main(int argc, char** argv){
    testAES();
    return 0;
}