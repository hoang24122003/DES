#include "des.h"

uint64_t permutation(uint64_t input, int length, int table_size, int table[])
{
    uint64_t a = 0;
    for (int i = 0; i < length; i++)
    {
        a <<= 1;
        a |= (input >> (table_size-table[i])) & 0x1;
    }
    return a;
}

uint64_t des(uint64_t plaintext, uint64_t key) 
{    
    int i, j;    
    uint64_t sub_key[16] = {0};

    /* initial permutation */
    uint64_t L = (permutation(plaintext, 64, 64, IP) >> 32) & 0xffffffff;
    uint64_t R = permutation(plaintext, 64, 64, IP) & 0xffffffff;
        
    /* key generation */
    uint64_t C = (permutation(key, 56, 64, PC1) >> 28) & 0xfffffff;
    uint64_t D = permutation(key, 56, 64, PC1) & 0xfffffff;
    for (i = 0; i< 16; i++) 
    {
        for (j = 0; j < shift[i]; j++) 
        {    
            C = 0xfffffff & (C << 1) | 0x1 & (C >> 27);
            D = 0xfffffff & (D << 1) | 0x1 & (D >> 27);    
        }
        sub_key[i] = permutation(C << 28 | D , 48, 56, PC2);    
    }
    
    /* single round */
    for (i = 0; i < 16; i++) {
        /* expansion/permutation + XOR */
        uint64_t input = permutation(R, 48, 32, E) ^ sub_key[i];   
        
        /* subtitution function */
        uint64_t output= 0;
        for (j = 0; j < 8; j++) 
        {    
            int row = (input & (0x840000000000 >> 6*j)) >> 42-6*j;
            row = (row >> 4) | row & 0x01;
            
            int column = (input & (0x780000000000 >> 6*j)) >> 43-6*j;
            
            output <<= 4;
            output |= S[j][16*row + column] & 0xf;    
        }
                
        /* permutation + input for next round*/
        uint64_t temp = R;
        R = L ^ permutation(output, 32, 32, P);
        L = temp;    
    }
    
    /* preoutput + inverse initial permutation */    
    return permutation(R << 32 | L, 64, 64, PI);    
}

int main()
{  
    uint64_t plaintext = 0x02468aceeca86420;
    uint64_t key = 0x0f1571c947d9e859;
    uint64_t result = des(plaintext, key);
    printf ("Plaintext : %016llx\n", plaintext );
    printf ("Key       : %016llx\n", key);
    printf ("Ciphertext: %016llx\n", result);
}