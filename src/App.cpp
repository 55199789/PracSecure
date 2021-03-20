#include <stdio.h>
#include <string.h>
#include <openssl/crypto.h>
#include "ecdh.h"

int main(int argc, char *argv[]) {
    if(argc!=4) {
        printf("Usage: ./app clientNum dim dropRate\n");
        return 0;
    }
    const int clientNum = atoi(argv[1]);
    const int dim = atoi(argv[2]);
    const double dropRate = atof(argv[3]);
    size_t skLens[clientNum];
    unsigned char *keys[clientNum]; 
    for(int i=0;i<clientNum;i++) {
        keys[i] = ECDH(skLens+i);
        // for(int j=0;j<skLens[i];j++) 
        //     printf("%02x", keys[i][j]);
        // printf("\n");
    }
    printf("AdvertiseKeys completed!\n");

    for(int i=0;i<clientNum;i++)
        OPENSSL_free(keys[i]);
}