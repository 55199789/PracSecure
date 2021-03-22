#include <crypto++/aes.h>
#include <crypto++/modes.h>
#include "mask.h"
using namespace std;
using namespace CryptoPP;
static const int vec_l = sizeof(DATATYPE)-1==0?1:sizeof(DATATYPE)-1;

void generateVectorWithSeed(vector<DATATYPE>& vec, \
                        const CryptoPP::SecByteBlock &seed, \
                        const int delta) {
    const size_t len = vec.size();
    CTR_Mode<AES>::Encryption rng;
    CryptoPP::SecByteBlock new_seed(48);
    if(seed.size()<48) {
        for(int i=0;i<48/seed.size();i++) 
            memcpy(new_seed.data() + i*seed.size(), seed.data(), seed.size());
        if(48%seed.size())
            memcpy(new_seed.data() + 48/seed.size() * seed.size(), seed.data(), \
                    48 - 48/seed.size() * seed.size());
        rng.SetKeyWithIV(new_seed, 32, new_seed+32, 16);
    }
    else rng.SetKeyWithIV(seed, 32, seed+32, 16);
    for(int i=0;i<len;i++) {
        rng.GenerateBlock((byte*)&vec[i], \
            vec_l);
        vec[i]*=delta;
    }
}