#include <crypto++/osrng.h>
#include "mask.h"
using namespace std;
using namespace CryptoPP;

void generateVectorWithSeed(vector<DATATYPE>& vec, \
                        const word32 &seed) {
    const size_t len = vec.size();
    RandomPool rng;
    rng.IncorporateEntropy((byte*)seed, \
                    sizeof(word32));
    for(int i=0;i<len;i++)
        rng.GenerateBlock((byte*)&vec[i], \
            sizeof(DATATYPE)-1);
}

void generateVectorWithSeed(vector<DATATYPE>& vec, \
                        const CryptoPP::SecByteBlock &seed, \
                        const int delta) {
    const size_t len = vec.size();
    RandomPool rng;
    rng.IncorporateEntropy(seed, \
                    seed.size());
    for(int i=0;i<len;i++) {
        rng.GenerateBlock((byte*)&vec[i], \
            sizeof(DATATYPE)-1);
        vec[i]*=delta;
    }
}