#ifndef MASK__Z
#define MASK__Z
#include "client.h"

void generateVectorWithSeed(std::vector<DATATYPE>&, \
                        const CryptoPP::word32&);
void generateVectorWithSeed(std::vector<DATATYPE>& vec, \
                        const CryptoPP::SecByteBlock &seed, \
                        const int delta) {
#endif