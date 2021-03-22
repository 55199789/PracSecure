#ifndef MASK__Z
#define MASK__Z
#include "client.h"
#include <crypto++/aes.h>
#include <crypto++/modes.h>
void generateVectorWithSeed(std::vector<DATATYPE>& vec, \
                        const CryptoPP::SecByteBlock &seed, \
                        const int delta = 1);
#endif