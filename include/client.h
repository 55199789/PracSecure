#ifndef APP_Z
#define APP_Z
#include<vector>
#include"ecdh.h"
#include"shamir.h"
#define DATATYPE int32_t
struct Client {
    KeyPair ckeyPairs, skeyPairs;
    CryptoPP::word32 bu;
    std::vector<Bytes> shares_s, shares_b, e;
    std::vector<CryptoPP::SecByteBlock*> ckeys, skeys;
    std::vector<DATATYPE> x, pu, y;
    // std::vector<std::vector<DATATYPE> > puv;
};

#endif