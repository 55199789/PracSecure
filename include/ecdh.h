#ifndef ECHD__Z
#define ECHD__Z
#include <crypto++/eccrypto.h>
struct KeyPair {
    CryptoPP::SecByteBlock *privKey, *pubKey;
    KeyPair():privKey(0),pubKey(0) {}
    ~KeyPair() {
        if(privKey)delete privKey;
        if(pubKey)delete pubKey;
    }
};

void ecdh_getKeyPairs(KeyPair &kp);

CryptoPP::SecByteBlock *key_agreement( \
            const CryptoPP::SecByteBlock *pubKeyA, \
            const CryptoPP::SecByteBlock *pubKeyB);
#endif