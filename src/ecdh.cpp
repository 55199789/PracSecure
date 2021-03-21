#include <stdio.h>
#include <crypto++/eccrypto.h>
#include <crypto++/osrng.h>
#include <crypto++/oids.h>
#include "ecdh.h"
using namespace CryptoPP;
static OID CURVE = ASN1::secp256r1();
static AutoSeededRandomPool rng;
static ECDH<ECP>::Domain dh(CURVE);
void ecdh_getKeyPairs(KeyPair &kp) {
    kp.privKey = new SecByteBlock(dh.PrivateKeyLength());
    kp.pubKey = new SecByteBlock(dh.PublicKeyLength());
    dh.GenerateKeyPair(rng, *kp.privKey, *kp.pubKey);
}

SecByteBlock *key_agreement(
            const SecByteBlock *privKeyA, \
            const SecByteBlock *pubKeyB) {
    SecByteBlock *key = \
            new SecByteBlock(dh.AgreedValueLength());
    if(!dh.Agree(*key, *privKeyA, *pubKeyB)) {
        printf("Failed to reach the shared key!\n");
        return 0;
    }
    return key;
}