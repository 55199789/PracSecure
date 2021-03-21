#include<crypto++/aes.h>
#include<crypto++/gcm.h>
#include "aes.h"
using namespace CryptoPP;

static SecByteBlock iv(AES::BLOCKSIZE);
void AES_GCM_en(const SecByteBlock &key, \
                const byte *in, \
                byte *out, size_t len) {
    memset(iv.data(), 0, sizeof(byte)*AES::BLOCKSIZE);
    GCM<AES>::Encryption gcmEn;
    gcmEn.SetKeyWithIV(key, key.size(), iv, iv.size());
    gcmEn.ProcessData(out, in, len);
}

void AES_GCM_de(const SecByteBlock &key, \
                const byte *in, \
                byte *out, size_t len) {
    memset(iv.data(), 0, sizeof(byte)*AES::BLOCKSIZE);
    GCM<AES>::Decryption gcmDe;
    gcmDe.SetKeyWithIV(key, key.size(), iv, iv.size());
    gcmDe.ProcessData(out, in, len);
}