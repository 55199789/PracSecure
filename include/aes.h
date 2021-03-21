#ifndef AES__Z
#define AES__Z
#include <crypto++/eccrypto.h>
void AES_GCM_en(const CryptoPP::SecByteBlock &key, \
                const byte *in, \
                byte *out, size_t len);
                
void AES_GCM_de(const CryptoPP::SecByteBlock &key, \
                const byte *in, \
                byte *out, size_t len);
#endif