#include <openssl/evp.h>
#include <openssl/ec.h>
#include "ecdh.h"
static EVP_PKEY *ECDH_client() {
    EVP_PKEY_CTX *pctx, *kctx;
	EVP_PKEY *params = NULL, *pkey=NULL;
	if(NULL == (pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL))) {
        printf("Context ID creation failed in client\n");
        return 0;
    }

	if(1 != EVP_PKEY_paramgen_init(pctx)) {
        printf("Parameters initialization failed in client\n");
        return 0;
    }

	if(1 != EVP_PKEY_CTX_set_ec_paramgen_curve_nid(\
                pctx, NID_X9_62_prime256v1)) {
        printf("EC parameter setting failed in client\n");
        return 0;
    }

	if (!EVP_PKEY_paramgen(pctx, &params)) {
        printf("Public key generation failed in client\n");
        return 0;
    }

	if(NULL == (kctx = EVP_PKEY_CTX_new(params, NULL))) {
        printf("Context creation failed in clientn");
        return 0;
    }

	if(1 != EVP_PKEY_keygen_init(kctx)) {
        printf("Key generation initialization failed in clientn");
        return 0;
    }

	if (1 != EVP_PKEY_keygen(kctx, &pkey)) {
        printf("Key generation failed in client\n");
        return 0;
    }
	EVP_PKEY_CTX_free(kctx);
	EVP_PKEY_free(params);
	EVP_PKEY_CTX_free(pctx);
    return pkey;
}

unsigned char *ECDH(size_t *keyLen) {
    EVP_PKEY_CTX *pctx, *kctx;
	EVP_PKEY_CTX *ctx;
	unsigned char *secret;
	EVP_PKEY *pkey = NULL, *peerkey, *params = NULL;
    *keyLen = 0;
	if(NULL == (pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL))) {
        printf("Context ID creation failed\n");
        return 0;
    }
	if(1 != EVP_PKEY_paramgen_init(pctx)) {
        printf("Parameters initialization failed\n");
        return 0;
    }
	if(1 != EVP_PKEY_CTX_set_ec_paramgen_curve_nid(\
                pctx, NID_X9_62_prime256v1)) {
        printf("EC parameter setting failed\n");
        return 0;
    }
	if (!EVP_PKEY_paramgen(pctx, &params)) {
        printf("Public key generation failed\n");
        return 0;
    }
	if(NULL == (kctx = EVP_PKEY_CTX_new(params, NULL))) {
        printf("Context creation failed\n");
        return 0;
    }
	if(1 != EVP_PKEY_keygen_init(kctx)) {
        printf("Key generation initialization failed\n");
        return 0;
    }
	if (1 != EVP_PKEY_keygen(kctx, &pkey)) {
        printf("Key generation failed\n");
        return 0;
    }
    size_t privKeyLen = 0, pubKeyLen = 0;
    printf("%d\n", EVP_PKEY_get_raw_private_key(pkey, NULL, &privKeyLen));
    EVP_PKEY_get_raw_public_key(pkey, NULL, &pubKeyLen);
    printf("Private key Len: %d, Public Key Len: %d\n", 
        privKeyLen, pubKeyLen);
    // unsigned char *privKey = (unsigned char *)\
    //             OPENSSL_malloc(privKeyLen);
    // EVP_PKEY_get_raw_private_key(pkey, privKey, &privKeyLen);

	// peerkey = ECDH_client();
	// if(NULL == (ctx = EVP_PKEY_CTX_new(pkey, NULL))) {
    //     printf("Key context new failed\n");
    //     return 0;
    // }
    
	// if(1 != EVP_PKEY_derive_init(ctx)) {
    //     printf("Key initialization failed\n");
    //     return 0;
    // }

	// if(1 != EVP_PKEY_derive_set_peer(ctx, peerkey))  {
    //     printf("Key peer key setting failed\n");
    //     return 0;
    // }

	// if(1 != EVP_PKEY_derive(ctx, NULL, keyLen))  {
    //     printf("Key length setting failed\n");
    //     return 0;
    // }

	// if(NULL == (secret = (unsigned char *)\
    //                     OPENSSL_malloc(*keyLen))) {
    //     printf("Key memeory allocation failed\n");
    //     return 0;
    // }

	// if(1 != (EVP_PKEY_derive(ctx, secret, keyLen))) {
    //     printf("Secret generation failed\n");
    //     return 0;
    // }

	EVP_PKEY_CTX_free(ctx);
	EVP_PKEY_free(peerkey);
	EVP_PKEY_free(pkey);
	EVP_PKEY_CTX_free(kctx);
	EVP_PKEY_free(params);
	EVP_PKEY_CTX_free(pctx);

	return secret;
}