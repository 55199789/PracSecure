#include <stdio.h>
#include <string.h>
#include <algorithm> 
#include <chrono>
#include <crypto++/eccrypto.h>
#include <crypto++/osrng.h>
#include <numeric>
#include "aes.h"
#include "client.h"
#include "ecdh.h"
#include "mask.h"
#include "shamir.h"
static void word2bytes(const CryptoPP::word32 &x, \
                Bytes &dst) {
    dst[0] = (x >> 24) & 0xFF;
    dst[1] = (x >> 16) & 0xFF;
    dst[2] = (x >> 8) & 0xFF;
    dst[3] = x & 0xFF;
}

double gettime(const char *name="\0", int is_end=false) {
    static std::chrono::time_point<std::chrono::high_resolution_clock> \
                            begin_time, end_time;
    static bool begin_done = false;
    if (!is_end) {
        begin_done = true;
        begin_time = std::chrono::high_resolution_clock::now();
    } else if (!begin_done) {
        printf("NOTE: begin time is not set, so elapsed time is not printed!\n");
    } else {
        end_time = std::chrono::high_resolution_clock::now();
        std::chrono::duration<double> elapsed = end_time - begin_time;
            printf("%s Time elapsed: %fs\n\n", name, elapsed.count());
        return elapsed.count();
    }
    return 0;
}


int main(int argc, char *argv[]) {
    if(argc!=4) {
        printf("Usage: ./app clientNum dim dropRate\n");
        return 0;
    }
    const int clientNum = atoi(argv[1]);
    const int dim = atoi(argv[2]);
    const double dropRate = atof(argv[3]);
    const int threshold = 2*clientNum / 3 + 1;
    Client clients[clientNum];
    std::vector<DATATYPE> final_x(dim, 0);
    CryptoPP::AutoSeededRandomPool rng;
    // Generate x
    for(int i=0;i<clientNum;i++) {
        clients[i].x.resize(dim);
        for(int j=0;j<dim;j++) {
            rng.GenerateBlock( \
                (byte*)&(clients[i].x[j]), 
                sizeof(DATATYPE)-1);
            final_x[j]+=clients[i].x[j];
        }
    }

    for(int i=0;i<clientNum;i++) {
        ecdh_getKeyPairs(clients[i].ckeyPairs);
        ecdh_getKeyPairs(clients[i].skeyPairs);
    }
    printf("AdvertiseKeys completed!\n");

    printf("Threshold: %d, Total number: %d\n", \
                threshold, clientNum);
    for(int i=0;i<clientNum;i++) {
        auto &it = clients[i];
        // Generate b_u
        it.bu = rng.GenerateWord32();
        // Generate t-out-of-|U1| share of s_u^{sk}
        Bytes secret_s(it.skeyPairs.privKey->begin(), \
                    it.skeyPairs.privKey->end());
        it.shares_s = SecretShareBytes(secret_s, \
                threshold, clientNum);
        // Generate t-out-of-|U1| share of b_u
        Bytes secret_b(4);
        word2bytes(it.bu, secret_b);
        it.shares_b = SecretShareBytes(secret_b, \
                threshold, clientNum);
        // Compute e_{u, v}
        it.ckeys.resize(clientNum);
        it.e.resize(clientNum);
        for(int j=0;j<clientNum;j++)
            if(i!=j) {
                it.ckeys[j] = key_agreement(it.ckeyPairs.privKey, \
                    clients[j].ckeyPairs.pubKey);
                const size_t s_len = sizeof(int)*2 + \
                        it.shares_s[j].size() + \
                        it.shares_b[j].size();
                byte *in = new byte[s_len];
                byte *out = new byte[s_len];
                memcpy(in, &i, sizeof(int));
                memcpy(in+sizeof(int), &j, sizeof(int));
                memcpy(in+sizeof(int)*2, it.shares_s[j].data(), \
                        it.shares_s[j].size());
                memcpy(in+sizeof(int)*2+it.shares_s[j].size(), \
                        it.shares_b[j].data(), \
                        it.shares_b[j].size());
                AES_GCM_en(*it.ckeys[j], in, out, s_len);
                it.e[j].assign(out, out + s_len);
                delete[] out;
                delete[] in;
            }
    }
    printf("ShareKeys completed!\n");

    for(int i=0;i<clientNum;i++) {
        auto &it = clients[i];
        it.skeys.resize(clientNum);
        it.pu.resize(dim);
        generateVectorWithSeed(it.pu, it.bu);
        for(int k=0;k<dim;k++) 
            it.y[k] = it.x[k] + it.pu[k];
        for(int j=0;j<clientNum;j++)
            if(i!=j) {
                it.skeys[j] = key_agreement(it.skeyPairs.privKey, \
                        clients[j].skeyPairs.pubKey);
                const int delta = i<j?-1:1;
                it.puv[j].resize(dim);
                generateVectorWithSeed(it.puv[j], \
                                    *it.skeys[j], \
                                    i<j?-1:1);
                for(int k=0;k<clientNum;k++)
                    it.y[k]+=it.puv[j][k];
            }
    }
    printf("MaskedInputCollection completed!\n");

    std::vector<int> ids(clientNum);
    std::iota(ids.begin(), ids.end(), 0);
    std::random_shuffle(ids.begin(), ids.end());
    const int survNum = clientNum*dropRate;
    std::vector<int> survival(ids.begin(), \
                    ids.begin() + survNum);
    std::sort(survival.begin(), survival.end());
    // Bytes recSecret = SecretRecoverBytes(shares, threshold);
    // for(auto i=recSecret.begin();i!=recSecret.end();i++) 
    //     printf("%02x", *i);
    // printf("\n");
}