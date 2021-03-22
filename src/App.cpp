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

static void bytes2word(const Bytes &dst, \
                CryptoPP::word32 &x) {
    x = 0;
    x |= dst[0]<<24; 
    x |= dst[1]<<16;
    x |= dst[2]<<8;
    x |= dst[3];
}

double gettime(int is_end=false) {
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
            // printf("%s Time elapsed: %fs\n\n", name, elapsed.count());
        return elapsed.count()*1000;
    }
    return 0;
}


int main(int argc, char *argv[]) {
    if(argc!=4) {
        printf("Usage: ./app clientNum vectorDim \
            survRate\n");
        return 0;
    }
    const int clientNum = atoi(argv[1]);
    const int dim = atoi(argv[2]);
    const double dropRate = atof(argv[3]);
    // const int threshold = clientNum / 2 + 1;
    const int threshold = 2*clientNum / 3 + 1;
    double t_adv[clientNum] = {0}, \
            t_shareKeys[clientNum] = {0}, \
            t_masks[clientNum] = {0}, \
            t_unmasking[clientNum] = {0};
    double T_shareKeys, T_masks, T_unmasking;
    Client *clients = new Client[clientNum];
    std::vector<DATATYPE> final_x(dim, 0);
    CryptoPP::AutoSeededRandomPool rng;
    // Generate x
    for(int i=0;i<clientNum;i++) {
        clients[i].x.resize(dim);
        for(int j=0;j<dim;j++)
            rng.GenerateBlock( \
                (byte*)&(clients[i].x[j]), 
                sizeof(DATATYPE)-1);
    }

    for(int i=0;i<clientNum;i++) {
        gettime();
        ecdh_getKeyPairs(clients[i].ckeyPairs);
        ecdh_getKeyPairs(clients[i].skeyPairs);
        t_adv[i] = gettime(1);
    }
    printf("AdvertiseKeys completed!\n");

    printf("Threshold: %d, Total number: %d\n", \
                threshold, clientNum);
    for(int i=0;i<clientNum;i++) {
        gettime();
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
        const size_t s_len = sizeof(int)*2 + \
                it.shares_s[0].size() + \
                it.shares_b[0].size();
        byte *in = new byte[s_len];
        byte *out = new byte[s_len];
        for(int j=0;j<clientNum;j++)
            if(i!=j) {
                it.ckeys[j] = key_agreement(it.ckeyPairs.privKey, \
                    clients[j].ckeyPairs.pubKey);
                memcpy(in, &i, sizeof(int));
                memcpy(in+sizeof(int), &j, sizeof(int));
                memcpy(in+sizeof(int)*2, it.shares_s[j].data(), \
                        it.shares_s[j].size());
                memcpy(in+sizeof(int)*2+it.shares_s[j].size(), \
                        it.shares_b[j].data(), \
                        it.shares_b[j].size());
                AES_GCM_en(*it.ckeys[j], in, out, s_len);
                it.e[j].assign(out, out + s_len);
            }
            delete[] out;
            delete[] in;
        t_shareKeys[i] = gettime(1);
    }
    {
    gettime();
    std::vector<std::vector<Bytes> > e_server(clientNum);
    for(int i=0;i<clientNum;i++)e_server[i] = clients[i].e;
    T_shareKeys = gettime(1);
    printf("ShareKeys completed!\n");
    }

    std::vector<int> ids(clientNum);
    std::iota(ids.begin(), ids.end(), 0);
    srand(time(NULL));
    std::random_shuffle(ids.begin(), ids.end());
    const int survNum = clientNum*dropRate;
    std::vector<int> survival(ids.begin(), \
                    ids.begin() + survNum);
    std::vector<int> drops(ids.begin()+survNum, \
                    ids.end());
    std::sort(survival.begin(), survival.end());
    std::sort(drops.begin(), drops.end());

    for(auto i:survival) {
        auto &it = clients[i];
        for(int j=0;j<dim;j++)
            final_x[j]+=it.x[j];
    }

    for(auto i:survival) {
        gettime();
        auto &it = clients[i];
        it.skeys.resize(clientNum);
        it.pu.resize(dim);
        it.y.resize(dim);
        Bytes buBytes(4);
        word2bytes(it.bu, buBytes);
        CryptoPP::SecByteBlock bu_sec((byte*)buBytes.data(), \
                    sizeof(it.bu));
        generateVectorWithSeed(it.pu, bu_sec);
        for(int k=0;k<dim;k++)
            it.y[k] = it.x[k] + it.pu[k];
        std::vector<DATATYPE> puv(dim);
        for(int j=0;j<clientNum;j++)
            if(i!=j) {
                it.skeys[j] = key_agreement(it.skeyPairs.privKey, \
                        clients[j].skeyPairs.pubKey);
                memset(puv.data(), 0, sizeof(DATATYPE)*dim);
                generateVectorWithSeed(puv, \
                                    *it.skeys[j], \
                                    i<j?-1:1);
                for(int k=0;k<dim;k++)
                    it.y[k] += puv[k];
            }
        t_masks[i] = gettime(1);
    }
    {
    gettime();
    std::vector<std::vector<DATATYPE> >  y_server(clientNum);
    for(int i=0;i<clientNum;i++) y_server[i] = clients[i].y;
    T_masks = gettime(1);
    printf("MaskedInputCollection completed!\n");
    }
    
    for(int i=0;i<clientNum;i++) {
        gettime();
        auto &it = clients[i];
        for(int j=0;j<clientNum;j++)
            if(i!=j) {
                CryptoPP::SecByteBlock *ckey = \
                    it.ckeys[j];
                const size_t s_len = sizeof(int)*2 + \
                        it.shares_s[j].size() + \
                        it.shares_b[j].size();
                byte out[s_len];
                AES_GCM_de(*ckey, clients[j].e[i].data(), \
                    out, s_len);
                int v_, u_;
                memcpy(&v_, out, sizeof(int));
                memcpy(&u_, out + sizeof(int), sizeof(int));    
                if(i!=u_ || j!=v_) {
                    printf("Error!!!\n");
                    return 0;
                }            
            }
        t_unmasking[i] = gettime(1);
    }
    printf("Unmasking validation completed!\n");

    gettime();
    std::vector<DATATYPE> z(dim, 0);
    for(auto i:survival) {
        auto &it = clients[i];
        std::vector<Bytes> shares(survNum, Bytes(4));
        for(int j=0;j<survNum;j++) 
            shares[j] = std::move(it.shares_b[j]);
            // shares[j] = it.shares_b[j];
        CryptoPP::SecByteBlock recSecret = SecretRecoverBytes(shares, \
                            threshold);
        std::vector<DATATYPE> pu(dim);
        generateVectorWithSeed(pu, recSecret);
        for(int j=0;j<dim;j++) 
            z[j] += it.y[j] - pu[j];
    }
    T_unmasking = gettime(1);
    printf("Recovering pu completed!\n");

    gettime();
    for(auto i:drops) {
        auto &it = clients[i];
        std::vector<Bytes> shares(survNum);
        for(int j=0;j<survNum;j++)
            shares[j] = std::move(it.shares_s[survival[j]]);
        CryptoPP::SecByteBlock recSecret = SecretRecoverBytes(shares, \
                            threshold);
        std::vector<std::vector<DATATYPE> > pvu(dim);
        for(auto j:survival) {
            pvu[j].resize(dim);
            CryptoPP::SecByteBlock *s_uv= \
                    key_agreement(&recSecret, clients[j].skeyPairs.pubKey);
            generateVectorWithSeed(pvu[j], *s_uv, i<j?-1:1);
            for(int k=0;k<dim;k++)
                // z[k] -= clients[j].puv[i][k];
                z[k] += pvu[j][k];
        }
    }
    T_unmasking += gettime(1);
    printf("Aggregation completed!\n");

    for(int k=0;k<dim;k++){
        if(z[k]!=final_x[k]) {
            printf("Error\n");
            printf("%d: %d %d\n", k, z[k], final_x[k]);
            return 0;
        }
    }
    printf("Testing passed!\n");

    double t_shareKeys_avg = 0, \
            t_adv_avg = 0, \
            t_masks_avg = 0, \
            t_unmasking_avg = 0;
    for(auto i:t_adv) t_adv_avg += i;
    t_adv_avg /= clientNum;
    for(auto i:t_shareKeys) t_shareKeys_avg += i;
    t_shareKeys_avg /= clientNum;
    for(auto i:t_masks) t_masks_avg += i;
    t_masks_avg /= survNum;
    for(auto i:t_unmasking) t_unmasking_avg += i;
    t_unmasking_avg /= clientNum;

    printf("\t AdvertiseKeys\t ShareKyes\t Masking\t Unmasking\t Total\n");
    printf("Client\t%fms\t%fms\t%fms\t%fms\t%fms\n", t_adv_avg, \
            t_shareKeys_avg, t_masks_avg, t_unmasking_avg, \
            t_adv_avg + t_shareKeys_avg + 
            t_masks_avg + t_unmasking_avg);
    printf("Server\t%fms\t%fms\t%fms\t%fms\t%fms\n", 1.0, T_shareKeys, \
            T_masks, T_unmasking, \
            T_shareKeys + T_masks + T_unmasking + 1.0);
}