#include <string>
#include <sstream>
#include <crypto++/osrng.h>
#include <crypto++/channels.h>
#include <crypto++/files.h>
#include <crypto++/ida.h>
#include "shamir.h"
using namespace std;
using namespace CryptoPP;
vector<Bytes> SecretShareBytes(const Bytes& secret, \
                                int threshold, int nShares) {
	AutoSeededRandomPool rng;
	ChannelSwitch *channelSwitch;
	ArraySource source(secret.data(), secret.size(), false, \
                    new SecretSharing(rng, threshold, nShares, \
                            channelSwitch = new ChannelSwitch));
    vector<ostringstream> shares(nShares);
    vector_member_ptrs<FileSink> sinks(nShares);
    std::string channel;
    for (int i = 0; i < nShares; i++) {
        sinks[i].reset(new FileSink(shares[i]));

        channel = WordToString<word32>(i);
        sinks[i]->Put((byte *)channel.data(), 4);
        channelSwitch->AddRoute( channel,*sinks[i], DEFAULT_CHANNEL);
    }
    source.PumpAll();

    vector<Bytes> ret;
    for (const auto &share : shares) {
        const auto &piece = share.str();
        ret.push_back(Bytes(piece.begin(), piece.begin() + piece.size()));
    }
    return move(ret);
}

Bytes SecretRecoverBytes(vector<Bytes>& shares, int threshold) {
    if(threshold>shares.size()) {
        printf("Partial secret too few... Failed to recover!\n");
        return Bytes();
    }
    ostringstream out;
    SecretRecovery recovery( threshold, new FileSink(out));

    SecByteBlock channel(4);
    for (int i = 0; i < threshold; i++) {
        ArraySource arraySource(shares[i].data(), shares[i].size(), false);

        arraySource.Pump(4);
        arraySource.Get(channel, 4 );
        arraySource.Attach(new ChannelSwitch( recovery, \
                        string((char *)channel.begin(), 4)));

        arraySource.PumpAll();
    }
    const auto & secret = out.str();
    return Bytes(secret.begin(), secret.begin() + secret.size());
}