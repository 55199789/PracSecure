#ifndef _SHAMIR_Z
#define _SHAMIR_Z
#include <vector>
#define Bytes std::vector<byte>
std::vector<Bytes> SecretShareBytes(const Bytes& secret, \
                                int threshold, int nShares);
Bytes SecretRecoverBytes(std::vector<Bytes>& shares, \
                        int threshold);
#endif