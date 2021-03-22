# Practical Secure Aggregation 
An implementation of Secure Aggregation algorithm based 
on "[Practical Secure Aggregation for Privacy-Preserving Machine Learning 
(Bonawitz et. al)](https://dl.acm.org/doi/pdf/10.1145/3133956.3133982)" 
in C++.

We omit the communication part, only implement the computation part.
## Prerequisites
* Ensure [Crypto++](https://www.cryptopp.com/) is installed
```
sudo apt-get install libcrypto++-dev libcrypto++-doc libcrypto++-utils
```
* Download the source code
```
git clone https://github.com/55199789/PracSecure.git
```
## Run
* Enter the following code
```
cd PracSecure && make
./app <clientNum> <vectorDim> <survRate>
```
