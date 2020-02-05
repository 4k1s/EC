#include <string>
#include <iostream>

#include <cryptopp/osrng.h>
#include <cryptopp/eccrypto.h>
#include <cryptopp/ecp.h>
#include <cryptopp/integer.h>
#include <cryptopp/ecp.h>

/* ECC over prime p (ECP) and Schnorr aggregating signing functions */

namespace Schnorr {
  
  class ECC {
  private:
    static const size_t SECRET_KEY_SIZE = 32;
    static const size_t SIGNATURE_SIZE = 32;

    bool secretKeySet;
    bool publicKeySet;

    CryptoPP::ECP ec;
    CryptoPP::ECPPoint G;
    CryptoPP::Integer q;
    CryptoPP::AutoSeededRandomPool rng;

    CryptoPP::Integer secretKey;
    /* public key Q */
    CryptoPP::ECPPoint Q;

    CryptoPP::Integer HashPointMessage(const CryptoPP::ECPPoint& R, const byte* message, int mlen);
    
    void PrintInteger(CryptoPP::Integer i);

  public:
    ECC();

    ~ECC();

    bool HasPrivateKey();
    bool HasPublicKey();

    bool GenerateSecretKey();
    bool GeneratePublicKey();
    bool GenerateKeys();

    /* vch: vector unsigned char */
    bool SetVchPublicKey(std::vector<unsigned char> vchPubKey);
    bool GetVchPublicKey(std::vector<unsigned char>& vchPubKey);
    
    bool SetVchSecretKey(std::vector<unsigned char> vchSecret);
    bool GetVchSecretKey(std::vector<unsigned char>& vchSecret);

    bool GetSignatureFromVch(std::vector<unsigned char> vchSig, CryptoPP::Integer& sigE, CryptoPP::Integer& sigS);
    bool GetVchFromSignature(std::vector<unsigned char>& vchSig, CryptoPP::Integer sigE, CryptoPP::Integer sigS);

    CryptoPP::Integer GetPublicKeyX();
    CryptoPP::Integer GetPublicKeyY();
    CryptoPP::Integer GetSecretKey();

    void ModuloAddToHex(CryptoPP::Integer k, CryptoPP::Integer iL, std::vector<unsigned char>& dataBytes);
    void GetVchPointMultiplyAdd(CryptoPP::Integer iL, std::vector<unsigned char>& dataBytes);
    
    bool Sign(std::vector<unsigned char> vchHash, std::vector<unsigned char>& vchSig);
    bool Verify(std::vector<unsigned char> vchHash, std::vector<unsigned char> vchSig);
  };
}
