#include <cryptopp/keccak.h>
#include "schnorr.h"

#include <iostream>
#include <sstream>
#include <string>

int main() {
  return 0;
}

Schnorr::ECC::ECC() {
  secretKeySet = false;
  publicKeySet = false;

  /* Load in curve secp256r1 */
  CryptoPP::Integer p, a, b, Gx, Gy;

  /* parameteres */
  p = CryptoPP::Integer(
      "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F");
  a = CryptoPP::Integer(
      "0x0000000000000000000000000000000000000000000000000000000000000000");
  b = CryptoPP::Integer(
      "0x0000000000000000000000000000000000000000000000000000000000000007");
  q = CryptoPP::Integer(
      "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");
  Gx = CryptoPP::Integer(
      "0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798");
  Gy = CryptoPP::Integer(
      "0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8");

  /* Store the curve and the generator */
  ec = CryptoPP::ECP(p, a, b);
  G = CryptoPP::ECPPoint(Gx, Gy);
}

Schnorr::ECC::~ECC() {
  secretKeySet = false;
  publicKeySet = false;
}

bool Schnorr::ECC::HasPrivateKey() {
  return secretKeySet;
}

bool Schnorr::ECC::HasPublicKey() {
  return publicKeySet;
}

bool Schnorr::ECC::GenerateSecretKey() {
  secretKey = CryptoPP::Integer(rng, 256) % q;
  secretKeySet = true;
  return true;
}

bool Schnorr::ECC::GeneratePublicKey() {
  if (!secretKeySet)
    return false;
  Q = ec.ScalarMultiply(G, secretKey);
  publicKeySet = true;

  return true;
}

bool Schnorr::ECC::GenerateKeys() {
  if (!GenerateSecretKey())
    return false;
  if (!GeneratePublicKey())
    return false;
  return true;
}

CryptoPP::Integer Schnorr::ECC::GetPublicKeyX() {
  return Q.x;
}

CryptoPP::Integer Schnorr::ECC::GetPublicKeyY() {
  return Q.y;
}

CryptoPP::Integer Schnorr::ECC::GetSecretKey() {
  return secretKey;
}

/* Compute private child key (see BIP32) ... ki = parse256(IL) + kpar (mod n) */
void Schnorr::ECC::ModuloAddToHex(CryptoPP::Integer k,
                                  CryptoPP::Integer iL,
                                  std::vector<unsigned char>& dataBytes) {
  CryptoPP::Integer ki = (k + iL).Modulo(q);
  dataBytes.resize(32);
  ki.Encode(&dataBytes[0], 32);
}

/* Compute public child key (see BIP32) ... Ki = point(parse256(IL)) + Kpar */
void Schnorr::ECC::GetVchPointMultiplyAdd(
    CryptoPP::Integer iL,
    std::vector<unsigned char>& dataBytes) {
  if (!publicKeySet)
    return;

  CryptoPP::ECPPoint pi = ec.ScalarMultiply(G, iL);
  CryptoPP::ECPPoint Ki = ec.Add(pi, Q);

  const bool fCompressed = true;
  dataBytes.resize(ec.EncodedPointSize(fCompressed));
  ec.EncodePoint(&dataBytes[0], Ki, fCompressed);
}

bool Schnorr::ECC::SetVchPublicKey(std::vector<unsigned char> vchPubKey) {
  CryptoPP::ECPPoint publicKey;

  if (!ec.DecodePoint(publicKey, &vchPubKey[0], vchPubKey.size()))
    return false;

  publicKeySet = true;
  Q = publicKey;

  return true;
}

bool Schnorr::ECC::GetVchPublicKey(std::vector<unsigned char>& vchPubKey) {
  if (!publicKeySet)
    return false;

  /* set to true for compressed */
  const bool fCompressed = true;
  vchPubKey.resize(ec.EncodedPointSize(fCompressed));
  ec.EncodePoint(&vchPubKey[0], Q, fCompressed);

  return true;
}

bool Schnorr::ECC::SetVchSecretKey(std::vector<unsigned char> vchSecret) {
  if (vchSecret.size() != SECRET_KEY_SIZE)
    return false;

  secretKey.Decode(&vchSecret[0], SECRET_KEY_SIZE);
  secretKeySet = true;

  GeneratePublicKey();
  return true;
}

bool Schnorr::ECC::GetVchSecretKey(std::vector<unsigned char>& vchSecret) {
  if (!secretKeySet)
    return false;

  vchSecret.resize(SECRET_KEY_SIZE);
  secretKey.Encode(&vchSecret[0], SECRET_KEY_SIZE);
  return true;
}

CryptoPP::Integer Schnorr::ECC::HashPointMessage(const CryptoPP::ECPPoint& R,
                                                 const byte* message,
                                                 int mlen) {
  const int digestsize = 256 / 8;
  CryptoPP::Keccak sha(digestsize);

  int len = ec.EncodedPointSize();
  byte* buffer = new byte[len];
  ec.EncodePoint(buffer, R, false);
  sha.Update(buffer, len);
  delete[] buffer;

  sha.Update(message, mlen);

  byte digest[digestsize];
  sha.Final(digest);

  CryptoPP::Integer ans;
  ans.Decode(digest, digestsize);
  return ans;
}

bool Schnorr::ECC::Sign(std::vector<unsigned char> vchHash,
                        std::vector<unsigned char>& vchSig) {
  /* sign the hash */
  CryptoPP::Integer k;
  CryptoPP::ECPPoint R;
  CryptoPP::Integer sigE, sigS;

  k = CryptoPP::Integer(rng, 256) % q;
  R = ec.ScalarMultiply(G, k);

  sigE = HashPointMessage(R, &vchHash[0], (int)vchHash.size()) % q;
  sigS = (k - secretKey * sigE) % q;

  /* encode the vchSig */
  vchSig.resize(SIGNATURE_SIZE * 2);
  if (sigE.MinEncodedSize() > SIGNATURE_SIZE ||
      sigS.MinEncodedSize() > SIGNATURE_SIZE)
    return false;

  sigE.Encode(&vchSig[0], SIGNATURE_SIZE);
  sigS.Encode(&vchSig[SIGNATURE_SIZE], SIGNATURE_SIZE);

  return true;
}

bool Schnorr::ECC::Verify(std::vector<unsigned char> vchHash,
                          std::vector<unsigned char> vchSig) {
  /* decode the vchSig */
  CryptoPP::Integer sigE, sigS;
  if (vchSig.size() != (SIGNATURE_SIZE * 2))
    return false;

  /* extract bytes */
  std::vector<unsigned char> sigEVec(&vchSig[0], &vchSig[SIGNATURE_SIZE]);
  std::vector<unsigned char> sigSVec(&vchSig[SIGNATURE_SIZE],
                                     &vchSig[1 + SIGNATURE_SIZE * 2]);

  /* vectors to Integers */
  sigE.Decode(&sigEVec[0], SIGNATURE_SIZE);
  sigS.Decode(&sigSVec[0], SIGNATURE_SIZE);

  /* verify the hash */
  CryptoPP::ECPPoint R;
  R = ec.CascadeScalarMultiply(G, sigS, Q, sigE);

  CryptoPP::Integer sigEd =
      HashPointMessage(R, &vchHash[0], (int)vchHash.size()) % q;

  return (sigE == sigEd);
}

bool Schnorr::ECC::GetSignatureFromVch(std::vector<unsigned char> vchSig,
                                       CryptoPP::Integer& sigE,
                                       CryptoPP::Integer& sigS) {
  if (vchSig.size() != (SIGNATURE_SIZE * 2))
    return false;

  // extract bytes */
  std::vector<unsigned char> sigEVec(&vchSig[0], &vchSig[SIGNATURE_SIZE]);
  std::vector<unsigned char> sigSVec(&vchSig[SIGNATURE_SIZE],
                                     &vchSig[1 + SIGNATURE_SIZE * 2]);

  /* vectors to Integers */
  sigE.Decode(&sigEVec[0], SIGNATURE_SIZE);
  sigS.Decode(&sigSVec[0], SIGNATURE_SIZE);
  return true;
}

bool Schnorr::ECC::GetVchFromSignature(std::vector<unsigned char>& vchSig,
                                       CryptoPP::Integer sigE,
                                       CryptoPP::Integer sigS) {
  vchSig.resize(SIGNATURE_SIZE * 2);

  if (sigE.MinEncodedSize() > SIGNATURE_SIZE ||
      sigS.MinEncodedSize() > SIGNATURE_SIZE)
    return false;

  sigE.Encode(&vchSig[0], SIGNATURE_SIZE);
  sigS.Encode(&vchSig[SIGNATURE_SIZE], SIGNATURE_SIZE);
  return true;
}

void Schnorr::ECC::PrintInteger(CryptoPP::Integer i) {
  std::ostringstream oss;
  oss << std::hex << i;
  std::string str = oss.str();
  str = str.substr(0, str.size() - 1);
  std::cout << str << std::endl;
}
