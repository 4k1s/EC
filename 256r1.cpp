#include <crypto++/integer.h>
#include <crypto++/eccrypto.h>
#include <crypto++/osrng.h>
#include <crypto++/oids.h>

#include <iostream>

/*
 * DL: Discrete Log
 * AutoSeededRandomPool: deeded poll randomness. Default arguments: non-blocking, seed size 32bits
 * ECP: lliptic curve over prime p
 * secp256r1 : type of curve (r=random) y² = x³ + ax + b
 * a = FFFFFFFF 00000001 00000000 00000000 00000000 FFFFFFFF FFFFFFFF FFFFFFFC
 * b = 5AC635D8 AA3A93E7 B3EBBD55 769886BC 651D06B0 CC53B0F6 3BCE3C3E 27D2604B
 * OID: object ID , here ECP
 * ASN1: ASN.1 language for standarized serilization/deserilization
 * Element: a point on elliptic curve (used for public key, addition and miltiplication)
 * Integer: Very large positive or negative integer
 * Integer::One() and Integer::Two() are the numbers 1 and 2. The constructor is optimized
 * because they are frequently used (along with ::Zero())
 */

int main(int argc, char* argv[])
{
  typedef CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP> GroupParameters;
  typedef CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP>::Element Element;

  CryptoPP::AutoSeededRandomPool prng;    
  GroupParameters pars_256r1;
  pars_256r1.Initialize(CryptoPP::ASN1::secp256r1());

  /* private key */
  CryptoPP::Integer x(prng, CryptoPP::Integer::One(), pars_256r1.GetMaxExponent());
    
  std::cout << "Private exponent:" << std::endl;
  std::cout << "  " << std::hex << x << std::endl;
    
  /* public key */
  Element pub_key = pars_256r1.ExponentiateBase(x);

  std::cout << "Public element:" << std::endl;
  std::cout << "  " << std::hex << pub_key.x << std::endl;
  std::cout << "  " << std::hex << pub_key.y << std::endl;
    
  /* element addition with a random point */
  Element a = pars_256r1.GetCurve().Add(pub_key, CryptoPP::ECP::Point(7,9));

  std::cout << "Add:" << std::endl;
  std::cout << "  " << std::hex << a.x << std::endl;
  std::cout << "  " << std::hex << a.y << std::endl;

  /* scalar multiplication */
  Element m = pars_256r1.GetCurve().ScalarMultiply(a, CryptoPP::Integer::Two());

  std::cout << "Mult:" << std::endl;
  std::cout << "  " << std::hex << m.x << std::endl;
  std::cout << "  " << std::hex << m.y << std::endl;

  return 0;
}
