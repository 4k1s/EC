#include <crypto++/integer.h>
#include <crypto++/eccrypto.h>
#include <crypto++/osrng.h>
#include <crypto++/oids.h>

#include <iostream>

/*
 * DL: Discrete Log
 * ECP: lliptic curve over prime p
 * secp256k1 : type of curve (r=random) y² = x³ + ax + b
 * a = 0
 * b = 7
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
  GroupParameters group;
  group.Initialize(CryptoPP::ASN1::secp256k1());
  std::cout << sizeof(Element) << std::endl;
  

  // private key
  CryptoPP::Integer x(prng, CryptoPP::Integer::One(), group.GetMaxExponent());
    
  std::cout << "Private exponent:" << std::endl;
  std::cout << "  " << std::hex << x << std::endl;
    
  // public key
  Element y = group.ExponentiateBase(x);

  std::cout << "Public element:" << std::endl;
  std::cout << "  " << std::hex << y.x << std::endl;
  std::cout << "  " << std::hex << y.y << std::endl;
    
  // element addition
  Element u = group.GetCurve().Add(y, CryptoPP::ECP::Point(2,3));

  std::cout << "Add:" << std::endl;
  std::cout << "  " << std::hex << u.x << std::endl;
  std::cout << "  " << std::hex << u.y << std::endl;

  // scalar multiplication
  Element v = group.GetCurve().ScalarMultiply(u, CryptoPP::Integer::Two());

  std::cout << "Mult:" << std::endl;
  std::cout << "  " << std::hex << v.x << std::endl;
  std::cout << "  " << std::hex << v.y << std::endl;

  return 0;
}
