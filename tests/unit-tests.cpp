#include "gtest/gtest.h"
#include "../src/oneway.h"

#include <iostream>

TEST(PEM, ConvertPrivateKey)
{
    std::string PrivateKey = R"EOF(-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----
)EOF";

    std::string PublicKey = R"EOF(-----BEGIN RSA PUBLIC KEY-----
MIICCgKCAgEA3blPsSRzZENRwmxZgMjb/RDrsECdAnkMkvLPURe7qyIgqpJhn9qA
m4w/NiRS6Eqm3r5Sl+iw6ehvlatnZoZgca/kST2sgeU2/8vZ/YQ+Bl/MT5TWZqEB
KLZJi3zWz41wyKJE5Hxrj6Xg/ePB5NunDVcSiloaj51BFUmq5pVR5GDfKNcHIgJj
3GWTPAg4jufB7qWttkZxXZfCO0cwOImXzddPq4ll901g/JDOiWsO1GunjThkcVQF
8lXePCbZKO8t2jzMYLL8gFRe1gg8UgmUuvpJ/3aFpW6vp0LH2CqpDgaCsM3M3rIP
203Bi7/5ylCtbuam1EVS5F22/amR42PAUClv8HR7In+JQJP6AnDJLBzERubZNGX8
lpGOSXE7g6VPuxSw70e7V53+X43y++BYWtq3iixLrwaHMJGsRaStsGpgF1wVuEcU
2DHY+Txsiba5X6TrOtlWRc4gnPLyQM0Pqf9G6dMAxgctfSBi2xOQnmXYhOPohUrn
syIgggeGkoVPweZmlewYngFN1a1gxpokgWuQFWpY52rCNcuaQeQERZuyDVwYZktG
BI3AT9SNKzaWS/wLJ5DaQ+kYojOLQI9ILuhvgWLnZZ8+RW1U9PRr4DtmhGSWMGpf
GJOnTW4jdrOKyRyW1FKJlJ4jjaIpb/6HdoX3nkmUzpYl9cM84xeVTbsCAwEAAQ==
-----END RSA PUBLIC KEY-----
)EOF";

    std::shared_ptr<std::istream> ssIn(new std::stringstream(PrivateKey));
    std::shared_ptr<std::stringstream> ssOut(new std::stringstream);
    CryptoPP::RSA::PublicKey pubKey(loadKey<CryptoPP::RSA::PrivateKey>(ssIn));
    storeKey<CryptoPP::RSA::PublicKey>(pubKey, ssOut);

    EXPECT_EQ(PublicKey, ssOut->str());
}