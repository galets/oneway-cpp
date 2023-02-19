#pragma once

#include <iostream>

namespace oneway
{

    void genKey(std::ostream *out);
    void convertPrivateToPublic(std::istream *in, std::ostream *out);
    void encrypt(std::istream *inPublicKey, std::istream *in, std::ostream *out);
    void decrypt(std::istream *inPrivateKey, std::istream *in, std::ostream *out);
    void dump(std::istream *inPrivateKey, std::istream *in, std::ostream *out);
    void decrypt_symmetric(const char *symmetricKeyBase64, std::istream *in, std::ostream *out);

} // namespace oneway
