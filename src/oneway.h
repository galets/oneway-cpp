#pragma once

#include <iostream>
#include <functional>

namespace oneway
{

    void generatePrivateKey(
        std::ostream *outPrivateKey, std::function<void(size_t)> progress = [](size_t) {});
    void convertPrivateToPublic(std::istream *inPrivateKey, std::ostream *outPublicKey);
    void encrypt(std::istream *inPublicKey, std::istream *in, std::ostream *out);
    void decrypt(std::istream *inPrivateKey, std::istream *in, std::ostream *out);
    void dumpSymmetricKey(std::istream *inPrivateKey, std::istream *in, std::ostream *outSymmetricKey);
    void decryptWithSymmetricKey(std::istream *inSymmetricKey, std::istream *in, std::ostream *out);

} // namespace oneway
