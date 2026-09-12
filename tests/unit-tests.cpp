#include "gtest/gtest.h"
#include "../src/oneway.h"

#include <fstream>
#include <sstream>
#include <stdexcept>

// Reads tests/test-vectors/<name> at runtime.
static std::string vec(const char* name)
{
    std::ifstream f(std::string(TEST_VECTORS_DIR) + "/" + name, std::ios::binary);

    if (!f) {
        throw std::runtime_error(name);
    }

    std::ostringstream ss;
    ss << f.rdbuf();

    return ss.str();
}

TEST(PEM, ConvertPrivateKey)
{
    auto privateKey = vec("legacy-key1.key");
    auto publicKey = vec("legacy-key1.pub");

    std::stringstream in(privateKey);
    std::stringstream out;

    oneway::convertPrivateToPublic(&in, &out);

    EXPECT_EQ(publicKey, out.str());
}

TEST(PEM, Decrypt)
{
    auto privateKey = vec("legacy-key1.key");
    auto cipherText = vec("legacy-ciphertext1.1w");
    auto plainText = vec("legacy-plaintext1.txt");

    std::stringstream inKey(privateKey);
    std::stringstream in(cipherText);
    std::stringstream out;

    oneway::decrypt(&inKey, &in, &out);

    EXPECT_EQ(plainText, out.str());
}

TEST(PEM, GenKeyGeneratesCallbacks)
{
    std::stringstream inKey;
    std::vector<size_t> callbacks;

    // clang-format off
    oneway::generatePrivateKey(&inKey, [&](size_t n)
    {
        callbacks.push_back(n);
    });
    // clang-format on

    EXPECT_LT(1, callbacks.size());
    EXPECT_EQ(0, *callbacks.rbegin());
}
