#include "gtest/gtest.h"
#include "../src/oneway.h"

#include <iostream>

// Following entries generated using following command:
/*
nm -g tests/vectors.o | awk '{
    if($3 ~ /_start$/ || $3 ~ /_end$/) {
        print "extern char "$3"[];"
    }
}' | sort

*/

extern char _binary_tests_test_vectors_legacy_ciphertext1_1w_end[];
extern char _binary_tests_test_vectors_legacy_ciphertext1_1w_start[];
extern char _binary_tests_test_vectors_legacy_key1_key_end[];
extern char _binary_tests_test_vectors_legacy_key1_key_start[];
extern char _binary_tests_test_vectors_legacy_key1_pub_end[];
extern char _binary_tests_test_vectors_legacy_key1_pub_start[];
extern char _binary_tests_test_vectors_legacy_plaintext1_txt_end[];
extern char _binary_tests_test_vectors_legacy_plaintext1_txt_start[];

#define VECTORSTR(x) std::string(x##_start, x##_end - x##_start)
#define VECTORBIN(x) std::vector<char>(x##_start, x##_end - x##_start)

TEST(PEM, ConvertPrivateKey)
{
    auto privateKey = VECTORSTR(_binary_tests_test_vectors_legacy_key1_key);
    auto publicKey = VECTORSTR(_binary_tests_test_vectors_legacy_key1_pub);

    std::stringstream in(privateKey);
    std::stringstream out;

    oneway::convertPrivateToPublic(&in, &out);

    EXPECT_EQ(publicKey, out.str());
}

TEST(PEM, Decrypt)
{
    auto privateKey = VECTORSTR(_binary_tests_test_vectors_legacy_key1_key);
    auto cipherText = VECTORSTR(_binary_tests_test_vectors_legacy_ciphertext1_1w);
    auto plainText = VECTORSTR(_binary_tests_test_vectors_legacy_plaintext1_txt);

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
