#pragma once

#include <iostream>
#include <memory>
#include <cryptopp/rsa.h>

static const char *HEADER = "ASCR";
constexpr size_t HEADER_SIZE = 4;
constexpr int KEY_SIZE = 4096;
constexpr int SYMMETRIC_KEY_SIZE = 32;
constexpr int IV_LENGTH = 16;
constexpr int BUFFER_SIZE = 4096;
constexpr size_t AES256_CBC_BLOCKSIZE = 32;

std::shared_ptr<std::ostream> openOut(const char *name);
std::shared_ptr<std::istream> openIn(const char *name);
void write(std::ostream *stream, const void *data, size_t size);
size_t read(std::istream *stream, void *buffer, size_t bufferSize);
void readExact(std::istream *stream, void *buffer, size_t bufferSize);

template <typename T>
T loadKey(std::shared_ptr<std::istream> in);

template <typename T>
void storeKey(T &key, std::shared_ptr<std::ostream> out);

template <>
CryptoPP::RSA::PublicKey loadKey(std::shared_ptr<std::istream> in);

template <>
void storeKey(CryptoPP::RSA::PublicKey &key, std::shared_ptr<std::ostream> out);

class CGenKey
{
    char *fileName;
    CryptoPP::RSA::PrivateKey rsaPrivate;

public:
    CGenKey(char *fileName);

    void genkey();
    void printkey();
};

class CConvertToPublicKey
{
    const char *in, *out;

public:
    CConvertToPublicKey(char *inFileName, char *outFileName);
    void convert();
};

class CEncrypt
{
    unsigned char iv[IV_LENGTH];
    unsigned char key[SYMMETRIC_KEY_SIZE];
    const char *pubKeyFileName, *inFileName, *outFileName;

public:
    CEncrypt(char *pubKeyFileName, char *inFileName, char *outFileName);
    void encrypt();
};

class CDecrypt
{
    const char *privKeyName, *inFileName, *outFileName;

public:
    CDecrypt(char *privKeyName, char *inFileName, char *outFileName);

private:
    void read_header(std::istream *is, unsigned char iv[]);
    void read_symmetric_key(std::istream *is, unsigned char key[]);
    void skip_symmetric_key(std::istream *is);
    void decrypt_with_symmetric_key(std::istream *is, std::ostream *os, unsigned char iv[], unsigned char key[]);

public:
    void decrypt();
    void dump();
    void decrypt_symmetric(const char *keyBase64);
};
