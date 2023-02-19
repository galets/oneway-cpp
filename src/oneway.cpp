#include <fstream>
#include <iostream>
#include <memory>

#include <cryptopp/aes.h>
#include <cryptopp/base64.h>
#include <cryptopp/cryptlib.h>
#include <cryptopp/filters.h>
#include <cryptopp/files.h>
#include <cryptopp/modes.h>
#include <cryptopp/osrng.h>
#include <cryptopp/pem.h>
#include <cryptopp/pem_common.h>
#include <cryptopp/rsa.h>

#include "oneway.h"

namespace
{

    static const char *HEADER = "ASCR";
    constexpr size_t HEADER_SIZE = 4;
    constexpr int KEY_SIZE = 4096;
    constexpr int SYMMETRIC_KEY_SIZE = 32;
    constexpr int IV_LENGTH = 16;
    constexpr int BUFFER_SIZE = 4096;
    constexpr size_t AES256_CBC_BLOCKSIZE = 32;

    CryptoPP::AutoSeededRandomPool prng;

    void write(std::ostream *stream, const void *data, size_t size)
    {
        stream->write(reinterpret_cast<const char *>(data), size);
        if (stream->bad())
        {
            throw std::runtime_error("Failed to write data to stream");
        }
    }

    size_t read(std::istream *stream, void *buffer, size_t bufferSize)
    {
        stream->read(reinterpret_cast<char *>(buffer), bufferSize);
        if (stream->bad())
        {
            throw std::runtime_error("Failed to read data from stream");
        }
        return stream->gcount();
    }

    void readExact(std::istream *stream, void *buffer, size_t bufferSize)
    {
        size_t size = read(stream, buffer, bufferSize);
        if (size != bufferSize)
        {
            throw std::runtime_error("Input file ended prematurely");
        }
    }

    template <typename T>
    T loadKey(std::istream *in)
    {
        T key;
        CryptoPP::FileSource source(*in, true);
        CryptoPP::PEM_Load(source, key);
        return key;
    }

    template <typename T>
    void storeKey(const T &key, std::ostream *out)
    {
        CryptoPP::FileSink fs(*out);
        CryptoPP::PEM_Save(fs, key);
    }

    template <>
    CryptoPP::RSA::PublicKey loadKey(std::istream *in)
    {
        std::stringstream ss;
        ss << in->rdbuf();
        std::string input = ss.str();

        std::string start_delimiter(CryptoPP::PEM::RSA_PUBLIC_BEGIN.c_str());
        std::string end_delimiter(CryptoPP::PEM::RSA_PUBLIC_END.c_str());

        size_t start_pos = input.find(start_delimiter);
        if (start_pos == std::string::npos)
        {
            throw std::runtime_error(start_delimiter + " not found in PEM");
        }
        start_pos += start_delimiter.length();
        start_pos += 1;
        size_t end_pos = input.find(end_delimiter, start_pos);
        if (end_pos == std::string::npos)
        {
            throw std::runtime_error(end_delimiter + " not found in PEM");
        }
        std::string keyBase64 = input.substr(start_pos, end_pos - start_pos);

        auto queue = new CryptoPP::ByteQueue();
        CryptoPP::Base64Decoder b64dec(queue);
        b64dec.Put(reinterpret_cast<const uint8_t *>(keyBase64.data()), keyBase64.size());
        b64dec.MessageEnd();

        CryptoPP::BERSequenceDecoder seq(*queue);
        CryptoPP::Integer modulus, exponent;
        modulus.BERDecode(seq);
        exponent.BERDecode(seq);
        seq.MessageEnd();

        CryptoPP::RSA::PublicKey key;
        key.SetModulus(modulus);
        key.SetPublicExponent(exponent);
        return key;
    }

    template <>
    void storeKey(const CryptoPP::RSA::PublicKey &key, std::ostream *out)
    {
        *out << CryptoPP::PEM::RSA_PUBLIC_BEGIN << std::endl;

        CryptoPP::FileSink fs(*out);
        CryptoPP::Base64Encoder b64enc(new CryptoPP::FileSink(*out), true, 64);

        CryptoPP::DERSequenceEncoder subjectPublicKeyInfo(b64enc);
        key.GetModulus().BEREncode(subjectPublicKeyInfo);
        key.GetPublicExponent().BEREncode(subjectPublicKeyInfo);
        subjectPublicKeyInfo.MessageEnd();

        b64enc.MessageEnd();

        *out << CryptoPP::PEM::RSA_PUBLIC_END << std::endl;
    }

} // anonymous namespace

namespace oneway
{

    void generatePrivateKey(std::ostream *outPrivateKey)
    {
        CryptoPP::RSA::PrivateKey key;
        key.GenerateRandomWithKeySize(prng, KEY_SIZE);
        storeKey(key, outPrivateKey);
    }

    void convertPrivateToPublic(std::istream *inPrivateKey, std::ostream *outPublicKey)
    {
        auto privKey = loadKey<CryptoPP::RSA::PrivateKey>(inPrivateKey);
        CryptoPP::RSA::PublicKey pubKey(privKey);
        storeKey(pubKey, outPublicKey);
    }

    void encrypt(std::istream *inPublicKey, std::istream *in, std::ostream *out)
    {
        unsigned char iv[IV_LENGTH];
        prng.GenerateBlock(iv, IV_LENGTH);

        unsigned char key[SYMMETRIC_KEY_SIZE];
        prng.GenerateBlock(key, SYMMETRIC_KEY_SIZE);

        auto publicKey = loadKey<CryptoPP::RSA::PublicKey>(inPublicKey);
        auto keySize = publicKey.GetModulus().BitCount();
        if (keySize != KEY_SIZE)
        {
            std::stringstream ss;
            ss << "Invalid key size: " << keySize;
            throw std::runtime_error(ss.str());
        }

        CryptoPP::RSAES_PKCS1v15_Encryptor publicKeyEncryptor(publicKey);
        size_t ciphertextSize = publicKeyEncryptor.CiphertextLength(SYMMETRIC_KEY_SIZE);
        if (ciphertextSize > KEY_SIZE / 8)
        {
            throw std::runtime_error(std::string("Internal error, ciphertext would be too long: ", ciphertextSize));
        }
        unsigned char key_encrypted[KEY_SIZE / 8];
        publicKeyEncryptor.Encrypt(prng, key, SYMMETRIC_KEY_SIZE, key_encrypted);

        CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption symmetricEncryptor;
        symmetricEncryptor.SetKeyWithIV(key, SYMMETRIC_KEY_SIZE, iv, IV_LENGTH);

        write(out, HEADER, HEADER_SIZE);
        write(out, iv, sizeof(iv));
        write(out, key_encrypted, sizeof(key_encrypted));

        std::array<uint8_t, BUFFER_SIZE> buffer;
        CryptoPP::StreamTransformationFilter stf(symmetricEncryptor, new CryptoPP::FileSink(*out), CryptoPP::BlockPaddingSchemeDef::PKCS_PADDING);
        while (size_t bytes = read(in, buffer.data(), buffer.size()))
        {
            stf.Put(buffer.data(), bytes);
        }
        stf.MessageEnd();
    }

    static void read_header(std::istream *is, unsigned char iv[IV_LENGTH])
    {
        char header[HEADER_SIZE] = {0};
        readExact(is, header, sizeof(header));
        if (std::string(header, sizeof(header)) != HEADER)
        {
            throw std::runtime_error("bad header");
        }
        readExact(is, iv, IV_LENGTH);
    }

    static void read_symmetric_key(CryptoPP::RSA::PrivateKey privateKey, std::istream *is, unsigned char key[SYMMETRIC_KEY_SIZE])
    {
        unsigned char key_encrypted[KEY_SIZE / 8];
        readExact(is, key_encrypted, sizeof(key_encrypted));

        auto keySize = privateKey.GetModulus().BitCount();
        if (keySize != KEY_SIZE)
        {
            std::stringstream ss;
            ss << "Invalid key size: " << keySize;
            throw std::runtime_error(ss.str());
        }

        CryptoPP::RSAES_PKCS1v15_Decryptor decryptor(privateKey);
        if (decryptor.FixedMaxPlaintextLength() > sizeof(key_encrypted))
        {
            throw std::runtime_error("Invalid decryption parameters");
        }
        decryptor.Decrypt(prng, key_encrypted, sizeof(key_encrypted), key);
    }

    static void skip_symmetric_key(std::istream *is)
    {
        unsigned char key_encrypted[KEY_SIZE / 8];
        readExact(is, key_encrypted, sizeof(key_encrypted));
    }

    static void decrypt_with_symmetric_key(std::istream *is, std::ostream *os, const unsigned char iv[IV_LENGTH], const unsigned char key[SYMMETRIC_KEY_SIZE])
    {
        CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption symmetricDecryptor;
        symmetricDecryptor.SetKeyWithIV(key, SYMMETRIC_KEY_SIZE, iv, IV_LENGTH);

        CryptoPP::StreamTransformationFilter stf(symmetricDecryptor, new CryptoPP::FileSink(*os), CryptoPP::BlockPaddingSchemeDef::PKCS_PADDING);

        std::array<uint8_t, BUFFER_SIZE> bufferIn, bufferOut;
        while (size_t bytes = read(is, bufferIn.data(), BUFFER_SIZE))
        {
            stf.Put(bufferIn.data(), bytes);
        }
        stf.MessageEnd();
    }

    void decrypt(std::istream *inPrivateKey, std::istream *in, std::ostream *out)
    {
        unsigned char iv[IV_LENGTH];
        unsigned char key[SYMMETRIC_KEY_SIZE];

        auto privateKey = loadKey<CryptoPP::RSA::PrivateKey>(inPrivateKey);

        read_header(in, iv);
        read_symmetric_key(privateKey, in, key);
        decrypt_with_symmetric_key(in, out, iv, key);
    }

    void dumpSymmetricKey(std::istream *inPrivateKey, std::istream *in, std::ostream *outSymmetricKey)
    {
        unsigned char iv[IV_LENGTH];
        unsigned char key[SYMMETRIC_KEY_SIZE];

        auto privateKey = loadKey<CryptoPP::RSA::PrivateKey>(inPrivateKey);

        read_header(in, iv);
        read_symmetric_key(privateKey, in, key);

        CryptoPP::Base64Encoder b64enc(new CryptoPP::FileSink(*outSymmetricKey));
        b64enc.Put(key, SYMMETRIC_KEY_SIZE);
        b64enc.MessageEnd();
    }

    void decryptWithSymmetricKey(std::istream *inSymmetricKey, std::istream *in, std::ostream *out)
    {
        CryptoPP::FileSource b64dec(*inSymmetricKey, true, new CryptoPP::Base64Decoder);
        if (b64dec.MaxRetrievable() != SYMMETRIC_KEY_SIZE)
        {
            std::stringstream ss;
            ss << "Invalid length of input key: " << b64dec.MaxRetrievable();
            throw std::runtime_error(ss.str());
        }

        unsigned char key[SYMMETRIC_KEY_SIZE];
        size_t key_length = b64dec.Get(reinterpret_cast<uint8_t *>(key), SYMMETRIC_KEY_SIZE);

        unsigned char iv[IV_LENGTH];
        read_header(in, iv);
        skip_symmetric_key(in);
        decrypt_with_symmetric_key(in, out, iv, key);
    }

} // namespace oneway
