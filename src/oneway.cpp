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

CryptoPP::AutoSeededRandomPool prng;

template <typename T>
struct Noop
{
    void operator()(T *p) const
    {
    }
};

std::shared_ptr<std::ostream> openOut(const char *name)
{
    if (nullptr == name)
    {
        return std::shared_ptr<std::ostream>(&std::cout, Noop<std::ostream>());
    }
    return std::shared_ptr<std::ostream>(new std::ofstream(name, std::ios_base::binary));
}

std::shared_ptr<std::istream> openIn(const char *name)
{
    if (nullptr == name)
    {
        return std::shared_ptr<std::istream>(&std::cin, Noop<std::istream>());
    }
    return std::shared_ptr<std::istream>(new std::ifstream(name, std::ios_base::binary));
}

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
T loadKey(std::shared_ptr<std::istream> in)
{
    T key;
    CryptoPP::FileSource source(*in.get(), true);
    CryptoPP::PEM_Load(source, key);
    return key;
}

template <typename T>
void storeKey(T &key, std::shared_ptr<std::ostream> out)
{
    CryptoPP::FileSink fs(*out.get());
    CryptoPP::PEM_Save(fs, key);
}

template <>
CryptoPP::RSA::PublicKey loadKey(std::shared_ptr<std::istream> in)
{
    std::stringstream ss;
    ss << in->rdbuf();
    std::string input = ss.str();
    in.reset();

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
void storeKey(CryptoPP::RSA::PublicKey &key, std::shared_ptr<std::ostream> out)
{
    *out << CryptoPP::PEM::RSA_PUBLIC_BEGIN << std::endl;

    CryptoPP::FileSink fs(*out.get());
    CryptoPP::Base64Encoder b64enc(new CryptoPP::FileSink(*out), true, 64);

    CryptoPP::DERSequenceEncoder subjectPublicKeyInfo(b64enc);
    key.GetModulus().BEREncode(subjectPublicKeyInfo);
    key.GetPublicExponent().BEREncode(subjectPublicKeyInfo);
    subjectPublicKeyInfo.MessageEnd();

    b64enc.MessageEnd();

    *out << CryptoPP::PEM::RSA_PUBLIC_END << std::endl;
}

CGenKey::CGenKey(char *fileName) : fileName(fileName) {}

void CGenKey::genkey()
{
    rsaPrivate.GenerateRandomWithKeySize(prng, KEY_SIZE);
}

void CGenKey::printkey()
{
    storeKey(rsaPrivate, openOut(fileName));
}

CConvertToPublicKey::CConvertToPublicKey(char *inFileName, char *outFileName) : in(inFileName), out(outFileName) {}

void CConvertToPublicKey::convert()
{
    auto privKey = loadKey<CryptoPP::RSA::PrivateKey>(openIn(in));
    CryptoPP::RSA::PublicKey pubKey(privKey);
    storeKey(pubKey, openOut(out));
}

CEncrypt::CEncrypt(char *pubKeyFileName, char *inFileName, char *outFileName) : pubKeyFileName(pubKeyFileName), inFileName(inFileName), outFileName(outFileName)
{
    prng.GenerateBlock(iv, IV_LENGTH);
    prng.GenerateBlock(key, SYMMETRIC_KEY_SIZE);
}

void CEncrypt::encrypt()
{
    auto publicKey = loadKey<CryptoPP::RSA::PublicKey>(openIn(pubKeyFileName));
    auto keySize = publicKey.GetModulus().BitCount();
    if (keySize != KEY_SIZE)
    {
        throw std::runtime_error(std::string("Invalid key size: " + keySize));
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

    auto is = openIn(inFileName);
    auto os = openOut(outFileName);

    write(os.get(), HEADER, HEADER_SIZE);
    write(os.get(), iv, sizeof(iv));
    write(os.get(), key_encrypted, sizeof(key_encrypted));

    std::array<uint8_t, BUFFER_SIZE> buffer;
    CryptoPP::StreamTransformationFilter stf(symmetricEncryptor, new CryptoPP::FileSink(*os), CryptoPP::BlockPaddingSchemeDef::PKCS_PADDING);
    while (size_t bytes = read(is.get(), buffer.data(), buffer.size()))
    {
        stf.Put(buffer.data(), bytes);
    }
    stf.MessageEnd();
}

CDecrypt::CDecrypt(char *privKeyName, char *inFileName, char *outFileName) : privKeyName(privKeyName), inFileName(inFileName), outFileName(outFileName) {}

void CDecrypt::read_header(std::istream *is, unsigned char iv[])
{
    char header[HEADER_SIZE] = {0};
    readExact(is, header, sizeof(header));
    readExact(is, iv, IV_LENGTH);
}

void CDecrypt::read_symmetric_key(std::istream *is, unsigned char key[])
{
    unsigned char key_encrypted[KEY_SIZE / 8];
    readExact(is, key_encrypted, sizeof(key_encrypted));

    auto privateKey = loadKey<CryptoPP::RSA::PrivateKey>(openIn(privKeyName));
    auto keySize = privateKey.GetModulus().BitCount();
    if (keySize != KEY_SIZE)
    {
        throw std::runtime_error(std::string("Invalid key size: " + keySize));
    }

    CryptoPP::RSAES_PKCS1v15_Decryptor decryptor(privateKey);
    if (decryptor.FixedMaxPlaintextLength() > sizeof(key_encrypted))
    {
        throw std::runtime_error("Invalid decryption parameters");
    }
    decryptor.Decrypt(prng, key_encrypted, sizeof(key_encrypted), key);
}

void CDecrypt::skip_symmetric_key(std::istream *is)
{
    unsigned char key_encrypted[KEY_SIZE / 8];
    readExact(is, key_encrypted, sizeof(key_encrypted));
}

void CDecrypt::decrypt_with_symmetric_key(std::istream *is, std::ostream *os, unsigned char iv[], unsigned char key[])
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

void CDecrypt::decrypt()
{
    unsigned char iv[IV_LENGTH];
    unsigned char key[SYMMETRIC_KEY_SIZE];

    auto in = openIn(inFileName);
    auto out = openOut(outFileName);

    read_header(in.get(), iv);
    read_symmetric_key(in.get(), key);
    decrypt_with_symmetric_key(in.get(), out.get(), iv, key);
}

void CDecrypt::dump()
{
    unsigned char iv[IV_LENGTH];
    unsigned char key[SYMMETRIC_KEY_SIZE];

    auto in = openIn(inFileName);
    auto out = openOut(outFileName);

    read_header(in.get(), iv);
    read_symmetric_key(in.get(), key);

    CryptoPP::Base64Encoder b64enc(new CryptoPP::FileSink(*out));
    b64enc.Put(key, SYMMETRIC_KEY_SIZE);
    b64enc.MessageEnd();
}

void CDecrypt::decrypt_symmetric(const char *keyBase64)
{
    size_t keyBase64Len = std::strlen(keyBase64);
    if (keyBase64Len > (SYMMETRIC_KEY_SIZE * 4 / 3 + 2))
    {
        throw std::runtime_error("Invalid length of input key");
    }

    CryptoPP::Base64Decoder b64dec;
    b64dec.Put(reinterpret_cast<const uint8_t *>(keyBase64), keyBase64Len);
    b64dec.MessageEnd();

    unsigned char key[SYMMETRIC_KEY_SIZE];
    size_t key_length = b64dec.Get(reinterpret_cast<uint8_t *>(key), SYMMETRIC_KEY_SIZE);

    if (key_length == SYMMETRIC_KEY_SIZE + 1)
    {
        // key was padded
        --key_length;
    }

    if (key_length != SYMMETRIC_KEY_SIZE)
    {
        std::cerr << keyBase64 << " " << key_length << ":" << (SYMMETRIC_KEY_SIZE) << std::endl;
        throw std::runtime_error("Invalid length of input key");
    }

    auto in = openIn(inFileName);
    auto out = openOut(outFileName);

    unsigned char iv[IV_LENGTH];
    read_header(in.get(), iv);
    skip_symmetric_key(in.get());
    decrypt_with_symmetric_key(in.get(), out.get(), iv, key);
}
