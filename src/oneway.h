#pragma once

#include <iostream>
#include <memory>
#include <cryptopp/rsa.h>

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
