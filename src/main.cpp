#include <memory>
#include <fstream>
#include <iostream>
#include <sstream>

#include "oneway.h"
#include "config.h"
#include "build-number.h"

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

int main(int argc, char **argv)
{
    using namespace std;

    try
    {
        if (argc >= 2 && argc <= 3 && string(argv[1]) == string("--genkey"))
        {
            cerr << "Generating new key..." << endl;

            auto out = openOut((argc == 3) ? argv[2] : NULL);
            oneway::generatePrivateKey(out.get());

            return 0;
        }

        else if (argc >= 2 && argc <= 4 && string(argv[1]) == string("--publickey"))
        {
            cerr << "Converting private key to public..." << endl;

            auto in = openIn((argc >= 3) ? argv[2] : NULL);
            auto out = openOut((argc == 4) ? argv[3] : NULL);
            oneway::convertPrivateToPublic(in.get(), out.get());

            return 0;
        }

        else if (argc >= 3 && argc <= 5 && string(argv[1]) == string("--encrypt"))
        {
            cerr << "Encrypting..." << endl;

            auto inKey = openIn(argv[2]);
            auto in = openIn((argc >= 4) ? argv[3] : NULL);
            auto out = openOut((argc == 5) ? argv[4] : NULL);
            oneway::encrypt(inKey.get(), in.get(), out.get());

            return 0;
        }

        else if (argc >= 3 && argc <= 5 && string(argv[1]) == string("--decrypt"))
        {
            cerr << "Decrypting..." << endl;

            auto inKey = openIn(argv[2]);
            auto in = openIn((argc >= 4) ? argv[3] : NULL);
            auto out = openOut((argc == 5) ? argv[4] : NULL);
            oneway::decrypt(inKey.get(), in.get(), out.get());

            return 0;
        }

        else if (argc >= 3 && argc <= 5 && string(argv[1]) == string("--dump-key"))
        {
            cerr << "Dumping symmetric key..." << endl;

            auto inKey = openIn(argv[2]);
            auto in = openIn((argc >= 4) ? argv[3] : NULL);
            auto out = openOut((argc == 5) ? argv[4] : NULL);
            oneway::dumpSymmetricKey(inKey.get(), in.get(), out.get());

            return 0;
        }

        else if (argc >= 3 && argc <= 5 && string(argv[1]) == string("--decrypt-with-symkey"))
        {
            cerr << "Decrypting with symmetric key..." << endl;

            auto symmetricKey = std::string(argv[2]);
            std::stringstream inSymmetricKey(symmetricKey);
            auto in = openIn((argc >= 4) ? argv[3] : NULL);
            auto out = openOut((argc == 5) ? argv[4] : NULL);
            oneway::decryptWithSymmetricKey(&inSymmetricKey, in.get(), out.get());

            return 0;
        }

        else if (argc == 2 && string(argv[1]) == string("--version"))
        {
            cout << VERSION << "." << BUILD_NUMBER << endl;

            return 0;
        }

        else
        {
            cerr << "One way encryptor (c) 2014,2023 by galets, https://github.com/galets/oneway-cpp, version " << VERSION << "." << BUILD_NUMBER << endl;
            cerr << "Usage:" << endl;
            cerr << "   oneway --genkey private.key" << endl;
            cerr << "   oneway --publickey [private.key [public.key]]" << endl;
            cerr << "   oneway --encrypt public.key [plaintext.txt [encrypted.ascr]]" << endl;
            cerr << "   oneway --decrypt private.key [encrypted.ascr [plaintext.txt]]" << endl;
            cerr << "   oneway --dump-key private.key [encrypted.ascr [key.base64]]" << endl;
            cerr << "   oneway --decrypt-with-symkey symmetric-key-base64 [encrypted.ascr [plaintext.txt]]" << endl;
            cerr << "   oneway --version" << endl;
            cerr << endl;
            return 1;
        }
    }
    catch (const std::exception &ex)
    {
        cerr << "Error: " << ex.what() << endl;
        return 1;
    }
}
