#include "oneway.h"
#include "config.h"
#include "build-number.h"

int main(int argc, char **argv)
{
    using namespace std;

    try
    {
        if (argc >= 2 && argc <= 3 && string(argv[1]) == string("--genkey"))
        {
            cerr << "Generating new key..." << endl;

            CGenKey k((argc == 3) ? argv[2] : NULL);
            k.genkey();
            k.printkey();

            return 0;
        }

        else if (argc >= 2 && argc <= 4 && string(argv[1]) == string("--publickey"))
        {
            cerr << "Converting private key to public..." << endl;

            CConvertToPublicKey k((argc >= 3) ? argv[2] : NULL, (argc == 4) ? argv[3] : NULL);
            k.convert();

            return 0;
        }

        else if (argc >= 3 && argc <= 5 && string(argv[1]) == string("--encrypt"))
        {
            cerr << "Encrypting..." << endl;

            CEncrypt k(argv[2], (argc >= 4) ? argv[3] : NULL, (argc == 5) ? argv[4] : NULL);
            k.encrypt();

            return 0;
        }

        else if (argc >= 3 && argc <= 5 && string(argv[1]) == string("--decrypt"))
        {
            cerr << "Decrypting..." << endl;

            CDecrypt k(argv[2], (argc >= 4) ? argv[3] : NULL, (argc == 5) ? argv[4] : NULL);
            k.decrypt();

            return 0;
        }

        else if (argc >= 3 && argc <= 5 && string(argv[1]) == string("--dump-key"))
        {
            CDecrypt k(argv[2], (argc >= 4) ? argv[3] : NULL, (argc == 5) ? argv[4] : NULL);
            k.dump();

            return 0;
        }

        else if (argc >= 3 && argc <= 5 && string(argv[1]) == string("--decrypt-with-symkey"))
        {
            cerr << "Decrypting..." << endl;

            CDecrypt k(nullptr, (argc >= 4) ? argv[3] : NULL, (argc == 5) ? argv[4] : NULL);
            k.decrypt_symmetric(argv[2]);

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
