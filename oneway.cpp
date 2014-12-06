#include <stdio.h>
#include <string.h>

#include <iostream>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/rand.h>


using namespace std;

static const char* HEADER = "ASCR";
static const size_t HEADER_SIZE = 4;
static const int KEY_SIZE = 4096;
static const int IV_LENGTH = 16;

void dbg(const char* annotation, unsigned const char* buf, size_t size)
{
#ifdef _DEBUG
    cerr << annotation << ":";
    if (!buf)
    {
        cerr << " NULL" << endl;
        return;
    }

    for (size_t i=0; i<size; ++i)
    {
        char buffer [10];
        sprintf(buffer, " %02X", buf[i]);
        cerr << buffer;
    }
    cerr << endl;
#endif

}

class CGenKey
{
    BIGNUM *bn = NULL;
    BIO* bio_err = NULL;
    RSA *rsa = NULL;
    FILE *f = NULL;

    static int genrsa_cb(int p, int n, BN_GENCB *cb)
    {
        char c=0;

        if (p == 0) c='.';
        if (p == 1) c='+';
        if (p == 2) c='*';
        if (p == 3) c='\n';
        if (c)
        {
            BIO_write(static_cast<BIO*>(cb->arg), &c, 1);
            (void)BIO_flush(static_cast<BIO*>(cb->arg));
        }
        return 1;
    }

public:
    CGenKey(char* fileName)
    {
        if (fileName)
        {
            f = fopen(fileName, "wt");
            if (!f)
            {
                throw "Output file cannot be opened";
            }
        }
    }

    ~CGenKey()
    {
        if (bn)
        {
            BN_free(bn);
        }

        if (rsa)
        {
            RSA_free(rsa);
        }

        if (bio_err)
        {
            BIO_free(bio_err);
        }

        if (f)
        {
            fclose(f);
        }
    }

    void genkey()
    {
        bn = BN_new();
        if (!bn)
        {
            throw "BIGNUM cannot be created";
        }

        if (!BN_set_word(bn, RSA_F4))
        {
            throw "BN_set_word failed";
        }

        bio_err = BIO_new(BIO_s_file());
        if (bio_err == NULL)
        {
            throw "BIO_new failed";
        }
        BIO_set_fp(bio_err, stderr, BIO_NOCLOSE|BIO_FP_TEXT);

        BN_GENCB cb;
        BN_GENCB_set(&cb, genrsa_cb, bio_err);

        rsa = RSA_new();
        if (!rsa)
        {
            throw "RSA cannot be created";
        }

        if (!RAND_status())
        {
            throw "Not enough entropy";
        }

        if (!RSA_generate_key_ex(rsa, KEY_SIZE, bn, &cb))
        {
            throw "RSA key generation failed";
        }
    }

    void printkey()
    {
        if (!PEM_write_RSAPrivateKey(f == NULL ? stdout : f, rsa, NULL, NULL, 0, NULL, NULL))
        {
            throw "PEM_write_RSAPrivateKey failed";
        }
    }
};


class CConvertToPublicKey
{
    FILE *in = NULL;
    FILE *out = NULL;
    RSA *rsa = NULL;

public:
    CConvertToPublicKey(char * inFileName, char* outFileName)
    {
        if (inFileName)
        {
            in = fopen(inFileName, "rt");
            if (!in)
            {
                throw "Input file cannot be opened";
            }
        }

        if (outFileName)
        {
            out = fopen(outFileName, "wt");
            if (!out)
            {
                throw "Output file cannot be opened";
            }
        }
    }

    ~CConvertToPublicKey()
    {
        if (rsa)
        {
            RSA_free(rsa);
        }

        if (in)
        {
            fclose(in);
        }

        if (out)
        {
            fclose(out);
        }
    }

    void convert()
    {
        rsa = PEM_read_RSAPrivateKey(in ? in : stdin, NULL, NULL, NULL);
        if (!rsa)
        {
            throw "Failed to read private key";
        }

        if (!PEM_write_RSAPublicKey(out ? out : stdout, rsa))
        {
            throw "Failed to write public key";
        }
    }
};

class CEncryptDecryptBase
{
protected:
    FILE *fkey = NULL;
    FILE *in = NULL;
    FILE *out = NULL;
    RSA *rsa = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    const EVP_CIPHER *cipher;

    void write(const void* buf, size_t dataSize)
    {
        if (dataSize)
        {
            if (!fwrite(buf, dataSize, 1, out ? out : stdout))
            {
                throw "File write error";
            }
        }
    }

    size_t read(void* buf, size_t bufSize)
    {
        size_t bytes = fread(buf, 1, bufSize, in ? in : stdin);
        if (ferror(in))
        {
            throw "File read error";
        }
        return bytes;
    }

public:
    CEncryptDecryptBase(char *keyFileName, char *inFileName, char* outFileName)
    {
        fkey = fopen(keyFileName, "rt");
        if (!fkey)
        {
            throw "Could not open key";
        }

        if (inFileName)
        {
            in = fopen(inFileName, "rb");
            if (!in)
            {
                throw "Input file cannot be opened";
            }
        }

        if (outFileName)
        {
            out = fopen(outFileName, "wb");
            if (!out)
            {
                throw "Output file cannot be opened";
            }
        }

        cipher = EVP_aes_256_cbc();
        if (!cipher)
        {
            throw "Cipher not supported (AES256)";
        }

        if (cipher->iv_len != IV_LENGTH)
        {
            throw "Internal error: bad IV length";
        }

        ctx = EVP_CIPHER_CTX_new();
        if (!ctx)
        {
            throw "EVP_CIPHER_CTX_new failed";
        }

        EVP_CIPHER_CTX_init(ctx);
    }

    ~CEncryptDecryptBase()
    {
        if (rsa)
        {
            RSA_free(rsa);
        }

        if (ctx)
        {
            EVP_CIPHER_CTX_cleanup(ctx);
            EVP_CIPHER_CTX_free(ctx);
        }

        if (fkey)
        {
            fclose(fkey);
        }

        if (in)
        {
            fclose(in);
        }

        if (out)
        {
            fclose(out);
        }
    }
};

class CEncrypt: public CEncryptDecryptBase
{
    unsigned char iv[IV_LENGTH];
    unsigned char key[32];

public:
    CEncrypt(char *pubKeyFileName, char *inFileName, char* outFileName)
        : CEncryptDecryptBase(pubKeyFileName, inFileName, outFileName)
    {
        rsa = PEM_read_RSAPublicKey(fkey, NULL, NULL, NULL);
        if (!rsa)
        {
            throw "Could not read public key";
        }

        fclose(fkey);
        fkey = NULL;

        RAND_bytes(iv, sizeof(iv));
        RAND_bytes(key, sizeof(key));
    }

    void encrypt()
    {
        if (!EVP_EncryptInit(ctx, cipher, key, iv))
        {
            throw "EVP_EncryptInit failed";
        }

        write(HEADER, HEADER_SIZE);

        write(iv, sizeof(iv));

        unsigned char key_encrypted[KEY_SIZE / 8];
        if (RSA_size(rsa) != sizeof(key_encrypted))
        {
            throw "Invalid key size";
        }

        if (!RSA_public_encrypt(sizeof(key), key, key_encrypted, rsa, RSA_PKCS1_PADDING))
        {
            throw "RSA_public_encrypt failed";
        }

        write(key_encrypted, sizeof(key_encrypted));

        unsigned char inbuf[4096];
        int outlen;
        unsigned char outbuf[4096];
        for(;;)
        {
            size_t inlen = read(inbuf, sizeof(inbuf));
            if (!inlen)
            {
                break;
            }

            if(!EVP_EncryptUpdate(ctx, outbuf, &outlen, inbuf, inlen))
            {
                throw "EVP_EncryptUpdate failed";
            }
            write(outbuf, outlen);
        }

        if(!EVP_EncryptFinal(ctx, outbuf, &outlen))
        {
            throw "EVP_EncryptFinal failed";
        }
        write(outbuf, outlen);
    }
};

class CDecrypt: public CEncryptDecryptBase
{
public:
    CDecrypt(char *pubKeyFileName, char *inFileName, char* outFileName)
        : CEncryptDecryptBase(pubKeyFileName, inFileName, outFileName)
    {
        rsa = PEM_read_RSAPrivateKey(fkey, NULL, NULL, NULL);
        if (!rsa)
        {
            throw "Could not read private key";
        }

        fclose(fkey);
        fkey = NULL;
    }

    void decrypt()
    {
        char header[HEADER_SIZE];
        unsigned char iv[IV_LENGTH];
        unsigned char key[KEY_SIZE / 8 - 11];
        unsigned char key_encrypted[KEY_SIZE / 8];

        read(header, sizeof(header));
        if (0 != memcmp(header, HEADER, HEADER_SIZE))
        {
            throw "Invalid input file";
        }

        read(iv, sizeof(iv));
        read(key_encrypted, sizeof(key_encrypted));

        int key_size = RSA_private_decrypt(sizeof(key_encrypted), key_encrypted, key, rsa, RSA_PKCS1_PADDING);
        if (key_size != 32)
        {
            throw "RSA_private_decrypt failed";
        }

        if (!EVP_DecryptInit(ctx, cipher, key, iv))
        {
            throw "EVP_DecryptInit failed";
        }

        unsigned char inbuf[4096];
        int outlen;
        unsigned char outbuf[4096];
        for(;;)
        {
            size_t inlen = read(inbuf, sizeof(inbuf));
            if (!inlen)
            {
                break;
            }

            if(!EVP_DecryptUpdate(ctx, outbuf, &outlen, inbuf, inlen))
            {
                throw "EVP_DecryptUpdate failed";
            }
            write(outbuf, outlen);
        }

        if(!EVP_DecryptFinal(ctx, outbuf, &outlen))
        {
            throw "EVP_DecryptFinal failed";
        }
        write(outbuf, outlen);
    }
};


int main(int argc, char** argv)
{
    try
    {
        if (argc >= 2 && string(argv[1]) == string("--genkey"))
        {
            cerr << "Generating new key..." << endl;

            CGenKey k((argc == 3) ? argv[2] : NULL);
            k.genkey();
            k.printkey();

            return 0;
        }

        else if (argc >= 2 && string(argv[1]) == string("--publickey"))
        {
            cerr << "Converting private key to public..." << endl;

            CConvertToPublicKey k((argc >= 3) ? argv[2] : NULL, (argc == 4) ? argv[3] : NULL);
            k.convert();

            return 0;
        }

        else if (argc >= 3 && string(argv[1]) == string("--encrypt"))
        {
            cerr << "Encrypting..." << endl;

            CEncrypt k(argv[2], (argc >= 4) ? argv[3] : NULL, (argc == 5) ? argv[4] : NULL);
            k.encrypt();

            return 0;
        }

        else if (argc >= 3 && string(argv[1]) == string("--decrypt"))
        {
            cerr << "Decrypting..." << endl;

            CDecrypt k(argv[2], (argc >= 4) ? argv[3] : NULL, (argc == 5) ? argv[4] : NULL);
            k.decrypt();

            return 0;
        }

        else
        {
            cerr << "Usage:" << endl;
            cerr << "   oneway [--encrypt|--decrypt|--genkey|--publickey]" << endl;
            cerr << "Example:" << endl;
            cerr << "   oneway --genkey private.key" << endl;
            cerr << "   oneway --publickey [private.key [public.key]]" << endl;
            cerr << "   oneway --encrypt public.key [plaintext.txt [encrypted.ascr]]" << endl;
            cerr << "   oneway --decrypt private.key [encrypted.ascr [plaintext.txt]]" << endl;
            cerr << endl;
            return 0;
        }

    }
    catch(char const *ex)
    {
        cerr << "Error: " << ex << endl;
        return 1;
    }
}
