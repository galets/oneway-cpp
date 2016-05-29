oneway-cpp
==========

Simple asymmetric encryption, C++ implementation

Purpose:
-------------------------

data encryption on the systems, where storing password or key in cleartext is not desirable option.


Usage:
-------------------------

Tool will use standard io streams where possible, or files could be specified on command line

Generate private key:

	oneway --genkey private.key
	oneway --genkey >private.key

Extract public key component from private key:

	oneway --publickey private.key public.key
	oneway --publickey <private.key >public.key

Encrypt file using public key:   

	oneway --encrypt public.key plaintext.txt encrypted.ascr
	oneway --encrypt public.key plaintext.txt >encrypted.ascr
	oneway --encrypt public.key <plaintext.txt >encrypted.ascr
   
Decrypt file using private key:

	oneway --decrypt private.key encrypted.ascr plaintext.txt
	oneway --decrypt private.key encrypted.ascr >plaintext.txt
	oneway --decrypt private.key <encrypted.ascr >plaintext.txt

Two-stage decryption:
-------------------------

Where it is necessary to allow 3rd party independently decrypt files without providing private key, it is possible to decrypt files in two stages: first, a symmetric key is extracted, then file gets decrypted using given symmetric key

Extract symmetric key:

	oneway --dump-key private.key encrypted.ascr key.base64
	oneway --dump-key private.key encrypted.ascr >key.base64
	oneway --dump-key private.key <encrypted.ascr >key.base64

Decrypt file using symmetric key:

	oneway --decrypt-with-symkey "key-in-base64-format" encrypted.ascr plaintext.txt
	oneway --decrypt-with-symkey "key-in-base64-format" encrypted.ascr >plaintext.txt
	oneway --decrypt-with-symkey "key-in-base64-format" <encrypted.ascr >plaintext.txt

Symmetric key from one file would not work on any other file.

Internals:
-------------------------

Each file is encrypted using AES256 with randomly generated key. AES256 key is encrypted using 4096
bit RSA and stored with the file.

File structure:

	4 bytes:    signature  "ASCR"
	16 bytes:   AES IV
	512 bytes:  RSA 4096-encrypted AES key
	rest:       encrypted file contents


See Also:
-------------------------

Files in compatible format are produced by similar .NET utility located at:
https://github.com/galets/AsymmetricCrypt

License:
-------------------------

This utility is licensed under GPLv3
