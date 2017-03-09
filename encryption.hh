// Copyright (c) 2012-2014 Konstantin Isakov <ikm@zbackup.org> and ZBackup contributors, see CONTRIBUTORS
// Part of ZBackup. Licensed under GNU GPLv2 or later + OpenSSL, see LICENSE

#ifndef ENCRYPTION_HH_INCLUDED
#define ENCRYPTION_HH_INCLUDED

#include <stddef.h>
#include <exception>

#include <openssl/evp.h>

#include "ex.hh"
#include "encryption_key.hh"

/// What we implement right now is AES-128 in CBC mode with PKCS#7 padding
namespace Encryption {

enum
{
  KeySize = 16, /// Size of the key in bytes
  IvSize = 16, /// Size of the IV data in bytes
  BlockSize = 16 /// Cipher block size in bytes
};

/// The IV consisting of zero bytes. Use it when there is no IV
extern char const ZeroIv[ IvSize ];

class Cipher {
private:
  // 1 = encrypt, 0 = decrypt
  const int enc;
  EncryptionKey const& key;
  EVP_CIPHER_CTX* ctx;
  bool noCipher = false;

  void ssl_error(void);

public:
  Cipher(const EncryptionKey &, const unsigned char* iv, int enc);

  // encryption/decryption function
  size_t update(const unsigned char* in, unsigned char* out, size_t size);
  size_t finalize(const unsigned char* in, unsigned char* out, size_t size);

  bool isCipher();

  ~Cipher();
};
}

#endif
