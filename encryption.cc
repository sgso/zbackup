// Copyright (c) 2012-2014 Konstantin Isakov <ikm@zbackup.org> and ZBackup contributors, see CONTRIBUTORS
// Part of ZBackup. Licensed under GNU GPLv2 or later + OpenSSL, see LICENSE

#include <openssl/evp.h>
#include <openssl/err.h>

#include "check.hh"
#include "debug.hh"
#include "encryption.hh"
#include "static_assert.hh"

namespace Encryption {

char const ZeroIv[ IvSize ] = {0};

void Cipher::ssl_error(void)
{
  fprintf(stderr, "OpenSSL error: ");
  ERR_print_errors_fp(stderr);
  abort();
}

Cipher::Cipher(const EncryptionKey& key, const unsigned char* iv, int enc) : enc(enc), key(key)
{
  if (!key.hasKey())
    // make this Cipher pass through input without de/encrypting
    this->noCipher = true;

  unsigned char* key_arr = (unsigned char*)key.getKey();

  // allocate evp context
  ctx = EVP_CIPHER_CTX_new();

  if (!ctx)
    ssl_error();

  if (EVP_CipherInit_ex(ctx, EVP_aes_128_cbc(), NULL, key_arr, iv, enc) != 1)
    ssl_error();

  // set padding to zero for update runs
  if (EVP_CIPHER_CTX_set_padding(ctx, 0) != 1)
    ssl_error();
}

bool Cipher::isCipher()
{
  return !this->noCipher;
}

size_t Cipher::update(const unsigned char* in, unsigned char* out, size_t size)
{
  if (this->noCipher) return size;

  // Make sure that BlockSize is a multiple of the size of size_t
  STATIC_ASSERT(!(BlockSize % sizeof(size_t)));

  // for now...
  STATIC_ASSERT(BlockSize == 16);

  int len = 0;

  if (EVP_CipherUpdate(ctx, out, &len, in, size) != 1)
    ssl_error();

  dPrintf("Cipher::update (%s): size=%u, len=%u\n",
          enc ? "encrypting": "decrypting", size, len);

  return len;
}

size_t Cipher::finalize(const unsigned char* in, unsigned char* out, size_t size)
{
  if (this->noCipher) return size;

  EVP_CIPHER_CTX_set_padding(ctx, 16);

  size_t len = update(in, out, size);
  int pad = 0;

  if (EVP_CipherFinal_ex(ctx, out + len, &pad) != 1)
    ssl_error();

  dPrintf("Cipher::finalize (%s): size=%u, len=%u, pad=%u, return=%u\n",
          enc ? "encrypting": "decrypting", size, len, pad, len + pad);

  return len + pad;
}

Cipher::~Cipher()
{
  // free evp context
  if (!noCipher) EVP_CIPHER_CTX_free(ctx);
}
}
