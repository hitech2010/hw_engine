/*
 * hw_aes.c
 * Originally written by Zhao Junwang<zhjwpku@gmail.com> for the cryptop 
 * safemodule.
 */

#include <string.h>

#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/modes.h>

#include "common.h"

int aes_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key,
			const unsigned char *iv, int enc)
{
  int ret, mode;
  //HW_Cipher_Data *dat = (HW_Cipher_Data *)(ctx->cipher_data);
  HW_Cipher_Data *dat = (HW_Cipher_Data *)(EVP_CIPHER_CTX_cipher_data(ctx));
  
  mode = EVP_CIPHER_CTX_mode(ctx);
  if ((mode == EVP_CIPH_ECB_MODE || mode == EVP_CIPH_CBC_MODE) && !enc) {
    /* decryption */
    ret = AES_set_decrypt_key(key, EVP_CIPHER_CTX_key_length(ctx) * 8,
			      &dat->ks.ks);
    dat->block = (block128_f) AES_decrypt;
    dat->stream.cbc = mode == EVP_CIPH_CBC_MODE ? 
	  (cbc128_f) AES_cbc_encrypt : NULL;	// why encrypt?
  } else {
    /* encryption */
    ret = AES_set_encrypt_key(key, EVP_CIPHER_CTX_key_length(ctx) * 8,
			      &dat->ks.ks);
    dat->block = (block128_f) AES_encrypt;
    dat->stream.cbc = mode == EVP_CIPH_CBC_MODE ?
	  (cbc128_f) AES_cbc_encrypt : NULL;
  }

  if (ret < 0) {
    EVPerr(EVP_F_AES_INIT_KEY, EVP_R_AES_KEY_SETUP_FAILED);
    return 0;
  }

  return 1;
}

int aes_cbc_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
			  const unsigned char *in, size_t len)
{
  return 1;
}

int aes_ecb_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
			  const unsigned char *in, size_t len)
{
  return 1;
}

int aes_cfb_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
			  const unsigned char *in, size_t len)
{
  return 1;
}

int aes_ofb_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
			  const unsigned char *in, size_t len)
{
  return 1;
}

int aes_ctr_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
			  const unsigned char *in, size_t len)
{
  return 1;
}
