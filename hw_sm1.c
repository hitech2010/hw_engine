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

#if IS_USBKEY
int sm1_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key,
		 const unsigned char *iv, int enc)
{
  int ret;
  SM1_Cipher_Data *dat = (SM1_Cipher_Data *)(ctx->cipher_data);
  
  if (!enc){	//decryption
    ret = AES_set_decrypt_key(key, EVP_CIPHER_CTX_key_length(ctx) * 8, 
			      &dat->ks);
  } else {	//encryption
    ret = AES_set_encrypt_key(key, EVP_CIPHER_CTX_key_length(ctx) * 8,
			      &dat->ks);
  }

  if (ret < 0) {
    /* TODO We need to add our own err handle */
    EVPerr(EVP_F_AES_INIT_KEY, EVP_R_AES_KEY_SETUP_FAILED);
    return 0;
  }

  return 1;
}

int sm1_do_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
		  const unsigned char *in, size_t len) {
  return 1;		  
}


#endif
