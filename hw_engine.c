#include <stdio.h>
#include <string.h>

#include <openssl/engine.h>
#include <openssl/evp.h>
#include <openssl/md5.h>

#define HW_ENGINE_ID	"hw_engine"
#define	HW_ENGINE_NAME	"An OpenSSL engine for cryptop"

/* md5 */
extern void engine_md5_init(EVP_MD *);
static EVP_MD digest_md5;

/* digests */
static int digest_nids[] = { NID_md5, 0 };
static int digests(ENGINE *e, const EVP_MD **digest,
                   const int **nids, int nid)
{
  int ok = 1;
  if (!digest) {
    /* We are returning a list of supported nids */
    *nids = digest_nids;
    return (sizeof(digest_nids) - 1) / sizeof(digest_nids[0]);
  }

  /* We are being asked for a specific digest */
  switch (nid) {
  case NID_md5:
    *digest = &digest_md5;
    break;
  default:
    ok = 0;
    *digest = NULL;
    break;
  }
  return ok;
}

/* 
 * This is the function used by ENGINE_set_init_function.
 * We now use the OPENSSL builtin implementations. Should be replaced
 * by the cryptop functions.
*/
static int cryptop_init(ENGINE *e)
{
  engine_md5_init(&digest_md5);

  return 1;
};

static int cryptop_bind_helper(ENGINE *e)
{
  if (!ENGINE_set_id(e, HW_ENGINE_ID) ||
      !ENGINE_set_name(e, HW_ENGINE_NAME) ||
      !ENGINE_set_init_function(e, cryptop_init) ||
      !ENGINE_set_digests(e, digests)) {
    return 0;
  }

  return 1;
}

static int cryptop_bind_fn(ENGINE *e, const char *id)
{
  if (id && strcmp(id, HW_ENGINE_ID)) {
    fprintf(stderr, "Bad engine id %s, expected id is %s\n", id, HW_ENGINE_ID);
    return 0;
  }
  if (!cryptop_bind_helper(e)) {
    fprintf(stderr, "Bind failed\n");
  }

  return 1;
}

/* Begin: SHA implementations */
/* End: SHA implementations */
IMPLEMENT_DYNAMIC_BIND_FN(cryptop_bind_fn)
IMPLEMENT_DYNAMIC_CHECK_FN()
