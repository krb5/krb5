/* -*- Mode: C; c-file-style: "bsd" -*- */

#ifndef YHASH_H
#define YHASH_H

/* hash function interface */

/* default to SHA1 for yarrow 160 */

#include "shs.h"



#define HASH_CTX SHS_INFO
#define HASH_Init(x) shsinit(x)
#define HASH_Update(x, buf, sz) shsupdate(x, (void*)buf, sz)
#define HASH_Final(x, digest)  do { \
  shsfinal(x); \
  memcpy(digest, (void *) x.digest, SHS_DIGESTSIZE); \
  } while(0;)


#define HASH_DIGEST_SIZE SHS_DIGESTSIZE

#endif /* YHASH_H */
