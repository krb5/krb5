/* -*- Mode: C; c-file-style: "bsd" -*- */

#ifndef YHASH_H
#define YHASH_H

/* hash function interface */

/* default to SHA1 for yarrow 160 */

#if !defined(YARROW_HASH_SHA1) && !defined(YARROW_HASH_MD5)
#   define YARROW_HASH_SHA1
#endif

#if defined(YARROW_HASH_SHA1)

/* For yarrow160 use SHA1 */

#include "openssl/sha.h"

#define HASH_CTX SHA_CTX
#define HASH_Init(x) SHA1_Init(x)
#define HASH_Update(x, buf, sz) SHA1_Update(x, (void*)buf, sz)
#define HASH_Final(x, digest) SHA1_Final(digest, x)

#define HASH_DIGEST_SIZE SHA_DIGEST_LENGTH

#elif defined(YARROW_HASH_MD5)

#include "openssl/md5.h"

#define HASH_CTX MD5_CTX
#define HASH_Init(x) MD5_Init(x)
#define HASH_Update(x, buf, sz) MD5_Update(x, (void*)buf, sz)
#define HASH_Final(x, digest) MD5_Final(digest, x)

#define HASH_DIGEST_SIZE MD5_DIGEST_LENGTH

#endif

#endif /* YHASH_H */
