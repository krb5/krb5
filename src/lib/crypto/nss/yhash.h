/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* lib/crypto/openssl/hash/yhash.h
 */

#ifndef YHASH_H
#define YHASH_H

/* hash function interface */

/* default to SHA1 for yarrow 160 */

#include "shs.h"


#define HASH_CTX SHS_INFO
#define HASH_Init(x) shsInit(x)
#define HASH_Update(x, buf, sz) shsUpdate(x, (const void*)buf, sz)

#define HASH_Final(x, tdigest)  do {                    \
        int loopvar;                                    \
        unsigned char *out2 = (void *)(tdigest);        \
        HASH_CTX  *ctx = (x);                           \
        shsFinal(ctx);                                  \
        memcpy(out2, ctx->digestBuf, ctx->digestLen);   \
    } while(0)

#define HASH_DIGEST_SIZE SHS_DIGESTSIZE

#endif /* YHASH_H */
