/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */

#ifndef YHASH_H
#define YHASH_H

/* hash function interface */

/* default to SHA1 for yarrow 160 */

#include "shs.h"



#define HASH_CTX SHS_INFO
#define HASH_Init(x) shsInit(x)
#define HASH_Update(x, buf, sz) shsUpdate(x, (const void*)buf, sz)
#define HASH_Final(x, tdigest)  do {                                    \
        size_t loopvar;                                                 \
        unsigned char *out2 = (void *)(tdigest);                        \
        HASH_CTX  *ctx = (x);                                           \
        shsFinal(ctx);                                                  \
        for (loopvar=0; loopvar<(sizeof(ctx->digest)/sizeof(ctx->digest[0])); loopvar++) \
            store_32_be(ctx->digest[loopvar], &out2[loopvar*4]);        \
    } while(0)


#define HASH_DIGEST_SIZE SHS_DIGESTSIZE

#endif /* YHASH_H */
