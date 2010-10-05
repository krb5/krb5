/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
#ifndef _SHA2_DEFINED

#include "k5-int.h"

#define _SHA2_DEFINED

typedef krb5_octet      SHS_BYTE;
#define SHA2_DIGESTSIZE  32

/* The structure for storing SHA2 info */

typedef struct {
    void *nss_ctxt;
    unsigned char   digestBuf[SHA2_DIGESTSIZE]; /* output */
    unsigned int    digestLen; /* output */
} SHA2_INFO;

void sha2Init(SHA2_INFO *shsInfo);
void sha2Update(SHA2_INFO *shsInfo, const SHS_BYTE *buffer, unsigned int count);
void sha2Final(SHA2_INFO *shsInfo);

#endif /* _SHA2_DEFINED */
