/* -*- Mode: C; c-file-style: "bsd" -*- */

#ifndef YLOCK_H
#define YLOCK_H

#include "yarrow.h"

/* these functions should return:
 *
 *        YARROW_OK on success
 *    and YARROW_LOCKING on failure
 */

#include "openssl/crypto.h"
int LOCK( void ) { CRYPTO_w_lock(CRYPTO_LOCK_RAND); return (YARROW_OK); }
int UNLOCK( void ) { CRYPTO_w_unlock(CRYPTO_LOCK_RAND); return (YARROW_OK); }

#endif /* YLOCK_H */
