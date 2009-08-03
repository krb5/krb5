/* -*- Mode: C; c-file-style: "bsd" -*- */

#ifndef YLOCK_H
#define YLOCK_H

#include "yarrow.h"

/* these functions should return:
 *
 *        YARROW_OK on success
 *    and YARROW_LOCKING on failure
 */

#if 0
static int LOCK( void ) {  return (YARROW_OK); }
static int UNLOCK( void ) {  return (YARROW_OK); }
#else
#include "k5-thread.h"
extern k5_mutex_t krb5int_yarrow_lock;
#define LOCK()	(k5_mutex_lock(&krb5int_yarrow_lock) ? YARROW_LOCKING : YARROW_OK)
#define UNLOCK() (k5_mutex_unlock(&krb5int_yarrow_lock) ? YARROW_LOCKING : YARROW_OK)
#endif

#endif /* YLOCK_H */
