/* -*- Mode: C; c-file-style: "bsd" -*- */

#ifndef YLOCK_H
#define YLOCK_H

#include "yarrow.h"

/* these functions should return:
 *
 *        YARROW_OK on success
 *    and YARROW_LOCKING on failure
 */


int LOCK( void ) {  return (YARROW_OK); }
int UNLOCK( void ) {  return (YARROW_OK); }

#endif /* YLOCK_H */
