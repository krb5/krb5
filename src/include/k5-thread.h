/* Copyright 2004 Massachusetts Institute of Technology.
   All Rights Reserved.  */

#ifndef K5_MUTEX_INITIALIZER /* handle multiple inclusion */

#include "autoconf.h"

/* Interface (tentative):

   k5_mutex_t foo_mutex = K5_MUTEX_INITIALIZER;
   int k5_mutex_init(k5_mutex_t *);
   int k5_mutex_destroy(k5_mutex_t *);
   int k5_mutex_lock(k5_mutex_t *);
   int k5_mutex_unlock(k5_mutex_t *);

   k5_key_t key;
   int k5_key_create(k5_key_t *, void (*destructor)(void *));
   void *k5_getspecific(k5_key_t);
   int k5_setspecific(k5_key_t, const void *);
   ... stuff to signal library termination ...

   More to be added, probably.  */

#ifndef HAVE_PTHREAD_H
# undef ENABLE_THREADS
#endif

#define DEBUG_THREADS

#include <assert.h>
typedef struct {
    /* We've got some bits to spare; using more than one bit decreases
       the likelihood that random storage will contain the right
       values.  */
    unsigned int initialized : 3;
    unsigned int locked : 3;
    /* No source file in this tree gets anywhere near 32K lines.  */
    short lineno;
    const char *filename;
} k5_mutex_debug_info;
#define K5_MUTEX_DEBUG_INITIALIZER	{ 1, 0, 0, 0 }
#define K5_MUTEX_DEBUG_LOCKED		4
#define K5_MUTEX_DEBUG_UNLOCKED		3
#define k5_mutex_debug_init(M)			\
	((M)->initialized = 1,			\
	 (M)->locked = K5_MUTEX_DEBUG_UNLOCKED,	\
	 (M)->lineno = 0, (M)->filename = 0, 0)
#define k5_mutex_debug_destroy(M)				\
	(assert((M)->initialized == 1				\
		&& (M)->locked == K5_MUTEX_DEBUG_UNLOCKED),	\
	 (M)->initialized = 0)
#define k5_mutex_debug_lock(M)					\
	(assert((M)->initialized == 1				\
		&& (M)->locked == K5_MUTEX_DEBUG_UNLOCKED),	\
	 (M)->locked = K5_MUTEX_DEBUG_LOCKED,			\
	 (M)->lineno = __LINE__, (M)->filename = __FILE__, 0)
#define k5_mutex_debug_unlock(M)				\
	(assert((M)->initialized == 1				\
		&& (M)->locked == K5_MUTEX_DEBUG_LOCKED),	\
	 (M)->locked = K5_MUTEX_DEBUG_UNLOCKED,			\
	 (M)->lineno = __LINE__, (M)->filename = __FILE__, 0)

#ifdef ENABLE_THREADS

#include <pthread.h>

/* To do:  Weak symbol support.  Windows threads.

   Mutex initialization may need to be re-thought if we find we want
   any non-default attributes, like priority inheritance.  */

#ifndef DEBUG_THREADS

typedef pthread_mutex_t k5_mutex_t;
#define K5_MUTEX_INITIALIZER PTHREAD_MUTEX_INITIALIZER

#define k5_mutex_init(M)	pthread_mutex_init(M, 0)
#define k5_mutex_destroy(M)	pthread_mutex_destroy(M)
#define k5_mutex_lock(M)	pthread_mutex_lock(M)
#define k5_mutex_unlock(M)	pthread_mutex_unlock(M)

#else /* DEBUG_THREADS */

typedef struct {
    k5_mutex_debug_info debug;
    pthread_mutex_t lock;
} k5_mutex_t;
#define K5_MUTEX_INITIALIZER	{ K5_MUTEX_DEBUG_INITIALIZER, PTHREAD_MUTEX_INITIALIZER }
#define k5_mutex_init(M)	(k5_mutex_debug_init(&(M)->debug),	      \
				 assert(0==pthread_mutex_init(&(M)->lock,0)), \
				 0)
#define k5_mutex_destroy(M)	(k5_mutex_debug_init(&(M)->debug),	      \
				 assert(0==pthread_mutex_destroy(&(M)->lock))
#define k5_mutex_lock(M)	(k5_mutex_debug_lock(&(M)->debug),	    \
				 assert(0==pthread_mutex_lock(&(M)->lock)), \
				 0)
#define k5_mutex_unlock(M)	(k5_mutex_debug_unlock(&(M)->debug),	      \
				 assert(0==pthread_mutex_unlock(&(M)->lock)), \
				 0)

#endif /* DEBUG_THREADS ? */

#if 0
/* *** This will need to change.
   We'd prefer to use only one POSIX data key.

   And we need to do some additional bookkeeping for dealing with
   unloading libraries (free storage, destroy the key), such that we
   can't just map the functions to POSIX in the long term.  */
typedef pthread_key_t k5_key_t;
#define k5_key_create(K,D)	pthread_key_create(K,D)
#define k5_getspecific(K)	pthread_getspecific(K)
#define k5_setspecific(K,P)	pthread_setspecific(K,P)
#endif

#else /* ! ENABLE_THREADS */

#ifdef DEBUG_THREADS

#include <assert.h>

/* Even if not using threads, use some mutex-like locks to see if
   we're pairing up lock and unlock calls properly.  */

#define k5_mutex_t		k5_mutex_debug_info
#define K5_MUTEX_INITIALIZER	K5_MUTEX_DEBUG_INITIALIZER
#define k5_mutex_init		k5_mutex_debug_init
#define k5_mutex_destroy	k5_mutex_debug_destroy
#define k5_mutex_lock		k5_mutex_debug_lock
#define k5_mutex_unlock		k5_mutex_debug_unlock

#else /* ! DEBUG_THREADS */

/* no-op versions */

typedef char k5_mutex_t;
#define K5_MUTEX_INITIALIZER	0
#define k5_mutex_init(M)	(*(M) = 0, *(M) = *(M))
#define k5_mutex_destroy(M)	(0)
#define k5_mutex_lock(M)	(0)
#define k5_mutex_unlock(M)	(0)

#endif /* DEBUG_THREADS ? */

#endif /* ENABLE_THREADS ? */

#endif /* K5_MUTEX_INITIALIZER for multiple inclusion */
