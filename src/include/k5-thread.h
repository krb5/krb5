/*
 * include/k5-thread.h
 *
 * Copyright 2004 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * Export of this software from the United States of America may
 *   require a specific license from the United States Government.
 *   It is the responsibility of any person or organization contemplating
 *   export to obtain such a license before exporting.
 * 
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of M.I.T. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 * 
 *
 * Preliminary thread support.
 */

#ifndef k5_mutex_init /* handle multiple inclusion */

#include "autoconf.h"

/* Interface (tentative):

   Mutex support:

   // Between these two, we should be able to do pure compile-time
   // and pure run-time initialization.
   //   POSIX:   partial initializer is PTHREAD_MUTEX_INITIALIZER,
   //            finish does nothing
   //   Windows: partial initializer is an invalid handle,
   //            finish does the real initialization work
   //   debug:   partial initializer sets one magic value,
   //            finish verifies and sets a new magic value for
   //              lock/unlock to check
   k5_mutex_t foo_mutex = K5_MUTEX_PARTIAL_INITIALIZER;
   int k5_mutex_finish_init(k5_mutex_t *);
   // for dynamic allocation
   int k5_mutex_init(k5_mutex_t *);
   // Must work for both kinds of alloc, even if it means adding flags.
   int k5_mutex_destroy(k5_mutex_t *);

   // As before.
   int k5_mutex_lock(k5_mutex_t *);
   int k5_mutex_unlock(k5_mutex_t *);


   In each library, one new function to finish the static mutex init,
   and any other library-wide initialization that might be desired.
   On POSIX, this function would be called via the second support
   function (see below).  On Windows, it would be called at library
   load time.  These functions, or functions they calls, should be the
   only places that k5_mutex_finish_init gets called.

   A second function or macro called at various possible "first" entry
   points which either calls pthread_once on the first function
   (POSIX), or checks some flag set by the first function (Windows,
   debug support), and possibly returns an error.  (In the
   non-threaded case, a simple flag can be used to avoid multiple
   invocations, and the mutexes don't need run-time initialization
   anyways.)

   A third function for library termination calls mutex_destroy on
   each mutex for the library.  This function would be called
   automatically at library unload time.  If it turns out to be needed
   at exit time for libraries that don't get unloaded, perhaps we
   should also use atexit().  Any static mutexes should be cleaned up
   with k5_mutex_destroy here.


   How does that second support function invoke the first support
   function only once?  Through something modelled on pthread_once
   that I haven't written up yet.  Probably:

   k5_once_t foo_once = K5_ONCE_INIT;
   k5_once(k5_once_t *, void (*)(void));

   For POSIX: Map onto pthread_once facility.
   For non-threaded case: A simple flag.
   For Windows: Not needed; library init code takes care of it.


   Thread-specific data:

   // TSD keys are limited in number in gssapi/krb5/com_err; enumerate
   // them all.  This allows support code init to allocate the
   // necessary storage for pointers all at once, and avoids any
   // possible error in key creation.
   enum { ... } k5_key_t;
   // Register destructor function.  Called in library init code.
   int k5_key_register(k5_key_t, void (*destructor)(void *));
   // Returns NULL or data.
   void *k5_getspecific(k5_key_t);
   // Returns error if key out of bounds, or the pointer table can't
   // be allocated.  A call to k5_key_register must have happened first.
   // This may trigger the calling of pthread_setspecific on POSIX.
   int k5_setspecific(k5_key_t, void *);
   // Called in library termination code.
   // Trashes data in all threads, calling the registered destructor
   // (but calling it from the current thread).
   int k5_key_delete(k5_key_t);

   For the non-threaded version, the support code will have a static
   array indexed by k5_key_t values, and get/setspecific simply access
   the array elements.

   The TSD destructor table is global state, protected by a mutex if
   threads are enabled.

   Debug support: Not much.  Might check if k5_key_register has been
   called and abort if not.


   Any actual external symbols will use the krb5int_ prefix.  The k5_
   names will be simple macros or inline functions to rename the
   external symbols, or slightly more complex ones to expand the
   implementation inline (e.g., map to POSIX versions and/or debug
   code using __FILE__ and the like).


   More to be added, perhaps.  */

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
#define K5_MUTEX_DEBUG_INITIALIZER	{ 2, K5_MUTEX_DEBUG_UNLOCKED, 0, 0 }
#define K5_MUTEX_DEBUG_LOCKED		4
#define K5_MUTEX_DEBUG_UNLOCKED		3
#define k5_mutex_debug_finish_init(M)		\
	(assert((M)->initialized == 2), (M)->initialized = 1, 0)
#define k5_mutex_debug_init(M)			\
	((M)->initialized = 1,			\
	 (M)->locked = K5_MUTEX_DEBUG_UNLOCKED,	\
	 (M)->lineno = 0, (M)->filename = 0, 0)
#define k5_mutex_debug_destroy(M)				\
	(assert((M)->initialized == 1				\
		&& (M)->locked == K5_MUTEX_DEBUG_UNLOCKED),	\
	 (M)->initialized = 0)
#define k5_mutex_debug_lock(M)					\
	(assert((M)->initialized != 2),				\
	 assert((M)->initialized != 0),				\
	 assert((M)->initialized == 1),				\
	 assert((M)->locked != 0),				\
	 assert((M)->locked != K5_MUTEX_DEBUG_LOCKED),		\
	 assert((M)->locked == K5_MUTEX_DEBUG_UNLOCKED),	\
	 (M)->locked = K5_MUTEX_DEBUG_LOCKED,			\
	 (M)->lineno = __LINE__, (M)->filename = __FILE__, 0)
#define k5_mutex_debug_unlock(M)				\
	(assert((M)->initialized == 1				\
		&& (M)->locked == K5_MUTEX_DEBUG_LOCKED),	\
	 (M)->locked = K5_MUTEX_DEBUG_UNLOCKED,			\
	 (M)->lineno = __LINE__, (M)->filename = __FILE__, 0)


typedef enum {
    K5_KEY_COM_ERR,
    K5_KEY_MAX
} k5_key_t;


#ifdef ENABLE_THREADS

#include <pthread.h>

/* To do:  Weak symbol support.  Windows threads.

   Mutex initialization may need to be re-thought if we find we want
   any non-default attributes, like priority inheritance.  */

#ifndef DEBUG_THREADS

typedef pthread_mutex_t k5_mutex_t;
#define K5_MUTEX_PARTIAL_INITIALIZER PTHREAD_MUTEX_INITIALIZER

#define k5_mutex_finish_init(M)	((void)(M),0)
#define k5_mutex_init(M)	pthread_mutex_init(M, 0)
#define k5_mutex_destroy(M)	pthread_mutex_destroy(M)
#define k5_mutex_lock(M)	pthread_mutex_lock(M)
#define k5_mutex_unlock(M)	pthread_mutex_unlock(M)

#else /* DEBUG_THREADS */

typedef struct {
    k5_mutex_debug_info debug;
    pthread_mutex_t lock;
} k5_mutex_t;
#define K5_MUTEX_PARTIAL_INITIALIZER	\
		{ K5_MUTEX_DEBUG_INITIALIZER, PTHREAD_MUTEX_INITIALIZER }
#define k5_mutex_finish_init(M)	(k5_mutex_debug_finish_init(&(M)->debug))
#define k5_mutex_init(M)	(k5_mutex_debug_init(&(M)->debug),	      \
				 assert(0==pthread_mutex_init(&(M)->lock,0)), \
				 0)
#define k5_mutex_destroy(M)	(k5_mutex_debug_init(&(M)->debug),	      \
				 assert(0==pthread_mutex_destroy(&(M)->lock)))
#define k5_mutex_lock(M)	(k5_mutex_debug_lock(&(M)->debug),	    \
				 assert(0==pthread_mutex_lock(&(M)->lock)), \
				 0)
#define k5_mutex_unlock(M)	(k5_mutex_debug_unlock(&(M)->debug),	      \
				 assert(0==pthread_mutex_unlock(&(M)->lock)), \
				 0)

#if defined(__mips) && defined(__sgi) && defined(_SYSTYPE_SVR4)
/* IRIX 6.5 stub pthread support in libc is really annoying.
   The pthread_mutex_lock function returns ENOSYS for a program
   not linked against -lpthread.  No link-time failure, no weak
   symbols, etc.

   The C library doesn't provide pthread_once; we can use weak
   reference support for that.  */
#undef k5_mutex_lock
#undef k5_mutex_unlock
#define k5_mutex_lock(M)			\
	(k5_mutex_debug_lock(&(M)->debug),	\
	 (K5_PTHREADS_LOADED			\
	  ? pthread_mutex_lock(&(M)->lock)	\
	  : 0))
#define k5_mutex_unlock(M)			\
	(k5_mutex_debug_unlock(&(M)->debug),	\
	 (K5_PTHREADS_LOADED			\
	  ? pthread_mutex_unlock(&(M)->lock)	\
	  : 0))
#endif

#endif /* DEBUG_THREADS ? */

/* Linux with weak reference support:
   Stub mutex routines exist, but pthread_once does not.

   Solaris: In libc there's a pthread_once that doesn't seem
   to do anything.  Bleah.  But pthread_mutexattr_setrobust_np
   is defined only in libpthread.
 */

#ifdef HAVE_PRAGMA_WEAK_REF
# pragma weak pthread_once
# ifdef HAVE_PTHREAD_MUTEXATTR_SETROBUST_NP_IN_THREAD_LIB
#  pragma weak pthread_mutexattr_setrobust_np
# endif
# if !defined HAVE_PTHREAD_ONCE
#  define K5_PTHREADS_LOADED	(&pthread_once != 0)
# elif !defined HAVE_PTHREAD_MUTEXATTR_SETROBUST_NP \
	&& defined HAVE_PTHREAD_MUTEXATTR_SETROBUST_NP_IN_THREAD_LIB
#  define K5_PTHREADS_LOADED	(&pthread_mutexattr_setrobust_np != 0)
# else
#  define K5_PTHREADS_LOADED	(1)
# endif
#else
/* no pragma weak support */
# define K5_PTHREADS_LOADED	(1)
#endif

/* Would be nice to use a union, but we need to initialize both.  */
#ifdef HAVE_PRAGMA_WEAK_REF
typedef struct { pthread_once_t o; int i; } k5_once_t;
#define K5_ONCE_INIT	{ PTHREAD_ONCE_INIT, 2 }
#define k5_once(O,F)	(K5_PTHREADS_LOADED		\
			 ? pthread_once(&(O)->o,F)	\
			 : (O)->i == 2			\
			 ? ((O)->i = 3, (*F)(), 0)	\
			 : 0)
#else
typedef pthread_once_t k5_once_t;
#define K5_ONCE_INIT	PTHREAD_ONCE_INIT
#define k5_once		pthread_once
#endif

#else /* ! ENABLE_THREADS */

#ifdef DEBUG_THREADS

#include <assert.h>

/* Even if not using threads, use some mutex-like locks to see if
   we're pairing up lock and unlock calls properly.  */

#define k5_mutex_t		k5_mutex_debug_info
#define K5_MUTEX_PARTIAL_INITIALIZER	K5_MUTEX_DEBUG_INITIALIZER
#define k5_mutex_finish_init	k5_mutex_debug_finish_init
#define k5_mutex_init		k5_mutex_debug_init
#define k5_mutex_destroy	k5_mutex_debug_destroy
#define k5_mutex_lock		k5_mutex_debug_lock
#define k5_mutex_unlock		k5_mutex_debug_unlock

#define k5_once_t	unsigned char
#define K5_ONCE_INIT	2
#define k5_once(O,F)					\
	(assert(*(O) == 2 || *(O) == 3),		\
	 (*(O) == 3 ? 0 : ((F)(), *(O) = 3, 0)))

#else /* ! DEBUG_THREADS */

/* no-op versions */

typedef char k5_mutex_t;
#define K5_MUTEX_PARTIAL_INITIALIZER	0
#define k5_mutex_finish_init(M)	(0)
#define k5_mutex_init(M)	(*(M) = 0, *(M) = *(M))
#define k5_mutex_destroy(M)	(0)
#define k5_mutex_lock(M)	(0)
#define k5_mutex_unlock(M)	(0)

#define k5_once_t	unsigned char
#define K5_ONCE_INIT	2
#define k5_once(F,O)	\
	(*(O) == 3 ? 0 : ((F)(), *(O) = 3, 0))

#endif /* DEBUG_THREADS ? */

#endif /* ENABLE_THREADS ? */

/* rename shorthand symbols for export */
#define k5_key_register	krb5int_key_register
#define k5_getspecific	krb5int_getspecific
#define k5_setspecific	krb5int_setspecific
#define k5_key_delete	krb5int_key_delete
extern int k5_key_register(k5_key_t, void (*)(void *));
extern void *k5_getspecific(k5_key_t);
extern int k5_setspecific(k5_key_t, void *);
extern int k5_key_delete(k5_key_t);

#endif /* multiple inclusion? */
