/*
 * util/support/threads.c
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

#include <assert.h>
#include <stdlib.h>
#include <errno.h>
#include "k5-thread.h"
#include "k5-platform.h"

MAKE_INIT_FUNCTION(krb5int_thread_support_init);
MAKE_FINI_FUNCTION(krb5int_thread_support_fini);

#ifdef ENABLE_THREADS

#ifdef _WIN32

#error "need WIN32 thread support code written"

#else

/* POSIX */

/* Must support register/delete/register sequence, e.g., if krb5 is
   loaded so this support code stays in the process, and gssapi is
   loaded, unloaded, and loaded again.  */

static pthread_mutex_t key_lock = PTHREAD_MUTEX_INITIALIZER;
static void (*destructors[K5_KEY_MAX])(void *);
static unsigned char destructors_set[K5_KEY_MAX];

/* This is not safe yet!

   Thread termination concurrent with key deletion can cause two
   threads to interfere.  It's a bit tricky, since one of the threads
   will want to remove this structure from the list being walked by
   the other.

   Other cases, like looking up data while the library owning the key
   is in the process of being unloaded, we don't worry about.  */

struct tsd_block {
    struct tsd_block *next;
    void *values[K5_KEY_MAX];
};

static pthread_key_t key;
static void thread_termination(void *);

int krb5int_thread_support_init(void)
{
    return pthread_key_create(&key, thread_termination);
}

void krb5int_thread_support_fini(void)
{
    if (INITIALIZER_RAN(krb5int_thread_support_init))
	pthread_key_delete(key);
}

static void thread_termination (void *tptr)
{
    int i, pass, none_found;
    struct tsd_block *t = tptr;

    /* Make multiple passes in case, for example, a libkrb5 cleanup
       function wants to print out an error message, which causes
       com_err to allocate a thread-specific buffer, after we just
       freed up the old one.

       Shouldn't actually happen, if we're careful, but check just in
       case.  */

    pass = 0;
    none_found = 0;
    while (pass < 4 && !none_found) {
	none_found = 1;
	for (i = 0; i < K5_KEY_MAX; i++) {
	    if (destructors_set[i] && destructors[i] && t->values[i]) {
		void *v = t->values[i];
		t->values[i] = 0;
		(*destructors[i])(v);
		none_found = 0;
	    }
	}
    }
    /* remove thread from global linked list */
}

int k5_key_register (k5_key_t keynum, void (*destructor)(void *))
{
    int err;

    err = pthread_mutex_lock(&key_lock);
    if (err)
	return err;
    assert(keynum >= 0 && keynum < K5_KEY_MAX);
    assert(destructors_set[keynum] == 0);
    destructors_set[keynum] = 1;
    destructors[keynum] = destructor;
    err = pthread_mutex_unlock(&key_lock);
    if (err)
	return err;
    return 0;
}

void *k5_getspecific (k5_key_t keynum)
{
    struct tsd_block *t;
    int err;

    err = CALL_INIT_FUNCTION(krb5int_thread_support_init);
    if (err)
	return NULL;

    assert(keynum >= 0 && keynum < K5_KEY_MAX);
    assert(destructors_set[keynum] != 0);

    t = pthread_getspecific(key);
    if (t == NULL)
	return NULL;

    return t->values[keynum];
}

int k5_setspecific (k5_key_t keynum, void *value)
{
    struct tsd_block *t;
    int err;

    err = CALL_INIT_FUNCTION(krb5int_thread_support_init);
    if (err)
	return err;

    assert(keynum >= 0 && keynum < K5_KEY_MAX);
    assert(destructors_set[keynum] != 0);

    t = pthread_getspecific(key);
    if (t == NULL) {
	int i;
	t = malloc(sizeof(*t));
	if (t == NULL)
	    return errno;
	for (i = 0; i < K5_KEY_MAX; i++)
	    t->values[i] = 0;
	/* add to global linked list */
	t->next = 0;
	err = pthread_setspecific(key, t);
	if (err) {
	    free(t);
	    return err;
	}
    }

    t->values[keynum] = value;
    return 0;
}

int k5_key_delete (k5_key_t keynum)
{
    abort();
}

#endif /* Win32 vs POSIX */

#else

static void (*destructors[K5_KEY_MAX])(void *);
static void *tsd_values[K5_KEY_MAX];
static unsigned char destructors_set[K5_KEY_MAX];

int krb5int_thread_support_init(void)
{
    return 0;
}

void krb5int_thread_support_fini(void)
{
    /* ... */
}

int k5_key_register (k5_key_t keynum, void (*d)(void *))
{
    assert(keynum >= 0 && keynum < K5_KEY_MAX);
    assert(destructors_set[keynum] == 0);
    destructors[keynum] = d;
    destructors_set[keynum] = 1;
    return 0;
}

void *k5_getspecific (k5_key_t keynum)
{
    assert(keynum >= 0 && keynum < K5_KEY_MAX);
    assert(destructors_set[keynum] == 1);
    return tsd_values[keynum];
}

int k5_setspecific (k5_key_t keynum, void *value)
{
    assert(keynum >= 0 && keynum < K5_KEY_MAX);
    assert(destructors_set[keynum] == 1);
    tsd_values[keynum] = value;
    return 0;
}

int k5_key_delete (k5_key_t keynum)
{
    assert(keynum >= 0 && keynum < K5_KEY_MAX);
    assert(destructors_set[keynum] == 1);
    if (destructors[keynum] && tsd_values[keynum])
	(*destructors[keynum])(tsd_values[keynum]);
    destructors[keynum] = 0;
    tsd_values[keynum] = 0;
    destructors_set[keynum] = 0;
    return 0;
}

#endif
