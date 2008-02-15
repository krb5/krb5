/*
 * kdc/extern.c
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
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
 * allocations of extern stuff
 */

#include "k5-int.h"
#include "extern.h"

/* real declarations of KDC's externs */
kdc_realm_t	**kdc_realmlist = (kdc_realm_t **) NULL;
int		kdc_numrealms = 0;
krb5_data empty_string = {0, 0, ""};
krb5_timestamp kdc_infinity = KRB5_INT32_MAX; /* XXX */
krb5_rcache	kdc_rcache = (krb5_rcache) NULL;
krb5_keyblock	psr_key;

volatile int signal_requests_exit = 0;	/* gets set when signal hits */
volatile int signal_requests_hup = 0;   /* ditto */

krb5_context def_kdc_context;

#ifdef USE_THREADS
krb5_int32 thread_count;
k5_mutex_t kdc_lock;

inline void sleep_kdc(pthread_cond_t *cond)
{
	pthread_cond_wait(cond, &kdc_lock.os.p);
        /* This is a temporary fix. It has to be handled appropriately
           while writing the shim layer for condition variables */
#ifdef DEBUG_THREADS
        kdc_lock.os.owner = pthread_self();
#endif
}

inline void wakeup_kdc(pthread_cond_t *cond)
{
	pthread_cond_broadcast(cond);
}
#endif

inline void lock_kdc()
{
#ifdef USE_THREADS
	int rc;

	rc = k5_mutex_lock(&kdc_lock);
	assert (rc == 0);
#endif
}

inline void unlock_kdc()
{
#ifdef USE_THREADS
	int rc;

	rc = k5_mutex_unlock(&kdc_lock);
	assert (rc == 0);
#endif
}
