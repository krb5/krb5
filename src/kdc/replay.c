/*
 * kdc/replay.c
 *
 * Copyright 1991 by the Massachusetts Institute of Technology.
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
 * Replay lookaside cache for the KDC, to avoid extra work.
 *
 */

#include "k5-int.h"
#include "kdc_util.h"
#include "extern.h"

#ifndef NOCACHE

typedef struct _krb5_kdc_replay_ent {
    struct _krb5_kdc_replay_ent *next;
    int num_hits;
    krb5_int32 timein;
    time_t db_age;
    krb5_data *req_packet;
    krb5_data *reply_packet;
    char *realm;
#ifdef USE_THREADS
    pthread_cond_t cond;
    int num_waiting_threads;
    int valid;
#endif
} krb5_kdc_replay_ent;

static krb5_kdc_replay_ent root_ptr = {0};

static int hits = 0;
static int calls = 0;
static int max_hits_per_entry = 0;
static int num_entries = 0;

#define STALE_TIME	2*60		/* two minutes */
#define STALE(ptr) ((abs((ptr)->timein - timenow) >= STALE_TIME) || \
		    ((strcmp(ptr->realm, kdc_context->default_realm) == 0) && \
		    ((ptr)->db_age != db_age)))

#ifdef USE_THREADS
#define MATCH(ptr) (((ptr)->req_packet->length == inpkt->length) &&	\
		    !memcmp((ptr)->req_packet->data, inpkt->data,	\
			    inpkt->length) &&				\
		    ((ptr->reply_packet == NULL) || ((ptr)->db_age == db_age)))
#else
#define MATCH(ptr) (((ptr)->req_packet->length == inpkt->length) &&	\
		    !memcmp((ptr)->req_packet->data, inpkt->data,	\
			    inpkt->length) &&				\
		    ((ptr)->db_age == db_age))
#endif

/* XXX
   Todo:  quench the size of the queue...
 */

/* return TRUE if outpkt is filled in with a packet to reply with,
   FALSE if the caller should do the work */

krb5_boolean
kdc_check_lookaside(krb5_context kdc_context, krb5_data *inpkt, krb5_data **outpkt)
{
    krb5_int32 timenow;
    register krb5_kdc_replay_ent *eptr, *last, *hold;
    time_t db_age;

    if (krb5_timeofday(kdc_context, &timenow) || 
	krb5_db_get_age(kdc_context, 0, &db_age))
	return FALSE;

    calls++;

    /* search for a replay entry in the queue, possibly removing
       stale entries while we're here */

    if (root_ptr.next) {
	for (last = &root_ptr, eptr = root_ptr.next;
	     eptr;
	     eptr = eptr->next) {
	    if (MATCH(eptr)) {
#ifdef USE_THREADS
		if (eptr->valid == 0)
		    return FALSE;
		if (eptr->reply_packet == NULL) {
		    /* Another thread is processing the request */
		    if (eptr->num_waiting_threads == 0)
			pthread_cond_init(&eptr->cond, NULL);
		    eptr->num_waiting_threads++;
		    sleep_kdc(&eptr->cond);
		    eptr->num_waiting_threads--;
		    if (eptr->num_waiting_threads == 0)
			pthread_cond_destroy(&eptr->cond);
		    if (eptr->reply_packet == NULL) {
			if (eptr->num_waiting_threads == 0) {
			    last->next = eptr->next;
			    krb5_free_data(kdc_context, eptr->req_packet);
			    free(eptr);
			}
			return FALSE;
		    }
		}
#endif
		eptr->num_hits++;
		hits++;

		if (krb5_copy_data(kdc_context, eptr->reply_packet, outpkt))
		    return FALSE;
		else
		    return TRUE;
		/* return here, don't bother flushing even if it is stale.
		   if we just matched, we may get another retransmit... */
	    }
#ifdef USE_THREADS
	    if (STALE(eptr) && eptr->num_waiting_threads == 0)
#else
	    if (STALE(eptr))
#endif
            {
		/* flush it and collect stats */
		max_hits_per_entry = max(max_hits_per_entry, eptr->num_hits);
		krb5_free_data(kdc_context, eptr->req_packet);
		if (eptr->reply_packet)
		    krb5_free_data(kdc_context, eptr->reply_packet);
		hold = eptr;
		last->next = eptr->next;
		eptr = last;
		free(hold);
	    } else {
		/* this isn't it, just move along */
		last = eptr;
	    }
	}
    }
    return FALSE;
}

void
kdc_insert_lookaside_1(krb5_context kdc_context, krb5_data *inpkt)
{
#ifdef USE_THREADS
    register krb5_kdc_replay_ent *eptr;    
    krb5_int32 timenow;
    time_t db_age;

    if (krb5_timeofday(kdc_context, &timenow) || 
	krb5_db_get_age(kdc_context, 0, &db_age))
	return;

    /* this is a new entry */
    eptr = (krb5_kdc_replay_ent *)calloc(1, sizeof(*eptr));
    if (!eptr)
	return;
    eptr->timein = timenow;
    eptr->db_age = db_age;
    eptr->realm = malloc(strlen(kdc_context->default_realm) + 1);
    if (eptr->realm == NULL)
	return;
    strcpy(eptr->realm, kdc_context->default_realm);

    /*
     * This is going to hurt a lot malloc()-wise due to the need to
     * allocate memory for the krb5_data and krb5_address elements.
     * ARGH!
     */
    if (krb5_copy_data(kdc_context, inpkt, &eptr->req_packet)) {
	free(eptr->realm);
	free(eptr);
	return;
    }

    eptr->reply_packet = NULL;
    eptr->valid = 1;

    eptr->next = root_ptr.next;
    root_ptr.next = eptr;
    num_entries++;
    return;
#endif
}

void
kdc_insert_lookaside_2(krb5_context kdc_context, krb5_data *inpkt, krb5_data *outpkt)
{
    register krb5_kdc_replay_ent *eptr = NULL;
#ifdef USE_THREADS
    register krb5_kdc_replay_ent *last = NULL;
#else
    krb5_int32 timenow;
    time_t db_age;
#endif

#ifdef USE_THREADS
    if (root_ptr.next) {
	for (last = &root_ptr, eptr = root_ptr.next;
	     eptr;
	     eptr = eptr->next) {
	    if (((eptr)->req_packet->length == inpkt->length) &&
                    !memcmp((eptr)->req_packet->data, inpkt->data,
                            inpkt->length)) {
		break;
	    }
	    last = eptr;
	}
    }
    if (eptr == NULL) /* the entry could have become stale and been removed */ 
	return;

    if (eptr->reply_packet != NULL)
	return;

    if (outpkt != NULL)
	if (krb5_copy_data(kdc_context, outpkt, &eptr->reply_packet)) {
            eptr->valid = 0;
        }
    else
	eptr->valid = 0;

    if (eptr->num_waiting_threads != 0) {
	wakeup_kdc(&eptr->cond);
    } else if (eptr->reply_packet == NULL) {
	last->next = eptr->next;
	krb5_free_data(kdc_context, eptr->req_packet);
	free(eptr->realm);
	free(eptr);
    }
#else
    if (krb5_timeofday(kdc_context, &timenow) ||
        krb5_db_get_age(kdc_context, 0, &db_age))
        return;

    /* this is a new entry */
    eptr = (krb5_kdc_replay_ent *)calloc(1, sizeof(*eptr));
    if (!eptr)
        return;
    eptr->timein = timenow;
    eptr->db_age = db_age;
    eptr->realm = malloc(strlen(kdc_context->default_realm) + 1);
    if (eptr->realm == NULL)
        return;
    strcpy(eptr->realm, kdc_context->default_realm);

    /*
     * This is going to hurt a lot malloc()-wise due to the need to
     * allocate memory for the krb5_data and krb5_address elements.
     * ARGH!
     */
    if (krb5_copy_data(kdc_context, inpkt, &eptr->req_packet)) {
	free(eptr->realm);
        free(eptr);
        return;
    }
    if (krb5_copy_data(kdc_context, outpkt, &eptr->reply_packet)) {
        krb5_free_data(kdc_context, eptr->req_packet);
	free(eptr->realm);
        free(eptr);
        return;
    }
    eptr->next = root_ptr.next;
    root_ptr.next = eptr;
    num_entries++;
#endif

    return;
}

/* frees memory associated with the lookaside queue for memory profiling */
void
kdc_free_lookaside(krb5_context kcontext)
{
    register krb5_kdc_replay_ent *eptr, *last, *hold;
    if (root_ptr.next) {
        for (last = &root_ptr, eptr = root_ptr.next;
	     eptr; eptr = eptr->next) {
		krb5_free_data(kcontext, eptr->req_packet);
		krb5_free_data(kcontext, eptr->reply_packet);
		free(eptr->realm);
		hold = eptr;
		last->next = eptr->next;
		eptr = last;
		free(hold);
	}
    }
}

#endif /* NOCACHE */
