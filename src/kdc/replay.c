/*
 * $Source$
 * $Author$
 *
 * Copyright 1991 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>.
 *
 * Replay lookaside cache for the KDC, to avoid extra work.
 *
 */

#if !defined(lint) && !defined(SABER)
static char rcsid_replay_c[] =
"$Id$";
#endif	/* !lint & !SABER */

#include <krb5/krb5.h>
#include <krb5/ext-proto.h>
#include <krb5/libos-proto.h>
#include <krb5/kdb.h>
#include "kdc_util.h"

typedef struct _krb5_kdc_replay_ent {
    struct _krb5_kdc_replay_ent *next;
    int num_hits;
    krb5_int32 timein;
    krb5_data *req_packet;
    krb5_data *reply_packet;
} krb5_kdc_replay_ent;

static krb5_kdc_replay_ent root_ptr = {0};

static int hits = 0;
static int calls = 0;
static int max_hits_per_entry = 0;
static int num_entries = 0;

#ifndef max
#define max(a,b) (((a) > (b)) ? (a) : (b))
#endif

#define STALE_TIME	2*60		/* two minutes */
#define STALE(ptr) (abs((ptr)->timein - timenow) >= STALE_TIME)

#define MATCH(ptr) (((ptr)->req_packet->length == inpkt->length) && \
		    !memcmp((ptr)->req_packet->data, inpkt->data, inpkt->length))

/* XXX
   Todo:  quench the size of the queue...
 */

/* return TRUE if outpkt is filled in with a packet to reply with,
   FALSE if the caller should do the work */

krb5_boolean
kdc_check_lookaside(inpkt, outpkt)
register krb5_data *inpkt;
register krb5_data **outpkt;
{
    krb5_int32 timenow;
    register krb5_kdc_replay_ent *eptr, *last, *hold;

    if (krb5_timeofday(&timenow))
	return FALSE;

    calls++;

    /* search for a replay entry in the queue, possibly removing
       stale entries while we're here */

    if (root_ptr.next) {
	for (last=&root_ptr, eptr = root_ptr.next;
	     eptr;
	     eptr = eptr->next) {
	    if (MATCH(eptr)) {
		eptr->num_hits++;
		hits++;

		if (krb5_copy_data(eptr->reply_packet, outpkt))
		    return FALSE;
		else
		    return TRUE;
		/* return here, don't bother flushing even if it is stale.
		   if we just matched, we may get another retransmit... */
	    }
	    if (STALE(eptr)) {
		/* flush it and collect stats */
		max_hits_per_entry = max(max_hits_per_entry, eptr->num_hits);
		krb5_free_data(eptr->req_packet);
		krb5_free_data(eptr->reply_packet);
		hold = eptr;
		last->next = eptr->next;
		eptr = last;
		xfree(hold);
	    } else {
		/* this isn't it, just move along */
		last = eptr;
	    }
	}
    }
    return FALSE;
}

/* insert a request & reply into the lookaside queue.  assumes it's not
   already there, and can fail softly due to other weird errors. */

void
kdc_insert_lookaside(inpkt, outpkt)
register krb5_data *inpkt;
register krb5_data *outpkt;
{
    register krb5_kdc_replay_ent *eptr;    
    krb5_int32 timenow;

    if (krb5_timeofday(&timenow))
	return;

    /* this is a new entry */
    eptr = (krb5_kdc_replay_ent *)calloc(1, sizeof(*eptr));
    if (!eptr)
	return;
    eptr->timein = timenow;
    if (krb5_copy_data(inpkt, &eptr->req_packet)) {
	xfree(eptr);
	return;
    }
    if (krb5_copy_data(outpkt, &eptr->reply_packet)) {
	krb5_free_data(eptr->req_packet);
	xfree(eptr);
	return;
    }
    eptr->next = root_ptr.next;
    root_ptr.next = eptr;
    num_entries++;
    return;
}
