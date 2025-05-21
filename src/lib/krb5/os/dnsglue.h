/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* lib/krb5/os/dnsglue.h */
/*
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
 */

/*
 * Glue layer for DNS resolver, to make parsing of replies easier
 * whether we are using BIND 4, 8, or 9.  This header is not used on
 * Windows.
 */

/*
 * BIND 4 doesn't have the ns_initparse() API, so we need to do some manual
 * parsing.  BIND 8 does have ns_initparse(), but has enums for the various
 * protocol constants rather than the BIND 4 macros.
 */

#ifndef KRB5_DNSGLUE_H
#define KRB5_DNSGLUE_H

#include "autoconf.h"
#ifdef KRB5_DNS_LOOKUP

#include "k5-int.h"
#include "k5-input.h"
#include "os-proto.h"
#include <netinet/in.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <resolv.h>
#include <netdb.h>

#if HAVE_SYS_PARAM_H
#include <sys/param.h>          /* for MAXHOSTNAMELEN */
#endif

#ifndef MAXDNAME

#ifdef NS_MAXDNAME
#define MAXDNAME NS_MAXDNAME
#else
#ifdef MAXLABEL
#define MAXDNAME (16 * MAXLABEL)
#else
#define MAXDNAME (16 * MAXHOSTNAMELEN)
#endif
#endif

#endif

#if HAVE_NS_INITPARSE
/*
 * Solaris 7 has ns_rr_cl rather than ns_rr_class.
 */
#if !defined(ns_rr_class) && defined(ns_rr_cl)
#define ns_rr_class ns_rr_cl
#endif
#endif

#if HAVE_RES_NSEARCH
/*
 * Some BIND 8 / BIND 9 implementations disable the BIND 4 style
 * constants.
 */
#ifndef C_IN
#define C_IN ns_c_in
#endif
#ifndef T_SRV
#define T_SRV ns_t_srv
#endif
#ifndef T_TXT
#define T_TXT ns_t_txt
#endif

#else  /* !HAVE_RES_NSEARCH */

/*
 * Some BIND implementations might be old enough to lack these.
 */
#ifndef T_TXT
#define T_TXT 15
#endif
#ifndef T_SRV
#define T_SRV 33
#endif

#endif /* HAVE_RES_NSEARCH */

#ifndef T_URI
#define T_URI 256
#endif

struct k5_dns_state;

/* Perform a name lookup and set *ds_out to a handle for iteration over the
 * answers.  Return -1 on error, 0 on success. */
int k5_dns_init(const char *host, int nclass, int ntype,
                struct k5_dns_state **ds_out);

/*
 * Initialize *ans_out with the record data of the next matching answer from
 * ds, or with the empty string if there are no more matching answers.  Return
 * -1 on error, 0 on success.
 */
int k5_dns_nextans(struct k5_dns_state *ds, struct k5input *ans_out);

/* Expand a compressed name from in into buf (a buffer with at least len bytes
 * of space) and advance past it.  Return -1 on error, 0 on success. */
int k5_dns_expand(struct k5_dns_state *ds, struct k5input *in,
                  char *buf, int len);

/* Release ds. */
void k5_dns_fini(struct k5_dns_state *ds);

#endif /* KRB5_DNS_LOOKUP */
#endif /* !defined(KRB5_DNSGLUE_H) */
