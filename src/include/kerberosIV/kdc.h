/*
 * include/kerberosIV/kdc.h
 *
 * Copyright 1987, 1988, 1994 by the Massachusetts Institute of Technology.
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
 * Include file for the Kerberos Key Distribution Center. 
 */

#ifndef KDC_DEFS
#define KDC_DEFS

#define S_AD_SZ		sizeof(struct sockaddr_in)

#ifdef notdef
#define max(a,b)	(a>b ? a : b)
#define min(a,b)	(a<b ? a : b)
#endif

#define TRUE		1
#define FALSE		0

#define MKEYFILE	"/.k"
#define K_LOGFIL	"/kerberos/kpropd.log"
#define KS_LOGFIL	"/kerberos/kerberos_slave.log"
#define KRB_ACL		"/kerberos/kerberos.acl"
#define KRB_PROG	"./kerberos"

#define ONE_MINUTE	60
#define FIVE_MINUTES	(5 * ONE_MINUTE)
#define ONE_HOUR	(60 * ONE_MINUTE)
#define ONE_DAY		(24 * ONE_HOUR)
#define THREE_DAYS	(3 * ONE_DAY)

#endif /* KDC_DEFS */

