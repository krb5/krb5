/*
 * $Source$
 * $Author$
 * $Header$
 *
 * Copyright 1987, 1988 by the Massachusetts Institute of Technology. 
 *
 * For copying and distribution information, please see the file
 * <mit-copyright.h>. 
 *
 * Include file for the Kerberos Key Distribution Center. 
 */

#include <mit-copyright.h>

#ifndef KDC_DEFS
#define KDC_DEFS

#define S_AD_SZ		sizeof(struct sockaddr_in)

#define max(a,b)	(a>b ? a : b)
#define min(a,b)	(a<b ? a : b)

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

