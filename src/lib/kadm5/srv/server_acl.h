/*
 * kadmin/v5server/kadm5_defs.h
 *
 * Copyright 1995 by the Massachusetts Institute of Technology.
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
 * permission.  M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 *
 */

#ifndef	SERVER_ACL_H__
#define	SERVER_ACL_H__

/*
 * Debug definitions.
 */
#define	DEBUG_SPROC	1
#define	DEBUG_OPERATION	2
#define	DEBUG_HOST	4
#define	DEBUG_REALM	8
#define	DEBUG_REQUESTS	16
#define	DEBUG_ACL	32
#define	DEBUG_PROTO	64
#define	DEBUG_CALLS	128
#define	DEBUG_NOSLAVES	256
#ifdef	DEBUG
#define	DPRINT(l1, cl, al)	if ((cl & l1) != 0) xprintf al
#else	/* DEBUG */
#define	DPRINT(l1, cl, al)
#endif	/* DEBUG */
#define	DLOG(l1, cl, msg)	if ((cl & l1) != 0)	\
					com_err(programname, 0, msg)

/*
 * Access control bits.
 */
#define	ACL_ADD			1
#define	ACL_DELETE		2
#define	ACL_MODIFY		4
#define	ACL_CHANGEPW		8
/* #define ACL_CHANGE_OWN_PW	16 */
#define	ACL_INQUIRE		32
/* #define ACL_EXTRACT		64 */
#define	ACL_LIST		128
#define ACL_SETKEY		256
#define	ACL_RENAME		(ACL_ADD+ACL_DELETE)

#define	ACL_ALL_MASK		(ACL_ADD	| \
				 ACL_DELETE	| \
				 ACL_MODIFY	| \
				 ACL_CHANGEPW	| \
				 ACL_INQUIRE	| \
				 ACL_LIST	| \
				 ACL_SETKEY)

krb5_error_code acl_init
	KRB5_PROTOTYPE((krb5_context,
		   int,
		   char *));
void acl_finish
	KRB5_PROTOTYPE((krb5_context,
		   int));
krb5_boolean acl_check
	KRB5_PROTOTYPE((krb5_context,
		   gss_name_t,
		   krb5_int32,
		   krb5_principal));

#endif	/* SERVER_ACL_H__ */
