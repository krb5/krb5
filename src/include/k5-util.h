/*
 * Copyright (C) 1989-1998 by the Massachusetts Institute of Technology,
 * Cambridge, MA, USA.  All Rights Reserved.
 * 
 * This software is being provided to you, the LICENSEE, by the 
 * Massachusetts Institute of Technology (M.I.T.) under the following 
 * license.  By obtaining, using and/or copying this software, you agree 
 * that you have read, understood, and will comply with these terms and 
 * conditions:  
 * 
 * Export of this software from the United States of America may
 * require a specific license from the United States Government.
 * It is the responsibility of any person or organization contemplating
 * export to obtain such a license before exporting.
 * 
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify and distribute 
 * this software and its documentation for any purpose and without fee or 
 * royalty is hereby granted, provided that you agree to comply with the 
 * following copyright notice and statements, including the disclaimer, and 
 * that the same appear on ALL copies of the software and documentation, 
 * including modifications that you make for internal use or for 
 * distribution:
 * 
 * THIS SOFTWARE IS PROVIDED "AS IS", AND M.I.T. MAKES NO REPRESENTATIONS 
 * OR WARRANTIES, EXPRESS OR IMPLIED.  By way of example, but not 
 * limitation, M.I.T. MAKES NO REPRESENTATIONS OR WARRANTIES OF 
 * MERCHANTABILITY OR FITNESS FOR ANY PARTICULAR PURPOSE OR THAT THE USE OF 
 * THE LICENSED SOFTWARE OR DOCUMENTATION WILL NOT INFRINGE ANY THIRD PARTY 
 * PATENTS, COPYRIGHTS, TRADEMARKS OR OTHER RIGHTS.   
 * 
 * The name of the Massachusetts Institute of Technology or M.I.T. may NOT 
 * be used in advertising or publicity pertaining to distribution of the 
 * software.  Title to copyright in this software and any associated 
 * documentation shall at all times remain with M.I.T., and USER agrees to 
 * preserve same.
 *
 * Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.  
 */

/*
 * "internal" utility functions used by various applications.
 * They live in libkrb5util.
 */

int krb5_seteuid(int);
int krb5_setedid(int);
int krb5_setegid(int);

#if defined(KRB_DEFS) && defined(SOCK_DGRAM)
krb5_error_code krb5_compat_recvauth(krb5_context, krb5_auth_context *,
				     krb5_pointer, char *, krb5_principal, 
				     krb5_int32, krb5_keytab,
				     krb5_int32, char *, char *,
				     struct sockaddr_in *, 
				     struct sockaddr_in *, char *,
				     krb5_ticket **, krb5_int32 *, 
				     AUTH_DAT **, Key_schedule, char *);

krb5_error_code
krb5_compat_recvauth_version(krb5_context, krb5_auth_context *,
			     krb5_pointer, krb5_principal, krb5_int32, 
			     krb5_keytab, krb5_int32, char *, char *,
			     struct sockaddr_in *, struct sockaddr_in *,
			     char *, krb5_ticket **, krb5_int32*, 
			     AUTH_DAT **,  Key_schedule, krb5_data *);

#endif
