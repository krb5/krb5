/*
 * $Source$
 * $Author$
 * $Id$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/mit-copyright.h>.
 *
 * #defines for using generic encoder routine.
 */

#include <krb5/copyright.h>

#ifndef __KRB5_ENCODE_DEFS__
#define __KRB5_ENCODE_DEFS__

#define encode_krb5_authenticator(pauth, error) \
    encode_generic(pauth, error, \
		   encode_KRB5_Authenticator, \
		   krb5_authenticator2KRB5_Authenticator, \
		   free_KRB5_Authenticator)
#define decode_krb5_authenticator(pauth, error) \
    (krb5_authenticator *) \
    decode_generic(pauth, error, \
		   decode_KRB5_Authenticator, \
		   KRB5_Authenticator2krb5_authenticator, \
		   free_KRB5_Authenticator)
						
#define encode_krb5_ticket(ptick, error) \
    encode_generic(ptick, error, \
		   encode_KRB5_Ticket, \
		   krb5_ticket2KRB5_Ticket, \
		   free_KRB5_Ticket)

#define decode_krb5_ticket(ptick, error) \
    (krb5_ticket *) \
    decode_generic(ptick, error, \
		   decode_KRB5_Ticket, \
		   KRB5_Ticket2krb5_ticket, \
		   free_KRB5_Ticket)

#endif /* __KRB5_ENCODE_DEFS__ */
