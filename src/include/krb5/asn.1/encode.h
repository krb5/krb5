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

#define encode_krb5_as_req(req, error) \
    encode_generic(req, error, \
		   encode_KRB5_AS__REQ, \
		   krb5_as_req2KRB5_AS__REQ, \
		   free_KRB5_AS__REQ)
#define decode_krb5_as_req(req, error) \
    (krb5_as_req *) \
    decode_generic(req, error, \
		   decode_KRB5_AS__REQ, \
		   KRB5_AS__REQ2krb5_as_req, \
		   free_KRB5_AS__REQ)

#define encode_krb5_as_rep(req, error) \
    encode_generic(req, error, \
		   encode_KRB5_KDC__REP, \
		   krb5_as_rep2KRB5_KDC__REP, \
		   free_KRB5_KDC__REP)
#define decode_krb5_as_rep(req, error) \
    (krb5_kdc_rep *) \
    decode_generic(req, error, \
		   decode_KRB5_KDC__REP, \
		   KRB5_KDC__REP2krb5_as_rep, \
		   free_KRB5_KDC__REP)

#define encode_krb5_tgs_rep(req, error) \
    encode_generic(req, error, \
		   encode_KRB5_KDC__REP, \
		   krb5_tgs_rep2KRB5_KDC__REP, \
		   free_KRB5_KDC__REP)
#define decode_krb5_tgs_rep(req, error) \
    (krb5_kdc_rep *) \
    decode_generic(req, error, \
		   decode_KRB5_KDC__REP, \
		   KRB5_KDC__REP2krb5_tgs_rep, \
		   free_KRB5_KDC__REP)


#define encode_krb5_ap_req(req, error) \
    encode_generic(req, error, \
		   encode_KRB5_AP__REQ, \
		   krb5_ap_req2KRB5_AP__REQ, \
		   free_KRB5_AP__REQ)
#define decode_krb5_ap_req(req, error) \
    (krb5_ap_req *) \
    decode_generic(req, error, \
		   decode_KRB5_AP__REQ, \
		   KRB5_AP__REQ2krb5_ap_req, \
		   free_KRB5_AP__REQ)

#define encode_krb5_ap_rep(req, error) \
    encode_generic(req, error, \
		   encode_KRB5_AP__REP, \
		   krb5_ap_rep2KRB5_AP__REP, \
		   free_KRB5_AP__REP)
#define decode_krb5_ap_rep(req, error) \
    (krb5_ap_rep *) \
    decode_generic(req, error, \
		   decode_KRB5_AP__REP, \
		   KRB5_AP__REP2krb5_ap_rep, \
		   free_KRB5_AP__REP)

#define encode_krb5_tgs_req(req, error) \
    encode_generic(req, error, \
		   encode_KRB5_TGS__REQ, \
		   krb5_tgs_req2KRB5_TGS__REQ, \
		   free_KRB5_TGS__REQ)
#define decode_krb5_tgs_req(req, error) \
    (krb5_tgs_req *) \
    decode_generic(req, error, \
		   decode_KRB5_TGS__REQ, \
		   KRB5_TGS__REQ2krb5_tgs_req, \
		   free_KRB5_TGS__REQ)

#define encode_krb5_safe(req, error) \
    encode_generic(req, error, \
		   encode_KRB5_KRB__SAFE, \
		   krb5_safe2KRB5_KRB__SAFE, \
		   free_KRB5_KRB__SAFE)
#define decode_krb5_safe(req, error) \
    (krb5_safe *) \
    decode_generic(req, error, \
		   decode_KRB5_KRB__SAFE, \
		   KRB5_KRB__SAFE2krb5_safe, \
		   free_KRB5_KRB__SAFE)

#define encode_krb5_priv(req, error) \
    encode_generic(req, error, \
		   encode_KRB5_KRB__PRIV, \
		   krb5_priv2KRB5_KRB__PRIV, \
		   free_KRB5_KRB__PRIV)
#define decode_krb5_priv(req, error) \
    (krb5_priv *) \
    decode_generic(req, error, \
		   decode_KRB5_KRB__PRIV, \
		   KRB5_KRB__PRIV2krb5_priv, \
		   free_KRB5_KRB__PRIV)

#define encode_krb5_error(req, error) \
    encode_generic(req, error, \
		   encode_KRB5_KRB__ERROR, \
		   krb5_error2KRB5_KRB__ERROR, \
		   free_KRB5_KRB__ERROR)
#define decode_krb5_error(req, error) \
    (krb5_error *) \
    decode_generic(req, error, \
		   decode_KRB5_KRB__ERROR, \
		   KRB5_KRB__ERROR2krb5_error, \
		   free_KRB5_KRB__ERROR)


#endif /* __KRB5_ENCODE_DEFS__ */
