/*
 * $Source$
 * $Author$
 * $Id$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>.
 *
 * #defines for using generic encoder routine.
 */

#include <krb5/copyright.h>

#ifndef KRB5_ENCODE_DEFS__
#define KRB5_ENCODE_DEFS__

typedef	int (*encoder_func) PROTOTYPE((PE *, int, int, char *, krb5_pointer));
typedef void (*free_func) PROTOTYPE((krb5_pointer ));
typedef krb5_pointer (*translator_func) PROTOTYPE((krb5_pointer, int * ));
typedef int (*decoder_func) PROTOTYPE((PE, int, int, char *, krb5_pointer));

/* encode.c */
krb5_error_code krb5_encode_generic
    PROTOTYPE((const krb5_pointer,
	       krb5_data **,
	       int (* )PROTOTYPE ((PE *,int,int,char *,krb5_pointer )),
	       krb5_pointer (* )PROTOTYPE ((krb5_pointer,int *)),
	       void (* )PROTOTYPE ((krb5_pointer ))));
krb5_error_code krb5_decode_generic
	PROTOTYPE((const krb5_data *,
		   krb5_pointer *,
		   int (* )PROTOTYPE ((PE,int,int,char *,krb5_pointer )),
		   krb5_pointer (* )PROTOTYPE ((krb5_pointer,int *)),
		   void (* )PROTOTYPE ((krb5_pointer ))));

#define encode_krb5_authenticator(pauth, output) \
    krb5_encode_generic((krb5_pointer)pauth,  output, \
		   (encoder_func) encode_KRB5_Authenticator, \
		   (translator_func) krb5_authenticator2KRB5_Authenticator, \
		   (free_func) free_KRB5_Authenticator)
#define decode_krb5_authenticator(pauth, output) \
    krb5_decode_generic(pauth, (krb5_pointer *) output, \
		   (decoder_func) decode_KRB5_Authenticator, \
		   (translator_func) KRB5_Authenticator2krb5_authenticator, \
		   (free_func) free_KRB5_Authenticator)
						
#define encode_krb5_ticket(ptick, output) \
    krb5_encode_generic((krb5_pointer)ptick,  output, \
		   (encoder_func) encode_KRB5_Ticket, \
		   (translator_func) krb5_ticket2KRB5_Ticket, \
		   (free_func) free_KRB5_Ticket)
#define decode_krb5_ticket(ptick, output) \
    krb5_decode_generic(ptick, (krb5_pointer *) output, \
		   (decoder_func) decode_KRB5_Ticket, \
		   (translator_func) KRB5_Ticket2krb5_ticket, \
		   (free_func) free_KRB5_Ticket)

#define encode_krb5_enc_tkt_part(ptick, output) \
    krb5_encode_generic((krb5_pointer)ptick,  output, \
		   (encoder_func) encode_KRB5_EncTicketPart, \
		   (translator_func) krb5_enc_tkt_part2KRB5_EncTicketPart, \
		   (free_func) free_KRB5_EncTicketPart)
#define decode_krb5_enc_tkt_part(ptick, output) \
    krb5_decode_generic(ptick, (krb5_pointer *) output, \
		   (decoder_func) decode_KRB5_EncTicketPart, \
		   (translator_func) KRB5_EncTicketPart2krb5_enc_tkt_part, \
		   (free_func) free_KRB5_EncTicketPart)

#define encode_krb5_as_req(req, output) \
    krb5_encode_generic((krb5_pointer)req, output, \
		   (encoder_func) encode_KRB5_AS__REQ, \
		   (translator_func) krb5_kdc_req2KRB5_TGS__REQ, \
		   (free_func) free_KRB5_AS__REQ)
#define decode_krb5_as_req(req, output) \
    krb5_decode_generic(req, (krb5_pointer *) output, \
		   (decoder_func) decode_KRB5_AS__REQ, \
		   (translator_func) KRB5_TGS__REQ2krb5_kdc_req, \
		   (free_func) free_KRB5_AS__REQ)

#define encode_krb5_as_rep(req, output) \
    krb5_encode_generic((krb5_pointer)req, output, \
		   (encoder_func) encode_KRB5_KDC__REP, \
		   (translator_func) krb5_as_rep2KRB5_KDC__REP, \
		   (free_func) free_KRB5_KDC__REP)
#define decode_krb5_as_rep(req, output) \
    krb5_decode_generic(req, (krb5_pointer *) output, \
		   (decoder_func) decode_KRB5_KDC__REP, \
		   (translator_func) KRB5_KDC__REP2krb5_as_rep, \
		   (free_func) free_KRB5_KDC__REP)

#define encode_krb5_enc_kdc_rep_part(req, output) \
    krb5_encode_generic((krb5_pointer)req, output, \
		   (encoder_func) encode_KRB5_EncKDCRepPart, \
		   (translator_func) krb5_enc_kdc_rep_part2KRB5_EncKDCRepPart, \
		   (free_func) free_KRB5_EncKDCRepPart)
#define decode_krb5_enc_kdc_rep_part(req, output) \
    krb5_decode_generic(req, (krb5_pointer *) output, \
		   (decoder_func) decode_KRB5_EncKDCRepPart, \
		   (translator_func) KRB5_EncKDCRepPart2krb5_enc_kdc_rep_part, \
		   (free_func) free_KRB5_EncKDCRepPart)

#define encode_krb5_tgs_rep(req, output) \
    krb5_encode_generic((krb5_pointer)req, output, \
		   (encoder_func) encode_KRB5_KDC__REP, \
		   (translator_func) krb5_tgs_rep2KRB5_KDC__REP, \
		   (free_func) free_KRB5_KDC__REP)
#define decode_krb5_tgs_rep(req, output) \
    krb5_decode_generic(req, (krb5_pointer *) output, \
		   (decoder_func) decode_KRB5_KDC__REP, \
		   (translator_func) KRB5_KDC__REP2krb5_tgs_rep, \
		   (free_func) free_KRB5_KDC__REP)

#define encode_krb5_ap_req(req, output) \
    krb5_encode_generic((krb5_pointer)req,  output, \
		   (encoder_func) encode_KRB5_AP__REQ, \
		   (translator_func) krb5_ap_req2KRB5_AP__REQ, \
		   (free_func) free_KRB5_AP__REQ)
#define decode_krb5_ap_req(req, output) \
    krb5_decode_generic(req, (krb5_pointer *) output, \
		   (decoder_func) decode_KRB5_AP__REQ, \
		   (translator_func) KRB5_AP__REQ2krb5_ap_req, \
		   (free_func) free_KRB5_AP__REQ)

#define encode_krb5_ap_rep(reply, output) \
    krb5_encode_generic((krb5_pointer)reply, output, \
		   (encoder_func) encode_KRB5_AP__REP, \
		   (translator_func) krb5_ap_rep2KRB5_AP__REP, \
		   (free_func) free_KRB5_AP__REP)
#define decode_krb5_ap_rep(reply, output) \
    krb5_decode_generic(reply, (krb5_pointer *) output, \
		   (decoder_func) decode_KRB5_AP__REP, \
		   (translator_func) KRB5_AP__REP2krb5_ap_rep, \
		   (free_func) free_KRB5_AP__REP)

#define encode_krb5_ap_rep_enc_part(rpart, output) \
    krb5_encode_generic((krb5_pointer)rpart, output, \
		   (encoder_func) encode_KRB5_EncAPRepPart, \
		   (translator_func) krb5_ap_rep_enc_part2KRB5_EncAPRepPart, \
		   (free_func) free_KRB5_EncAPRepPart)
#define decode_krb5_ap_rep_enc_part(rpart, output) \
    krb5_decode_generic(rpart, (krb5_pointer *) output, \
		    (decoder_func) decode_KRB5_EncAPRepPart, \
		    (translator_func) KRB5_EncAPRepPart2krb5_ap_rep_enc_part, \
		    (free_func) free_KRB5_EncAPRepPart)

#define encode_krb5_tgs_req(req, output) \
    krb5_encode_generic((krb5_pointer)req, output, \
		   (encoder_func) encode_KRB5_TGS__REQ, \
		   (translator_func) krb5_kdc_req2KRB5_TGS__REQ, \
		   (free_func) free_KRB5_TGS__REQ)
#define decode_krb5_tgs_req(req, output) \
    krb5_decode_generic(req, (krb5_pointer *) output, \
		   (decoder_func) decode_KRB5_TGS__REQ, \
		   (translator_func) KRB5_TGS__REQ2krb5_kdc_req, \
		   (free_func) free_KRB5_TGS__REQ)

#define encode_krb5_safe(req, output) \
    krb5_encode_generic((krb5_pointer)req, output, \
		   (encoder_func) encode_KRB5_KRB__SAFE, \
		   (translator_func) krb5_safe2KRB5_KRB__SAFE, \
		   (free_func) free_KRB5_KRB__SAFE)
#define decode_krb5_safe(req, output) \
    krb5_decode_generic(req, (krb5_pointer *) output, \
		   (decoder_func) decode_KRB5_KRB__SAFE, \
		   (translator_func) KRB5_KRB__SAFE2krb5_safe, \
		   (free_func) free_KRB5_KRB__SAFE)

#define encode_krb5_priv(req, output) \
    krb5_encode_generic((krb5_pointer)req, output, \
		   (encoder_func) encode_KRB5_KRB__PRIV, \
		   (translator_func) krb5_priv2KRB5_KRB__PRIV, \
		   (free_func) free_KRB5_KRB__PRIV)
#define decode_krb5_priv(req, output) \
    krb5_decode_generic(req, (krb5_pointer *) output, \
		   (decoder_func) decode_KRB5_KRB__PRIV, \
		   (translator_func) KRB5_KRB__PRIV2krb5_priv, \
		   (free_func) free_KRB5_KRB__PRIV)

#define encode_krb5_enc_priv_part(req, output) \
    krb5_encode_generic((krb5_pointer)req, output, \
		   (encoder_func) encode_KRB5_EncKrbPrivPart, \
		   (translator_func) krb5_priv_enc_part2KRB5_EncKrbPrivPart, \
		   (free_func) free_KRB5_EncKrbPrivPart)
#define decode_krb5_enc_priv_part(req, output) \
    krb5_decode_generic(req, (krb5_pointer *) output, \
		   (decoder_func) decode_KRB5_EncKrbPrivPart, \
		   (translator_func) KRB5_EncKrbPrivPart2krb5_priv_enc_part, \
		   (free_func) free_KRB5_EncKrbPrivPart)

#define encode_krb5_error(req, output) \
    krb5_encode_generic((krb5_pointer)req, output, \
		   (encoder_func) encode_KRB5_KRB__ERROR, \
		   (translator_func) krb5_error2KRB5_KRB__ERROR, \
		   (free_func) free_KRB5_KRB__ERROR)
#define decode_krb5_error(req, output) \
    krb5_decode_generic(req, (krb5_pointer *) output, \
		   (decoder_func) decode_KRB5_KRB__ERROR, \
		   (translator_func) KRB5_KRB__ERROR2krb5_error, \
		   (free_func) free_KRB5_KRB__ERROR)

/* ASN.1 encoding knowledge; KEEP IN SYNC WITH ASN.1 defs! */
/* here we use some knowledge of ASN.1 encodings */
/* 
  AS_REQ is APPLICATION 0.
  KDC_REP is APPLICATION 1.
  KRB_ERROR is APPLICATION 2.
  AP_REQ is APPLICATION 3.
  AP_REP is APPLICATION 4.
  TGS_REQ is APPLICATION 5.
  KRB_SAFE is APPLICATION 6.
  KRB_PRIV is APPLICATION 7.
  Authenticator is APPLICATION 8.
  EncTicketPart is APPLICATION 9.
  Ticket is APPLICATION 10.
  EncKDCRepPart is APPLICATION 11.
  EncAPRepPart is APPLICATION 12.
  RealTGS-REQ is APPLICATION 13.
  EncTgsReqPart is APPLICATION 14.
  EncKrbPrivPart is APPLICATION 15.
 */
/* allow either constructed or primitive encoding, so check for bit 6
   set or reset */
#define krb5_is_as_req(dat)\
	((dat) && (dat)->length && ((dat)->data[0] == 0x60 ||\
				    (dat)->data[0] == 0x20))
#define krb5_is_kdc_rep(dat)\
	((dat) && (dat)->length && ((dat)->data[0] == 0x61 ||\
				    (dat)->data[0] == 0x21))
#define krb5_is_krb_error(dat)\
	((dat) && (dat)->length && ((dat)->data[0] == 0x62 ||\
				    (dat)->data[0] == 0x22))
#define krb5_is_ap_req(dat)\
	((dat) && (dat)->length && ((dat)->data[0] == 0x63 ||\
				    (dat)->data[0] == 0x23))
#define krb5_is_ap_rep(dat)\
	((dat) && (dat)->length && ((dat)->data[0] == 0x64 ||\
				    (dat)->data[0] == 0x24))
#define krb5_is_tgs_req(dat)\
	((dat) && (dat)->length && ((dat)->data[0] == 0x65 ||\
				    (dat)->data[0] == 0x25))
#define krb5_is_krb_safe(dat)\
	((dat) && (dat)->length && ((dat)->data[0] == 0x66 ||\
				    (dat)->data[0] == 0x26))
#define krb5_is_krb_priv(dat)\
	((dat) && (dat)->length && ((dat)->data[0] == 0x67 ||\
				    (dat)->data[0] == 0x27))
#define krb5_is_krb_authenticator(dat)\
	((dat) && (dat)->length && ((dat)->data[0] == 0x68 ||\
				    (dat)->data[0] == 0x28))
#define krb5_is_krb_enc_tkt_part(dat)\
	((dat) && (dat)->length && ((dat)->data[0] == 0x69 ||\
				    (dat)->data[0] == 0x29))
#define krb5_is_krb_ticket(dat)\
	((dat) && (dat)->length && ((dat)->data[0] == 0x6a ||\
				    (dat)->data[0] == 0x2a))
#define krb5_is_krb_enc_kdc_rep_part(dat)\
	((dat) && (dat)->length && ((dat)->data[0] == 0x6b ||\
				    (dat)->data[0] == 0x2b))
#define krb5_is_krb_enc_ap_rep_part(dat)\
	((dat) && (dat)->length && ((dat)->data[0] == 0x6c ||\
				    (dat)->data[0] == 0x2c))
#define krb5_is_krb_real_tgs_req(dat)\
	((dat) && (dat)->length && ((dat)->data[0] == 0x6d ||\
				    (dat)->data[0] == 0x2d))
#define krb5_is_krb_enc_tgs_req_part(dat)\
	((dat) && (dat)->length && ((dat)->data[0] == 0x6e ||\
				    (dat)->data[0] == 0x2e))
#define krb5_is_krb_enc_krb_priv_part(dat)\
	((dat) && (dat)->length && ((dat)->data[0] == 0x6f ||\
				    (dat)->data[0] == 0x2f))


#endif /* KRB5_ENCODE_DEFS__ */
