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
 * <<< Description >>>
 */

#include <krb5/copyright.h>

#ifndef __KRB5_ASN1DEFS__
#define __KRB5_ASN1DEFS__

/* asn1glue.c */
struct type_UNIV_UTCTime *unix2utctime
	PROTOTYPE((int ,
		   int * ));
long utctime2unix
	PROTOTYPE((struct type_UNIV_UTCTime *,
		   int * ));
struct type_KRB5_Checksum *krb5_checksum2KRB5_Checksum
	PROTOTYPE((krb5_checksum *,
		   int * ));
krb5_checksum *KRB5_Checksum2krb5_checksum
	PROTOTYPE((struct type_KRB5_Checksum *,
		   int * ));
struct type_KRB5_EncryptionKey *krb5_keyblock2KRB5_EncryptionKey
	PROTOTYPE((krb5_keyblock *,
		   int * ));
krb5_keyblock *KRB5_EncryptionKey2krb5_keyblock
	PROTOTYPE((struct type_KRB5_EncryptionKey *,
		   int * ));
struct type_KRB5_TicketFlags *krb5_flags2KRB5_TicketFlags
	PROTOTYPE((krb5_flags ,
		   int * ));
krb5_flags KRB5_TicketFlags2krb5_flags
	PROTOTYPE((struct type_KRB5_TicketFlags *,
		   int * ));
krb5_data *qbuf2krb5_data
	PROTOTYPE((struct qbuf *,
		   int * ));
struct type_KRB5_PrincipalName *krb5_principal2KRB5_PrincipalName
	PROTOTYPE((krb5_principal ,
		   int * ));
krb5_principal KRB5_PrincipalName2krb5_principal
	PROTOTYPE((struct type_KRB5_PrincipalName *,
		   struct type_KRB5_Realm *,
		   int * ));
struct type_KRB5_Authenticator *krb5_authenticator2KRB5_Authenticator
	PROTOTYPE((krb5_authenticator *,
		   int * ));
krb5_authenticator *KRB5_Authenticator2krb5_authenticator
	PROTOTYPE((struct type_KRB5_Authenticator *,
		   int * ));
struct type_KRB5_HostAddresses *krb5_address2KRB5_HostAddresses
	PROTOTYPE((krb5_address **,
		   int * ));
krb5_address **KRB5_HostAddresses2krb5_address
	PROTOTYPE((struct type_KRB5_HostAddresses *,
		   int * ));
struct type_KRB5_AuthorizationData *krb5_authdata2KRB5_AuthorizationData
	PROTOTYPE((krb5_authdata **,
		   int * ));
krb5_authdata **KRB5_AuthorizationData2krb5_authdata
	PROTOTYPE((struct type_KRB5_AuthorizationData *,
		   int * ));
struct type_KRB5_EncTicketPart *krb5_enc_tkt_part2KRB5_EncTicketPart
	PROTOTYPE((krb5_enc_tkt_part *,
		   int * ));
krb5_enc_tkt_part *KRB5_EncTicketPart2krb5_enc_tkt_part
	PROTOTYPE((struct type_KRB5_EncTicketPart *,
		   int * ));
struct type_KRB5_Ticket *krb5_ticket2KRB5_Ticket
	PROTOTYPE((krb5_ticket *,
		   int * ));
krb5_ticket *KRB5_Ticket2krb5_ticket
	PROTOTYPE((struct type_KRB5_Ticket *,
		   int * ));
struct type_KRB5_AS__REQ *krb5_as_req2KRB5_AS__REQ
	PROTOTYPE((krb5_as_req *,
		   int * ));
krb5_as_req *KRB5_AS__REQ2krb5_as_req
	PROTOTYPE((struct type_KRB5_AS__REQ *,
		   int * ));
struct type_KRB5_KDC__REP *krb5_as_rep2KRB5_KDC__REP
	PROTOTYPE((krb5_kdc_rep *,
		   int * ));
struct type_KRB5_KDC__REP *krb5_tgs_rep2KRB5_KDC__REP
	PROTOTYPE((krb5_kdc_rep *,
		   int * ));
krb5_kdc_rep *KRB5_KDC__REP2krb5_kdc_rep
	PROTOTYPE((struct type_KRB5_KDC__REP *,
		   krb5_msgtype *,
		   int * ));
krb5_kdc_rep *KRB5_KDC__REP2krb5_as_rep
	PROTOTYPE((struct type_KRB5_KDC__REP *,
		   int * ));
krb5_kdc_rep *KRB5_KDC__REP2krb5_tgs_rep
	PROTOTYPE((struct type_KRB5_KDC__REP *,
		   int * ));
struct type_KRB5_LastReq *krb5_last_req2KRB5_LastReq
	PROTOTYPE((krb5_last_req_entry **,
		   int * ));
krb5_last_req_entry **KRB5_LastReq2krb5_last_req
	PROTOTYPE((struct type_KRB5_LastReq *,
		   int * ));
struct type_KRB5_EncKDCRepPart *krb5_enc_kdc_rep_part2KRB5_EncKDCRepPart
	PROTOTYPE((krb5_enc_kdc_rep_part *,
		   int * ));
krb5_enc_kdc_rep_part *KRB5_EncKDCRepPart2krb5_enc_kdc_rep_part
	PROTOTYPE((struct type_KRB5_EncKDCRepPart *,
		   int * ));
struct type_KRB5_KRB__ERROR *krb5_error2KRB5_KRB__ERROR
	PROTOTYPE((krb5_error *,
		   int * ));
krb5_error *KRB5_KRB__ERROR2krb5_error
	PROTOTYPE((struct type_KRB5_KRB__ERROR *,
		   int * ));
struct type_KRB5_AP__REQ *krb5_ap_req2KRB5_AP__REQ
	PROTOTYPE((krb5_ap_req *,
		   int * ));
krb5_ap_req *KRB5_AP__REQ2krb5_ap_req
	PROTOTYPE((struct type_KRB5_AP__REQ *,
		   int * ));
struct type_KRB5_AP__REP *krb5_ap_rep2KRB5_AP__REP
	PROTOTYPE((krb5_ap_rep *,
		   int * ));
krb5_ap_rep *KRB5_AP__REP2krb5_ap_rep
	PROTOTYPE((struct type_KRB5_AP__REP *,
		   int * ));
struct type_KRB5_EncAPRepPart *krb5_ap_rep_enc_part2KRB5_EncAPRepPart
	PROTOTYPE((krb5_ap_rep_enc_part *,
		   int * ));
krb5_ap_rep_enc_part *KRB5_EncAPRepPart2krb5_ap_rep_enc_part
	PROTOTYPE((struct type_KRB5_EncAPRepPart *,
		   int * ));
struct type_KRB5_TGS__REQ *krb5_tgs_req2KRB5_TGS__REQ
	PROTOTYPE((krb5_tgs_req *,
		   int * ));
krb5_tgs_req *KRB5_TGS__REQ2krb5_tgs_req
	PROTOTYPE((struct type_KRB5_TGS__REQ *,
		   int * ));
struct type_KRB5_RealTGS__REQ *krb5_real_tgs_req2KRB5_RealTGS__REQ
	PROTOTYPE((krb5_real_tgs_req *,
		   int * ));
krb5_real_tgs_req *KRB5_RealTGS__REQ2krb5_real_tgs_req
	PROTOTYPE((struct type_KRB5_RealTGS__REQ *,
		   int * ));
struct type_KRB5_EncTgsReqPart *krb5_tgs_req_enc_part2KRB5_EncTgsReqPart
	PROTOTYPE((krb5_tgs_req_enc_part *,
		   int * ));
krb5_tgs_req_enc_part *KRB5_EncTgsReqPart2krb5_tgs_req_enc_part
	PROTOTYPE((struct type_KRB5_EncTgsReqPart *,
		   int * ));
struct type_KRB5_KRB__SAFE *krb5_safe2KRB5_KRB__SAFE
	PROTOTYPE((krb5_safe *,
		   int * ));
krb5_safe *KRB5_KRB__SAFE2krb5_safe
	PROTOTYPE((struct type_KRB5_KRB__SAFE *,
		   int * ));
struct type_KRB5_KRB__PRIV *krb5_priv2KRB5_KRB__PRIV
	PROTOTYPE((krb5_priv *,
		   int * ));
krb5_priv *KRB5_KRB__PRIV2krb5_priv
	PROTOTYPE((struct type_KRB5_KRB__PRIV *,
		   int * ));
struct type_KRB5_EncKrbPrivPart *krb5_priv_enc_part2KRB5_EncKrbPrivPart
	PROTOTYPE((krb5_priv_enc_part *,
		   int * ));
krb5_priv_enc_part *KRB5_EncKrbPrivPart2krb5_priv_enc_part
	PROTOTYPE((struct type_KRB5_EncKrbPrivPart *,
		   int * ));

#endif /* __KRB5_ASN1DEFS__ */
