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
 * Function prototypes for asn1 glue routines.
 */

#include <krb5/copyright.h>

#ifndef KRB5_ASN1DEFS__
#define KRB5_ASN1DEFS__

/* asn1glue.c */
struct type_UNIV_UTCTime *unix2utctime
	PROTOTYPE((const int ,
		   int * ));
long utctime2unix
	PROTOTYPE((const struct type_UNIV_UTCTime *,
		   int * ));
struct type_KRB5_Checksum *krb5_checksum2KRB5_Checksum
	PROTOTYPE((const krb5_checksum *,
		   int * ));
krb5_checksum *KRB5_Checksum2krb5_checksum
	PROTOTYPE((const struct type_KRB5_Checksum *,
		   int * ));
struct type_KRB5_EncryptionKey *krb5_keyblock2KRB5_EncryptionKey
	PROTOTYPE((const krb5_keyblock *,
		   int * ));
krb5_keyblock *KRB5_EncryptionKey2krb5_keyblock
	PROTOTYPE((const struct type_KRB5_EncryptionKey *,
		   int * ));
struct type_KRB5_TicketFlags *krb5_flags2KRB5_TicketFlags
	PROTOTYPE((const krb5_flags ,
		   int * ));
krb5_flags KRB5_TicketFlags2krb5_flags
	PROTOTYPE((const struct type_KRB5_TicketFlags *,
		   int * ));
krb5_data *qbuf2krb5_data
	PROTOTYPE((const struct qbuf *,
		   int * ));
struct type_KRB5_PrincipalName *krb5_principal2KRB5_PrincipalName
	PROTOTYPE((const krb5_principal ,
		   int * ));
krb5_principal KRB5_PrincipalName2krb5_principal
	PROTOTYPE((const struct type_KRB5_PrincipalName *,
		   const struct type_KRB5_Realm *,
		   int * ));
struct type_KRB5_Authenticator *krb5_authenticator2KRB5_Authenticator
	PROTOTYPE((const krb5_authenticator *,
		   int * ));
krb5_authenticator *KRB5_Authenticator2krb5_authenticator
	PROTOTYPE((const struct type_KRB5_Authenticator *,
		   int * ));
struct type_KRB5_HostAddresses *krb5_address2KRB5_HostAddresses
	PROTOTYPE((krb5_address * const *,
		   int * ));
krb5_address **KRB5_HostAddresses2krb5_address
	PROTOTYPE((const struct type_KRB5_HostAddresses *,
		   int * ));
struct type_KRB5_HostAddress *krb5_addr2KRB5_HostAddress
	PROTOTYPE((krb5_address const *,
		   int * ));
krb5_address *KRB5_HostAddress2krb5_addr
	PROTOTYPE((const struct type_KRB5_HostAddress *,
		   int * ));
struct type_KRB5_AuthorizationData *krb5_authdata2KRB5_AuthorizationData
	PROTOTYPE((krb5_authdata * const *,
		   int * ));
krb5_authdata **KRB5_AuthorizationData2krb5_authdata
	PROTOTYPE((const struct type_KRB5_AuthorizationData *,
		   int * ));
struct type_KRB5_EncTicketPart *krb5_enc_tkt_part2KRB5_EncTicketPart
	PROTOTYPE((const krb5_enc_tkt_part *,
		   int * ));
krb5_enc_tkt_part *KRB5_EncTicketPart2krb5_enc_tkt_part
	PROTOTYPE((const struct type_KRB5_EncTicketPart *,
		   int * ));
struct type_KRB5_Ticket *krb5_ticket2KRB5_Ticket
	PROTOTYPE((const krb5_ticket *,
		   int * ));
krb5_ticket *KRB5_Ticket2krb5_ticket
	PROTOTYPE((const struct type_KRB5_Ticket *,
		   int * ));
struct type_KRB5_AS__REQ *krb5_as_req2KRB5_AS__REQ
	PROTOTYPE((const krb5_as_req *,
		   int * ));
krb5_as_req *KRB5_AS__REQ2krb5_as_req
	PROTOTYPE((const struct type_KRB5_AS__REQ *,
		   int * ));
struct type_KRB5_KDC__REP *krb5_as_rep2KRB5_KDC__REP
	PROTOTYPE((const krb5_kdc_rep *,
		   int * ));
struct type_KRB5_KDC__REP *krb5_tgs_rep2KRB5_KDC__REP
	PROTOTYPE((const krb5_kdc_rep *,
		   int * ));
struct type_KRB5_KDC__REP *krb5_kdc_rep2KRB5_KDC__REP
	PROTOTYPE((const krb5_kdc_rep *,
		   const krb5_msgtype,
		   int * ));
krb5_kdc_rep *KRB5_KDC__REP2krb5_kdc_rep
	PROTOTYPE((const struct type_KRB5_KDC__REP *,
		   krb5_msgtype *,
		   int * ));
krb5_kdc_rep *KRB5_KDC__REP2krb5_as_rep
	PROTOTYPE((const struct type_KRB5_KDC__REP *,
		   int * ));
krb5_kdc_rep *KRB5_KDC__REP2krb5_tgs_rep
	PROTOTYPE((const struct type_KRB5_KDC__REP *,
		   int * ));
struct type_KRB5_LastReq *krb5_last_req2KRB5_LastReq
	PROTOTYPE((krb5_last_req_entry * const *,
		   int * ));
krb5_last_req_entry **KRB5_LastReq2krb5_last_req
	PROTOTYPE((const struct type_KRB5_LastReq *,
		   int * ));
struct type_KRB5_EncKDCRepPart *krb5_enc_kdc_rep_part2KRB5_EncKDCRepPart
	PROTOTYPE((const krb5_enc_kdc_rep_part *,
		   int * ));
krb5_enc_kdc_rep_part *KRB5_EncKDCRepPart2krb5_enc_kdc_rep_part
	PROTOTYPE((const struct type_KRB5_EncKDCRepPart *,
		   int * ));
struct type_KRB5_KRB__ERROR *krb5_error2KRB5_KRB__ERROR
	PROTOTYPE((const krb5_error *,
		   int * ));
krb5_error *KRB5_KRB__ERROR2krb5_error
	PROTOTYPE((const struct type_KRB5_KRB__ERROR *,
		   int * ));
struct type_KRB5_AP__REQ *krb5_ap_req2KRB5_AP__REQ
	PROTOTYPE((const krb5_ap_req *,
		   int * ));
krb5_ap_req *KRB5_AP__REQ2krb5_ap_req
	PROTOTYPE((const struct type_KRB5_AP__REQ *,
		   int * ));
struct type_KRB5_AP__REP *krb5_ap_rep2KRB5_AP__REP
	PROTOTYPE((const krb5_ap_rep *,
		   int * ));
krb5_ap_rep *KRB5_AP__REP2krb5_ap_rep
	PROTOTYPE((const struct type_KRB5_AP__REP *,
		   int * ));
struct type_KRB5_EncAPRepPart *krb5_ap_rep_enc_part2KRB5_EncAPRepPart
	PROTOTYPE((const krb5_ap_rep_enc_part *,
		   int * ));
krb5_ap_rep_enc_part *KRB5_EncAPRepPart2krb5_ap_rep_enc_part
	PROTOTYPE((const struct type_KRB5_EncAPRepPart *,
		   int * ));
struct type_KRB5_TGS__REQ *krb5_tgs_req2KRB5_TGS__REQ
	PROTOTYPE((const krb5_tgs_req *,
		   int * ));
krb5_tgs_req *KRB5_TGS__REQ2krb5_tgs_req
	PROTOTYPE((const struct type_KRB5_TGS__REQ *,
		   int * ));
struct type_KRB5_RealTGS__REQ *krb5_real_tgs_req2KRB5_RealTGS__REQ
	PROTOTYPE((const krb5_real_tgs_req *,
		   int * ));
krb5_real_tgs_req *KRB5_RealTGS__REQ2krb5_real_tgs_req
	PROTOTYPE((const struct type_KRB5_RealTGS__REQ *,
		   int * ));
struct type_KRB5_EncTgsReqPart *krb5_tgs_req_enc_part2KRB5_EncTgsReqPart
	PROTOTYPE((const krb5_tgs_req_enc_part *,
		   int * ));
krb5_tgs_req_enc_part *KRB5_EncTgsReqPart2krb5_tgs_req_enc_part
	PROTOTYPE((const struct type_KRB5_EncTgsReqPart *,
		   int * ));
struct type_KRB5_KRB__SAFE *krb5_safe2KRB5_KRB__SAFE
	PROTOTYPE((const krb5_safe *,
		   int * ));
krb5_safe *KRB5_KRB__SAFE2krb5_safe
	PROTOTYPE((const struct type_KRB5_KRB__SAFE *,
		   int * ));
struct type_KRB5_KRB__PRIV *krb5_priv2KRB5_KRB__PRIV
	PROTOTYPE((const krb5_priv *,
		   int * ));
krb5_priv *KRB5_KRB__PRIV2krb5_priv
	PROTOTYPE((const struct type_KRB5_KRB__PRIV *,
		   int * ));
struct type_KRB5_EncKrbPrivPart *krb5_priv_enc_part2KRB5_EncKrbPrivPart
	PROTOTYPE((const krb5_priv_enc_part *,
		   int * ));
krb5_priv_enc_part *KRB5_EncKrbPrivPart2krb5_priv_enc_part
	PROTOTYPE((const struct type_KRB5_EncKrbPrivPart *,
		   int * ));

struct type_UNIV_GeneralizedTime *unix2gentime
	PROTOTYPE((const int, register int *));
long gentime2unix
	PROTOTYPE((const struct type_UNIV_GeneralizedTime *,
		   int *));

#endif /* KRB5_ASN1DEFS__ */
