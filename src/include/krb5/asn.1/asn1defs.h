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
	PROTOTYPE((int val,
		   int *error ));
long utctime2unix
	PROTOTYPE((struct type_UNIV_UTCTime *val,
		   int *error ));
struct type_KRB5_Checksum *krb5_checksum2KRB5_Checksum
	PROTOTYPE((krb5_checksum *val,
		   int *error ));
krb5_checksum *KRB5_Checksum2krb5_checksum
	PROTOTYPE((struct type_KRB5_Checksum *val,
		   int *error ));
struct type_KRB5_EncryptionKey *krb5_keyblock2KRB5_EncryptionKey
	PROTOTYPE((krb5_keyblock *val,
		   int *error ));
krb5_keyblock *KRB5_EncryptionKey2krb5_keyblock
	PROTOTYPE((struct type_KRB5_EncryptionKey *val,
		   int *error ));
struct type_KRB5_TicketFlags *krb5_flags2KRB5_TicketFlags
	PROTOTYPE((krb5_flags val,
		   int *error ));
krb5_flags KRB5_TicketFlags2krb5_flags
	PROTOTYPE((struct type_KRB5_TicketFlags *val,
		   int *error ));
krb5_data *qbuf2krb5_data
	PROTOTYPE((struct qbuf *val,
		   int *error ));
struct type_KRB5_PrincipalName *krb5_principal2KRB5_PrincipalName
	PROTOTYPE((krb5_principal val,
		   int *error ));
void krb5_free_principal
	PROTOTYPE((krb5_principal val ));
krb5_principal KRB5_PrincipalName2krb5_principal
	PROTOTYPE((struct type_KRB5_PrincipalName *val,
		   struct type_KRB5_Realm *realm,
		   int *error ));
struct type_KRB5_Authenticator *krb5_authenticator2KRB5_Authenticator
	PROTOTYPE((krb5_authenticator *val,
		   int *error ));
void krb5_free_authenticator
	PROTOTYPE((krb5_authenticator *val ));
krb5_authenticator *KRB5_Authenticator2krb5_authenticator
	PROTOTYPE((struct type_KRB5_Authenticator *val,
		   int *error ));
struct type_KRB5_HostAddresses *krb5_address2KRB5_HostAddresses
	PROTOTYPE((krb5_address **val,
		   int *error ));
void krb5_free_address
	PROTOTYPE((krb5_address **val ));
krb5_address **KRB5_HostAddresses2krb5_address
	PROTOTYPE((struct type_KRB5_HostAddresses *val,
		   int *error ));
struct type_KRB5_AuthorizationData *krb5_authdata2KRB5_AuthorizationData
	PROTOTYPE((krb5_authdata **val,
		   int *error ));
void krb5_free_authdata
	PROTOTYPE((krb5_authdata **val ));
krb5_authdata **KRB5_AuthorizationData2krb5_authdata
	PROTOTYPE((struct type_KRB5_AuthorizationData *val,
		   int *error ));
struct type_KRB5_EncTicketPart *krb5_enc_tkt_part2KRB5_EncTicketPart
	PROTOTYPE((krb5_enc_tkt_part *val,
		   int *error ));
void krb5_free_enc_tkt_part
	PROTOTYPE((krb5_enc_tkt_part *val ));
krb5_enc_tkt_part *KRB5_EncTicketPart2krb5_enc_tkt_part
	PROTOTYPE((struct type_KRB5_EncTicketPart *val,
		   int *error ));
struct type_KRB5_Ticket *krb5_ticket2KRB5_Ticket
	PROTOTYPE((krb5_ticket *val,
		   int *error ));
void krb5_free_ticket
	PROTOTYPE((krb5_ticket *val ));
krb5_ticket *KRB5_Ticket2krb5_ticket
	PROTOTYPE((struct type_KRB5_Ticket *val,
		   int *error ));
struct type_KRB5_AS__REQ *krb5_as_req2KRB5_AS__REQ
	PROTOTYPE((krb5_as_req *val,
		   int *error ));
void krb5_free_as_req
	PROTOTYPE((krb5_as_req *val ));
krb5_as_req *KRB5_AS__REQ2krb5_as_req
	PROTOTYPE((struct type_KRB5_AS__REQ *val,
		   int *error ));
struct type_KRB5_KDC__REP *krb5_as_rep2KRB5_KDC__REP
	PROTOTYPE((krb5_kdc_rep *val,
		   int *error ));
struct type_KRB5_KDC__REP *krb5_tgs_rep2KRB5_KDC__REP
	PROTOTYPE((krb5_kdc_rep *val,
		   int *error ));
void krb5_free_kdc_rep
	PROTOTYPE((krb5_kdc_rep *val ));
krb5_kdc_rep *KRB5_KDC__REP2krb5_kdc_rep
	PROTOTYPE((struct type_KRB5_KDC__REP *val,
		   int *type,
		   int *error ));
krb5_kdc_rep *KRB5_KDC__REP2krb5_as_rep
	PROTOTYPE((struct type_KRB5_KDC__REP *val,
		   int *error ));
krb5_kdc_rep *KRB5_KDC__REP2krb5_tgs_rep
	PROTOTYPE((struct type_KRB5_KDC__REP *val,
		   int *error ));
struct type_KRB5_LastReq *krb5_last_req2KRB5_LastReq
	PROTOTYPE((krb5_last_req_entry **val,
		   int *error ));
void krb5_free_last_req
	PROTOTYPE((krb5_last_req_entry **val ));
krb5_last_req_entry **KRB5_LastReq2krb5_last_req
	PROTOTYPE((struct type_KRB5_LastReq *val,
		   int *error ));
struct type_KRB5_EncKDCRepPart *krb5_enc_kdc_rep_part2KRB5_EncKDCRepPart
	PROTOTYPE((krb5_enc_kdc_rep_part *val,
		   int *error ));
void krb5_free_enc_kdc_rep_part
	PROTOTYPE((krb5_enc_kdc_rep_part *val ));
krb5_enc_kdc_rep_part *KRB5_EncKDCRepPart2krb5_enc_kdc_rep_part
	PROTOTYPE((struct type_KRB5_EncKDCRepPart *val,
		   int *error ));
struct type_KRB5_KRB__ERROR *krb5_error2KRB5_KRB__ERROR
	PROTOTYPE((krb5_error *val,
		   int *error ));
void krb5_free_error
	PROTOTYPE((krb5_error *val ));
krb5_error *KRB5_KRB__ERROR2krb5_error
	PROTOTYPE((struct type_KRB5_KRB__ERROR *val,
		   int *error ));
struct type_KRB5_AP__REQ *krb5_ap_req2KRB5_AP__REQ
	PROTOTYPE((krb5_ap_req *val,
		   int *error ));
void krb5_free_ap_req
	PROTOTYPE((krb5_ap_req *val ));
krb5_ap_req *KRB5_AP__REQ2krb5_ap_req
	PROTOTYPE((struct type_KRB5_AP__REQ *val,
		   int *error ));
struct type_KRB5_AP__REP *krb5_ap_rep2KRB5_AP__REP
	PROTOTYPE((krb5_ap_rep *val,
		   int *error ));
void krb5_free_ap_rep
	PROTOTYPE((krb5_ap_rep *val ));
krb5_ap_rep *KRB5_AP__REP2krb5_ap_rep
	PROTOTYPE((struct type_KRB5_AP__REP *val,
		   int *error ));
struct type_KRB5_EncAPRepPart *krb5_ap_rep_enc_part2KRB5_EncAPRepPart
	PROTOTYPE((krb5_ap_rep_enc_part *val,
		   int *error ));
krb5_ap_rep_enc_part *KRB5_EncAPRepPart2krb5_ap_rep_enc_part
	PROTOTYPE((struct type_KRB5_EncAPRepPart *val,
		   int *error ));
struct type_KRB5_TGS__REQ *krb5_tgs_req2KRB5_TGS__REQ
	PROTOTYPE((krb5_tgs_req *val,
		   int *error ));
void krb5_free_tgs_req
	PROTOTYPE((krb5_tgs_req *val ));
krb5_tgs_req *KRB5_TGS__REQ2krb5_tgs_req
	PROTOTYPE((struct type_KRB5_TGS__REQ *val,
		   int *error ));
struct type_KRB5_EncTgsReqPart *krb5_tgs_req_enc_part2KRB5_EncTgsReqPart
	PROTOTYPE((krb5_tgs_req_enc_part *val,
		   int *error ));
void krb5_free_tgs_req_enc_part
	PROTOTYPE((krb5_tgs_req_enc_part *val ));
krb5_tgs_req_enc_part *KRB5_EncTgsReqPart2krb5_tgs_req_enc_part
	PROTOTYPE((struct type_KRB5_EncTgsReqPart *val,
		   int *error ));
struct type_KRB5_KRB__SAFE *krb5_safe2KRB5_KRB__SAFE
	PROTOTYPE((krb5_safe *val,
		   int *error ));
void krb5_free_safe
	PROTOTYPE((krb5_safe *val ));
krb5_safe *KRB5_KRB__SAFE2krb5_safe
	PROTOTYPE((struct type_KRB5_KRB__SAFE *val,
		   int *error ));
struct type_KRB5_KRB__PRIV *krb5_priv2KRB5_KRB__PRIV
	PROTOTYPE((krb5_priv *val,
		   int *error ));
void krb5_free_priv
	PROTOTYPE((krb5_priv *val ));
krb5_priv *KRB5_KRB__PRIV2krb5_priv
	PROTOTYPE((struct type_KRB5_KRB__PRIV *val,
		   int *error ));
struct type_KRB5_EncKrbPrivPart *krb5_priv_enc_part2KRB5_EncKrbPrivPart
	PROTOTYPE((krb5_priv_enc_part *val,
		   int *error ));
void krb5_free_priv_enc_part
	PROTOTYPE((krb5_priv_enc_part *val ));
krb5_priv_enc_part *KRB5_EncKrbPrivPart2krb5_priv_enc_part
	PROTOTYPE((struct type_KRB5_EncKrbPrivPart *val,
		   int *error ));

#endif /* __KRB5_ASN1DEFS__ */
