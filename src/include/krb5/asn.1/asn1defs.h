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



/* adat2kadat.c */
krb5_authdata **KRB5_AuthorizationData2krb5_authdata
	PROTOTYPE((const struct type_KRB5_AuthorizationData *, int *));

/* addr2kaddr.c */
krb5_address **KRB5_HostAddresses2krb5_address
	PROTOTYPE((const struct type_KRB5_HostAddresses *, int *));

/* adr2kadr.c */
krb5_address *KRB5_HostAddress2krb5_addr
	PROTOTYPE((const struct type_KRB5_HostAddress *, int *));

/* aprp2kaprp.c */
krb5_ap_rep *KRB5_AP__REP2krb5_ap_rep
	PROTOTYPE((const struct type_KRB5_AP__REP *, int *));

/* aprq2kaprq.c */
krb5_ap_req *KRB5_AP__REQ2krb5_ap_req
	PROTOTYPE((const struct type_KRB5_AP__REQ *, int *));

/* arep2karep.c */
krb5_ap_rep_enc_part *KRB5_EncAPRepPart2krb5_ap_rep_enc_part
	PROTOTYPE((const struct type_KRB5_EncAPRepPart *, int *));

/* auth2kauth.c */
krb5_authenticator *KRB5_Authenticator2krb5_authenticator
	PROTOTYPE((const struct type_KRB5_Authenticator *, int *));

/* ck2kck.c */
krb5_checksum *KRB5_Checksum2krb5_checksum
	PROTOTYPE((const struct type_KRB5_Checksum *, int *));

/* edat2kedat.c */
krb5_enc_data *KRB5_EncryptedData2krb5_enc_data
	PROTOTYPE((const struct type_KRB5_EncryptedData *, int *));

/* ekrp2kekrp.c */
krb5_enc_kdc_rep_part *KRB5_EncTGSRepPart2krb5_enc_kdc_rep_part
	PROTOTYPE((const struct type_KRB5_EncTGSRepPart *, int *));

/* enck2kkey.c */
krb5_keyblock *KRB5_EncryptionKey2krb5_keyblock
	PROTOTYPE((const struct type_KRB5_EncryptionKey *, int *));

/* err2kerr.c */
krb5_error *KRB5_KRB__ERROR2krb5_error
	PROTOTYPE((const struct type_KRB5_KRB__ERROR *, int *));

/* etpt2ketpt.c */
krb5_enc_tkt_part *KRB5_EncTicketPart2krb5_enc_tkt_part
	PROTOTYPE((const struct type_KRB5_EncTicketPart *, int *));

/* g2unix.c */
long gentime2unix
	PROTOTYPE((const struct type_UNIV_GeneralizedTime *, int *));

/* kadat2adat.c */
struct type_KRB5_AuthorizationData *krb5_authdata2KRB5_AuthorizationData
	PROTOTYPE((krb5_authdata *const *, int *));

/* kaddr2addr.c */
struct type_KRB5_HostAddresses *krb5_address2KRB5_HostAddresses
	PROTOTYPE((krb5_address *const *, int *));

/* kadr2adr.c */
struct type_KRB5_HostAddress *krb5_addr2KRB5_HostAddress
	PROTOTYPE((krb5_address const *, int *));

/* kaprp2aprp.c */
struct type_KRB5_AP__REP *krb5_ap_rep2KRB5_AP__REP
	PROTOTYPE((const krb5_ap_rep *, int *));

/* kaprq2aprq.c */
struct type_KRB5_AP__REQ *krb5_ap_req2KRB5_AP__REQ
	PROTOTYPE((const krb5_ap_req *, int *));

/* karep2arep.c */
struct type_KRB5_EncAPRepPart *krb5_ap_rep_enc_part2KRB5_EncAPRepPart
	PROTOTYPE((const krb5_ap_rep_enc_part *, int *));

/* kasrp2kdcr.c */
struct type_KRB5_KDC__REP *krb5_as_rep2KRB5_KDC__REP
	PROTOTYPE((const krb5_kdc_rep *, int *));

/* kauth2auth.c */
struct type_KRB5_Authenticator *krb5_authenticator2KRB5_Authenticator
	PROTOTYPE((const krb5_authenticator *, int *));

/* kck2ck.c */
struct type_KRB5_Checksum *krb5_checksum2KRB5_Checksum
	PROTOTYPE((const krb5_checksum *, int *));

/* kdcr2kasrp.c */
krb5_kdc_rep *KRB5_KDC__REP2krb5_as_rep
	PROTOTYPE((const struct type_KRB5_KDC__REP *, int *));

/* kdcr2kkdcr.c */
krb5_kdc_rep *KRB5_KDC__REP2krb5_kdc_rep
	PROTOTYPE((const struct type_KRB5_KDC__REP *, krb5_msgtype *, int *));

/* kdcr2ktgsr.c */
krb5_kdc_rep *KRB5_KDC__REP2krb5_tgs_rep
	PROTOTYPE((const struct type_KRB5_KDC__REP *, int *));

/* kedat2edat.c */
struct type_KRB5_EncryptedData *krb5_enc_data2KRB5_EncryptedData
	PROTOTYPE((const krb5_enc_data *, int *));

/* kekrp2ekrp.c */
struct type_KRB5_EncTGSRepPart *krb5_enc_kdc_rep_part2KRB5_EncTGSRepPart
	PROTOTYPE((const krb5_enc_kdc_rep_part *, int *));

/* kerr2err.c */
struct type_KRB5_KRB__ERROR *krb5_error2KRB5_KRB__ERROR
	PROTOTYPE((const krb5_error *, int *));

/* ketpt2etpt.c */
struct type_KRB5_EncTicketPart *krb5_enc_tkt_part2KRB5_EncTicketPart
	PROTOTYPE((const krb5_enc_tkt_part *, int *));

/* kkdcr2kdcr.c */
struct type_KRB5_KDC__REP *krb5_kdc_rep2KRB5_KDC__REP
	PROTOTYPE((const register krb5_kdc_rep *,
		   const krb5_msgtype,
		   int *));

/* kkey2enck.c */
struct type_KRB5_EncryptionKey *krb5_keyblock2KRB5_EncryptionKey
	PROTOTYPE((const krb5_keyblock *, int *));

/* klsrq2lsrq.c */
struct type_KRB5_LastReq *krb5_last_req2KRB5_LastReq
	PROTOTYPE((krb5_last_req_entry *const *, int *));

/* kprep2prep.c */
struct type_KRB5_EncKrbPrivPart *krb5_priv_enc_part2KRB5_EncKrbPrivPart
	PROTOTYPE((const krb5_priv_enc_part *, int *));

/* kprin2prin.c */
struct type_KRB5_PrincipalName *krb5_principal2KRB5_PrincipalName
	PROTOTYPE((const krb5_principal , int *));

/* kpriv2priv.c */
struct type_KRB5_KRB__PRIV *krb5_priv2KRB5_KRB__PRIV
	PROTOTYPE((const krb5_priv *, int *));

/* ksafe2safe.c */
struct type_KRB5_KRB__SAFE *krb5_safe2KRB5_KRB__SAFE
	PROTOTYPE((const krb5_safe *, int *));

/* ktgrq2tgrq.c */
struct type_KRB5_TGS__REQ *krb5_kdc_req2KRB5_TGS__REQ
	PROTOTYPE((const krb5_kdc_req *, int *));

/* ktgsr2kdcr.c */
struct type_KRB5_KDC__REP *krb5_tgs_rep2KRB5_KDC__REP
	PROTOTYPE((const krb5_kdc_rep *, int *));

/* ktkt2tkt.c */
struct type_KRB5_Ticket *krb5_ticket2KRB5_Ticket
	PROTOTYPE((const krb5_ticket *, int *));

/* ktrep2trep.c */
struct type_KRB5_EncTgsReqPart *krb5_tgs_req_enc_part2KRB5_EncTgsReqPart
	PROTOTYPE((const krb5_tgs_req_enc_part *, int *));

/* lsrq2klsrq.c */
krb5_last_req_entry **KRB5_LastReq2krb5_last_req
	PROTOTYPE((const struct type_KRB5_LastReq *, int *));

/* prep2kprep.c */
krb5_priv_enc_part *KRB5_EncKrbPrivPart2krb5_priv_enc_part
	PROTOTYPE((const struct type_KRB5_EncKrbPrivPart *, int *));

/* prin2kprin.c */
krb5_principal KRB5_PrincipalName2krb5_principal
	PROTOTYPE((const struct type_KRB5_PrincipalName *, const struct type_KRB5_Realm *, int *));

/* priv2kpriv.c */
krb5_priv *KRB5_KRB__PRIV2krb5_priv
	PROTOTYPE((const struct type_KRB5_KRB__PRIV *, int *));

/* qbuf2data.c */
krb5_data *qbuf2krb5_data
	PROTOTYPE((const struct qbuf *, int *));

/* safe2ksafe.c */
krb5_safe *KRB5_KRB__SAFE2krb5_safe
	PROTOTYPE((const struct type_KRB5_KRB__SAFE *, int *));

/* tgrq2ktgrq.c */
krb5_kdc_req *KRB5_TGS__REQ2krb5_kdc_req
	PROTOTYPE((const struct type_KRB5_TGS__REQ *, int *));

/* tkt2ktkt.c */
krb5_ticket *KRB5_Ticket2krb5_ticket
	PROTOTYPE((const struct type_KRB5_Ticket *, int *));

/* trep2ktrep.c */
krb5_tgs_req_enc_part *KRB5_EncTgsReqPart2krb5_tgs_req_enc_part
	PROTOTYPE((const struct type_KRB5_EncTgsReqPart *, int *));

/* u2gen.c */
struct type_UNIV_GeneralizedTime *unix2gentime
	PROTOTYPE((const int , int *));

#undef P
#endif /* KRB5_ASN1DEFS__ */
