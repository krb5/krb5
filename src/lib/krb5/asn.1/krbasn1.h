#ifndef __KRBASN1_H__
#define __KRBASN1_H__

#include <krb5/krb5.h>
#include <stdlib.h>
#include <errno.h>
#include <limits.h>

/* The current version of {en,de}code_krb5_enc_kdc_rep_part has a
   problem in that there's no way to know the message type (AS/TGS) of
   a krb5_enc_kdc_rep_part.  This should be fixed in the next version
   by including a msg_type field in krb5_enc_kdc_rep_part.  When that
   happens, #defining ENCKRB5KDCREPPART_HAS_MSGTYPE will activate the
   code that uses it. */
/* #define ENCKRB5KDCREPPART_HAS_MSGTYPE */

typedef krb5_octet asn1_octet;
typedef krb5_error_code asn1_error_code;

typedef enum { PRIMITIVE = 0x00, CONSTRUCTED = 0x20 } asn1_construction;

typedef enum { UNIVERSAL = 0x00, APPLICATION = 0x40,
		 CONTEXT_SPECIFIC = 0x80, PRIVATE = 0xC0 } asn1_class;

typedef int asn1_tagnum;
#define ASN1_TAGNUM_CEILING INT_MAX
#define ASN1_TAGNUM_MAX (ASN1_TAGNUM_CEILING-1)

/* This is Kerberos Version 5 */
#define KVNO 5

/* Universal Tag Numbers */
#define ASN1_INTEGER		2
#define ASN1_BITSTRING		3
#define ASN1_OCTETSTRING	4
#define ASN1_NULL		5
#define ASN1_OBJECTIDENTIFIER	6
#define ASN1_SEQUENCE		16
#define ASN1_SET		17
#define ASN1_PRINTABLESTRING	19
#define ASN1_IA5STRING		22
#define ASN1_UTCTIME		23
#define ASN1_GENERALTIME	24
#define ASN1_GENERALSTRING	27

/* Kerberos Message Types */
#define ASN1_KRB_AS_REQ		10
#define ASN1_KRB_AS_REP		11
#define ASN1_KRB_TGS_REQ	12
#define ASN1_KRB_TGS_REP	13
#define ASN1_KRB_AP_REQ		14
#define ASN1_KRB_AP_REP		15
#define ASN1_KRB_SAFE		20
#define ASN1_KRB_PRIV		21
#define ASN1_KRB_CRED		22
#define ASN1_KRB_ERROR		30

#endif
