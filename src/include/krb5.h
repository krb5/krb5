/*
 * include/krb5.h
 *
 * Copyright 1989,1990,1995 by the Massachusetts Institute of Technology.
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
 *
 * General definitions for Kerberos version 5.
 */

#ifndef KRB5_GENERAL__
#define KRB5_GENERAL__

#ifdef _MSDOS

#define SIZEOF_INT      2
#define SIZEOF_LONG     4

#ifndef KRB5_CONFIG__
#define KRB5_PROVIDE_PROTOTYPES
#define HAS_VOID_TYPE
#define HAVE_STDARG_H
#ifndef INTERFACE
#define INTERFACE   __far __export __pascal
#define INTERFACE_C __far __export __cdecl
#endif /* !INTERFACE */
#define FAR     _far
#define NEAR    _near
#ifndef _SIZE_T_DEFINED
typedef unsigned int size_t;
#define _SIZE_T_DEFINED
#endif /* !_SIZE_T_DEFINED */
#ifndef KRB5_SYSTYPES__
#define KRB5_SYSTYPES__
#include <sys/types.h>
typedef unsigned long u_long;      /* Not part of sys/types.h on the pc */
typedef unsigned int	u_int;
typedef unsigned short	u_short;
typedef unsigned char	u_char;
#endif /* KRB5_SYSTYPES__ */

#endif /* !KRB5_CONFIG */
#else /* !_MSDOS */
#ifndef KRB5_CONFIG__
#define INTERFACE
#define INTERFACE_C
#define FAR
#define NEAR
#endif /* !KRB5_CONFIG__ */
#ifdef HAS_SYS_TYPES
#include <sys/types.h>
#endif
#endif /* _MSDOS */

/*
 * begin wordsize.h
 */

/*
 * Word-size related definition.
 */

typedef	unsigned char	krb5_octet;
typedef	unsigned char	krb5_ui_1;

#if (SIZEOF_INT == 2)
typedef	int	krb5_int16;
typedef	unsigned int	krb5_ui_2;
#define VALID_INT_BITS    0x7fff
#define VALID_UINT_BITS   0xffff
#elif (SIZEOF_SHORT == 2)
typedef	short	krb5_int16;
typedef	unsigned short	krb5_ui_2;
#else
  ?==error: undefined 16 bit type
#endif

#if (SIZEOF_INT == 4)
typedef	int	krb5_int32;
typedef	unsigned int	krb5_ui_4;
#define VALID_INT_BITS    0x7fffffff
#define VALID_UINT_BITS   0xffffffff
#elif (SIZEOF_LONG == 4)
typedef	long	krb5_int32;
typedef	unsigned long	krb5_ui_4;
#elif (SIZEOF_SHORT == 4)
typedef	short	krb5_int32;
typedef	unsigned short	krb5_ui_4;
#else
 ?== error: undefined 32 bit type
#endif

#define KRB5_INT32_MAX	2147483647
/* this strange form is necessary since - is a unary operator, not a sign
   indicator */
#define KRB5_INT32_MIN	(-KRB5_INT32_MAX-1)

/*
 * end wordsize.h
 */

/*
 * begin "base-defs.h"
 */

/*
 * Basic definitions for Kerberos V5 library
 */

#ifndef FALSE
#define	FALSE	0
#endif
#ifndef TRUE
#define	TRUE	1
#endif

typedef	unsigned int krb5_boolean;
typedef	unsigned int krb5_msgtype;	
typedef	unsigned int krb5_kvno;	

typedef	unsigned int krb5_addrtype;
typedef unsigned int krb5_keytype;
typedef unsigned int krb5_enctype;
typedef unsigned int krb5_cksumtype;
typedef unsigned int krb5_authdatatype;

typedef krb5_int32	krb5_preauthtype; /* This may change, later on */
typedef	krb5_int32	krb5_flags;
typedef krb5_int32	krb5_timestamp;
typedef	krb5_int32	krb5_error_code;
typedef krb5_int32	krb5_deltat;

typedef krb5_error_code	krb5_magic;

typedef struct _krb5_data {
    krb5_magic magic;
    int length;
    char FAR *data;
} krb5_data;

/* Define krb5_const as necessary */

/*
 * Hardcoded scrudge to deal with Ultrix; see note on NPROTOTYPE below
 */

#if defined(KRB5_NO_CONST) || (defined(__ultrix) && !defined(__GNUC__))
#define krb5_const
#else
#define krb5_const const
#endif

#if defined(__STDC__) || defined(HAS_VOID_TYPE) || defined(_WINDOWS)
typedef	void FAR * krb5_pointer;
typedef void krb5_const FAR * krb5_const_pointer;
#else
typedef char FAR * krb5_pointer;
typedef char krb5_const FAR * krb5_const_pointer;
#endif

#if (defined(__STDC__) || defined(_WINDOWS) || defined(KRB5_PROVIDE_PROTOTYPES)) && !defined(KRB5_NO_PROTOTYPES)
#define KRB5_PROTOTYPE(x) x
#if defined(__STDC__) || defined(HAVE_STDARG_H) || defined(_WINDOWS)
#define	KRB5_STDARG_P(x) x
#else
#define KRB5_STDARG_P(x) ()
#endif /* defined(__STDC__) || defined(HAVE_STDARG_H) */
#else
#define KRB5_PROTOTYPE(x) ()
#define KRB5_STDARG_P(x) ()
#endif /* STDC or PROTOTYPES */

/*
 * This gross compiler dependency is in here because the stock Ultrix
 * compiler defines __STDC__ but doesn't deal with nested prototypes
 * properly.  The reason this isn't tested for is so that this header
 * is actually useful when installed.
 */
#if defined(KRB5_NO_NESTED_PROTOTYPES) || (defined(__ultrix) && !defined(__GNUC__))
#define	KRB5_NPROTOTYPE(x) ()
#else
#define	KRB5_NPROTOTYPE(x) KRB5_PROTOTYPE(x)
#endif

typedef struct krb5_principal_data {
    krb5_magic magic;
    krb5_data realm;
    krb5_data FAR *data;		/* An array of strings */
    krb5_int32 length;
    krb5_int32 type;
} krb5_principal_data;

typedef	krb5_principal_data FAR * krb5_principal;

/*
 * Per V5 spec on definition of principal types
 */

/* Name type not known */
#define KRB5_NT_UNKNOWN		0
/* Just the name of the principal as in DCE, or for users */
#define KRB5_NT_PRINCIPAL	1
/* Service and other unique instance (krbtgt) */
#define KRB5_NT_SRV_INST	2
/* Service with host name as instance (telnet, rcommands) */
#define KRB5_NT_SRV_HST		3
/* Service with host as remaining components */
#define KRB5_NT_SRV_XHST	4
/* Unique ID */
#define KRB5_NT_UID		5

/* constant version thereof: */
typedef krb5_const krb5_principal_data FAR *krb5_const_principal;

#define krb5_princ_realm(context, princ) (&(princ)->realm)
#define krb5_princ_set_realm(context, princ,value) ((princ)->realm = *(value))
#define krb5_princ_set_realm_length(context, princ,value) (princ)->realm.length = (value)
#define krb5_princ_set_realm_data(context, princ,value) (princ)->realm.data = (value)
#define	krb5_princ_size(context, princ) (princ)->length
#define	krb5_princ_type(context, princ) (princ)->type
#define	krb5_princ_name(context, princ) (princ)->data
#define	krb5_princ_component(context, princ,i) ((princ)->data + i)

/*
 * end "base-defs.h"
 */

/*
 * begin "hostaddr.h"
 */

/* structure for address */
typedef struct _krb5_address {
    krb5_magic magic;
    krb5_addrtype addrtype;
    int length;
    krb5_octet FAR *contents;
} krb5_address;

/* per Kerberos v5 protocol spec */
#define	ADDRTYPE_INET		0x0002
#define	ADDRTYPE_CHAOS		0x0005
#define	ADDRTYPE_XNS		0x0006
#define	ADDRTYPE_ISO		0x0007
#define ADDRTYPE_DDP		0x0010
/* not yet in the spec... */
#define ADDRTYPE_ADDRPORT	0x0100
#define ADDRTYPE_IPPORT		0x0101

/* macros to determine if a type is a local type */
#define ADDRTYPE_IS_LOCAL(addrtype) (addrtype & 0x8000)

/*
 * end "hostaddr.h"
 */


struct _krb5_context;
typedef struct _krb5_context FAR * krb5_context;

struct _krb5_auth_context;
typedef struct _krb5_auth_context FAR * krb5_auth_context;

/*
 * begin "encryption.h"
 */

typedef struct _krb5_keyblock {
    krb5_magic magic;
    krb5_keytype keytype;
    krb5_enctype etype;	/* hint of what encryption type to use */
    int length;
    krb5_octet FAR *contents;
} krb5_keyblock;

typedef struct _krb5_checksum {
    krb5_magic magic;
    krb5_cksumtype checksum_type;	/* checksum type */
    int length;
    krb5_octet FAR *contents;
} krb5_checksum;

typedef struct _krb5_encrypt_block {
    krb5_magic magic;
    struct _krb5_cryptosystem_entry FAR *crypto_entry;
    krb5_keyblock FAR *key;
    krb5_pointer priv;			/* for private use, e.g. DES
					   key schedules */
    krb5_int32 priv_size;		/* Size of private data */
} krb5_encrypt_block;

typedef struct _krb5_enc_data {
    krb5_magic magic;
    krb5_enctype etype;
    krb5_kvno kvno;
    krb5_data ciphertext;
} krb5_enc_data;

/* could be used in a table to find an etype and initialize a block */
typedef struct _krb5_cryptosystem_entry {
    krb5_magic magic;
    krb5_error_code (*encrypt_func) KRB5_NPROTOTYPE(( krb5_const_pointer /* in */,
					       krb5_pointer /* out */,
					       krb5_const size_t,
					       krb5_encrypt_block FAR *,
					       krb5_pointer));
    krb5_error_code (*decrypt_func) KRB5_NPROTOTYPE(( krb5_const_pointer /* in */,
					       krb5_pointer /* out */,
					       krb5_const size_t,
					       krb5_encrypt_block FAR *,
					       krb5_pointer));
    krb5_error_code (*process_key) KRB5_NPROTOTYPE(( krb5_encrypt_block FAR *,
					      krb5_const krb5_keyblock FAR *));
    krb5_error_code (*finish_key) KRB5_NPROTOTYPE(( krb5_encrypt_block FAR *));
    krb5_error_code (*string_to_key) KRB5_NPROTOTYPE((krb5_const krb5_encrypt_block FAR *,
						 krb5_const krb5_keytype,
						krb5_keyblock FAR *,
						krb5_const krb5_data FAR *,
 	                                        krb5_const krb5_data FAR *));
    krb5_error_code  (*init_random_key) KRB5_NPROTOTYPE((krb5_const krb5_keyblock FAR *,
						   krb5_pointer FAR *));
    krb5_error_code  (*finish_random_key) KRB5_NPROTOTYPE(( krb5_pointer FAR *));
    krb5_error_code (*random_key) KRB5_NPROTOTYPE(( krb5_const krb5_encrypt_block FAR *,
					      krb5_pointer,
					      krb5_keyblock FAR * FAR *));
    int block_length;
    int pad_minimum;			/* needed for cksum size computation */
    int keysize;
    krb5_enctype proto_enctype;		/* encryption type,
					   (assigned protocol number AND
					    table index) */
    krb5_keytype proto_keytype;		/* key type,
					   (assigned protocol number AND
					    table index) */
} krb5_cryptosystem_entry;

typedef struct _krb5_cs_table_entry {
    krb5_magic magic;
    krb5_cryptosystem_entry FAR *system;
    krb5_pointer random_sequence;	/* from init_random_key() */
} krb5_cs_table_entry;

/* could be used in a table to find a sumtype */
typedef krb5_error_code  (*SUM_FUNC) KRB5_NPROTOTYPE (
			(krb5_pointer /* in */,
			size_t /* in_length */,
			krb5_pointer /* key/seed */,
			size_t /* key/seed size */,
			krb5_checksum FAR * /* out_cksum */));

typedef krb5_error_code  (*SUM_VERF_FUNC) KRB5_NPROTOTYPE (
			(krb5_checksum FAR * /* out_cksum */,
			krb5_pointer /* in */,
			size_t /* in_length */,
			krb5_pointer /* key/seed */,
			size_t /* key/seed size */));

typedef struct _krb5_checksum_entry {
    krb5_magic magic;
    SUM_FUNC sum_func;			/* Checksum generator */
    SUM_VERF_FUNC sum_verf_func;	/* Verifier of checksum */
    int checksum_length;		/* length of stuff returned by
					   sum_func */
    unsigned int is_collision_proof:1;
    unsigned int uses_key:1;
} krb5_checksum_entry;

/* per Kerberos v5 protocol spec */
#define	KEYTYPE_NULL		0x0000
#define KEYTYPE_DES		0x0001	/* Data Encryption Standard,
					   FIPS 46,81 */
#define KEYTYPE_UNKNOWN		0x01ff

#define	ETYPE_NULL		0x0000
#define	ETYPE_DES_CBC_CRC	0x0001	/* DES cbc mode with CRC-32 */
#define	ETYPE_DES_CBC_MD4	0x0002	/* DES cbc mode with RSA-MD4 */
#define	ETYPE_DES_CBC_MD5	0x0003	/* DES cbc mode with RSA-MD5 */
#define	ETYPE_RAW_DES_CBC       0x0004  /* Raw DES cbc mode */

#define ETYPE_UNKNOWN		0x1FF 	/* Reserved local value */

#define	CKSUMTYPE_CRC32		0x0001
#define	CKSUMTYPE_RSA_MD4	0x0002
#define	CKSUMTYPE_RSA_MD4_DES	0x0003
#define	CKSUMTYPE_DESCBC	0x0004
/* des-mac-k */
/* rsa-md4-des-k */
#define	CKSUMTYPE_RSA_MD5	0x0007
#define	CKSUMTYPE_RSA_MD5_DES	0x0008

#ifndef krb5_roundup
/* round x up to nearest multiple of y */
#define krb5_roundup(x, y) ((((x) + (y) - 1)/(y))*(y))
#endif /* roundup */

/* macro function definitions to help clean up code */
#define	krb5_encrypt_size(length, crypto) \
     krb5_roundup((length)+(crypto)->pad_minimum, (crypto)->block_length)

/* This array is indexed by encryption type */
extern krb5_cs_table_entry * NEAR krb5_csarray[];
extern int krb5_max_cryptosystem;		/* max entry in array */

/* This array is indexed by key type, and has (should have) pointers to
   the same entries as krb5_csarray */
/* XXX what if a given keytype works for several etypes? */
extern krb5_cs_table_entry * NEAR krb5_keytype_array[];
extern int krb5_max_keytype;		/* max entry in array */

/* This array is indexed by checksum type */
extern krb5_checksum_entry * NEAR krb5_cksumarray[];
extern int krb5_max_cksum;		/* max entry in array */

#define valid_etype(etype)     ((((int) (etype)) <= krb5_max_cryptosystem) && ((etype) > 0) && krb5_csarray[etype])

#define valid_keytype(ktype)     ((((int) (ktype)) <= krb5_max_keytype) && ((ktype) > 0) && krb5_keytype_array[ktype])

#define valid_cksumtype(cktype)     ((((int) (cktype)) <= krb5_max_cksum) && ((cktype) > 0) && krb5_cksumarray[cktype])

#define is_coll_proof_cksum(cktype) (krb5_cksumarray[cktype]->is_collision_proof)
#define is_keyed_cksum(cktype) (krb5_cksumarray[cktype]->uses_key)

/* set up *eblockp to use etype */
#define krb5_use_cstype(context, eblockp, etype) (eblockp)->crypto_entry = krb5_csarray[(etype)]->system
/* ...or keytype */
#define krb5_use_keytype(context, eblockp, keytype) (eblockp)->crypto_entry = krb5_keytype_array[(keytype)]->system

#define krb5_encrypt(context, inptr, outptr, size, eblock, ivec) (*(eblock)->crypto_entry->encrypt_func)(inptr, outptr, size, eblock, ivec)
#define krb5_decrypt(context, inptr, outptr, size, eblock, ivec) (*(eblock)->crypto_entry->decrypt_func)(inptr, outptr, size, eblock, ivec)
#define krb5_process_key(context, eblock, key) (*(eblock)->crypto_entry->process_key)(eblock, key)
#define krb5_finish_key(context, eblock) (*(eblock)->crypto_entry->finish_key)(eblock)
#define krb5_string_to_key(context, eblock, keytype, keyblock, data, princ) (*(eblock)->crypto_entry->string_to_key)(eblock, keytype, keyblock, data, princ)
#define krb5_init_random_key(context, eblock, keyblock, ptr) (*(eblock)->crypto_entry->init_random_key)(keyblock, ptr)
#define krb5_finish_random_key(context, eblock, ptr) (*(eblock)->crypto_entry->finish_random_key)(ptr)
#define krb5_random_key(context, eblock, ptr, keyblock) (*(eblock)->crypto_entry->random_key)(eblock, ptr, keyblock)

#define krb5_eblock_keytype(context, eblockp) ((eblockp)->crypto_entry->proto_keytype)
#define krb5_eblock_enctype(context, eblockp) ((eblockp)->crypto_entry->proto_enctype)

/*
 * Here's the stuff for the checksum switch:
 */
#define krb5_checksum_size(context, ctype)  (krb5_cksumarray[ctype]->checksum_length)
#define krb5_calculate_checksum(context, ctype, in, in_length, seed, seed_length, outcksum) ((*krb5_cksumarray[ctype]->sum_func)(in, in_length, seed, seed_length, outcksum))
#define krb5_verify_checksum(context, ctype, cksum, in, in_length, seed, seed_length) ((*krb5_cksumarray[ctype]->sum_verf_func)(cksum, in, in_length, seed, seed_length))

/*
 * end "encryption.h"
 */

/*
 * begin "fieldbits.h"
 */

/* kdc_options for kdc_request */
/* options is 32 bits; each host is responsible to put the 4 bytes
   representing these bits into net order before transmission */
/* #define	KDC_OPT_RESERVED	0x80000000 */
#define	KDC_OPT_FORWARDABLE		0x40000000
#define	KDC_OPT_FORWARDED		0x20000000
#define	KDC_OPT_PROXIABLE		0x10000000
#define	KDC_OPT_PROXY			0x08000000
#define	KDC_OPT_ALLOW_POSTDATE		0x04000000
#define	KDC_OPT_POSTDATED		0x02000000
/* #define	KDC_OPT_UNUSED		0x01000000 */
#define	KDC_OPT_RENEWABLE		0x00800000
/* #define	KDC_OPT_UNUSED		0x00400000 */
/* #define	KDC_OPT_RESERVED	0x00200000 */
/* #define	KDC_OPT_RESERVED	0x00100000 */
/* #define	KDC_OPT_RESERVED	0x00080000 */
/* #define	KDC_OPT_RESERVED	0x00040000 */
/* #define	KDC_OPT_RESERVED	0x00020000 */
/* #define	KDC_OPT_RESERVED	0x00010000 */
/* #define	KDC_OPT_RESERVED	0x00008000 */
/* #define	KDC_OPT_RESERVED	0x00004000 */
/* #define	KDC_OPT_RESERVED	0x00002000 */
/* #define	KDC_OPT_RESERVED	0x00001000 */
/* #define	KDC_OPT_RESERVED	0x00000800 */
/* #define	KDC_OPT_RESERVED	0x00000400 */
/* #define	KDC_OPT_RESERVED	0x00000200 */
/* #define	KDC_OPT_RESERVED	0x00000100 */
/* #define	KDC_OPT_RESERVED	0x00000080 */
/* #define	KDC_OPT_RESERVED	0x00000040 */
/* #define	KDC_OPT_RESERVED	0x00000020 */
#define	KDC_OPT_RENEWABLE_OK		0x00000010
#define	KDC_OPT_ENC_TKT_IN_SKEY		0x00000008
/* #define	KDC_OPT_UNUSED		0x00000004 */
#define	KDC_OPT_RENEW			0x00000002
#define	KDC_OPT_VALIDATE		0x00000001

/*
 * Mask of ticket flags in the TGT which should be converted into KDC
 * options when using the TGT to get derivitive tickets.
 * 
 *  New mask = KDC_OPT_FORWARDABLE | KDC_OPT_PROXIABLE |
 *             KDC_OPT_ALLOW_POSTDATE | KDC_OPT_RENEWABLE
 */
#define KDC_TKT_COMMON_MASK		0x54800000

/* definitions for ap_options fields */
/* ap_options are 32 bits; each host is responsible to put the 4 bytes
   representing these bits into net order before transmission */
#define	AP_OPTS_RESERVED		0x80000000
#define	AP_OPTS_USE_SESSION_KEY		0x40000000
#define	AP_OPTS_MUTUAL_REQUIRED		0x20000000
/* #define	AP_OPTS_RESERVED	0x10000000 */
/* #define	AP_OPTS_RESERVED	0x08000000 */
/* #define	AP_OPTS_RESERVED	0x04000000 */
/* #define	AP_OPTS_RESERVED	0x02000000 */
/* #define	AP_OPTS_RESERVED	0x01000000 */
/* #define	AP_OPTS_RESERVED	0x00800000 */
/* #define	AP_OPTS_RESERVED	0x00400000 */
/* #define	AP_OPTS_RESERVED	0x00200000 */
/* #define	AP_OPTS_RESERVED	0x00100000 */
/* #define	AP_OPTS_RESERVED	0x00080000 */
/* #define	AP_OPTS_RESERVED	0x00040000 */
/* #define	AP_OPTS_RESERVED	0x00020000 */
/* #define	AP_OPTS_RESERVED	0x00010000 */
/* #define	AP_OPTS_RESERVED	0x00008000 */
/* #define	AP_OPTS_RESERVED	0x00004000 */
/* #define	AP_OPTS_RESERVED	0x00002000 */
/* #define	AP_OPTS_RESERVED	0x00001000 */
/* #define	AP_OPTS_RESERVED	0x00000800 */
/* #define	AP_OPTS_RESERVED	0x00000400 */
/* #define	AP_OPTS_RESERVED	0x00000200 */
/* #define	AP_OPTS_RESERVED	0x00000100 */
/* #define	AP_OPTS_RESERVED	0x00000080 */
/* #define	AP_OPTS_RESERVED	0x00000040 */
/* #define	AP_OPTS_RESERVED	0x00000020 */
/* #define	AP_OPTS_RESERVED	0x00000010 */
/* #define	AP_OPTS_RESERVED	0x00000008 */
/* #define	AP_OPTS_RESERVED	0x00000004 */
/* #define	AP_OPTS_RESERVED	0x00000002 */
#define AP_OPTS_USE_SUBKEY      0x00000001

#define AP_OPTS_WIRE_MASK	0xfffffff0

/* definitions for ad_type fields. */
#define	AD_TYPE_RESERVED	0x8000
#define	AD_TYPE_EXTERNAL	0x4000
#define	AD_TYPE_REGISTERED	0x2000

#define AD_TYPE_FIELD_TYPE_MASK	0x1fff

/* Ticket flags */
/* flags are 32 bits; each host is responsible to put the 4 bytes
   representing these bits into net order before transmission */
/* #define	TKT_FLG_RESERVED	0x80000000 */
#define	TKT_FLG_FORWARDABLE		0x40000000
#define	TKT_FLG_FORWARDED		0x20000000
#define	TKT_FLG_PROXIABLE		0x10000000
#define	TKT_FLG_PROXY			0x08000000
#define	TKT_FLG_MAY_POSTDATE		0x04000000
#define	TKT_FLG_POSTDATED		0x02000000
#define	TKT_FLG_INVALID			0x01000000
#define	TKT_FLG_RENEWABLE		0x00800000
#define	TKT_FLG_INITIAL			0x00400000
#define	TKT_FLG_PRE_AUTH		0x00200000
#define	TKT_FLG_HW_AUTH			0x00100000
/* #define	TKT_FLG_RESERVED	0x00080000 */
/* #define	TKT_FLG_RESERVED	0x00040000 */
/* #define	TKT_FLG_RESERVED	0x00020000 */
/* #define	TKT_FLG_RESERVED	0x00010000 */
/* #define	TKT_FLG_RESERVED	0x00008000 */
/* #define	TKT_FLG_RESERVED	0x00004000 */
/* #define	TKT_FLG_RESERVED	0x00002000 */
/* #define	TKT_FLG_RESERVED	0x00001000 */
/* #define	TKT_FLG_RESERVED	0x00000800 */
/* #define	TKT_FLG_RESERVED	0x00000400 */
/* #define	TKT_FLG_RESERVED	0x00000200 */
/* #define	TKT_FLG_RESERVED	0x00000100 */
/* #define	TKT_FLG_RESERVED	0x00000080 */
/* #define	TKT_FLG_RESERVED	0x00000040 */
/* #define	TKT_FLG_RESERVED	0x00000020 */
/* #define	TKT_FLG_RESERVED	0x00000010 */
/* #define	TKT_FLG_RESERVED	0x00000008 */
/* #define	TKT_FLG_RESERVED	0x00000004 */
/* #define	TKT_FLG_RESERVED	0x00000002 */
/* #define	TKT_FLG_RESERVED	0x00000001 */

/* definitions for lr_type fields. */
#define	LR_TYPE_THIS_SERVER_ONLY	0x8000

#define LR_TYPE_INTERPRETATION_MASK	0x7fff

/* definitions for ad_type fields. */
#define	AD_TYPE_EXTERNAL	0x4000
#define	AD_TYPE_REGISTERED	0x2000

#define AD_TYPE_FIELD_TYPE_MASK	0x1fff
#define AD_TYPE_INTERNAL_MASK	0x3fff

/* definitions for msec direction bit for KRB_SAFE, KRB_PRIV */
#define	MSEC_DIRBIT		0x8000
#define	MSEC_VAL_MASK		0x7fff

/*
 * end "fieldbits.h"
 */

/*
 * begin "proto.h"
 */

/* Protocol version number */
#define	KRB5_PVNO	5

/* Message types */

#define	KRB5_AS_REQ	((krb5_msgtype)10) /* Req for initial authentication */
#define	KRB5_AS_REP	((krb5_msgtype)11) /* Response to KRB_AS_REQ request */
#define	KRB5_TGS_REQ	((krb5_msgtype)12) /* TGS request to server */
#define	KRB5_TGS_REP	((krb5_msgtype)13) /* Response to KRB_TGS_REQ req */
#define	KRB5_AP_REQ	((krb5_msgtype)14) /* application request to server */
#define	KRB5_AP_REP	((krb5_msgtype)15) /* Response to KRB_AP_REQ_MUTUAL */
#define	KRB5_SAFE	((krb5_msgtype)20) /* Safe application message */
#define	KRB5_PRIV	((krb5_msgtype)21) /* Private application message */
#define	KRB5_CRED	((krb5_msgtype)22) /* Credential forwarding message */
#define	KRB5_ERROR	((krb5_msgtype)30) /* Error response */

/* LastReq types */
#define KRB5_LRQ_NONE			0
#define KRB5_LRQ_ALL_LAST_TGT		1
#define KRB5_LRQ_ONE_LAST_TGT		(-1)
#define KRB5_LRQ_ALL_LAST_INITIAL	2
#define KRB5_LRQ_ONE_LAST_INITIAL	(-2)
#define KRB5_LRQ_ALL_LAST_TGT_ISSUED	3
#define KRB5_LRQ_ONE_LAST_TGT_ISSUED	(-3)
#define KRB5_LRQ_ALL_LAST_RENEWAL	4
#define KRB5_LRQ_ONE_LAST_RENEWAL	(-4)
#define KRB5_LRQ_ALL_LAST_REQ		5
#define KRB5_LRQ_ONE_LAST_REQ		(-5)

/* PADATA types */
#define KRB5_PADATA_NONE                0
#define	KRB5_PADATA_AP_REQ		1
#define	KRB5_PADATA_TGS_REQ		KRB5_PADATA_AP_REQ
#define KRB5_PADATA_ENC_TIMESTAMP	2
#define	KRB5_PADATA_PW_SALT		3
#if 0				/* Not used */
#define KRB5_PADATA_ENC_ENCKEY          4  /* Key encrypted within itself */
#endif
#define KRB5_PADATA_ENC_UNIX_TIME       5  /* timestamp encrypted in key */
#define KRB5_PADATA_ENC_SANDIA_SECURID  6  /* SecurId passcode */
#define KRB5_PADATA_SESAME		7  /* Sesame project */
#define KRB5_PADATA_OSF_DCE		8  /* OSF DCE */
    
/* Reserved for SPX pre-authentication. */
#define KRB5_PADATA_DASS		16

/* Transited encoding types */
#define	KRB5_DOMAIN_X500_COMPRESS	1

/* alternate authentication types */
#define	KRB5_ALTAUTH_ATT_CHALLENGE_RESPONSE	64

/* authorization data types */
#define	KRB5_AUTHDATA_OSF_DCE	64
#define KRB5_AUTHDATA_SESAME	65

/*
 * end "proto.h"
 */

/*
 * begin "error_def.h"
 */

#include <errno.h>

/*
 * end "error_def.h"
 */

/* Time set */
typedef struct _krb5_ticket_times {
    krb5_timestamp authtime; /* XXX ? should ktime in KDC_REP == authtime
				in ticket? otherwise client can't get this */ 
    krb5_timestamp starttime;		/* optional in ticket, if not present,
					   use authtime */
    krb5_timestamp endtime;
    krb5_timestamp renew_till;
} krb5_ticket_times;

/* structure for auth data */
typedef struct _krb5_authdata {
    krb5_magic magic;
    krb5_authdatatype ad_type;
    int length;
    krb5_octet FAR *contents;
} krb5_authdata;

/* structure for transited encoding */
typedef struct _krb5_transited {
    krb5_magic magic;
    krb5_octet tr_type;
    krb5_data tr_contents;
} krb5_transited;

typedef struct _krb5_enc_tkt_part {
    krb5_magic magic;
    /* to-be-encrypted portion */
    krb5_flags flags;			/* flags */
    krb5_keyblock FAR *session;		/* session key: includes keytype */
    krb5_principal client;		/* client name/realm */
    krb5_transited transited;		/* list of transited realms */
    krb5_ticket_times times;		/* auth, start, end, renew_till */
    krb5_address FAR * FAR *caddrs;	/* array of ptrs to addresses */
    krb5_authdata FAR * FAR *authorization_data; /* auth data */
} krb5_enc_tkt_part;

typedef struct _krb5_ticket {
    krb5_magic magic;
    /* cleartext portion */
    krb5_principal server;		/* server name/realm */
    krb5_enc_data enc_part;		/* encryption type, kvno, encrypted
					   encoding */
    krb5_enc_tkt_part FAR *enc_part2;	/* ptr to decrypted version, if
					   available */
} krb5_ticket;

/* the unencrypted version */
typedef struct _krb5_authenticator {
    krb5_magic magic;
    krb5_principal client;		/* client name/realm */
    krb5_checksum FAR *checksum;	/* checksum, includes type, optional */
    krb5_int32 cusec;			/* client usec portion */
    krb5_timestamp ctime;		/* client sec portion */
    krb5_keyblock FAR *subkey;		/* true session key, optional */
    krb5_int32 seq_number;		/* sequence #, optional */
    krb5_authdata FAR * FAR *authorization_data; /* New add by Ari, auth data */
} krb5_authenticator;

typedef struct _krb5_tkt_authent {
    krb5_magic magic;
    krb5_ticket FAR *ticket;
    krb5_authenticator FAR *authenticator;
    krb5_flags ap_options;
} krb5_tkt_authent;

/* credentials:  Ticket, session key, etc. */
typedef struct _krb5_creds {
    krb5_magic magic;
    krb5_principal client;		/* client's principal identifier */
    krb5_principal server;		/* server's principal identifier */
    krb5_keyblock keyblock;		/* session encryption key info */
    krb5_ticket_times times;		/* lifetime info */
    krb5_boolean is_skey;		/* true if ticket is encrypted in
					   another ticket's skey */
    krb5_flags ticket_flags;		/* flags in ticket */
    krb5_address FAR * FAR *addresses;	/* addrs in ticket */
    krb5_data ticket;			/* ticket string itself */
    krb5_data second_ticket;		/* second ticket, if related to
					   ticket (via DUPLICATE-SKEY or
					   ENC-TKT-IN-SKEY) */
    krb5_authdata FAR * FAR *authdata;	/* authorization data */
} krb5_creds;

/* Last request fields */
typedef struct _krb5_last_req_entry {
    krb5_magic magic;
    krb5_octet lr_type;
    krb5_timestamp value;
} krb5_last_req_entry;

/* pre-authentication data */
typedef struct _krb5_pa_data {
    krb5_magic magic;
    krb5_ui_2  pa_type;
    int length;
    krb5_octet FAR *contents;
} krb5_pa_data;

typedef struct _krb5_kdc_req {
    krb5_magic magic;
    krb5_msgtype msg_type;		/* AS_REQ or TGS_REQ? */
    krb5_pa_data FAR * FAR *padata;	/* e.g. encoded AP_REQ */
    /* real body */
    krb5_flags kdc_options;		/* requested options */
    krb5_principal client;		/* includes realm; optional */
    krb5_principal server;		/* includes realm (only used if no
					   client) */
    krb5_timestamp from;		/* requested starttime */
    krb5_timestamp till;		/* requested endtime */
    krb5_timestamp rtime;		/* (optional) requested renew_till */
    krb5_int32 nonce;			/* nonce to match request/response */
    int netypes;			/* # of etypes, must be positive */
    krb5_enctype FAR *etype;		/* requested encryption type(s) */
    krb5_address FAR * FAR *addresses;	/* requested addresses, optional */
    krb5_enc_data authorization_data;	/* encrypted auth data; OPTIONAL */
    krb5_authdata FAR * FAR *unenc_authdata; /* unencrypted auth data,
					   if available */
    krb5_ticket FAR * FAR *second_ticket;/* second ticket array; OPTIONAL */
} krb5_kdc_req;

typedef struct _krb5_enc_kdc_rep_part {
    krb5_magic magic;
    /* encrypted part: */
    krb5_msgtype msg_type;		/* krb5 message type */
    krb5_keyblock FAR *session;		/* session key */
    krb5_last_req_entry FAR * FAR *last_req; /* array of ptrs to entries */
    krb5_int32 nonce;			/* nonce from request */
    krb5_timestamp key_exp;		/* expiration date */
    krb5_flags flags;			/* ticket flags */
    krb5_ticket_times times;		/* lifetime info */
    krb5_principal server;		/* server's principal identifier */
    krb5_address FAR * FAR *caddrs;	/* array of ptrs to addresses,
					   optional */
} krb5_enc_kdc_rep_part;

typedef struct _krb5_kdc_rep {
    krb5_magic magic;
    /* cleartext part: */
    krb5_msgtype msg_type;		/* AS_REP or KDC_REP? */
    krb5_pa_data FAR * FAR *padata;	/* preauthentication data from KDC */
    krb5_principal client;		/* client's principal identifier */
    krb5_ticket FAR *ticket;		/* ticket */
    krb5_enc_data enc_part;		/* encryption type, kvno, encrypted
					   encoding */
    krb5_enc_kdc_rep_part FAR *enc_part2;/* unencrypted version, if available */
} krb5_kdc_rep;

/* error message structure */
typedef struct _krb5_error {
    krb5_magic magic;
    /* some of these may be meaningless in certain contexts */
    krb5_timestamp ctime;		/* client sec portion; optional */
    krb5_int32 cusec;			/* client usec portion; optional */
    krb5_int32 susec;			/* server usec portion */
    krb5_timestamp stime;		/* server sec portion */
    krb5_ui_4 error;			/* error code (protocol error #'s) */
    krb5_principal client;		/* client's principal identifier;
					   optional */
    krb5_principal server;		/* server's principal identifier */
    krb5_data text;			/* descriptive text */
    krb5_data e_data;			/* additional error-describing data */
} krb5_error;

typedef struct _krb5_ap_req {
    krb5_magic magic;
    krb5_flags ap_options;		/* requested options */
    krb5_ticket FAR *ticket;		/* ticket */
    krb5_enc_data authenticator;	/* authenticator (already encrypted) */
} krb5_ap_req;

typedef struct _krb5_ap_rep {
    krb5_magic magic;
    krb5_enc_data enc_part;
} krb5_ap_rep;

typedef struct _krb5_ap_rep_enc_part {
    krb5_magic magic;
    krb5_timestamp ctime;		/* client time, seconds portion */
    krb5_int32 cusec;			/* client time, microseconds portion */
    krb5_keyblock FAR *subkey;		/* true session key, optional */
    krb5_int32 seq_number;		/* sequence #, optional */
} krb5_ap_rep_enc_part;

typedef struct _krb5_response {
    krb5_magic magic;
    krb5_octet message_type;
    krb5_data response;
} krb5_response;

typedef struct _krb5_safe {
    krb5_magic magic;
    krb5_data user_data;		/* user data */
    krb5_timestamp timestamp;		/* client time, optional */
    krb5_int32 usec;			/* microsecond portion of time,
					   optional */
    krb5_int32 seq_number;		/* sequence #, optional */
    krb5_address FAR *s_address;	/* sender address */
    krb5_address FAR *r_address;	/* recipient address, optional */
    krb5_checksum FAR *checksum;	/* data integrity checksum */
} krb5_safe;

typedef struct _krb5_priv {
    krb5_magic magic;
    krb5_enc_data enc_part;		/* encrypted part */
} krb5_priv;

typedef struct _krb5_priv_enc_part {
    krb5_magic magic;
    krb5_data user_data;		/* user data */
    krb5_timestamp timestamp;		/* client time, optional */
    krb5_int32 usec;			/* microsecond portion of time, opt. */
    krb5_int32 seq_number;		/* sequence #, optional */
    krb5_address FAR *s_address;	/* sender address */
    krb5_address FAR *r_address;	/* recipient address, optional */
} krb5_priv_enc_part;

typedef struct _krb5_cred_info {
    krb5_magic magic;
    krb5_keyblock FAR *session;         /* session key used to encrypt */
					/* ticket */
    krb5_principal client;              /* client name/realm, optional */
    krb5_principal server;              /* server name/realm, optional */
    krb5_flags flags;			/* ticket flags, optional */
    krb5_ticket_times times;		/* auth, start, end, renew_till, */
                                        /* optional */
    krb5_address FAR * FAR *caddrs;	/* array of ptrs to addresses */
} krb5_cred_info;

typedef struct _krb5_cred_enc_part {
    krb5_magic magic;
    krb5_int32 nonce;                   /* nonce, optional */
    krb5_timestamp timestamp;           /* client time */
    krb5_int32 usec;                    /* microsecond portion of time */
    krb5_address FAR *s_address;        /* sender address, optional */
    krb5_address FAR *r_address;        /* recipient address, optional */
    krb5_cred_info FAR * FAR *ticket_info;
} krb5_cred_enc_part;    

typedef struct _krb5_cred {
    krb5_magic magic;
    krb5_ticket FAR * FAR *tickets;	/* tickets */
    krb5_enc_data enc_part;		/* encrypted part */
    krb5_cred_enc_part FAR *enc_part2; 	/* unencrypted version, if available*/
} krb5_cred;

/* Sandia password generation structures */
typedef struct _passwd_phrase_element {
    krb5_magic magic;
    krb5_data FAR *passwd;
    krb5_data FAR *phrase;
} passwd_phrase_element;

typedef struct _krb5_pwd_data {
    krb5_magic magic;
    int sequence_count;
    passwd_phrase_element FAR * FAR *element;
} krb5_pwd_data;

/* these need to be here so the typedefs are available for the prototypes */

/*
 * begin "safepriv.h"
 */

#define KRB5_AUTH_CONTEXT_DO_TIME       0x00000001
#define KRB5_AUTH_CONTEXT_RET_TIME      0x00000002
#define KRB5_AUTH_CONTEXT_DO_SEQUENCE   0x00000004
#define KRB5_AUTH_CONTEXT_RET_SEQUENCE  0x00000008
 
typedef struct krb5_replay_data { 
    krb5_timestamp      timestamp; 
    krb5_int32          usec;
    krb5_int32          seq; 
} krb5_replay_data;

/* flags for krb5_auth_con_genaddrs() */
#define KRB5_AUTH_CONTEXT_GENERATE_LOCAL_ADDR           0x00000001
#define KRB5_AUTH_CONTEXT_GENERATE_REMOTE_ADDR          0x00000002
#define KRB5_AUTH_CONTEXT_GENERATE_LOCAL_FULL_ADDR      0x00000004
#define KRB5_AUTH_CONTEXT_GENERATE_REMOTE_FULL_ADDR     0x00000008

/*
 * end "safepriv.h"
 */


/*
 * begin "ccache.h"
 */

typedef	krb5_pointer	krb5_cc_cursor;	/* cursor for sequential lookup */

typedef struct _krb5_ccache {
    krb5_magic magic;
    struct _krb5_cc_ops FAR *ops;
    krb5_pointer data;
} FAR *krb5_ccache;

typedef struct _krb5_cc_ops {
    krb5_magic magic;
    char FAR *prefix;
    char FAR * (INTERFACE *get_name) KRB5_NPROTOTYPE((krb5_context, krb5_ccache));
    krb5_error_code (INTERFACE *resolve) KRB5_NPROTOTYPE((krb5_context, krb5_ccache FAR *,
					    char FAR *));
    krb5_error_code (INTERFACE *gen_new) KRB5_NPROTOTYPE((krb5_context, krb5_ccache FAR *));
    krb5_error_code (INTERFACE *init) KRB5_NPROTOTYPE((krb5_context, krb5_ccache,
					    krb5_principal));
    krb5_error_code (INTERFACE *destroy) KRB5_NPROTOTYPE((krb5_context, krb5_ccache));
    krb5_error_code (INTERFACE *close) KRB5_NPROTOTYPE((krb5_context, krb5_ccache));
    krb5_error_code (INTERFACE *store) KRB5_NPROTOTYPE((krb5_context, krb5_ccache,
					    krb5_creds FAR *));
    krb5_error_code (INTERFACE *retrieve) KRB5_NPROTOTYPE((krb5_context, krb5_ccache,
					    krb5_flags, krb5_creds FAR *,
					    krb5_creds FAR *));
    krb5_error_code (INTERFACE *get_princ) KRB5_NPROTOTYPE((krb5_context, krb5_ccache,
					    krb5_principal FAR *));
    krb5_error_code (INTERFACE *get_first) KRB5_NPROTOTYPE((krb5_context, krb5_ccache,
					    krb5_cc_cursor FAR *));
    krb5_error_code (INTERFACE *get_next) KRB5_NPROTOTYPE((krb5_context, krb5_ccache,
					    krb5_cc_cursor FAR *, krb5_creds FAR *));
    krb5_error_code (INTERFACE *end_get) KRB5_NPROTOTYPE((krb5_context, krb5_ccache,
					    krb5_cc_cursor FAR *));
    krb5_error_code (INTERFACE *remove_cred) KRB5_NPROTOTYPE((krb5_context, krb5_ccache,
					    krb5_flags, krb5_creds FAR *));
    krb5_error_code (INTERFACE *set_flags) KRB5_NPROTOTYPE((krb5_context, krb5_ccache,
					    krb5_flags));
} krb5_cc_ops;

/* for retrieve_cred */
#define	KRB5_TC_MATCH_TIMES		0x00000001
#define	KRB5_TC_MATCH_IS_SKEY		0x00000002
#define	KRB5_TC_MATCH_FLAGS		0x00000004
#define	KRB5_TC_MATCH_TIMES_EXACT	0x00000008
#define	KRB5_TC_MATCH_FLAGS_EXACT	0x00000010
#define	KRB5_TC_MATCH_AUTHDATA		0x00000020
#define	KRB5_TC_MATCH_SRV_NAMEONLY	0x00000040
#define	KRB5_TC_MATCH_2ND_TKT		0x00000080

/* for set_flags and other functions */
#define KRB5_TC_OPENCLOSE		0x00000001

#define krb5_cc_initialize(context, cache, principal) (*(cache)->ops->init)(context, cache, principal)
#define krb5_cc_gen_new(context, cache) (*(cache)->ops->gen_new)(context, cache)
#define krb5_cc_destroy(context, cache) (*(cache)->ops->destroy)(context, cache)
#define krb5_cc_close(context, cache) (*(cache)->ops->close)(context, cache)
#define krb5_cc_store_cred(context, cache, creds) (*(cache)->ops->store)(context, cache, creds)
#define krb5_cc_retrieve_cred(context, cache, flags, mcreds, creds) (*(cache)->ops->retrieve)(context, cache, flags, mcreds, creds)
#define krb5_cc_get_principal(context, cache, principal) (*(cache)->ops->get_princ)(context, cache, principal)
#define krb5_cc_start_seq_get(context, cache, cursor) (*(cache)->ops->get_first)(context, cache, cursor)
#define krb5_cc_next_cred(context, cache, cursor, creds) (*(cache)->ops->get_next)(context, cache, cursor, creds)
#define krb5_cc_end_seq_get(context, cache, cursor) (*(cache)->ops->end_get)(context, cache, cursor)
#define krb5_cc_remove_cred(context, cache, flags, creds) (*(cache)->ops->remove_cred)(context, cache,flags, creds)
#define krb5_cc_set_flags(context, cache, flags) (*(cache)->ops->set_flags)(context, cache, flags)
#define krb5_cc_get_name(context, cache) (*(cache)->ops->get_name)(context, cache)
#define krb5_cc_get_type(context, cache) (*(cache)->ops->prefix)

extern krb5_cc_ops FAR *krb5_cc_dfl_ops;

/*
 * end "ccache.h"
 */

/*
 * begin "rcache.h"
 */

typedef struct krb5_rc_st {
    krb5_magic magic;
    struct _krb5_rc_ops FAR *ops;
    krb5_pointer data;
} FAR *krb5_rcache;

typedef struct _krb5_donot_replay {
    krb5_magic magic;
    char FAR *server;			/* null-terminated */
    char FAR *client;			/* null-terminated */
    krb5_int32 cusec;
    krb5_timestamp ctime;
} krb5_donot_replay;

typedef struct _krb5_rc_ops {
    krb5_magic magic;
    char FAR *type;
    krb5_error_code (*init)KRB5_NPROTOTYPE((krb5_context, krb5_rcache,krb5_deltat)); /* create */
    krb5_error_code (*recover)KRB5_NPROTOTYPE((krb5_context, krb5_rcache)); /* open */
    krb5_error_code (*destroy)KRB5_NPROTOTYPE((krb5_context, krb5_rcache));
    krb5_error_code (*close)KRB5_NPROTOTYPE((krb5_context, krb5_rcache));
    krb5_error_code (*store)KRB5_NPROTOTYPE((krb5_context, krb5_rcache,krb5_donot_replay FAR *));
    krb5_error_code (*expunge)KRB5_NPROTOTYPE((krb5_context, krb5_rcache));
    krb5_error_code (*get_span)KRB5_NPROTOTYPE((krb5_context, krb5_rcache,krb5_deltat FAR *));
    char FAR *(*get_name)KRB5_NPROTOTYPE((krb5_context, krb5_rcache));
    krb5_error_code (*resolve)KRB5_NPROTOTYPE((krb5_context, krb5_rcache, char FAR *));
} krb5_rc_ops;

krb5_error_code krb5_rc_default 
	KRB5_PROTOTYPE((krb5_context,
		   krb5_rcache FAR *));
krb5_error_code krb5_rc_register_type 
	KRB5_PROTOTYPE((krb5_context,
		   krb5_rc_ops FAR *));
krb5_error_code krb5_rc_resolve_type 
	KRB5_PROTOTYPE((krb5_context,
		   krb5_rcache FAR *,char FAR *));
krb5_error_code krb5_rc_resolve_full 
	KRB5_PROTOTYPE((krb5_context,
		   krb5_rcache FAR *,char FAR *));
char FAR * krb5_rc_get_type 
	KRB5_PROTOTYPE((krb5_context,
		   krb5_rcache));
char FAR * krb5_rc_default_type 
	KRB5_PROTOTYPE((krb5_context));
char FAR * krb5_rc_default_name 
	KRB5_PROTOTYPE((krb5_context));
krb5_error_code krb5_auth_to_rep 
	KRB5_PROTOTYPE((krb5_context,
		   krb5_tkt_authent FAR *,
		   krb5_donot_replay FAR *));

#define krb5_rc_initialize(context, id, span) (*(id)->ops->init)(context, id, span)
#define krb5_rc_recover(context, id) (*(id)->ops->recover)(context, id)
#define krb5_rc_destroy(context, id) (*(id)->ops->destroy)(context, id)
#define krb5_rc_close(context, id) (*(id)->ops->close)(context, id)
#define krb5_rc_store(context, id, dontreplay) (*(id)->ops->store)(context, id, dontreplay)
#define krb5_rc_expunge(context, id) (*(id)->ops->expunge)(context, id)
#define krb5_rc_get_lifespan(context, id, spanp) (*(id)->ops->get_span)(context, id, spanp)
#define krb5_rc_get_name(context, id) (*(id)->ops->get_name)(context, id)
#define krb5_rc_resolve(context, id, name) (*(id)->ops->resolve)(context, id, name)

extern krb5_rc_ops krb5_rc_dfl_ops;

/*
 * end "rcache.h"
 */

/*
 * begin "keytab.h"
 */


/* XXX */
#define MAX_KEYTAB_NAME_LEN 1100 /* Long enough for MAXPATHLEN + some extra */

typedef krb5_pointer krb5_kt_cursor;	/* XXX */

typedef struct krb5_keytab_entry_st {
    krb5_magic magic;
    krb5_principal principal;	/* principal of this key */
    krb5_timestamp timestamp;   /* time entry written to keytable */
    krb5_kvno vno;		/* key version number */
    krb5_keyblock key;		/* the secret key */
} krb5_keytab_entry;


typedef struct _krb5_kt {
    krb5_magic magic;
    struct _krb5_kt_ops FAR *ops;
    krb5_pointer data;
} FAR *krb5_keytab;


typedef struct _krb5_kt_ops {
    krb5_magic magic;
    char FAR *prefix;
    /* routines always present */
    krb5_error_code (*resolve) 
	KRB5_NPROTOTYPE((krb5_context,
		    krb5_const char FAR *,
		    krb5_keytab FAR *));
    krb5_error_code (*get_name) 
	KRB5_NPROTOTYPE((krb5_context,
		    krb5_keytab,
		    char FAR *,
		    int));
    krb5_error_code (*close) 
	KRB5_NPROTOTYPE((krb5_context,
		    krb5_keytab));
    krb5_error_code (*get) 
	KRB5_NPROTOTYPE((krb5_context,
		    krb5_keytab,
		    krb5_principal,
		    krb5_kvno,
		    krb5_keytype,
		    krb5_keytab_entry FAR *));
    krb5_error_code (*start_seq_get) 
	KRB5_NPROTOTYPE((krb5_context,
		    krb5_keytab,
		    krb5_kt_cursor FAR *));	
    krb5_error_code (*get_next) 
	KRB5_NPROTOTYPE((krb5_context,
		    krb5_keytab,
		    krb5_keytab_entry FAR *,
		    krb5_kt_cursor FAR *));
    krb5_error_code (*end_get) 
	KRB5_NPROTOTYPE((krb5_context,
		    krb5_keytab,
		    krb5_kt_cursor FAR *));
    /* routines to be included on extended version (write routines) */
    krb5_error_code (*add) 
	KRB5_NPROTOTYPE((krb5_context,
		    krb5_keytab,
		    krb5_keytab_entry FAR *));
    krb5_error_code (*remove) 
	KRB5_NPROTOTYPE((krb5_context,
		    krb5_keytab,
		  krb5_keytab_entry FAR *));

    /* Handle for serializer */
    void * serializer;
} krb5_kt_ops;

#define krb5_kt_get_type(context, keytab) (*(keytab)->ops->prefix)
#define krb5_kt_get_name(context, keytab, name, namelen) (*(keytab)->ops->get_name)(context, keytab,name,namelen)
#define krb5_kt_close(context, keytab) (*(keytab)->ops->close)(context, keytab)
#define krb5_kt_get_entry(context, keytab, principal, vno, keytype, entry) (*(keytab)->ops->get)(context, keytab, principal, vno, keytype, entry)
#define krb5_kt_start_seq_get(context, keytab, cursor) (*(keytab)->ops->start_seq_get)(context, keytab, cursor)
#define krb5_kt_next_entry(context, keytab, entry, cursor) (*(keytab)->ops->get_next)(context, keytab, entry, cursor)
#define krb5_kt_end_seq_get(context, keytab, cursor) (*(keytab)->ops->end_get)(context, keytab, cursor)
/* remove and add are functions, so that they can return NOWRITE
   if not a writable keytab */


extern krb5_kt_ops krb5_kt_dfl_ops;

/*
 * end "keytab.h"
 */

/*
 * begin "func-proto.h"
 */

krb5_error_code INTERFACE krb5_init_context
	KRB5_PROTOTYPE((krb5_context FAR *));
void krb5_free_context
	KRB5_PROTOTYPE((krb5_context));

krb5_error_code krb5_set_default_in_tkt_etypes
	KRB5_PROTOTYPE((krb5_context,
		   krb5_const krb5_enctype *));
krb5_error_code krb5_get_default_in_tkt_etypes
	KRB5_PROTOTYPE((krb5_context,
		   krb5_enctype **));

/* libkrb.spec */
krb5_error_code krb5_kdc_rep_decrypt_proc
	KRB5_PROTOTYPE((krb5_context,
		   krb5_const krb5_keyblock *,
		   krb5_const_pointer,
		   krb5_kdc_rep * ));
krb5_error_code krb5_encrypt_tkt_part
	KRB5_PROTOTYPE((krb5_context,
		   krb5_encrypt_block *,
		   krb5_const krb5_keyblock *,
		   krb5_ticket * ));
krb5_error_code krb5_decrypt_tkt_part
	KRB5_PROTOTYPE((krb5_context,
		   krb5_const krb5_keyblock *,
		   krb5_ticket * ));
krb5_error_code krb5_get_cred_from_kdc
	KRB5_PROTOTYPE((krb5_context,
		   krb5_ccache,		/* not const, as reading may save
					   state */
		   krb5_creds *,
		   krb5_creds **,
		   krb5_creds *** ));
void krb5_free_tgt_creds
	KRB5_PROTOTYPE((krb5_context,
		   krb5_creds ** ));	/* XXX too hard to do with const */

#define	KRB5_GC_USER_USER	1	/* want user-user ticket */
#define	KRB5_GC_CACHED		2	/* want cached ticket only */

krb5_error_code INTERFACE krb5_get_credentials
	KRB5_PROTOTYPE((krb5_context,
		   krb5_const krb5_flags,
		   krb5_ccache,
		   krb5_creds FAR *,
		   krb5_creds FAR * FAR *));
krb5_error_code INTERFACE krb5_get_cred_via_tkt
        KRB5_PROTOTYPE((krb5_context,
                   krb5_creds *,
                   krb5_const krb5_flags,
                   krb5_address * krb5_const *,
                   krb5_creds *,
                   krb5_creds **));
krb5_error_code krb5_mk_req
	KRB5_PROTOTYPE((krb5_context,
		   krb5_auth_context *,
		   krb5_const krb5_flags,
		   char *,
		   char *,
		   krb5_data *,
		   krb5_ccache,
		   krb5_data * ));
krb5_error_code INTERFACE krb5_mk_req_extended
	KRB5_PROTOTYPE((krb5_context,
		   krb5_auth_context FAR *,
		   krb5_const krb5_flags,
		   krb5_data FAR *,
		   krb5_creds FAR *,
		   krb5_data FAR * ));
krb5_error_code krb5_mk_rep
	KRB5_PROTOTYPE((krb5_context,
		   krb5_auth_context,
		   krb5_data *));
krb5_error_code INTERFACE krb5_rd_rep
	KRB5_PROTOTYPE((krb5_context,
		   krb5_auth_context,
		   krb5_const krb5_data FAR *,
		   krb5_ap_rep_enc_part FAR * FAR *));
krb5_error_code krb5_mk_error
	KRB5_PROTOTYPE((krb5_context,
		   krb5_const krb5_error *,
		   krb5_data * ));
krb5_error_code krb5_rd_error
	KRB5_PROTOTYPE((krb5_context,
		   krb5_const krb5_data *,
		   krb5_error ** ));
krb5_error_code krb5_rd_safe
	KRB5_PROTOTYPE((krb5_context,
		   krb5_auth_context,
		   krb5_const krb5_data *,
		   krb5_data *,
		   krb5_replay_data *));
krb5_error_code krb5_rd_priv
	KRB5_PROTOTYPE((krb5_context,
		   krb5_auth_context,
		   krb5_const krb5_data *,
		   krb5_data *,
		   krb5_replay_data *));
krb5_error_code INTERFACE krb5_parse_name
	KRB5_PROTOTYPE((krb5_context,
		   krb5_const char FAR *,
		   krb5_principal FAR * ));
krb5_error_code INTERFACE krb5_unparse_name
	KRB5_PROTOTYPE((krb5_context,
		   krb5_const_principal,
		   char FAR * FAR * ));
krb5_error_code krb5_unparse_name_ext
	KRB5_PROTOTYPE((krb5_context,
		   krb5_const_principal,
		   char **,
		   int *));
krb5_boolean krb5_address_search
	KRB5_PROTOTYPE((krb5_context,
		   krb5_const krb5_address *,
		   krb5_address * krb5_const *));
krb5_boolean krb5_address_compare
	KRB5_PROTOTYPE((krb5_context,
		   krb5_const krb5_address *,
		   krb5_const krb5_address *));
int krb5_address_order
	KRB5_PROTOTYPE((krb5_context,
		   krb5_const krb5_address *,
		   krb5_const krb5_address *));
krb5_boolean krb5_realm_compare
	KRB5_PROTOTYPE((krb5_context,
		   krb5_const_principal,
		   krb5_const_principal));
krb5_boolean krb5_principal_compare
	KRB5_PROTOTYPE((krb5_context,
		   krb5_const_principal,
		   krb5_const_principal));
krb5_error_code krb5_copy_keyblock
    	KRB5_PROTOTYPE((krb5_context,
		   krb5_const krb5_keyblock *,
	       krb5_keyblock **));
krb5_error_code krb5_copy_keyblock_contents
    	KRB5_PROTOTYPE((krb5_context,
		   krb5_const krb5_keyblock *,
	       krb5_keyblock *));
krb5_error_code krb5_copy_creds
    	KRB5_PROTOTYPE((krb5_context,
		   krb5_const krb5_creds *,
	       krb5_creds **));
krb5_error_code krb5_copy_data
    	KRB5_PROTOTYPE((krb5_context,
		   krb5_const krb5_data *,
	       krb5_data **));
krb5_error_code krb5_copy_principal
    	KRB5_PROTOTYPE((krb5_context,
		   krb5_const_principal,
	       krb5_principal *));
krb5_error_code krb5_copy_addresses
    	KRB5_PROTOTYPE((krb5_context,
		   krb5_address * krb5_const *,
	       krb5_address ***));
krb5_error_code krb5_copy_ticket
    	KRB5_PROTOTYPE((krb5_context,
		   krb5_const krb5_ticket *, krb5_ticket **));
krb5_error_code krb5_copy_authdata
    	KRB5_PROTOTYPE((krb5_context,
		   krb5_authdata * krb5_const *,
	       krb5_authdata ***));
krb5_error_code krb5_copy_authenticator
    	KRB5_PROTOTYPE((krb5_context,
		   krb5_const krb5_authenticator *,
	       krb5_authenticator **));
krb5_error_code krb5_copy_checksum
    	KRB5_PROTOTYPE((krb5_context,
		   krb5_const krb5_checksum *,
	       krb5_checksum **));
void INTERFACE krb5_init_ets KRB5_PROTOTYPE((krb5_context));
krb5_error_code krb5_generate_subkey
    	KRB5_PROTOTYPE((krb5_context,
		   krb5_const krb5_keyblock *, krb5_keyblock **));
krb5_error_code krb5_generate_seq_number
    	KRB5_PROTOTYPE((krb5_context,
		   krb5_const krb5_keyblock *, krb5_int32 *));
krb5_error_code krb5_get_server_rcache
    	KRB5_PROTOTYPE((krb5_context,
		   krb5_const krb5_data *, krb5_rcache *));
krb5_error_code INTERFACE_C krb5_build_principal_ext
    	KRB5_STDARG_P((krb5_context, krb5_principal FAR *, int, krb5_const char FAR *, ...));
krb5_error_code krb5_build_principal
    	KRB5_STDARG_P((krb5_context, krb5_principal *, int, krb5_const char *, ...));
#ifdef va_start
/* XXX depending on varargs include file defining va_start... */
krb5_error_code krb5_build_principal_va
    	KRB5_PROTOTYPE((krb5_context,
		   krb5_principal *, int, krb5_const char *, va_list));
#endif

krb5_error_code krb5_425_conv_principal
	KRB5_PROTOTYPE((krb5_context,
		   krb5_const char *name, krb5_const char *instance, krb5_const char *realm,
		   krb5_principal *princ));

krb5_error_code
krb5_524_conv_principal
	KRB5_PROTOTYPE((krb5_context context, krb5_const krb5_principal princ, 
		   char *name, char *inst, char *realm));

krb5_error_code krb5_obtain_padata
    	KRB5_PROTOTYPE((krb5_context,
		   int type, krb5_principal client, krb5_address **src_addr,
	           krb5_keyblock *encrypt_key, krb5_pa_data **data));

krb5_error_code krb5_verify_padata
    	KRB5_PROTOTYPE((krb5_context,
		   krb5_pa_data * data, krb5_principal client,
	       krb5_address **src_addr, krb5_keyblock *decrypt_key,
	       int *req_id, int *flags));

/* libkt.spec */
krb5_error_code krb5_kt_register
	KRB5_PROTOTYPE((krb5_context,
		   krb5_kt_ops * ));
krb5_error_code krb5_kt_resolve
	KRB5_PROTOTYPE((krb5_context,
		   krb5_const char *,
		   krb5_keytab * ));
krb5_error_code krb5_kt_default_name
	KRB5_PROTOTYPE((krb5_context,
		   char *,
		   int ));
krb5_error_code krb5_kt_default
	KRB5_PROTOTYPE((krb5_context,
		   krb5_keytab * ));
krb5_error_code krb5_kt_free_entry
	KRB5_PROTOTYPE((krb5_context,
		   krb5_keytab_entry * ));
/* remove and add are functions, so that they can return NOWRITE
   if not a writable keytab */
krb5_error_code krb5_kt_remove_entry
	KRB5_PROTOTYPE((krb5_context,
		   krb5_keytab,
		   krb5_keytab_entry * ));
krb5_error_code krb5_kt_add_entry
	KRB5_PROTOTYPE((krb5_context,
		   krb5_keytab,
		   krb5_keytab_entry * ));
krb5_error_code krb5_principal2salt
	KRB5_PROTOTYPE((krb5_context,
		   krb5_const_principal, krb5_data *));
krb5_error_code krb5_principal2salt_norealm
	KRB5_PROTOTYPE((krb5_context,
		   krb5_const_principal, krb5_data *));

/* librc.spec--see rcache.h */

/* libcc.spec */
krb5_error_code krb5_cc_resolve
	KRB5_PROTOTYPE((krb5_context,
		   char *,
		   krb5_ccache * ));
krb5_error_code krb5_cc_generate_new
	KRB5_PROTOTYPE((krb5_context,
		   krb5_cc_ops *,
		   krb5_ccache * ));
char * krb5_cc_default_name
	KRB5_PROTOTYPE((krb5_context));
krb5_error_code INTERFACE krb5_cc_default
	KRB5_PROTOTYPE((krb5_context,
		   krb5_ccache FAR *));
unsigned int INTERFACE krb5_get_notification_message
   KRB5_PROTOTYPE((void));

/* chk_trans.c */
krb5_error_code krb5_check_transited_list
    KRB5_PROTOTYPE((krb5_context,
		   krb5_data *trans, krb5_data *realm1, krb5_data *realm2));

/* free_rtree.c */
void krb5_free_realm_tree
	KRB5_PROTOTYPE((krb5_context,
		   krb5_principal *));

/* krb5_free.c */
void INTERFACE krb5_free_principal
	KRB5_PROTOTYPE((krb5_context,
		   krb5_principal ));
void krb5_free_authenticator
	KRB5_PROTOTYPE((krb5_context,
		   krb5_authenticator * ));
void krb5_free_authenticator_contents
	KRB5_PROTOTYPE((krb5_context,
		   krb5_authenticator * ));
void INTERFACE krb5_free_addresses
	KRB5_PROTOTYPE((krb5_context,
		   krb5_address FAR * FAR * ));
void krb5_free_address
	KRB5_PROTOTYPE((krb5_context,
		   krb5_address * ));
void krb5_free_authdata
	KRB5_PROTOTYPE((krb5_context,
		   krb5_authdata ** ));
void krb5_free_enc_tkt_part
	KRB5_PROTOTYPE((krb5_context,
		   krb5_enc_tkt_part * ));
void krb5_free_ticket
	KRB5_PROTOTYPE((krb5_context,
		   krb5_ticket * ));
void krb5_free_tickets
	KRB5_PROTOTYPE((krb5_context,
		   krb5_ticket ** ));
void krb5_free_kdc_req
	KRB5_PROTOTYPE((krb5_context,
		   krb5_kdc_req * ));
void krb5_free_kdc_rep
	KRB5_PROTOTYPE((krb5_context,
		   krb5_kdc_rep * ));
void krb5_free_last_req
	KRB5_PROTOTYPE((krb5_context,
		   krb5_last_req_entry ** ));
void krb5_free_enc_kdc_rep_part
	KRB5_PROTOTYPE((krb5_context,
		   krb5_enc_kdc_rep_part * ));
void krb5_free_error
	KRB5_PROTOTYPE((krb5_context,
		   krb5_error * ));
void krb5_free_ap_req
	KRB5_PROTOTYPE((krb5_context,
		   krb5_ap_req * ));
void krb5_free_ap_rep
	KRB5_PROTOTYPE((krb5_context,
		   krb5_ap_rep * ));
void krb5_free_safe
	KRB5_PROTOTYPE((krb5_context,
		   krb5_safe * ));
void krb5_free_priv
	KRB5_PROTOTYPE((krb5_context,
		   krb5_priv * ));
void krb5_free_priv_enc_part
	KRB5_PROTOTYPE((krb5_context,
		   krb5_priv_enc_part * ));
void krb5_free_cred
   KRB5_PROTOTYPE((krb5_context, 
         krb5_cred *));
void INTERFACE krb5_free_creds
	KRB5_PROTOTYPE((krb5_context,
		   krb5_creds FAR *));
void INTERFACE krb5_free_cred_contents
	KRB5_PROTOTYPE((krb5_context,
		   krb5_creds FAR *));
void krb5_free_cred_enc_part
   KRB5_PROTOTYPE((krb5_context,
         krb5_cred_enc_part *));
void krb5_free_checksum
	KRB5_PROTOTYPE((krb5_context,
		   krb5_checksum *));
void krb5_free_keyblock
	KRB5_PROTOTYPE((krb5_context,
		   krb5_keyblock *));
void krb5_free_pa_data
	KRB5_PROTOTYPE((krb5_context,
		   krb5_pa_data **));
void INTERFACE krb5_free_ap_rep_enc_part
	KRB5_PROTOTYPE((krb5_context,
		   krb5_ap_rep_enc_part FAR *));
void krb5_free_tkt_authent
	KRB5_PROTOTYPE((krb5_context,
		   krb5_tkt_authent *));
void krb5_free_pwd_data
   KRB5_PROTOTYPE((krb5_context,
         krb5_pwd_data *));
void krb5_free_pwd_sequences
   KRB5_PROTOTYPE((krb5_context,
         passwd_phrase_element **));

/* From krb5/os but needed but by the outside world */
krb5_error_code INTERFACE krb5_us_timeofday
	KRB5_PROTOTYPE((krb5_context,
		   krb5_int32 FAR *,
		   krb5_int32 FAR * ));
krb5_error_code INTERFACE krb5_timeofday
	KRB5_PROTOTYPE((krb5_context,
		   krb5_int32 FAR * ));
		 /* get all the addresses of this host */
krb5_error_code INTERFACE krb5_os_localaddr
	KRB5_PROTOTYPE((krb5_context,
		   krb5_address FAR * FAR * FAR *));
krb5_error_code INTERFACE krb5_get_default_realm
	KRB5_PROTOTYPE((krb5_context,
		    char FAR * FAR * ));
krb5_error_code INTERFACE krb5_set_default_realm
	KRB5_PROTOTYPE((krb5_context,
                   krb5_const char FAR * ));
krb5_error_code INTERFACE krb5_sname_to_principal
        KRB5_PROTOTYPE((krb5_context,
		   krb5_const char FAR *,
                   krb5_const char FAR *,
                   krb5_int32,
                   krb5_principal FAR *));

krb5_error_code INTERFACE krb5_set_config_files
	KRB5_PROTOTYPE ((krb5_context, krb5_const char **));

krb5_error_code krb5_encode_kdc_rep
	KRB5_PROTOTYPE((krb5_context,
		   krb5_const krb5_msgtype,
		   krb5_const krb5_enc_kdc_rep_part *,
		   krb5_encrypt_block *,
		   krb5_const krb5_keyblock *,
		   krb5_kdc_rep *,
		   krb5_data ** ));

krb5_error_code krb5_send_tgs
	KRB5_PROTOTYPE((krb5_context,
		   krb5_const krb5_flags,
		   krb5_const krb5_ticket_times *,
		   krb5_const krb5_enctype *,
		   krb5_const_principal,
		   krb5_address * krb5_const *,
		   krb5_authdata * krb5_const *,
		   krb5_pa_data * krb5_const *,
		   krb5_const krb5_data *,
		   krb5_creds *,
		   krb5_response * ));

krb5_error_code krb5_get_in_tkt
	KRB5_PROTOTYPE((krb5_context,
		   krb5_const krb5_flags,
		   krb5_address * krb5_const *,
		   krb5_enctype *,
		   krb5_preauthtype *,
		   krb5_error_code ( * )(krb5_context,
					krb5_const krb5_keytype,
                                        krb5_data *,
                                        krb5_const_pointer,
                                        krb5_keyblock **),
		   krb5_const_pointer,
		   krb5_error_code ( * )(krb5_context,
					krb5_const krb5_keyblock *,
					krb5_const_pointer,
					krb5_kdc_rep * ),
		   krb5_const_pointer,
		   krb5_creds *,
		   krb5_ccache,
		   krb5_kdc_rep ** ));

krb5_error_code INTERFACE krb5_get_in_tkt_with_password
	KRB5_PROTOTYPE((krb5_context,
		   krb5_const krb5_flags,
		   krb5_address FAR * krb5_const FAR *,
		   krb5_enctype FAR *,
		   krb5_preauthtype FAR *,
		   krb5_const char FAR *,
		   krb5_ccache,
		   krb5_creds FAR *,
		   krb5_kdc_rep FAR * FAR * ));

krb5_error_code krb5_get_in_tkt_with_skey
	KRB5_PROTOTYPE((krb5_context,
		   krb5_const krb5_flags,
		   krb5_address * krb5_const *,
		   krb5_enctype *,
		   krb5_preauthtype *,
		   krb5_const krb5_keyblock *,
		   krb5_ccache,
		   krb5_creds *,
		   krb5_kdc_rep ** ));

krb5_error_code krb5_get_in_tkt_with_keytab
	KRB5_PROTOTYPE((krb5_context,
		   krb5_const krb5_flags,
		   krb5_address * krb5_const *,
		   krb5_enctype *,
		   krb5_preauthtype *,
		   krb5_const krb5_keytab,
		   krb5_ccache,
		   krb5_creds *,
		   krb5_kdc_rep ** ));


krb5_error_code krb5_decode_kdc_rep
	KRB5_PROTOTYPE((krb5_context,
		   krb5_data *,
		   krb5_const krb5_keyblock *,
		   krb5_const krb5_enctype,
		   krb5_kdc_rep ** ));

krb5_error_code krb5_rd_req
	KRB5_PROTOTYPE((krb5_context,
		   krb5_auth_context *,
		   krb5_const krb5_data *,
		   krb5_const_principal,
		   krb5_keytab,
		   krb5_flags *,
		   krb5_ticket **));

krb5_error_code krb5_rd_req_decoded
	KRB5_PROTOTYPE((krb5_context,
		   krb5_auth_context *,
		   krb5_const krb5_ap_req *,
		   krb5_const_principal,
		   krb5_keytab,
		   krb5_flags *,
		   krb5_ticket **));

krb5_error_code krb5_kt_read_service_key
	KRB5_PROTOTYPE((krb5_context,
		   krb5_pointer,
		   krb5_principal,
		   krb5_kvno,
		   krb5_keytype,
		   krb5_keyblock **));
krb5_error_code krb5_mk_safe
	KRB5_PROTOTYPE((krb5_context,
		   krb5_auth_context,
		   krb5_const krb5_data *,
		   krb5_data *,
		   krb5_replay_data *));
krb5_error_code krb5_mk_priv
	KRB5_PROTOTYPE((krb5_context,
		   krb5_auth_context,
		   krb5_const krb5_data *,
		   krb5_data *,
		   krb5_replay_data *));
krb5_error_code krb5_cc_register
	KRB5_PROTOTYPE((krb5_context,
		   krb5_cc_ops *,
		   krb5_boolean ));

krb5_error_code krb5_sendauth 
	KRB5_PROTOTYPE((krb5_context,
		   krb5_auth_context *,
		   krb5_pointer,
		   char *,
		   krb5_principal,
		   krb5_principal,
		   krb5_flags,
		   krb5_data *,
		   krb5_creds *,
		   krb5_ccache,
		   krb5_error **,
		   krb5_ap_rep_enc_part **,
		   krb5_creds **));
	
krb5_error_code krb5_recvauth KRB5_PROTOTYPE((krb5_context,
		   krb5_auth_context *,
		   krb5_pointer,
		   char *,
		   krb5_principal,
		   krb5_int32, 
		   krb5_keytab,
		   krb5_ticket **));

krb5_error_code krb5_walk_realm_tree
    	KRB5_PROTOTYPE((krb5_context,
		   krb5_const krb5_data *,
	       krb5_const krb5_data *,
	       krb5_principal **,
	       int));

krb5_error_code INTERFACE krb5_mk_ncred
    	KRB5_PROTOTYPE((krb5_context,
                   krb5_auth_context,
                   krb5_creds **,
                   krb5_data **,
                   krb5_replay_data *));

krb5_error_code INTERFACE krb5_mk_1cred
        KRB5_PROTOTYPE((krb5_context,
                   krb5_auth_context,
                   krb5_creds *,
                   krb5_data **,
                   krb5_replay_data *));

krb5_error_code krb5_rd_cred
        KRB5_PROTOTYPE((krb5_context,
                   krb5_auth_context,
		   krb5_data *,
                   krb5_creds ***,
                   krb5_replay_data *));

krb5_error_code krb5_auth_con_init
	KRB5_PROTOTYPE((krb5_context,
		   krb5_auth_context *));

krb5_error_code krb5_auth_con_free
	KRB5_PROTOTYPE((krb5_context,
		   krb5_auth_context));

krb5_error_code krb5_auth_con_setflags
	KRB5_PROTOTYPE((krb5_context,
		   krb5_auth_context,
		   krb5_int32));

krb5_error_code krb5_auth_con_getflags
	KRB5_PROTOTYPE((krb5_context,
		   krb5_auth_context,
		   krb5_int32 *));

krb5_error_code krb5_auth_con_setaddrs
	KRB5_PROTOTYPE((krb5_context,
		   krb5_auth_context,
		   krb5_address *,
		   krb5_address *));

krb5_error_code krb5_auth_con_getaddrs
	KRB5_PROTOTYPE((krb5_context,
		   krb5_auth_context,
		   krb5_address **,
		   krb5_address **));

krb5_error_code krb5_auth_con_setports
	KRB5_PROTOTYPE((krb5_context,
		   krb5_auth_context,
		   krb5_address *,
		   krb5_address *));

krb5_error_code krb5_auth_con_setuseruserkey
	KRB5_PROTOTYPE((krb5_context,
		   krb5_auth_context,
		   krb5_keyblock *));

krb5_error_code krb5_auth_con_getkey
	KRB5_PROTOTYPE((krb5_context,
		   krb5_auth_context,
		   krb5_keyblock **));

krb5_error_code krb5_auth_con_getlocalsubkey
	KRB5_PROTOTYPE((krb5_context,
		   krb5_auth_context,
		   krb5_keyblock **));

krb5_error_code krb5_auth_con_setcksumtype
	KRB5_PROTOTYPE((krb5_context,
		   krb5_auth_context,
		   krb5_cksumtype));

krb5_error_code krb5_auth_con_getcksumtype
	KRB5_PROTOTYPE((krb5_context,
		   krb5_auth_context,
		   krb5_cksumtype *));

krb5_error_code krb5_auth_con_getlocalseqnumber
	KRB5_PROTOTYPE((krb5_context,
		   krb5_auth_context,
		   krb5_int32 *));

krb5_error_code krb5_auth_con_getremoteseqnumber
	KRB5_PROTOTYPE((krb5_context,
		   krb5_auth_context,
		   krb5_int32 *));

krb5_error_code krb5_auth_con_initivector
	KRB5_PROTOTYPE((krb5_context,
		   krb5_auth_context));

krb5_error_code krb5_auth_con_setivector
	KRB5_PROTOTYPE((krb5_context,
		   krb5_auth_context,
		   krb5_pointer));

krb5_error_code krb5_auth_con_getivector
	KRB5_PROTOTYPE((krb5_context,
		   krb5_auth_context,
		   krb5_pointer *));

krb5_error_code krb5_auth_con_setrcache
	KRB5_PROTOTYPE((krb5_context,
		   krb5_auth_context,
		   krb5_rcache));

krb5_error_code krb5_auth_con_getrcache
	KRB5_PROTOTYPE((krb5_context,
		   krb5_auth_context,
		   krb5_rcache *));

krb5_error_code krb5_auth_con_getauthenticator
   KRB5_PROTOTYPE((krb5_context,
         krb5_auth_context,
         krb5_authenticator **));

krb5_error_code krb5_auth_con_getremotesubkey
   KRB5_PROTOTYPE((krb5_context,
         krb5_auth_context,
         krb5_keyblock **));

#define KRB5_REALM_BRANCH_CHAR '.'

/*
 * end "func-proto.h"
 */

/*
 * begin "k5-free.h"
 */

/* to keep lint happy */
#define krb5_xfree(val) free((char FAR *)(val))

#define krb5_free_data(context, val) { krb5_xfree((val)->data); krb5_xfree(val);}

/*
 * end "k5-free.h"
 */

/* The name of the Kerberos ticket granting service... and its size */
#define	KRB5_TGS_NAME		"krbtgt"
#define KRB5_TGS_NAME_SIZE	6

/* flags for recvauth */
#define KRB5_RECVAUTH_SKIP_VERSION	0x0001
#define KRB5_RECVAUTH_BADAUTHVERS	0x0002

#endif /* KRB5_GENERAL__ */
/*
 * include/krb5/krb5_err.h:
 * This file is automatically generated; please do not edit it.
 */
#define KRB5KDC_ERR_NONE                         (-1765328384L)
#define KRB5KDC_ERR_NAME_EXP                     (-1765328383L)
#define KRB5KDC_ERR_SERVICE_EXP                  (-1765328382L)
#define KRB5KDC_ERR_BAD_PVNO                     (-1765328381L)
#define KRB5KDC_ERR_C_OLD_MAST_KVNO              (-1765328380L)
#define KRB5KDC_ERR_S_OLD_MAST_KVNO              (-1765328379L)
#define KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN          (-1765328378L)
#define KRB5KDC_ERR_S_PRINCIPAL_UNKNOWN          (-1765328377L)
#define KRB5KDC_ERR_PRINCIPAL_NOT_UNIQUE         (-1765328376L)
#define KRB5KDC_ERR_NULL_KEY                     (-1765328375L)
#define KRB5KDC_ERR_CANNOT_POSTDATE              (-1765328374L)
#define KRB5KDC_ERR_NEVER_VALID                  (-1765328373L)
#define KRB5KDC_ERR_POLICY                       (-1765328372L)
#define KRB5KDC_ERR_BADOPTION                    (-1765328371L)
#define KRB5KDC_ERR_ETYPE_NOSUPP                 (-1765328370L)
#define KRB5KDC_ERR_SUMTYPE_NOSUPP               (-1765328369L)
#define KRB5KDC_ERR_PADATA_TYPE_NOSUPP           (-1765328368L)
#define KRB5KDC_ERR_TRTYPE_NOSUPP                (-1765328367L)
#define KRB5KDC_ERR_CLIENT_REVOKED               (-1765328366L)
#define KRB5KDC_ERR_SERVICE_REVOKED              (-1765328365L)
#define KRB5KDC_ERR_TGT_REVOKED                  (-1765328364L)
#define KRB5KDC_ERR_CLIENT_NOTYET                (-1765328363L)
#define KRB5KDC_ERR_SERVICE_NOTYET               (-1765328362L)
#define KRB5KDC_ERR_KEY_EXP                      (-1765328361L)
#define KRB5KDC_ERR_PREAUTH_FAILED               (-1765328360L)
#define KRB5KDC_ERR_PREAUTH_REQUIRED             (-1765328359L)
#define KRB5KDC_ERR_SERVER_NOMATCH               (-1765328358L)
#define KRB5PLACEHOLD_27                         (-1765328357L)
#define KRB5PLACEHOLD_28                         (-1765328356L)
#define KRB5PLACEHOLD_29                         (-1765328355L)
#define KRB5PLACEHOLD_30                         (-1765328354L)
#define KRB5KRB_AP_ERR_BAD_INTEGRITY             (-1765328353L)
#define KRB5KRB_AP_ERR_TKT_EXPIRED               (-1765328352L)
#define KRB5KRB_AP_ERR_TKT_NYV                   (-1765328351L)
#define KRB5KRB_AP_ERR_REPEAT                    (-1765328350L)
#define KRB5KRB_AP_ERR_NOT_US                    (-1765328349L)
#define KRB5KRB_AP_ERR_BADMATCH                  (-1765328348L)
#define KRB5KRB_AP_ERR_SKEW                      (-1765328347L)
#define KRB5KRB_AP_ERR_BADADDR                   (-1765328346L)
#define KRB5KRB_AP_ERR_BADVERSION                (-1765328345L)
#define KRB5KRB_AP_ERR_MSG_TYPE                  (-1765328344L)
#define KRB5KRB_AP_ERR_MODIFIED                  (-1765328343L)
#define KRB5KRB_AP_ERR_BADORDER                  (-1765328342L)
#define KRB5KRB_AP_ERR_ILL_CR_TKT                (-1765328341L)
#define KRB5KRB_AP_ERR_BADKEYVER                 (-1765328340L)
#define KRB5KRB_AP_ERR_NOKEY                     (-1765328339L)
#define KRB5KRB_AP_ERR_MUT_FAIL                  (-1765328338L)
#define KRB5KRB_AP_ERR_BADDIRECTION              (-1765328337L)
#define KRB5KRB_AP_ERR_METHOD                    (-1765328336L)
#define KRB5KRB_AP_ERR_BADSEQ                    (-1765328335L)
#define KRB5KRB_AP_ERR_INAPP_CKSUM               (-1765328334L)
#define KRB5PLACEHOLD_51                         (-1765328333L)
#define KRB5PLACEHOLD_52                         (-1765328332L)
#define KRB5PLACEHOLD_53                         (-1765328331L)
#define KRB5PLACEHOLD_54                         (-1765328330L)
#define KRB5PLACEHOLD_55                         (-1765328329L)
#define KRB5PLACEHOLD_56                         (-1765328328L)
#define KRB5PLACEHOLD_57                         (-1765328327L)
#define KRB5PLACEHOLD_58                         (-1765328326L)
#define KRB5PLACEHOLD_59                         (-1765328325L)
#define KRB5KRB_ERR_GENERIC                      (-1765328324L)
#define KRB5KRB_ERR_FIELD_TOOLONG                (-1765328323L)
#define KRB5PLACEHOLD_62                         (-1765328322L)
#define KRB5PLACEHOLD_63                         (-1765328321L)
#define KRB5PLACEHOLD_64                         (-1765328320L)
#define KRB5PLACEHOLD_65                         (-1765328319L)
#define KRB5PLACEHOLD_66                         (-1765328318L)
#define KRB5PLACEHOLD_67                         (-1765328317L)
#define KRB5PLACEHOLD_68                         (-1765328316L)
#define KRB5PLACEHOLD_69                         (-1765328315L)
#define KRB5PLACEHOLD_70                         (-1765328314L)
#define KRB5PLACEHOLD_71                         (-1765328313L)
#define KRB5PLACEHOLD_72                         (-1765328312L)
#define KRB5PLACEHOLD_73                         (-1765328311L)
#define KRB5PLACEHOLD_74                         (-1765328310L)
#define KRB5PLACEHOLD_75                         (-1765328309L)
#define KRB5PLACEHOLD_76                         (-1765328308L)
#define KRB5PLACEHOLD_77                         (-1765328307L)
#define KRB5PLACEHOLD_78                         (-1765328306L)
#define KRB5PLACEHOLD_79                         (-1765328305L)
#define KRB5PLACEHOLD_80                         (-1765328304L)
#define KRB5PLACEHOLD_81                         (-1765328303L)
#define KRB5PLACEHOLD_82                         (-1765328302L)
#define KRB5PLACEHOLD_83                         (-1765328301L)
#define KRB5PLACEHOLD_84                         (-1765328300L)
#define KRB5PLACEHOLD_85                         (-1765328299L)
#define KRB5PLACEHOLD_86                         (-1765328298L)
#define KRB5PLACEHOLD_87                         (-1765328297L)
#define KRB5PLACEHOLD_88                         (-1765328296L)
#define KRB5PLACEHOLD_89                         (-1765328295L)
#define KRB5PLACEHOLD_90                         (-1765328294L)
#define KRB5PLACEHOLD_91                         (-1765328293L)
#define KRB5PLACEHOLD_92                         (-1765328292L)
#define KRB5PLACEHOLD_93                         (-1765328291L)
#define KRB5PLACEHOLD_94                         (-1765328290L)
#define KRB5PLACEHOLD_95                         (-1765328289L)
#define KRB5PLACEHOLD_96                         (-1765328288L)
#define KRB5PLACEHOLD_97                         (-1765328287L)
#define KRB5PLACEHOLD_98                         (-1765328286L)
#define KRB5PLACEHOLD_99                         (-1765328285L)
#define KRB5PLACEHOLD_100                        (-1765328284L)
#define KRB5PLACEHOLD_101                        (-1765328283L)
#define KRB5PLACEHOLD_102                        (-1765328282L)
#define KRB5PLACEHOLD_103                        (-1765328281L)
#define KRB5PLACEHOLD_104                        (-1765328280L)
#define KRB5PLACEHOLD_105                        (-1765328279L)
#define KRB5PLACEHOLD_106                        (-1765328278L)
#define KRB5PLACEHOLD_107                        (-1765328277L)
#define KRB5PLACEHOLD_108                        (-1765328276L)
#define KRB5PLACEHOLD_109                        (-1765328275L)
#define KRB5PLACEHOLD_110                        (-1765328274L)
#define KRB5PLACEHOLD_111                        (-1765328273L)
#define KRB5PLACEHOLD_112                        (-1765328272L)
#define KRB5PLACEHOLD_113                        (-1765328271L)
#define KRB5PLACEHOLD_114                        (-1765328270L)
#define KRB5PLACEHOLD_115                        (-1765328269L)
#define KRB5PLACEHOLD_116                        (-1765328268L)
#define KRB5PLACEHOLD_117                        (-1765328267L)
#define KRB5PLACEHOLD_118                        (-1765328266L)
#define KRB5PLACEHOLD_119                        (-1765328265L)
#define KRB5PLACEHOLD_120                        (-1765328264L)
#define KRB5PLACEHOLD_121                        (-1765328263L)
#define KRB5PLACEHOLD_122                        (-1765328262L)
#define KRB5PLACEHOLD_123                        (-1765328261L)
#define KRB5PLACEHOLD_124                        (-1765328260L)
#define KRB5PLACEHOLD_125                        (-1765328259L)
#define KRB5PLACEHOLD_126                        (-1765328258L)
#define KRB5PLACEHOLD_127                        (-1765328257L)
#define KRB5_ERR_RCSID                           (-1765328256L)
#define KRB5_LIBOS_BADLOCKFLAG                   (-1765328255L)
#define KRB5_LIBOS_CANTREADPWD                   (-1765328254L)
#define KRB5_LIBOS_BADPWDMATCH                   (-1765328253L)
#define KRB5_LIBOS_PWDINTR                       (-1765328252L)
#define KRB5_PARSE_ILLCHAR                       (-1765328251L)
#define KRB5_PARSE_MALFORMED                     (-1765328250L)
#define KRB5_CONFIG_CANTOPEN                     (-1765328249L)
#define KRB5_CONFIG_BADFORMAT                    (-1765328248L)
#define KRB5_CONFIG_NOTENUFSPACE                 (-1765328247L)
#define KRB5_BADMSGTYPE                          (-1765328246L)
#define KRB5_CC_BADNAME                          (-1765328245L)
#define KRB5_CC_UNKNOWN_TYPE                     (-1765328244L)
#define KRB5_CC_NOTFOUND                         (-1765328243L)
#define KRB5_CC_END                              (-1765328242L)
#define KRB5_NO_TKT_SUPPLIED                     (-1765328241L)
#define KRB5KRB_AP_WRONG_PRINC                   (-1765328240L)
#define KRB5KRB_AP_ERR_TKT_INVALID               (-1765328239L)
#define KRB5_PRINC_NOMATCH                       (-1765328238L)
#define KRB5_KDCREP_MODIFIED                     (-1765328237L)
#define KRB5_KDCREP_SKEW                         (-1765328236L)
#define KRB5_IN_TKT_REALM_MISMATCH               (-1765328235L)
#define KRB5_PROG_ETYPE_NOSUPP                   (-1765328234L)
#define KRB5_PROG_KEYTYPE_NOSUPP                 (-1765328233L)
#define KRB5_WRONG_ETYPE                         (-1765328232L)
#define KRB5_PROG_SUMTYPE_NOSUPP                 (-1765328231L)
#define KRB5_REALM_UNKNOWN                       (-1765328230L)
#define KRB5_SERVICE_UNKNOWN                     (-1765328229L)
#define KRB5_KDC_UNREACH                         (-1765328228L)
#define KRB5_NO_LOCALNAME                        (-1765328227L)
#define KRB5_RC_TYPE_EXISTS                      (-1765328226L)
#define KRB5_RC_MALLOC                           (-1765328225L)
#define KRB5_RC_TYPE_NOTFOUND                    (-1765328224L)
#define KRB5_RC_UNKNOWN                          (-1765328223L)
#define KRB5_RC_REPLAY                           (-1765328222L)
#define KRB5_RC_IO                               (-1765328221L)
#define KRB5_RC_NOIO                             (-1765328220L)
#define KRB5_RC_PARSE                            (-1765328219L)
#define KRB5_RC_IO_EOF                           (-1765328218L)
#define KRB5_RC_IO_MALLOC                        (-1765328217L)
#define KRB5_RC_IO_PERM                          (-1765328216L)
#define KRB5_RC_IO_IO                            (-1765328215L)
#define KRB5_RC_IO_UNKNOWN                       (-1765328214L)
#define KRB5_RC_IO_SPACE                         (-1765328213L)
#define KRB5_TRANS_CANTOPEN                      (-1765328212L)
#define KRB5_TRANS_BADFORMAT                     (-1765328211L)
#define KRB5_LNAME_CANTOPEN                      (-1765328210L)
#define KRB5_LNAME_NOTRANS                       (-1765328209L)
#define KRB5_LNAME_BADFORMAT                     (-1765328208L)
#define KRB5_CRYPTO_INTERNAL                     (-1765328207L)
#define KRB5_KT_BADNAME                          (-1765328206L)
#define KRB5_KT_UNKNOWN_TYPE                     (-1765328205L)
#define KRB5_KT_NOTFOUND                         (-1765328204L)
#define KRB5_KT_END                              (-1765328203L)
#define KRB5_KT_NOWRITE                          (-1765328202L)
#define KRB5_KT_IOERR                            (-1765328201L)
#define KRB5_NO_TKT_IN_RLM                       (-1765328200L)
#define KRB5DES_BAD_KEYPAR                       (-1765328199L)
#define KRB5DES_WEAK_KEY                         (-1765328198L)
#define KRB5_BAD_KEYTYPE                         (-1765328197L)
#define KRB5_BAD_KEYSIZE                         (-1765328196L)
#define KRB5_BAD_MSIZE                           (-1765328195L)
#define KRB5_CC_TYPE_EXISTS                      (-1765328194L)
#define KRB5_KT_TYPE_EXISTS                      (-1765328193L)
#define KRB5_CC_IO                               (-1765328192L)
#define KRB5_FCC_PERM                            (-1765328191L)
#define KRB5_FCC_NOFILE                          (-1765328190L)
#define KRB5_FCC_INTERNAL                        (-1765328189L)
#define KRB5_CC_WRITE                            (-1765328188L)
#define KRB5_CC_NOMEM                            (-1765328187L)
#define KRB5_INVALID_FLAGS                       (-1765328186L)
#define KRB5_NO_2ND_TKT                          (-1765328185L)
#define KRB5_NOCREDS_SUPPLIED                    (-1765328184L)
#define KRB5_SENDAUTH_BADAUTHVERS                (-1765328183L)
#define KRB5_SENDAUTH_BADAPPLVERS                (-1765328182L)
#define KRB5_SENDAUTH_BADRESPONSE                (-1765328181L)
#define KRB5_SENDAUTH_REJECTED                   (-1765328180L)
#define KRB5_SENDAUTH_MUTUAL_FAILED              (-1765328179L)
#define KRB5_PREAUTH_BAD_TYPE                    (-1765328178L)
#define KRB5_PREAUTH_NO_KEY                      (-1765328177L)
#define KRB5_PREAUTH_FAILED                      (-1765328176L)
#define KRB5_RCACHE_BADVNO                       (-1765328175L)
#define KRB5_CCACHE_BADVNO                       (-1765328174L)
#define KRB5_KEYTAB_BADVNO                       (-1765328173L)
#define KRB5_PROG_ATYPE_NOSUPP                   (-1765328172L)
#define KRB5_RC_REQUIRED                         (-1765328171L)
#define KRB5_ERR_BAD_HOSTNAME                    (-1765328170L)
#define KRB5_ERR_HOST_REALM_UNKNOWN              (-1765328169L)
#define KRB5_SNAME_UNSUPP_NAMETYPE               (-1765328168L)
#define KRB5KRB_AP_ERR_V4_REPLY                  (-1765328167L)
#define KRB5_REALM_CANT_RESOLVE                  (-1765328166L)
#define KRB5_TKT_NOT_FORWARDABLE                 (-1765328165L)
extern void initialize_krb5_error_table ();
#define ERROR_TABLE_BASE_krb5 (-1765328384L)

/* for compatibility with older versions... */
#define init_krb5_err_tbl initialize_krb5_error_table
#define krb5_err_base ERROR_TABLE_BASE_krb5
/*
 * include/krb5/kdb5_err.h:
 * This file is automatically generated; please do not edit it.
 */
#define KRB5_KDB_RCSID                           (-1780008448L)
#define KRB5_KDB_INUSE                           (-1780008447L)
#define KRB5_KDB_UK_SERROR                       (-1780008446L)
#define KRB5_KDB_UK_RERROR                       (-1780008445L)
#define KRB5_KDB_UNAUTH                          (-1780008444L)
#define KRB5_KDB_NOENTRY                         (-1780008443L)
#define KRB5_KDB_ILL_WILDCARD                    (-1780008442L)
#define KRB5_KDB_DB_INUSE                        (-1780008441L)
#define KRB5_KDB_DB_CHANGED                      (-1780008440L)
#define KRB5_KDB_TRUNCATED_RECORD                (-1780008439L)
#define KRB5_KDB_RECURSIVELOCK                   (-1780008438L)
#define KRB5_KDB_NOTLOCKED                       (-1780008437L)
#define KRB5_KDB_BADLOCKMODE                     (-1780008436L)
#define KRB5_KDB_DBNOTINITED                     (-1780008435L)
#define KRB5_KDB_DBINITED                        (-1780008434L)
#define KRB5_KDB_ILLDIRECTION                    (-1780008433L)
#define KRB5_KDB_NOMASTERKEY                     (-1780008432L)
#define KRB5_KDB_BADMASTERKEY                    (-1780008431L)
#define KRB5_KDB_INVALIDKEYSIZE                  (-1780008430L)
#define KRB5_KDB_CANTREAD_STORED                 (-1780008429L)
#define KRB5_KDB_BADSTORED_MKEY                  (-1780008428L)
#define KRB5_KDB_CANTLOCK_DB                     (-1780008427L)
#define KRB5_KDB_DB_CORRUPT                      (-1780008426L)
#define KRB5_KDB_BAD_VERSION                     (-1780008425L)
#define KRB5_KDB_BAD_SALTTYPE                    (-1780008424L)
#define KRB5_KDB_BAD_KEYTYPE                     (-1780008423L)
extern void initialize_kdb5_error_table ();
#define ERROR_TABLE_BASE_kdb5 (-1780008448L)

/* for compatibility with older versions... */
#define init_kdb5_err_tbl initialize_kdb5_error_table
#define kdb5_err_base ERROR_TABLE_BASE_kdb5
/*
 * include/krb5/kv5m_err.h:
 * This file is automatically generated; please do not edit it.
 */
#define KV5M_NONE                                (-1760647424L)
#define KV5M_PRINCIPAL                           (-1760647423L)
#define KV5M_DATA                                (-1760647422L)
#define KV5M_KEYBLOCK                            (-1760647421L)
#define KV5M_CHECKSUM                            (-1760647420L)
#define KV5M_ENCRYPT_BLOCK                       (-1760647419L)
#define KV5M_ENC_DATA                            (-1760647418L)
#define KV5M_CRYPTOSYSTEM_ENTRY                  (-1760647417L)
#define KV5M_CS_TABLE_ENTRY                      (-1760647416L)
#define KV5M_CHECKSUM_ENTRY                      (-1760647415L)
#define KV5M_AUTHDATA                            (-1760647414L)
#define KV5M_TRANSITED                           (-1760647413L)
#define KV5M_ENC_TKT_PART                        (-1760647412L)
#define KV5M_TICKET                              (-1760647411L)
#define KV5M_AUTHENTICATOR                       (-1760647410L)
#define KV5M_TKT_AUTHENT                         (-1760647409L)
#define KV5M_CREDS                               (-1760647408L)
#define KV5M_LAST_REQ_ENTRY                      (-1760647407L)
#define KV5M_PA_DATA                             (-1760647406L)
#define KV5M_KDC_REQ                             (-1760647405L)
#define KV5M_ENC_KDC_REP_PART                    (-1760647404L)
#define KV5M_KDC_REP                             (-1760647403L)
#define KV5M_ERROR                               (-1760647402L)
#define KV5M_AP_REQ                              (-1760647401L)
#define KV5M_AP_REP                              (-1760647400L)
#define KV5M_AP_REP_ENC_PART                     (-1760647399L)
#define KV5M_RESPONSE                            (-1760647398L)
#define KV5M_SAFE                                (-1760647397L)
#define KV5M_PRIV                                (-1760647396L)
#define KV5M_PRIV_ENC_PART                       (-1760647395L)
#define KV5M_CRED                                (-1760647394L)
#define KV5M_CRED_INFO                           (-1760647393L)
#define KV5M_CRED_ENC_PART                       (-1760647392L)
#define KV5M_PWD_DATA                            (-1760647391L)
#define KV5M_ADDRESS                             (-1760647390L)
#define KV5M_KEYTAB_ENTRY                        (-1760647389L)
#define KV5M_CONTEXT                             (-1760647388L)
#define KV5M_OS_CONTEXT                          (-1760647387L)
#define KV5M_ALT_METHOD                          (-1760647386L)
#define KV5M_ETYPE_INFO_ENTRY                    (-1760647385L)
#define KV5M_DB_CONTEXT                          (-1760647384L)
#define KV5M_AUTH_CONTEXT                        (-1760647383L)
#define KV5M_KEYTAB                              (-1760647382L)
#define KV5M_RCACHE                              (-1760647381L)
#define KV5M_CCACHE                              (-1760647380L)
extern void initialize_kv5m_error_table ();
#define ERROR_TABLE_BASE_kv5m (-1760647424L)

/* for compatibility with older versions... */
#define init_kv5m_err_tbl initialize_kv5m_error_table
#define kv5m_err_base ERROR_TABLE_BASE_kv5m
/*
 * include/krb5/asn1_err.h:
 * This file is automatically generated; please do not edit it.
 */
#define ASN1_BAD_TIMEFORMAT                      (1859794432L)
#define ASN1_MISSING_FIELD                       (1859794433L)
#define ASN1_MISPLACED_FIELD                     (1859794434L)
#define ASN1_TYPE_MISMATCH                       (1859794435L)
#define ASN1_OVERFLOW                            (1859794436L)
#define ASN1_OVERRUN                             (1859794437L)
#define ASN1_BAD_ID                              (1859794438L)
#define ASN1_BAD_LENGTH                          (1859794439L)
#define ASN1_BAD_FORMAT                          (1859794440L)
#define ASN1_PARSE_ERROR                         (1859794441L)
extern void initialize_asn1_error_table ();
#define ERROR_TABLE_BASE_asn1 (1859794432L)

/* for compatibility with older versions... */
#define init_asn1_err_tbl initialize_asn1_error_table
#define asn1_err_base ERROR_TABLE_BASE_asn1
