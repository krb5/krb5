/*
 * $Source$
 * $Author$
 * $Id$
 *
 * Copyright 1989,1990 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * For copying and distribution information, please see the file
 * <krb5/copyright.h>.
 *
 * General definitions for Kerberos version 5.
 */

#include <krb5/copyright.h>

#ifndef KRB5_GENERAL__
#define KRB5_GENERAL__

#ifndef KRB5_SYSTYPES__
#define KRB5_SYSTYPES__
#include <sys/types.h>
#endif /* KRB5_SYSTYPES__ */

#include <krb5/config.h>

#include <krb5/base-defs.h>
#include <krb5/hostaddr.h>
#include <krb5/encryption.h>
#include <krb5/fieldbits.h>
#include <krb5/errors.h>
#include <krb5/proto.h>
#include <krb5/macros.h>
#include <krb5/error_def.h>

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
    krb5_authdatatype ad_type;
    int length;
    krb5_octet *contents;
} krb5_authdata;

/* structure for transited encoding */
typedef struct _krb5_transited {
    krb5_octet tr_type;
    krb5_data tr_contents;
} krb5_transited;

typedef struct _krb5_enc_tkt_part {
    /* to-be-encrypted portion */
    krb5_flags flags;			/* flags */
    krb5_keyblock *session;		/* session key: includes keytype */
    krb5_principal client;		/* client name/realm */
    krb5_transited transited;		/* list of transited realms */
    krb5_ticket_times times;		/* auth, start, end, renew_till */
    krb5_address **caddrs;		/* array of ptrs to addresses */
    krb5_authdata **authorization_data;	/* auth data */
} krb5_enc_tkt_part;

typedef struct _krb5_ticket {
    /* cleartext portion */
    krb5_principal server;		/* server name/realm */
    krb5_enc_data enc_part;		/* encryption type, kvno, encrypted
					   encoding */
    krb5_enc_tkt_part *enc_part2;	/* ptr to decrypted version, if
					   available */
} krb5_ticket;

/* the unencrypted version */
typedef struct _krb5_authenticator {
    krb5_principal client;		/* client name/realm */
    krb5_checksum *checksum;		/* checksum, includes type, optional */
    krb5_int32 cusec;			/* client usec portion */
    krb5_timestamp ctime;		/* client sec portion */
    krb5_keyblock *subkey;		/* true session key, optional */
    krb5_int32 seq_number;		/* sequence #, optional */
} krb5_authenticator;

typedef struct _krb5_tkt_authent {
    krb5_ticket *ticket;
    krb5_authenticator *authenticator;
    krb5_flags ap_options;
} krb5_tkt_authent;

/* credentials:  Ticket, session key, etc. */
typedef struct _krb5_creds {
    krb5_principal client;		/* client's principal identifier */
    krb5_principal server;		/* server's principal identifier */
    krb5_keyblock keyblock;		/* session encryption key info */
    krb5_ticket_times times;		/* lifetime info */
    krb5_boolean is_skey;		/* true if ticket is encrypted in
					   another ticket's skey */
    krb5_flags ticket_flags;		/* flags in ticket */
    krb5_address **addresses;		/* addrs in ticket */
    krb5_data ticket;			/* ticket string itself */
    krb5_data second_ticket;		/* second ticket, if related to
					   ticket (via DUPLICATE-SKEY or
					   ENC-TKT-IN-SKEY) */
    krb5_authdata **authdata;		/* authorization data */
} krb5_creds;

/* Last request fields */
typedef struct _krb5_last_req_entry {
    krb5_octet lr_type;
    krb5_timestamp value;
} krb5_last_req_entry;

/* pre-authentication data */
typedef struct _krb5_pa_data {
    krb5_ui_2  pa_type;
    int length;
    krb5_octet *contents;
} krb5_pa_data;

typedef struct _krb5_kdc_req {
    krb5_msgtype msg_type;		/* AS_REQ or TGS_REQ? */
    krb5_pa_data **padata;		/* e.g. encoded AP_REQ */
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
    krb5_enctype *etype;		/* requested encryption type(s) */
    krb5_address **addresses;		/* requested addresses, optional */
    krb5_enc_data authorization_data;	/* encrypted auth data; OPTIONAL */
    krb5_authdata **unenc_authdata;	/* unencrypted auth data,
					   if available */
    krb5_ticket **second_ticket;	/* second ticket array; OPTIONAL */
} krb5_kdc_req;

typedef struct _krb5_enc_kdc_rep_part {
    /* encrypted part: */
    krb5_keyblock *session;		/* session key */
    krb5_last_req_entry **last_req;	/* array of ptrs to entries */
    krb5_int32 nonce;			/* nonce from request */
    krb5_timestamp key_exp;		/* expiration date */
    krb5_flags flags;			/* ticket flags */
    krb5_ticket_times times;		/* lifetime info */
    krb5_principal server;		/* server's principal identifier */
    krb5_address **caddrs;		/* array of ptrs to addresses,
					   optional */
} krb5_enc_kdc_rep_part;

typedef struct _krb5_kdc_rep {
    /* cleartext part: */
    krb5_msgtype msg_type;		/* AS_REP or KDC_REP? */
    krb5_pa_data **padata;		/* preauthentication data from KDC */
    krb5_principal client;		/* client's principal identifier */
    krb5_ticket *ticket;		/* ticket */
    krb5_enc_data enc_part;		/* encryption type, kvno, encrypted
					   encoding */
    krb5_enc_kdc_rep_part *enc_part2;	/* unencrypted version, if available */
} krb5_kdc_rep;

/* error message structure */
typedef struct _krb5_error {
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
    krb5_flags ap_options;		/* requested options */
    krb5_ticket *ticket;		/* ticket */
    krb5_enc_data authenticator;	/* authenticator (already encrypted) */
} krb5_ap_req;

typedef struct _krb5_ap_rep {
    krb5_enc_data enc_part;
} krb5_ap_rep;

typedef struct _krb5_ap_rep_enc_part {
    krb5_timestamp ctime;		/* client time, seconds portion */
    krb5_int32 cusec;			/* client time, microseconds portion */
    krb5_keyblock *subkey;		/* true session key, optional */
    krb5_int32 seq_number;		/* sequence #, optional */
} krb5_ap_rep_enc_part;

typedef struct _krb5_response {
    krb5_octet message_type;
    krb5_data response;
} krb5_response;

typedef struct _krb5_safe {
    krb5_data user_data;		/* user data */
    krb5_timestamp timestamp;		/* client time, optional */
    krb5_int32 usec;			/* microsecond portion of time,
					   optional */
    krb5_int32 seq_number;		/* sequence #, optional */
    krb5_address *s_address;		/* sender address */
    krb5_address *r_address;		/* recipient address, optional */
    krb5_checksum *checksum;		/* data integrity checksum */
} krb5_safe;

typedef struct _krb5_priv {
    krb5_enc_data enc_part;		/* encrypted part */
} krb5_priv;

typedef struct _krb5_priv_enc_part {
    krb5_data user_data;		/* user data */
    krb5_timestamp timestamp;		/* client time, optional */
    krb5_int32 usec;			/* microsecond portion of time, opt. */
    krb5_int32 seq_number;		/* sequence #, optional */
    krb5_address *s_address;		/* sender address */
    krb5_address *r_address;		/* recipient address, optional */
} krb5_priv_enc_part;

/* these need to be here so the typedefs are available for the prototypes */
#include <krb5/safepriv.h>
#include <krb5/ccache.h>
#include <krb5/rcache.h>
#include <krb5/keytab.h>
#include <krb5/func-proto.h>
#include <krb5/free.h>

#endif /* KRB5_GENERAL__ */
