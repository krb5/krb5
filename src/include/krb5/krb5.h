/*
 * $Source$
 * $Author$
 * $Id$
 *
 * Copyright 1989,1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/mit-copyright.h>.
 *
 * General definitions for Kerberos version 5.
 */

#include <krb5/copyright.h>

#ifndef __KRB5_GENERAL__
#define __KRB5_GENERAL__

#include <sys/types.h>

#include <krb5/config.h>

#include <krb5/base-defs.h>
#include <krb5/hostaddr.h>
#include <krb5/encryption.h>
#include <krb5/fieldbits.h>
#include <krb5/errors.h>
#include <krb5/proto.h>
#include <krb5/macros.h>

/* Time set */
typedef struct _krb5_ticket_times {
    krb5_timestamp authtime; /* XXX ? should ktime in KDC_REP == authtime
				in ticket? otherwise client can't get this */ 
    krb5_timestamp starttime;
    krb5_timestamp endtime;
    krb5_timestamp renew_till;
} krb5_ticket_times;

/* structure for auth data */
typedef struct _krb5_authdata {
    krb5_authdatatype ad_type;
    int length;
    krb5_octet *contents;
} krb5_authdata;

typedef struct _krb5_enc_tkt_part {
    /* to-be-encrypted portion */
    krb5_confounder confounder;		/* confounder */
    krb5_flags flags;			/* flags */
    krb5_keyblock *session;		/* session key: includes keytype */
    krb5_principal client;		/* client name/realm */
    krb5_data transited;		/* list of transited realms */
    krb5_ticket_times times;		/* auth, start, end, renew_till */
    krb5_address **caddrs;		/* array of ptrs to addresses */
    krb5_authdata **authorization_data;	/* auth data */
} krb5_enc_tkt_part;

typedef struct _krb5_ticket {
    /* cleartext portion */
    krb5_principal server;		/* server name/realm */
    krb5_enctype etype;			/* ticket encryption type */
    krb5_kvno skvno;			/* server kvno */
    krb5_data enc_part;			/* encrypted encoding,
					   see above for hidden contents */
    krb5_enc_tkt_part *enc_part2;	/* ptr to decrypted version, if
					   available */
} krb5_ticket;

/* the unencrypted version */
typedef struct _krb5_authenticator {
    krb5_principal client;		/* client name/realm */
    krb5_checksum *checksum;		/* checksum, includes type */
    krb5_ui_2 cmsec;			/* client msec portion */
    krb5_timestamp ctime;		/* client sec portion */
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
    krb5_data ticket;			/* ticket string itself */
    krb5_data second_ticket;		/* second ticket, if related to
					   ticket (via DUPLICATE-SKEY or
					   ENC-TKT-IN-SKEY) */
} krb5_creds;

/* Last request fields */
typedef struct _krb5_last_req_entry {
    krb5_ui_4 value;
    krb5_octet lr_type;
} krb5_last_req_entry;

typedef struct _krb5_as_req {
    krb5_flags kdc_options;		/* requested options */
    krb5_timestamp ctime;		/* client's time */
    krb5_timestamp from;		/* requested starttime */
    krb5_timestamp till;		/* requested endtime */
    krb5_timestamp rtime;		/* (optional) requested renew_till */
    krb5_enctype etype;			/* requested encryption type */
    krb5_principal client;		/* includes realm */
    krb5_address **addresses;		/* requested addresses */
    krb5_principal server;		/* includes realm (but not used) */
} krb5_as_req;

typedef struct _krb5_enc_kdc_rep_part {
    /* encrypted part: */
    krb5_confounder confounder;		/* confounder */
    krb5_keyblock *session;		/* session key */
    krb5_last_req_entry **last_req;	/* array of ptrs to entries */
    krb5_timestamp ctime;		/* client timestamp */
    krb5_timestamp key_exp;		/* expiration date */
    krb5_flags flags;			/* ticket flags */
    krb5_ticket_times times;		/* lifetime info */
    krb5_principal server;		/* server's principal identifier */
    krb5_address **caddrs;		/* array of ptrs to addresses */
} krb5_enc_kdc_rep_part;

typedef struct _krb5_kdc_rep {
    /* cleartext part: */
    krb5_principal client;		/* client's principal identifier */
    krb5_enctype etype;			/* encryption type */
    krb5_kvno ckvno;			/* client key version */
    krb5_ticket *ticket;		/* ticket */
    krb5_data enc_part;			/* encrypted part */
    krb5_enc_kdc_rep_part *enc_part2;	/* unencrypted version, if available */
} krb5_kdc_rep;

/* error message structure */
typedef struct _krb5_error {
    /* some of these may be meaningless in certain contexts */
    krb5_timestamp ctime;		/* client sec portion */
    krb5_ui_2 cmsec;			/* client msec portion */
    krb5_ui_2 smsec;			/* server msec portion */
    krb5_timestamp stime;		/* server sec portion */
    krb5_ui_4 error;			/* error code (protocol error #'s) */
    krb5_principal client;		/* client's principal identifier */
    krb5_principal server;		/* server's principal identifier */
    krb5_data text;			/* descriptive text */
} krb5_error;

typedef struct _krb5_ap_req {
    krb5_flags ap_options;		/* requested options */
    krb5_ticket *ticket;		/* ticket */
    krb5_data authenticator;		/* authenticator (already encrypted) */
} krb5_ap_req;

typedef struct _krb5_ap_rep {
    krb5_data enc_part;
} krb5_ap_rep;

typedef struct _krb5_ap_rep_enc_part {
    krb5_timestamp ctime;		/* client time, seconds portion */
    krb5_ui_2 cmsec;			/* client time, milliseconds portion */
} krb5_ap_rep_enc_part;

typedef struct _krb5_response {
    krb5_octet message_type;
    krb5_data *response;
} krb5_response;

typedef struct _krb5_tgs_req_enc_part {
    krb5_authdata **authorization_data;	/* auth data */
    krb5_ticket *second_ticket;		/* second ticket */
} krb5_tgs_req_enc_part;

typedef struct _krb5_real_tgs_req {
    krb5_flags kdc_options;		/* requested options */
    krb5_timestamp from;		/* requested starttime */
    krb5_timestamp till;		/* requested endtime */
    krb5_timestamp rtime;		/* (optional) requested renew_till */
    krb5_timestamp ctime;		/* client's time */
    krb5_enctype etype;			/* encryption type */
    krb5_principal server;		/* server's principal identifier */
    krb5_address **addresses;		/* array of ptrs to addresses */
    krb5_data enc_part;			/* (optional) encrypted part */
    krb5_tgs_req_enc_part *enc_part2;	/* ptr to decrypted version, if
					   available */
} krb5_real_tgs_req;

typedef struct _krb5_tgs_req {
    krb5_data header;			/* encoded AP-REQ */
    krb5_data tgs_request;		/* encoded krb5_real_tgs_req */
    krb5_ap_req *header2;		/* pointer to decoded, if available */
    krb5_real_tgs_req *tgs_request2;	/* pointer to decoded, if available */
} krb5_tgs_req;

typedef struct _krb5_safe {
    krb5_data user_data;		/* user data */
    krb5_timestamp timestamp;		/* client time */
    krb5_ui_2 msec;			/* millisecond portion of time */
    krb5_address **addresses;		/* array of ptrs to addresses */
    krb5_checksum *checksum;		/* data integrity checksum */
} krb5_safe;

typedef struct _krb5_priv {
    krb5_enctype etype;			/* encryption type */
    krb5_data enc_part;			/* encrypted part */
} krb5_priv;

typedef struct _krb5_priv_enc_part {
    krb5_data user_data;		/* user data */
    krb5_timestamp timestamp;		/* client time */
    krb5_ui_2 msec;			/* millisecond portion of time */
    krb5_address **addresses;		/* array of ptrs to addresses */
} krb5_priv_enc_part;

/* these need to be here so the typedefs are available for the prototypes */
#include <krb5/ccache.h>
#include <krb5/rcache.h>
#include <krb5/keytab.h>
#include <krb5/func-proto.h>

#endif /* __KRB5_GENERAL__ */
