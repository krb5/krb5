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
 * krb425.h
 */


#ifndef KRB5_krb425__
#define KRB5_krb425__

#include <krb5/copyright.h>
#include <ctype.h>
#include <netdb.h>
#include <krb.h>
#include <krb5/krb5.h>
#include <krb5/libos-proto.h>
#include <krb5/asn1.h>
#include <netinet/in.h>
#include <stdio.h>
#include <krb5/ext-proto.h>

#define min(a,b)	((a) < (b) ? (a) : (b))

#define	set_data5(d5,s)	d5.length = strlen(s); d5.data = s

#define	set_cksum(ck,v)	{ \
	ck.checksum_type = CKSUMTYPE_CRC32; \
	ck.length = sizeof(v); \
	ck.contents = (krb5_octet *)&v; \
}

#define	set_string(str,sz,d5) { \
	if (d5) { \
		int x; \
		x = min(sz-1, d5->length); \
		strncpy(str, d5->data, x); \
		str[x] = 0; \
	} else \
		str[0] = 0; \
}

extern char 		*_krb425_local_realm;
extern krb5_ccache 	_krb425_ccache;
extern int		_krb425_error_init;


extern int	krb425error();

extern char *basename();
extern int des_key_sched();
extern int kname_parse();
extern int krb_get_cred();
extern int krb_get_lrealm();
extern int krb_kntoln();
extern long krb_mk_priv();
extern int krb_mk_req();
extern int krb_net_read();
extern int krb_net_write();
extern long krb_rd_priv();
extern int krb_rd_req();
extern int mit_des_string_to_key();


#ifdef	EBUG
#define	PLINE		{ fprintf(stderr, "%26s:%4d\n", basename(__FILE__),__LINE__); \
			  fflush(stderr); }
#define	show5(x)	fprintf(stderr, "``%.*s''", x.length, x.data)
#define	EPRINT		fprintf(stderr, "%26s:%4d: ", basename(__FILE__), __LINE__), \
			fprintf(stderr,
#define	ENEWLINE	fprintf(stderr, "\n");
#define	ERROR(error)	{ \
	if (!_krb425_error_init) { \
		_krb425_error_init = 1; \
		krb5_init_ets(); \
	} \
	fprintf(stderr, "%26s:%4d: %s (%d)\n", basename(__FILE__), __LINE__, \
		error_message(error), error); \
}
#else
#define	PLINE
#endif

#endif /* KRB5_krb425__ */

