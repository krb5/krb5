/*
 * lib/kadm/str_conv.c
 *
 * Copyright 1995 by the Massachusetts Institute of Technology.
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
 */

/*
 * str_conv.c - Convert between strings and Kerberos internal data.
 */

/*
 * Table of contents:
 *
 * String decoding:
 * ----------------
 * krb5_string_to_flags()	- Convert string to krb5_flags.
 *
 * String encoding:
 * ----------------
 * krb5_flags_to_string()	- Convert krb5_flags to string.
 */

#include "k5-int.h"
#include "adm.h"
#include "adm_proto.h"

/*
 * Local data structures.
 */
struct flags_lookup_entry {
    krb5_flags		fl_flags;		/* Flag			*/
    krb5_boolean	fl_sense;		/* Sense of the flag	*/
    const char *	fl_specifier;		/* How to recognize it	*/
    const char *	fl_output;		/* How to spit it out	*/
};

/*
 * Local strings
 */

/* Keytype strings */
/* Flags strings */
static const char flags_pdate_in[]	= "postdateable";
static const char flags_fwd_in[]	= "forwardable";
static const char flags_tgtbased_in[]	= "tgt-based";
static const char flags_renew_in[]	= "renewable";
static const char flags_proxy_in[]	= "proxiable";
static const char flags_dup_skey_in[]	= "dup-skey";
static const char flags_tickets_in[]	= "allow-tickets";
static const char flags_preauth_in[]	= "preauth";
static const char flags_hwauth_in[]	= "hwauth";
static const char flags_pwchange_in[]	= "pwchange";
static const char flags_service_in[]	= "service";
static const char flags_pwsvc_in[]	= "pwservice";
static const char flags_md5_in[]	= "md5";
static const char flags_pdate_out[]	= "Not Postdateable";
static const char flags_fwd_out[]	= "Not Forwardable";
static const char flags_tgtbased_out[]	= "No TGT-based requests";
static const char flags_renew_out[]	= "Not renewable";
static const char flags_proxy_out[]	= "Not proxiable";
static const char flags_dup_skey_out[]	= "No DUP_SKEY requests";
static const char flags_tickets_out[]	= "All Tickets Disallowed";
static const char flags_preauth_out[]	= "Preauthorization required";
static const char flags_hwauth_out[]	= "HW Authorization required";
static const char flags_pwchange_out[]	= "Password Change required";
static const char flags_service_out[]	= "Service Disabled";
static const char flags_pwsvc_out[]	= "Password Changing Service";
static const char flags_md5_out[]	= "RSA-MD5 supported";
static const char flags_default_neg[]	= "-";
static const char flags_default_sep[]	= " ";

/*
 * Lookup tables.
 */

static const struct flags_lookup_entry flags_table[] = {
/* flag				sense	input specifier	   output string     */
/*----------------------------- -------	------------------ ------------------*/
{ KRB5_KDB_DISALLOW_POSTDATED,	0,	flags_pdate_in,	   flags_pdate_out   },
{ KRB5_KDB_DISALLOW_FORWARDABLE,0,	flags_fwd_in,	   flags_fwd_out     },
{ KRB5_KDB_DISALLOW_TGT_BASED,	0,	flags_tgtbased_in, flags_tgtbased_out},
{ KRB5_KDB_DISALLOW_RENEWABLE,	0,	flags_renew_in,	   flags_renew_out   },
{ KRB5_KDB_DISALLOW_PROXIABLE,	0,	flags_proxy_in,	   flags_proxy_out   },
{ KRB5_KDB_DISALLOW_DUP_SKEY,	0,	flags_dup_skey_in, flags_dup_skey_out},
{ KRB5_KDB_DISALLOW_ALL_TIX,	0,	flags_tickets_in,  flags_tickets_out },
{ KRB5_KDB_REQUIRES_PRE_AUTH,	1,	flags_preauth_in,  flags_preauth_out },
{ KRB5_KDB_REQUIRES_HW_AUTH,	1,	flags_hwauth_in,   flags_hwauth_out  },
{ KRB5_KDB_REQUIRES_PWCHANGE,	1,	flags_pwchange_in, flags_pwchange_out},
{ KRB5_KDB_DISALLOW_SVR,	0,	flags_service_in,  flags_service_out },
{ KRB5_KDB_PWCHANGE_SERVICE,	1,	flags_pwsvc_in,	   flags_pwsvc_out   },
{ KRB5_KDB_SUPPORT_DESMD5,	1,	flags_md5_in,	   flags_md5_out     }
};
static const int flags_table_nents = sizeof(flags_table)/
				     sizeof(flags_table[0]);


krb5_error_code
krb5_string_to_flags(string, positive, negative, flagsp)
    char	* string;
    const char	* positive;
    const char	* negative;
    krb5_flags	* flagsp;
{
    int 	i;
    int 	found;
    const char	*neg;
    size_t	nsize, psize;
    int		cpos;
    int		sense;

    found = 0;
    /* We need to have a way to negate it. */
    neg = (negative) ? negative : flags_default_neg;
    nsize = strlen(neg);
    psize = (positive) ? strlen(positive) : 0;

    cpos = 0;
    sense = 1;
    /* First check for positive or negative sense */
    if (!strncasecmp(neg, string, nsize)) {
	sense = 0;
	cpos += (int) nsize;
    }
    else if (psize && !strncasecmp(positive, string, psize)) {
	cpos += (int) psize;
    }

    for (i=0; i<flags_table_nents; i++) {
	if (!strcasecmp(&string[cpos], flags_table[i].fl_specifier)) {
	    found = 1;
	    if (sense == (int) flags_table[i].fl_sense)
		*flagsp |= flags_table[i].fl_flags;
	    else
		*flagsp &= ~flags_table[i].fl_flags;

	    break;
	}
    }
    return((found) ? 0 : EINVAL);
}

krb5_error_code
krb5_flags_to_string(flags, sep, buffer, buflen)
    krb5_flags	flags;
    const char	* sep;
    char	* buffer;
    size_t	buflen;
{
    int			i;
    krb5_flags		pflags;
    const char		*sepstring;
    char		*op;
    int			initial;
    krb5_error_code	retval;

    retval = 0;
    op = buffer;
    pflags = 0;
    initial = 1;
    sepstring = (sep) ? sep : flags_default_sep;
    /* Blast through the table matching all we can */
    for (i=0; i<flags_table_nents; i++) {
	if (flags & flags_table[i].fl_flags) {
	    /* Found a match, see if it'll fit into the output buffer */
	    if ((op+strlen(flags_table[i].fl_output)+strlen(sepstring)) <
		(buffer + buflen)) {
		if (!initial) {
		    strcpy(op, sep);
		    op += strlen(sep);
		}
		initial = 0;
		strcpy(op, flags_table[i].fl_output);
		op += strlen(flags_table[i].fl_output);
	    }
	    else {
		retval = ENOMEM;
		break;
	    }
	    /* Keep track of what we matched */
	    pflags |= flags_table[i].fl_flags;
	}
    }
    if (!retval) {
	/* See if there's any leftovers */
	if (flags & ~pflags)
	    retval = EINVAL;
	else if (initial)
	    *buffer = '\0';
    }
    return(retval);
}
