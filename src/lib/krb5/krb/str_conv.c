/*
 * lib/kadm/str_conv.c
 *
 * Copyright 1995, 2000 by the Massachusetts Institute of Technology.
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
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
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
 * krb5_string_to_enctype()	- Convert string to krb5_enctype.
 * krb5_string_to_salttype()	- Convert string to salttype (krb5_int32)
 * krb5_string_to_cksumtype()	- Convert string to krb5_cksumtype;
 * krb5_string_to_timestamp()	- Convert string to krb5_timestamp.
 * krb5_string_to_deltat()	- Convert string to krb5_deltat.
 *
 * String encoding:
 * ----------------
 * krb5_enctype_to_string()	- Convert krb5_enctype to string.
 * krb5_salttype_to_string()	- Convert salttype (krb5_int32) to string.
 * krb5_cksumtype_to_string()	- Convert krb5_cksumtype to string.
 * krb5_timestamp_to_string()	- Convert krb5_timestamp to string.
 * krb5_timestamp_to_sfstring()	- Convert krb5_timestamp to short filled string
 * krb5_deltat_to_string()	- Convert krb5_deltat to string.
 */

#include "k5-int.h"

/* Salt type conversions */

/*
 * Local data structures.
 */
struct enctype_lookup_entry {
    krb5_enctype	ktt_enctype;		/* Keytype		*/
    const char *	ktt_specifier;		/* How to recognize it	*/
    const char *	ktt_output;		/* How to spit it out	*/
};

struct salttype_lookup_entry {
    krb5_int32		stt_enctype;		/* Salt type		*/
    const char *	stt_specifier;		/* How to recognize it	*/
    const char *	stt_output;		/* How to spit it out	*/
};

struct cksumtype_lookup_entry {
    krb5_cksumtype	cst_cksumtype;		/* Checksum type	*/
    const char *	cst_specifier;		/* How to recognize it	*/
    const char *	cst_output;		/* How to spit it out	*/
};

/*
 * Local strings
 */

/* Keytype strings */
static const char enctype_des_in[]		= "des";
static const char enctype_null_in[]		= "null";
static const char enctype_descbccrc_in[]	= "des-cbc-crc";
static const char enctype_descbcmd4_in[]	= "des-cbc-md4";
static const char enctype_descbcmd5_in[]	= "des-cbc-md5";
static const char enctype_des3cbcsha_in[]	= "des3-cbc-sha";
static const char enctype_descbcraw_in[]	= "des-cbc-raw";
static const char enctype_null_out[]		= "Null";
static const char enctype_descbccrc_out[]	= "DES cbc mode with CRC-32";
static const char enctype_descbcmd4_out[]	= "DES cbc mode with RSA-MD4";
static const char enctype_descbcmd5_out[]	= "DES cbc mode with RSA-MD5";
static const char enctype_des3cbcsha_out[]	= "DES-3 cbc mode with NIST-SHA";
static const char enctype_descbcraw_out[]	= "DES cbc mode raw";

/* Checksum type strings */
static const char cstype_crc32_in[]	= "crc32";
static const char cstype_md4_in[]	= "md4";
static const char cstype_md4des_in[]	= "md4-des";
static const char cstype_descbc_in[]	= "des-cbc";
static const char cstype_md5_in[]	= "md5";
static const char cstype_md5des_in[]	= "md5-des";
static const char cstype_sha_in[]	= "sha";
static const char cstype_hmacsha_in[]	= "hmac-sha";
static const char cstype_crc32_out[]	= "CRC-32";
static const char cstype_md4_out[]	= "RSA-MD4";
static const char cstype_md4des_out[]	= "RSA-MD4 with DES cbc mode";
static const char cstype_descbc_out[]	= "DES cbc mode";
static const char cstype_md5_out[]	= "RSA-MD5";
static const char cstype_md5des_out[]	= "RSA-MD5 with DES cbc mode";
static const char cstype_sha_out[]	= "NIST-SHA";
static const char cstype_hmacsha_out[]	= "HMAC-SHA";

/*
 * Lookup tables.
 */

static const struct enctype_lookup_entry enctype_table[] = {
/* krb5_enctype		input specifier		output string		*/
/*-------------		-----------------------	------------------------*/
{ ENCTYPE_NULL,		enctype_null_in,	enctype_null_out	},
{ ENCTYPE_DES_CBC_MD5,	enctype_des_in,		enctype_descbcmd5_out	},
{ ENCTYPE_DES_CBC_CRC,	enctype_descbccrc_in,	enctype_descbccrc_out	},
{ ENCTYPE_DES_CBC_MD4,	enctype_descbcmd4_in,	enctype_descbcmd4_out	},
{ ENCTYPE_DES_CBC_MD5,	enctype_descbcmd5_in,	enctype_descbcmd5_out	},
{ ENCTYPE_DES3_CBC_SHA,	enctype_des3cbcsha_in,	enctype_des3cbcsha_out	},
{ ENCTYPE_DES_CBC_RAW,	enctype_descbcraw_in,	enctype_descbcraw_out	}
};
static const int enctype_table_nents = sizeof(enctype_table)/
				       sizeof(enctype_table[0]);

static const struct salttype_lookup_entry salttype_table[] = {
/* salt type			input specifier	output string  */
/*-----------------------------	--------------- ---------------*/
{ KRB5_KDB_SALTTYPE_NORMAL,	"normal",	"Version 5"	  },
{ KRB5_KDB_SALTTYPE_V4,		"v4",		"Version 4"	  },
{ KRB5_KDB_SALTTYPE_NOREALM,	"norealm",	"Version 5 - No Realm" },
{ KRB5_KDB_SALTTYPE_ONLYREALM,	"onlyrealm",	"Version 5 - Realm Only" },
{ KRB5_KDB_SALTTYPE_SPECIAL,	"special",	"Special" },
{ KRB5_KDB_SALTTYPE_AFS3,	"afs3",		"AFS version 3"    }
};
static const int salttype_table_nents = sizeof(salttype_table)/
					sizeof(salttype_table[0]);

static const struct cksumtype_lookup_entry cksumtype_table[] = {
/* krb5_cksumtype         input specifier	output string		*/
/*----------------------- ---------------------	------------------------*/
{ CKSUMTYPE_CRC32,        cstype_crc32_in,	cstype_crc32_out	},
{ CKSUMTYPE_RSA_MD4,      cstype_md4_in,	cstype_md4_out		},
{ CKSUMTYPE_RSA_MD4_DES,  cstype_md4des_in,	cstype_md4des_out	},
{ CKSUMTYPE_DESCBC,       cstype_descbc_in,	cstype_descbc_out	},
{ CKSUMTYPE_RSA_MD5,      cstype_md5_in,	cstype_md5_out		},
{ CKSUMTYPE_RSA_MD5_DES,  cstype_md5des_in,	cstype_md5des_out	},
{ CKSUMTYPE_NIST_SHA,     cstype_sha_in,	cstype_sha_out		},
{ CKSUMTYPE_HMAC_SHA,	  cstype_hmacsha_in,	cstype_hmacsha_out	}
};
static const int cksumtype_table_nents = sizeof(cksumtype_table)/
					 sizeof(cksumtype_table[0]);


/*
 * String to internal datatype routines.
 *
 * These routines return 0 for success, EINVAL for invalid entry.
 */
krb5_error_code
krb5_string_to_enctype(string, enctypep)
    char		* string;
    krb5_enctype	* enctypep;
{
    int i;
    int found;

    found = 0;
    for (i=0; i<enctype_table_nents; i++) {
	if (!strcasecmp(string, enctype_table[i].ktt_specifier)) {
	    found = 1;
	    *enctypep = enctype_table[i].ktt_enctype;
	    break;
	}
    }
    return((found) ? 0 : EINVAL);
}

krb5_error_code
krb5_string_to_salttype(string, salttypep)
    char		* string;
    krb5_int32		* salttypep;
{
    int i;
    int found;

    found = 0;
    for (i=0; i<salttype_table_nents; i++) {
	if (!strcasecmp(string, salttype_table[i].stt_specifier)) {
	    found = 1;
	    *salttypep = salttype_table[i].stt_enctype;
	    break;
	}
    }
    return((found) ? 0 : EINVAL);
}

krb5_error_code
krb5_string_to_cksumtype(string, cksumtypep)
    char		* string;
    krb5_cksumtype	* cksumtypep;
{
    int i;
    int found;

    found = 0;
    for (i=0; i<cksumtype_table_nents; i++) {
	if (!strcasecmp(string, cksumtype_table[i].cst_specifier)) {
	    found = 1;
	    *cksumtypep = cksumtype_table[i].cst_cksumtype;
	    break;
	}
    }
    return((found) ? 0 : EINVAL);
}

/*
 * Internal datatype to string routines.
 *
 * These routines return 0 for success, EINVAL for invalid parameter, ENOMEM
 * if the supplied buffer/length will not contain the output.
 */
krb5_error_code
krb5_enctype_to_string(enctype, buffer, buflen)
    krb5_enctype	enctype;
    char		* buffer;
    size_t		buflen;
{
    int i;
    const char *out;

    out = (char *) NULL;
    for (i=0; i<enctype_table_nents; i++) {
	if (enctype ==  enctype_table[i].ktt_enctype) {
	    out = enctype_table[i].ktt_output;
	    break;
	}
    }
    if (out) {
	if (buflen > strlen(out))
	    strcpy(buffer, out);
	else
	    out = (char *) NULL;
	return((out) ? 0 : ENOMEM);
    }
    else
	return(EINVAL);
}

krb5_error_code
krb5_salttype_to_string(salttype, buffer, buflen)
    krb5_int32	salttype;
    char	* buffer;
    size_t	buflen;
{
    int i;
    const char *out;

    out = (char *) NULL;
    for (i=0; i<salttype_table_nents; i++) {
	if (salttype ==  salttype_table[i].stt_enctype) {
	    out = salttype_table[i].stt_output;
	    break;
	}
    }
    if (out) {
	if (buflen > strlen(out))
	    strcpy(buffer, out);
	else
	    out = (char *) NULL;
	return((out) ? 0 : ENOMEM);
    }
    else
	return(EINVAL);
}

krb5_error_code
krb5_cksumtype_to_string(cksumtype, buffer, buflen)
    krb5_cksumtype	cksumtype;
    char		* buffer;
    size_t		buflen;
{
    int i;
    const char *out;

    out = (char *) NULL;
    for (i=0; i<cksumtype_table_nents; i++) {
	if (cksumtype ==  cksumtype_table[i].cst_cksumtype) {
	    out = cksumtype_table[i].cst_output;
	    break;
	}
    }
    if (out) {
	if (buflen > strlen(out))
	    strcpy(buffer, out);
	else
	    out = (char *) NULL;
	return((out) ? 0 : ENOMEM);
    }
    else
	return(EINVAL);
}

/* (absolute) time conversions */

#ifndef HAVE_STRFTIME
#undef strftime
#define strftime my_strftime
static size_t strftime (char *, size_t, const char *, const struct tm *);
#endif

#ifndef HAVE_STRPTIME
#undef strptime
#define strptime my_strptime
static char *strptime (const char *, const char *, struct tm *);
#endif

KRB5_DLLIMP krb5_error_code KRB5_CALLCONV
krb5_string_to_timestamp(string, timestampp)
    char		FAR * string;
    krb5_timestamp	FAR * timestampp;
{
    int i;
    struct tm timebuf;
    time_t now, ret_time;
    char *s;
    static const char * const atime_format_table[] = {
	"%Y%m%d%H%M%S",		/* yyyymmddhhmmss		*/
	"%Y.%m.%d.%H.%M.%S",	/* yyyy.mm.dd.hh.mm.ss		*/
	"%y%m%d%H%M%S",		/* yymmddhhmmss			*/
	"%y.%m.%d.%H.%M.%S",	/* yy.mm.dd.hh.mm.ss		*/
	"%y%m%d%H%M",		/* yymmddhhmm			*/
	"%H%M%S",		/* hhmmss			*/
	"%H%M",			/* hhmm				*/
	"%T",			/* hh:mm:ss			*/
	"%R",			/* hh:mm			*/
	/* The following not really supported unless native strptime present */
	"%x:%X",		/* locale-dependent short format */
	"%d-%b-%Y:%T",		/* dd-month-yyyy:hh:mm:ss	*/
	"%d-%b-%Y:%R"		/* dd-month-yyyy:hh:mm		*/
    };
    static const int atime_format_table_nents =
	sizeof(atime_format_table)/sizeof(atime_format_table[0]);


    now = time((time_t *) NULL);
    for (i=0; i<atime_format_table_nents; i++) {
        /* We reset every time throughout the loop as the manual page
	 * indicated that no guarantees are made as to preserving timebuf
	 * when parsing fails
	 */
	memcpy(&timebuf, localtime(&now), sizeof(timebuf));
	if ((s = strptime(string, atime_format_table[i], &timebuf))
	    && (s != string)) {
	    if (timebuf.tm_year <= 0)
		continue;	/* clearly confused */
	    ret_time = mktime(&timebuf);
	    if (ret_time == (time_t) -1)
		continue;	/* clearly confused */
	    *timestampp = (krb5_timestamp) ret_time;
	    return 0;
	}
    }
    return(EINVAL);
}

KRB5_DLLIMP krb5_error_code KRB5_CALLCONV
krb5_timestamp_to_string(timestamp, buffer, buflen)
    krb5_timestamp	timestamp;
    char		FAR * buffer;
    size_t		buflen;
{
    int ret;
    time_t timestamp2 = timestamp;

    ret = strftime(buffer, buflen, "%c", localtime(&timestamp2));
    if (ret == 0 || ret == buflen)
	return(ENOMEM);
    return(0);
}

KRB5_DLLIMP krb5_error_code KRB5_CALLCONV
krb5_timestamp_to_sfstring(timestamp, buffer, buflen, pad)
    krb5_timestamp	timestamp;
    char		FAR * buffer;
    size_t		buflen;
    char		FAR * pad;
{
    struct tm	*tmp;
    size_t i;
    size_t	ndone;
    time_t timestamp2 = timestamp;

    static const char * const sftime_format_table[] = {
	"%c",			/* Default locale-dependent date and time */
	"%d %b %Y %T",		/* dd mon yyyy hh:mm:ss			*/
	"%x %X",		/* locale-dependent short format	*/
	"%d/%m/%Y %R"		/* dd/mm/yyyy hh:mm			*/
    };
    static const int sftime_format_table_nents =
	sizeof(sftime_format_table)/sizeof(sftime_format_table[0]);

    tmp = localtime(&timestamp2);
    ndone = 0;
    for (i=0; i<sftime_format_table_nents; i++) {
	if ((ndone = strftime(buffer, buflen, sftime_format_table[i], tmp)))
	    break;
    }
    if (!ndone) {
#define sftime_default_len	2+1+2+1+4+1+2+1+2+1
	if (buflen >= sftime_default_len) {
	    sprintf(buffer, "%02d/%02d/%4d %02d:%02d",
		    tmp->tm_mday, tmp->tm_mon+1, 1900+tmp->tm_year,
		    tmp->tm_hour, tmp->tm_min);
	    ndone = strlen(buffer);
	}
    }
    if (ndone && pad) {
	for (i=ndone; i<buflen-1; i++)
	    buffer[i] = *pad;
	buffer[buflen-1] = '\0';
    }
    return((ndone) ? 0 : ENOMEM);
}

/* relative time (delta-t) conversions */

/* string->deltat is in deltat.y */

KRB5_DLLIMP krb5_error_code KRB5_CALLCONV
krb5_deltat_to_string(deltat, buffer, buflen)
    krb5_deltat	deltat;
    char	FAR * buffer;
    size_t	buflen;
{
    int			days, hours, minutes, seconds;
    krb5_deltat		dt;

    /*
     * We want something like ceil(log10(2**(nbits-1))) + 1.  That log
     * value is log10(2)*(nbits-1) or log10(2**8)*(nbits-1)/8.  So,
     * 2.4... is log10(256), rounded up.  Add one to handle leading
     * minus, and one more to force int cast to round the value up.
     * This doesn't include room for a trailing nul.
     *
     * This will break if bytes are more than 8 bits.
     */
#define MAX_CHARS_FOR_INT_TYPE(TYPE)	((int) (2 + 2.408241 * sizeof (TYPE)))
    char tmpbuf[MAX_CHARS_FOR_INT_TYPE(int) * 4 + 8];

    days = (int) (deltat / (24*3600L));
    dt = deltat % (24*3600L);
    hours = (int) (dt / 3600);
    dt %= 3600;
    minutes = (int) (dt / 60);
    seconds = (int) (dt % 60);

    memset (tmpbuf, 0, sizeof (tmpbuf));
    if (days == 0)
	sprintf(buffer, "%d:%02d:%02d", hours, minutes, seconds);
    else if (hours || minutes || seconds)
	sprintf(buffer, "%d %s %02d:%02d:%02d", days,
		(days > 1) ? "days" : "day",
		hours, minutes, seconds);
    else
	sprintf(buffer, "%d %s", days,
		(days > 1) ? "days" : "day");
    if (tmpbuf[sizeof(tmpbuf)-1] != 0)
	/* Something must be very wrong with my math above, or the
	   assumptions going into it...  */
	abort ();
    if (strlen (tmpbuf) > buflen)
	return ENOMEM;
    else
	strncpy (buffer, tmpbuf, buflen);
    return 0;
}

#undef __P
#define __P(X) X

#if !defined (HAVE_STRFTIME) || !defined (HAVE_STRPTIME)
#undef _CurrentTimeLocale
#define _CurrentTimeLocale (&dummy_locale_info)

struct dummy_locale_info_t {
    char d_t_fmt[15];
    char t_fmt_ampm[12];
    char t_fmt[9];
    char d_fmt[9];
    char day[7][10];
    char abday[7][4];
    char mon[12][10];
    char abmon[12][4];
    char am_pm[2][3];
};
static const struct dummy_locale_info_t dummy_locale_info = {
    "%a %b %d %X %Y",		/* %c */
    "%I:%M:%S %p",		/* %r */
    "%H:%M:%S",			/* %X */
    "%m/%d/%y",			/* %x */
    { "Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday",
      "Saturday" },
    { "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat" },
    { "January", "February", "March", "April", "May", "June",
      "July", "August", "September", "October", "November", "December" },
    { "Jan", "Feb", "Mar", "Apr", "May", "Jun",
      "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" },
    { "AM", "PM" },
};
#undef  TM_YEAR_BASE
#define TM_YEAR_BASE 1900
#endif

#ifndef HAVE_STRFTIME
#undef  DAYSPERLYEAR
#define DAYSPERLYEAR 366
#undef  DAYSPERNYEAR
#define DAYSPERNYEAR 365
#undef  DAYSPERWEEK
#define DAYSPERWEEK 7
#undef  isleap
#define isleap(N)	((N % 4) == 0 && (N % 100 != 0 || N % 400 == 0))
#undef  tzname
#define tzname my_tzname
static const char *const tzname[2] = { 0, 0 };
#undef  tzset
#define tzset()

#include "strftime.c"
#endif

#ifndef HAVE_STRPTIME
#include "strptime.c"
#endif
