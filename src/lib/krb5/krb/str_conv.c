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

struct deltat_match_entry {
    const char *	dt_scan_format;		/* sscanf format	*/
    int			dt_nmatch;		/* Number to match	*/
    int			dt_dindex;		/* Day index		*/
    int			dt_hindex;		/* Hour index		*/
    int			dt_mindex;		/* Minute index		*/
    int			dt_sindex;		/* Second index		*/
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

/* Salttype strings */
static const char stype_v5_in[]		= "normal";
static const char stype_v4_in[]		= "v4";
static const char stype_norealm_in[]	= "norealm";
static const char stype_olrealm_in[]	= "onlyrealm";
static const char stype_special_in[]	= "special";
static const char stype_afs3_in[]	= "afs3";
static const char stype_v5_out[]	= "Version 5";
static const char stype_v4_out[]	= "Version 4";
static const char stype_norealm_out[]	= "Version 5 - No Realm";
static const char stype_olrealm_out[]	= "Version 5 - Realm Only";
static const char stype_special_out[]	= "Special";
static const char stype_afs3_out[]	= "AFS version 3";

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

/* Absolute time strings */
static const char atime_full_digits[]	= "%y%m%d%H%M%S";
static const char atime_full_digits_d[]	= "%y.%m.%d.%H.%M.%S";
static const char atime_nsec_digits[]	= "%y%m%d%H%M";
static const char atime_rel_hms[]	= "%H%M%S";
static const char atime_rel_hm[]	= "%H%M";
static const char atime_rel_col_hms[]	= "%T";
static const char atime_rel_col_hm[]	= "%R";
static const char atime_ldep_sfmt[]	= "%x:%X";
static const char atime_full_text[]	= "%d-%b-%Y:%T";
static const char atime_full_text_nos[]	= "%d-%b-%Y:%R";
#if	!HAVE_STRPTIME
static const char ascan_full_digits[]	= "%02d%02d%02d%02d%02d%02d";
static const char ascan_full_digits_d[]	= "%02d.%02d.%02d.%02d.%02d.%02d";
static const char ascan_nsec_digits[]	= "%02d%02d%02d%02d%02d";
static const char ascan_rel_hms[]	= "%02d%02d%02d";
static const char ascan_rel_hm[]	= "%02d%02d";
static const char ascan_rel_col_hms[]	= "%02d:%02d:%02d";
static const char ascan_rel_col_hm[]	= "%02d:%02d";
#endif	/* !HAVE_STRPTIME */
#ifdef	HAVE_STRFTIME
static const char sftime_ldep_time[]	= "%c";
static const char sftime_med_fmt[]	= "%d %b %y %T";
static const char sftime_short_fmt[]	= "%x %X";
static const char sftime_last_fmt[]	= "%d/%m/%y %R";
#endif	/* HAVE_STRFTIME */
static const char sftime_default_fmt[]	= "%02d/%02d/%02d %02d:%02d";
static const size_t sftime_default_len	= 2+1+2+1+2+1+2+1+2+1;

/* Delta time strings */
static const char dtscan_dhms_notext[]	= "%d-%02d:%02d:%02d";
static const char dtscan_dhms_stext[]	= "%dd%dh%dm%ds";
static const char dtscan_hms_notext[]	= "%d:%02d:%02d";
static const char dtscan_hms_stext[]	= "%dh%dm%ds";
static const char dtscan_hm_notext[] 	= "%d:%02d";
static const char dtscan_hm_stext[]	= "%dh%dm";
static const char dtscan_days[]		= "%d%[d]";
static const char dtscan_hours[]	= "%d%[h]";
static const char dtscan_minutes[]	= "%d%[m]";
static const char dtscan_seconds[]	= "%d%[s]";
static const char dt_day_singular[]	= "day";
static const char dt_day_plural[]	= "days";
static const char dt_output_donly[]	= "%d %s";
static const char dt_output_dhms[]	= "%d %s %02d:%02d:%02d";
static const char dt_output_hms[]	= "%d:%02d:%02d";

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
/* salt type			input specifier		output string	  */
/*-----------------------------	-----------------------	------------------*/
{ KRB5_KDB_SALTTYPE_NORMAL,	stype_v5_in,		stype_v5_out	  },
{ KRB5_KDB_SALTTYPE_V4,		stype_v4_in,		stype_v4_out	  },
{ KRB5_KDB_SALTTYPE_NOREALM,	stype_norealm_in,	stype_norealm_out },
{ KRB5_KDB_SALTTYPE_ONLYREALM,	stype_olrealm_in,	stype_olrealm_out },
{ KRB5_KDB_SALTTYPE_SPECIAL,	stype_special_in,	stype_special_out },
{ KRB5_KDB_SALTTYPE_AFS3,	stype_afs3_in,		stype_afs3_out    }
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

static const char * const atime_format_table[] = {
atime_full_digits,	/* yymmddhhmmss			*/
atime_full_digits_d,	/* yy.mm.dd.hh.mm.ss		*/
atime_nsec_digits,	/* yymmddhhmm			*/
atime_rel_hms,		/* hhmmss			*/
atime_rel_hm,		/* hhmm				*/
atime_rel_col_hms,	/* hh:mm:ss			*/
atime_rel_col_hm,	/* hh:mm			*/
/* The following not really supported unless native strptime present */
atime_ldep_sfmt,	/*locale-dependent short format	*/
atime_full_text,	/* dd-month-yyyy:hh:mm:ss	*/
atime_full_text_nos	/* dd-month-yyyy:hh:mm		*/
};
static const int atime_format_table_nents = sizeof(atime_format_table)/
					    sizeof(atime_format_table[0]);

#ifdef HAVE_STRFTIME
static const char * const sftime_format_table[] = {
sftime_ldep_time,	/* Default locale-dependent date and time	*/
sftime_med_fmt,		/* dd mon yy hh:mm:ss				*/
sftime_short_fmt,	/* locale-dependent short format		*/
sftime_last_fmt		/* dd/mm/yy hh:mm				*/
};
static const int sftime_format_table_nents = sizeof(sftime_format_table)/
					    sizeof(sftime_format_table[0]);
#endif /* HAVE_STRFTIME */

static const struct deltat_match_entry deltat_table[] = {
/* scan format		nmatch	daypos	hourpos	minpos	secpos	*/
/*---------------------	-------	-------	-------	-------	--------*/
{ dtscan_dhms_notext,	4,	0,	1,	2,	3	},
{ dtscan_dhms_stext,	4,	0,	1,	2,	3	},
{ dtscan_hms_notext,	3,	-1,	0,	1,	2	},
{ dtscan_hms_stext,	3,	-1,	0,	1,	2	},
{ dtscan_hm_notext,	2,	-1,	-1,	0,	1	},
{ dtscan_hm_stext,	2,	-1,	-1,	0,	1	},
{ dtscan_days,		2,	0,	-1,	-1,	-1	},
{ dtscan_hours,		2,	-1,	0,	-1,	-1	},
{ dtscan_minutes,	2,	-1,	-1,	0,	-1	},
{ dtscan_seconds,	2,	-1,	-1,	-1,	0	}
};
static const int deltat_table_nents = sizeof(deltat_table)/
				      sizeof(deltat_table[0]);

#if	!HAVE_STRPTIME
/*
 * Rudimentary version of strptime for systems which don't have it.
 */
static char *
strptime(buf, format, tm)
    char *buf;
    const char *format;
    struct tm *tm;
{
    int year, month, day, hour, minute, second;
    char *bp;
    time_t now;
    
    /*
     * We only understand the following fixed formats:
     *    %y%m%d%H%M%S
     *    %y.%m.%d.%H.%M.%S
     *    %y%m%d%H%M
     *    %H%M%S
     *    %H%M
     *    %T
     *    %R
     */
    bp = (char *) NULL;
    if (!strcmp(format, atime_full_digits) &&
	(sscanf(buf, ascan_full_digits,
		&year, &month, &day, &hour, &minute, &second) == 6)) {
	tm->tm_year = year;
	tm->tm_mon = month - 1;
	tm->tm_mday = day;
	tm->tm_hour = hour;
	tm->tm_min = minute;
	tm->tm_sec = second;
	bp = &buf[strlen(atime_full_digits)];
    }
    else if (!strcmp(format,atime_full_digits_d) &&
	     (sscanf(buf, ascan_full_digits_d,
		     &year, &month, &day, &hour, &minute, &second) == 6)) {
	tm->tm_year = year;
	tm->tm_mon = month - 1;
	tm->tm_mday = day;
	tm->tm_hour = hour;
	tm->tm_min = minute;
	tm->tm_sec = second;
	bp = &buf[strlen(atime_full_digits_d)];
    }
    else if (!strcmp(format, atime_nsec_digits) &&
	     (sscanf(buf, ascan_nsec_digits,
		&year, &month, &day, &hour, &minute) == 5)) {
	tm->tm_year = year;
	tm->tm_mon = month - 1;
	tm->tm_mday = day;
	tm->tm_hour = hour;
	tm->tm_min = minute;
	tm->tm_sec = 0;
	bp = &buf[strlen(atime_nsec_digits)];
    }
    else if (!strcmp(format, atime_rel_hms) &&
	     (sscanf(buf, ascan_rel_hms, &hour, &minute, &second) == 3)) {
	now = time((time_t *) NULL);
	memcpy(tm, localtime(&now), sizeof(struct tm));
	tm->tm_hour = hour;
	tm->tm_min = minute;
	tm->tm_sec = second;
	bp = &buf[strlen(atime_rel_hms)];
    }
    else if (!strcmp(format, atime_rel_hm) &&
	     (sscanf(buf, ascan_rel_hm, &hour, &minute) == 2)) {
	now = time((time_t *) NULL);
	memcpy(tm, localtime(&now), sizeof(struct tm));
	tm->tm_hour = hour;
	tm->tm_min = minute;
	bp = &buf[strlen(atime_rel_hm)];
    }
    else if (!strcmp(format, atime_rel_col_hms) &&
	     (sscanf(buf, ascan_rel_col_hms, &hour, &minute, &second) == 3)) {
	now = time((time_t *) NULL);
	memcpy(tm, localtime(&now), sizeof(struct tm));
	tm->tm_hour = hour;
	tm->tm_min = minute;
	tm->tm_sec = second;
	bp = &buf[strlen(atime_rel_col_hms)];
    }
    else if (!strcmp(format, atime_rel_col_hm) &&
	     (sscanf(buf, ascan_rel_col_hm, &hour, &minute) == 2)) {
	now = time((time_t *) NULL);
	memcpy(tm, localtime(&now), sizeof(struct tm));
	tm->tm_hour = hour;
	tm->tm_min = minute;
	bp = &buf[strlen(atime_rel_col_hm)];
    }
    return(bp);
}
#endif	/* HAVE_STRPTIME */

/*
 * String to internal datatype routines.
 *
 * These routines return 0 for success, EINVAL for invalid entry.
 */
KRB5_DLLIMP krb5_error_code KRB5_CALLCONV
krb5_string_to_enctype(string, enctypep)
    char		FAR * string;
    krb5_enctype	FAR * enctypep;
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

KRB5_DLLIMP krb5_error_code KRB5_CALLCONV
krb5_string_to_salttype(string, salttypep)
    char	FAR * string;
    krb5_int32	FAR * salttypep;
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

KRB5_DLLIMP krb5_error_code KRB5_CALLCONV
krb5_string_to_cksumtype(string, cksumtypep)
    char		FAR * string;
    krb5_cksumtype	FAR * cksumtypep;
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

KRB5_DLLIMP krb5_error_code KRB5_CALLCONV
krb5_string_to_timestamp(string, timestampp)
    char		FAR * string;
    krb5_timestamp	FAR * timestampp;
{
    int i;
    int found;
    struct tm timebuf;
    time_t now;
    char *s;

    found = 0;
    now = time((time_t *) NULL);
    for (i=0; i<atime_format_table_nents; i++) {
        /* We reset every time throughout the loop as the manual page
	 * indicated that no guarantees are made as to preserving timebuf
	 * when parsing fails
	 */
	memcpy(&timebuf, localtime(&now), sizeof(timebuf));
	if ((s = strptime(string, atime_format_table[i], &timebuf))
	    && (s != string)) {
	    found = 1;
	    break;
	}
    }
    if (found)
	*timestampp = (krb5_timestamp) mktime(&timebuf);
    return((found) ? 0 : EINVAL);
}

KRB5_DLLIMP krb5_error_code KRB5_CALLCONV
krb5_string_to_deltat(string, deltatp)
    char	FAR * string;
    krb5_deltat	FAR * deltatp;
{
    int i;
    int found;
    int svalues[4];
    int days, hours, minutes, seconds;
    krb5_deltat	dt;

    found = 0;
    days = hours = minutes = seconds = 0;
    for (i=0; i<deltat_table_nents; i++) {
	if (sscanf(string, deltat_table[i].dt_scan_format,
		   &svalues[0], &svalues[1], &svalues[2], &svalues[3]) ==
	    deltat_table[i].dt_nmatch) {
	    if (deltat_table[i].dt_dindex >= 0)
		days = svalues[deltat_table[i].dt_dindex];
	    if (deltat_table[i].dt_hindex >= 0)
		hours = svalues[deltat_table[i].dt_hindex];
	    if (deltat_table[i].dt_mindex >= 0)
		minutes = svalues[deltat_table[i].dt_mindex];
	    if (deltat_table[i].dt_sindex >= 0)
		seconds = svalues[deltat_table[i].dt_sindex];
	    found = 1;
	    break;
	}
    }
    if (found) {
	dt = days;
	dt *= 24;
	dt += hours;
	dt *= 60;
	dt += minutes;
	dt *= 60;
	dt += seconds;
	*deltatp = dt;
    }
    return((found) ? 0 : EINVAL);
}

/*
 * Internal datatype to string routines.
 *
 * These routines return 0 for success, EINVAL for invalid parameter, ENOMEM
 * if the supplied buffer/length will not contain the output.
 */
KRB5_DLLIMP krb5_error_code KRB5_CALLCONV
krb5_enctype_to_string(enctype, buffer, buflen)
    krb5_enctype	enctype;
    char		FAR * buffer;
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

KRB5_DLLIMP krb5_error_code KRB5_CALLCONV
krb5_salttype_to_string(salttype, buffer, buflen)
    krb5_int32	salttype;
    char	FAR * buffer;
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

KRB5_DLLIMP krb5_error_code KRB5_CALLCONV
krb5_cksumtype_to_string(cksumtype, buffer, buflen)
    krb5_cksumtype	cksumtype;
    char		FAR * buffer;
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

KRB5_DLLIMP krb5_error_code KRB5_CALLCONV
krb5_timestamp_to_string(timestamp, buffer, buflen)
    krb5_timestamp	timestamp;
    char		FAR * buffer;
    size_t		buflen;
{
#if	HAVE_STRFTIME
    if (strftime(buffer, buflen, "%c", localtime((time_t *) &timestamp)))
	return(0);
    else
	return(ENOMEM);
#else	/* HAVE_STRFTIME */
    if (strlen(ctime((time_t *) &timestamp)) <= buflen) {
	strcpy(buffer, ctime((time_t *) &timestamp));
	/* ctime returns <datestring>\n\0 */
	buffer[strlen(buffer)-1] = '\0';
	return(0);
    }
    return(ENOMEM);
#endif	/* HAVE_STRFTIME */
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

    tmp = localtime((time_t *) &timestamp);
    ndone = 0;
#if	HAVE_STRFTIME
    for (i=0; i<sftime_format_table_nents; i++) {
	if ((ndone = strftime(buffer, buflen, sftime_format_table[i], tmp)))
	    break;
    }
#endif	/* HAVE_STRFTIME */
    if (!ndone) {
	if (buflen >= sftime_default_len) {
	    sprintf(buffer, sftime_default_fmt,
		    tmp->tm_mday, tmp->tm_mon+1, tmp->tm_year,
		    tmp->tm_hour, tmp->tm_min, tmp->tm_sec);
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

KRB5_DLLIMP krb5_error_code KRB5_CALLCONV
krb5_deltat_to_string(deltat, buffer, buflen)
    krb5_deltat	deltat;
    char	FAR * buffer;
    size_t	buflen;
{
    int			days, hours, minutes, seconds;
    krb5_deltat		dt;
    krb5_error_code	retval;

    days = (int) (deltat / (24*3600l));
    dt = deltat % (24*3600l);
    hours = (int) (dt / 3600);
    dt %= 3600;
    minutes = (int) (dt / 60);
    seconds = (int) (dt % 60);

    retval = 0;
    if (days) {
	if (hours || minutes || seconds) {
	    if (buflen < (strlen(dt_output_dhms)+strlen(dt_day_plural)))
		retval = ENOMEM;
	    else
		sprintf(buffer, dt_output_dhms, days,
			(days > 1) ? dt_day_plural : dt_day_singular,
			hours, minutes, seconds);
	}
	else {
	    if (buflen < (strlen(dt_output_donly)+strlen(dt_day_plural)))
		retval = ENOMEM;
	    else
		sprintf(buffer, dt_output_donly, days,
			(days > 1) ? dt_day_plural : dt_day_singular);
	}
    }
    else {
	if (buflen < strlen(dt_output_hms))
	    retval = ENOMEM;
	else
	    sprintf(buffer, dt_output_hms, hours, minutes, seconds);
    }
    return(retval);
}
