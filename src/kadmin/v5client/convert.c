/*
 * kadmin/v5client/convert.c
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
 * convert.c	- Perform various conversions for kadmin5.
 */
#include "k5-int.h"
#include "adm.h"
#include "kadmin5.h"

/* Size of static buffers for conversions */
#define	BUFFER_SIZE	512

/* Forward declarations */
static krb5_boolean get_integer PROTOTYPE((char *, const char *, void *));
static krb5_boolean get_datestring PROTOTYPE((char *, const char *, void *));
static krb5_boolean get_saltstring PROTOTYPE((char *, const char *, void *));
/* static krb5_boolean get_deltastring PROTOTYPE((char *, const char *, void *)); */

/* Local data structure for flag to string and option to flag operations */
struct flagtable {
    krb5_flags		f_value;
    const char		*f_string;
    const char 		*f_option;
    krb5_boolean	f_sense;
};

/* Local data structure for option parsing */
struct opttable {
    krb5_ui_4		o_value;
    const char		*o_option;
    krb5_boolean	(*o_dispatch) PROTOTYPE((char *,
						 const char *,
						 void *));
    void 		*o_arg;
};

/*
 * Static strings.
 */
static const char *dt_output_fmt	= "%d %s %d:%d:%d";
static const char *dt_output_noday_fmt	= "%d:%d:%d";
static const char *dt_output_donly_fmt	= "%d %s";
static const char *dt_day_singular	= "day";
static const char *dt_day_plural	= "days";
static const char *dbflag_bit_fmt	= "Bit-%d";
static const char *salt_norm_name	= "Normal";
static const char *salt_v4_name		= "Kerberos V4";
static const char *salt_norealm_name	= "NoRealm";
static const char *salt_orealm_name	= "OnlyRealm";
static const char *salt_special_name	= "Special";
static const char *salt_ufo_fmt		= "Unknown(%d)";
static const char *salt_norm_spec	= "v5";
static const char *salt_v4_spec		= "v4";
static const char *salt_norealm_spec	= "norealm";
static const char *salt_orealm_spec	= "onlyrealm";
static const char *salt_special_spec	= "special";
static const char *o_not_int_fmt	= "%s does not specify an integer value for %s";
static const char *o_val_req_fmt	= "value required for %s";
static const char *o_not_time_fmt	= "%s does not specify a valid time value for %s";
static const char *o_not_salt_fmt	= "%s does not specify a valid salt type for %s";
static const char *o_opt_ufo_fmt	= "%s is unrecognized";
static const char *help_option_head	= "%s: valid options are:\n";
static const char *help_flag_head	= "%s: additional principal flags are:\n";

static const char flg_out_pdate[]	= "Not Postdateable";
static const char flg_in_pdate[]	= "postdateable";
static const char flg_out_fwd[]		= "Not Forwardable";
static const char flg_in_fwd[]		= "forwardable";
static const char flg_out_tgs[]		= "No TGT-based Requests";
static const char flg_in_tgs[]		= "tgt_req";
static const char flg_out_renew[]	= "Not Renewable";
static const char flg_in_renew[]	= "renewable";
static const char flg_out_proxy[]	= "Not Proxiable";
static const char flg_in_proxy[]	= "proxiable";
static const char flg_out_dskey[]	= "No DUP_SKEY Requests";
static const char flg_in_dskey[]	= "dup_skey";
static const char flg_out_tix[]		= "All Tickets Disallowed";
static const char flg_in_tix[]		= "allow_tickets";
static const char flg_out_pauth[]	= "Preauthorization Required";
static const char flg_in_pauth[]	= "preauth";
static const char flg_out_hauth[]	= "HW Authorization Required";
static const char flg_in_hauth[]	= "hwauth";
static const char flg_out_pwchg[]	= "Password Change Required";
static const char flg_in_pwchg[]	= "pwchange_req";
static const char flg_out_svr[]		= "Server Disallowed";
static const char flg_in_svr[]		= "server";
static const char flg_out_pwsvc[]	= "Password Changing Service";
static const char flg_in_pwsvc[]	= "pwservice";
static const char flg_out_md5[]		= "DES MD5 supported";
static const char flg_in_md5[]		= "md5";

static const char opt_kvno[]		= "kvno";
static const char opt_maxlife[]		= "maxlife";
static const char opt_maxrenewlife[]	= "maxrenewlife";
static const char opt_expiration[]	= "expiration";
static const char opt_pwexpiration[]	= "pwexpiration";
static const char opt_randomkey[]	= "randomkey";
static const char opt_salttype[]	= "salttype";

/*
 * Formatting buffers
 */
static char 		dt_outbuf[BUFFER_SIZE];
static char 		abs_outbuf[BUFFER_SIZE];
static char		db_outbuf[BUFFER_SIZE];
static char 		salt_outbuf[BUFFER_SIZE];
static krb5_db_entry	opt_dbent;

/* Flag to string and option to flag table */
static struct flagtable flagtable[] = {
/* flag					output string	   input option sen */
{ KRB5_KDB_DISALLOW_POSTDATED,		flg_out_pdate,     flg_in_pdate, 0 },
{ KRB5_KDB_DISALLOW_FORWARDABLE,	flg_out_fwd,       flg_in_fwd, 0 },
{ KRB5_KDB_DISALLOW_TGT_BASED,		flg_out_tgs,	   flg_in_tgs, 0 },
{ KRB5_KDB_DISALLOW_RENEWABLE,		flg_out_renew,	   flg_in_renew, 0 },
{ KRB5_KDB_DISALLOW_PROXIABLE,		flg_out_proxy,	   flg_in_proxy, 0 },
{ KRB5_KDB_DISALLOW_DUP_SKEY,		flg_out_dskey,	   flg_in_dskey, 0 },
{ KRB5_KDB_DISALLOW_ALL_TIX,		flg_out_tix,	   flg_in_tix, 0 },
{ KRB5_KDB_REQUIRES_PRE_AUTH,		flg_out_pauth,	   flg_in_pauth, 1 },
{ KRB5_KDB_REQUIRES_HW_AUTH,		flg_out_hauth,	   flg_in_hauth, 1 },
{ KRB5_KDB_REQUIRES_PWCHANGE,		flg_out_pwchg,	   flg_in_pwchg, 1 },
{ KRB5_KDB_DISALLOW_SVR,		flg_out_svr,	   flg_in_svr, 0 },
{ KRB5_KDB_PWCHANGE_SERVICE,		flg_out_pwsvc,     flg_in_pwsvc, 1 },
{ KRB5_KDB_SUPPORT_DESMD5,		flg_out_md5,	   flg_in_md5, 1 },
};

/* Option string parse table */
static struct opttable opttable[] = {
/* flag				option			dispatch routine
      argument */
{ KRB5_ADM_M_KVNO,		opt_kvno,		get_integer,
      (void *) &opt_dbent.kvno },
{ KRB5_ADM_M_MAXLIFE,		opt_maxlife,		get_integer,
      (void *) &opt_dbent.max_life },
{ KRB5_ADM_M_MAXRENEWLIFE,	opt_maxrenewlife,	get_integer,
      (void *) &opt_dbent.max_renewable_life },
{ KRB5_ADM_M_EXPIRATION,	opt_expiration,		get_datestring,
      (void *) &opt_dbent.expiration },
{ KRB5_ADM_M_PWEXPIRATION,	opt_pwexpiration,	get_datestring,
      (void *) &opt_dbent.pw_expiration },
{ KRB5_ADM_M_SALTTYPE,		opt_salttype,		get_saltstring,
      (void *) &opt_dbent },
};

/* strptime formats table to recognize absolute dates */
/*
 * Recognize character string times of the format.
 *      1) yymmddhhmmss		(doesn't work under OSF/1)
 *      2) yy.mm.dd.hh.mm.ss
 *      3) yymmddhhmm
 *      4) hhmmss (relative to today)
 *      5) hhmm (relative to today)
 *      6) hh:mm:ss (relative to today)
 *      7) hh:mm (relative to today)
 *      8) locale-dependent short format (mm/dd/yy:hh:mm:ss in usa)
 *      9) dd-text_month-yyyy:hh:mm:ss
 *      10) dd-text_month-yyyy:hh:mm
 */
static char *absformats[] =
{
    "%y%m%d%H%M%S",		/* yymmddhhmmss */
    "%y.%m.%d.%H.%M.%S",	/* yy.mm.dd.hh.mm.ss */
    "%y%m%d%H%M",		/* yymmddhhmm */
    "%H%M%S",			/* hhmmss */
    "%H%M",			/* hhmm */
    "%T",			/* hh:mm:ss */
    "%R",			/* hh:mm */
    "%x:%X",			/* locale-dependent short format */
    "%d-%b-%Y:T",		/* dd-month-yyyy:hh:mm:ss */
    "%d-%b-%Y:R"		/* dd-month-yyyy:hh:mm */
};

#if	!HAVE_STRPTIME
/*
 * Rudimentary version of strptime for systems which don't have it.
 */
static char *
strptime( char *buf, char *format, struct tm *tm )
{
    int year, month, day, hour, minute, second;
    char *bp;
    
    /*
     * We only understand two formats:
     *    %y%m%d%H%M%S
     * This is fixed length, 12 characters.
     *    %y.%m.%d.%H.%M.%S
     * This is fixed length, 17 characters.
     */
    bp = (char *) NULL;
    if ((strcmp(format,"%y%m%d%H%M%S") == 0) &&
	(sscanf(buf, "%02d%02d%02d%02d%02d%02d",
		&year, &month, &day, &hour, &minute, &second) == 6)) {
	tm->tm_year = year;
	tm->tm_mon = month - 1;
	tm->tm_mday = day;
	tm->tm_hour = hour;
	tm->tm_min = minute;
	tm->tm_sec = second;
	bp = &buf[12];
    }
    else {
	if ((strcmp(format,"%y.%m.%d.%H.%M.%S") == 0) &&
	    (sscanf(buf, "%02d.%02d.%02d.%02d.%02d.%02d",
		    &year, &month, &day, &hour, &minute, &second) == 6)) {
	    tm->tm_year = year;
	    tm->tm_mon = month - 1;
	    tm->tm_mday = day;
	    tm->tm_hour = hour;
	    tm->tm_min = minute;
	    tm->tm_sec = second;
	    bp = &buf[17];
	}
    }
    return(bp);
}
#endif	/* HAVE_STRPTIME */

/*
 * delta2string()	- Convert delta time value to string.
 *
 * WARNING: the returned output buffer is static.
 */
char *
delta2string(dt)
    krb5_deltat	dt;
{
    int		days, hours, minutes, seconds;

    days = dt / (24*3600);
    dt %= 24 * 3600;
    hours = dt / 3600;
    dt %= 3600;
    minutes = dt / 60;
    dt %= 60;
    seconds = dt;

    if (days) {
	if (hours || minutes || seconds)
	    sprintf(dt_outbuf, dt_output_fmt, days,
		    ((days > 1) ? dt_day_plural : dt_day_singular),
		    hours, minutes, seconds);
	else
	    sprintf(dt_outbuf, dt_output_donly_fmt, days,
		    ((days > 1) ? dt_day_plural : dt_day_singular));
    }
    else
	sprintf(dt_outbuf, dt_output_noday_fmt, hours, minutes, seconds);
    return(dt_outbuf);
}

/*
 * abs2string()	- Convert absolute Kerberos time to string.
 *
 * WARNING: the returned output buffer is static.
 */
char *
abs2string(t)
    krb5_timestamp	t;
{
    /*
     * ctime returns <datestring>\n\0.
     */
    strcpy(abs_outbuf, ctime((time_t *) &t));
    abs_outbuf[strlen(abs_outbuf)-1] = '\0';
    return(abs_outbuf);
}

/*
 * dbflags2string()	- Convert database flags to string.
 *
 * WARNING: the returned output buffer is static.
 */
char *
dbflags2string(f)
    krb5_flags	f;
{
    int 	bit;
    int		i;
    krb5_flags	mask;
    struct flagtable *fent;

    mask = 1;
    db_outbuf[0] = '\0';
    for (bit=0; bit<(sizeof(krb5_flags)*8); bit++) {
	if (f & mask) {
	    /* Bit is set, find it in the flag table */
	    fent = (struct flagtable *) NULL;
	    for (i=0; i<(sizeof(flagtable)/sizeof(flagtable[0])); i++) {
		if (mask == flagtable[i].f_value) {
		    fent = &flagtable[i];
		    break;
		}
	    }

	    /* Either print out table value or unknown bit value. */
	    if (fent)
		strcat(db_outbuf, fent->f_string);
	    else
		sprintf(&db_outbuf[strlen(db_outbuf)],
			dbflag_bit_fmt, bit);
	    strcat(db_outbuf, ", ");
	}
	mask <<= 1;
    }
    /*
     * Clean up our trailing comma-space if present.
     */
    if (strlen(db_outbuf) > 2)
	db_outbuf[strlen(db_outbuf)-2] = '\0';
    return(db_outbuf);
}

/*
 * salt2string()	- Convert salt type to string.
 *
 * WARNING: the returned output buffer is static.
 */
char *
salt2string(stype)
    krb5_int32	stype;
{
    switch (stype) {
    case KRB5_KDB_SALTTYPE_NORMAL:
	strcpy(salt_outbuf, salt_norm_name);
	break;
    case KRB5_KDB_SALTTYPE_V4:
	strcpy(salt_outbuf, salt_v4_name);
	break;
    case KRB5_KDB_SALTTYPE_NOREALM:
	strcpy(salt_outbuf, salt_norealm_name);
	break;
    case KRB5_KDB_SALTTYPE_ONLYREALM:
	strcpy(salt_outbuf, salt_orealm_name);
	break;
    case KRB5_KDB_SALTTYPE_SPECIAL:
	strcpy(salt_outbuf, salt_special_name);
	break;
    default:
	sprintf(salt_outbuf, salt_ufo_fmt, stype);
	break;
    }
    return(salt_outbuf);
}

/*
 * string2salt()	- Convert string to salt type.
 */
static krb5_int32
string2salt(sstring, goodp)
    char		*sstring;
    krb5_boolean	*goodp;
{
    if (!strcasecmp(sstring, salt_norm_spec)) {
	*goodp = 1;
	return(KRB5_KDB_SALTTYPE_NORMAL);
    }
    else if (!strcasecmp(sstring, salt_v4_spec)) {
	*goodp = 1;
	return(KRB5_KDB_SALTTYPE_V4);
    }
    else if (!strcasecmp(sstring, salt_norealm_spec)) {
	*goodp = 1;
	return(KRB5_KDB_SALTTYPE_NOREALM);
    }
    else if (!strcasecmp(sstring, salt_orealm_spec)) {
	*goodp = 1;
	return(KRB5_KDB_SALTTYPE_ONLYREALM);
    }
    else if (!strcasecmp(sstring, salt_special_spec)) {
	*goodp = 1;
	return(KRB5_KDB_SALTTYPE_SPECIAL);
    }
    else {
	*goodp = 0;
	return(-1);
    }
}

/*
 * get_integer()	- Test for an option and its integer value.
 */
static krb5_boolean
get_integer(arg, value, optp)
    char	*arg;
    const char	*value;
    void	*optp;
{
    int 		index;
    krb5_boolean	good;
    krb5_int32		*intp;

    intp = (krb5_int32 *) optp;
    good = 0;
    /* Match the value */
    if (!strncasecmp(arg, value, strlen(value))) {
	/* If we have a match, look for value=<value> */
	index = strlen(value);
	if (arg[index] == '=') {
	    /* Match one integer argument */
	    if (sscanf(&arg[index+1], "%d", intp) == 1)
		good = 1;
	    else
		com_err(requestname, 0, o_not_int_fmt, &arg[index+1], value);
	}
	else
	    com_err(requestname, 0, o_val_req_fmt, value);
    }
    return(good);
}

/*
 * get_datestring()	- Test for an option and its date value
 */
static krb5_boolean
get_datestring(arg, value, optp)
    char	*arg;
    const char	*value;
    void	*optp;
{
    int 		index;
    krb5_timestamp	*tp;
    krb5_boolean	good, found;
    char		*retval;
    int			ti;
    time_t		now;
    struct tm		*tmp;
    struct tm		timebuf;

    tp = (krb5_timestamp *) optp;
    good = 0;
    found = 0;
    /* Match the value */
    if (!strncasecmp(arg, value, strlen(value))) {
	/* If we have a match, look for value=<value> */
	index = strlen(value);
	if (arg[index] == '=') {
	    /* Prime with current time */
	    now = time((time_t *) NULL);
	    tmp = localtime(&now);
	    memcpy(&timebuf, tmp, sizeof(struct tm));
	    /* Match date argument */
	    for (ti=0; ti<(sizeof(absformats)/sizeof(absformats[0])); ti++) {
		if (strptime(&arg[index+1], absformats[ti], &timebuf)) {
		    found = 1;
		    break;
		}
		memcpy(&timebuf, tmp, sizeof(struct tm));
	    }
	    if (found) {
		*tp = (krb5_timestamp) mktime(&timebuf);
		good = 1;
	    }
	    else
		com_err(requestname, 0, o_not_time_fmt, &arg[index+1], value);
	}
	else
	    com_err(requestname, 0, o_val_req_fmt, value);
    }
    return(good);
}

/*
 * get_saltstring()	- Test for an option and its salt type value
 */
static krb5_boolean
get_saltstring(arg, value, optp)
    char	*arg;
    const char	*value;
    void	*optp;
{
    int			index;
    krb5_db_entry	*dbentp;
    krb5_boolean	good;
    char		*s1, *s2;

    dbentp = (krb5_db_entry *) optp;
    good = 0;
    /* Match the value */
    if (!strncasecmp(arg, value, strlen(value))) {
	/* If we have a match, look for value=<value> */
	index = strlen(value);
	if (arg[index] == '=') {
	    if (s2 = strchr(&arg[index+1], (int) ',')) {
		*s2 = '\0';
		s2++;
	    }
	    s1 = &arg[index+1];
	    dbentp->salt_type = string2salt(s1, &good);
	    if (good) {
		if (s2) {
		    dbentp->alt_salt_type = string2salt(s2, &good);
		    if (!good)
			com_err(requestname, 0, o_not_salt_fmt, s2, value);
		}
		else
		    dbentp->alt_salt_type = KRB5_KDB_SALTTYPE_NORMAL;
	    }
	    else
		com_err(requestname, 0, o_not_salt_fmt, s1, value);
	}
	else
	    com_err(requestname, 0, o_val_req_fmt, value);
    }

    return(good);
}

/*
 * parse_princ_options()	- Parse an argument list for values.
 *
 * NOTE: The formatting buffer is static.
 */
krb5_boolean
parse_princ_options(argc, argv, vmaskp, dbentp)
    int			argc;
    char		*argv[];
    krb5_ui_4		*vmaskp;
    krb5_db_entry	*dbentp;
{
    int	i, oindex;
    krb5_boolean	good;
    krb5_boolean	found;

    good = 1;
    /* Copy in our values */
    memcpy(&opt_dbent, dbentp, sizeof(krb5_db_entry));
    for (i=0; i<argc; i++) {
	found = 0;
	/*
	 * First try the option table.
	 */
	for (oindex=0; oindex<(sizeof(opttable)/sizeof(opttable[0]));
	     oindex++) {
	    if ((*opttable[oindex].o_dispatch)(argv[i],
					       opttable[oindex].o_option,
					       opttable[oindex].o_arg)) {
		*vmaskp |= opttable[oindex].o_value;
		found = 1;
		break;
	    }
	}

	/*
	 * If we didn't find an option, try trapsing through the flag table.
	 */
	if (!found) {
	    int 		ti, rindex;
	    krb5_boolean	sense;

	    found = 0;
	    rindex = 0;
	    sense = 1;
	    if ((argv[i][0] == '-') || (argv[i][0] == '+')) {
		if (argv[i][0] == '-')
		    sense = 0;
		rindex = 1;
	    }
	    for (ti=0; ti<(sizeof(flagtable)/sizeof(flagtable[0])); ti++) {
		if (!strncasecmp(&argv[i][rindex], flagtable[ti].f_option,
				 strlen(flagtable[ti].f_option))) {
		    found = 1;
		    if (sense == flagtable[ti].f_sense)
			opt_dbent.attributes |= flagtable[ti].f_value;
		    else
			opt_dbent.attributes &= ~flagtable[ti].f_value;
		    *vmaskp |= KRB5_ADM_M_FLAGS;
		}
	    }
	    if (!found) {
		com_err(requestname, 0, o_opt_ufo_fmt, argv[i]);
		good = 0;
	    }
	}
    }
    /* Copy out our values, if good */
    if (good)
	memcpy(dbentp, &opt_dbent, sizeof(krb5_db_entry));
    return(good);
}

/*
 * help_princ_options()	- Print out a list of settable principal options.
 */
void
help_princ_options()
{
    int index;
    int ntable;

    fprintf(stderr, help_option_head, requestname);
    ntable = (sizeof(opttable)/sizeof(opttable[0]));
    for (index=0; index<ntable-1; index++)
	fprintf(stderr, "%s, ", opttable[index].o_option);
    fprintf(stderr,"%s\n", opttable[ntable-1].o_option);
    fprintf(stderr, help_flag_head, requestname);
    ntable = (sizeof(flagtable)/sizeof(flagtable[0]));
    for (index=0; index<ntable-1; index++)
	fprintf(stderr, "[+/-]%s, ", flagtable[index].f_option);
    fprintf(stderr, "[+/-]%s\n", flagtable[ntable-1].f_option);
}
