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
static const char *o_not_int_fmt	= "%s does not specify an integer value for %s";
static const char *o_val_req_fmt	= "value required for %s";
static const char *o_not_time_fmt	= "%s does not specify a valid time value for %s";
static const char *o_not_salt_fmt	= "%s does not specify a valid salt type for %s";
static const char *o_opt_ufo_fmt	= "%s is unrecognized";
static const char *help_option_head	= "%s: valid options are:\n";

static const char opt_maxlife[]		= "maxlife";
static const char opt_maxrenewlife[]	= "maxrenewlife";
static const char opt_expiration[]	= "expiration";
static const char opt_pwexpiration[]	= "pwexpiration";
static const char opt_randomkey[]	= "randomkey";

/*
 * Formatting buffers
 */
static char 		dt_outbuf[BUFFER_SIZE];
static char 		abs_outbuf[BUFFER_SIZE];
static char		db_outbuf[BUFFER_SIZE];
static char 		salt_outbuf[BUFFER_SIZE];
static krb5_db_entry	opt_dbent;

/* Option string parse table */
static struct opttable opttable[] = {
/* flag				option			dispatch routine
      argument */
{ KRB5_ADM_M_MAXLIFE,		opt_maxlife,		get_integer,
      (void *) &opt_dbent.max_life },
{ KRB5_ADM_M_MAXRENEWLIFE,	opt_maxrenewlife,	get_integer,
      (void *) &opt_dbent.max_renewable_life },
{ KRB5_ADM_M_EXPIRATION,	opt_expiration,		get_datestring,
      (void *) &opt_dbent.expiration },
{ KRB5_ADM_M_PWEXPIRATION,	opt_pwexpiration,	get_datestring,
      (void *) &opt_dbent.pw_expiration }
};


/*
 * delta2string()	- Convert delta time value to string.
 *
 * WARNING: the returned output buffer is static.
 */
char *
delta2string(dt)
    krb5_deltat	dt;
{
    return(krb5_deltat_to_string(dt, dt_outbuf, sizeof(dt_outbuf)) ?
	   (char *) NULL : dt_outbuf);
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
    return(krb5_timestamp_to_string(t, abs_outbuf, sizeof(abs_outbuf)) ?
	   (char *) NULL : abs_outbuf);
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
    return(krb5_flags_to_string(f, ", ", db_outbuf, sizeof(db_outbuf)) ?
	   (char *) NULL : db_outbuf);
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
    krb5_boolean	good;
    char		*retval;
    int			ti;

    tp = (krb5_timestamp *) optp;
    good = 0;
    /* Match the value */
    if (!strncasecmp(arg, value, strlen(value))) {
	/* If we have a match, look for value=<value> */
	index = strlen(value);
	if (arg[index] == '=') {
	    if (!krb5_string_to_timestamp(&arg[index+1], tp))
		good = 1;
	    else
		com_err(requestname, 0, o_not_time_fmt, &arg[index+1], value);
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
	    if (!krb5_string_to_flags(argv[i], "+", "-",
				      &opt_dbent.attributes)) {
		    found = 1;
		    *vmaskp |= KRB5_ADM_M_FLAGS;
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
}
