/*
 * kadmin/server/adm_fmt_inq.c
 *
 * Copyright 1990,1991 by the Massachusetts Institute of Technology.
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
 * Sandia National Laboratories also makes no representations about the 
 * suitability of the modifications, or additions to this software for 
 * any purpose.  It is provided "as is" without express or implied warranty.
 *
 * 	Administrative Display Routine
 */

#include "k5-int.h"
#include <stdio.h>

#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#ifdef TIME_WITH_SYS_TIME
#include <time.h>
#endif
#else
#include <time.h>
#endif

#define REALM_SEP	'@'
#define REALM_SEP_STR	"@"

krb5_error_code
adm_print_attributes(ret_data, attribs)
char *ret_data;
krb5_flags attribs;
{
    char *my_data;

    if ((my_data = (char *) calloc (1,255)) == (char *) 0)
	return ENOMEM;

    sprintf(my_data, "Principal Attributes (PA): ");
    if (attribs & KRB5_KDB_DISALLOW_POSTDATED)
        strcat(my_data, "NOPOST ");
    else
        strcat(my_data, "POST ");
    if (attribs & KRB5_KDB_DISALLOW_FORWARDABLE)
        strcat(my_data, "NOFOR ");
    else
        strcat(my_data, "FOR ");
    if (attribs & KRB5_KDB_DISALLOW_TGT_BASED)
        strcat(my_data, "NOTGT ");
    else
        strcat(my_data, "TGT ");
    if (attribs & KRB5_KDB_DISALLOW_RENEWABLE)
        strcat(my_data, "NOREN ");
    else
        strcat(my_data, "REN ");
    if (attribs & KRB5_KDB_DISALLOW_PROXIABLE)
        strcat(my_data, "NOPROXY\n");
    else
        strcat(my_data, "PROXY\n");
    strcat(my_data, "                           ");
    if (attribs & KRB5_KDB_DISALLOW_DUP_SKEY)
        strcat(my_data, "NODUPSKEY ");
    else
        strcat(my_data, "DUPSKEY ");
    if (attribs & KRB5_KDB_DISALLOW_ALL_TIX)
        strcat(my_data, "LOCKED ");
    else
        strcat(my_data, "UNLOCKED ");
    if (attribs & KRB5_KDB_DISALLOW_SVR)
        strcat(my_data, "NOSVR\n");
    else
        strcat(my_data, "SVR\n");
    
#ifdef SANDIA
    strcat(my_data, "                           ");
    if (attribs & KRB5_KDB_REQUIRES_PRE_AUTH)
        strcat(my_data, "PREAUTH ");
    else
        strcat(my_data, "NOPREAUTH ");
    if (attribs & KRB5_KDB_REQUIRES_PWCHANGE)
        strcat(my_data, "PWCHG ");
    else
        strcat(my_data, "PWOK ");
    if (attribs & KRB5_KDB_REQUIRES_HW_AUTH)
        strcat(my_data, "SID\n");
    else
        strcat(my_data, "NOSID\n");
#endif
    (void) strcat(ret_data, my_data);
    free(my_data);
    return(0);
}

krb5_error_code
adm_print_exp_time(context, ret_data, time_input)
    krb5_context context;
    char *ret_data;
    krb5_timestamp *time_input;
{
    char *my_data;
    struct tm *exp_time;

    if ((my_data = (char *) calloc (1,255)) == (char *) 0)
	return ENOMEM;

    exp_time = localtime((time_t *) time_input);
    sprintf(my_data, 
	"Principal Expiration Date (PED): %02d%02d/%02d/%02d:%02d:%02d:%02d\n",
	(exp_time->tm_year >= 100) ? 20 : 19,
	(exp_time->tm_year >= 100) ? exp_time->tm_year - 100 : exp_time->tm_year,
	exp_time->tm_mon + 1,
	exp_time->tm_mday,
	exp_time->tm_hour,
	exp_time->tm_min,
	exp_time->tm_sec);
    (void) strcat(ret_data, my_data);
    free(my_data);
    return(0);
}

/*
 * With the new database format, we assume that a database entry always has a
 * key which is des:normal
 */
krb5_error_code
adm_fmt_prt(context, entry, Principal_name, ret_data)
    krb5_context context;
    krb5_db_entry *entry;
    char *Principal_name;
    char *ret_data;
{
    struct tm *mod_time;
    krb5_error_code retval;
    krb5_key_data	*pkey;
    krb5_tl_mod_princ	*mprinc_data;
#ifdef SANDIA
    struct tm *exp_time;
    int pwd_expire;
    krb5_timestamp now;
#endif

    char *my_data;
    char thisline[80];

    if ((my_data = (char *) calloc (1, 2048)) == (char *) 0)
	return ENOMEM;

    (void) sprintf(my_data, "\n\nPrincipal: %s\n\n", Principal_name);
    sprintf(thisline,
	"Maximum Ticket Lifetime (MTL) = %d (seconds)\n", entry->max_life);
    strcat(my_data, thisline);
    sprintf(thisline, "Maximum Renewal Lifetime (MRL) = %d (seconds)\n", 
			entry->max_renewable_life);
    strcat(my_data, thisline);
    pkey = (krb5_key_data *) NULL;
    if (retval = krb5_dbe_find_enctype(context,
				       entry,
				       ENCTYPE_DES_CBC_MD5,
				       KRB5_KDB_SALTTYPE_NORMAL,
				       -1,
				       &pkey)) {
	free(my_data);
	return retval;
    }
    sprintf(thisline, "Principal Key Version (PKV) = %d\n",
	    pkey->key_data_kvno);
    strcat(my_data, thisline);
    if (retval = adm_print_exp_time(context, my_data, &entry->expiration)) {
	free(my_data);
	return retval;
    }

    /*
     * Find the modification tagged entry.
     */
    if (krb5_dbe_decode_mod_princ_data(context, entry, &mprinc_data)) {
	free(my_data);
	return retval;
    }
    mod_time = localtime((time_t *) &mprinc_data->mod_date);
    sprintf(thisline, 
	"Last Modification Date (LMD): %02d%02d/%02d/%02d:%02d:%02d:%02d\n",
           (mod_time->tm_year >= 100) ? 20 : 19,
           (mod_time->tm_year >= 100) ? mod_time->tm_year - 100 : mod_time->tm_year,
           mod_time->tm_mon + 1,
           mod_time->tm_mday,
           mod_time->tm_hour,
           mod_time->tm_min,
           mod_time->tm_sec);
    strcat(my_data, thisline);
    krb5_free_principal(context, mprinc_data->mod_princ);
    krb5_xfree(mprinc_data);
    if (retval = adm_print_attributes(my_data, entry->attributes)) {
	free(my_data);
	return retval;
    }
    switch (pkey->key_data_type[1] & 0xff) {
           case 0 : strcat(my_data,
			"Principal Salt Type (PST) = Version 5 Normal\n");
		    break;
           case 1 : strcat(my_data, "Principal Salt Type (PST) = Version 4\n");
		    break;
           case 2 : strcat(my_data, "Principal Salt Type (PST) = NOREALM\n");
		    break;
           case 3 : strcat(my_data, "Principal Salt Type (PST) = ONLYREALM\n");
		    break;
           case 4 : strcat(my_data, "Principal Salt Type (PST) = Special\n");
		    break;
           } 
#ifdef SANDIA
    sprintf(thisline,
	"Invalid Authentication Count (FCNT) = %d\n", entry->fail_auth_count);
    strcat(my_data, thisline);
    retval = krb5_timeofday(context, &now);
    pwd_expire = (now - entry->last_pwd_change) / 86400;
    sprintf(thisline, "Password Age is %d Days\n", pwd_expire);
    strcat(my_data, thisline);
#endif
    (void) strcat(ret_data, my_data);
    free(my_data);
    return(0);
}
