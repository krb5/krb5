/*
 * Copyright 1993 OpenVision Technologies, Inc., All Rights Reserved
 *
 * $Header$
 */

#if !defined(lint) && !defined(__CODECENTER__)
static char *rcsid = "$Header$";
#endif

#include    <sys/time.h>
#include    <stdio.h>
#include    <malloc.h>
#include    <unistd.h>

#include    <kadm5/adb.h>
#include    "export_err.h"
#include    "local.h"

extern	int errno;

void print_key_data(FILE *f, krb5_key_data *key_data)
{
     int c;
     
     fprintf(f, "%d\t%d\t", key_data->key_data_type[0],
	     key_data->key_data_length[0]);
     for(c = 0; c < key_data->key_data_length[0]; c++) 
	  fprintf(f, "%02x ",
		  key_data->key_data_contents[0][c]);
}

/*
 * Function: print_princ
 * 
 * Purpose: output osa_adb_princ_ent data in a human
 *	    readable format (which is a format suitable for
 *	    ovsec_adm_import consumption)
 *
 * Arguments:
 *	data		(input) pointer to a structure containing a FILE *
 *			        and a record counter.
 *	entry		(input) entry to get dumped.
 * 	<return value>	void
 *
 * Requires:
 *	nuttin
 * 
 * Effects:
 *	writes data to the specified file pointerp.
 *
 * Modifies:
 *	nuttin
 * 
 */
krb5_error_code print_princ(krb5_pointer data, krb5_db_entry *kdb)
{
    char *princstr;
    int	x, y, foundcrc, ret;
    struct retdata *d;
    krb5_tl_data tl_data;
    osa_princ_ent_rec adb;
    XDR xdrs;

    d = (struct retdata *) data;

    /*
     * XXX Currently, lookup_tl_data always returns zero; it sets
     * tl_data->tl_data_length to zero if the type isn't found.
     * This should be fixed...
     */
    /*
     * XXX Should this function do nothing for a principal with no
     * admin data, or print a record of "default" values?   See
     * comment in server_kdb.c to help decide.
     */
    tl_data.tl_data_type = KRB5_TL_KADM_DATA;
    if ((ret = krb5_dbe_lookup_tl_data(d->context, kdb, &tl_data))
	|| (tl_data.tl_data_length == 0))
	 return(0);

    memset(&adb, 0, sizeof(adb));
    xdrmem_create(&xdrs, tl_data.tl_data_contents,
		  tl_data.tl_data_length, XDR_DECODE);
    if (! xdr_osa_princ_ent_rec(&xdrs, &adb)) {
	 xdr_destroy(&xdrs);
	 return(OSA_ADB_XDR_FAILURE);
    }
    xdr_destroy(&xdrs);
    
    krb5_unparse_name(d->context, kdb->princ, &princstr);
    fprintf(d->fp, "princ\t%s\t", princstr);
    if(adb.policy == NULL)
	fputc('\t', d->fp);
    else
	fprintf(d->fp, "%s\t", adb.policy);
    fprintf(d->fp, "%x\t%d\t%d\t%d", adb.aux_attributes,
	    adb.old_key_len,adb.old_key_next, adb.admin_history_kvno);

    for (x = 0; x < adb.old_key_len; x++) {
	 if (! d->ovsec_compat)
	      fprintf(d->fp, "\t%d", adb.old_keys[x].n_key_data);

	 foundcrc = 0;
	 for (y = 0; y < adb.old_keys[x].n_key_data; y++) {
	      krb5_key_data *key_data = &adb.old_keys[x].key_data[y];

	      if (d->ovsec_compat) {
		   if (key_data->key_data_type[0] != ENCTYPE_DES_CBC_CRC)
			continue;
		   if (foundcrc) {
			fprintf(stderr, error_message(EXPORT_DUP_DESCRC), 
				princstr);
			continue;
		   }
		   foundcrc++;
	      }
	      fputc('\t', d->fp);
	      print_key_data(d->fp, key_data);
	 }
	 if (d->ovsec_compat && !foundcrc)
	      fprintf(stderr, error_message(EXPORT_NO_DESCRC), princstr);
    }

    d->count++;
    fputc('\n', d->fp);
    free(princstr);
    return(0);
}

/*
 * Function: print_policy
 * 
 * Purpose: Print the contents of a policy entry in a human readable format.
 *	    This format is also suitable for consumption for dbimport.
 *
 * Arguments:
 *	data		(input) a pointer to a structure containing a FILE *
 *			        and a record counter.
 *	entry		(input) policy entry
 * 	<return value>	void
 *
 * Requires:
 *	nuttin
 * 
 * Effects:
 *	writes data to file
 *
 * Modifies:
 *	nuttin
 * 
 */

void
print_policy(void *data, osa_policy_ent_t entry)
{
    struct  retdata *d;

    d = (struct retdata *) data;
    fprintf(d->fp, "policy\t%s\t%d\t%d\t%d\t%d\t%d\t%d\n", entry->name,
	    entry->pw_min_life, entry->pw_max_life, entry->pw_min_length,
	    entry->pw_min_classes, entry->pw_history_num,
	    entry->policy_refcnt);
    d->count++;
    return;
}

/*
 * Function: export_principal
 * 
 * Purpose:  interates through the principal database with the
 *	     osa_adb_iter_princ function which calls the print_princ
 *	     routine with the FILE * of our filename. If the file
 *	     name that gets passed in is NULL then we use stdout.
 *
 * Arguments:
 *	d		(input) pointer to retdata.
 * 	<return value>	error code. 0 if sucsessful.
 *
 * Requires:
 *	nuttin
 * 
 * Effects:
 *	calls osa_adb_iter_princ which calls print_princ
 *
 * Modifies:
 *	nuttin
 * 
 */
osa_adb_ret_t
export_principal(struct retdata *d, kadm5_config_params *params)
{
     int ret;

     if (ret = krb5_db_set_name(d->context, params->dbname))
	  return ret;

     if (ret = krb5_db_init(d->context))
	  return ret;

     if (ret = krb5_dbm_db_iterate(d->context, print_princ, d))
	  return ret;

     if (ret = krb5_db_fini(d->context))
	  return ret;

     return 0;
}

/*
 * Function: export_policy
 * 
 * Purpose: iterates through the policy database with the
 *	    osa_adb_iter_policy function which calls the print_policy
 *	    routine with the FILE * of our filename. If the file name
 *	    that gets passed in is NULL then we use stdout.
 *
 * Arguments:
 *	d		(input) a pointer to retdata
 * 	<return value>	error code 0 if sucsessfull.
 *
 * Requires:
 *	nuttin
 * 
 * Effects:
 *	calls osa_adb_iter_policy which calls print_policy
 *
 * Modifies:
 *	nuttin
 * 
 */
osa_adb_ret_t
export_policy(struct retdata *d, osa_adb_policy_t db)
{
    osa_adb_ret_t	ret;
    
    if((ret = osa_adb_iter_policy(db, print_policy, (void *) d))
       != OSA_ADB_OK) {
	return ret;
    }
    return OSA_ADB_OK;
}
