/*
 * Copyright 1993 OpenVision Technologies, Inc., All Rights Reserved
 *
 * $Header$
 */

#if !defined(lint) && !defined(__CODECENTER__)
static char *rcsid = "$Header$";
#endif

#include    <unistd.h>
#include    <string.h>
#include    <stdlib.h>
#include    <memory.h>

#include    <kadm5/adb.h>
#include    "import_err.h"
#include    "import.h"

#define LINESIZE	32768 /* XXX */
#define PLURAL(count)	(((count) == 1) ? error_message(IMPORT_SINGLE_RECORD) : error_message(IMPORT_PLURAL_RECORDS))
   
int parse_pw_hist_ent(current, hist, ovsec_compat)
   char *current;
   osa_pw_hist_ent *hist;
   int ovsec_compat;
{
     int tmp, i, j, ret;
     char *cp;

     ret = 0;
     if (!ovsec_compat) {
	  if ((cp = nstrtok((char *) NULL, "\t")) == NULL) {
	       com_err(NULL, IMPORT_BAD_RECORD, "%s", current);
	       return IMPORT_FAILED;
	  }
	  hist->n_key_data = atoi(cp);
     } else
	  hist->n_key_data = 1;

     hist->key_data = (krb5_key_data *) malloc(hist->n_key_data *
					       sizeof(krb5_key_data));
     if (hist->key_data == NULL)
	  return ENOMEM;
     memset(hist->key_data, 0, sizeof(krb5_key_data)*hist->n_key_data);

     for (i = 0; i < hist->n_key_data; i++) {
	  krb5_key_data *key_data = &hist->key_data[i];

	  key_data->key_data_ver = 1;
	  
	  if((cp = nstrtok((char *) NULL, "\t")) == NULL) {
	       com_err(NULL, IMPORT_BAD_RECORD, "%s", current);
	       ret = IMPORT_FAILED;
	       goto done;
	  }
	  key_data->key_data_type[0] = atoi(cp);

	  if((cp = nstrtok((char *) NULL, "\t")) == NULL) {
	       com_err(NULL, IMPORT_BAD_RECORD, "%s", current);
	       ret =  IMPORT_FAILED;
	       goto done;
	  }
	  key_data->key_data_length[0] = atoi(cp);
	  
	  if((cp = nstrtok((char *) NULL, "\t")) == NULL) {
	       com_err(NULL, IMPORT_BAD_RECORD, "%s", current);
	       ret = IMPORT_FAILED;
	       goto done;
	  }
	  if(!(key_data->key_data_contents[0] =
	       (krb5_octet *) malloc(key_data->key_data_length[0]+1))) {
	       ret = ENOMEM;
	       goto done;
	  }
	  for(j = 0; j < key_data->key_data_length[0]; j++) {
	       if(sscanf(cp, "%02x", &tmp) != 1) {
		    com_err(NULL, IMPORT_BAD_RECORD, "%s", current);
		    ret = IMPORT_FAILED;
		    goto done;
	       }
	       key_data->key_data_contents[0][j] = tmp;
	       cp = strchr(cp, ' ') + 1;
	  }
     }
     
done:
     return ret;
}

		     

/*
 * Function: parse_principal
 * 
 * Purpose: parse principal line in db dump file
 *
 * Arguments:
 * 	<return value>	0 on sucsess, error code on failure
 *
 * Requires:
 *	principal database to be opened.
 *	nstrtok(3) to have a valid buffer in memory.
 * 
 * Effects:
 *	[effects]
 *
 * Modifies:
 *	[modifies]
 * 
 */
int parse_principal(context, ovsec_compat)
   krb5_context context;
   int ovsec_compat;
{
    XDR xdrs;
    osa_princ_ent_t	    rec;
    osa_adb_ret_t	    ret;
    krb5_tl_data	    tl_data;
    krb5_principal	    princ;
    krb5_db_entry	    kdb;
    char		    *current;
    char		    *cp;
    int			    tmp, x, i, one, more;

    if((cp = nstrtok((char *) NULL, "\t")) == NULL)
	return IMPORT_BAD_FILE;
    if((rec = (osa_princ_ent_t) malloc(sizeof(osa_princ_ent_rec))) == NULL)
	return ENOMEM;
    memset(rec, 0, sizeof(osa_princ_ent_rec));
    if((ret = krb5_parse_name(context, cp, &princ))) 
	goto done;
    krb5_unparse_name(context, princ, &current);
    if((cp = nstrtok((char *) NULL, "\t")) == NULL) {
	com_err(NULL, IMPORT_BAD_RECORD, "%s", current);
	ret =  IMPORT_FAILED;
	goto done;
    } else {
	if(strcmp(cp, "")) {
	    if((rec->policy = (char *) malloc(strlen(cp)+1)) == NULL)  {
		ret = ENOMEM;
		goto done;
	    }
	    strcpy(rec->policy, cp);
	} else rec->policy = NULL;
    }
    if((cp = nstrtok((char *) NULL, "\t")) == NULL) {
	com_err(NULL, IMPORT_BAD_RECORD, "%s", current);
	ret = IMPORT_FAILED;
	goto done;
    }
    rec->aux_attributes = strtol(cp, (char  **)NULL, 16);
    if((cp = nstrtok((char *) NULL, "\t")) == NULL) {
	com_err(NULL, IMPORT_BAD_RECORD, "%s", current);
	ret = IMPORT_FAILED;
	goto done;
    }
    rec->old_key_len = atoi(cp);
    if((cp = nstrtok((char *) NULL, "\t")) == NULL) {
	com_err(NULL, IMPORT_BAD_RECORD, "%s", current);
	ret = IMPORT_FAILED;
	goto done;
    }
    rec->old_key_next = atoi(cp);
    if((cp = nstrtok((char *) NULL, "\t")) == NULL) {
	com_err(NULL, IMPORT_BAD_RECORD, "%s", current);
	ret = IMPORT_FAILED;
	goto done;
    }
    rec->admin_history_kvno = atoi(cp);
    if (! rec->old_key_len) {
       rec->old_keys = NULL;
    } else {
       if(!(rec->old_keys = (osa_pw_hist_ent *)
	    malloc(sizeof(osa_pw_hist_ent) * rec->old_key_len))) {
	  ret = ENOMEM;
	  goto done;
       }
       memset(rec->old_keys,0,
	      sizeof(osa_pw_hist_ent) * rec->old_key_len);
       for(x = 0; x < rec->old_key_len; x++)
	    parse_pw_hist_ent(current, &rec->old_keys[x], ovsec_compat);
    }

    xdralloc_create(&xdrs, XDR_ENCODE);
    if (! xdr_osa_princ_ent_rec(&xdrs, rec)) {
	 xdr_destroy(&xdrs);
	 ret = OSA_ADB_XDR_FAILURE;
	 goto done;
    }

    tl_data.tl_data_type = KRB5_TL_KADM_DATA;
    tl_data.tl_data_length = xdr_getpos(&xdrs);
    tl_data.tl_data_contents = xdralloc_getdata(&xdrs);

    one = 1;
    ret = krb5_db_get_principal(context, princ, &kdb, &one,
				&more);
    if (ret)
	 goto done;
    
    if (ret = krb5_dbe_update_tl_data(context, &kdb,
				&tl_data))
	 goto done;

    if (ret = krb5_db_put_principal(context, &kdb, &one))
	 goto done;

    xdr_destroy(&xdrs);

done:
    free(current);
    krb5_free_principal(context, princ);
    osa_free_princ_ent(rec);
    return ret;
}
    
/*
 * Function: parse-policy
 * 
 * Purpose: parse the ascii text of a dump file and turn it into
 *	    a policy_ent_rec.
 *
 * Arguments:
 * 	<return value>	0 on sucsess, error code on failure;
 *
 * Requires:
 *	nstrtok to have a buffer in memory
 * 
 * Effects:
 *	write data out to db.
 *
 * Modifies:
 *	policy db.
 * 
 */
int
parse_policy(pol_db)
   osa_adb_policy_t pol_db;
{
    osa_policy_ent_t	    rec;
    char		    *cp;
    osa_adb_ret_t	    ret;
    
    if((rec = (osa_policy_ent_t) malloc(sizeof(osa_princ_ent_rec))) == NULL)
	return ENOMEM;
    memset(rec, 0, sizeof(osa_princ_ent_rec));
    if((cp = nstrtok((char *) NULL, "\t")) == NULL) {
	ret = IMPORT_BAD_FILE;
	goto done;
    }
    if((rec->name = (char *) malloc(strlen(cp) + 1)) == NULL) {
	ret = ENOMEM;
	goto done;
    }
    strcpy(rec->name, cp);
    if((cp = nstrtok((char *) NULL, "\t")) == NULL) {
	com_err(NULL, IMPORT_BAD_RECORD, "%s", rec->name);
	ret = IMPORT_FAILED;
	goto done;
    }
    rec->pw_min_life = atoi(cp);
    if((cp = nstrtok((char *) NULL, "\t")) == NULL) {
	com_err(NULL, IMPORT_BAD_RECORD, "%s", rec->name);
	ret = IMPORT_FAILED;
	goto done;
    }
    rec->pw_max_life = atoi(cp);
    if((cp = nstrtok((char *) NULL, "\t")) == NULL) {
	com_err(NULL, IMPORT_BAD_RECORD, "%s", rec->name);
	ret = IMPORT_FAILED;
	goto done;
    }
    rec->pw_min_length = atoi(cp);
    if((cp = nstrtok((char *) NULL, "\t")) == NULL) {
	com_err(NULL, IMPORT_BAD_RECORD, "%s", rec->name);
	ret = IMPORT_FAILED;
	goto done;
    }
    rec->pw_min_classes = atoi(cp);
    if((cp = nstrtok((char *) NULL, "\t")) == NULL) {
	com_err(NULL, IMPORT_BAD_RECORD, "%s", rec->name);
	ret = IMPORT_FAILED;
	goto done;
    }
    rec->pw_history_num = atoi(cp);
    if((cp = nstrtok((char *) NULL, "\t")) == NULL) {
	com_err(NULL, IMPORT_BAD_RECORD, "%s", rec->name);
	ret = IMPORT_FAILED;
	goto done;
    }
    rec->policy_refcnt = atoi(cp);
    ret = osa_adb_create_policy(pol_db, rec);
done:
   osa_free_policy_ent(rec);
   return ret;
}

/*
 * Function: import-file
 * 
 * Purpose: import a flat ascii file and convert it to a db file.
 *
 * Arguments:
 *	fp		    (input) file pointer to read db.
 * 	<return value>	    0 or error code on error.
 *
 * Requires:
 *	fp be valid
 * 
 * Effects:
 *	calls appropriate routine to write out db files.
 *
 * Modifies:
 *	database file.
 *
 */

int import_file(krb5_context context, FILE *fp, int merge_princs,
		osa_adb_policy_t pol_db) 
{
    
    int	    count = 0;
    int	    errcnt = 0;
    int	    ret = 0;
    int	    found_footer = 0;
    int	    file_count;
    int	    ovsec_compat;
    char    line[LINESIZE];
    char    version[BUFSIZ];
    char    date[BUFSIZ];
    char    *cp;
    
    if(fgets(line, LINESIZE, fp) == NULL)
	return IMPORT_BAD_FILE;
    if ((sscanf(line, "%[^\t]\t %[^\t]", version, date)) != 2)
	return IMPORT_BAD_FILE;
    if(!strcmp(version, VERSION_OVSEC_10))
	 ovsec_compat++;
    else if (strcmp(version, VERSION_KADM5_20))
	 return IMPORT_BAD_VERSION;

    while(fgets(line, LINESIZE, fp) != (char *) NULL) {
	if(found_footer) {
	    com_err(NULL, IMPORT_EXTRA_DATA, NULL);
	    break;
	}
	cp = nstrtok(line, "\t");
	if(!strcasecmp(cp, "princ")) {
	    if(merge_princs &&
	       (ret = parse_principal(context, ovsec_compat)) != OSA_ADB_OK) {
		if(ret == IMPORT_FAILED) {
		    if(!confirm())
			break;
		    else {
			errcnt++;
			continue;
		    }
		} else break;
	    } else {
		count++;
		continue;
	    }
	}
	if(!strcasecmp(cp, "policy")) {
	    if((ret = parse_policy(pol_db)) != OSA_ADB_OK) {
		if(ret == IMPORT_FAILED) {
		    if(!confirm())
			break;
		    else {
			errcnt++;
			continue;
		    }
		} else break;
	    } else {
		count++;
		continue;
	    }
	}
	if(!strcasecmp(cp, "end of database")) {
	    found_footer = 1;
	} else {
	    com_err(NULL, IMPORT_BAD_TOKEN, "%s", cp);
	    if(!confirm()) {
		ret = IMPORT_BAD_FILE;
		break;
	    }  else {
		errcnt++;
		continue;
	    }
	}
    }
    if(ret == OSA_ADB_OK && found_footer) {
	if((cp = nstrtok(NULL, "\t")) == NULL) {
	    com_err(NULL, IMPORT_BAD_FOOTER, NULL);
	    if(!confirm())
		ret = IMPORT_BAD_FOOTER;
	    else
		ret = OSA_ADB_OK;
	} else
	    file_count = atoi(cp);
	if(file_count != (count + errcnt)) {
	    fprintf(stderr, error_message(IMPORT_COUNT_MESSAGE), file_count,
		    PLURAL(file_count), count, PLURAL(count));
	    if(!confirm())
		ret =  IMPORT_MISMATCH_COUNT;
	    else
		ret = OSA_ADB_OK;
	} else fprintf(stderr, error_message(IMPORT_NO_ERR), count,
		       PLURAL(count));
    } else if(ret == OSA_ADB_OK && !found_footer) {
	com_err(NULL, IMPORT_BAD_FOOTER, NULL);
	if(!confirm())
	    ret = IMPORT_BAD_FOOTER;
	else
	    ret = OSA_ADB_OK;
    }

    return ret;
}
    
