/*
 * kadmin/v4server/kadm_funcs.c
 *
 * Copyright 1988 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <mit-copyright.h>.
 *
 * Kerberos administration server-side database manipulation routines
 */


#include <mit-copyright.h>
/*
kadm_funcs.c
the actual database manipulation code
*/

#include <stdio.h>
#include <string.h>
#include <sys/param.h>
#ifdef NDBM_PW_CHECK
#include <ndbm.h>
#endif
#include <ctype.h>
#include <pwd.h>
#include <sys/file.h>
#include <kadm.h>
#include <kadm_err.h>
#include <krb_db.h>
#include <syslog.h>
#include <fcntl.h>
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#ifdef TIME_WITH_SYS_TIME
#include <time.h>
#endif
#else
#include <time.h>
#endif

#include "kadm_server.h"

extern Kadm_Server server_parm;

#include <kadm5/admin.h>
extern void *kadm5_handle;

/* Generate dummy password.  Yes, it's gross. */
static char *dummypw()
{
    static char dummybuf[256];
    int i;

    if (dummybuf[0] == 0)
	for (i = 0; i < 256; i++)
	    dummybuf[i] = (i + 1) % 256;
    return dummybuf;
}

/*
 * kadm_entry2princ:
 *
 * Convert a kadm5_principal_ent_t to a Principal.  Assumes that princ
 * is already allocated.
 */
static krb5_error_code
kadm_entry2princ(entry, princ)
    kadm5_principal_ent_t entry;
    Principal *princ;
{
    char realm[REALM_SZ + 1];	/* dummy values only */
    krb5_error_code retval;
    int i;

    /* NOTE: does not convert the key */
    memset(princ, 0, sizeof (*princ));
    retval = krb5_524_conv_principal(kadm_context, entry->principal,
				     princ->name, princ->instance, realm);
    if (retval)
	return retval;
    princ->exp_date = entry->pw_expiration;
    strncpy(princ->exp_date_txt,
	    ctime((const time_t *) &entry->pw_expiration), DATE_SZ);
    princ->attributes = entry->attributes;
    princ->max_life = krb_time_to_life(0, entry->max_life);
    princ->kdc_key_ver = 1; /* entry->mkvno .... WTF??? --tlyu */
    for (i = 0; i < entry->n_key_data; i++) {
	/* XXX This assumes knowledge of the internals of krb5_key_data */
	if (entry->key_data[i].key_data_type[0] == ENCTYPE_DES_CBC_CRC &&
	    entry->key_data[i].key_data_type[1] == KRB5_KDB_SALTTYPE_V4) {
	    princ->key_version = entry->key_data[i].key_data_kvno;
	    break;
	}
    }

    retval = krb5_524_conv_principal(kadm_context, entry->mod_name,
					princ->mod_name, princ->mod_instance,
					realm);
    if (retval)
	return retval;

    princ->mod_date = entry->mod_date;
    strncpy(princ->mod_date_txt,
	    ctime((const time_t *) &entry->mod_date),
	    DATE_SZ);

    return 0;
}

static int check_access(pname, pinst, prealm, acltype)
    char *pname;
    char *pinst;
    char *prealm;
    enum acl_types acltype;
{
    char checkname[MAX_K_NAME_SZ];
    char filename[MAXPATHLEN];
    extern char *acldir;

    (void) sprintf(checkname, "%s.%s@%s", pname, pinst, prealm);
    
    switch (acltype) {
    case ADDACL:
	(void) sprintf(filename, "%s%s", acldir, ADD_ACL_FILE);
    break;
    case GETACL:
	(void) sprintf(filename, "%s%s", acldir, GET_ACL_FILE);
    break;
    case MODACL:
	(void) sprintf(filename, "%s%s", acldir, MOD_ACL_FILE);
    break;
    case DELACL:
	(void) sprintf(filename, "%s%s", acldir, DEL_ACL_FILE);
    break;
    case STABACL:
	(void) sprintf(filename, "%s%s", acldir, STAB_ACL_FILE);
    break;
    }
    return(acl_check(filename, checkname));
}

static int wildcard(str)
char *str;
{
    if (!strcmp(str, WILDCARD_STR))
	return(1);
    return(0);
}

krb5_error_code
kadm_add_entry (rname, rinstance, rrealm, valsin, valsout)
    char *rname;		/* requestors name */
    char *rinstance;		/* requestors instance */
    char *rrealm;		/* requestors realm */
    Kadm_vals *valsin;
    Kadm_vals *valsout;
{
    Principal data_i, data_o;	/* temporary principal */
    u_char flags[4];
    krb5_error_code retval;
    kadm5_principal_ent_rec newentry, tmpentry;
    krb5_keyblock newpw;
    long mask = 0;

    if (!check_access(rname, rinstance, rrealm, ADDACL)) {
	syslog(LOG_WARNING,
	       "WARNING: '%s.%s@%s' tried to add an entry for '%s.%s'",
	       rname, rinstance, rrealm, valsin->name, valsin->instance);
	return KADM_UNAUTH;
    }

    /* Need to check here for "legal" name and instance */
    if (wildcard(valsin->name) || wildcard(valsin->instance)) {
	retval = KADM_ILL_WILDCARD;
	goto err;
    }

    syslog(LOG_INFO, "request to add an entry for '%s.%s' from '%s.%s@%s'",
	   valsin->name, valsin->instance, rname, rinstance, rrealm);

    kadm_vals_to_prin(valsin->fields, &data_i, valsin);
    (void) strncpy(data_i.name, valsin->name, ANAME_SZ);
    (void) strncpy(data_i.instance, valsin->instance, INST_SZ);

    memset(&newentry, 0, sizeof (newentry));
    retval = krb5_425_conv_principal(kadm_context,
				     data_i.name, data_i.instance,
				     server_parm.krbrlm,
				     &newentry.principal);
    if (retval)
	goto err_newentry;

    if (IS_FIELD(KADM_EXPDATE,valsin->fields)) {
	newentry.princ_expire_time = data_i.exp_date;
	mask |= KADM5_PRINC_EXPIRE_TIME;
    }

    if (IS_FIELD(KADM_MAXLIFE,valsin->fields)) {
	newentry.max_life = krb_life_to_time(0, data_i.max_life);
	mask |= KADM5_MAX_LIFE;
    }

    /* Create with ticket issuing disabled. */
    newentry.attributes = KRB5_KDB_DISALLOW_ALL_TIX;
    mask |= KADM5_PRINCIPAL|KADM5_ATTRIBUTES;
    retval = kadm5_get_principal(kadm5_handle, newentry.principal,
				 &tmpentry, KADM5_PRINCIPAL_NORMAL_MASK);
    switch (retval) {
    case KADM5_UNK_PRINC:
	break;
    case 0:
	kadm5_free_principal_ent(kadm5_handle, &tmpentry);
	retval = KADM_INUSE;
    default:
	goto err_newentry;
	break;
    }

    retval = kadm5_create_principal(kadm5_handle, &newentry,
				    mask, dummypw());
    if (retval)
	goto err_newentry;

    newpw.magic = KV5M_KEYBLOCK;
    if ((newpw.contents = (krb5_octet *)malloc(8)) == NULL) {
	retval = KADM_NOMEM;
	goto err_newentry;
    }

    data_i.key_low = ntohl(data_i.key_low);
    data_i.key_high = ntohl(data_i.key_high);
    memcpy(newpw.contents, &data_i.key_low, 4);
    memcpy((char *)(((krb5_int32 *) newpw.contents) + 1), &data_i.key_high, 4);
    newpw.length = 8;
    newpw.enctype = ENCTYPE_DES_CBC_CRC;

    retval = kadm5_setv4key_principal(kadm5_handle,
				      newentry.principal, &newpw);
    memset((char *)newpw.contents, 0, newpw.length);
    free(newpw.contents);
    if (retval)
	goto err_newentry;

    newentry.attributes &= ~KRB5_KDB_DISALLOW_ALL_TIX;
    retval = kadm5_modify_principal(kadm5_handle, &newentry,
				    KADM5_ATTRIBUTES);
    if (retval)
      goto err_newentry;

    retval = kadm5_get_principal(kadm5_handle, newentry.principal,
				 &tmpentry, KADM5_PRINCIPAL_NORMAL_MASK);
    kadm5_free_principal_ent(kadm5_handle, &newentry);
    if (retval)
	goto err;

    kadm_entry2princ(&tmpentry, &data_o);
    kadm5_free_principal_ent(kadm5_handle, &tmpentry);
    memset((char *)flags, 0, sizeof(flags));
    SET_FIELD(KADM_NAME,flags);
    SET_FIELD(KADM_INST,flags);
    SET_FIELD(KADM_EXPDATE,flags);
    SET_FIELD(KADM_ATTR,flags);
    SET_FIELD(KADM_MAXLIFE,flags);
    kadm_prin_to_vals(flags, valsout, &data_o);
    syslog(LOG_INFO, "'%s.%s' added.", valsin->name, valsin->instance);
    return KADM_DATA;		/* Set all the appropriate fields */

err_newentry:
    kadm5_free_principal_ent(kadm5_handle, &newentry);
err:
    syslog(LOG_ERR, "FAILED adding '%s.%s' (%s)",
	   valsin->name, valsin->instance, error_message(retval));
    return retval;
}

#ifndef KADM5
#define faildel(code) {  (void) syslog(LOG_ERR, "FAILED deleting '%s.%s' (%s)", valsin->name, valsin->instance, error_message(code)); return code; }

krb5_error_code
kadm_del_entry (rname, rinstance, rrealm, valsin, valsout)
char *rname;				/* requestors name */
char *rinstance;			/* requestors instance */
char *rrealm;				/* requestors realm */
Kadm_vals *valsin;
Kadm_vals *valsout;
{
  int numfound;			/* check how many we get written */
  krb5_boolean more;			/* pointer to more grabbed records */
  Principal data_i, data_o;		/* temporary principal */
  u_char flags[4];
  krb5_db_entry entry, odata;
  krb5_error_code retval;
  krb5_principal inprinc;

  if (!check_access(rname, rinstance, rrealm, DELACL)) {
    (void) syslog(LOG_WARNING, "WARNING: '%s.%s@%s' tried to delete an entry for '%s.%s'",
	       rname, rinstance, rrealm, valsin->name, valsin->instance);
    return KADM_UNAUTH;
  }
  
  /* Need to check here for "legal" name and instance */
  if (wildcard(valsin->name) || wildcard(valsin->instance)) {
      faildel(KADM_ILL_WILDCARD);
  }

  syslog(LOG_INFO, "request to delete an entry for '%s.%s' from '%s.%s@%s'",
	 valsin->name, valsin->instance, rname, rinstance, rrealm);
  
  retval = krb5_425_conv_principal(kadm_context, valsin->name,
				   valsin->instance,
				   server_parm.krbrlm, &inprinc);
  if (retval)
    faildel(retval);

  numfound = 1;
  retval = krb5_db_get_principal(kadm_context, inprinc, &entry, &numfound,
				 &more);

  if (retval) {
    krb5_db_free_principal(kadm_context, &entry, numfound);
    faildel(retval);
  } else if (!numfound || more) {
    faildel(KADM_NOENTRY);
  }

  retval = krb5_db_delete_principal(kadm_context, inprinc, &numfound);
  if (retval) {
    krb5_db_free_principal(kadm_context, &entry, numfound);
    faildel(retval);
  }
  if (!numfound) {
    krb5_db_free_principal(kadm_context, &entry, numfound);
    faildel(KADM_UK_SERROR);
  } else {
    if (retval) {
      faildel(retval);
    } else if (numfound != 1 || more) {
      krb5_db_free_principal(kadm_context, &entry, numfound);
      faildel(KADM_UK_RERROR);
    }
    kadm_entry2princ(&entry, &data_o);
    krb5_db_free_principal(kadm_context, &entry, numfound);
    memset((char *)flags, 0, sizeof(flags));
    SET_FIELD(KADM_NAME,flags);
    SET_FIELD(KADM_INST,flags);
    SET_FIELD(KADM_EXPDATE,flags);
    SET_FIELD(KADM_ATTR,flags);
    SET_FIELD(KADM_MAXLIFE,flags);
    kadm_prin_to_vals(flags, valsout, &data_o);
    syslog(LOG_INFO, "'%s.%s' deleted.", valsin->name, valsin->instance);
    return KADM_DATA;		/* Set all the appropriate fields */
  }
}
#undef faildel

#endif /* !KADM5 */

krb5_error_code
kadm_get_entry (rname, rinstance, rrealm, valsin, flags, valsout)
    char *rname;		/* requestors name */
    char *rinstance;		/* requestors instance */
    char *rrealm;		/* requestors realm */
    Kadm_vals *valsin;		/* what they wannt to get */
    u_char *flags;		/* which fields we want */
    Kadm_vals *valsout;		/* what data is there */
{
    Principal data_o;		/* Data object to hold Principal */
    krb5_principal inprinc;
    krb5_error_code retval;
    kadm5_principal_ent_rec ent;

    if (!check_access(rname, rinstance, rrealm, GETACL)) {
	syslog(LOG_WARNING, "WARNING: '%s.%s@%s' tried to get '%s.%s's entry",
	       rname, rinstance, rrealm, valsin->name, valsin->instance);
	return KADM_UNAUTH;
    }

    if (wildcard(valsin->name) || wildcard(valsin->instance)) {
	retval = KADM_ILL_WILDCARD;
	goto err;
    }

    syslog(LOG_INFO, "retrieve '%s.%s's entry for '%s.%s@%s'",
	   valsin->name, valsin->instance, rname, rinstance, rrealm);

    retval = krb5_425_conv_principal(kadm_context, valsin->name,
				     valsin->instance,
				     server_parm.krbrlm, &inprinc);
    if (retval)
	goto err_princ;

    retval = kadm5_get_principal(kadm5_handle, inprinc, &ent,
				 KADM5_PRINCIPAL_NORMAL_MASK);
    krb5_free_principal(kadm_context, inprinc);
    switch (retval) {
    case KADM5_UNK_PRINC:
	retval = KADM_NOENTRY;
	goto err_princ;
    default:
	goto err_princ;
    case 0:
	break;
    }
    retval = kadm_entry2princ(&ent, &data_o);
    kadm5_free_principal_ent(kadm5_handle, &ent);
    if (retval) {
	goto err_princ;
    }
    kadm_prin_to_vals(flags, valsout, &data_o);
    syslog(LOG_INFO, "'%s.%s' retrieved.", valsin->name, valsin->instance);
    return KADM_DATA;		/* Set all the appropriate fields */
err_princ:
    krb5_free_principal(kadm_context, inprinc);
err:
    syslog(LOG_ERR, "FAILED retrieving '%s.%s' (%s)",
	   valsin->name, valsin->instance, error_message(retval));
    return retval;
}


krb5_error_code
kadm_mod_entry (rname, rinstance, rrealm, valsin1, valsin2, valsout)
    char *rname;				/* requestors name */
    char *rinstance;			/* requestors instance */
    char *rrealm;				/* requestors realm */
    Kadm_vals *valsin1, *valsin2;		/* holds the parameters being
						   passed in */
    Kadm_vals *valsout;		/* the actual record which is returned */
{
    Principal data_o, temp_key;
    u_char fields[4];
    krb5_keyblock newpw;
    krb5_error_code retval;
    krb5_principal theprinc;
    kadm5_principal_ent_rec entry;
    long mask = 0;

    if (wildcard(valsin1->name) || wildcard(valsin1->instance)) {
	retval = KADM_ILL_WILDCARD;
	goto err;
    }

    if (!check_access(rname, rinstance, rrealm, MODACL)) {
	syslog(LOG_WARNING, "WARNING: '%s.%s@%s' tried to change '%s.%s's entry",
	       rname, rinstance, rrealm, valsin1->name, valsin1->instance);
	return KADM_UNAUTH;
    }

    syslog(LOG_INFO, "request to modify '%s.%s's entry from '%s.%s@%s' ",
	   valsin1->name, valsin1->instance, rname, rinstance, rrealm);
    retval = krb5_425_conv_principal(kadm_context,
				     valsin1->name, valsin1->instance,
				     server_parm.krbrlm, &theprinc);
    if (retval)
	goto err;
    retval = kadm5_get_principal(kadm5_handle, theprinc, &entry,
				 KADM5_PRINCIPAL_NORMAL_MASK);
    if (retval)
	goto err_princ;

    kadm_vals_to_prin(valsin2->fields, &temp_key, valsin2);

    if (IS_FIELD(KADM_EXPDATE,valsin2->fields)) {
	entry.princ_expire_time = temp_key.exp_date;
	mask |= KADM5_PRINC_EXPIRE_TIME;
    }

    if (IS_FIELD(KADM_MAXLIFE,valsin2->fields)) {
	entry.max_life = krb_life_to_time(0, temp_key.max_life);
	mask |= KADM5_MAX_LIFE;
    }

    retval = kadm5_modify_principal(kadm5_handle, &entry, mask);
    if (retval)
	goto err_entry;

    if (IS_FIELD(KADM_DESKEY,valsin2->fields)) {
	if ((newpw.contents = (krb5_octet *)malloc(8)) == NULL) {
	    retval = KADM_NOMEM;
	    goto err_entry;
	}
	newpw.magic = KV5M_KEYBLOCK;
	newpw.length = 8;
	newpw.enctype = ENCTYPE_DES_CBC_CRC;
	temp_key.key_low = ntohl(temp_key.key_low);
	temp_key.key_high = ntohl(temp_key.key_high);
	memcpy(newpw.contents, &temp_key.key_low, 4);
	memcpy(newpw.contents + 4, &temp_key.key_high, 4);
	memset((char *)&temp_key, 0, sizeof(temp_key));

	retval = kadm5_setv4key_principal(kadm5_handle, entry.principal,
					  &newpw);
	krb5_free_keyblock_contents(kadm_context, &newpw);
	if (retval)
	    goto err_entry;
    }

    kadm5_free_principal_ent(kadm5_handle, &entry);

    retval = kadm5_get_principal(kadm5_handle, theprinc, &entry,
				 KADM5_PRINCIPAL_NORMAL_MASK);
    if (retval)
	goto err_princ;

    retval = kadm_entry2princ(&entry, &data_o);
    kadm5_free_principal_ent(kadm5_handle, &entry);
    krb5_free_principal(kadm_context, theprinc);
    if (retval)
	goto err;

    memset((char *) fields, 0, sizeof(fields));
    SET_FIELD(KADM_NAME,fields);
    SET_FIELD(KADM_INST,fields);
    SET_FIELD(KADM_EXPDATE,fields);
    SET_FIELD(KADM_ATTR,fields);
    SET_FIELD(KADM_MAXLIFE,fields);
    kadm_prin_to_vals(fields, valsout, &data_o);
    syslog(LOG_INFO, "'%s.%s' modified.", valsin1->name, valsin1->instance);
    return KADM_DATA;		/* Set all the appropriate fields */

err_entry:
    kadm5_free_principal_ent(kadm5_handle, &entry);
err_princ:
    krb5_free_principal(kadm_context, theprinc);
err:
    syslog(LOG_ERR, "FAILED modifying '%s.%s' (%s)",
	   valsin1->name, valsin1->instance, error_message(retval));
    return retval;
}

#ifndef KADM5
#define failchange(code) {  syslog(LOG_ERR, "FAILED changing key for '%s.%s@%s' (%s)", rname, rinstance, rrealm, error_message(code)); return code; }

krb5_error_code
kadm_change (rname, rinstance, rrealm, newpw)
char *rname;
char *rinstance;
char *rrealm;
des_cblock newpw;
{
  int numfound;
  krb5_boolean more;
  krb5_principal rprinc;
  krb5_error_code retval;
  krb5_keyblock localpw;
  krb5_db_entry odata;
  krb5_key_data *pkey;
  krb5_keysalt sblock;

  if (strcmp(server_parm.krbrlm, rrealm)) {
      syslog(LOG_ERR, "change key request from wrong realm, '%s.%s@%s'!\n",
		 rname, rinstance, rrealm);
      return(KADM_WRONG_REALM);
  }

  if (wildcard(rname) || wildcard(rinstance)) {
      failchange(KADM_ILL_WILDCARD);
  }
  syslog(LOG_INFO, "'%s.%s@%s' wants to change its password",
	     rname, rinstance, rrealm);
  retval = krb5_425_conv_principal(kadm_context, rname, rinstance,
				   server_parm.krbrlm, &rprinc);
  if (retval)
    failchange(retval);
  if ((localpw.contents = (krb5_octet *)malloc(8)) == NULL)
    failchange(KADM_NOMEM);
  memcpy(localpw.contents, newpw, 8);
  localpw.magic = KV5M_KEYBLOCK;
  localpw.enctype = ENCTYPE_DES_CBC_CRC;
  localpw.length = 8;
  numfound = 1;
  retval = krb5_db_get_principal(kadm_context, rprinc, &odata,
				 &numfound, &more);
  krb5_free_principal(kadm_context, rprinc);
  if (retval) {
    memset(localpw.contents, 0, localpw.length);
    free(localpw.contents);
    failchange(retval);
  } else if (numfound == 1) {
    if (retval = krb5_dbe_find_enctype(kadm_context,
				       &odata,
				       ENCTYPE_DES_CBC_CRC,
				       KRB5_KDB_SALTTYPE_V4,
				       -1,
				       &pkey)) {
      failchange(retval);
    }
    pkey->key_data_kvno++;
    pkey->key_data_kvno %= 256;
    numfound = 1;
    sblock.type = KRB5_KDB_SALTTYPE_V4;
    sblock.data.length = 0;
    sblock.data.data = (char *) NULL;
    retval = krb5_dbekd_encrypt_key_data(kadm_context,
					 /* XXX but I'm ifdef'd out here,
					    so I can't really test this. */
					 &server_parm.master_encblock,
					 &localpw,
					 &sblock,
					 (int) pkey->key_data_kvno,
					 pkey);
    memset(localpw.contents, 0, localpw.length);
    free(localpw.contents);
    if (retval) {
      failchange(retval);
    }
    retval = krb5_db_put_principal(kadm_context, &odata, &numfound);
    krb5_db_free_principal(kadm_context, &odata, 1);
    if (retval) {
      failchange(retval);
    } else if (more) {
      failchange(KADM_UK_SERROR);
    } else {
      syslog(LOG_INFO,
	     "'%s.%s@%s' password changed.", rname, rinstance, rrealm);
      return KADM_SUCCESS;
    }
  }
  else {
    failchange(KADM_NOENTRY);
  }
}
#undef failchange
#endif /* !KADM5 */

static int
check_pw(newpw, checkstr)
	des_cblock	newpw;
	char		*checkstr;
{
#ifdef NOENCRYPTION
	return 0;
#else /* !NOENCRYPTION */
	des_cblock	checkdes;

	(void) des_string_to_key(checkstr, checkdes);
	return(!memcmp(checkdes, newpw, sizeof(des_cblock)));
#endif /* NOENCRYPTION */
}

static char *reverse(str)
	char	*str;
{
	static char newstr[80];
	char	*p, *q;
	int	i;

	i = strlen(str);
	if (i >= sizeof(newstr))
		i = sizeof(newstr)-1;
	p = str+i-1;
	q = newstr;
	q[i]='\0';
	for(; i > 0; i--) 
		*q++ = *p--;
	
	return(newstr);
}

static int lower(str)
	char	*str;
{
	register char	*cp;
	int	effect=0;

	for (cp = str; *cp; cp++) {
		if (isupper((int) *cp)) {
			*cp = tolower((int) *cp);
			effect++;
		}
	}
	return(effect);
}

static int
des_check_gecos(gecos, newpw)
	char	*gecos;
	des_cblock newpw;
{
	char		*cp, *ncp, *tcp;
	
	for (cp = gecos; *cp; ) {
		/* Skip past punctuation */
		for (; *cp; cp++)
			if (isalnum((int) *cp))
				break;
		/* Skip to the end of the word */
		for (ncp = cp; *ncp; ncp++)
			if (!isalnum((int) *ncp) && *ncp != '\'')
				break;
		/* Delimit end of word */
		if (*ncp)
			*ncp++ = '\0';
		/* Check word to see if it's the password */
		if (*cp) {
			if (check_pw(newpw, cp))
				return(KADM_INSECURE_PW);
			tcp = reverse(cp);
			if (check_pw(newpw, tcp))
				return(KADM_INSECURE_PW);
			if (lower(cp)) {
				if (check_pw(newpw, cp))
					return(KADM_INSECURE_PW);
				tcp = reverse(cp);
				if (check_pw(newpw, tcp))
					return(KADM_INSECURE_PW);
			}
			cp = ncp;				
		} else
			break;
	}
	return(0);
}

static int
str_check_gecos(gecos, pwstr)
	char	*gecos;
	char	*pwstr;
{
	char		*cp, *ncp, *tcp;
	
	for (cp = gecos; *cp; ) {
		/* Skip past punctuation */
		for (; *cp; cp++)
			if (isalnum((int) *cp))
				break;
		/* Skip to the end of the word */
		for (ncp = cp; *ncp; ncp++)
			if (!isalnum((int) *ncp) && *ncp != '\'')
				break;
		/* Delimit end of word */
		if (*ncp)
			*ncp++ = '\0';
		/* Check word to see if it's the password */
		if (*cp) {
			if (!strcasecmp(pwstr, cp))
				return(KADM_INSECURE_PW);
			tcp = reverse(cp);
			if (!strcasecmp(pwstr, tcp))
				return(KADM_INSECURE_PW);
			cp = ncp;				
		} else
			break;
	}
	return(0);
}


krb5_error_code
kadm_approve_pw(rname, rinstance, rrealm, newpw, pwstring)
char *rname;
char *rinstance;
char *rrealm;
des_cblock newpw;
char *pwstring;
{
	int		retval;
#if NDBM_PW_CHECK
	static DBM *pwfile = NULL;
	datum		passwd, entry;
#endif
	struct passwd	*ent;
#ifdef HESIOD
	extern struct passwd *hes_getpwnam();
#endif
	
	if (pwstring && !check_pw(newpw, pwstring))
		/*
		 * Someone's trying to toy with us....
		 */
		return(KADM_PW_MISMATCH);
	if (pwstring && (strlen(pwstring) < 5))
		return(KADM_INSECURE_PW);
#if NDBM_PW_CHECK
	if (!pwfile) {
		pwfile = dbm_open(PW_CHECK_FILE, O_RDONLY, 0644);
	}
	if (pwfile) {
		passwd.dptr = (char *) newpw;
		passwd.dsize = 8;
		entry = dbm_fetch(pwfile, passwd);
		if (entry.dptr)
			return(KADM_INSECURE_PW);
	}
#endif
	if (check_pw(newpw, rname) || check_pw(newpw, reverse(rname)))
		return(KADM_INSECURE_PW);
#ifdef HESIOD
	ent = hes_getpwnam(rname);
#else
	ent = getpwnam(rname);
#endif
	if (ent && ent->pw_gecos) {
		if (pwstring)
			retval = str_check_gecos(ent->pw_gecos, pwstring);
		else
			retval = des_check_gecos(ent->pw_gecos, newpw);
		if (retval)
			return(retval);
	}
	return(0);
}

/*
 * This routine checks to see if a principal should be considered an
 * allowable service name which can be changed by kadm_change_srvtab.
 *
 * We do this check by using the ACL library.  This makes the
 * (relatively) reasonable assumption that both the name and the
 * instance will  not contain '.' or '@'. 
 */
static int kadm_check_srvtab(name, instance)
	char	*name;
	char	*instance;
{
	char filename[MAXPATHLEN];
	extern char *acldir;

	(void) sprintf(filename, "%s%s", acldir, STAB_SERVICES_FILE);
	if (!acl_check(filename, name))
		return(KADM_NOT_SERV_PRINC);

	(void) sprintf(filename, "%s%s", acldir, STAB_HOSTS_FILE);
	if (acl_check(filename, instance))
		return(KADM_NOT_SERV_PRINC);
	return 0;
}

/*
 * This works around a bug in kadm5, since kadm5_free_key_data() is
 * actually not implemented.  It abuses the knowledge that it's safe
 * to call free() on the keyblocks allocated by
 * kadm5_randkey_principal().
 */
static void free_keyblocks(context, keyblocks, nkeys)
    krb5_context context;
    krb5_keyblock *keyblocks;
    int nkeys;
{
    int i;
    for (i = 0; i < nkeys; i++) {
	krb5_free_keyblock_contents(context, &keyblocks[i]);
    }
    free(keyblocks);
}

/*
 * Routine to allow some people to change the key of a srvtab
 * principal to a random key, which the admin server will return to
 * the client.
 */
krb5_error_code
kadm_chg_srvtab(rname, rinstance, rrealm, values)
    char *rname;		/* requestors name */
    char *rinstance;		/* requestors instance */
    char *rrealm;		/* requestors realm */
    Kadm_vals *values;
{
    int isnew;
    krb5_principal inprinc;
    krb5_error_code retval;
    krb5_keyblock *keyblocks;
    int nkeys, i;
    kadm5_principal_ent_rec princ_ent;

    memset(&princ_ent, 0, sizeof (princ_ent)); /* XXX */

    if (!check_access(rname, rinstance, rrealm, STABACL)) {
	retval = (krb5_error_code) KADM_UNAUTH;
	goto err;
    }
    if (wildcard(rname) || wildcard(rinstance)) {
	retval = (krb5_error_code) KADM_ILL_WILDCARD;
	goto err;
    }
    retval = (krb5_error_code) kadm_check_srvtab(values->name,
						 values->instance);
    if (retval)
	goto err;

    retval = krb5_425_conv_principal(kadm_context, values->name,
				     values->instance,
				     server_parm.krbrlm, &inprinc);
    if (retval)
	goto err;
    /*
     * OK, get the entry, and create it if it doesn't exist.
     */
    retval = kadm5_get_principal(kadm5_handle, inprinc, &princ_ent,
				 KADM5_PRINCIPAL_NORMAL_MASK);
    switch (retval) {
    case KADM5_UNK_PRINC:
	isnew = 1;
	retval = krb5_copy_principal(kadm_context, inprinc,
				     &princ_ent.principal);
	if (retval)
	    goto err_princ;

	princ_ent.attributes = KRB5_KDB_DISALLOW_ALL_TIX;

	retval = kadm5_create_principal(kadm5_handle, &princ_ent,
					KADM5_PRINCIPAL|KADM5_ATTRIBUTES,
					dummypw());
	if (retval)
	    goto err_princ_ent;
	break;
    case 0:
	isnew = 0;
	break;
    default:
	goto err_princ;
	break;
    }

    /* randomize */
    retval = kadm5_randkey_principal(kadm5_handle, inprinc,
				     &keyblocks, &nkeys);
    if (retval) {
	if (isnew)
	    goto err_princ_ent;
	else
	    goto err_princ;
    }

    if (isnew) {
	/* Allow tickets now, if we just created this principal. */
	princ_ent.attributes &= ~KRB5_KDB_DISALLOW_ALL_TIX;
	retval = kadm5_modify_principal(kadm5_handle, &princ_ent,
					KADM5_ATTRIBUTES);
	kadm5_free_principal_ent(kadm5_handle, &princ_ent);
	if (retval)
	    goto err_princ;
    }

    for (i = 0; i < nkeys; i++) {
	/*
	 * XXX kadm5_randkey_principal() doesn't actually generate
	 * multiple keys for the DES_CBC_* enctypes; rather it makes
	 * them all DES_CBC_CRC, thus preventing a service from using
	 * DES_CBC_MD5, or something.
	 */
	if (keyblocks[i].enctype == ENCTYPE_DES_CBC_CRC)
	    break;
    }
    if (i == nkeys) {
	krb5_free_principal(kadm_context, inprinc);
	free_keyblocks(kadm_context, keyblocks, nkeys);
	syslog(LOG_ERR, "change_srvtab: DES_CBC_CRC key not found");
	return(KADM_NOENTRY);	/* XXX not quite accurate */
    }
    if (keyblocks[i].length != 8) {
	krb5_free_principal(kadm_context, inprinc);
	free_keyblocks(kadm_context, keyblocks, nkeys);
	syslog(LOG_ERR, "change_srvtab: bad length for DES_CBC_CRC key");
	return(KADM_NOENTRY);	/* XXX not quite accruate */
    }

    /*
     * Set up return values.
     */
    memcpy((char *)&values->key_low, keyblocks[i].contents, 4);
    memcpy((char *)&values->key_high, keyblocks[i].contents + 4, 4);
    values->key_low = htonl(values->key_low);
    values->key_high = htonl(values->key_high);
    free_keyblocks(kadm_context, keyblocks, nkeys);
    retval = kadm5_get_principal(kadm5_handle, inprinc, &princ_ent,
				 KADM5_PRINCIPAL_NORMAL_MASK);
    if (retval)
	goto err_princ;

    values->exp_date = princ_ent.princ_expire_time;
    values->max_life = princ_ent.kvno; /* XXX kludge for backwards compat */
    memset(values->fields, 0, sizeof(values->fields));
    SET_FIELD(KADM_NAME, values->fields);
    SET_FIELD(KADM_INST, values->fields);
    SET_FIELD(KADM_EXPDATE, values->fields);
#if 0
    SET_FIELD(KADM_ATTR, values->fields); /* XXX should we be doing this? */
#endif
    SET_FIELD(KADM_MAXLIFE, values->fields);
    SET_FIELD(KADM_DESKEY, values->fields);

    kadm5_free_principal_ent(kadm5_handle, &princ_ent);
    krb5_free_principal(kadm_context, inprinc);

    syslog(LOG_INFO, "change_srvtab: service '%s.%s' %s by %s.%s@%s.",
	   values->name, values->instance,
	   isnew ? "created" : "changed",
	   rname, rinstance, rrealm);
    return KADM_DATA;

err_princ_ent:
    kadm5_free_principal_ent(kadm5_handle, &princ_ent);
err_princ:
    krb5_free_principal(kadm_context, inprinc);
err:
    syslog(LOG_ERR,
	   "change_srvtab: FAILED changing '%s.%s' by '%s.%s@%s' (%s)",
	   values->name, values->instance,
	   rname, rinstance, rrealm, error_message(retval));
    return retval;
}
