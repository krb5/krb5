/*
 * admin/edit/dumpv4.c
 *
 * Copyright 1990,1991, 1994 by the Massachusetts Institute of Technology.
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
 *
 * Dump a KDC database into a V4 slave dump.
 */

#ifdef KRB5_KRB4_COMPAT

#include "k5-int.h"
#include "com_err.h"

#include <des.h>
#include <krb.h>
#ifdef HAVE_KRB_DB_H
#include <krb_db.h>
#endif /*HAVE_KRB_DB_H*/
#ifdef HAVE_KDC_H
;/* MKEYFILE is now defined in kdc.h */
#include <kdc.h>
#endif /*HAVE_KDC_H*/
#include <stdio.h>
#include <kadm5/admin.h>
#include "kdb5_util.h"

struct dump_record {
	char	*comerr_name;
	FILE	*f;
	krb5_encrypt_block *v5master;
	C_Block		v4_master_key;
	Key_schedule	v4_master_key_schedule;
	long	master_key_version;
	char	*realm;
};

extern krb5_encrypt_block master_encblock;
extern krb5_keyblock master_keyblock;
extern krb5_principal master_princ;
extern krb5_boolean dbactive;
extern int exit_status;
extern krb5_context util_context;
extern kadm5_config_params global_params;

void update_ok_file();

#define ANAME_SZ 40
#define INST_SZ 40

static char *v4_mkeyfile = "/.k";

static int
v4init(arg, manual)
    struct dump_record *arg;
    int manual;
{
    int fd;
    int ok = 0;

    if (!manual) {
	fd = open(v4_mkeyfile, O_RDONLY, 0600);
	if (fd >= 0) {
	    if (read(fd,arg->v4_master_key,sizeof(C_Block)) == sizeof(C_Block))
		ok = 1;
	    close(fd);
	}
    }
    if (!ok) {
	des_read_password(arg->v4_master_key, "V4 Kerberos master key: ", 1);
	printf("\n");
    }
    arg->master_key_version = 1;
    key_sched(arg->v4_master_key, arg->v4_master_key_schedule);

    return 0;
}

v4_print_time(file, timeval)
    FILE   *file;
    unsigned long timeval;
{
    struct tm *tm;
    struct tm *gmtime();
    tm = gmtime((time_t *)&timeval);
    fprintf(file, " %04d%02d%02d%02d%02d",
            tm->tm_year < 1900 ? tm->tm_year + 1900: tm->tm_year,
            tm->tm_mon + 1,
            tm->tm_mday,
            tm->tm_hour,
            tm->tm_min);
}



krb5_error_code
dump_v4_iterator(ptr, entry)
    krb5_pointer ptr;
    krb5_db_entry *entry;
{
    struct dump_record *arg = (struct dump_record *) ptr;
    krb5_principal mod_princ;
    krb5_timestamp mod_time;
    krb5_error_code retval;
    int	i, max_kvno, ok_key;

    struct v4princ {
	char name[ANAME_SZ+1];
	char instance[INST_SZ+1];
	char realm[REALM_SZ+1];
	int max_life;
	int kdc_key_ver, key_version, attributes;
	char mod_name[ANAME_SZ+1];
	char mod_instance[INST_SZ+1];
	char mod_realm[REALM_SZ+1];
    } v4princ, *principal;
    des_cblock v4key;
    
    principal = &v4princ;

    if (strcmp(krb5_princ_realm(util_context, entry->princ)->data, arg->realm))
	/* skip this because it's a key for a different realm, probably
	 * a paired krbtgt key */
	return 0;

    retval = krb5_524_conv_principal(util_context, entry->princ,
				     principal->name, principal->instance,
				     principal->realm);
    if (retval)
	/* Skip invalid V4 principals */
	return 0;

    if (!strcmp(principal->name, "K") && !strcmp(principal->instance, "M"))
	/* The V4 master key is handled specially */
	return 0;

    if (! principal->name[0])
	return 0;
    if (! principal->instance[0])
	strcpy(principal->instance, "*");

    /* Now move to mod princ */
    if (retval = krb5_dbe_lookup_mod_princ_data(util_context,entry,
						&mod_time, &mod_princ)){
	com_err(arg->comerr_name, retval, "while unparsing db entry");
	exit_status++;
	return retval;
    }
    retval = krb5_524_conv_principal(util_context, mod_princ,
				     principal->mod_name, principal->mod_instance,
				     principal->mod_realm);
    if (retval) {
	/* Invalid V4 mod principal */
	principal->mod_name[0] = '\0';
	principal->mod_instance[0] = '\0';
    }

    if (! principal->mod_name[0])
	strcpy(principal->mod_name, "*");
    if (! principal->mod_instance[0])
	strcpy(principal->mod_instance, "*");
    
    /* OK deal with the key now. */
    for (max_kvno = i = 0; i < entry->n_key_data; i++) {
	if (max_kvno < entry->key_data[i].key_data_kvno) {
	     max_kvno = entry->key_data[i].key_data_kvno;
	     ok_key = i;
	}
    }

    i = ok_key;
    while (ok_key < entry->n_key_data) {
	if (max_kvno == entry->key_data[ok_key].key_data_kvno) {
	    if (entry->key_data[ok_key].key_data_type[1]
		== KRB5_KDB_SALTTYPE_V4) {
		goto found_one;
	    }
	}
	ok_key++;
    }

    /* See if there are any DES keys that may be suitable */
    ok_key = i;
    while (ok_key < entry->n_key_data) {
	if (max_kvno == entry->key_data[ok_key].key_data_kvno) {
	    krb5_enctype enctype = entry->key_data[ok_key].key_data_type[0];
	    if ((enctype == ENCTYPE_DES_CBC_CRC) ||
		(enctype == ENCTYPE_DES_CBC_MD5) ||
		(enctype == ENCTYPE_DES_CBC_RAW))
		goto found_one;
	}
	ok_key++;
    }
    /* skip this because it's a new style key and we can't help it */
    return 0;

found_one:;
    principal->key_version = max_kvno;
    if ((principal->max_life = entry->max_life / (60 * 5)) > 255)
	principal->max_life = 255;
    principal->kdc_key_ver = arg->master_key_version;
    principal->attributes = 0;	/* ??? not preserved either */

    fprintf(arg->f, "%s %s %d %d %d %d ",
	    principal->name,
	    principal->instance,
	    principal->max_life,
	    principal->kdc_key_ver,
	    principal->key_version,
	    principal->attributes);

    handle_one_key(arg, arg->v5master, &entry->key_data[ok_key], v4key);

    for (i = 0; i < 8; i++) {
	fprintf(arg->f, "%02x", ((unsigned char*)v4key)[i]);
	if (i == 3) fputc(' ', arg->f);
    }

    v4_print_time(arg->f, entry->expiration);
    v4_print_time(arg->f, mod_time);

    fprintf(arg->f, " %s %s\n", principal->mod_name, principal->mod_instance);
    return 0;
}

/*ARGSUSED*/
void dump_v4db(argc, argv)
	int	argc;
	char	**argv;
{
	FILE	*f;
	struct dump_record	arg;
	
	if (argc > 2) {
		com_err(argv[0], 0, "Usage: %s filename", argv[0]);
		exit_status++;
		return;
	}
	if (!dbactive) {
		com_err(argv[0], 0, Err_no_database);
		exit_status++;
		return;
	}
	if (argc == 2) {
		/*
		 * Make sure that we don't open and truncate on the fopen,
		 * since that may hose an on-going kprop process.
		 * 
		 * We could also control this by opening for read and
		 * write, doing an flock with LOCK_EX, and then
		 * truncating the file once we have gotten the lock,
		 * but that would involve more OS dependancies than I
		 * want to get into.
		 */
		unlink(argv[1]);
		if (!(f = fopen(argv[1], "w"))) {
			com_err(argv[0], errno,
				"While opening file %s for writing", argv[1]);
			exit_status++;
			return;
		}
	} else {
		f = stdout;
	}

	arg.comerr_name = argv[0];
	arg.f = f;
	v4init(&arg, 0);
	handle_keys(&arg);

	/* special handling for K.M since it isn't preserved */
	{
	  des_cblock v4key;
	  int i;

	  /* assume:
	     max lifetime (255)
	     key version == 1 (actually, should be whatever the v5 one is)
	     master key version == key version
	     args == 0 (none are preserved)
	     expiration date is the default 2000
	     last mod time is near zero (arbitrarily.)
	     creator is db_creation *
	     */

	  fprintf(f,"K M 255 1 1 0 ");
	  
#ifndef	KDB4_DISABLE
	  kdb_encrypt_key (arg.v4_master_key, v4key, 
			   arg.v4_master_key, arg.v4_master_key_schedule, 
			   ENCRYPT);
#else	/* KDB4_DISABLE */
	  pcbc_encrypt((C_Block *) arg.v4_master_key,
		       (C_Block *) v4key,
		       (long) sizeof(C_Block),
		       arg.v4_master_key_schedule,
		       (C_Block *) arg.v4_master_key,
		       ENCRYPT);
#endif	/* KDB4_DISABLE */

	  for (i=0; i<8; i++) {
	    fprintf(f, "%02x", ((unsigned char*)v4key)[i]);
	    if (i == 3) fputc(' ', f);
	  }
	  fprintf(f," 200001010459 197001020000 db_creation *\n");
	}

	(void) krb5_db_iterate(util_context, dump_v4_iterator, 
			       (krb5_pointer) &arg);
	if (argc == 2)
		fclose(f);
	if (argv[1])
		update_ok_file(argv[1]);
}

int handle_keys(arg)
    struct dump_record *arg;
{
    krb5_error_code retval;
    char *defrealm;
    char *mkey_name = 0;
    char *mkey_fullname;
    krb5_principal master_princ;

    if (retval = krb5_get_default_realm(util_context, &defrealm)) {
      com_err(arg->comerr_name, retval, 
	      "while retrieving default realm name");
      exit(1);
    }	    
    arg->realm = defrealm;

    /* assemble & parse the master key name */

    if (retval = krb5_db_setup_mkey_name(util_context, mkey_name, arg->realm, 
					 &mkey_fullname, &master_princ)) {
	com_err(arg->comerr_name, retval, "while setting up master key name");
	exit(1);
    }

    krb5_use_enctype(util_context, &master_encblock, DEFAULT_KDC_ENCTYPE);
    if (retval = krb5_db_fetch_mkey(util_context, master_princ, 
				    &master_encblock, 0,
				    0, global_params.stash_file, 0,
				    &master_keyblock)) { 
	com_err(arg->comerr_name, retval, "while reading master key");
	exit(1);
    }
    if (retval = krb5_process_key(util_context, &master_encblock, 
				    &master_keyblock)) {
	com_err(arg->comerr_name, retval, "while processing master key");
	exit(1);
    }
    arg->v5master = &master_encblock;
    return(0);
}

handle_one_key(arg, v5master, v5key, v4key)
    struct dump_record *arg;
    krb5_encrypt_block *v5master;
    krb5_key_data *v5key;
    des_cblock v4key;
{
    krb5_error_code retval;

    krb5_keyblock v4v5key;
    krb5_keyblock v5plainkey;
    /* v4key is the actual v4 key from the file. */

    if (retval = krb5_dbekd_decrypt_key_data(util_context, v5master, v5key, 
				             &v5plainkey, NULL)) 
	return retval;

    /* v4v5key.contents = (krb5_octet *)v4key; */
    /* v4v5key.enctype = ENCTYPE_DES; */
    /* v4v5key.length = sizeof(v4key); */

    memcpy(v4key, v5plainkey.contents, sizeof(des_cblock));
#ifndef	KDB4_DISABLE
    kdb_encrypt_key (v4key, v4key, 
		     arg->v4_master_key, arg->v4_master_key_schedule, 
		     ENCRYPT);
#else	/* KDB4_DISABLE */
    pcbc_encrypt((C_Block *) v4key,
		 (C_Block *) v4key,
		 (long) sizeof(C_Block),
		 arg->v4_master_key_schedule,
		 (C_Block *) arg->v4_master_key,
		 ENCRYPT);
#endif	/* KDB4_DISABLE */
    return 0;
}

#else /* KRB5_KRB4_COMPAT */
void dump_v4db(argc, argv)
	int	argc;
	char	**argv;
{
	printf("This version of krb5_edit does not support the V4 dump command.\n");
}
#endif /* KRB5_KRB4_COMPAT */
