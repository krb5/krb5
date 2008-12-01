/*
 * include/kerberosIV/krb_db.h
 *
 * Copyright 1987, 1988, 1994 by the Massachusetts Institute of Technology.
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
 * spm		Project Athena  8/85 
 *
 * This file defines data structures for the kerberos
 * authentication/authorization database. 
 *
 * They MUST correspond to those defined in *.rel 
 */

#ifndef KRB_DB_DEFS
#define KRB_DB_DEFS

#define KERB_M_NAME		"K"	/* Kerberos */
#define KERB_M_INST		"M"	/* Master */
#define KERB_DEFAULT_NAME	"default"
#define KERB_DEFAULT_INST	""
#define	DBM_FILE		"/kerberos/principal"

/* this also defines the number of queue headers */
#define KERB_DB_HASH_MODULO 64


/* Arguments to kerb_dbl_lock() */

#define KERB_DBL_EXCLUSIVE 1
#define KERB_DBL_SHARED 0

/* arguments to kerb_db_set_lockmode() */

#define KERB_DBL_BLOCKING 0
#define KERB_DBL_NONBLOCKING 1

/* Principal defines the structure of a principal's name */

typedef struct {
    char    name[ANAME_SZ];
    char    instance[INST_SZ];

    unsigned long key_low;
    unsigned long key_high;
    unsigned long exp_date;
    char    exp_date_txt[DATE_SZ];
    unsigned long mod_date;
    char    mod_date_txt[DATE_SZ];
    unsigned short attributes;
    unsigned char max_life;
    unsigned char kdc_key_ver;
    unsigned char key_version;

    char    mod_name[ANAME_SZ];
    char    mod_instance[INST_SZ];
    char   *old;		/* cast to (Principal *); not in db,
				 * ptr to old vals */
}
        Principal;

typedef struct {
    long    cpu;
    long    elapsed;
    long    dio;
    long    pfault;
    long    t_stamp;
    long    n_retrieve;
    long    n_replace;
    long    n_append;
    long    n_get_stat;
    long    n_put_stat;
}
        DB_stat;

/* Dba defines the structure of a database administrator */

typedef struct {
    char    name[ANAME_SZ];
    char    instance[INST_SZ];
    unsigned short attributes;
    unsigned long exp_date;
    char    exp_date_txt[DATE_SZ];
    char   *old;	/*
			 * cast to (Dba *); not in db, ptr to
			 * old vals
			 */
}
        Dba;

#if 0
extern int kerb_get_principal();
extern int kerb_put_principal();
extern int kerb_db_get_stat();
extern int kerb_db_put_stat();
extern int kerb_get_dba();
extern int kerb_db_get_dba();
#endif

#endif /* KRB_DB_DEFS */
