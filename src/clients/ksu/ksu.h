/* 
 * Copyright (c) 1994 by the University of Southern California
 *
 * EXPORT OF THIS SOFTWARE from the United States of America may
 *     require a specific license from the United States Government.
 *     It is the responsibility of any person or organization contemplating
 *     export to obtain such a license before exporting.
 *
 * WITHIN THAT CONSTRAINT, permission to copy, modify, and distribute
 *     this software and its documentation in source and binary forms is
 *     hereby granted, provided that any documentation or other materials
 *     related to such distribution or use acknowledge that the software
 *     was developed by the University of Southern California. 
 *
 * DISCLAIMER OF WARRANTY.  THIS SOFTWARE IS PROVIDED "AS IS".  The
 *     University of Southern California MAKES NO REPRESENTATIONS OR
 *     WARRANTIES, EXPRESS OR IMPLIED.  By way of example, but not
 *     limitation, the University of Southern California MAKES NO
 *     REPRESENTATIONS OR WARRANTIES OF MERCHANTABILITY OR FITNESS FOR ANY
 *     PARTICULAR PURPOSE. The University of Southern
 *     California shall not be held liable for any liability nor for any
 *     direct, indirect, or consequential damages with respect to any
 *     claim by the user or distributor of the ksu software.
 *
 * KSU was writen by:  Ari Medvinsky, ari@isi.edu
 */

#include <krb5/krb5.h>
#include <krb5/asn1.h>
#include <krb5/ext-proto.h>
#include <krb5/los-proto.h>
#include <krb5/dbm.h>

#include <krb5/osconf.h>
#include <krb5/sysincl.h>
#include <stdio.h>
#include <com_err.h>
#include <sys/types.h> 
#include <sys/param.h>
#include <pwd.h>
#include <unistd.h>
#include <string.h>
#include <syslog.h>

#define NO_TARGET_FILE '.'

#define KRB5_DEFAULT_OPTIONS 0
#define KRB5_DEFAULT_TKT_LIFE 60*60*8 /* 8 hours */

#define KRB5_SECONDARY_CACHE "FILE:/tmp/krb5cc_"

#define KRB5_LOGIN_NAME ".k5login"
#define KRB5_USERS_NAME ".k5users"
#define USE_DEFAULT_REALM_NAME "."
#define PERMIT_ALL_COMMANDS "*" 
#define KRB5_SEC_BUFFSIZE 80
#define NOT_AUTHORIZED 1

#define CHUNK 3
#define CACHE_MODE 0600
#define MAX_CMD 2048 /* this is temp, should use realloc instead,          
			as done in most of the code */       
		      

extern int optind;
extern char * optarg;

/* globals */
extern char * prog_name;
extern int auth_debug;
extern char k5login_path[MAXPATHLEN];
extern char k5users_path[MAXPATHLEN];
extern char * gb_err;
/***********/

typedef struct opt_info{
	int opt;
	long lifetime;
	long rlife;
	int princ;
}opt_info;

extern krb5_boolean krb5_auth_check();
extern krb5_error_code get_best_principal();
extern void dump_principal ();
extern krb5_error_code krb5_verify_tkt_def();
extern krb5_boolean krb5_fast_auth();
extern krb5_boolean krb5_get_tkt_via_passwd ();
extern int gen_sim();  
extern krb5_error_code krb5_authorization();     
extern krb5_error_code k5login_lookup ();
extern krb5_error_code k5users_lookup ();
extern krb5_error_code get_line ();
extern char *  get_first_token ();
extern char *  get_next_token ();
extern krb5_boolean fowner();

#ifndef min
#define min(a,b) ((a) > (b) ? (b) : (a))
#endif /* min */


extern char *krb5_lname_file;  /* Note: print this out just be sure
				  that it gets set */   	    


