/*
 * Copyright 1993 OpenVision Technologies, Inc., All Rights Reserved.
 *
 * $Id$
 * $Source$
 */

#if !defined(lint) && !defined(__CODECENTER__)
static char *rcsid = "$Header$";
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <krb5.h>
#include <k5-int.h>
#include <kadm5/admin.h>

int add_principal(char *keytab_str, krb5_keytab keytab, char *me_str,
		   char *princ_str, int create);
int remove_principal(char *keytab_str, krb5_keytab keytab, char
		     *princ_str, char *kvno_str);
static char *etype_string(krb5_enctype enctype);

krb5_context context;
char *whoami;
int quiet;

void usage()
{
     fprintf(stderr, "Usage: ovsec_edit_keytab [-k[eytab] keytab] [-q] cmd\n");
     fprintf(stderr, "  cmds are:\t-a[dd] [-c[reate] [-p principal] principal\n");
     fprintf(stderr, "\t\t-c[hange] [-p principal] principal\n");
     fprintf(stderr, "\t\t-r[emove] principal [kvno|\"all\"|\"old\"]\n");
     exit(1);
}
     
main(int argc0, char **argv0)
{
     extern krb5_kt_ops krb5_ktf_writable_ops;
     krb5_keytab keytab = 0;
     char *me_str, *princ_str, *keytab_str, *kvno_str;
     char keytab_buf[1024];
     int argc, code, did_something, create;
     char **argv;

     whoami = strrchr(argv0[0], '/') ? strrchr(argv0[0], '/') + 1 : argv0[0];

     if (code = krb5_init_context(&context)) {
	  com_err(whoami, code, "while initializing krb5 context");
	  exit(1);
     }
     
     krb5_init_ets(context);

     /* register the WRFILE keytab type and set it as the default */
     if (code = krb5_kt_register(context, &krb5_ktf_writable_ops)) {
	  com_err(whoami, code,
		  "while registering writable key table functions");
	  exit(1);
     }

     /* process non-action arguments first */
     argc = argc0-1;
     argv = argv0+1;
     while (argc) {
	  if (strncmp(*argv, "-k", 2) == 0) {
	       argc--; argv++;
	       if (!argc) usage();

	       if (keytab == NULL) {
		    if (strchr(*argv, ':') != NULL) {
			 keytab_str = strdup(*argv);
			 if (keytab_str == NULL) {
			      com_err(whoami, ENOMEM,
				      "while creating keytab name");
			      exit(1);
			 }
		    } else {
			 keytab_str = (char *)
			      malloc(strlen("WRFILE:")+strlen(*argv)+1);
			 if (keytab_str == NULL) {
			      com_err(whoami, ENOMEM,
				      "while creating keytab name");
			      exit(1);
			 }
			 sprintf(keytab_str, "WRFILE:%s", *argv);
		    }
		    
		    code = krb5_kt_resolve(context, keytab_str, &keytab);
		    if (code != 0) {
			 com_err(whoami, code, "while resolving keytab %s", 
				 keytab_str);
			 exit(1);
		    }
	       } else {
		    usage();
	       }
	  } else if (strcmp(*argv, "-q") == 0) {
	       quiet++;
	  }
	  /* otherwise ignore the argument, for now */
	  argc--; argv++;
     }

     if (keytab == NULL) {
	  code = krb5_kt_default(context, &keytab);
	  if (code != 0) {
	       com_err(whoami, code, "while opening default keytab");
	       exit(1);
	  }
	  code = krb5_kt_get_name(context, keytab,
				  keytab_buf, sizeof(keytab_buf));
	  keytab_str = keytab_buf;
     }

     argc = argc0-1;
     argv = argv0+1;

     did_something = 0;

     /* now process the action arguments */
     while (argc) {
	  if (strncmp(*argv, "-k", 2) == 0) {
	       /* if there is no keytab argument the previous loop */
	       /* would have called usage(), so just skip it */
	       argc--; argv++;
	  } else if (strcmp(*argv, "-q") == 0) {
	       /* skip it */
	  } else if (strncmp(*argv, "-a", 2) == 0 ||
		     strncmp(*argv, "-c", 2) == 0) {
	       did_something++;
	       
	       argc--; argv++;
	       if (!argc) usage();

	       me_str = NULL;
	       create = 0;
	       while (argc) {
		    if (strcmp(*argv, "-p") == 0) {
			 argc--; argv++;
			 if (argc < 1) usage();

			 me_str = *argv;
		    } else if (strncmp(*argv, "-c", 2) == 0) {
			 create++;
		    } else
			 break;
		    argc--; argv++;
	       }
	       if (argc != 1) usage();

	       code = add_principal(keytab_str, keytab, me_str ? me_str :
				    *argv, *argv, create);
	       break;
	  } else if (strncmp(*argv, "-r", 2) == 0) {
	       did_something++;
	       
	       argc--; argv++;
	       if (!argc) usage();
	       princ_str = *argv;
	       if (argc > 0) {
		    argc--;
		    argv++;
		    kvno_str = *argv;
	       } else
		    kvno_str = NULL;

	       code = remove_principal(keytab_str, keytab, princ_str,
				       kvno_str);
	       break;
	  } else {
	       fprintf(stderr, "%s: Unknown command line option %s.\n",
		       whoami, *argv);
	       usage();
	  }

	  argc--; argv++;
     }

     /* argv ends up pointing at the last recognized argument */
     if (!did_something || argc > 1)
	  usage();

     /* use argc as temp */
     argc = krb5_kt_close(context, keytab);
     if (argc != 0) {
	  com_err(whoami, argc, "while closing keytab");
	  code = argc;
     }

     free(keytab_str);

     return (code != 0);
}

int add_principal(char *keytab_str, krb5_keytab keytab, char *me_str,
		  char *princ_str, int create) 
{
     kadm5_principal_ent_rec princ_rec;
     krb5_principal me, princ;
     krb5_keytab_entry new_entry;
     krb5_keyblock *keys;
     void *handle;
     int code, code2, mask, nkeys, i;

     (void) memset((char *)&princ_rec, 0, sizeof(princ_rec));

     me = princ = NULL;
     handle = NULL;
     keys = NULL;
     nkeys = 0;

     code = krb5_parse_name(context, me_str, &me);
     if (code != 0) {
	  com_err(whoami, code, "while parsing -p principal name %s",
		  me_str);
	  goto cleanup;
     }

     code = krb5_parse_name(context, princ_str, &princ);
     if (code != 0) {
	  com_err(whoami, code, "while parsing -add principal name %s",
		  princ_str);
	  goto cleanup;
     }

     /* first try using the keytab */
     code = kadm5_init_with_skey(me_str, keytab_str,
				 KADM5_ADMIN_SERVICE,
				 NULL, /* default configuration */
				 KADM5_STRUCT_VERSION,
				 KADM5_API_VERSION_2, &handle);
     if (code != 0) {
	  /* KRB5_KT_NOTFOUND and ENOENT are not "errors" because this */
	  /* program does not require the keytab entry to exist */
	  if (code != KRB5_KT_NOTFOUND && code != ENOENT) {
	       if (code == KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN)
		    fprintf(stderr, "%s: Principal %s does not exist.\n",
			    whoami, me_str);
	       else
		    com_err(whoami, code, "while authenticating as principal "
			    "%s from keytab", me_str);
	  }
	  
	  code2 = kadm5_init_with_password(me_str, NULL,
					   KADM5_ADMIN_SERVICE,
					   NULL,
					   KADM5_STRUCT_VERSION,
					   KADM5_API_VERSION_2,
					   &handle);
	  if (code2 != 0) {
	       if (code2 != code) /* don't dup error messages */ {
		    com_err(whoami, code2, "while authenticating as "
			    "principal %s from password", me_str);
	       }
	       goto cleanup;
	  }
     }

     if (create) {
	  /* always try to create and just ignore dup errors because it */
	  /* reduces duplicate code... and how often will this happen? */

	  /* be sure to create the principal with the secure sequence */
	  /* of events as specified in the functional spec */
	  
	  princ_rec.principal = princ;
	  princ_rec.attributes = KRB5_KDB_DISALLOW_ALL_TIX;
	  mask = KADM5_PRINCIPAL | KADM5_ATTRIBUTES;
	  code = kadm5_create_principal(handle, &princ_rec,
					     mask, "dummy");
	  if (code == KADM5_DUP) {
	       printf("%s: Principal %s already exists.\n",
		      whoami, princ_str);
	  } else if (code != 0) {
	       if (code == KADM5_AUTH_ADD) {
		    fprintf(stderr, "%s: Operation requires "
			    "``add'' and ``modify'' privileges while creating "
			    "principal.\n", whoami);
	       } else {
		    com_err(whoami, code, "while creating "
			    "principal %s.", princ_str);
	       }
	       goto cleanup;
	  } else if (!quiet)
	       printf("%s: Created principal %s.\n", whoami, princ_str);
     }
     
     code = kadm5_randkey_principal(handle, princ, &keys, &nkeys);
     if (code != 0) {
	  if (code == KADM5_UNK_PRINC) {
	       fprintf(stderr, "%s: Principal %s does not exist.\n",
		       whoami, princ_str);
	  } else
	       com_err(whoami, code, "while changing %s's key",
		       princ_str);
	  goto cleanup;
     }

     code = kadm5_get_principal(handle, princ, &princ_rec,
				KADM5_PRINCIPAL_NORMAL_MASK);
     if (code != 0) {
	  com_err(whoami, code, "while retrieving principal");
	  goto cleanup;
     }

     if (create) {
	  /* complete the secure principal-creation sequence */
	  princ_rec.attributes &= ~KRB5_KDB_DISALLOW_ALL_TIX;
	  mask = KADM5_ATTRIBUTES;
	  code = kadm5_modify_principal(handle, &princ_rec, mask);
	  if (code != 0) {
	       if (code == KADM5_AUTH_ADD) {
		    fprintf(stderr, "%s: Operation requires "
			    "``add'' and ``modify'' privileges while creating "
			    "principal.\n", whoami);
	       } else 
		    com_err(whoami, code, "while modifying newly created "
			    "principal");
	       (void) kadm5_free_principal_ent(handle, &princ_rec);
	       goto cleanup;
	  }
     }

     for (i = 0; i < nkeys; i++) {
	  memset((char *) &new_entry, 0, sizeof(new_entry));
	  new_entry.principal = princ;
	  new_entry.key = keys[i];
	  new_entry.vno = princ_rec.kvno;

	  code = krb5_kt_add_entry(context, keytab, &new_entry);
	  if (code != 0) {
	       com_err(whoami, code, "while adding key to keytab");
	       (void) kadm5_free_principal_ent(handle, &princ_rec);
	       goto cleanup;
	  }

	  if (!quiet)
	       printf("%s: Entry for principal %s with kvno %d, "
		      "encryption type %s added to keytab %s.\n",
		      whoami, princ_str, princ_rec.kvno,
		      etype_string(keys[i].enctype), keytab_str);
     }

     code = kadm5_free_principal_ent(handle, &princ_rec);
     if (code != 0) {
	  com_err(whoami, code, "while freeing principal entry");
	  goto cleanup;
     }

cleanup:
     if (handle) {
	  code2 = kadm5_destroy(handle);
	  if (code2 != 0) {
	       com_err(whoami, code2, "while closing admin server connection");
	  }
     }
     if (nkeys) {
	  for (i = 0; i < nkeys; i++)
	       krb5_free_keyblock(context, &keys[i]);
	  free(keys);
     }
     if (me)
	  krb5_free_principal(context, me);
     if (princ)
	  krb5_free_principal(context, princ);

     return code;
}

int remove_principal(char *keytab_str, krb5_keytab keytab, char
		     *princ_str, char *kvno_str)
{
     krb5_principal princ;
     krb5_keytab_entry entry;
     krb5_kt_cursor cursor;
     enum { UNDEF, SPEC, HIGH, ALL, OLD } mode;
     int code, kvno, did_something;

     code = krb5_parse_name(context, princ_str, &princ);
     if (code != 0) {
	  com_err(whoami, code, "while parsing principal name %s",
		  princ_str);
	  return code;
     }

     mode = UNDEF;
     if (kvno_str == NULL) {
	  mode = HIGH;
	  kvno = 0;
     } else if (strcmp(kvno_str, "all") == 0) {
	  mode = ALL;
	  kvno = 0;
     } else if (strcmp(kvno_str, "old") == 0) {
	  mode = OLD;
	  kvno = 0;
     } else {
	  mode = SPEC;
	  kvno = atoi(kvno_str);
     }

     /* kvno is set to specified value for SPEC, 0 otherwise */
     code = krb5_kt_get_entry(context, keytab, princ, kvno, 0, &entry);
     if (code != 0) {
	  if (code == ENOENT) {
	       fprintf(stderr, "%s: Keytab %s does not exist.\n",
		       whoami, keytab_str);
	  } else if (code == KRB5_KT_NOTFOUND) {
	       if (mode != SPEC)
		    fprintf(stderr, "%s: No entry for principal "
			    "%s exists in keytab %s\n",
			    whoami, princ_str, keytab_str);
	       else
		    fprintf(stderr, "%s: No entry for principal "
			    "%s with kvno %d exists in keytab "
			    "%s.\n", whoami, princ_str, kvno,
			    keytab_str);
	  } else {
	       com_err(whoami, code, "while retrieving highest kvno "
		       "from keytab");
	  }
	  return code;
     }

     /* set kvno to spec'ed value for SPEC, highest kvno otherwise */
     kvno = entry.vno;
     krb5_kt_free_entry(context, &entry);

     code = krb5_kt_start_seq_get(context, keytab, &cursor);
     if (code != 0) {
	  com_err(whoami, code, "while starting keytab scan");
	  return code;
     }

     did_something = 0;
     while ((code = krb5_kt_next_entry(context, keytab, &entry, &cursor)) == 0) {
	  if (krb5_principal_compare(context, princ, entry.principal) &&
	      ((mode == ALL) ||
	       (mode == SPEC && entry.vno == kvno) ||
	       (mode == OLD && entry.vno != kvno) ||
	       (mode == HIGH && entry.vno == kvno))) {

	       /*
		* Ack!  What a kludge... the scanning functions lock
		* the keytab so entries cannot be removed while they
		* are operating.
		*/
	       code = krb5_kt_end_seq_get(context, keytab, &cursor);
	       if (code != 0) {
		    com_err(whoami, code, "while temporarily ending "
			    "keytab scan");
		    return code;
	       }
	       code = krb5_kt_remove_entry(context, keytab, &entry);
	       if (code != 0) {
		    com_err(whoami, code, "while deleting entry from keytab");
		    return code;
	       }
	       code = krb5_kt_start_seq_get(context, keytab, &cursor);
	       if (code != 0) {
		    com_err(whoami, code, "while restarting keytab scan");
		    return code;
	       }

	       did_something++;
	       if (!quiet)
		    printf("%s: Entry for principal %s with kvno %d "
			   "removed from keytab %s.\n", whoami,
			   princ_str, entry.vno, keytab_str);
	  }
	  krb5_kt_free_entry(context, &entry);
     }
     if (code && code != KRB5_KT_END) {
	  com_err(whoami, code, "while scanning keytab");
	  return code;
     }
     if (code = krb5_kt_end_seq_get(context, keytab, &cursor)) {
	  com_err(whoami, code, "while ending keytab scan");
	  return code;
     }

     /*
      * If !did_someting then mode must be OLD or we would have
      * already returned with an error.  But check it anyway just to
      * prevent unexpected error messages...
      */
     if (!did_something && mode == OLD) {
	  fprintf(stderr, "%s: There is only one entry for principal "
		  "%s in keytab %s\n", whoami, princ_str, keytab_str);
	  return 1;
     }
     
     return 0;
}

/*
 * etype_string(enctype): return a string representation of the
 * encryption type.  XXX copied from klist.c; this should be a
 * library function, or perhaps just #defines
 */
static char *etype_string(enctype)
    krb5_enctype enctype;
{
    static char buf[12];
    
    switch (enctype) {
    case ENCTYPE_DES_CBC_CRC:
	return "DES-CBC-CRC";
	break;
    case ENCTYPE_DES_CBC_MD4:
	return "DES-CBC-MD4";
	break;
    case ENCTYPE_DES_CBC_MD5:
	return "DES-CBC-MD5";
	break;
#if 0
    case ENCTYPE_DES3_CBC_MD5:
	return "DES3-CBC-MD5";
	break;
#endif
    default:
	sprintf(buf, "etype %d", enctype);
	return buf;
	break;
    }
}
