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

static int add_principal(void *handle, char *keytab_str, krb5_keytab keytab,
			 char *princ_str);
static int remove_principal(char *keytab_str, krb5_keytab keytab, char
			    *princ_str, char *kvno_str);
static char *etype_string(krb5_enctype enctype);

extern char *krb5_defkeyname;	 
extern char *whoami;
extern krb5_context context;
extern void *handle;
static int quiet;

void add_usage()
{
     fprintf(stderr, "Usage: ktadd [-k[eytab] keytab] [-q] [principal | -glob princ-exp] [...]\n");
}
     
void rem_usage()
{
     fprintf(stderr, "Usage: ktremove [-k[eytab] keytab] [-q] principal [kvno|\"all\"|\"old\"]\n");
}

int process_keytab(krb5_context context, char **keytab_str,
		   krb5_keytab *keytab) 
{
     int code;
     
     if (*keytab_str == NULL) {
	  if (! (*keytab_str = strdup(krb5_defkeyname))) {
	       com_err(whoami, ENOMEM, "while creating keytab name");
	       return 1;
	  }
	  code = krb5_kt_default(context, keytab);
	  if (code != 0) {
	       com_err(whoami, code, "while opening default keytab");
	       free(*keytab_str);
	       return 1;
	  }
     } else {
	  if (strchr(*keytab_str, ':') != NULL) {
	       *keytab_str = strdup(*keytab_str);
	       if (*keytab_str == NULL) {
		    com_err(whoami, ENOMEM, "while creating keytab name");
		    return 1;
	       }
	  } else {
	       char *tmp = *keytab_str;

	       *keytab_str = (char *)
		    malloc(strlen("WRFILE:")+strlen(tmp)+1);
	       if (*keytab_str == NULL) {
		    com_err(whoami, ENOMEM, "while creating keytab name");
		    return 1;
	       }
	       sprintf(*keytab_str, "WRFILE:%s", tmp);
	  }
	  
	  code = krb5_kt_resolve(context, *keytab_str, keytab);
	  if (code != 0) {
	       com_err(whoami, code, "while resolving keytab %s", *keytab_str);
	       free(keytab_str);
	       return 1;
	  }
     }
     
     return 0;
}

     
void kadmin_keytab_add(int argc, char **argv)
{
     krb5_keytab keytab = 0;
     char *princ_str, *keytab_str = NULL, **princs;
     int code, num, i;

     argc--; argv++;
     while (argc) {
	  if (strncmp(*argv, "-k", 2) == 0) {
	       argc--; argv++;
	       if (!argc || keytab_str) {
		    add_usage();
		    return;
	       }
	       keytab_str = *argv;
	  } else if (strcmp(*argv, "-q") == 0) {
	       quiet++;
	  } else
	       break;
	  argc--; argv++;
     }

     if (argc == 0) {
	  add_usage();
	  return;
     }

     if (process_keytab(context, &keytab_str, &keytab))
	  return;
     
     while (*argv) {
	  if (strcmp(*argv, "-glob") == 0) {
	       if (*++argv == NULL) {
		    add_usage();
		    break;
	       }
	       
	       if (code = kadm5_get_principals(handle, *argv, &princs, &num)) {
		    com_err(whoami, code, "while expanding expression \"%s\".",
			    *argv);
		    argv++;
		    continue;
	       }
	       
	       for (i = 0; i < num; i++) 
		    (void) add_principal(handle, keytab_str, keytab,
					 princs[i]); 
	       kadm5_free_name_list(handle, princs, num);
	  } else
	       (void) add_principal(handle, keytab_str, keytab, *argv);
	  argv++;
     }
	  
     code = krb5_kt_close(context, keytab);
     if (code != 0)
	  com_err(whoami, code, "while closing keytab");

     free(keytab_str);
}

void kadmin_keytab_remove(int argc, char **argv)
{
     krb5_keytab keytab = 0;
     char *princ_str, *keytab_str = NULL;
     int code;

     argc--; argv++;
     while (argc) {
	  if (strncmp(*argv, "-k", 2) == 0) {
	       argc--; argv++;
	       if (!argc || keytab_str) {
		    rem_usage();
		    return;
	       }
	       keytab_str = *argv;
	  } else if (strcmp(*argv, "-q") == 0) {
	       quiet++;
	  } else
	       break;
	  argc--; argv++;
     }

     if (argc != 1 && argc != 2) {
	  rem_usage();
	  return;
     }
     if (process_keytab(context, &keytab_str, &keytab))
	  return;

     (void) remove_principal(keytab_str, keytab, argv[0], argv[1]);

     code = krb5_kt_close(context, keytab);
     if (code != 0)
	  com_err(whoami, code, "while closing keytab");

     free(keytab_str);
}

int add_principal(void *handle, char *keytab_str, krb5_keytab keytab,
		  char *princ_str) 
{
     kadm5_principal_ent_rec princ_rec;
     krb5_principal princ;
     krb5_keytab_entry new_entry;
     krb5_keyblock *keys;
     int code, code2, mask, nkeys, i;

     (void) memset((char *)&princ_rec, 0, sizeof(princ_rec));

     princ = NULL;
     keys = NULL;
     nkeys = 0;

     code = krb5_parse_name(context, princ_str, &princ);
     if (code != 0) {
	  com_err(whoami, code, "while parsing -add principal name %s",
		  princ_str);
	  goto cleanup;
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
     if (nkeys) {
	  for (i = 0; i < nkeys; i++)
	       krb5_free_keyblock_contents(context, &keys[i]);
	  free(keys);
     }
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
