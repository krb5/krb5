/*
 * lib/krb5/krb/conv_princ.c
 *
 * Copyright 1992 by the Massachusetts Institute of Technology.
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
 * Build a principal from a V4 specification, or separate a V5
 * principal into name, instance, and realm.
 * 
 * NOTE: This is highly site specific, and is only really necessary
 * for sites who need to convert from V4 to V5.  It is used by both
 * the KDC and the kdb5_convert program.  Since its use is highly
 * specialized, the necesary information is just going to be
 * hard-coded in this file.
 */

#include "k5-int.h"
#include <string.h>
#include <ctype.h>

/* The maximum sizes for V4 aname, realm, sname, and instance +1 */
/* Taken from krb.h */
#define 	ANAME_SZ	40
#define		REALM_SZ	40
#define		SNAME_SZ	40
#define		INST_SZ		40

struct krb_convert {
	char	*v4_str;
	char	*v5_str;
	int	flags;
};

#define DO_REALM_CONVERSION 0x00000001

/*
 * Kadmin doesn't do realm conversion because it's currently
 * kadmin/REALM.NAME.  It should be kadmin/kerberos.master.host, but
 * we'll fix that in the next release.
 */
static struct krb_convert sconv_list[] = {
    "kadmin",	"kadmin",	0,
    "rcmd",	"host",		DO_REALM_CONVERSION,
    "discuss",	"discuss",	DO_REALM_CONVERSION,
    "rvdsrv",	"rvdsrv",	DO_REALM_CONVERSION,
    "sample",	"sample",	DO_REALM_CONVERSION,
    "olc",	"olc",		DO_REALM_CONVERSION,
    "pop",	"pop",		DO_REALM_CONVERSION,
    "sis",	"sis",		DO_REALM_CONVERSION,
    "rfs",	"rfs",		DO_REALM_CONVERSION,
    0,		0,
};

/*
 * char *strnchr(s, c, n)
 *   char *s;
 *   char c;
 *   int n;
 *
 * returns a pointer to the first occurrence of character c in the
 * string s, or a NULL pointer if c does not occur in in the string;
 * however, at most the first n characters will be considered.
 *
 * This falls in the "should have been in the ANSI C library"
 * category. :-)
 */
static char *strnchr(s, c, n)
   register char *s, c;
   register int n;
{
     if (n < 1) 
	  return 0;
     
     while (n-- && *s) {
	  if (*s == c)
	       return s;
	  s++;
     }
     return 0;
}


/* XXX This calls for a new error code */
#define KRB5_INVALID_PRINCIPAL KRB5_LNAME_BADFORMAT

krb5_error_code INTERFACE
krb5_524_conv_principal(context, princ, name, inst, realm)
    krb5_context context;
    const krb5_principal princ;
    char *name;
    char *inst;
    char *realm;
{
     struct krb_convert *p;
     krb5_data *comp;
     char *c;

     *name = *inst = '\0';
     switch (krb5_princ_size(context, princ)) {
     case 2:
	  /* Check if this principal is listed in the table */
	  comp = krb5_princ_component(context, princ, 0);
	  p = sconv_list;
	  while (p->v4_str) {
	       if (strncmp(p->v5_str, comp->data, comp->length) == 0) {
		    /* It is, so set the new name now, and chop off */
		    /* instance's domain name if requested */
		    strcpy(name, p->v4_str);
		    if (p->flags & DO_REALM_CONVERSION) {
			 comp = krb5_princ_component(context, princ, 1);
			 c = strnchr(comp->data, '.', comp->length);
			 if (!c || (c - comp->data) > INST_SZ - 1)
			      return KRB5_INVALID_PRINCIPAL;
			 strncpy(inst, comp->data, c - comp->data);
			 inst[c - comp->data] = '\0';
		    }
		    break;
	       }
	       p++;
	  }
	  /* If inst isn't set, the service isn't listed in the table, */
	  /* so just copy it. */
	  if (*inst == '\0') {
	       comp = krb5_princ_component(context, princ, 1);
	       if (comp->length >= INST_SZ - 1)
		    return KRB5_INVALID_PRINCIPAL;
	       strncpy(inst, comp->data, comp->length);
	       inst[comp->length] = '\0';
	  }
	  /* fall through */
     case 1:
	  /* name may have been set above; otherwise, just copy it */
	  if (*name == '\0') {
	       comp = krb5_princ_component(context, princ, 0);
	       if (comp->length >= ANAME_SZ)
		    return KRB5_INVALID_PRINCIPAL;
	       strncpy(name, comp->data, comp->length);
	       name[comp->length] = '\0';
	  }
	  break;
     default:
	  return KRB5_INVALID_PRINCIPAL;
     }

     comp = krb5_princ_realm(context, princ);
     if (comp->length > REALM_SZ - 1)
	  return KRB5_INVALID_PRINCIPAL;
     strncpy(realm, comp->data, comp->length);
     realm[comp->length] = '\0';

     return 0;
}

krb5_error_code INTERFACE
krb5_425_conv_principal(context, name, instance, realm, princ)
   krb5_context context;
   const char	*name;
   const char	*instance;
   const char	*realm;
   krb5_principal	*princ;
{
     struct krb_convert *p;
     char buf[256];		/* V4 instances are limited to 40 characters */
     krb5_error_code retval;
     char *domain, *cp;
     
     if (instance) {
	  if (instance[0] == '\0') {
	       instance = 0;
	       goto not_service;
	  }
	  p = sconv_list;
	  while (1) {
	       if (!p->v4_str)
		    goto not_service;
	       if (!strcmp(p->v4_str, name))
		    break;
	       p++;
	  }
	  name = p->v5_str;
	  if (p->flags & DO_REALM_CONVERSION) {
	       strcpy(buf, instance);
	       retval = krb5_get_realm_domain(context, realm, &domain);
	       if (retval)
		   return retval;
	       if (domain) {
		   for (cp = domain; *cp; cp++)
		       if (isupper(*cp))
			   *cp = tolower(*cp);
		   strcat(buf, domain);
		   krb5_xfree(domain);
	       }
	       instance = buf;
	  }
     }
     
not_service:	
     return(krb5_build_principal(context, princ, strlen(realm), realm, name,
				 instance, 0));
}
