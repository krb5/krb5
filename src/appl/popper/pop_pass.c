/*
 * Copyright (c) 1989 Regents of the University of California.
 * All rights reserved.  The Berkeley software License Agreement
 * specifies the terms and conditions for redistribution.
 */

#ifndef lint
static char copyright[] = "Copyright (c) 1990 Regents of the University of California.\nAll rights reserved.\n";
/* based on @(#)pop_pass.c	2.3  4/2/91 */
#endif

#include <stdio.h>
#include <sys/types.h>
#ifdef HAVE_STRINGS_H
#include <strings.h>
#else
#include <string.h>
#endif
#include <pwd.h>
#include "popper.h"

#ifdef KERBEROS
#ifdef KRB4
#ifdef KRB5
 #error you can only use one of KRB4, KRB5
#endif
#include <krb.h>
extern AUTH_DAT kdata;
#endif /* KRB4 */
#ifdef KRB5
#include "krb5.h"
#include "com_err.h"
extern krb5_principal ext_client;
extern krb5_context pop_context;
extern char *client_name;
#endif /* KRB5 */
#endif /* KERBEROS */

#ifdef POP_PASSFILE
struct passwd * our_getpwnam();
#endif

/* 
 *  pass:   Obtain the user password from a POP client
 */

int pop_pass (p)
POP     *   p;
{
#ifdef KERBEROS
#ifdef KRB4
    char lrealm[REALM_SZ];
    int status; 
#endif /* KRB4 */
#ifdef KRB5
    char *lrealm;
    krb5_data *tmpdata;
#endif /* KRB5 */
#else
    register struct passwd  *   pw;
    char *crypt();
#endif /* KERBEROS */

#ifdef KERBEROS
#ifdef KRB4
    if ((status = krb_get_lrealm(lrealm,1)) == KFAILURE) {
        pop_log(p, POP_WARNING, "%s: (%s.%s@%s) %s", p->client, kdata.pname, 
		kdata.pinst, kdata.prealm, krb_err_txt[status]);
        return(pop_msg(p,POP_FAILURE,
            "Kerberos error:  \"%s\".", krb_err_txt[status]));
    }

    if (strcmp(kdata.prealm,lrealm))  {
         pop_log(p, POP_WARNING, "%s: (%s.%s@%s) realm not accepted.", 
		 p->client, kdata.pname, kdata.pinst, kdata.prealm);
	 return(pop_msg(p,POP_FAILURE,
		     "Kerberos realm \"%s\" not accepted.", kdata.prealm));
    }

    if (strcmp(kdata.pinst,"")) {
        pop_log(p, POP_WARNING, "%s: (%s.%s@%s) instance not accepted.", 
		 p->client, kdata.pname, kdata.pinst, kdata.prealm);
        return(pop_msg(p,POP_FAILURE,
	      "Must use null Kerberos(tm) instance -  \"%s.%s\" not accepted.",
	      kdata.pname, kdata.pinst));
    }

#endif /* KRB4 */
#ifdef KRB5
#ifdef NO_CROSSREALM
    {
      krb5_error_code retval;

    if (retval = krb5_get_default_realm(pop_context, &lrealm)) {
        pop_log(p, POP_WARNING, "%s: (%s) %s", p->client, client_name,
		error_message(retval));
        return(pop_msg(p,POP_FAILURE,
            "Kerberos error:  \"%s\".", error_message(retval)));
    }
    }

    tmpdata = krb5_princ_realm(pop_context, ext_client);
    if (strncmp(tmpdata->data, lrealm, tmpdata->length))  {
         pop_log(p, POP_WARNING, "%s: (%s) realm not accepted.", 
		 p->client, client_name);
	 return(pop_msg(p,POP_FAILURE,
		     "Kerberos realm \"%*s\" not accepted.",
			tmpdata->length, tmpdata->data));
    }
#endif
    /* only accept one-component names, i.e. realm and name only */
    if (krb5_princ_size(pop_context, ext_client) > 1) {
        pop_log(p, POP_WARNING, "%s: (%s) instance not accepted.", 
		 p->client, client_name);
        return(pop_msg(p,POP_FAILURE,
		       "Must use null Kerberos(tm) \"instance\" -  \"%s\" not accepted.",
		       client_name));
    }

    /*
     * be careful! we are assuming that the instance and realm have been
     * checked already! I used to simply copy the pname into p->user
     * but this causes too much confusion and assumes p->user will never
     * change. This makes me feel more comfortable.
     */
    tmpdata = krb5_princ_component(pop_context, ext_client, 0);
    if(strncmp(p->user, tmpdata->data, tmpdata->length))
      {
	pop_log(p, POP_WARNING, "%s: auth failed: %s vs %s", 
		 p->client, client_name, p->user);
        return(pop_msg(p,POP_FAILURE,
	      "Wrong username supplied (%*s vs. %s).\n", tmpdata->length,
		       tmpdata->data,
		       p->user));
      }
#endif /* KRB5 */

    /*  Build the name of the user's maildrop */
    (void)sprintf(p->drop_name,"%s/%s",MAILDIR,p->user);
    
    /*  Make a temporary copy of the user's maildrop */
    if (pop_dropcopy(p, NULL) != POP_SUCCESS) return (POP_FAILURE);

#else /* KERBEROS */

    /*  Look for the user in the password file */
#ifdef POP_PASSFILE
    our_setpwent(POP_PASSFILE);

    if ((pw = our_getpwnam(p->user)) == NULL)
#else    
    if ((pw = getpwnam(p->user)) == NULL)
#endif
        return (pop_msg(p,POP_FAILURE,
            "Password supplied for \"%s\" is incorrect.",p->user));

    /*  We don't accept connections from users with null passwords */
    if (pw->pw_passwd == NULL)
        return (pop_msg(p,POP_FAILURE,
            "Password supplied for \"%s\" is incorrect.",p->user));

    /*  Compare the supplied password with the password file entry */
    if (strcmp (crypt (p->pop_parm[1], pw->pw_passwd), pw->pw_passwd) != 0)
        return (pop_msg(p,POP_FAILURE,
            "Password supplied for \"%s\" is incorrect.",p->user));

    /*  Build the name of the user's maildrop */
    (void)sprintf(p->drop_name,"%s/%s",MAILDIR,p->user);

    /*  Make a temporary copy of the user's maildrop */
    /*    and set the group and user id */
    if (pop_dropcopy(p,pw) != POP_SUCCESS) return (POP_FAILURE);

#endif /* KERBEROS */

    /*  Get information about the maildrop */
    if (pop_dropinfo(p) != POP_SUCCESS) return(POP_FAILURE);

    /*  Initialize the last-message-accessed number */
    p->last_msg = 0;

    /*  Authorization completed successfully */
    return (pop_msg (p,POP_SUCCESS,
        "%s has %d message(s) (%d octets).",
            p->user,p->msg_count,p->drop_size));
}

#ifdef POP_PASSFILE

/*
 * I'm getting myself deeper and deeper
 */

static char *pwfile = "/etc/passwd";

our_setpwent(file)
     char *file;
{
  if(file)
    {
      pwfile = (char *) malloc(strlen(file) + 1);
      if(pwfile)
	strcpy(pwfile, file);
      else
	return(-1);
      return(0);
    }
  return(-1);
}

struct passwd *
our_getpwnam(user)
     char *user;
{
  FILE *fp;
  char buf[BUFSIZ];
  register char *c;
  register char *d;
  static struct passwd p;

  if(!(fp = fopen(pwfile, "r")))
    return(NULL);

  memset(&p, 0, sizeof(p));
  while(fgets(buf, sizeof(buf), fp))
    {
      if(!(c = (char *) strchr(buf, ':')))
	continue;

      *c++ = '\0';
      if(strcmp(buf, user))
	continue;
      
      p.pw_name = strdup(buf);

#if defined(hpux) || defined(__hpux)
      if (!(d = (char *) strchr(c, ':')))
         return(&p);
#else 
      if(!((d = (char *) strchr(c, ':')) && (c = (char *) strchr(++d, ':')) &&
	 (d = (char *) strchr(++c, ':'))))
	return(&p);
#endif
      *d = '\0';

      p.pw_passwd = strdup(c);
      return(&p);
    }
  
  return(NULL);
}

#endif /* POP_PASSFILE */
