/*
 * Copyright (c) 1989 Regents of the University of California.
 * All rights reserved.  The Berkeley software License Agreement
 * specifies the terms and conditions for redistribution.
 */

/* 
 * authorization rules for use with kerberos (tom)
 * password server using kerberos (jon)
 */

#ifndef lint
static char copyright[] = "Copyright (c) 1990 Regents of the University of California.\nAll rights reserved.\n";
static char SccsId[] = "@(#)pop_pass.c  1.7 7/13/90";
#endif not lint

#include <stdio.h>
#include <sys/types.h>
#include <strings.h>
#include <pwd.h>
#include <netinet/in.h>
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
#include <krb5/krb5.h>
#include <krb5/ext-proto.h>
#include <krb5/los-proto.h>
#include <com_err.h>
extern krb5_principal ext_client;
extern char *client_name;
#endif /* KRB5 */
#endif /* KERBEROS */

#ifndef KERBEROS_PASSWD_HACK

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
    krb5_error_code retval;
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
    if (retval = krb5_get_default_realm(&lrealm)) {
        pop_log(p, POP_WARNING, "%s: (%s) %s", p->client, client_name,
		error_message(retval));
        return(pop_msg(p,POP_FAILURE,
            "Kerberos error:  \"%s\".", error_message(retval)));
    }

    tmpdata = krb5_princ_realm(ext_client);
    if (strncmp(tmpdata->data, lrealm, tmpdata->length))  {
         pop_log(p, POP_WARNING, "%s: (%s) realm not accepted.", 
		 p->client, client_name);
	 return(pop_msg(p,POP_FAILURE,
		     "Kerberos realm \"%*s\" not accepted.",
			tmpdata->length, tmpdata->data));
    }

    /* only accept one-component names, i.e. realm and name only */
    if (krb5_princ_size(ext_client) > 1) {
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
    tmpdata = krb5_princ_component(ext_client, 0);
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
    (void)sprintf(p->drop_name,"%s/%s",POP_MAILDIR,p->user);
    
    /*  Make a temporary copy of the user's maildrop */
    if (pop_dropcopy(p) != POP_SUCCESS) return (POP_FAILURE);

#else /* KERBEROS */

    /*  Look for the user in the password file */
    if ((pw = getpwnam(p->user)) == NULL)
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
    (void)sprintf(p->drop_name,"%s/%s",POP_MAILDIR,p->user);

    /*  Make a temporary copy of the user's maildrop */
    if (pop_dropcopy(p) != POP_SUCCESS) return (POP_FAILURE);

#ifndef KERBEROS_PASSWD_HACK
    /*  Set the group and user id */
    (void)setgid(pw->pw_gid);
    (void)setuid(pw->pw_uid);
#endif /* KERBEROS_PASSWD_HACK */

#ifdef DEBUG
    if(p->debug)pop_log(p,POP_DEBUG,"uid = %d, gid = %d",getuid(),getgid());
#endif DEBUG

#endif /* KERBEROS */

    /*  Get information about the maildrop */
    if (pop_dropinfo(p) != POP_SUCCESS) {
      pop_log(p, POP_PRIORITY, "dropinfo failure");
      return(POP_FAILURE);
    }

    /*  Initialize the last-message-accessed number */
    p->last_msg = 0;

    /*  Authorization completed successfully */
    return (pop_msg (p,POP_SUCCESS,
        "%s has %d message(s) (%d octets).",
            p->user,p->msg_count,p->drop_size));
}





#else /* KERBEROS_PASSWD_HACK */



#ifdef KRB4

/*
 * Check to see if the user is in the passwd file, if not get a kerberos
 * ticket with the password
 */



#include <sys/file.h>
#include <netdb.h>
#include <krb.h>

int pop_pass (p)
POP     *   p;
{
    register struct passwd  *   pw;
    char *crypt();
    
    setpwfile(POP_PASSFILE);

    /*  Look for the user in the password file */
    pw = getpwnam(p->user);

    /*  Compare the supplied password with the password file entry */
    if (pw && pw->pw_passwd) {
      if (strcmp (crypt (p->pop_parm[1], pw->pw_passwd), pw->pw_passwd) != 0)
        return (pop_msg(p,POP_FAILURE,
            "Password supplied for \"%s\" is incorrect.",p->user));
    }
    else {
      if(verify_passwd_hack_hack_hack(p) != POP_SUCCESS)
	return(POP_FAILURE);
    }

    /*  Build the name of the user's maildrop */
    (void)sprintf(p->drop_name,"%s/%s",POP_MAILDIR,p->user);
    
    /*  Make a temporary copy of the user's maildrop */
    if (pop_dropcopy(p) != POP_SUCCESS) return (POP_FAILURE);

    
#ifndef KERBEROS_PASSWD_HACK
    /*  Set the group and user id */
    (void)setgid(pw->pw_gid);
    (void)setuid(pw->pw_uid);
#endif /* KERBEROS_PASSWD_HACK */

#ifdef DEBUG
    if(p->debug)pop_log(p,POP_DEBUG,"uid = %d, gid = %d",getuid(),getgid());
#endif DEBUG

    /*  Get information about the maildrop */
    if (pop_dropinfo(p) != POP_SUCCESS) {
      pop_log(p, POP_PRIORITY, "dropinfo failure");
      return(POP_FAILURE);
    }

    /*  Initialize the last-message-accessed number */
    p->last_msg = 0;

    /*  Authorization completed successfully */
    return (pop_msg (p,POP_SUCCESS,
        "%s has %d message(s) (%d octets).",
            p->user,p->msg_count,p->drop_size));
}


/* for Ultrix and friends ... */
#ifndef MAXHOSTNAMELEN
#define MAXHOSTNAMELEN 64
#endif

#ifndef MAXPATHLEN
#define MAXPATHLEN 1024
#endif


int verify_passwd_hack_hack_hack(p)
     POP *p;
{
    char lrealm[REALM_SZ];
    int status, fd; 
    KTEXT_ST ticket;
    AUTH_DAT kdata;
    char savehost[MAXHOSTNAMELEN];
    char tkt_file_name[MAXPATHLEN];
    struct sockaddr_in sin;
    int len;

    extern int errno;
    extern int sp;

    /* Be sure ticket file is correct and exists */

    sprintf(tkt_file_name, "/tmp/tkt_pop.%s.%d", p->user, getpid());
    if (setenv("KRBTKFILE", tkt_file_name, 1 /* overwrite = yes */))
      return(pop_msg(p,POP_FAILURE, "Could not set ticket file name."));

    if ((fd = open(tkt_file_name, O_RDWR|O_CREAT, 0600)) == -1) {
      close(fd);
	pop_log(p, POP_ERROR, "%s: could not create ticket file, \"%s\": %s",
		p->user, tkt_file_name, sys_errlist[errno]);
	return(pop_msg(p,POP_FAILURE,"POP server error: %s while creating %s.",
		       sys_errlist[errno], tkt_file_name));
    }
    close(fd);

    /* 
     * Get an initial ticket using the given name/password and then use it.
     * This hack will allow us to stop maintaining a separate pop passwd 
     * on eagle. We can cut over to real Kerberos POP clients at any point. 
     */

    if ((status = krb_get_lrealm(lrealm,1)) == KFAILURE) {
        pop_log(p,POP_ERROR, "%s (%s):  error getting local realm:  \"%s\".", 
		p->user, p->client, krb_err_txt[status]);
	return(pop_msg(p,POP_FAILURE, "POP server error:  \"%s\".", 
		       krb_err_txt[status]));
    }
    
    status = krb_get_pw_in_tkt(p->user, "", lrealm, "krbtgt", lrealm,
				2 /* 10 minute lifetime */, p->pop_parm[1]);
    if (status != KSUCCESS) {
        pop_log(p,POP_WARNING, "%s (%s): error getting tgt: %s", 
		p->user, p->client, krb_err_txt[status]);
      return(pop_msg(p,POP_FAILURE,
		       "Kerberos authentication error:  \"%s\".", 
		       krb_err_txt[status]));
    }
    
    /*
     * Now use the ticket for something useful, to make sure
     * it is valid.
     */

    (void) strncpy(savehost, krb_get_phost(p->myhost), sizeof(savehost));
    savehost[sizeof(savehost)-1] = 0;

    status = krb_mk_req(&ticket, "pop", savehost, lrealm, 0);
    if (status == KDC_PR_UNKNOWN) {
          pop_log(p, POP_ERROR, "%s (%s): %s", p->user, p->client, 
		  krb_err_txt[status]);
          return(pop_msg(p,POP_FAILURE,
		     "POP server configuration error:  \"%s\".", 
		     krb_err_txt[status]));
    } 
      
    if (status != KSUCCESS) {
	  dest_tkt();
	  pop_log(p, POP_ERROR, "%s (%s): krb_mk_req error: %s", p->user, 
		  p->client, krb_err_txt[status]);
	  return(pop_msg(p,POP_FAILURE,
	        "Kerberos authentication error (while getting ticket) \"%s\".",
			 krb_err_txt[status]));
    }  

    len = sizeof(sin);
    getsockname(sp, &sin, &len); 
    if ((status = krb_rd_req(&ticket, "pop", savehost, sin.sin_addr.s_addr, 
			     &kdata, ""))
	!= KSUCCESS) {
         dest_tkt();
	 pop_log(p, POP_WARNING, "%s (%s): krb_rd_req error: %s", p->user, 
		 p->client, krb_err_txt[status]);
	 return(pop_msg(p,POP_FAILURE,
			"Kerberos authentication error:  \"%s\".", 
			krb_err_txt[status]));
    }
    dest_tkt();
    return(POP_SUCCESS);
}

#endif
#ifdef KRB5
 #error: no passwd_hack source for V5.
#endif
#endif /* KERBEROS_PASSWD_HACK */
