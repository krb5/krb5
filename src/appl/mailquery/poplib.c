/*
 * (c) Copyright 1994 HEWLETT-PACKARD COMPANY
 * 
 * To anyone who acknowledges that this file is provided 
 * "AS IS" without any express or implied warranty:
 * permission to use, copy, modify, and distribute this 
 * file for any purpose is hereby granted without fee, 
 * provided that the above copyright notice and this 
 * notice appears in all copies, and that the name of 
 * Hewlett-Packard Company not be used in advertising or 
 * publicity pertaining to distribution of the software 
 * without specific, written prior permission.  Hewlett-
 * Packard Company makes no representations about the 
 * suitability of this software for any purpose.
 */

/*
 * Poplib - library routines for speaking POP
 */
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <errno.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#if defined(KRB4) && defined(KRB5)
error You cannot define both KRB4 and KRB5
#endif
#ifndef KPOP_SERVICE
#define KPOP_SERVICE "kpop"
#endif
#ifdef KPOP
#ifdef KRB4
#include <krb.h>
#endif
#ifdef KRB5
#include "krb5.h"
#include "com_err.h"
#include <ctype.h>
#endif
#endif

#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#else
extern char *malloc();
#endif

#include "pop.h"

void *xmalloc();
int getline(), multiline(), putline();

char Errmsg[80];		/* to return error messages */
int pop_debug;

static FILE *sfi = 0;
static FILE *sfo = 0;

int pop_init(host, reserved)
char *host;
int reserved;
{
    register struct hostent *hp;
    register struct servent *sp;
#ifndef KPOP
    int lport = IPPORT_RESERVED - 1;
#endif
    struct sockaddr_in sin;
    int s;
    char *get_errmsg();
    char response[1024];
    char *routine;
#ifdef KPOP
#ifdef KRB4
    CREDENTIALS cred;
    KTEXT ticket = (KTEXT)NULL;
    int rem;
#endif
#ifdef KRB5
    krb5_error_code retval;
    krb5_context context;
    krb5_ccache ccdef;
    krb5_principal client = NULL, server = NULL;
    krb5_error *err_ret = NULL;
    krb5_auth_context auth_context;
#endif
#endif

    if (sfi && sfo) {
	return OK;		/* guessing at this -- eichin -- XXX */
    }

    hp = gethostbyname(host);
    if (hp == NULL) {
	sprintf(Errmsg, "MAILHOST unknown: %s", host);
	return(NOTOK);
    }

#ifdef KPOP
    sp = getservbyname(KPOP_SERVICE, "tcp");
    if (sp == 0) {
	(void) strcpy(Errmsg, "tcp/kpop: unknown service");
	return(NOTOK);
    }
#else /* !KPOP */
    sp = getservbyname("pop", "tcp");
    if (sp == 0) {
	(void) strcpy(Errmsg, "tcp/pop: unknown service");
	return(NOTOK);
    }
#endif /* KPOP */
    if (sp == 0) {
	strcpy(Errmsg, "tcp/pop: unknown service");
	return(NOTOK);
    }

    sin.sin_family = hp->h_addrtype;
    memcpy((char *)&sin.sin_addr, hp->h_addr, hp->h_length);
    sin.sin_port = sp->s_port;
#ifdef KPOP
    s = socket(AF_INET, SOCK_STREAM, 0);
#else /* !KPOP */
    if (reserved) 
      s = rresvport(&lport);
    else
      s = socket(AF_INET, SOCK_STREAM, 0);
#endif /* KPOP */
    
    if (s < 0) {
	sprintf(Errmsg, "error creating socket: %s", get_errmsg());
	return(NOTOK);
    }

    if (connect(s, (struct sockaddr *)&sin, sizeof sin) < 0) {
	sprintf(Errmsg, "error during connect: %s", get_errmsg());
	close(s);
	return(NOTOK);
    }

#ifdef KPOP
#ifdef KRB4
    /* Get tgt creds from ticket file. This is used to calculate the
     * lifetime for the pop ticket so that it expires with the
     * tgt */
    rem = krb_get_cred("krbtgt", krb_realmofhost(hp->h_name), krb_realmofhost(hp->h_name), &cred);
    if (rem == KSUCCESS) {
            long lifetime;
            lifetime = ((cred.issue_date + ((unsigned char)cred.lifetime * 5 * 60)) - time(0)) / (5 * 60);
            if (lifetime > 0)
                    krb_set_lifetime(lifetime);
    }            
    ticket = (KTEXT)malloc( sizeof(KTEXT_ST) );
    rem = krb_sendauth(0L, s, ticket, "pop", hp->h_name, (char *)0,
		       0, (MSG_DAT *) 0, (CREDENTIALS *) 0,
		       (bit_64 *) 0, (struct sockaddr_in *)0,
		       (struct sockaddr_in *)0,"ZMAIL0.0");
    if (rem != KSUCCESS) {
	(void) sprintf(Errmsg, "kerberos error: %s",krb_err_txt[rem]);
	(void) close(s);
	return(NOTOK);
    }
#endif /* KRB4 */
#ifdef KRB5
    retval = krb5_init_context(&context);
    if (retval) {
	    com_err("pop_init", retval, "while initializing krb5");
	    close(s);
	    return(NOTOK);
    }
    routine = "krb5_cc_default";
    if ((retval = krb5_cc_default(context, &ccdef))) {
    krb5error:
	sprintf(Errmsg, "%s: krb5 error: %s", routine, error_message(retval));
	close(s);
	return(NOTOK);
    }
    routine = "krb5_cc_get_principal";
    if ((retval = krb5_cc_get_principal(context, ccdef, &client))) {
	goto krb5error;
    }

    routine = "krb5_sname_to_principal";
    if ((retval = krb5_sname_to_principal(context, hp->h_name, "pop",
					  KRB5_NT_UNKNOWN, &server))) {
	goto krb5error;
    }

    retval = krb5_sendauth(context, &auth_context, (krb5_pointer) &s, 
			   "KPOPV1.0", client, server,
			   AP_OPTS_MUTUAL_REQUIRED,
			   NULL,	/* no data to checksum */
			   0,		/* no creds, use ccache instead */
			   ccdef,
			   &err_ret, 0,
			   NULL);	/* don't need reply */
    krb5_free_principal(context, server);
    if (retval) {
	if (err_ret && err_ret->text.length) {
	    sprintf(Errmsg, "krb5 error: %s [server says '%*s'] ",
		    error_message(retval),
		    err_ret->text.length,
		    err_ret->text.data);
	    krb5_free_error(context, err_ret);
	} else
	    sprintf(Errmsg, "krb5_sendauth: krb5 error: %s", error_message(retval));
	close(s);
	return(NOTOK);
    }
#endif /* KRB5 */
#endif /* KPOP */

    sfi = fdopen(s, "r");
    sfo = fdopen(s, "w");
    if (sfi == NULL || sfo == NULL) {
	sprintf(Errmsg, "error in fdopen: %s", get_errmsg());
	close(s);
	return(NOTOK);
    }

    if (getline(response, sizeof response, sfi) != OK) {
	error(response);
	return(NOTOK);
    }
    if (pop_debug)
      fprintf(stderr, "<--- %s\n", response);

    return(OK);
}

int pop_command(fmt, a, b, c, d)
char *fmt;
char *a, *b, *c, *d;
{
    char buf[1024];

    sprintf(buf, fmt, a, b, c, d);

    if (pop_debug) fprintf(stderr, "---> %s\n", buf);
    if (putline(buf, Errmsg, sfo) == NOTOK) return(NOTOK);

    if (getline(buf, sizeof buf, sfi) != OK) {
	strcpy(Errmsg, buf);
	return(NOTOK);
    }

    if (pop_debug) fprintf(stderr, "<--- %s\n", buf);
    if (*buf != '+') {
	strcpy(Errmsg, buf);
	return(NOTOK);
    } else {
	return(OK);
    }
}

int pop_query(nbytes, user)
     int *nbytes;
     char *user;
{
    char buf[1024];

    if (strlen(user) > 120) {
	if (pop_debug) fprintf(stderr, "username %s too long\n", user);
	return NOTOK;
    }
    
    sprintf(buf, "QUERY %s", user);    
    if (pop_debug) fprintf(stderr, "---> %s\n", buf);
    if (putline(buf, Errmsg, sfo) == NOTOK) return (NOTOK);

    if (getline(buf, sizeof buf, sfi) != OK) {
	strcpy(Errmsg, buf);
	return NOTOK;
    }

    if (pop_debug) fprintf(stderr, "<--- %s\n", buf);
    if (*buf != '+') {
	strcpy(Errmsg, buf);
	return NOTOK;
    } else {
	sscanf(buf, "+OK %d", nbytes);
	return OK;
    }
}
    
int pop_stat(nmsgs, nbytes)
int *nmsgs, *nbytes;
{
    char buf[1024];

    if (pop_debug) fprintf(stderr, "---> STAT\n");
    if (putline("STAT", Errmsg, sfo) == NOTOK) return(NOTOK);

    if (getline(buf, sizeof buf, sfi) != OK) {
	strcpy(Errmsg, buf);
	return(NOTOK);
    }

    if (pop_debug) fprintf(stderr, "<--- %s\n", buf);
    if (*buf != '+') {
	strcpy(Errmsg, buf);
	return(NOTOK);
    } else {
	sscanf(buf, "+OK %d %d", nmsgs, nbytes);
	return(OK);
    }
}

int pop_retr(msgno, action, arg)
int msgno;
int (*action)();
char *arg;			/* is this always FILE*??? -- XXX */
{
    char buf[1024];
    int nbytes = 0;
    
    sprintf(buf, "RETR %d", msgno);

    if (pop_debug)
      fprintf(stderr, "---> %s\n", buf);

    if (putline(buf, Errmsg, sfo) == NOTOK) return(NOTOK);

    if (getline(buf, sizeof buf, sfi) != OK) {
	strcpy(Errmsg, buf);
	return(NOTOK);
    }
    if (pop_debug)
      fprintf(stderr, "<--- %s\n", buf);

    sscanf(buf, "+OK %d", &nbytes);

    while (1) {
	switch (multiline(buf, sizeof buf, sfi)) {
	case OK:
            if ((*action)(buf, arg, nbytes) < 0) {
                strcat(Errmsg, get_errmsg());
                return (DONE);	/* Some error occured in action */
            }
	    break;
	case DONE:
	    return (OK);
	case NOTOK:
	    strcpy(Errmsg, buf);
	    return (NOTOK);
	}
    }
}

int pop_getline(buf, n)
     char *buf;
     int n;
{
    return getline(buf, n, sfi);
}

int getline(buf, n, f)
char *buf;
register int n;
FILE *f;
{
    register char *p;
    int c;

    p = buf;
    while (--n > 0 && (c = fgetc(f)) != EOF)
      if ((*p++ = c) == '\n') break;

    if (ferror(f)) {
	strcpy(buf, "error on connection");
	return (NOTOK);
    }

    if (c == EOF && p == buf) {
	strcpy(buf, "connection closed by foreign host");
	return (DONE);
    }

    *p = '\0';
    if (*--p == '\n') *p = '\0';
    if (*--p == '\r') *p = '\0';
    return(OK);
}

int multiline(buf, n, f)
char *buf;
register int n;
FILE *f;
{
    if (getline(buf, n, f) != OK) return (NOTOK);
    if (*buf == '.') {
	if (*(buf+1) == '\0') {
	    return (DONE);
	} else {
	    strcpy(buf, buf+1);
	}
    }
    return(OK);
}

#ifndef HAS_STRERROR
char *
strerror(e)
    int e;
{
    extern int errno, sys_nerr;
    extern char *sys_errlist[];

    if (errno < sys_nerr)
      return sys_errlist[errno];
    else
      return "unknown error";
}
#endif

char *
get_errmsg()
{
    char *s = strerror(errno);
    
    return(s);
}

int putline(buf, err, f)
char *buf;
char *err;
FILE *f;
{
    fprintf(f, "%s\r\n", buf);
    fflush(f);
    if (ferror(f)) {
	strcpy(err, "lost connection");
	return(NOTOK);
    }
    return(OK);
}


/* Print error message and exit.  */

void fatal (s1, s2)
     char *s1, *s2;
{
  error (s1, s2);
  exit (1);
}

/* Print error message.  `s1' is printf control string, `s2' is arg for it. */

void error (s1, s2, s3)
     char *s1, *s2, *s3;
{
  printf ("poplib: ");
  printf (s1, s2, s3);
  printf ("\n");
}

void pfatal_with_name (name)
     char *name;
{
  char *s = concat ("", strerror(errno), " for %s");

  fatal (s, name);
}

/* Return a newly-allocated string whose contents concatenate those of s1, s2, s3.  */

char *
concat (s1, s2, s3)
     char *s1, *s2, *s3;
{
  int len1 = strlen (s1), len2 = strlen (s2), len3 = strlen (s3);
  char *result = (char *) xmalloc (len1 + len2 + len3 + 1);

  strcpy (result, s1);
  strcpy (result + len1, s2);
  strcpy (result + len1 + len2, s3);
  *(result + len1 + len2 + len3) = 0;

  return result;
}

/* Like malloc but get fatal error if memory is exhausted.  */

void *
xmalloc (size)
     int size;
{
  void *result = (void *)malloc (size);
  if (!result)
    fatal ("virtual memory exhausted", 0);
  return result;
}
