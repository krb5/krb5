/* This file is part of the Project Athena Zephyr Notification System.
 * It contains code for the "zmailnotify" command.
 *
 *	Created by:	Robert French
 *
 *	$OrigSource: /mit/zephyr/src/clients/zmailnotify/RCS/zmailnotify.c,v $
 *	$OrigAuthor: jtkohl $
 *
 *	Copyright (c) 1987,1988 by the Massachusetts Institute of Technology.
 *	For copying and distribution information, see the file
 *	"mit-copyright.h". 
 */

#include <zephyr/mit-copyright.h>

#include <zephyr/zephyr.h>

#ifndef lint
static char rcsid_zwmnotify_c[] = "$OrigHeader: zmailnotify.c,v 1.8 88/11/14 11:50:30 jtkohl Exp $";
#endif /* lint */

#include <stdlib.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/file.h>
#ifdef HAS_UNISTD_H
#include <unistd.h>
#endif
#include <pwd.h>
#include <stdio.h>
#include <sgtty.h>
#include <signal.h>
#include <errno.h>
#include <netdb.h>
#ifdef HESIOD
#include <hesiod.h>
#endif
#ifdef NIS
#include <rpcsvc/ypclnt.h>
#endif
#include <string.h>

#ifdef KERBEROS
#ifndef KPOP_SNAME
#define	KPOP_SNAME	"pop"
#endif
#ifndef KPOP_SERVICE
#define KPOP_SERVICE	"kpop"
#endif
#ifdef KRB5
/* these need to be here to declare the functions which are used by
   non-kerberos specific code */
#include <krb5/krb5.h>
#include <krb5/ext-proto.h>
#else
#include <krb.h>
#endif
#endif

#define NOTOK (-1)
#define OK 0
#define DONE 1

FILE *sfi;
FILE *sfo;
char Errmsg[80];
#ifdef KERBEROS
char *PrincipalHostname(), *index();
#endif /* KERBEROS */

extern uid_t getuid();
char *getenv();
void get_message(), pop_close(), mail_notify();
#define MAXMAIL 4

struct _mail {
	char *from;
	char *to;
	char *subj;
} maillist[MAXMAIL];

char *mailptr = NULL;

/* This entire program is a kludge - beware! */

main()
{
	FILE *lock;
	int nmsgs;
	char *user,response[512],lockfile[100];
	char *host,*dir;
	int i,nbytes,retval,uselock;
	struct passwd *pwd;
	struct _mail mymail;
#ifdef HESIOD
	struct hes_postoffice *p;
#endif /* HESIOD */
#ifdef NIS
        char *domainname;
        int yperr, len;
#endif /* NIS */
        char *host_list;

	if ((retval = ZInitialize()) != ZERR_NONE) {
		com_err("zmailnotify",retval,"while initializing");
		exit(1);
	}

	dir = getenv("HOME");
	user = getenv("USER");
	if (!user || !dir) {
		pwd = (struct passwd *)getpwuid((int) getuid());
		if (!pwd) {
			fprintf(stderr,"Can't figure out who you are!\n");
			exit(1);
		}
		if (!user)
			user = pwd->pw_name;
		if (!dir)
			dir = pwd->pw_dir;
	}

	(void) sprintf(lockfile,"%s/.maillock",dir);
	
	host = getenv("MAILHOST");
#ifdef HESIOD
	if (host == NULL) {
		p = hes_getmailhost(user);
		if (p != NULL && strcmp(p->po_type, "POP") == 0)
			host = p->po_host;
		else {
			fprintf(stderr,"no POP server listed in Hesiod");
			exit(1);
		} 
	}
#endif /* HESIOD */
#ifdef NIS
        /* Get pop-hosts for user from NIS map */
        if (yp_get_default_domain(&domainname) == 0) {
                if (yp_bind(domainname) == 0) {
                        yperr = yp_match(domainname, "pop-hosts", user, strlen(user), &host_list, &len);
                        if (yperr == YPERR_KEY) {
                                yperr = yp_match(domainname, "pop-hosts", "*", 1, &host_list, &len);
                        }
                        if (yperr) {
                                fprintf(stderr, "Cannot find pop host for %s : %s\n", user, yperr_string(yperr));
                        }
                        else {
                                host_list[len] = '\0';
                                host = host_list;
                        }
                }
        }
#endif /* NIS */
	if (host == NULL) {
		fprintf(stderr,"no MAILHOST defined");
		exit(1);
	}

	lock = fopen(lockfile,"r");
	if (lock)
#if	SYS5_FILE_LOCKS
                (void) lockf(fileno(lock),F_LOCK, 0);
#else
		(void) flock(fileno(lock),LOCK_EX);
#endif
	
        host_list = host;
        while (host = strtok(host_list, " \t,:")) {
                host_list = NULL;
                if (pop_init(host) == OK) {
                        break;
                }
        }
        if (!host) {
                fprintf(stderr,Errmsg);
                exit(1);
        }

	if ((getline(response, sizeof response, sfi) != OK) ||
	    (*response != '+')) {
		fprintf(stderr,"%s",response);
		exit(1);
	}

#ifdef KERBEROS
	if (pop_command("USER %s", user) == NOTOK || 
	    pop_command("PASS %s", user) == NOTOK) {
#else /* !KERBEROS */
	if (pop_command("USER %s", user) == NOTOK || 
	    pop_command("RPOP %s", user) == NOTOK) {
#endif /* KERBEROS */
		fprintf(stderr,Errmsg);
		(void) pop_command("QUIT");
		pop_close();
		exit (1);
	} 

	if (pop_stat(&nmsgs, &nbytes) == NOTOK) {
		fprintf(stderr,Errmsg);
		(void) pop_command("QUIT");
		pop_close();
		exit (1);
	}
        
#ifndef KERBEROS
        setuid(getuid());
#endif
        
	if (!nmsgs) {
		if (lock) {
#if	!SYS5_FILE_LOCKS
			(void) flock(fileno(lock),LOCK_UN);
#endif
			(void) fclose(lock);
		} 
		(void) unlink(lockfile);
		(void) pop_command("QUIT");
		pop_close();
		exit (0);
	}

	uselock = 0;
        if (lock) {
		uselock = 1;
		mymail.to = malloc(BUFSIZ);
		mymail.from = malloc(BUFSIZ);
		mymail.subj = malloc(BUFSIZ);
		if (fgets(mymail.from,BUFSIZ,lock) != NULL)
		    mymail.from[strlen(mymail.from)-1] = 0;
		else
		    mymail.from[0]=0;
		if (fgets(mymail.to,BUFSIZ,lock) != NULL)
		    mymail.to[strlen(mymail.to)-1] = 0;
		else
		    mymail.to[0] = 0;
		if (fgets(mymail.subj,BUFSIZ,lock) != NULL)
		    mymail.subj[strlen(mymail.subj)-1] = 0;
		else
		    mymail.subj[0] = 0;
	}
	else {
		lock = fopen(lockfile,"w");
		if (lock)
#if	SYS5_FILE_LOCKS
			(void) lockf(fileno(lock),F_LOCK,0);
#else
			(void) flock(fileno(lock),LOCK_EX);
#endif
                else
                        perror("create lock file");
		uselock = 0;
	}
	
	for (i=nmsgs;i>0;i--) {
		if (nmsgs-i == MAXMAIL)
			break;
		if (get_mail(i, &maillist[nmsgs-i]))
			exit (1);
		if (uselock && (!strcmp(maillist[nmsgs-i].to,mymail.to) &&
				!strcmp(maillist[nmsgs-i].from,mymail.from) &&
				!strcmp(maillist[nmsgs-i].subj,mymail.subj)))
			break;
	}
        
	i++;
	for (;i<=nmsgs;i++)
		mail_notify(&maillist[nmsgs-i]);
	i--;
	if (lock) {
#if	!SYS5_FILE_LOCKS
		(void) flock(fileno(lock),LOCK_UN);
#endif
		(void) fclose(lock);
	}
	lock = fopen(lockfile,"w");
	if (!lock) {
                perror("open lockfile");
		exit (1);
        }
	fprintf(lock,"%s\n%s\n%s\n",
		maillist[nmsgs-i].from,
		maillist[nmsgs-i].to,
		maillist[nmsgs-i].subj);
	(void) fclose(lock);

	(void) pop_command("QUIT");
	pop_close();
	exit(0);
}

void get_message(i)
	int i;
{
	int mbx_write();
	if (pop_retr(i, mbx_write, 0) != OK) {
		fprintf(stderr,Errmsg);
		(void) pop_command("QUIT");
		pop_close();
		exit(1);
	}
}

/* Pop stuff */

void pop_close()
{
	if (sfi)
		(void) fclose(sfi);
	if (sfo)
		(void) fclose(sfo);
}

get_mail(i,mail)
	int i;
	struct _mail *mail;
{
	char from[512],to[512],subj[512];
	char *c,*ptr,*ptr2;
	
	*from = 0;
	*to = 0;
	*subj = 0;

	if (mailptr)
		free(mailptr);

	mailptr = 0;
	
	get_message(i);

	ptr = mailptr;
	while (ptr) {
		ptr2 = index(ptr,'\n');
		if (ptr2)
			*ptr2++ = 0;
		if (*ptr == '\0')
			break;
		if (!strncmp(ptr, "From: ", 6))
			(void) strcpy(from, ptr+6);
		else if (!strncmp(ptr, "To: ", 4))
			(void) strcpy(to, ptr+4);
		else if (!strncmp(ptr, "Subject: ", 9))
			(void) strcpy(subj, ptr+9);
		ptr = ptr2;
	}

	/* add elipsis at end of "To:" field if it continues onto */
	/* more than one line */
	i = strlen(to) - 2;
	c = to+i;
	if (*c++ == ',') {
		*c++ = ' ';
		*c++ = '.';
		*c++ = '.';
		*c++ = '.';
		*c++ = '\n';
		*c = 0;
	}

	mail->from = malloc((unsigned)(strlen(from)+1));
	(void) strcpy(mail->from,from);
	mail->to = malloc((unsigned)(strlen(to)+1));
	(void) strcpy(mail->to,to);
	mail->subj = malloc((unsigned)(strlen(subj)+1));
	(void) strcpy(mail->subj,subj);

	return (0);
}

void
mail_notify(mail)
	struct _mail *mail;
{
	int retval;
	char *fields[3];
	ZNotice_t notice;

	(void) bzero((char *)&notice, sizeof(notice));
	notice.z_kind = UNACKED;
	notice.z_port = 0;
	notice.z_class = "MAIL";
	notice.z_class_inst = "POPRET";
	notice.z_opcode = "NEW_MAIL";
	notice.z_sender = 0;
	notice.z_recipient = ZGetSender();
	notice.z_default_format = "You have new mail:\n\nFrom: $1\nTo: $2\nSubject: $3";

	fields[0] = mail->from;
	fields[1] = mail->to;
	fields[2] = mail->subj;
      
	if ((retval = ZSendList(&notice,fields,3,ZNOAUTH)) != ZERR_NONE)
		com_err("zmailnotify",retval,"while sending notice");
}

/*
 * These are the necessary KPOP routines snarfed from
 * the GNU movemail program.
 */

pop_init(host)
char *host;
{
    register struct hostent *hp;
    register struct servent *sp;
    int lport = IPPORT_RESERVED - 1;
    struct sockaddr_in sin;
    int s;
    char *get_errmsg();
#ifdef KERBEROS
#ifdef KRB4
    KTEXT ticket;
    MSG_DAT msg_data;
    CREDENTIALS cred;
    Key_schedule schedule;
    int rem;
#endif /* KRB4 */
#ifdef KRB5
    krb5_error_code retval;
    krb5_ccache ccdef;
    krb5_principal client, server;
    krb5_error *err_ret = NULL;
    register char *cp;
#endif /* KRB5 */
#endif /* KERBEROS */
    hp = gethostbyname(host);
    if (hp == NULL) {
	sprintf(Errmsg, "MAILHOST unknown: %s", host);
	return(NOTOK);
    }

#ifdef KERBEROS
    sp = getservbyname(KPOP_SERVICE, "tcp");
#else
    sp = getservbyname("pop", "tcp");
#endif
    if (sp == 0) {
#ifdef KERBEROS
	strcpy(Errmsg, "tcp/kpop: unknown service");
#else
	strcpy(Errmsg, "tcp/pop: unknown service");
#endif
	return(NOTOK);
    }

    sin.sin_family = hp->h_addrtype;
    memcpy((char *)&sin.sin_addr, hp->h_addr, hp->h_length);
    sin.sin_port = sp->s_port;
#ifdef KERBEROS
    s = socket(AF_INET, SOCK_STREAM, 0);
#else
    s = rresvport(&lport);
#endif

    if (s < 0) {
	sprintf(Errmsg, "error creating socket: %s", get_errmsg());
	return(NOTOK);
    }

    if (connect(s, (struct sockaddr *)&sin, sizeof sin) < 0) {
	sprintf(Errmsg, "error during connect: %s", get_errmsg());
	close(s);
	return(NOTOK);
    }

#ifdef KERBEROS
#ifdef KRB4
    ticket = (KTEXT) malloc(sizeof(KTEXT_ST));
    rem = krb_sendauth(0L, s, ticket, KPOP_SNAME, hp->h_name,
		       (char *) krb_realmofhost(hp->h_name),
		       (unsigned long)0, &msg_data, &cred, schedule,
		       (struct sockaddr_in *)0,
		       (struct sockaddr_in *)0,
		       "KPOPV0.1");
    if (rem != KSUCCESS) {
	 sprintf(Errmsg, "kerberos error: %s", krb_err_txt[rem]);
	 close(s);
	 return(NOTOK);
    }
#endif /* KRB4 */
#ifdef KRB5
    krb5_init_ets();

    if (retval = krb5_cc_default(&ccdef)) {
    krb5error:
	sprintf(Errmsg, "krb5 error: %s", error_message(retval));
	close(s);
	return(NOTOK);
    }
    if (retval = krb5_cc_get_principal(ccdef, &client)) {
	goto krb5error;
    }

#if 0
    /* lower-case to get name for "instance" part of service name */
    for (cp = hp->h_name; *cp; cp++)
	if (isupper(*cp))
	    *cp = tolower(*cp);
#endif

    if (retval = krb5_sname_to_principal(hp->h_name, KPOP_SNAME,
					 KRB5_NT_SRV_HST, &server)) {
	goto krb5error;
    }

    retval = krb5_sendauth((krb5_pointer) &s, "KPOPV1.0", client, server,
			   AP_OPTS_MUTUAL_REQUIRED,
			   0,		/* no checksum */
			   0,		/* no creds, use ccache instead */
			   ccdef,
			   0,		/* don't need seq # */
			   0,		/* don't need a subsession key */
			   &err_ret,
			   0);		/* don't need reply */
    krb5_free_principal(server);
    if (retval) {
	if (err_ret && err_ret->text.length) {
	    sprintf(Errmsg, "krb5 error: %s [server says '%*s'] ",
		    error_message(retval),
		    err_ret->text.length,
		    err_ret->text.data);
	    krb5_free_error(err_ret);
	} else
	    sprintf(Errmsg, "krb5 error: %s", error_message(retval));
	close(s);
	return(NOTOK);
    }
#endif /* KRB5 */
#endif /* KERBEROS */
		       
    sfi = fdopen(s, "r");
    sfo = fdopen(s, "w");
    if (sfi == NULL || sfo == NULL) {
	sprintf(Errmsg, "error in fdopen: %s", get_errmsg());
	close(s);
	return(NOTOK);
    }

    return(OK);
}

/*VARARGS1*/
pop_command(fmt, a, b, c, d)
char *fmt;
{
    char buf[4096];

    (void) sprintf(buf, fmt, a, b, c, d);

    if (putline(buf, Errmsg, sfo) == NOTOK) return(NOTOK);

    if (getline(buf, sizeof buf, sfi) != OK) {
	(void) strcpy(Errmsg, buf);
	return(NOTOK);
    }

    if (*buf != '+') {
	(void) strcpy(Errmsg, buf);
	return(NOTOK);
    } else {
	return(OK);
    }
}

    
pop_stat(nmsgs, nbytes)
int *nmsgs, *nbytes;
{
    char buf[4096];

    if (putline("STAT", Errmsg, sfo) == NOTOK) return(NOTOK);

    if (getline(buf, sizeof buf, sfi) != OK) {
	(void) strcpy(Errmsg, buf);
	return(NOTOK);
    }

    if (*buf != '+') {
	(void) strcpy(Errmsg, buf);
	return(NOTOK);
    } else {
	if (sscanf(buf, "+OK %d %d", nmsgs, nbytes) != 2)
	    return(NOTOK);
	return(OK);
    }
}

pop_retr(msgno, action, arg)
int (*action)();
{
    char buf[4096];

    (void) sprintf(buf, "RETR %d", msgno);
    if (putline(buf, Errmsg, sfo) == NOTOK) return(NOTOK);

    if (getline(buf, sizeof buf, sfi) != OK) {
	(void) strcpy(Errmsg, buf);
	return(NOTOK);
    }

    while (1) {
	switch (multiline(buf, sizeof buf, sfi)) {
	case OK:
	    (*action)(buf, arg);
	    break;
	case DONE:
	    return (OK);
	case NOTOK:
	    (void) strcpy(Errmsg, buf);
	    return (NOTOK);
	}
    }
}

getline(buf, n, f)
char *buf;
register int n;
FILE *f;
{
    register char *p;
    int c;

    p = fgets(buf, n, f);

    if (ferror(f)) {
	(void) strcpy(buf, "error on connection");
	return (NOTOK);
    }

    if (p == NULL) {
	(void) strcpy(buf, "connection closed by foreign host\n");
	return (DONE);
    }

    p = buf + strlen(buf);
    if (*--p == '\n') *p = NULL;
    if (*--p == '\r') *p = NULL;
    return(OK);
}

multiline(buf, n, f)
char *buf;
register int n;
FILE *f;
{
    if (getline(buf, n, f) != OK) return (NOTOK);
    if (*buf == '.') {
	if (*(buf+1) == NULL) {
	    return (DONE);
	} else {
	    (void) strcpy(buf, buf+1);
	}
    }
    return(OK);
}

char *
get_errmsg()
{
    extern int errno, sys_nerr;
    extern char *sys_errlist[];
    char *s;

    if (errno < sys_nerr)
      s = sys_errlist[errno];
    else
      s = "unknown error";
    return(s);
}

putline(buf, err, f)
char *buf;
char *err;
FILE *f;
{
    fprintf(f, "%s\r\n", buf);
    (void) fflush(f);
    if (ferror(f)) {
	(void) strcpy(err, "lost connection");
	return(NOTOK);
    }
    return(OK);
}

/*ARGSUSED*/
mbx_write(line, dummy)
char *line;
int dummy;				/* for consistency with pop_retr */
{
	if (mailptr) {
		mailptr = realloc(mailptr,(unsigned)(strlen(mailptr)+strlen(line)+2));
		(void) strcat(mailptr,line);
	} 
	else {
		mailptr = malloc((unsigned)(strlen(line)+2));
		(void) strcpy(mailptr,line);
	}
	(void) strcat(mailptr,"\n");
	return(0);
}
