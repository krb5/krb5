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
 * Mailquery - contact the POP mail host an see if a user has
 *             mail. By default the result if reflected in the
 *             exit status.
 *             
 * Usage: mailquery [-dv] [-e <cmd>]
 *      -d - debug
 *      -v - print result
 *      -e - exec this command if there is mail.
 */
#include <stdio.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#include <string.h>
#include <pwd.h>
#include <fcntl.h>
#include <sys/file.h>  
#ifdef HESIOD
#include <hesiod.h>
#endif
#include "pop.h"

extern int pop_debug;
int verbose = 0;
char *exec_cmd;

int mailquery();

void usage()
{
    fprintf(stderr, "usage: mailquery [-d] [-v] [-e cmd] [user[@host]]\n");
} 

int main(argc, argv)
     int argc;
     char *argv[];
{
    extern char *getenv();
    int nbytes;
    char *mhost = NULL, *mhp;
    char *user = 0;
    struct passwd * pwd;
    char c;
    extern int optind;
    extern char *optarg;
#ifdef HESIOD
    struct hes_postoffice *p;
#endif /* HESIOD */

    while ((c = getopt(argc, argv, "dve:")) != EOF) {
	switch (c) {
	  case 'd':
	    pop_debug = 1;
	    break;

	  case 'e':
	    exec_cmd = optarg;
	    break;
	    
	  case 'v':
	    verbose = 1;
	    break;
	    
	  case '?':
	    usage();
	    exit(1);
	}
    }
    
    argc -= optind;
    argv += optind;

    if (argc > 0) {
	user = argv[0];
	if ((mhost = strchr(argv[0], '@')) != NULL) {
	    *mhost = '\0';
	    mhost++;
	}
#ifndef HESIOD
        else {
	    mhost = DEFMAILHOST;
	}
#endif
    }
    
    if (user == (char *) 0 || *user == '\0') {
	if ((pwd = getpwuid(getuid())) == NULL) {
	    perror("getpwuid");
	    exit(1);
	}
	user = pwd->pw_name;
    }

    if ((mhost == NULL) &&
        (mhp = getenv("MAILHOST")))
            mhost = mhp;

#ifdef HESIOD
    if (mhost == NULL) {
            p = hes_getmailhost(user);
            if (p != NULL && strcmp(p->po_type, "POP") == 0)
                    mhost = p->po_host;
            else {
                    fprintf(stderr,"no POP server listed in Hesiod for %s\n", user);
                    exit(1);
            } 
    }
#endif	/* HESIOD */

    if (mhost == NULL) {
	mhost = DEFMAILHOST;
    }

    nbytes = mailquery(mhost, user);
    
    if ((nbytes > 0) && (exec_cmd != 0)) {
	if (pop_debug)
	  fprintf(stderr, "about to execute %s\n", exec_cmd);
	system(exec_cmd);
    }
    
    exit(nbytes == 0);

}

int mailquery(mhost, user)
     char *mhost;
     char *user;
{
    int nbytes, nmsgs;
    
    if (pop_init(mhost, 0) == NOTOK) {
	error(Errmsg);
	exit(1);
    }

#ifdef KPOP
    if (pop_command("USER %s", user) == NOTOK || 
        pop_command("PASS %s", user) == NOTOK) {
#else /* !KPOP */
    if (pop_command("USER %s", user) == NOTOK || 
        pop_command("RPOP %s", user) == NOTOK) {
#endif /* KPOP */
            error(Errmsg);
            (void) pop_command("QUIT");
            exit (1);
    } 

    if (pop_stat(&nmsgs, &nbytes) == NOTOK) {
            error(Errmsg);
            (void) pop_command("QUIT");
            exit (1);
    }

    (void) pop_command("QUIT");
    
    if (verbose)
      printf("%d messages (%d bytes) on host %s\n", nmsgs, nbytes, mhost);

    return nbytes;
}
    
