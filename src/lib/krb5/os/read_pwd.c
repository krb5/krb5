/*
 * $Source$
 * $Author$
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <krb5/mit-copyright.h>.
 *
 * libos: krb5_read_password for BSD 4.3
 */

#ifndef	lint
static char rcsid_read_pwd_c[] =
"$Id$";
#endif	/* lint */

#include <krb5/copyright.h>

#include <krb5/krb5.h>
#include <krb5/krb5_err.h>

#include <sys/ioctl.h>
#include <stdio.h>
#include <errno.h>
#include <signal.h>
#include <setjmp.h>

#include <krb5/ext-proto.h>

#ifdef POSIX
#define sigtype void
#else
#define sigtype int
#endif /* POSIX */

extern int errno;

#define cleanup(errcode) (void) signal(SIGINT, ointrfunc); ioctl(0, TIOCSETP, (char *)&tty_savestate); return errcode;

static jmp_buf pwd_jump;

sigtype
intr_routine()
{
    longjmp(pwd_jump, 1);
}

krb5_error_code
krb5_read_password(prompt, prompt2, return_pwd, size_return)
char *prompt;
char *prompt2;
char *return_pwd;
int size_return;
{
    /* adapted from Kerberos v4 des/read_password.c */

    struct sgttyb tty_state, tty_savestate;
    char *readin_string = 0;
    register char *ptr;
    int scratchchar;
    sigtype (*ointrfunc)();

    /* save terminal state */
    if (ioctl(0,TIOCGETP,(char *)&tty_savestate) == -1) 
	return errno;

    tty_state = tty_savestate;

    tty_state.sg_flags &= ~ECHO;
    if (ioctl(0,TIOCSETP,(char *)&tty_state) == -1)
	return errno;

    if (setjmp(pwd_jump)) {
	/* interrupted */
	if (readin_string) {
	    (void) bzero(readin_string, size_return);
	    free(readin_string);
	}
	(void) bzero(return_pwd, size_return);
	cleanup(KRB5_LIBOS_PWDINTR);
    }
    /* save intrfunc */
    ointrfunc = signal(SIGINT, intr_routine);

    /* put out the prompt */
    (void) fputs(prompt,stdout);
    (void) fflush(stdout);
    (void) bzero(return_pwd, size_return);

    if (fgets(return_pwd, size_return, stdin) == NULL) {
	/* error */
	(void) bzero(return_pwd, size_return);
	cleanup(KRB5_LIBOS_CANTREADPWD);
    }
    /* fgets always null-terminates the returned string */

    /* replace newline with null */
    if (ptr = index(return_pwd, '\n'))
	*ptr = '\0';
    else /* flush rest of input line */
	do {
	    scratchchar = getchar();
	} while (scratchchar != EOF && scratchchar != '\n');

    if (prompt2) {
	/* put out the prompt */
	(void) putchar('\n');
	(void) fputs(prompt2,stdout);
	(void) fflush(stdout);
	readin_string = malloc(size_return);
	if (!readin_string) {
	    (void) bzero(return_pwd, size_return);
	    cleanup(ENOMEM);
	}
	(void) bzero(readin_string, size_return);
	if (fgets(readin_string, size_return, stdin) == NULL) {
	    /* error */
	    (void) bzero(readin_string, size_return);
	    (void) bzero(return_pwd, size_return);
	    free(readin_string);
	    cleanup(KRB5_LIBOS_CANTREADPWD);
	}
	if (ptr = index(readin_string, '\n'))
	    *ptr = '\0';
	else /* need to flush */
	    do {
		scratchchar = getchar();
	    } while (scratchchar != EOF && scratchchar != '\n');
	/* compare */
	if (strncmp(return_pwd, readin_string, size_return)) {
	    (void) bzero(readin_string, size_return);
	    (void) bzero(return_pwd, size_return);
	    free(readin_string);
	    cleanup(KRB5_LIBOS_BADPWDMATCH);
	}
	(void) bzero(readin_string, size_return);
	free(readin_string);
    }
    
    /* reset intrfunc */
    (void) signal(SIGINT, ointrfunc);

    if (ioctl(0, TIOCSETP, (char *)&tty_savestate) == -1)
	return errno;


    return 0;
}
