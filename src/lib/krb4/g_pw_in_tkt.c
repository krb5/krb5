/*
 * g_pw_in_tkt.c
 *
 * Copyright 1987, 1988 by the Massachusetts Institute of Technology.
 *
 * For copying and distribution information, please see the file
 * <mit-copyright.h>.
 */

#include "mit-copyright.h"
#include "krb.h"
#include "krb_err.h"
#include "prot.h"
#include <string.h>

#ifndef NULL
#define NULL 0
#endif

#ifndef INTK_PW_NULL
#define INTK_PW_NULL KRBET_GT_PW_NULL
#endif

/*
 * This file contains two routines: passwd_to_key() converts
 * a password into a DES key (prompting for the password if
 * not supplied), and krb_get_pw_in_tkt() gets an initial ticket for
 * a user.
 */

/*
 * passwd_to_key(): given a password, return a DES key.
 * There are extra arguments here which (used to be?)
 * used by srvtab_to_key().
 *
 * If the "passwd" argument is not null, generate a DES
 * key from it, using string_to_key().
 *
 * If the "passwd" argument is null, then on a Unix system we call
 * des_read_password() to prompt for a password and then convert it
 * into a DES key.  But "prompting" the user is harder in a Windows or
 * Macintosh environment, so we rely on our caller to explicitly do
 * that now.
 *
 * In either case, the resulting key is put in the "key" argument,
 * and 0 is returned.
 */
/*ARGSUSED */
int
passwd_to_key(user,instance,realm,passwd,key)
    char *user, *instance, *realm, *passwd;
    C_Block key;
{
#if defined(_WINDOWS) || defined(macintosh)
    string_to_key(passwd, key);
#else /* unix */
#ifdef NOENCRYPTION
    if (!passwd)
	placebo_read_password(key, "Password: ", 0);
#else /* Do encyryption */
    if (passwd)
        string_to_key(passwd, key);
    else {
        des_read_password(key, "Password: ", 0);
    }
#endif /* NOENCRYPTION */
#endif /* unix */
    return (0);
}

/*
 * krb_get_pw_in_tkt() takes the name of the server for which the initial
 * ticket is to be obtained, the name of the principal the ticket is
 * for, the desired lifetime of the ticket, and the user's password.
 * It passes its arguments on to krb_get_in_tkt(), which contacts
 * Kerberos to get the ticket, decrypts it using the password provided,
 * and stores it away for future use.
 *
 * On a Unix system, krb_get_pw_in_tkt() is able to prompt the user
 * for a password, if the supplied password is null.  On a a non Unix
 * system, it now requires the caller to supply a non-null password.
 * This is because of the complexities of prompting the user in a
 * non-terminal-oriented environment like the Macintosh (running in a
 * driver) or MS-Windows (in a DLL).
 *
 * krb_get_pw_in_tkt() passes two additional arguments to krb_get_in_tkt():
 * the name of a routine (passwd_to_key()) to be used to get the
 * password in case the "password" argument is null and NULL for the
 * decryption procedure indicating that krb_get_in_tkt should use the 
 * default method of decrypting the response from the KDC.
 *
 * The result of the call to krb_get_in_tkt() is returned.
 */

KRB5_DLLIMP int KRB5_CALLCONV
krb_get_pw_in_tkt(user,instance,realm,service,sinstance,life,password)
    char FAR *user, FAR *instance, FAR *realm, FAR *service, FAR *sinstance;
    int life;
    char FAR *password;
{
#if defined(_WINDOWS) || defined(macintosh)
    /* In spite of the comments above, we don't allow that path here,
       to simplify coding the non-UNIX clients. The only code that now
       depends on this behavior is the preauth support, which has a
       seperate function without this trap. Strictly speaking, this 
       is an API change. */

    if (password == 0)
    	return INTK_PW_NULL;
#endif

    return(krb_get_in_tkt(user,instance,realm,service,sinstance,life,
                          (key_proc_type)passwd_to_key,
			  (decrypt_tkt_type)NULL, password));
}

/*
 * krb_get_pw_in_tkt_preauth() gets handed the password or key explicitly,
 * since the whole point of "pre" authentication is to prove that we've
 * already got the key, and the only way to do that is to ask the user
 * for it. Clearly we shouldn't ask twice.
 */
 
static C_Block old_key;

static int stub_key(user,instance,realm,passwd,key)
    char *user, *instance, *realm, *passwd;
    C_Block key;
{
   (void) memcpy((char *) key, (char *) old_key, sizeof(old_key));
   return 0;
}

KRB5_DLLIMP int KRB5_CALLCONV
krb_get_pw_in_tkt_preauth(user,instance,realm,service,sinstance,life,password)
    char FAR *user, FAR *instance, FAR *realm, FAR *service, FAR *sinstance;
    int life;
    char FAR *password;
{
   char *preauth_p;
   int   preauth_len;
   int   ret_st;

#if defined(_WINDOWS) || defined(macintosh)
   /* On non-Unix systems, we can't handle a null password, because
      passwd_to_key can't handle prompting for the password.  */
   if (password == 0)
     return INTK_PW_NULL;
#endif

   krb_mk_preauth(&preauth_p, &preauth_len, (key_proc_type)passwd_to_key,
		  user, instance, realm, password, old_key);
   ret_st = krb_get_in_tkt_preauth(user,instance,realm,service,sinstance,life,
				   (key_proc_type) stub_key,
				   (decrypt_tkt_type) NULL, password,
				   preauth_p, preauth_len);

   krb_free_preauth(preauth_p, preauth_len);
   return ret_st;
}

/* FIXME!  This routine belongs in the krb library and should simply
   be shared between the encrypted and NOENCRYPTION versions!  */
 
#ifdef NOENCRYPTION
/*
 * This routine prints the supplied string to standard
 * output as a prompt, and reads a password string without
 * echoing.
 */

#include <stdio.h>
#ifdef	BSDUNIX
#include <string.h>
#include <sys/ioctl.h>
#include <signal.h>
#include <setjmp.h>
#else
char     *strcpy();
int      strcmp();
#endif
#if defined(__svr4__) || defined(__SVR4)
#include <sgtty.h>
#endif

#ifdef	BSDUNIX
static jmp_buf env;
#endif

#ifdef BSDUNIX
static void sig_restore();
static push_signals(), pop_signals();
int placebo_read_pw_string();
#endif

/*** Routines ****************************************************** */
int
placebo_read_password(k,prompt,verify)
    des_cblock *k;
    char *prompt;
    int	verify;
{
    int ok;
    char key_string[BUFSIZ];

#ifdef BSDUNIX
    if (setjmp(env)) {
	ok = -1;
	goto lose;
    }
#endif

    ok = placebo_read_pw_string(key_string, BUFSIZ, prompt, verify);
    if (ok == 0)
	memset(k, 0, sizeof(C_Block));

lose:
    memset(key_string, 0, sizeof (key_string));
    return ok;
}

/*
 * This version just returns the string, doesn't map to key.
 *
 * Returns 0 on success, non-zero on failure.
 */

int
placebo_read_pw_string(s,max,prompt,verify)
    char *s;
    int	max;
    char *prompt;
    int	verify;
{
    int ok = 0;
    char *ptr;
    
#ifdef BSDUNIX
    jmp_buf old_env;
    struct sgttyb tty_state;
#endif
    char key_string[BUFSIZ];

    if (max > BUFSIZ) {
	return -1;
    }

#ifdef	BSDUNIX
    memcpy(env, old_env, sizeof(env));
    if (setjmp(env))
	goto lose;

    /* save terminal state */
    if (ioctl(0,TIOCGETP,&tty_state) == -1) 
	return -1;

    push_signals();
    /* Turn off echo */
    tty_state.sg_flags &= ~ECHO;
    if (ioctl(0,TIOCSETP,&tty_state) == -1)
	return -1;
#endif
    while (!ok) {
	printf(prompt);
	fflush(stdout);
#ifdef	CROSSMSDOS
	h19line(s,sizeof(s),0);
	if (!strlen(s))
	    continue;
#else
	if (!fgets(s, max, stdin)) {
	    clearerr(stdin);
	    continue;
	}
	if ((ptr = strchr(s, '\n')))
	    *ptr = '\0';
#endif
	if (verify) {
	    printf("\nVerifying, please re-enter %s",prompt);
	    fflush(stdout);
#ifdef CROSSMSDOS
	    h19line(key_string,sizeof(key_string),0);
	    if (!strlen(key_string))
		continue;
#else
	    if (!fgets(key_string, sizeof(key_string), stdin)) {
		clearerr(stdin);
		continue;
	    }
            if ((ptr = strchr(key_string, '\n')))
	    *ptr = '\0';
#endif
	    if (strcmp(s,key_string)) {
		printf("\n\07\07Mismatch - try again\n");
		fflush(stdout);
		continue;
	    }
	}
	ok = 1;
    }

#ifdef	BSDUNIX
lose:
    if (!ok)
	memset(s, 0, max);
    printf("\n");
    /* turn echo back on */
    tty_state.sg_flags |= ECHO;
    if (ioctl(0,TIOCSETP,&tty_state))
	ok = 0;
    pop_signals();
    memcpy(old_env, env, sizeof(env));
#endif
    if (verify)
	memset(key_string, 0, sizeof (key_string));
    s[max-1] = 0;		/* force termination */
    return !ok;			/* return nonzero if not okay */
}

#ifdef	BSDUNIX
/*
 * this can be static since we should never have more than
 * one set saved....
 */
static sigtype (*old_sigfunc[NSIG])();

static push_signals()
{
    register i;
    for (i = 0; i < NSIG; i++)
	old_sigfunc[i] = signal(i,sig_restore);
}

static pop_signals()
{
    register i;
    for (i = 0; i < NSIG; i++)
	signal(i,old_sigfunc[i]);
}

static void sig_restore(sig,code,scp)
    int sig,code;
    struct sigcontext *scp;
{
    longjmp(env,1);
}
#endif
#endif /* NOENCRYPTION */
