#include "k5-int.h"
#if !defined(_MSDOS) && (!defined(_WIN32) || (defined(_WIN32) && defined(__CYGWIN32__))) && !defined(macintosh)
#include <stdio.h>
#include <errno.h>
#include <signal.h>
#include <setjmp.h>
#ifdef __vxworks
#define ECHO_PASSWORD
#endif

#ifndef ECHO_PASSWORD
#include <termios.h>
#endif /* ECHO_PASSWORD */

static jmp_buf pwd_jump;

static krb5_sigtype
intr_routine(signo)
    int signo;
{
    longjmp(pwd_jump, 1);
    /*NOTREACHED*/
}

KRB5_DLLIMP krb5_error_code KRB5_CALLCONV
krb5_prompter_posix(krb5_context context,
		    void *data,
		    const char *name,
		    const char *banner,
		    int num_prompts,
		    krb5_prompt prompts[])
{
    /* adapted from Kerberos v5 krb5_read_password() */

    register char *ptr;
    int scratchchar;
    krb5_sigtype (*volatile ointrfunc)();
    volatile krb5_error_code errcode;
    int i;
#ifndef ECHO_PASSWORD
    struct termios echo_control, save_control;
    volatile int fd;
#endif

    if (name) {
	fputs(name, stdout);
	fputs("\n", stdout);
    }

    if (banner) {
       fputs(banner, stdout);
       fputs("\n", stdout);
    }

    if (setjmp(pwd_jump)) {
	errcode = KRB5_LIBOS_PWDINTR; 	/* we were interrupted... */
	goto cleanup;
    }
    /* save intrfunc */
    ointrfunc = signal(SIGINT, intr_routine);

    for (i=0; i<num_prompts; i++) {
#ifndef ECHO_PASSWORD
	if (prompts[i].hidden) {
	    /* get the file descriptor associated with stdin */
	    fd = fileno(stdin);

	    if (isatty(fd) == 1) {
		if (tcgetattr(fd, &echo_control) == -1)
		    return errno;

		save_control = echo_control;
		echo_control.c_lflag &= ~(ECHO|ECHONL);

		if (tcsetattr(fd, TCSANOW, &echo_control) == -1)
		    return errno;
	    }
	}
#endif /* ECHO_PASSWORD */

	/* put out the prompt */
	(void) fputs(prompts[i].prompt,stdout);
	(void) fputs(": ",stdout);
	(void) fflush(stdout);
	(void) memset(prompts[i].reply->data, 0, prompts[i].reply->length);

	if (fgets(prompts[i].reply->data, prompts[i].reply->length, stdin)
	    == NULL) {
	    if (prompts[i].hidden)
		(void) putchar('\n');
	    errcode = KRB5_LIBOS_CANTREADPWD;
	    goto cleanup;
	}
	if (prompts[i].hidden)
	    (void) putchar('\n');
	/* fgets always null-terminates the returned string */

	/* replace newline with null */
	if ((ptr = strchr(prompts[i].reply->data, '\n')))
	    *ptr = '\0';
	else /* flush rest of input line */
	    do {
		scratchchar = getchar();
	    } while (scratchchar != EOF && scratchchar != '\n');
    
	prompts[i].reply->length = strlen(prompts[i].reply->data);

#ifndef ECHO_PASSWORD
	if (prompts[i].hidden && (isatty(fd) == 1))
	    if ((tcsetattr(fd, TCSANOW, &save_control) == -1) &&
		(errcode == 0))
	        return errno;
#endif
    }

    errcode = 0;

cleanup:
    (void) signal(SIGINT, ointrfunc);
    return(errcode);
}
#else /* MSDOS */

#if defined(_WIN32)

#include <io.h>

KRB5_DLLIMP krb5_error_code KRB5_CALLCONV
krb5_prompter_posix(krb5_context context,
		    void *data,
		    const char *name,
		    const char *banner,
		    int num_prompts,
		    krb5_prompt prompts[])
{
    HANDLE		handle;
    DWORD		old_mode, new_mode;
    char		*ptr;
    int			scratchchar;
    krb5_error_code	errcode = 0;
    int			i;

    handle = GetStdHandle(STD_INPUT_HANDLE);
    if (handle == INVALID_HANDLE_VALUE)
	return ENOTTY;
    if (!GetConsoleMode(handle, &old_mode))
	return ENOTTY;

    new_mode = old_mode;
    new_mode |=  ( ENABLE_LINE_INPUT | ENABLE_PROCESSED_INPUT );
    new_mode &= ~( ENABLE_ECHO_INPUT );

    if (!SetConsoleMode(handle, new_mode))
	return ENOTTY;

    if (!SetConsoleMode(handle, old_mode))
	return ENOTTY;

    if (name) {
	fputs(name, stdout);
	fputs("\n", stdout);
    }

    if (banner) {
       fputs(banner, stdout);
       fputs("\n", stdout);
    }

    for (i = 0; i < num_prompts; i++) {
	if (prompts[i].hidden) {
	    if (!SetConsoleMode(handle, new_mode)) {
		errcode = ENOTTY;
		goto cleanup;
	    }
	}

	fputs(prompts[i].prompt,stdout);
	fputs(": ", stdout);
	fflush(stdout);
	memset(prompts[i].reply->data, 0, prompts[i].reply->length);

	if (fgets(prompts[i].reply->data, prompts[i].reply->length, stdin)
	    == NULL) {
	    if (prompts[i].hidden)
		putchar('\n');
	    errcode = KRB5_LIBOS_CANTREADPWD;
	    goto cleanup;
	}
	if (prompts[i].hidden)
	    putchar('\n');
	/* fgets always null-terminates the returned string */

	/* replace newline with null */
	if ((ptr = strchr(prompts[i].reply->data, '\n')))
	    *ptr = '\0';
	else /* flush rest of input line */
	    do {
		scratchchar = getchar();
	    } while (scratchchar != EOF && scratchchar != '\n');
    
	prompts[i].reply->length = strlen(prompts[i].reply->data);

	if (!SetConsoleMode(handle, old_mode)) {
	    errcode = ENOTTY;
	    goto cleanup;
	}
    }

 cleanup:
    if (errcode) {
	for (i = 0; i < num_prompts; i++) {
	    memset(prompts[i].reply->data, 0, prompts[i].reply->length);
	}
    }
    return errcode;
}

#else /* !_WIN32 */

KRB5_DLLIMP krb5_error_code KRB5_CALLCONV
krb5_prompter_posix(krb5_context context,
		    void *data,
		    const char *name,
		    const char *banner,
		    int num_prompts,
		    krb5_prompt prompts[])
{
    return(EINVAL);
}
#endif /* !_WIN32 */
#endif /* !MSDOS */

void
krb5int_set_prompt_types(context, types)
    krb5_context context;
    krb5_prompt_type *types;
{
    context->prompt_types = 0;
}

KRB5_DLLIMP
krb5_prompt_type*
KRB5_CALLCONV
krb5_get_prompt_types(context)
    krb5_context context;
{
    return context->prompt_types;
}
