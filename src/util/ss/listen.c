/*
 * Listener loop for subsystem library libss.a.
 *
 *	util/ss/listen.c
 * 
 * Copyright 1987, 1988 by MIT Student Information Processing Board
 *
 * For copyright information, see copyright.h.
 */

#include "copyright.h"
#include "ss_internal.h"
#include <stdio.h>
#include <setjmp.h>
#include <signal.h>
#include <sys/param.h>
#ifdef BSD
#include <sgtty.h>
#endif

static ss_data *current_info;
static jmp_buf listen_jmpb;

static RETSIGTYPE print_prompt()
{
#ifdef BSD
    /* put input into a reasonable mode */
    struct sgttyb ttyb;
    if (ioctl(fileno(stdin), TIOCGETP, &ttyb) != -1) {
	if (ttyb.sg_flags & (CBREAK|RAW)) {
	    ttyb.sg_flags &= ~(CBREAK|RAW);
	    (void) ioctl(0, TIOCSETP, &ttyb);
	}
    }
#endif
    (void) fputs(current_info->prompt, stdout);
    (void) fflush(stdout);
}

static RETSIGTYPE listen_int_handler()
{
    putc('\n', stdout);
    longjmp(listen_jmpb, 1);
}

int ss_listen (sci_idx)
    int sci_idx;
{
    register char *cp;
    register RETSIGTYPE (*sig_cont)();
    register ss_data *info;
    RETSIGTYPE (*sig_int)(), (*old_sig_cont)();
    char input[BUFSIZ];
    char buffer[BUFSIZ];
    char *end = buffer;
    int mask;
    int code;
    jmp_buf old_jmpb;
    ss_data *old_info = current_info;
    
    current_info = info = ss_info(sci_idx);
    sig_cont = (RETSIGTYPE (*)())0;
    info->abort = 0;
    mask = sigblock(sigmask(SIGINT));
    memcpy(old_jmpb, listen_jmpb, sizeof(jmp_buf));
    sig_int = signal(SIGINT, listen_int_handler);
    setjmp(listen_jmpb);
    (void) sigsetmask(mask);
    while(!info->abort) {
	print_prompt();
	*end = '\0';
	old_sig_cont = sig_cont;
	sig_cont = signal(SIGCONT, print_prompt);
	if (sig_cont == print_prompt)
	    sig_cont = old_sig_cont;
	if (fgets(input, BUFSIZ, stdin) != input) {
	    code = SS_ET_EOF;
	    goto egress;
	}
	cp = strchr(input, '\n');
	if (cp) {
	    *cp = '\0';
	    if (cp == input)
		continue;
	}
	(void) signal(SIGCONT, sig_cont);
	for (end = input; *end; end++)
	    ;

	code = ss_execute_line (sci_idx, input);
	if (code == SS_ET_COMMAND_NOT_FOUND) {
	    register char *c = input;
	    while (*c == ' ' || *c == '\t')
		c++;
	    cp = strchr (c, ' ');
	    if (cp)
		*cp = '\0';
	    cp = strchr (c, '\t');
	    if (cp)
		*cp = '\0';
	    ss_error (sci_idx, 0,
		    "Unknown request \"%s\".  Type \"?\" for a request list.",
		       c);
	}
    }
    code = 0;
egress:
    (void) signal(SIGINT, sig_int);
    memcpy(listen_jmpb, old_jmpb, sizeof(jmp_buf));
    current_info = old_info;
    return code;
}

void ss_abort_subsystem(sci_idx, code)
    int sci_idx;
    int code;
{
    ss_info(sci_idx)->abort = 1;
    ss_info(sci_idx)->exit_status = code;
    
}

int ss_quit(argc, argv, sci_idx, infop)
    int argc;
    char **argv;
    int sci_idx;
    pointer infop;
{
    ss_abort_subsystem(sci_idx, 0);
}
