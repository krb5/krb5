/*
 * Copyright 1997 by Massachusetts Institute of Technology
 * 
 * Copyright 1987, 1988 by MIT Student Information Processing Board
 *
 * Permission to use, copy, modify, and distribute this software
 * and its documentation for any purpose and without fee is
 * hereby granted, provided that the above copyright notice
 * appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation,
 * and that the names of M.I.T. and the M.I.T. S.I.P.B. not be
 * used in advertising or publicity pertaining to distribution
 * of the software without specific, written prior permission.
 * Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. and the M.I.T. S.I.P.B. make no representations about
 * the suitability of this software for any purpose.  It is
 * provided "as is" without express or implied warranty.
 */

#include <stdio.h>
#include <string.h>

#include "com_err.h"
#include "error_table.h"

#if defined(_WIN32)
#include <io.h>
#endif

static /*@null@*/ et_old_error_hook_func com_err_hook = 0;

static void default_com_err_proc (const char *whoami, errcode_t code,
				  const char *fmt, va_list ap)
{
#if defined(_WIN32)

	char errbuf[1024] = "";

	if (whoami) {
		errbuf[sizeof(errbuf) - 1] = '\0';
		strncat (errbuf, whoami, sizeof(errbuf) - 1 - strlen(errbuf));
		strncat (errbuf, ": ", sizeof(errbuf) - 1 - strlen(errbuf));
	}
	if (code) {
		errbuf[sizeof(errbuf) - 1] = '\0';
		strncat (errbuf, error_message(code), sizeof(errbuf) - 1 - strlen(errbuf));
		strncat (errbuf, " ", sizeof(errbuf) - 1 - strlen(errbuf));
	}
	if (fmt)
	    /* ITS4: ignore vsprintf */
	    vsprintf (errbuf + strlen (errbuf), fmt, ap);
	errbuf[sizeof(errbuf) - 1] = '\0';

#ifdef _WIN32
	if (_isatty(_fileno(stderr))) {
	    fputs(errbuf, stderr);
	    fputc('\r', stderr);
	    fputc('\n', stderr);
	    fflush(stderr);
	} else
#endif /* _WIN32 */
	    MessageBox ((HWND)NULL, errbuf, "Kerberos", MB_ICONEXCLAMATION);

#else /* !_WIN32 */
    
	if (whoami) {
		fputs(whoami, stderr);
		fputs(": ", stderr);
	}
	if (code) {
		fputs(error_message(code), stderr);
		fputs(" ", stderr);
	}
	if (fmt) {
		vfprintf(stderr, fmt, ap);
	}
	/* should do this only on a tty in raw mode */
	putc('\r', stderr);
	putc('\n', stderr);
	fflush(stderr);

#endif
}

void KRB5_CALLCONV com_err_va(const char *whoami,
			      errcode_t code,
			      const char *fmt,
			      va_list ap)
{
	if (!com_err_hook)
		default_com_err_proc(whoami, code, fmt, ap);
	else
	  (com_err_hook)(whoami, code, fmt, ap);
}


void KRB5_CALLCONV_C com_err(const char *whoami,
			     errcode_t code,
			     const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	com_err_va(whoami, code, fmt, ap);
	va_end(ap);
}

#if !(defined(_WIN32))
et_old_error_hook_func set_com_err_hook (et_old_error_hook_func new_proc)
{
	et_old_error_hook_func x = com_err_hook;

	com_err_hook = new_proc;
	return x;
}

et_old_error_hook_func reset_com_err_hook ()
{
	et_old_error_hook_func x = com_err_hook;
    
	com_err_hook = NULL;
	return x;
}
#endif
