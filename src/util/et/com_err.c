/*
 * Copyright 1987, 1988 by MIT Student Information Processing Board.
 *
 * For copyright info, see mit-sipb-copyright.h.
 */

#include <stdio.h>
#include <string.h>
#include "mit-sipb-copyright.h"

#if defined(HAVE_STDARG_H) || defined(_WINDOWS) || defined (_MACINTOSH)
#include <stdarg.h>
#else
#include <varargs.h>
#define VARARGS
#endif

#ifdef _MACINTOSH
#include "icons.h"
#endif

#include "error_table.h"
#include "internal.h"

#ifdef notdef
/*
 * Protect us from header version (externally visible) of com_err, so
 * we can survive in a <varargs.h> environment.  I think.
 */
#define com_err com_err_external
#include "com_err.h"
#undef com_err
#endif

/* We have problems with varargs definitions if we include com_err.h */

/*
 * XXX for now, we define error_message by hand.  Ultimately, we
 * should fix up com_err.h so that it's safe to #include here 
 * directly.
 */
#if defined(__STDC__) || defined(_WINDOWS)
extern char const * INTERFACE error_message (long);
#else
extern char * INTERFACE error_message ();
#endif

static void
#if defined(__STDC__) || defined(_WINDOWS)
    default_com_err_proc (const char *whoami, long code, const char *fmt, va_list args)
#else
    default_com_err_proc (whoami, code, fmt, args)
    const char *whoami;
    long code;
    const char *fmt;
    va_list args;
#endif
{
    static char errbuf[1024];                   /* For those w/o stdio */

    *errbuf = '\0';
    if (whoami) {
	strcat (errbuf, whoami);
	strcat (errbuf, ": ");
    }
    if (code) {
	strcat (errbuf, error_message(code));
	strcat (errbuf, " ");
    }
    if (fmt) {
        vsprintf (errbuf + strlen (errbuf), fmt, args);
    }
#ifdef _WINDOWS
    MessageBox (NULL, errbuf, "Kerboros", MB_ICONEXCLAMATION);
#else
#ifdef _MACINTOSH
{
WindowPtr	errWindow;
ControlHandle	errOkButton;
Rect		errOkButtonRect = { 120, 220, 140, 280 };
Rect		errRect = { 0, 0, 150, 300 };
GDHandle	mainDevice = GetMainDevice();
Rect		mainRect = (**mainDevice).gdRect;
Rect		tmpRect;
Rect		errTextRect = { 10, 70, 110, 290 };
Rect		errIconRect = { 10, 10, 10 + 32, 10 + 32 };
EventRecord	theEvent;
Point		localPt;
Boolean		done;

	/* Find Centered rect for window */
	tmpRect.top	= (mainRect.bottom + mainRect.top)/2 - (errRect.bottom + errRect.top)/2;
	tmpRect.bottom = tmpRect.top + (errRect.bottom - errRect.top);
	tmpRect.left = (mainRect.right + mainRect.left)/2 - (errRect.right + errRect.left)/2;
	tmpRect.right = tmpRect.left + (errRect.right - errRect.left);

	/* Create the error window - as a dialog window */
	errWindow = NewWindow(NULL, &tmpRect, "\p", TRUE, dBoxProc, (WindowPtr) -1, FALSE, 0L);

	SetPort(errWindow);
	TextFont(systemFont);
	TextSize(12);

	errOkButton = NewControl(errWindow,&errOkButtonRect,"\pOk",TRUE,0,0,1,pushButProc,0L);
	DrawControls(errWindow);

	/* Draw the error text */
	TextBox(errbuf, strlen(errbuf), &errTextRect, teForceLeft);

	/* Draw the Stop icon */
	PlotIcon(&errIconRect, GetResource('ICON', 0));

	/* mini event loop here */
	done = FALSE;
	while(!done)
	{
		GetNextEvent(mDownMask | mUpMask, &theEvent);
		if (theEvent.what == mouseDown)
		{
			localPt = theEvent.where;
			GlobalToLocal(&localPt);
			if (TestControl(errOkButton, localPt) && TrackControl(errOkButton, localPt, NULL))
			{
				done = TRUE;
			}
		}
	}

	/* Dispose of the Window, disposes of controls */
	DisposeWindow(errWindow);
}
#else
    fputs (errbuf, stderr);
    /* should do this only on a tty in raw mode */
    putc('\r', stderr);
    putc('\n', stderr);
    fflush(stderr);
#endif
#endif
}

#if defined(__STDC__) || defined(_WINDOWS)
typedef void (*errf) (const char *, long, const char *, va_list);
#else
typedef void (*errf) ();
#endif

errf com_err_hook = default_com_err_proc;

void com_err_va (whoami, code, fmt, args)
    const char *whoami;
    long code;
    const char *fmt;
    va_list args;
{
    (*com_err_hook) (whoami, code, fmt, args);
}

#ifndef VARARGS
void INTERFACE_C com_err (const char *whoami,
	      long code,
	      const char *fmt, ...)
{
#else
void INTERFACE_C com_err (va_alist)
    va_dcl
{
    const char *whoami, *fmt;
    long code;
#endif
    va_list pvar;

    if (!com_err_hook)
	com_err_hook = default_com_err_proc;
#ifdef VARARGS
    va_start (pvar);
    whoami = va_arg (pvar, const char *);
    code = va_arg (pvar, long);
    fmt = va_arg (pvar, const char *);
#else
    va_start(pvar, fmt);
#endif
    com_err_va (whoami, code, fmt, pvar);
    va_end(pvar);
}

errf set_com_err_hook (new_proc)
    errf new_proc;
{
    errf x = com_err_hook;

    if (new_proc)
	com_err_hook = new_proc;
    else
	com_err_hook = default_com_err_proc;

    return x;
}

errf reset_com_err_hook () {
    errf x = com_err_hook;
    com_err_hook = default_com_err_proc;
    return x;
}
