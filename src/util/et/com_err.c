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

#if defined(_MSDOS) || defined(_WIN32)
#include <io.h>
#endif
#ifdef macintosh
#include "icons.h"
static void MacMessageBox(char *errbuf);
#endif

static et_old_error_hook_func com_err_hook = 0;

static void default_com_err_proc
ET_P((const char FAR *whoami, errcode_t code,
	const char FAR *fmt, va_list ap));

static void default_com_err_proc(whoami, code, fmt, ap)
	const char FAR *whoami;
	errcode_t code;
	const char FAR *fmt;
	va_list ap;
{
#if defined(_MSDOS) || defined(_WIN32) || defined(macintosh)

	char errbuf[1024] = "";

	if (whoami) {
		strcat (errbuf, whoami);
		strcat (errbuf, ": ");
	}
	if (code) {
		strcat (errbuf, error_message(code));
		strcat (errbuf, " ");
	}
	if (fmt)
		vsprintf (errbuf + strlen (errbuf), fmt, ap);

#ifdef macintosh
	MacMessageBox(errbuf);
#else
#ifdef _WIN32
	if (_isatty(_fileno(stderr))) {
	    fputs(errbuf, stderr);
	    fputc('\r', stderr);
	    fputc('\n', stderr);
	    fflush(stderr);
	} else
#endif /* _WIN32 */
	    MessageBox ((HWND)NULL, errbuf, "Kerberos", MB_ICONEXCLAMATION);
#endif /* macintosh */

#else /* !_MSDOS && !_WIN32 && !macintosh */
    
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

KRB5_DLLIMP void KRB5_CALLCONV com_err_va(whoami, code, fmt, ap)
	const char FAR *whoami;
	errcode_t code;
	const char FAR *fmt;
	va_list ap;
{
	if (!com_err_hook)
		default_com_err_proc(whoami, code, fmt, ap);
	else
	  (com_err_hook)(whoami, code, fmt, ap);
}


#ifndef ET_VARARGS
KRB5_DLLIMP void KRB5_CALLCONV_C com_err(const char FAR *whoami,
					 errcode_t code,
					 const char FAR *fmt, ...)
#else
KRB5_DLLIMP void KRB5_CALLCONV_C com_err(whoami, code, fmt, va_alist)
	const char FAR *whoami;
	errcode_t code;
	const char FAR *fmt;
	va_dcl
#endif
{
	va_list ap;

#ifdef ET_VARARGS
	va_start(ap);
#else
	va_start(ap, fmt);
#endif
	com_err_va(whoami, code, fmt, ap);
	va_end(ap);
}

#if !(defined(_MSDOS)||defined(_WIN32))
et_old_error_hook_func set_com_err_hook (new_proc)
	et_old_error_hook_func new_proc;
{
	et_old_error_hook_func x = com_err_hook;

	com_err_hook = new_proc;
	return x;
}

et_old_error_hook_func reset_com_err_hook ()
{
	et_old_error_hook_func x = com_err_hook;
    
	com_err_hook = 0;
	return x;
}
#endif

#ifdef macintosh
static void MacMessageBox(errbuf)
	char *errbuf;
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
	long		gestaltResult;
	OSErr		theError;

	/* Find Centered rect for window */
	tmpRect.top	= ((mainRect.bottom + mainRect.top)/2 -
			   (errRect.bottom + errRect.top)/2);
	tmpRect.bottom = tmpRect.top + (errRect.bottom - errRect.top);
	tmpRect.left = ((mainRect.right + mainRect.left)/2 -
			(errRect.right + errRect.left)/2);
	tmpRect.right = tmpRect.left + (errRect.right - errRect.left);

	/* Create the error window - as a dialog window */
	/* First check if we have color QuickDraw */
	/* (we can assume we have Gestalt because we are on system 7) */
	theError = Gestalt (gestaltQuickdrawFeatures, &gestaltResult);
	if ((theError == noErr) && (gestaltResult & (1 << gestaltHasColor) != 0))
		errWindow = NewCWindow(NULL, &tmpRect, "\p", TRUE, dBoxProc, (WindowPtr) -1, FALSE, 0L);
	else
		errWindow = NewWindow(NULL, &tmpRect, "\p", TRUE, dBoxProc, (WindowPtr) -1, FALSE, 0L);

	SetPort(errWindow);
	TextFont(systemFont);
	TextSize(12);

	errOkButton = NewControl(errWindow, &errOkButtonRect,
				 "\pOk", TRUE, 0, 0, 1, pushButProc, 0L);
      DrawControls(errWindow);
	InsetRect(&errOkButtonRect, -4, -4);
	PenSize(3,3);
	FrameRoundRect(&errOkButtonRect, 15,15);
	PenSize(1,1);
	InsetRect(&errOkButtonRect, 4, 4);

	/* Draw the error text */
	TETextBox(errbuf, strlen(errbuf), &errTextRect, teForceLeft);

	/* Draw the Stop icon */
	PlotIcon(&errIconRect, GetResource('ICON', 0));

	/* mini event loop here */
	done = FALSE;
	while(!done) {
		WaitNextEvent(mDownMask | mUpMask | keyDownMask, &theEvent, 15, nil);
		if (theEvent.what == mouseDown) {
			localPt = theEvent.where;
			GlobalToLocal(&localPt);
			if (TestControl(errOkButton, localPt) &&
			    TrackControl(errOkButton, localPt, NULL)) {
				done = TRUE;
			}
		} else if (theEvent.what == keyDown &&
			   (theEvent.message & 0xff) == 0x0d ||	/* CR */
			   (theEvent.message & 0xff) == 0x03 ||	/* Enter */
			   (theEvent.message & 0xff) == 0x1b) {	/* Escape */
			long t;
			/* Hilite the button for a bit */
			HiliteControl(errOkButton, 1);	
			Delay(5, &t);
			/* Dehilite the button */
			HiliteControl(errOkButton, 0);
			done = TRUE;
		}
	}

	/* Dispose of the Window, disposes of controls */
	DisposeWindow(errWindow);
}
#endif
