/*
 * Copyright 1993-1994 OpenVision Technologies, Inc., All Rights Reserved.
 * 
 * $Header$
 *
 *
 */

static char rcsid_2[] = "$Id$";

#include <kadm5/admin.h>
#include <krb5.h>

#include "kpasswd_strings.h"
#define string_text error_message
#define initialize_kpasswd_strings initialize_kpws_error_table

#include <stdio.h>
#include <pwd.h>
#include <string.h>

char *whoami;

#include <Xm/Xm.h>
#include <Xm/MessageB.h>
#include <Xm/ScrolledW.h>
#include <Xm/Form.h>
#include <Xm/Text.h>
#include <Xm/PushB.h>
#include <Xm/Label.h>
#include <Xm/Separator.h>
#include <X11/cursorfont.h>
#include <X11/Shell.h>

Widget toplevel, scroll_text, prompt_text;
Widget quit_btn, help_btn, old_lbl, new_lbl, again_lbl, main_lbl;
XtAppContext app_con;
int looping;
int retval=0;


/***************************************************************************
 *
 *  A few utility functions for setting/unsetting the busy cursor
 *  (i.e. the watch cursor).
 */
static void
SetCursor(w,c)
     Widget w;
     Cursor c;
{
  while (XtIsSubclass(w, shellWidgetClass) != True)
    w = XtParent(w);

  XDefineCursor(XtDisplay(w), XtWindow(w), c);
  XFlush(XtDisplay(w));
}

 
static void
SetStandardCursor()
{
  static Cursor ArrowCursor = (Cursor)NULL;
 
  if (ArrowCursor == (Cursor)NULL)
    ArrowCursor = XCreateFontCursor(XtDisplay(toplevel), XC_top_left_arrow);
  SetCursor(toplevel, ArrowCursor);
}

 
static void
SetWatchCursor()
{
  static Cursor WatchCursor = (Cursor)NULL;

  if (WatchCursor == (Cursor)NULL)
    WatchCursor = XCreateFontCursor(XtDisplay(toplevel), XC_watch);
  SetCursor(toplevel, WatchCursor);
}


/***************************************************************************
 *
 *  Set up a com_err hook, for displaying to a motif scrolling widget.
 */

#if __STDC__
#	include <stdarg.h>
#else /* varargs: not STDC or no <stdarg> */
	/* Non-ANSI, always take <varargs.h> path. */
#	undef VARARGS
#	define VARARGS 1
#	include <varargs.h>
#endif /* varargs */

static void
#ifdef __STDC__
motif_com_err (const char *whoami, long code, const char *fmt, va_list args)
#else
motif_com_err (whoami, code, fmt, args)
    const char *whoami;
    long code;
    const char *fmt;
    va_list args;
#endif
{
  XEvent event;
  char buf[2048];

  buf[0] = '\0';

  if (whoami)
    {
      strncpy(buf, whoami, sizeof(buf) - 1);
      buf[sizeof(buf) - 1] = '\0';
      strncat(buf, ": ", sizeof(buf) - 1 - strlen(buf));
    }
  if (code)
    {
      buf[sizeof(buf) - 1] = '\0';
      strncat(buf, error_message(code), sizeof(buf) - 1 - strlen(buf));
      strncat(buf, " ", sizeof(buf) - 1 - strlen(buf));
    }
  if (fmt)
    {
      vsprintf(buf + strlen(buf), fmt, args);
    }

  XtVaSetValues(scroll_text, XmNvalue, buf, NULL);

  for (; XtAppPending(app_con); )
    {
      XtAppNextEvent(app_con, &event);
      XtDispatchEvent(&event);
    }
}


/***************************************************************************
 *
 *  Function to display help widget.
 */
static void
help()
{
  static Widget help_dlg = NULL;

  if (!help_dlg)
    {
      help_dlg = XmCreateInformationDialog(toplevel, "help_dlg", NULL,
					   0);
      XtUnmanageChild(XmMessageBoxGetChild(help_dlg, XmDIALOG_CANCEL_BUTTON));
      XtUnmanageChild(XmMessageBoxGetChild(help_dlg, XmDIALOG_HELP_BUTTON));
    }
  XtManageChild(help_dlg);
}


/***************************************************************************
 *
 *  Unset the global "looping" when we want to get out of reading a
 *  password.
 */
static void
unset_looping()
{
  looping = 0;
}


/***************************************************************************
 *
 *  Function to exit the gui.  Callback on the "Exit" button.
 */
static void
quit()
{
  exit(retval);
}


/***************************************************************************
 *
 *  Set up motif widgets, callbacks, etc.
 */
static void
create_widgets(argc, argv)
     int *argc;
     char *argv[];
{
  Widget form, lbl_form,
  	sep,
  	scroll_win;
  Pixel bg;

  toplevel = XtAppInitialize(&app_con, "Kpasswd", NULL, 0, argc, argv,
			     NULL, NULL, 0);
  form = XtCreateManagedWidget("form", xmFormWidgetClass, toplevel, NULL, 0);
  quit_btn = XtVaCreateManagedWidget("Quit", xmPushButtonWidgetClass,
				form,
				XmNleftAttachment, XmATTACH_FORM,
				XmNbottomAttachment, XmATTACH_FORM,
				NULL);
  XtAddCallback(quit_btn, XmNactivateCallback, quit, 0);
  help_btn = XtVaCreateManagedWidget("Help", xmPushButtonWidgetClass,
				form,
				XmNrightAttachment, XmATTACH_FORM,
				XmNbottomAttachment, XmATTACH_FORM,
				/* XmNshowAsDefault, TRUE, */
				NULL);
  XtAddCallback(help_btn, XmNactivateCallback, help, 0);
  sep = XtVaCreateManagedWidget("sep", xmSeparatorWidgetClass,
				form,
				XmNleftAttachment, XmATTACH_FORM,
				XmNrightAttachment, XmATTACH_FORM,
				XmNbottomAttachment, XmATTACH_WIDGET,
				XmNbottomWidget, quit_btn,
				NULL);
  lbl_form = XtVaCreateManagedWidget("lbl_form", xmFormWidgetClass,
				form,
				XmNspacing, 0,
				XmNleftAttachment, XmATTACH_FORM,
				XmNbottomAttachment, XmATTACH_WIDGET,
				XmNbottomWidget, sep,
				NULL);
  old_lbl = XtVaCreateManagedWidget("old_lbl", xmLabelWidgetClass,
				lbl_form,
				XmNtopAttachment, XmATTACH_FORM,
				XmNleftAttachment, XmATTACH_FORM,
				XmNrightAttachment, XmATTACH_FORM,
				XmNbottomAttachment, XmATTACH_FORM,
				NULL);
  new_lbl = XtVaCreateManagedWidget("new_lbl", xmLabelWidgetClass,
				lbl_form,
				XmNtopAttachment, XmATTACH_FORM,
				XmNleftAttachment, XmATTACH_FORM,
				XmNrightAttachment, XmATTACH_FORM,
				XmNbottomAttachment, XmATTACH_FORM,
				NULL);
  again_lbl = XtVaCreateManagedWidget("again_lbl", xmLabelWidgetClass,
				lbl_form,
				XmNtopAttachment, XmATTACH_FORM,
				XmNleftAttachment, XmATTACH_FORM,
				XmNrightAttachment, XmATTACH_FORM,
				XmNbottomAttachment, XmATTACH_FORM,
				NULL);
  prompt_text = XtVaCreateManagedWidget("prompt_text", xmTextWidgetClass,
				form,
				XmNeditMode, XmSINGLE_LINE_EDIT,
				XmNleftAttachment, XmATTACH_WIDGET,
				XmNleftWidget, lbl_form,
				XmNrightAttachment, XmATTACH_FORM,
				XmNbottomAttachment, XmATTACH_WIDGET,
				XmNbottomWidget, sep,
				NULL);
  XtAddCallback(prompt_text, XmNactivateCallback, unset_looping, 0);
  XtVaGetValues(prompt_text, XmNbackground, &bg, NULL);
  XtVaSetValues(prompt_text, XmNforeground, bg, NULL);

  main_lbl = XtVaCreateWidget("main_lbl", xmLabelWidgetClass,
				form,
				XmNtopAttachment, XmATTACH_FORM,
				XmNleftAttachment, XmATTACH_FORM,
				XmNrightAttachment, XmATTACH_FORM,
				NULL);
  scroll_win = XtVaCreateManagedWidget("scroll_win",
				xmScrolledWindowWidgetClass,
				form,
				XmNscrollingPolicy, XmAPPLICATION_DEFINED,
				XmNscrollBarDisplayPolicy, XmSTATIC,
				XmNtopAttachment, XmATTACH_WIDGET,
				XmNtopWidget, main_lbl,
				XmNleftAttachment, XmATTACH_FORM,
				XmNrightAttachment, XmATTACH_FORM,
				XmNbottomAttachment, XmATTACH_WIDGET,
				XmNbottomWidget, prompt_text,
				NULL);
  scroll_text = XtVaCreateManagedWidget("scroll_text", xmTextWidgetClass,
				scroll_win,
				XmNeditMode, XmMULTI_LINE_EDIT,
				XmNeditable, FALSE,
				NULL);
  XtRealizeWidget(toplevel);
}


/***************************************************************************
 *
 *  
 */
static long
read_password(password, pwsize)
     char *password;
     int *pwsize;
{
  XEvent event;
  char *text_val;

  /* OK, this next part is gross...  but this is due to the fact that	*/
  /* this is not your traditional X program, which would be event	*/
  /* driven.  Instead, this program is more 'CLI' in nature, so we	*/
  /* handle the dialogs synchronously... 				*/

  XtVaSetValues(prompt_text, XmNmaxLength, *pwsize, XmNvalue, "", NULL);
  for (looping=1; looping; )
    {
      XtAppNextEvent(app_con, &event);
      XtDispatchEvent(&event);
    }
  XtVaGetValues(prompt_text, XmNvalue, &text_val, NULL);
  *pwsize = strlen(text_val);
  strcpy(password, text_val);
  memset(text_val, 0, *pwsize);
  XtVaSetValues(prompt_text, XmNvalue, text_val, NULL);
  return(0);
}
  

/***************************************************************************
 *
 *  
 */
void
display_intro_message(fmt_string, arg_string)
     char *fmt_string;
     char *arg_string;
{
  XmString xmstr;
  char buf[1024];

  sprintf(buf, fmt_string, arg_string);

  xmstr = XmStringCreateLtoR(buf, XmSTRING_DEFAULT_CHARSET);
  XtVaSetValues(main_lbl, XmNlabelString, xmstr, NULL);
  XmStringFree(xmstr);
  XtManageChild(main_lbl);
}


long
read_old_password(context, password, pwsize)
     krb5_context context;
     char *password;
     int *pwsize;
{
  long code;

  XtManageChild(old_lbl);
  code = read_password(password, pwsize);
  SetWatchCursor();
  return code;
}

long
read_new_password(server_handle, password, pwsize, msg_ret, princ)
     void *server_handle;
     char *password;
     int *pwsize;
     char *msg_ret;
     krb5_principal princ;
{
  char *password2 = (char *) malloc(*pwsize * sizeof(char));
  int pwsize2 = *pwsize;

  SetStandardCursor();

  if (password2 == NULL)
    {
      strcpy(msg_ret, error_message(ENOMEM));
      SetWatchCursor();
      return(ENOMEM);
    }

  XtManageChild(new_lbl); XtUnmanageChild(old_lbl);
  read_password(password, pwsize);
  XtManageChild(again_lbl); XtUnmanageChild(new_lbl);
  read_password(password2, &pwsize2);

  if (strcmp(password, password2))
    {
      memset(password, 0, *pwsize);

      memset(password2, 0, pwsize2);
      free(password2);
      
      strcpy(msg_ret, string_text(CHPASS_UTIL_NEW_PASSWORD_MISMATCH));
      SetWatchCursor();
      return(KRB5_LIBOS_BADPWDMATCH);
    }

  memset(password2, 0, pwsize2);
  free(password2);

  SetWatchCursor();
  return (ovsec_kadm_chpass_principal_util(server_handle, princ, password,
                                            NULL /* don't need new pw back */,
                                            msg_ret));
}
  

/***************************************************************************
 *
 *
 */
void
main(argc, argv)
     int argc;
     char *argv[];
{
  krb5_context context;
  int code;

  initialize_kpasswd_strings();

  whoami = (whoami = strrchr(argv[0], '/')) ? whoami + 1 : argv[0];

  (void) set_com_err_hook(motif_com_err);

  create_widgets(&argc, argv);
  XmProcessTraversal(prompt_text, XmTRAVERSE_CURRENT);

  if (retval = krb5_init_context(&context)) {
       com_err(whoami, retval, "initializing krb5 context");
       exit(retval);
  }

  while (1)
    {
      retval = kpasswd(context, argc, argv);
      SetStandardCursor();

      if (!retval)
	com_err(0, 0, string_text(KPW_STR_PASSWORD_CHANGED));

      if (retval == 0)		/* 0 is success, so presumably the user */
				/* is done. */
	XmProcessTraversal(quit_btn, XmTRAVERSE_CURRENT);

      if ((retval == 1) ||	/* the rest are "fatal", so we should */
	  (retval == 3) ||	/* "force" the user to quit... */
	  (retval == 6) ||
	  (retval == 7))
	{
	  XtSetSensitive(prompt_text, FALSE);
	  XmProcessTraversal(quit_btn, XmTRAVERSE_CURRENT);
	  XtAppMainLoop(app_con);
	}
    }

  /* NOTREACHED */
  exit(retval);
}
