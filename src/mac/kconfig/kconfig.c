/*
 * Copyright 1991-1994 by The University of Texas at Austin
 * All rights reserved.
 *
 * For infomation contact:
 * Rick Watson
 * University of Texas
 * Computation Center, COM 1
 * Austin, TX 78712
 * r.watson@utexas.edu
 * 512-471-3241
 */

/*
 * Kconfig
 */


/* #define SAPTIMEBOMB 1 */

#include <stdio.h>
#include <Sound.h>
#ifndef __MWERKS__
#include <Controls.h>
#include <Desk.h>
#include <DiskInit.h>
#include <Devices.h>
#include <Dialogs.h>
#include <Errors.h>
#include <Events.h>
#include <Folders.h>
#include <Fonts.h>
#include <GestaltEqu.h>
#include <Lists.h>
#include <Memory.h>
#include <Menus.h>
#include <Notification.h>
#include <OSEvents.h>
#include <OSUtils.h>
#include <Packages.h>
#include <Printing.h>
#include <QuickDraw.h>
#include <Resources.h>
#include <Scrap.h>
#include <Script.h>
#include <StdArg.h>
#include <StdLib.h>
#include <String.h>
#include <Strings.h>
#include <SysEqu.h>
#include <TextEdit.h>
#include <ToolUtils.h>
#include <Traps.h>
#include <Windows.h>
#include <StdLib.h>

#define TRUE 1
#define FALSE 0
#endif

#define CELLH 12						/* list cell height */

#ifdef KRB4
#	define	DEFINE_SOCKADDR
#	include "krb.h"
#	include "kconfig.h"
#	include "kconfig.proto.h"
#	include "krb_driver.h"
#	include "kconfig.vers"
#	include "glue.h"
#	include "bsd-mac-compat.h"
#	include "testtrack.h"
#endif

#ifdef KRB5
#	include "k5-int.h"
#	include "com_err.h"
#	include "kconfig.h"
#	include "kconfig.proto.h"
#	include "kconfig.vers"
#	include "prof_int.h"
#	include "adm_proto.h"
//#	include "bsd-mac-compat.h"
#	include "testtrack.h"
#endif

#include "WindowUtil.h"

#define num_WaitNextEvent	0x60
#define num_JugglDispatch	0x8F	/* The Temp Memory calls (RWR) */
#define num_UnknownTrap		0x9F
#define num_ScriptTrap		0xBF
#define switchEvt	 1 /* Switching event (suspend/resume )	 for app4evt */

//#define dangerousPattern 1
#define KFAILURE 255
#define KSUCCESS 0

// Timebomb info
#define TBALERTID	135
#define TB30ALERTID	136


	//  IH 05.03.96: PPC Port, must use UPPs instead of Procedure Ptrs
static DeviceLoopDrawingUPP	gpictdrawprocUPP = NULL;
static ModalFilterUPP 		gklistFilterUPP = NULL;
static ModalFilterUPP		gokFilterUPP = NULL;
static ModalFilterUPP		ginternalBufferFilterUPP = NULL;
static UserItemUPP			gdooutlineUPP = NULL;
static UserItemUPP			gdopictUPP = NULL;
static UserItemUPP			gdrawRealmUPP = NULL;
static UserItemUPP			gdolistUPP = NULL;

OSErr GetUserInfo( char *UserName, char *password );

/*
 * Globals
 */
#ifdef KRB4
	krbHiParmBlock khipb;
	krbParmBlock klopb;
	/* We use the mac stubs to open the driver. */
#	define	kdriver	mac_stubs_kdriver		/* .Kerberos driver reference */
#endif

#ifdef KRB5
	krb5_context kcontext;
	krb5_ccache k5_ccache;
    static char ccname[FILENAME_MAX] = "ccredcache";           /* ccache file location */
#endif

MenuHandle menus[NUM_MENUS];
DialogPtr maind = 0;					/* main dialog window */
Rect oldzoom;
ParamBlockRec pb;
queuetype domainQ = 0;
queuetype serverQ = 0;
queuetype credentialsQ = 0;
ListHandle dlist;						/* domain list */
ListHandle slist;						/* server list */
struct listfilter lf;					/* lf for maind */
/* Add the 'new' handle so we can disable the control for the SAP release */
Handle dnewHandle, ddeleteHandle, deditHandle;
Handle snewHandle, sdeleteHandle, seditHandle;
Handle passwordHandle;
preferences prefs;						/* preferences */

#ifdef KRB4
char *prefsFilename = "\pCNS Config Preferences";
#endif

#ifdef KRB5
char *prefsFilename = "\pCNSk5 Config Preferences";
#define kUNKNOWNUSERNAME "Unknown"
char gUserName[255];					/* last user name */
char gRealmName[255];					/* last realm name */
#endif

/*+
 * Function: Initializes ccache and catches illegal caches such as
 *  bad format or no permissions.
 *
 * Parameters:
 *  ccache - credential cache structure to use
 *
 * Returns: krb5_error_code
 */
static krb5_error_code
k5_init_ccache (krb5_ccache *ccache) {
    krb5_error_code code;
    krb5_principal princ;
    FILE *fp;

	strcpy(gUserName, kUNKNOWNUSERNAME);

    code = krb5_cc_default (kcontext, ccache); // Initialize the ccache
    if (code)
        return code;

    code = krb5_cc_get_principal (kcontext, *ccache, &princ);
    if (code == KRB5_FCC_NOFILE) {              // Doesn't exist yet
        fp = fopen (krb5_cc_get_name(kcontext, *ccache), "w");
        if (fp == NULL)                         // Can't open it
            return KRB5_FCC_PERM;
        fclose (fp);
    } else if ( code == noErr ) {
    	strcpy(gUserName, princ->data->data);
		strcpy(gRealmName, princ->realm.data);
	} 

    if (code) {                                 // Bad, delete and try again
        remove (krb5_cc_get_name(kcontext, *ccache));
        code = krb5_cc_get_principal (kcontext, *ccache, &princ);
        if (code == KRB5_FCC_NOFILE)            // Doesn't exist yet
            return 0;
        if (code)
            return code;
    }

    krb5_free_principal (kcontext, princ);
    return 0;
}

int main (void)
{
	int i, s;
	MenuHandle 		menuhandle;
	
#ifdef SAPTIMEBOMB
	DateTimeRec		goalTimeBomb;
	long			currentTime, goalTimeBombInSecs;
#endif
#ifdef KRB5
	krb5_error_code code;
#endif
	

	/*	
	 * Setup
	 */
	InitGraf (&qd.thePort); /* Init the graf port */
	InitFonts();
	InitWindows();
	InitMenus();
	TEInit();
	InitDialogs(0);
	InitCursor();
	FlushEvents(everyEvent, 0);

#ifdef SAPTIMEBOMB
	goalTimeBomb.year = 1997;
	goalTimeBomb.month = 6;
	goalTimeBomb.day = 1;
	goalTimeBomb.hour = 0; /* Let's use midnight for simplicity */
	goalTimeBomb.minute = 0;
	goalTimeBomb.second = 0;
	
	DateToSeconds( &goalTimeBomb, &goalTimeBombInSecs );
	
	GetDateTime(&currentTime);
	
	if ( (goalTimeBombInSecs - currentTime) <= 0 ) {
		StopAlert(TBALERTID, NULL);
		ExitToShell();
    } else if ( (goalTimeBombInSecs - currentTime) < 1209600 ) { /* num seconds in 14 days */
		NoteAlert(TB30ALERTID, NULL);
	}
#endif

#ifdef KRB4
	init_cornell_des();
#endif
#ifdef KRB5
    code = krb5_init_context(&kcontext);
    if (code)
    {
    	doalert("Kerberos configuration file not present");
    	getout(0);
    }
#endif

#ifdef KRB5
	k5_init_ccache (&k5_ccache);
	/*strcpy(gUserName, kUNKNOWNUSERNAME);*/
#endif
	
		//  IH 05.03.95: Create the UPPs for ToolBox callback routines
	gpictdrawprocUPP = NewDeviceLoopDrawingProc(pictdrawproc);
	if (gpictdrawprocUPP == NULL)
		doalert("Error creating a Universal Proc Pointer");
	gklistFilterUPP = NewModalFilterProc(klistFilter);
	if (gklistFilterUPP == NULL)
		doalert("Error creating a Universal Proc Pointer");
	gokFilterUPP = NewModalFilterProc(okFilter);
	if (gokFilterUPP == NULL)
		doalert("Error creating a Universal Proc Pointer");
	ginternalBufferFilterUPP = NewModalFilterProc(internalBufferFilter);
	if (ginternalBufferFilterUPP == NULL)
		doalert("Error creating a Universal Proc Pointer");
	gdooutlineUPP = NewUserItemProc(dooutline);	
	if (gdooutlineUPP == NULL)
		doalert("Error creating a Universal Proc Pointer");
	gdopictUPP = NewUserItemProc(dopict);	
	if (gdopictUPP == NULL)
		doalert("Error creating a Universal Proc Pointer");
	gdrawRealmUPP = NewUserItemProc(drawRealm);	
	if (gdrawRealmUPP == NULL)
		doalert("Error creating a Universal Proc Pointer");
	gdolistUPP = NewUserItemProc(dolist);	
	if (gdolistUPP == NULL)
		doalert("Error creating a Universal Proc Pointer");

	readprefs();
	
	/*
	 *	Setup the menus.  Assumes the menu resources start at 128 and are
	 *	contiguous.
	 */
	for (i = 0; i < NUM_MENUS; i++) {
		menuhandle = GetMenu(i + MENU_OFFSET);
		if (menuhandle == 0) 
			break;

		if (i < MENU_SUBMENUS)			/* if not a submenu */
			InsertMenu(menuhandle, 0);
		else
			InsertMenu(menuhandle, -1);
		menus[i] = menuhandle;
	}
	AppendResMenu (menus[APPL_MENU], 'DRVR');
	DrawMenuBar();

#ifdef KRB4
	s = krb_start_session((char *)0);
	if (s != KSUCCESS) {
		doalert("Kerberos driver is not installed");
		getout(0);
	}
#endif


	/*
	 * build the main window
	 */
	bzero(&oldzoom, sizeof(oldzoom));
#ifdef KRB4
	getRealmMaps();
	getServerMaps();
#endif
#ifdef KRB5
	getServerMaps();	/* Get Servers first */
	getRealmMaps();		/* Need servers to get realms */
#endif

	buildmain();

	/*
	 * Run the main event loop.
	 */
	mainEvent();
}


/*
 * mainEvent
 * The main event loop.
 */
void mainEvent ()
{
	int s, state;
	int aborted;
	int in_background;
	int running = TRUE;
	unsigned long curtime;
	short item;
	EventRecord event;
	DialogPtr mydlg;
	Point cell;
	
	while (running) {
		WaitNextEvent (everyEvent, &event, 30, NULL);
		
		/*
		 * Update display items.
		 */
		updatedisplay();

		/*
		 * Set the state of the edit and delete buttons depending on if any
		 * cells are selected or not.
		 */
		SetPt(&cell, 0, 0);
		/* disabled for SAP release */
	/*	if (LGetSelect(true, &cell, dlist))
			state = 0;
		else*/
			state = 255;					/* disable */
		HiliteControl((ControlHandle) dnewHandle, state);
		HiliteControl((ControlHandle) ddeleteHandle, state);
		HiliteControl((ControlHandle) deditHandle, state);

		SetPt(&cell, 0, 0);
		/* disabled for SAP release */
	/*	if (LGetSelect(true, &cell, slist))
			state = 0;
		else*/
			state = 255;					/* disable */
		HiliteControl((ControlHandle) snewHandle, state);
		HiliteControl((ControlHandle) sdeleteHandle, state);
		HiliteControl((ControlHandle) seditHandle, state);

		/*
		 * First handle some events we want to see before the
		 * Dialog Manager sees them. If we continue, we will
		 * bypass letting the Dialog Manager look at the
		 * events.
		 */
		switch (event.what) {
		case mouseDown:
			if (HandleMouseDown(&event))
				continue;
			break;

		case keyDown:
			if ((event.modifiers & cmdKey) && 
				((event.message & 0x7f) == '.')) {
				aborted = TRUE;
				SysBeep(20);
				continue;
			} else if (event.modifiers & cmdKey) {
				HandleMenu(MenuKey(event.message&charCodeMask), 
						   event.modifiers);
				continue;
			}
			break;

		case app4Evt:					/* really a suspend/resume event */
			switch ((event.message>>24) & 0xff) {
			case switchEvt:
				/* Treat switch events as activate events too */
				if (event.message & 0x01) { /* Resume Event */
					in_background = FALSE;
					doactivate(FrontWindow(), activeFlag);
					break;
				} else {				/* Suspend Event */
					in_background = TRUE;
					doactivate(FrontWindow(), 0);
					break;
				}
			}
			break;

		case updateEvt:
			if (doupdate((WindowPtr) event.message)) /* handle updates */
				continue;
			break;

		case activateEvt:				/* (de)active a window */
			if (doactivate((WindowPtr) event.message, event.modifiers))
				continue;
			break;

		case diskEvt:					/* disk inserted */
			if (((event.message >> 16) & 0xFFFF) != noErr) {
				DILoad();
				DIBadMount(event.where, event.message);
				DIUnload();
				continue;
			}
			break;
		} /* switch */

		/*
		 * Let the Dialog Manager have a crack at it.
		 */
		if (IsDialogEvent (&event))
			if (DialogSelect (&event, &mydlg, &item))
				if (mydlg == maind)
					mainhit(&event, mydlg, item);
	}									/* while */
	
	getout(0);
}


int HandleMouseDown (event)
	EventRecord *event;
{
	struct cmdw *cmdw;
	WindowPtr window;

	int windowCode = FindWindow (event->where, &window);
	
	switch (windowCode) {
	
	case inSysWindow: 
		SystemClick (event, window);
		return TRUE;
		
	case inMenuBar:
		HandleMenu(MenuSelect(event->where), event->modifiers);
		return TRUE;
		
	case inContent:
		if (window != FrontWindow ()) {
			if (window == (WindowPtr)maind) {
				SelectWindow(window);
				return TRUE;
			}
		} else if (window == (WindowPtr)maind) {
#ifdef notdef
			(void) listevents(maind, event);
			return TRUE;
#endif
		}
		break;

	case inDrag:						/* Wanna drag? */
		SelectWindow(window);
		DragWindow (window, event->where, &qd.screenBits.bounds);
		writeprefs();
		return TRUE;

	case inGoAway:
		if (window == (WindowPtr)maind)
			if (TrackGoAway (window, event->where))
				getout(0);
		break;

#ifdef notdef
	case inGrow:
		if (window != FrontWindow()) {
			SelectWindow(window);
			return TRUE;
		} else {
			if (window == (WindowPtr)maind) {
				dogrow(window, event->where);
				return TRUE;
			}
		}
		break;
#endif
		
	case inZoomOut:
		if (window == (WindowPtr)maind) {
		}
		break;
		
	} /* switch */

	return FALSE;
}


/*
 * HandleMenu - handle menu events.
 */
HandleMenu (long which, short modifiers)
{
	int id;								/* menu id */
	int item;							/* menu item */
	int s;
	short num;
	WindowPtr window;
	struct cmdw *cmdw;
	char fname[256];
	Point pt;
	SFReply reply;
	
	item = which & 0xFFFF;
	id = which >> 16;
	
	switch (id - MENU_OFFSET) {
	case APPL_MENU:						/* Mac system menu item */
		handapple(item);
		break;

	case FILE_MENU:						/* File menu */
		switch (item) {
		case LOGIN_FILE:
			doLogin();
			break;
		
		case LOGOUT_FILE:
			doLogout();
			break;
		
		case PASSWORD_FILE:
			kpass_dialog();
			break;

		case LIST_FILE:
			klist_dialog();
			break;

		case QUIT_FILE:					/* Quit */
		case CLOSE_FILE:				/* Close Window */
			getout(0);
		}
		break;

	case EDIT_MENU:
		window = FrontWindow();
	
		switch(item) {
		case UNDO_EDIT:					/* undo */
			SysBeep(3);
			break;

		case CUT_EDIT:					/* cut */
			break;

		case COPY_EDIT:					/* copy */
			break;

		case PASTE_EDIT:				/* paste */
			break;

		case CLEAR_EDIT:				/* clear */
			break;
		}
		break;

	}

	HiliteMenu(0);
}

	
/*
 * doupdate
 */
int doupdate (WindowPtr window)
{
#ifdef notdef
	GrafPtr savePort;

	GetPort (&savePort);
	SetPort (window);

	if (window == (WindowPtr)maind) {
		BeginUpdate (window);

		DrawGrowIcon(window);

		EndUpdate(window);
		return FALSE;
	}

	SetPort(savePort);
#endif
	return FALSE;
}


/*
 * doactivate
 */
int doactivate (WindowPtr window, int mod)
{
	GrafPtr savePort;
	struct cmdw *cmdw;
	
	if (!window)
		return FALSE;

	GetPort (&savePort);
	SetPort (window);

	HiliteWindow (window, ((mod & activeFlag) != 0));
	
#ifdef notdef
	if (window == (WindowPtr)maind)
		DrawGrowIcon(window);
#endif

	SetPort (savePort);
	return FALSE;
}


#ifdef notdef
/*
 * dogrow
 */
void dogrow (WindowPtr window, Point p)
{
    long gr;
    int height;
    int width;
    Rect growRect;
    GrafPtr savePort;

    growRect = qd.screenBits.bounds;
    growRect.top = 50;					/* minimal horizontal size */
    growRect.left = 50;					/* minimal vertical size */

    gr = GrowWindow(window, p, &growRect);

    if (gr == 0)
		return;
    height = HiWord (gr);
    width = LoWord (gr);

    SizeWindow (window, width, height, FALSE); /* resize the window */

    GetPort (&savePort);
    SetPort (window);
	/* setsizes(false); */
    InvalRect(&window->portRect);		/* invalidate whole window rectangle */
    EraseRect(&window->portRect);
    SetPort (savePort);
}
#endif


/* 
 * handapple - Handle the apple menu, either running a desk accessory
 *			   or calling a routine to display information about our
 *			   program.	 Use the practice of
 *			   checking for available memory, and saving the GrafPort
 *			   described in the DA Manager's Guide.
 */
handapple (accitem)
	int accitem;
{
	GrafPtr savePort;					/* Where to save current port */
	Handle acchdl;						/* holds ptr to accessory resource */
	Str255 accname;						/* string holds accessory name */
	long accsize;						/* holds size of the acc + stack */

	if (accitem == 1) {
		about ();
		return;
	}
	GetMenuItemText (menus[APPL_MENU], accitem, accname); /* get the pascal name */
	SetResLoad (FALSE);					/* don't load into memory */

	/* figure out acc size + heap */
	accsize = GetResourceSizeOnDisk (GetNamedResource ((ResType) 'DRVR', accname));
	acchdl = NewHandle (accsize);		/* try for a block this size */
	SetResLoad (TRUE);					/* reset flag for rsrc mgr */
	if (!acchdl) {						/* if not able to get a chunk */
		SysBeep(3);
		return;
	}
	DisposeHandle (acchdl);				/* get rid of this handle */
	GetPort (&savePort);				/* save the current port */
	OpenDeskAcc (accname);				/* run desk accessory */
	SetPort (savePort);					/* and put back our port */
}


#define DTH 14							/* dialog text height */
void about ()
{
	int ok;
	GrafPtr savePort;
	DialogPtr dialog;
	short item;
	short itemType;
	Handle itemHandle;
	Rect itemRect;

	GetPort(&savePort);

	PositionTemplate((Rect *)0, 'DLOG', DLOG_ABOUT, 50, 50);
	dialog = GetNewDialog(DLOG_ABOUT, (Ptr)0, (WindowPtr)-1);
	SetPort((GrafPtr)dialog);

	/*
	 * Set the draw procedure for the user items.
	 */
	GetDialogItem(dialog, ABOUT_OUT, &itemType, &itemHandle, &itemRect);
		//  IH 05.03.96: PPC Port - Replace Procedure Pointer by UPP
	SetDialogItem(dialog, ABOUT_OUT, itemType, (Handle)gdooutlineUPP, &itemRect);
	GetDialogItem(dialog, ABOUT_PICT, &itemType, &itemHandle, &itemRect);
		//  IH 05.03.96: PPC Port - Replace Procedure Pointer by UPP
	SetDialogItem(dialog, ABOUT_PICT, itemType, (Handle)gdopictUPP, &itemRect);

	ok = 0;
	do {
		/* 
		 * process hits in the dialog.
		 */
		ModalDialog(0, &item);
				
		switch(item) {
		case ABOUT_OK:
			ok = 1;
			break;
		} /* switch */
	} while (ok == 0);

	DisposeDialog(dialog);
	SetPort(savePort);
}


pascal void pictdrawproc (short depth, short flags, GDHandle device, DialogPtr dialog)
{
	#pragma unused (device, flags)
	
	if (depth < 8)
		drawpict(dialog, PICT_ABOUT_BW);
	else
		drawpict(dialog, PICT_ABOUT_C);
}


void drawpict (DialogPtr dialog, int id)
{
	Handle h;
	Rect rect;
    short itemType;
    Handle itemHandle;
    Rect itemRect;
	GrafPtr savePort;

	GetPort(&savePort);
	SetPort(dialog);

	GetDialogItem(dialog, ABOUT_PICT, &itemType, &itemHandle, &itemRect);
	if (h = Get1Resource('PICT', id)) {
		LoadResource(h);
		if (!ResError()) {
			HLock(h);

			bcopy(((char *)*h)+2, &rect, sizeof(Rect));
			AlignRect(&itemRect, &rect, 50, 50);
			DrawPicture((PicHandle)h, &rect);
			HUnlock(h);
		}
	}
	SetPort(savePort);
}


/*
 * this routine will be called by the Dialog Manager to draw the pict
 */
pascal void dopict (DialogPtr dialog, short itemNo)
{
	long qdv;
	
	if (!trapAvailable(_DeviceLoop) || Gestalt('qd  ', &qdv) || ((qdv&0xff) == 0)) { /* if old mac */
		drawpict(dialog, PICT_ABOUT_BW);
	} else {
			//  IH 05.03.96: PPC Port - Replace Procedure Pointer by UPP
		DeviceLoop(dialog->visRgn, gpictdrawprocUPP, 
				   (long)dialog, 0);
	}
}


/*
 * this routine will be called by the Dialog Manager to draw the outline of the
 * default button.
 */
pascal void dooutline (DialogPtr dialog, short itemNo)
{
	short		itemType;
	Handle		itemHandle;
	Rect		itemRect;
	
	GetDialogItem(dialog, itemNo, &itemType, &itemHandle, &itemRect);
	/* 
	 * outline the default button (see IM I-407).  in this case it 
	 * is the OK button. this lets the user know that pressing 
	 * the return will have the same effect as clicking this button.
	 */
	PenSize(3, 3);
	InsetRect(&itemRect, -4, -4);
	FrameRoundRect(&itemRect, 16, 16);
	PenSize(1, 1);
}


/*
 * ------------------ routines ------------------
 */


/*
 * updatedisplay
 * Update the main display window.
 */
void updatedisplay ()
{
	int s, savemode;
	Str255 scratch;
	static Str255 oldrealm = "", olduser = "";
	GrafPtr savePort;
	short itemType;
	Handle itemHandle;
	Rect itemRect;
	Point pt;
    krb5_principal princ;
    int	anErr;

	if (!maind)
		return;
		
	GetPort(&savePort);
	SetPort(maind);
	
	/*
	 * Display the local realm
	 */
#ifdef KRB4
	klopb.uRealm = scratch;
	if (s = lowcall(cKrbGetLocalRealm))
		strcpy(scratch, "None");
#endif
#ifdef KRB5
{
char *ptr;
	if (krb5_get_default_realm(kcontext, &ptr) == 0)
	{
		strcpy(scratch, ptr);
		free(ptr);
	}
	else
		strcpy(scratch, "None");
}
#endif

	if (strcmp(scratch, oldrealm)) {
		GetDialogItem(maind, MAIN_REALM, &itemType, &itemHandle, &itemRect);
		savemode = maind->txMode;
		MoveTo(itemRect.left+4, itemRect.bottom-4);
		strcpy(oldrealm, scratch);
		c2pstr(scratch);
		TextMode(srcCopy);
		DrawString(scratch);
		GetPen(&pt);
		itemRect.right -= 17;	/* room for triangle */
		itemRect.left = pt.h;
		InsetRect(&itemRect, 1, 1);
		EraseRect(&itemRect);	/* erase remainder of space in rect */
		TextMode(savemode);
	}
	
	/*
	 * Display the local user
	 */
#ifdef KRB4
	bzero(&khipb, sizeof(krbHiParmBlock));
	khipb.user = scratch;
	if (s = hicall(cKrbGetUserName))
		strcpy(scratch, "None");
#endif
#ifdef KRB5
/*	anErr = krb5_cc_get_principal(kcontext, k5_ccache, &princ);
	
	if ( anErr == noErr )
	{
		strcpy(scratch, princ->data->data);
		strcat(scratch, "@");
		strcat(scratch, princ->realm.data);
	}
	else
		strcpy(scratch, kUNKNOWNUSERNAME);*/
		
	
	/* old cruft */
	if (strcmp(gUserName, kUNKNOWNUSERNAME))
	{
		strcpy(scratch, gUserName);
		strcat(scratch, "@");
		strcat(scratch, gRealmName);
	}
	else
		strcpy(scratch, kUNKNOWNUSERNAME);
#endif
	if (strcmp(scratch, olduser)) {
		strcpy(olduser, scratch);
		c2pstr(scratch);
		setText(maind, MAIN_USER, scratch);
	}
	SetPort(savePort);
}


void setText (DialogPtr dialog, int item, char *text)
{
	short itemType;
	Handle itemHandle;
	Rect itemRect;

	GetDialogItem(dialog, item, &itemType, &itemHandle, &itemRect);
	SetDialogItemText(itemHandle, text);
}


/*
 * buildmain
 * Build the main window.
 */
void buildmain ()
{
	int h;
	int n, cellw;
	int ndomains, nservers;
	int listwidth;
	short itemNo;				/* the item in the dialog selected */
	short itemType;				/* dummy parameter for call to GetDialogItem */
	Handle itemHandle;			/* dummy parameter for call to GetDialogItem */
	Rect itemRect;				/* the location of the list in the dialog */
	Rect dataBounds;			/* the dimensions of the data in the list */
	Point cellSize;				/* width and height of a cells rectangle */
	Point cell;					/* an index through the list */
	char string[255];
	short length;
	short checked;				/* flag for check box value */
	short bit;					/* used as a mask to test selection flags */ 
	struct user *user, *save, *tmp;
	char *cp;
	GrafPtr savePort;
    Handle wh;					/* window handle */
    Rect *rectp;
	DialogPtr dialog;
	Rect dRect, sRect;
	domaintype *dp;
	servertype *sp;
	
    /*
     * Get the dialog resource and modify the location.
     * Since it will already be in memory, GetNewDialog will use
     * the values we just set.
	 * ??? WE SHOULD MAKE SURE THE WINDOW IS ON THE SCREEN ???
     */
	if (prefs.wrect.top != prefs.wrect.bottom) {
		if (wh = GetResource('DLOG', DLOG_MAIN)) {
			rectp = (Rect *)*wh;
			bcopy(&prefs.wrect, rectp, sizeof(Rect));
			PositionRectOnScreen(rectp, false);
/*			PositionRect(rectp, rectp, 50, 50);			/* make sure on screen */
		}
	}
	maind = dialog = GetNewDialog(DLOG_MAIN, (Ptr)0, (WindowPtr) -1);
	if (!maind) {
		doalert("DLOG %d missing", DLOG_MAIN);
		getout(0);
	}
	GetPort(&savePort);
	SetPort((GrafPtr)maind);

	/* 
	 * allow the dialog manager routines to access various things
	 */
	((DialogPeek)dialog)->window.refCon = (long)&lf;
		
	/* 
	 * set the procedure pointer for the user items in the dialog.
	 * this will allow he default button to be outlined and the list 
	 * to be drawn by the Dialog Manger.
     * Also, set the correct list heights.
	 */
	GetDialogItem(dialog, MAIN_REALM, &itemType, &itemHandle, &itemRect);
		//  IH 05.03.96: PPC Port - Replace Procedure Pointer by UPP
	SetDialogItem(dialog, MAIN_REALM, itemType, (Handle)gdrawRealmUPP, &itemRect);
	
	GetDialogItem(dialog, MAIN_DMAP, &itemType, &itemHandle, &dRect);
	h = (((dRect.bottom - dRect.top) / CELLH) * CELLH);
	dRect.bottom = dRect.top + h;
		//  IH 05.03.96: PPC Port - Replace Procedure Pointer by UPP
	SetDialogItem(dialog, MAIN_DMAP, itemType, (Handle) gdolistUPP, &dRect);

	GetDialogItem(dialog, MAIN_SERVERS, &itemType, &itemHandle, &sRect);
	h = (((sRect.bottom - sRect.top) / CELLH) * CELLH);
	sRect.bottom = sRect.top + h;
		//  IH 05.03.96: PPC Port - Replace Procedure Pointer by UPP
	SetDialogItem(dialog, MAIN_SERVERS, itemType, (Handle) gdolistUPP, &sRect);

	/* Add for 'new' SAP release */
	GetDialogItem(dialog, MAIN_DNEW, &itemType, &dnewHandle, &itemRect);
	GetDialogItem(dialog, MAIN_SNEW, &itemType, &snewHandle, &itemRect);
	GetDialogItem(dialog, MAIN_DDELETE, &itemType, &ddeleteHandle, &itemRect);
	GetDialogItem(dialog, MAIN_SDELETE, &itemType, &sdeleteHandle, &itemRect);
	GetDialogItem(dialog, MAIN_DEDIT, &itemType, &deditHandle, &itemRect);
	GetDialogItem(dialog, MAIN_SEDIT, &itemType, &seditHandle, &itemRect);

	listwidth = dRect.right - dRect.left;

	/* 
	 * make room for scroll bars (see IM IV-270)
	 */
	dRect.right -= 15;
	sRect.right -= 15;	

	/* 
	 * create domain list
	 */
	ndomains = 0;								/* count items */
	for (dp = (domaintype *)domainQ; dp; dp = dp->next)
		ndomains++;
	SetRect(&dataBounds, 0, 0, 1, ndomains);
	SetPt(&cellSize, dRect.right-dRect.left, CELLH);
	dlist = LNew(&dRect, &dataBounds, cellSize, 128,
				(WindowPtr) dialog, false, false, false, true);

	/* 
	 * use the default selection flags
	 */
	(*dlist)->selFlags = 0;

	/*
	 * Initialize the cells in the list.
	 */
	dp = (domaintype *)domainQ;
	cell.h = cell.v = 0;
	while (dp) {
		setdcellstring(string, dp);
		LSetCell(string, strlen(string), cell, dlist);
		cell.v++;
		dp = dp->next;
	}

	/* 
	 * create servers list
	 */
	nservers = 0;								/* count items */
	for (sp = (servertype *)serverQ; sp; sp = sp->next)
		nservers++;
	SetRect(&dataBounds, 0, 0, 1, nservers);
	SetPt(&cellSize, sRect.right-sRect.left, CELLH);
	slist = LNew(&sRect, &dataBounds, cellSize, 128, 
				(WindowPtr) dialog, false, false, false, true);

	/* 
	 * use the default selection flags
	 */
	(*slist)->selFlags = 0;

	/*
	 * Initialize the cells in the list.
	 */
	sp = (servertype *)serverQ;
	cell.h = cell.v = 0;
	while (sp) {
		setscellstring(string, sp);
		LSetCell(string, strlen(string), cell, slist);
		cell.v++;
		sp = sp->next;
	}

	lf.nlists = 2;
	lf.list[0] = dlist;
	lf.list[1] = slist;
	lf.listitem[0] = MAIN_DMAP;
	lf.listitem[1] = MAIN_SERVERS;
	lf.edititem[0] = MAIN_DEDIT;
	lf.edititem[1] = MAIN_SEDIT;

	/* 
	 * turn cell drawing on only after the cell contents have been initialized.
	 * this will avoid watching the delay between the LSetCells 
	 * calls and is faster.
	 */
	LSetDrawingMode(true, dlist);
	LSetDrawingMode(true, slist);
	
	/* Disable password button because it doesn't work */
	GetDialogItem(dialog, MAIN_PASSWORD, &itemType, &passwordHandle, &itemRect);
	HiliteControl((ControlHandle) passwordHandle, 255);
	
		
	DrawMenuBar();
	SetPort (savePort);					/* and put back our port */
}


/*
 * setdcellstring
 */
void setdcellstring (unsigned char *string, domaintype *dp)
{
	unsigned char *cp;

	cp = string;
	strcpy(cp, dp->host);
	cp += strlen(cp);
		
	strcpy(cp, "\x09" "170;");			/* tab over */
	cp += strlen(cp);

	strcpy(cp, dp->realm);
	cp += strlen(cp);

	*cp = '\0';
}


/*
 * setscellstring
 */
void setscellstring (unsigned char *string, servertype *sp)
{
	unsigned char *cp;

	cp = string;
	strcpy(cp, sp->host);
	cp += strlen(cp);
		
	strcpy(cp, "\x09" "170;");			/* tab over */
	cp += strlen(cp);

	strcpy(cp, sp->realm);
	cp += strlen(cp);

	if (sp->admin) {
		strcpy(cp, "\x09" "360;");
		cp += strlen(cp);
		strcpy(cp, "Admin");
		cp += strlen(cp);
	}

	*cp = '\0';
}


/*
 * setrcellstring
 */
void setrcellstring (unsigned char *string, credentialstype *rp)
{
#ifdef KRB4
	unsigned char *cp;
	
	cp = string;				/* name */
	strcpy(cp, rp->name);	
	cp += strlen(cp);
	if (rp->instance[0]) {		/* instance */
		*cp++ = '.';
		strcpy(cp, rp->instance);
		cp += strlen(cp);
	}
	if (rp->realm[0]) {			/* realm */
		*cp++ = '@';
		strcpy(cp, rp->realm);
		cp += strlen(cp);
	}
	strcpy(cp, "\x09" "170;");	/* tab */
	cp += strlen(cp);
	strcpy(cp, rp->sname);		/* sname */
	cp += strlen(cp);
	if (rp->sinstance[0]) {		/* sinstance */
		*cp++ = '.';
		strcpy(cp, rp->sinstance);
		cp += strlen(cp);
	}
	if (rp->srealm[0]) {		/* srealm */
		*cp++ = '@';
		strcpy(cp, rp->srealm);
		cp += strlen(cp);
	}
	*cp = '\0';
#endif
#ifdef KRB5
	unsigned char *cp;
	
	cp = string;

	strcpy(cp, rp->pname);		/* name */
	cp += strlen(cp);

	strcpy(cp, "\x09" "170;");	/* tab */
	cp += strlen(cp);

	strcpy(cp, rp->cname);		/* credential name */
	cp += strlen(cp);

	*cp = '\0';
#endif
}


/*
 * drawRealm
 * Called by the Dialog manager to draw user items
 */
pascal void drawRealm (DialogPtr dialog, short item)
{
	int s, savemode;
	short itemType;
	Handle itemHandle;
	Rect itemRect;
	Str255 scratch;
	GrafPtr savePort;
	Point pt;
	
	GetPort(&savePort);
	SetPort(dialog);

	/*
	 * Display the local realm
	 */
#ifdef KRB4
	klopb.uRealm = scratch;
	if (s = lowcall(cKrbGetLocalRealm))
		strcpy(scratch, "None");
#endif
#ifdef KRB5
{
char *ptr;
	if (krb5_get_default_realm(kcontext, &ptr) == 0)
	{
		strcpy(scratch, ptr);
		free(ptr);
	}
	else
		strcpy(scratch, "None");
}
#endif

	GetDialogItem(dialog, item, &itemType, &itemHandle, &itemRect);
	EraseRect(&itemRect);
	doshadow(&itemRect);
	dotriangle(&itemRect);

	savemode = dialog->txMode;
	MoveTo(itemRect.left+4, itemRect.bottom-4);
	c2pstr(scratch);
	TextMode(srcCopy);
	DrawString(scratch);
	TextMode(savemode);
	GetPen(&pt);
	itemRect.right -= 17;	/* room for triangle */
	itemRect.left = pt.h;
	InsetRect(&itemRect, 1, 1);
	EraseRect(&itemRect);	/* erase remainder of space in rect */

	SetPort(savePort);
}


/*
 * this routine will be called by the Dialog Manager to draw the list. 
 */
pascal void dolist (DialogPtr dialog, short itemNo)
{
	int i;
	short itemType;
	Handle itemHandle;
	Rect itemRect;
	ListHandle list;
	struct listfilter *lf;

	/*
	 * figure out which list is being updated
	 */
	lf = (struct listfilter *) ((DialogPeek)dialog)->window.refCon;
	for (i = 0; i < lf->nlists; i++)
 		if (lf->listitem[i] == itemNo)
			break;
	if (i == lf->nlists)
		return;
		
	list = lf->list[i];
	GetDialogItem(dialog, itemNo,  &itemType, &itemHandle, &itemRect);
	
	/* 
	 *let the List Manager draw the list
	 */
	LUpdate(dialog->visRgn, list);
	
	/* 
	 * draw the lists framing rectangle OUTSIDE the view rectangle.
	 * if the frame is drawn inside the view rectangle then these lines
	 * will be erased, drawn onto or scrolled by the List Manager 
	 * since the lines are within the rectangle LM expects to be 
	 * able to draw in.
	 */
	InsetRect(&itemRect, -1, -1);
	FrameRect(&itemRect);
}


/*
 * mainhit
 * Called when an item in the dialog box is hit.
 */
void mainhit (EventRecord *event, DialogPtr dlg, int item)
{
	int s, i, n;
	int admin;
	int listwidth;
	short itemType;				/* dummy parameter for call to GetDialogItem */
	Handle itemHandle;			/* dummy parameter for call to GetDialogItem */
	Rect itemRect;				/* the location of the list in the dialog */
	Point where;
	Point cell;
	GrafPtr savePort;
	char e1[256];
	char e2[256];
	domaintype *dp;
	servertype *sp;
	Str255 string, oldh, oldr;
	
	GetPort(&savePort);
	SetPort(dlg);

	switch (item) {
	case MAIN_LOGIN:						/* login button */
		doLogin();
		break;
		
	case MAIN_LOGOUT: 						/* logout button */
		doLogout();
		break;
		
	case MAIN_DMAP:							/* domain map ui */
		where = event->where;
		GlobalToLocal(&where);
		/*
		 * Unselect cells in other list
		 */
		cell.h = cell.v = 0;
		 while (LGetSelect(true, &cell, slist))
			LSetSelect(false, cell, slist);

		/* 
		 * let the List Manager process the mouse down. this includes 
		 * cell selection dragging, scrolling and double clicks by the 
		 * user.
		 */
		 
		 /* disabled for SAP purposes */
		if (LClick(where, event->modifiers, dlist)) { 
			/* 
			 * a double click in a cell has occured. find out in which 
			 * one of the cells the user has double clicked in.
			 */
		/*	cell = LLastClick(dlist);
			goto dedit;*/
		}

		break;
		
	case MAIN_SERVERS:						/* servers map ui */
		where = event->where;
		GlobalToLocal(&where);
		/*
		 * Unselect cells in other list
		 */
		cell.h = cell.v = 0;
		 while (LGetSelect(true, &cell, dlist))
			LSetSelect(false, cell, dlist);

		/* 
		 * let the List Manager process the mouse down. this includes 
		 * cell selection dragging, scrolling and double clicks by the 
		 * user.
		 */
		if (LClick(where, event->modifiers, slist)) {
			/* 
			 * a double click in a cell has occured. find out in which 
			 * one of the cells the user has double clicked in.
			 */
		/*	cell = LLastClick(slist);
			goto sedit;*/
		}
		break;
		
	case MAIN_PASSWORD:						/* change password button */
		kpass_dialog();
		break;

	case MAIN_DNEW:							/* domain new */
		e1[0] = e2[0] = '\0';
		if (editlist(DLOG_DEDIT, e1, e2, 0)) {
			if (!(dp = (domaintype *)NewPtrClear(sizeof(domaintype)))) {
				SysBeep(20);
				break;
			}
			if (newdp(dp, e1, e2)) {
				qlink(&domainQ, dp);
				cell.v = (*dlist)->dataBounds.bottom;
				cell.h = 0;
				setdcellstring(string, dp);
				LAddRow(1, cell.v, dlist);
				LSetCell(string, strlen(string), cell, dlist);
			}
			addRealmMap(e1, e2);					
		}
		break;
		
	case MAIN_DDELETE:						/* domain delete */
		/*
		 * Loop for selected cells.
		 */
		 SetPt(&cell, 0, 0);
		 while (LGetSelect(true, &cell, dlist)) {
			dp = (domaintype *)domainQ;
			i = cell.v;
			while (dp && (i-- > 0))		/* find selected credential */
				dp = dp->next;
			if (dp) {
				qunlink(&domainQ, dp);
				deleteRealmMap(dp->host);
				DisposePtr((Ptr)dp);
				LSetSelect(false, cell, dlist);
				LDelRow(1, cell.v, dlist);
				SetPt(&cell, 0, 0);
			} else {						/* we are broken */
				SysBeep(20);
				break;
			}
		}
		break;
		
	case MAIN_DEDIT:						/* domain edit */
	dedit:
		/*
		 * Loop for selected cells.
		 */
		SetPt(&cell, 0, 0);
		while (LGetSelect(true, &cell, dlist)) {
			dp = (domaintype *)domainQ;
			i = cell.v;
			while (dp && (i-- > 0))		/* find selected item */
				dp = dp->next;
			if (dp) {
				strcpy(e1, dp->host);
				strcpy(e2, dp->realm);
				strcpy(oldh, dp->host);
				if (editlist(DLOG_DEDIT, e1, e2, 0)) {
					if (newdp(dp, e1, e2)) {
						setdcellstring(string, dp);
						LSetCell(string, strlen(string), cell, dlist);
					}
					deleteRealmMap(oldh);
					addRealmMap(e1, e2);					
				}
				LSetSelect(false, cell, dlist);		/* unselect item */
				SetPt(&cell, 0, 0);
			} else {						/* we are broken */
				SysBeep(20);
				break;
			}
		}
		break;

	case MAIN_SNEW:							/* server new */
		e1[0] = e2[0] = '\0';
		admin = 0;
		if (editlist(DLOG_SEDIT, e1, e2, &admin)) {
			if (!(sp = (servertype *)NewPtrClear(sizeof(servertype)))) {
				SysBeep(20);
				break;
			}
			if (newsp(sp, e1, e2, admin)) {
				qlink(&serverQ, sp);
				cell.v = (*slist)->dataBounds.bottom;
				cell.h = 0;
				setscellstring(string, sp);
				LAddRow(1, cell.v, slist);
				LSetCell(string, strlen(string), cell, slist);
			}
			addServerMap(e1, e2, admin);
		}
		break;
		
	case MAIN_SDELETE:						/* server delete */
		/*
		 * Loop for selected cells.
		 */
		 SetPt(&cell, 0, 0);
		 while (LGetSelect(true, &cell, slist)) {
			sp = (servertype *)serverQ;
			i = cell.v;
			while (sp && (i-- > 0))		/* find selected credential */
				sp = sp->next;
			if (sp) {
				qunlink(&serverQ, sp);
				deleteServerMap(sp->host, sp->realm);
				DisposePtr((Ptr)sp);
				LSetSelect(false, cell, slist);
				LDelRow(1, cell.v, slist);
				SetPt(&cell, 0, 0);
			} else {						/* we are broken */
				SysBeep(20);
				break;
			}
		}
		break;

	case MAIN_SEDIT:						/* server edit */
	sedit:
		/*
		 * Loop for selected cells.
		 */
		SetPt(&cell, 0, 0);
		while (LGetSelect(true, &cell, slist)) {
			sp = (servertype *)serverQ;
			i = cell.v;
			while (sp && (i-- > 0))		/* find selected item */
				sp = sp->next;
			if (sp) {
				strcpy(e1, sp->host);
				strcpy(e2, sp->realm);
				strcpy(oldh, sp->host);
				strcpy(oldr, sp->realm);
				admin = sp->admin;
				if (editlist(DLOG_SEDIT, e1, e2, &admin)) {
					if (newsp(sp, e1, e2, admin)) {
						setscellstring(string, sp);
						LSetCell(string, strlen(string), cell, slist);
					}
					deleteServerMap(oldh, oldr);
					addServerMap(e1, e2, admin);
				}

				LSetSelect(false, cell, slist);		/* unselect item */
				SetPt(&cell, 0, 0);
			} else {						/* we are broken */
				SysBeep(20);
				break;
			}
		}
		break;
		
	case MAIN_REALM:
		GetDialogItem(dlg, MAIN_REALM, &itemType, &itemHandle, &itemRect);
		if (popRealms(&itemRect, &string)) {
			trimstring(string);
#ifdef KRB4
			bzero(&klopb, sizeof(klopb));
			klopb.uRealm = string;
			if (s = lowcall(cKrbSetLocalRealm))
				kerror("Error in cKrbSetLocalRealm", s);
#endif
#ifdef KRB5
{
int		code;
struct profile_node *node;
char	*nam, *val;
void	*state;

			if ((s = krb5_set_default_realm(kcontext, string)) != 0)
				kerror("Error in cKrbSetLocalRealm", s);
/*also change the profile string to match */
	state = NULL;
	code = profile_find_node_subsection(kcontext->profile->first_file->root, "libdefaults", &state, &nam, &node);
	code = profile_remove_node(node, "default_realm", 0);
	code = profile_add_node(node, "default_realm", string, &node);
}			
#endif
		}			
		break;

	default:
		break;
	}

	SetPort(savePort);
}


/*
 * klist_dialog
 * Display credentials and allow selection/deletion
 */
void klist_dialog ()
{
	int i, ncredentials, listwidth;
	DialogPtr dialog;			/* the dialog */
	short itemNo;				/* the item in the dialog selected */
	short itemType;				/* dummy parameter for call to GetDialogItem */
	Handle itemHandle;			/* dummy parameter for call to GetDialogItem */
	Rect itemRect;				/* the location of the list in the dialog */
	Handle deleteHandle;		/* handle of delete button */
	ListHandle list;			/* the list constructed in the dialog */
	Rect dataBounds;			/* the dimensions of the data in the list */
	Point cellSize;				/* width and height of a cells rectangle */
	Point cell;					/* an index through the list */
	GrafPtr savePort;
	unsigned char string[512+4];
	int state;
	int changed = false;
	credentialstype *rp;
	struct listfilter lf;
	
	getCredentialsList();
	
	/*
     * Get the dialog resource and modify the location.
     * Since it will already be in memory, GetNewDialog will use
     * the values we just set.
     */
	PositionTemplate((Rect *)-1, 'DLOG', DLOG_KLIST, 50, 50);
	dialog = GetNewDialog(DLOG_KLIST, (Ptr) 0, (WindowPtr) -1);
	GetPort(&savePort);
	SetPort((GrafPtr) dialog);

	GetDialogItem(dialog, KLIST_DELETE, &itemType, &deleteHandle, &itemRect);

#ifdef KRB5
/* use logout to delete credentials */
	HideDialogItem(dialog, KLIST_DELETE);
#endif

	/* 
	 * allow the dialog manager routines to access various things
	 */
	((DialogPeek)dialog)->window.refCon = (long)&lf;
		
	/* 
	 * set the procedure pointer for the user items in the dialog.
	 * this will allow he default button to be outlined and the list 
	 * to be drawn by the Dialog Manger.
	 */
	GetDialogItem(dialog, KLIST_OUT, &itemType, &itemHandle, &itemRect);
		//  IH 05.03.96: PPC Port - Replace Procedure Pointer by UPP
	SetDialogItem(dialog, KLIST_OUT, itemType, (Handle) gdooutlineUPP, &itemRect);
		
	GetDialogItem(dialog, KLIST_LIST, &itemType, &itemHandle, &itemRect);
		//  IH 05.03.96: PPC Port - Replace Procedure Pointer by UPP
	SetDialogItem(dialog, KLIST_LIST, itemType, (Handle) gdolistUPP, &itemRect);
	/* note item rect used later */

	ShowWindow(dialog);

	listwidth = itemRect.right - itemRect.left;

	/* 
	 * make room for scroll bars (see IM IV-270)
	 */
	itemRect.right -= 15;

	/* 
	 * create a list
	 */
	ncredentials = 0;								/* count credentials */
	for (rp = (credentialstype *)credentialsQ; rp; rp = rp->next)
		ncredentials++;
	SetRect(&dataBounds, 0, 0, 1, ncredentials);
	SetPt(&cellSize, itemRect.right-itemRect.left, CELLH);
	list = LNew(&itemRect, &dataBounds, cellSize, 128, 
				(WindowPtr) dialog, false, false, false, true);

	/* 
	 * use the default selection flags
	 */
	(*list)->selFlags = 0;

	/*
	 * Initialize the cells in the list.
	 */
	rp = (credentialstype *)credentialsQ;
	cell.h = cell.v = 0;
	while (rp) {
		setrcellstring(string, rp);
		LSetCell(string, strlen(string), cell, list);
		cell.v++;
		rp = rp->next;
	}

	lf.nlists = 1;
	lf.list[0] = list;
	lf.listitem[0] = KLIST_LIST;
	lf.edititem[0] = 0;

	/* 
	 * turn cell drawing on only after the cell contents have been initialized.
	 * this will avoid watching the delay between the LSetCells 
	 * calls and is faster.
	 */
	LSetDrawingMode(true, list);
		
	do {
		/*
		 * Set the state of the edit and delete buttons depending on if any
		 * cells are selected or not.
		 */
		 /* disabled for SAP release */
		/*SetPt(&cell, 0, 0);
		if (LGetSelect(true, &cell, list))
			state = 0;
		else*/
			state = 255;					/* disable */
		HiliteControl((ControlHandle) deleteHandle, state);

		/* 
		 * process hits in the dialog.
		 */
			//  IH 05.03.96: PPC Port - Replace Procedure Pointer by UPP
		ModalDialog(gklistFilterUPP, &itemNo);
				
		switch(itemNo) {
			/* 
			 * process hits in the OK button.
			 */ 
		case KLIST_OK:
			/* 
			 * find out which cells have been selected.
			 */
			SetPt(&cell, 0, 0);
			while(LGetSelect(true, &cell, list)) {
				/* 
				 * there is nothing to do with the user's selections in 
				 * this sample so i'll just deselect the cells the 
				 * users has selected.
				 */
				LSetSelect(false, cell, list);
			}
			break;
			
		case KLIST_DELETE:
			changed = true;
			/*
			 * Loop for selected cells.
			 */
			 SetPt(&cell, 0, 0);
			 while (LGetSelect(true, &cell, list)) {
				rp = (credentialstype *)credentialsQ;
				i = cell.v;
				while (rp && (i-- > 0))		/* find selected credential */
					rp = rp->next;
			 	if (rp) {
					qunlink(&credentialsQ, rp);
					deleteCredentials(rp);
					DisposePtr((Ptr)rp);
					LSetSelect(false, cell, list);
					LDelRow(1, cell.v, list);
					SetPt(&cell, 0, 0);
				} else {						/* we are broken */
					SysBeep(20);
					break;
				}
			}
			break;
		}
	} while (itemNo != ok);
	
	/*	
	 * kill the list and dialog.
	 */
	SetPort(savePort);
	LDispose(list);
	DisposeDialog(dialog);
}


/* 
 * we need to be able to process mouse clicks in the list. the Dialog 
 * Manager makes this possible through filter procedures like this one. 
 * since the default filter procedure will be replaced we also need to 
 * handle return key presses.
 */
pascal Boolean klistFilter (DialogPtr dialog, EventRecord *event, short *itemHit)
{
	int i;
	ListHandle list;
	Point cell;
	char character;
	Point where;
	Rect itemRect;
	short itemType;
	Handle itemHandle;
	struct listfilter *lf;
	
	lf = (struct listfilter *) ((DialogPeek)dialog)->window.refCon;

	switch (event->what) {
	
		/* 
		 * watch for mouse clicks in the List
		 */
	case mouseDown :
		for (i = 0; i < lf->nlists; i++) {
			GetDialogItem(dialog, lf->listitem[i], &itemType, &itemHandle, &itemRect);
			where = event->where;
			GlobalToLocal(&where);
		
			/* 
			 * if the user has clicked in the list then we'll handle the 
			 * processing here
			 */
			if (PtInRect(where, &itemRect)) {
				/* 
				 * recover the list handle. it was stuffed into the dialog 
				 * window's refCon field when it was created.
				 */
				list = lf->list[i];
				
				/* 
				 * let the List Manager process the mouse down. this includes 
				 * cell selection dragging, scrolling and double clicks by the 
				 * user.
				 */
				if (LClick(where, event->modifiers, list)) {
					/* 
					 * a double click in a cell has occured. find out in which 
					 * one of the cells the user has double clicked in.
					 */
					cell = LLastClick(list);

					if (lf->edititem[i])
						*itemHit = lf->edititem[i];		/* fake an edit hit if double click */
				} else {
					/* 
					 * tell the application that the list has been clicked in.
					 */
					*itemHit = lf->listitem[i];
				}
				return true;	/* event has been handled */
			}
		} /* for */
		break;
	
		/* 
		 * be sure and return this information so the Dialog Manager will 
		 * process the return and enter key presses as clicks by the user in 
		 * the OK button. this is only required because we have overridden 
		 * the Dialog Manager's default filtering.
		 */
	case keyDown :	
	case autoKey :
		character = event->message & charCodeMask;
		switch (character) {
		case '\n':			/* Return */
		case '\003':		/* Enter */
			/* 
			 * tell the application that the OK button has been clicked by 
			 * the user.
			 */
			*itemHit = 1;				/* item 1 must be ok button */
			return true;				/* we handled the event */
		}
		break;
	}
	
	/* 
	 * tell the Dialog Manger that the event has NOT been handled and that 
	 * it should take further action on this event.
	 */
	return false;
}


Boolean editlist (int dlog, char *e1, char *e2, int *admin)
{
	int ok, ret = false;
	short item;
	GrafPtr savePort;
	DialogPtr dialog;
	short itemType;
	Handle itemHandle;
	Rect itemRect;
	char s1[256], s2[256];
	int astate;

	PositionTemplate((Rect *)-1, 'DLOG', dlog, 50, 50);
	dialog = GetNewDialog(dlog, (Ptr) 0, (WindowPtr) -1);
	GetPort(&savePort);
	SetPort((GrafPtr) dialog);

	/*
	 * Set the draw procedure for the user items.
	 */
	GetDialogItem(dialog, EDIT_OUT, &itemType, &itemHandle, &itemRect);
		//  IH 05.03.96: PPC Port - Replace Procedure Pointer by UPP
	SetDialogItem(dialog, EDIT_OUT, itemType, (Handle)gdooutlineUPP, &itemRect);

	GetDialogItem(dialog, EDIT_E1, &itemType, &itemHandle, &itemRect);
	c2pstr(e1);
	SetDialogItemText(itemHandle, e1);
	p2cstr(e1);

	GetDialogItem(dialog, EDIT_E2, &itemType, &itemHandle, &itemRect);
	c2pstr(e2);
	SetDialogItemText(itemHandle, e2);
	p2cstr(e2);

	if (admin) {
		astate = *admin;
		GetDialogItem(dialog, EDIT_ADMIN, &itemType, &itemHandle, &itemRect);
		SetControlValue((ControlHandle)itemHandle, astate);
	}

	SelectDialogItemText(dialog, EDIT_E1, 0, 32767);				/* select E1 */

	ok = 0;
	do {
		/* 
		 * process hits in the dialog.
		 */
			//  IH 05.03.96: PPC Port - Replace Procedure Pointer by UPP
		ModalDialog(gokFilterUPP, &item);
		switch (item) {
		case EDIT_OK:							/* ok button */
			ok = 1;
			break;
			
		case EDIT_CANCEL:
			ok = 2;
			break;

		case EDIT_ADMIN:
			astate ^= 1;
			GetDialogItem(dialog, EDIT_ADMIN, &itemType, &itemHandle, &itemRect);
			SetControlValue((ControlHandle)itemHandle, astate);
			break;
		}
	} while (ok == 0);
	
	if (ok == 1) {
		GetDialogItem(dialog, EDIT_E1, &itemType, &itemHandle, &itemRect);
		GetDialogItemText(itemHandle, s1);
		p2cstr(s1);

		GetDialogItem(dialog, EDIT_E2, &itemType, &itemHandle, &itemRect);
		GetDialogItemText(itemHandle, s2);
		p2cstr(s2);

		if (admin) {
			*admin = astate;
		}

		if (!s1[0] || !s2[0])				/* if either is empty */
			goto xit;

		strcpy(e1, s1);
		strcpy(e2, s2);

		ret = true;
	}
	
xit:
	DisposeDialog(dialog);
	SetPort(savePort);
	return ret;
}


pascal Boolean okFilter (DialogPtr dialog, EventRecord *event, short *itemHit)
{
	#pragma unused (dialog)
	char character;

	switch (event->what) {
	case keyDown :	
	case autoKey :
		character = event->message & charCodeMask;
		switch (character) {
		case '\n':			/* Return */
		case '\003':		/* Enter */
			/* 
			 * tell the application that the OK button has been clicked by 
			 * the user.
			 */
			*itemHit = 1;				/* item 1 must be ok button */
			return true;				/* we handled the event */
		}
		break;
	}
	
	/* 
	 * tell the Dialog Manger that the event has NOT been handled and that 
	 * it should take further action on this event.
	 */
	return false;
}


int popRealms (Rect *rect, char *retstring)
{   
    int i, s, itsID, selected;
    MenuHandle theMenu;
    long theChoice;
	Point pt;
	servertype *sp;
	Str255 scratch, localrealm;
                
	/*
	 * Get the local realm
	 */
#ifdef KRB4
	klopb.uRealm = localrealm;
	if (s = lowcall(cKrbGetLocalRealm))
		strcpy(localrealm, "None");
#endif
#ifdef KRB5
{
char *ptr;
	if (krb5_get_default_realm(kcontext, &ptr) == 0)
	{
		strcpy(scratch, ptr);
		free(ptr);
	}
	else
		strcpy(scratch, "None");
}
#endif

    /* 
	 * get an id for the menu and create it. 
	 */
    itsID = 0;
    while (itsID < 128)
        itsID = UniqueID('MENU');
    theMenu = NewMenu(itsID,"\pxxx");        /* create the menu */
    InsertMenu(theMenu, -1);                 /* add it to the menu list */
    
    /* 
	 * add the items 
	 */
	selected = 0;
	for (i = 1, sp = (servertype *)serverQ; sp; sp = sp->next, i++) {
		strcpy(scratch, sp->realm);
		if (strcmp(scratch, localrealm) == 0)
			selected = i;
		c2pstr(scratch);
		AppendMenu(theMenu, scratch);
	}
    SetItemMark(theMenu, selected, checkMark);
	fixmenuwidth(theMenu, rect->right - rect->left);

    /* 
	 *pop it up 
	 */
	pt.h = rect->left+1;
	pt.v = rect->top;
	LocalToGlobal(&pt);
    theChoice = PopUpMenuSelect(theMenu, pt.v, pt.h, selected);
	theChoice = theChoice & 0xffff;
    
	if (theChoice) {
		GetMenuItemText(theMenu, theChoice, retstring);		
		p2cstr(retstring);
	}

    DeleteMenu(itsID);
	DisposeMenu(theMenu);
	
	return(theChoice);
}


Boolean newdp (domaintype *dp, char *e1, char *e2)
{
	char *s1, *s2;
	
	if (!e1[0] || !e2[0])					/* if empty strings */
		return false;
		
	strcpy(dp->host, e1);
	strcpy(dp->realm, e2);
	return true;
}


Boolean newsp (servertype *sp, char *e1, char *e2, int admin)
{
	char *s1, *s2;
	
	if (!e1[0] || !e2[0])					/* if empty strings */
		return false;
		
	strcpy(sp->host, e1);
	strcpy(sp->realm, e2);
	sp->admin = admin;

	return true;
}


/*
 * bzero
 * Block zero
 */
void bzero (void *dst, long n)
{
	int i;
	register char *d = dst;

	while (n--)
	*d++ = 0;
}


/*
 * bcopy
 * Block copy
 */
void bcopy (void *src, void *dst, int n)
{
	int i;
	register char *s = src;
	register char *d = dst;

	for (i = 0; i < n; i++)
		*d++ = *s++;
}


/*
 * getmem
 * malloc a block of zeroed memory
 */
Ptr getmem (size)
	size_t size;
{
	Ptr p;

	p = (Ptr) malloc(size);
	if (!p) {
		doalert("getmem: request for %ld failed", size);
		getout(1);
	}
	bzero(p, size);

	return p;
}


/*
 * getout
 * clean up and get out
 */
getout (exit)
	int exit;
{
#ifdef KRB4
	krb_end_session((char *)0);		/* Clean up nicely */
	ExitToShell();
#endif
#ifdef KRB5
/*try to dump the profile as it exists in memory to a file */

	if (kcontext->profile)
	{
	FILE	*daFile;
	char	*profilepath;
	extern char* GetMacProfilePathName(void);
		profilepath = GetMacProfilePathName();
		daFile = fopen(profilepath, "w+");
		dump_profile_to_file(kcontext->profile->first_file->root, 0, daFile);
		fclose(daFile);
		free(profilepath);
	}
	ExitToShell();
	/* FIXME */
#endif
}


/*
 * doalert
 * Bring up an alert box
 */
void doalert (char *format, ...)
{
	char string[256];
	va_list args;

	va_start(args, format);

	vsprintf(&string[1], format, args);
	string[0] = strlen(&string[1]);
	va_end(args);

	ParamText(string, "", "", "");

	PositionTemplate((Rect *)-1, 'ALRT', ALERT_DOALERT, 50, 50);
	Alert(ALERT_DOALERT, NULL);
}


/*
 * Return 0 if strings (ignoring case) match
 */
static int strcasecmp (char *a, char *b)
{
	for (;;) {
		if (toupper(*a) != toupper(*b))
			return 1;
		if (*a == '\0')
			return 0;
		a++;
		b++;
	}
}


fatal (char *string)
{
	doalert(string);
	getout(0);
}


char *copystring (char *src)
{
	int n;
	char *dst;

	if (!src || (*src == '\0'))
		return NULL;

	n = strlen(src);
	dst = malloc(n+1);
	strcpy(dst, src);

	return dst;
}


/*
 * isPressed
 * k =  any keyboard scan code, 0-127
 */
short isPressed (unsigned short k)
{
	unsigned char km[16];

	GetKeys((long *)km);
	return (( km[k>>3] >> (k & 7) ) & 1);
}


void doLogin ()
{
#ifdef KRB4
	int s;

	/*
	 * Get a TGT
	 */
	bzero(&khipb, sizeof(krbHiParmBlock));
	khipb.service = 0;
	if (s = hicall(cKrbCacheInitialTicket))
		if (s != cKrbUserCancelled)
			kerror("Error in cKrbCacheInitialTicket", s);
#endif

#ifdef KRB5
    long lifetime = 8*60;	// 8 hours 
    krb5_error_code code;
    krb5_principal principal;
    krb5_creds creds;
    krb5_principal server;
    krb5_int32 sec, usec;
    char usernm[100] = "";
    char passwd[100];
    char credname[100];
    char realm[100];
    char *ptr;

	/* if the gUserName isn't uknown, we'll use that name */
	if (strcmp(gUserName, kUNKNOWNUSERNAME))
		strcpy(usernm, gUserName);

	if (GetUserInfo(usernm, passwd) == 2)
		return;

	if (krb5_get_default_realm(kcontext, &ptr) == 0)
	{
		strcpy(realm, ptr);
		free(ptr);
	}
	else
		strcpy(realm, "None");

	do {
	    principal = server = NULL;
		memset(&creds, 0, sizeof(creds));
	
	    sprintf (credname, "%s@%s", usernm, realm);
	    code = krb5_parse_name(kcontext, credname, &principal);
	    if (code) break;
	
		code = krb5_cc_initialize(kcontext, k5_ccache, principal);
	    if (code) break;
	
		code = krb5_build_principal_ext(kcontext, &server,
			krb5_princ_realm(kcontext, principal)->length,
			krb5_princ_realm(kcontext, principal)->data,
	        KRB5_TGS_NAME_SIZE, KRB5_TGS_NAME,
		    krb5_princ_realm(kcontext, principal)->length,
			krb5_princ_realm(kcontext, principal)->data, 0);
	    if (code) break;
	
		creds.client = principal;
		creds.server = server;
	
	    code = krb5_crypto_us_timeofday(&sec, &usec);
	    if (code) break;
	    creds.times.starttime = 0;
		creds.times.endtime = sec + 60L * lifetime;
		creds.times.renew_till = 0;
	
		code = krb5_get_in_tkt_with_password(kcontext, 0, NULL,
	        NULL, NULL, passwd, k5_ccache, &creds, 0);
	} while (0);
	
	if (principal)
	    krb5_free_principal(kcontext, principal);
	if (server) 
		krb5_free_principal(kcontext, server);

	if (code)
	{
		com_err (NULL, code, "while logging in.");
	}
	else
	{
		strcpy(gUserName, usernm);	/* copy the user name over to the global username */
		strcpy(gRealmName, realm);	/* copy the realm name over to the global realmname */
	}
#endif
}


#ifdef KRB5
/*+
 * Function: destroys all tickets in a k5 ccache
 *
 * Parameters:
 *  none
 *
 * Returns: K5 error code (0 == success)
 */
static krb5_error_code
k5_dest_tkt (void) {
    krb5_error_code code;
    krb5_principal princ;

    if (code = krb5_cc_get_principal(kcontext, k5_ccache, &princ)) {
        kerror ("while retrieving principal name", code);
        return code;
    }

    code = krb5_cc_initialize (kcontext, k5_ccache, princ);
    if (code != 0) {
        kerror ("when re-initializing cache", code);
        krb5_free_principal (kcontext, princ);
        return code;
    }

    krb5_free_principal (kcontext, princ);
   
   /* quick nasty hack to remove the ticket cache for better
      user understanding of what the hell is going on. */ 
    code = krb5_cc_destroy( kcontext, k5_ccache );
    k5_init_ccache (&k5_ccache);

    if ( code != 0 ) {
    	kerror("when removing cache", code);
    	return code;
    }
    
    return code;

}
#endif

void doLogout ()
{
#ifdef KRB4
	int s;
	
	pb.cntrlParam.csCode = cKrbDeleteAllSessions;
	if ((s = PBControl(&pb, false)) || (s = pb.cntrlParam.ioResult))
		kerror("Error in cKrbDeleteAllSessions", s);
#endif
#ifdef KRB5
	k5_dest_tkt();
	strcpy(gUserName, kUNKNOWNUSERNAME);
#endif
}


void getRealmMaps ()
{
#ifdef KRB4
	int i, s;
	Str255 host, realm;
	domaintype *dp;

	for (i = 1; ;i++) {
		klopb.itemNumber = &i;
		klopb.host = host;
		klopb.uRealm = realm;
		if (s = lowcall(cKrbGetNthRealmMap))
			break;
			
		if (!(dp = (domaintype *)NewPtrClear(sizeof(domaintype))))
			return;
		strcpy(dp->realm, realm);
		strcpy(dp->host, host);
		qlink(&domainQ, dp);
	}
#endif
#ifdef KRB5
int count;
char **domainlist;
char	*realm;
int		code;
int		i;
domaintype *dp;
const char	*realm_kdc_names[4];

    realm_kdc_names[0] = "domain_realm";
    realm_kdc_names[1] = 0;

    code = profile_get_relation_names(kcontext->profile, realm_kdc_names, 
				      &domainlist);

    count = 0;
    while (domainlist && domainlist[count])
	{
		code = profile_get_string(kcontext->profile, "domain_realm", domainlist[count], NULL, "", &realm);

		if (!(dp = (domaintype *)NewPtrClear(sizeof(domaintype))))
			return;
		strcpy(dp->realm, realm);
		strcpy(dp->host, domainlist[count]);
		qlink(&domainQ, dp);

	    count++;
	}
	free(domainlist);
#endif
}


void getServerMaps ()
{
#ifdef KRB4
	int i, s, ar;
	Str255 host, realm;
	servertype *sp;

	for (i = 1; ;i++) {
		klopb.itemNumber = &i;
		klopb.host = host;
		klopb.uRealm = realm;
		klopb.adminReturn = &ar;
		if (s = lowcall(cKrbGetNthServerMap))
			break;
			
		if (!(sp = (servertype *)NewPtrClear(sizeof(servertype))))
			return;
		strcpy(sp->realm, realm);
		strcpy(sp->host, host);
		sp->admin = ar;
		qlink(&serverQ, sp);
	}
#endif
#ifdef KRB5
int i, s, ar = 1;
Str255 realm;
servertype *sp;
int count;
char **realmlist;
char	*host;
int		code;
const char	*realm_kdc_names[4];

    realm_kdc_names[0] = "realms";
    realm_kdc_names[1] = 0;

    code = profile_get_subsection_names(kcontext->profile, realm_kdc_names, 
					&realmlist);

    count = 0;
    while (realmlist && realmlist[count])
	{
	    realm_kdc_names[0] = "realms";
    	realm_kdc_names[1] = realmlist[count];
    	realm_kdc_names[2] = "kdc";
    	realm_kdc_names[3] = 0;

		code = profile_get_string(kcontext->profile, "realms", realmlist[count], "kdc", "", &host);
	
		if (!(sp = (servertype *)NewPtrClear(sizeof(servertype))))
			return;
		strcpy(sp->realm, realmlist[count]);
		strcpy(sp->host, host);
		code = profile_get_string(kcontext->profile, "realms", realmlist[count], "kdc", "", &host);
		sp->admin = ar;
		qlink(&serverQ, sp);

	    count++;
	}
	free(realmlist);

#endif
}


void getCredentialsList ()
{
#ifdef KRB4
	int i, j, s;
	Str255 scratch;
	Str255 name, instance, realm, sname, sinstance, srealm, tktfile;
	credentialstype *rp;

	killCredentialsList();

	/*
	 * list credentials
	 */
	bzero(&klopb, sizeof(krbParmBlock));
	klopb.uName = name;
	klopb.uInstance = instance;
	klopb.uRealm = realm;
	klopb.sName = sname;
	klopb.sInstance = sinstance;
	klopb.sRealm = srealm;
	
	i = 1;
	for (j = 1; ;j++) {
		klopb.itemNumber = &i;
		if (s = lowcall(cKrbGetNthSession)) {
			if (s != cKrbSessDoesntExist)
				kerror("cKrbGetNthSession: ", s);
			return;
		}

		klopb.itemNumber = &j;
		if (s = lowcall(cKrbGetNthCredentials)) {
			if ((s != cKrbCredsDontExist) & 
				(cKrbKerberosErrBlock - s != KFAILURE)) {
				kerror("cKrbGetNthCredentials: ", s);
				break;
			}
			i += 1;
		    j = 0;
			continue;
		}

		if (!(rp = (credentialstype *)NewPtrClear(sizeof(credentialstype))))
			return;
				
		strcpy(rp->sname, sname);
		strcpy(rp->sinstance, sinstance);
		strcpy(rp->srealm, srealm);
		
		/*	
		cKrbGetNthCredentials no longer returns the principal's, name
		instance and realm.  Instead it returns the cache name, 
		"fixed user", "fixed instance", "fixed realm".  Must get the 
		principal's name, instance, and realm by calling a routine 
		added by cns.
		*/

		bzero(&klopb, sizeof(krbParmBlock));
		klopb.fullname = tktfile;
		klopb.uName = name;
		klopb.uInstance = instance;
		klopb.uRealm = realm;
		klopb.sName = sname;
		klopb.sInstance = sinstance;
		klopb.sRealm = srealm;
		
		if (s = lowcall(cKrbGetTfFullname)) {
			if (s != KSUCCESS)
				kerror("cKrbGetTfFullname: ", s);
			return;
			}
		
		strcpy(rp->name, name);
		strcpy(rp->instance, instance);
		strcpy(rp->realm, realm);
		
		qlink(&credentialsQ, rp);
	}
#endif
#ifdef KRB5
	int i, j, s;
	Str255 scratch;
	Str255 name, instance, realm, sname, sinstance, srealm, tktfile;
	credentialstype *rp;
	krb5_cc_cursor cursor;
	krb5_creds creds;
	char *tmpstr;
	
	killCredentialsList();

	/*
	 * list credentials
	 */
	cursor = 0;
	krb5_fcc_start_seq_get(kcontext, k5_ccache, &cursor);
	while (0 == krb5_fcc_next_cred(kcontext, k5_ccache, &cursor, &creds)) {
		/* Get Cred info here */
		if (!(rp = (credentialstype *)NewPtrClear(sizeof(credentialstype))))
			return;

		strncpy(rp->name, (char*) creds.client->data->data, sizeof(Str255));
		strcpy(rp->instance, "instance");
		strncpy(rp->realm, (char*) creds.client->realm.data, sizeof(Str255));
		strncpy(rp->sname, (char*) creds.server->data->data, sizeof(Str255));
		strcpy(rp->sinstance, "sinstance");
		strncpy(rp->srealm, (char*) creds.server->realm.data, sizeof(Str255));
		krb5_unparse_name(kcontext, creds.client, &tmpstr);
		strcpy(rp->pname, tmpstr);
		free(tmpstr);
		krb5_unparse_name(kcontext, creds.server, &tmpstr);
		strcpy(rp->cname, tmpstr);
		free(tmpstr);
		qlink(&credentialsQ, rp);
	}
	krb5_fcc_end_seq_get(kcontext, k5_ccache, &cursor);
	krb5_cc_default (kcontext, &k5_ccache);
#endif
}


void killCredentialsList ()
{
	credentialstype *rp;
	
	while (rp = credentialsQ) {
		qunlink(&credentialsQ, rp);
		DisposePtr((Ptr)rp);
	}
}


void addRealmMap (char *host, char *realm)
{
#ifdef KRB4
	int s;

	klopb.host = host;
	klopb.uRealm = realm;
	if (s = lowcall(cKrbAddRealmMap))
		kerror("Error calling cKrbAddRealmMap", s);
#endif
#ifdef KRB5
int		code;
struct profile_node *node;
char	*nam, *val;
void	*state;

	state = NULL;
	code = profile_find_node_subsection(kcontext->profile->first_file->root, "domain_realm", &state, &nam, &node);
	code = profile_remove_node(node, host, 0);
	code = profile_add_node(node, host, realm, &node);

#endif
}

void deleteRealmMap (char *host)
{
#ifdef KRB4
	int s;
	
	klopb.host = host;
	if (s = lowcall(cKrbDeleteRealmMap))
		kerror("Error calling cKrbDeleteRealmMap", s);
#endif
#ifdef KRB5
int		code;
struct profile_node *node;
char	*nam, *val;
void	*state;

	state = NULL;
	code = profile_find_node_subsection(kcontext->profile->first_file->root, "domain_realm", &state, &nam, &node);
	code = profile_remove_node(node, host, 0);
#endif
}


void deleteCredentials (credentialstype *rp)
{
#ifdef KRB4
	int s;
	
	klopb.uName = rp->name;
	klopb.uInstance = rp->instance;
	klopb.uRealm = rp->realm;
	klopb.sName = rp->sname;
	klopb.sInstance = rp->sinstance;
	klopb.sRealm = rp->srealm;
	if (s = lowcall(cKrbDeleteCredentials))
		kerror("Error calling cKrbDeleteCredentials: ", s);
#endif
#ifdef KRB5
	/* FIXME */
#endif
}



void addServerMap (char *host, char *realm, int admin)
{
#ifdef KRB4
	int s;

	klopb.host = host;
	klopb.uRealm = realm;
	klopb.admin = admin;
	if (s = lowcall(cKrbAddServerMap))
		kerror("Error calling cKrbAddServerMap", s);
#endif
#ifdef KRB5
int		code;
struct profile_node *node, *node2;
char	*nam, *val;
void	*state;

	state = NULL;
	code = profile_find_node_subsection(kcontext->profile->first_file->root, "realms", &state, &nam, &node);
	code = profile_add_node(node, realm, 0, &node);		/* Create the realm node */
	code = profile_add_node(node, "kdc", host, &node2);		/* Create the realm node */
	code = profile_add_node(node, "admin_server", host, &node2);		/* Create the realm node */
#endif
}


void deleteServerMap (char *host, char *realm)
{
#ifdef KRB4
	int s;
	
	klopb.host = host;
	klopb.uRealm = realm;
	if (s = lowcall(cKrbDeleteServerMap))
		kerror("Error calling cKrbDeleteServerMap", s);
#endif
#ifdef KRB5
int		code;
struct profile_node *node;
char	*nam, *val;
void	*state;

	state = NULL;
	code = profile_find_node_subsection(kcontext->profile->first_file->root, "realms", &state, &nam, &node);
	code = profile_remove_node(node, realm, 1);
#endif
}


void kerror (char *text, int error)
{
#ifdef KRB4
	int k;
	Str255 scratch;
	char *etext;

	switch (error) {
	case cKrbCorruptedFile:
		etext = "Couldn't find a needed resource";
		break;
	case cKrbNoKillIO:
		etext = "Can't killIO because all calls sync";
		break;
	case cKrbBadSelector:
		etext = "csCode passed doesn't select a recognized function";
		break;
	case cKrbCantClose:
		etext = "We must always remain open";
		break;
	case cKrbMapDoesntExist:
		etext = "Tried to access a map that doesn't exist";
		break;
	case cKrbSessDoesntExist:
		etext = "Tried to access a session that doesn't exist";
		break;
	case cKrbCredsDontExist:
		etext = "Tried to access credentials that don't exist";
		break;
	case cKrbTCPunavailable:
		etext = "Couldn't open MacTCP driver";
		break;
	case cKrbUserCancelled:
		etext = "User cancelled a log in operation";
		break;
	case cKrbConfigurationErr:
		etext = "Kerberos Preference file is not configured properly";
		break;
	case cKrbServerRejected:
		etext = "A server rejected our ticket";
		break;
	case cKrbServerImposter:
		etext = "Server appears to be a phoney";
		break;
	case cKrbServerRespIncomplete:
		etext = "Server response is not complete";
		break;
	case cKrbNotLoggedIn:
		etext = "Returned by cKrbGetUserName if user is not logged in";
		break;
	default:
		k = cKrbKerberosErrBlock - error;
		if ((k > 0) && (k < 256)) {
			etext = krb_get_err_text(k);
			break;
		}

		sprintf(scratch, "Mac Kerberos error #%d", error);
		etext = scratch;
		break;
	}

	doalert("%s: %s", text, etext);
#endif
#ifdef KRB5
	/* FIXME */
#endif
}

#ifdef KRB4
int lowcall (int cscode)
{
	short s;
	
	bzero(&pb, sizeof(ParamBlockRec));
	*(long *)pb.cntrlParam.csParam = (long)&klopb;
	pb.cntrlParam.ioCompletion = nil;
	pb.cntrlParam.ioCRefNum = kdriver;

	pb.cntrlParam.csCode = cscode;
	if (s = PBControl(&pb, false))
		return s;
	if (s = pb.cntrlParam.ioResult)
		return s;
	return 0;
}


int hicall (int cscode)
{
	short s;
	
	bzero(&pb, sizeof(ParamBlockRec));
	*(long *)pb.cntrlParam.csParam = (long)&khipb;
	pb.cntrlParam.ioCompletion = nil;
	pb.cntrlParam.ioCRefNum = kdriver;

	pb.cntrlParam.csCode = cscode;
	if (s = PBControl(&pb, false))
		return s;
	if (s = pb.cntrlParam.ioResult)
		return s;
	return 0;
}
#endif

/*
 * qlink
 * Add an entry to the end of a linked list
 */
void qlink (void **flist, void *fentry)
{
    struct dummy {
		struct dummy *next;
    } **list, *entry;

    list = flist;
    entry = fentry;
    
    /*
     * Find address of last entry in the list.
     */
    while (*list)
	list = &(*list)->next;

    /*
     * Link entry
     */
    *list = entry;
    entry->next = 0;
}


/*
 * qunlink
 * Remove an entry from linked list
 * Returns the entry or NULL if not found.
 */
void *qunlink (void **flist, void *fentry)
{
    struct dummy {
	struct dummy *next;
    } **list, *entry;

    list = flist;
    entry = fentry;
    
    /*
     * Find entry and unlink it
     */
    while (*list) {
	if ((*list) == entry) {
	    *list = entry->next;
	    return entry;
	}

	list = &(*list)->next;
    }
    return NULL;
}


/*
 * fixmenuwidth
 * set minimum menu width by widening item
 */
void fixmenuwidth (MenuHandle themenu, int minwidth)
{
	Str255 scratch;
	
	minwidth -= 27;
	GetMenuItemText(themenu, 1, scratch);
	if (StringWidth(scratch) >= minwidth)
		return;
	while (StringWidth(scratch) < minwidth)
		scratch[scratch[0]++ + 1] = ' ';
	SetMenuItemText(themenu, 1, scratch);
}


/*
 * doshadow
 * Draw shadowed frame
 * Also in sldef.c
 */
doshadow (Rect *rect)
{
	FrameRect(rect);
	MoveTo(rect->left+2, rect->bottom);	/* shadow */
	LineTo(rect->right, rect->bottom);
	LineTo(rect->right, rect->top+2);
}


/*
 * dotriangle
 * Also in sldef.c
 */
void dotriangle (Rect *rect)
{
	int i;
	PolyHandle poly;
	Pattern black;
	
	for (i = 0; i < sizeof(black); i++)
#ifdef dangerousPattern
		black[i] = 0xff;
#else
		black.pat[i] = 0xff;		/* ... should use qd-> */
#endif

	poly = OpenPoly();							/* should make permanent ??? */
	MoveTo(rect->right - 16, rect->top + 5);
	LineTo(rect->right - 5, rect->top + 5);
	LineTo(rect->right - 10, rect->top + 10);
	LineTo(rect->right - 16, rect->top + 5);
	ClosePoly();
#ifdef dangerousPattern
	FillPoly(poly, black);
#else
	FillPoly(poly, &black);
#endif
	KillPoly(poly);
}


/*
 * trimstring
 * Trim trailing blanks from a string
 */
void trimstring (char *cp)
{
	int n;
	
	if (*cp == ' ')
		return;
	
	if (!(n = strlen(cp)))
		return;
	cp += n - 1;
	while (*cp == ' ')
		cp--;
	*++cp = '\0';
}


/* changing passwords doesn't work presently because :src:lib:kadm doesn't
compile.  kadm doesn't compile 'cause SOCKET_STREAM isn't an available socket
type in macsock.  I'm not even real sure this is the right way to change
a password, this is the only example I've seen yet
*/

#ifdef KRB5
	krb5_error_code
	k5_change_password (
	    krb5_context k5context,
		char *user,
		char *realm,
		char *opasswd,
		char *npasswd,
	    char **text);
#endif

/*
 * kpass_dialog
 */
void kpass_dialog ()
{
	int s = 0, ok;
	short item;
	GrafPtr savePort;
	DialogPtr dialog;
	short itemType;
	Handle itemHandle;
	Rect itemRect;
	char *reason = NULL, username[256], realm[256];
	struct valcruft valcruft;
	Str255 scratch;

	PositionTemplate((Rect *)-1, 'DLOG', DLOG_KPASS, 50, 50);
	dialog = GetNewDialog(DLOG_KPASS, (Ptr) 0, (WindowPtr) -1);
	GetPort(&savePort);
	SetPort((GrafPtr) dialog);

	/*
	 * Set the draw procedure for the user items.
	 */
	GetDialogItem(dialog, KPASS_OUT, &itemType, &itemHandle, &itemRect);
		//  IH 05.03.96: PPC Port - Replace Procedure Pointer by UPP
	SetDialogItem(dialog, KPASS_OUT, itemType, (Handle)gdooutlineUPP, &itemRect);

	/* preset dialog ... */
	SetWRefCon(dialog, (long)&valcruft);	/* Stash the cruft's address */
	bzero(&valcruft, sizeof(valcruft));

#ifdef KRB4
	/* preset initial user */
	khipb.user = scratch;
	if (!(s = hicall(cKrbGetUserName))) {
		c2pstr(scratch);
		GetDialogItem(dialog, KPASS_USER, &itemType, &itemHandle, &itemRect);
		SetDialogItemText(itemHandle, scratch);
		SelectDialogItemText(dialog, KPASS_PASS, 0, 32767);
	}

	/* get local realm */
	klopb.uRealm = realm;
	if (s = lowcall(cKrbGetLocalRealm))
		strcpy(realm, "");

#endif
#ifdef KRB5
{
char *ptr;
	GetDialogItem(dialog, KPASS_USER, &itemType, &itemHandle, &itemRect);
	SetDialogItemText(itemHandle, "\p");
	SelectDialogItemText(dialog, KPASS_PASS, 0, 32767);

// Get default realm
	if (krb5_get_default_realm(kcontext, &ptr) == 0)
	{
		strcpy(realm, ptr);
		free(ptr);
	}
	else
		strcpy(realm, "None");
}
#endif
	
	retry:
	
	ok = 0;
	do {
		/* 
		 * process hits in the dialog.
		 */
			//  IH 05.03.96: PPC Port - Replace Procedure Pointer by UPP
		ModalDialog(ginternalBufferFilterUPP, &item);
		switch (item) {
		case KPASS_OK:					/* ok button */
			ok = 1;
			break;
			
		case KPASS_CANCEL:
			ok = 2;
			break;

		case KPASS_JPW:					/* jump to password */
			SelectDialogItemText(dialog, KPASS_PASS, 0, 32767);			
			break;

		case KPASS_JNEW:				/* jump to new */
			SelectDialogItemText(dialog, KPASS_NEW, 0, 32767);			
			break;

		case KPASS_JNEW2:
			SelectDialogItemText(dialog, KPASS_NEW2, 0, 32767);
			break;
		}
	} while (ok == 0);
	
	if (ok == 1) {
		GetDialogItem(dialog, KPASS_USER, &itemType, &itemHandle, &itemRect);
		GetDialogItemText(itemHandle, username);
		p2cstr(username);

#ifndef KRB5
		/*
		 * If user put an @ in the username, ignore the realm, otherwise
		 * tack on the realm. 
		 */
		if ((strchr(username, '@') == 0) && realm[0]) {
			strcat(username, "@");
			strcat(username, realm);
		}
#endif

		p2cstr(valcruft.buffer1);				/* password */
		p2cstr(valcruft.buffer2);				/* new */
		p2cstr(valcruft.buffer3);				/* new2 */

		if (strcmp(valcruft.buffer2, valcruft.buffer3) != 0) {
			doalert("New passwords do not match");
			c2pstr(valcruft.buffer1);				/* password */
			c2pstr(valcruft.buffer2);				/* new */
			c2pstr(valcruft.buffer3);				/* new2 */
			goto retry;
		}

#ifdef KRB4
		OpenResolver(0);
		s = kerberos_changepw(username, valcruft.buffer1, valcruft.buffer2,
							  &reason);
		CloseResolver();
#endif

#ifdef KRB5
		{
			char *text;
			// Change the password from old to new
/* Comment this out because it's broken, and we desperately need to build kconfig */
//			s = k5_change_password(kcontext, username, realm, valcruft.buffer1, valcruft.buffer2, &text);
			if (s)
			{
				SysBeep(10);	// change password failed
		        com_err (NULL, s, "while logging in.");
			}
		}
#endif

		if (s) {
			kerror(reason, s);
			SelectDialogItemText(dialog, KPASS_PASS, 0, 32767);		/* hilite password */
			c2pstr(valcruft.buffer1);				/* password */
			c2pstr(valcruft.buffer2);				/* new */
			c2pstr(valcruft.buffer3);				/* new2 */
			goto retry;
		}
	}
	
	DisposeDialog(dialog);
	SetPort (savePort);
}


/*
 * Routines from Apple for hiding passwords
 */
pascal Boolean internalBufferFilter (DialogPtr dlog, EventRecord *event, short *itemHit)
{	
	char key;
	short start,end;
	struct valcruft *valcruft;
	unsigned char *buffer;
	Handle h;
	int i, len;
	char *cp;
	long offset;
	unsigned char scratch[256];
	int editevent;
	
	valcruft = (struct valcruft *)GetWRefCon(dlog);

	if (((DialogPeek)dlog)->editField == (KPASS_PASS - 1))
		buffer = valcruft->buffer1;
	else if (((DialogPeek)dlog)->editField == (KPASS_NEW - 1))
		buffer = valcruft->buffer2;
	else if (((DialogPeek)dlog)->editField == (KPASS_NEW2 - 1))
		buffer = valcruft->buffer3;
	else
		buffer = 0;

	start = (**((DialogPeek)dlog)->textH).selStart;	/* Get current selection */
	end = (**((DialogPeek)dlog)->textH).selEnd;
	
	/*
	 * Preprocess events, looking for edit events.
	 */
	editevent = 0;
	switch (event->what) {
	case keyDown:
	case autoKey:
		if (event->modifiers & cmdKey) {
			if (((DialogPeek)dlog)->editField != (KPASS_PASS - 1))
				return false;
			switch (event->message & charCodeMask) {
			case 'v':
			case 'V':
				editevent = EV_PASTE;
				break;
			case 'c':
			case 'C':
				editevent = EV_COPY;
				break;
			case 'x':
			case 'X':
				editevent = EV_CUT;
				break;
			default:
				return false;			/* unknown cmd key */
			}
		}
		break;

	default:							/* not key */
		return false;
	}

	/*
	 * Handle cut, copy, paste events.
	 */
	if (editevent) {
		switch (editevent) {
		case EV_PASTE:
			if (!buffer)
				break;
			if (start != end)
				DeleteRange(buffer, start, end);
			h = NewHandle(100);
			if ((len = GetScrap(h, 'TEXT', &offset)) < 0) {
				SysBeep(3);
			} else {
				cp = (char *)*h;
				for (i = 0; i < len; i++)
					InsertChar(buffer, start+i, cp[i]);
			}
			DisposeHandle(h);
			buffer[(*buffer) + 1] = '\0';		/* terminate string */
			strcpy(scratch, &buffer[1]);
			hidestring(scratch);
			setctltxt(dlog, KPASS_PASS, scratch);	/* update display */
			SelectDialogItemText(dlog, KPASS_PASS, start+i, start+i);
			break;
			
		case EV_COPY:
			SysBeep(3);						/* can't copy hidden field */
			return true;
		
		case EV_CUT:
			SysBeep(3);
			return true;
		}
		return true;						/* we handled it */
	}
	
	key = event->message & charCodeMask;
	switch (key) {	
	case '\n':							/* Return */
	case '\003':						/* Enter */
		/*
		 * If return, check to see that the password has been filled
		 * in. If not, jump to it unless we're already in the password
		 * field.
		 */
		switch (((DialogPeek)dlog)->editField + 1) {
		case KPASS_USER:
			if (*valcruft->buffer1 == 0) {
				*itemHit = KPASS_JPW;
				return true;
			} else if (*valcruft->buffer2 == 0) {
				*itemHit = KPASS_JNEW;
				return true;
			} else if (*valcruft->buffer3 == 0) {
				*itemHit = KPASS_JNEW2;
				return true;
			}
			break;

		case KPASS_PASS:
			if (*valcruft->buffer2 == 0) {
				*itemHit = KPASS_JNEW;
				return true;
			} else if (*valcruft->buffer3 == 0) {
				*itemHit = KPASS_JNEW2;
				return true;
			}
			break;

		case KPASS_NEW:
			if (*valcruft->buffer1 == 0) {
				*itemHit = KPASS_JPW;
				return true;
			} else if (*valcruft->buffer3 == 0) {
				*itemHit = KPASS_JNEW2;
				return true;
			}
			break;

		case KPASS_NEW2:
			if (*valcruft->buffer1 == 0) {
				*itemHit = KPASS_JPW;
				return true;
			} else if (*valcruft->buffer2 == 0) {
				*itemHit = KPASS_JNEW;
				return true;
			}
		}
		*itemHit = 1;					/* OK Button */
		return true;					/* We handled the event */
	case '\t':							/* Tab */
	case '\034':						/* Left arrow */
	case '\035':						/* Right arrow */
	case '\036':						/* Up arrow */
	case '\037':						/* Down arrow */
		return false;					/* Let ModalDialog handle them */
	default:							/* Everything else falls through */
		break;
	}
	
	switch (((DialogPeek)dlog)->editField + 1) {
	case KPASS_PASS:
	case KPASS_NEW:
	case KPASS_NEW2:
		break;

	default:
		return false;
	}

	if (start != end) {					/* If there's a selection, delete it */
		DeleteRange(buffer,start,end);
		if (key == '\010')
			return false;
	}
	
	if (key == '\010') {					// Backspace
		if (start != 0)
		DeleteRange(buffer,start-1,start);	// Delete the character to the left
	} else {
		if (*buffer >= (VCL-1))	{			/* if buffer full */
			SysBeep(10);
			return true;					/* eat event */
		}
		InsertChar(buffer,start,key);		// Insert the real key into the buffer
		event->message = '¥';			// Character to use in field
	}
	
	return false; 							// Let ModalDialog insert the fake char
}


void DeleteRange (unsigned char *buffer, short start, short end)
{	
	register unsigned char	*src,*dest,*last;
	
	last = buffer + *buffer;
	
	src = buffer + end + 1;
	dest = buffer + start + 1;
	
	while (src <= last)			// Shift character to the left over the removed characters
		*(dest++) = *(src++);
	
	(*buffer) -= (end-start);	// Adjust the buffer's length
}

void InsertChar (unsigned char *buffer, short pos, char c)
{	
	register short	index, len;
	
	len = *buffer;
	
	if (len >= (VCL-1))		// if the string is full
		return;
	
	for (index = len; index > pos; index--)	// Shift characters to the right to make room
		buffer[index+1] = buffer[index];
	
	buffer[pos+1] = c;		// Fill in the new character
	
	(*buffer)++;			// Add one to the length of the string
}


void hidestring (unsigned char *cp)
{
	while (*cp)
		*cp++ = 0xa5;			/* bullet */
}


/*
 * setctltxt
 * Set a control's text
 */
void setctltxt (DialogPtr dialog, int ctl, unsigned char *text)
{
	short itemType;
	Handle itemHandle;
	Rect itemRect;

	GetDialogItem(dialog, ctl, &itemType, &itemHandle, &itemRect);
	c2pstr(text);
	SetDialogItemText(itemHandle, (StringPtr)text);
	p2cstr(text);
}


/*
 * readprefs
 */
void readprefs ()
{
	short rf = -1;
	Handle h = 0;
	
	if ((rf = openprefres(true)) == -1)
		goto defaults;
	
	if ((h = Get1Resource(PREFS_TYPE, PREFS_ID)) == 0)
		goto defaults;

	HLock(h);
	bcopy(*h, &prefs, sizeof(prefs));
	
	if (prefs.version != PVERS)
		goto defaults;
		
xit:
	if (h)
		ReleaseResource(h);
	if (rf != -1)
		CloseResFile(rf);
	return;

defaults:
	bzero(&prefs, sizeof(prefs));
	prefs.version = PVERS;
	goto xit;
}



/*
 * writeprefs
 */
void writeprefs ()
{
	OSErr s;
	short rf = -1;
	Handle h = 0;
    Rect *rectp;
	Point pt;
	GrafPtr savePort;
	
	if ((rf = openprefres(true)) == -1) {
		doalert("Could not open preferences file");
		return;
	}
	
	if ((h = Get1Resource(PREFS_TYPE, PREFS_ID)) == 0) {
		if (!(h = NewHandle(sizeof(prefs)))) {
			doalert("Could not create prefs handle");
			goto xit;
		}
		AddResource(h, PREFS_TYPE, PREFS_ID, "\pPrefs");
		if (s = ResError())
			doalert("Error creating Prefs resource: %d", s);
	} else {
		SetHandleSize(h, sizeof(prefs));
		if (s = MemError()) {
			doalert("Could not resize prefs handle: %d", s);
			goto xit;
		}
	}		

	/*
	 * Update window position
	 */
	GetPort(&savePort);
	SetPort(maind);
	rectp = &maind->portRect;
	pt.h = rectp->left;
	pt.v = rectp->top;
	LocalToGlobal(&pt);
	prefs.wrect.left = pt.h;
	prefs.wrect.top = pt.v;
	pt.h = rectp->right;
	pt.v = rectp->bottom;
	LocalToGlobal(&pt);
	prefs.wrect.right = pt.h;
	prefs.wrect.bottom = pt.v;
	SetPort(savePort);

	HLock(h);
	bcopy(&prefs, *h, sizeof(prefs));
	ChangedResource(h);
	
xit:
	if (rf != -1)
		CloseResFile(rf);
}


/*
 * openprefres
 * Open CNS Config Preferences resource file
 * return rf or -1 if error
 */
int openprefres (int create)
{
	int s;
	int rf;
	short vref;
	long dirid = 0, fold;
	SysEnvRec theWorld;
	HParamBlockRec pb;
 
	/*
	 * Try to find the Preferences folder, else use the system folder.
	 */
	if (Gestalt('fold', &fold)  || 
		((fold & 1) != 1) ||
		FindFolder(kOnSystemDisk, 'pref', false, &vref, &dirid)) {
		if (SysEnvirons (1, &theWorld) == 0)
			vref = theWorld.sysVRefNum;
		else
			vref = 0;
	}

	if ((rf = HOpenResFile(vref, dirid, prefsFilename, fsRdWrPerm)) == -1) {
		s = ResError();
		if (((s == fnfErr) || (s == eofErr)) && create) {
			HCreateResFile(vref, dirid, prefsFilename);				/* create the file */
			if (s = ResError()) {
				return -1;
			}
			/*
			 * set finder info for new file, ignore errors.
			 */
			bzero(&pb, sizeof(pb));
			pb.fileParam.ioNamePtr = prefsFilename;
			pb.fileParam.ioVRefNum = vref;
			pb.fileParam.ioFDirIndex = 0;
			pb.fileParam.ioDirID = dirid;
			if (!(rf = PBHGetFInfo(&pb, false))) {
				pb.fileParam.ioFlFndrInfo.fdType = PREFS_TYPE;
				pb.fileParam.ioFlFndrInfo.fdCreator = KCONFIG_CREATOR;
				pb.fileParam.ioNamePtr = prefsFilename;
				pb.fileParam.ioVRefNum = vref;
				pb.fileParam.ioDirID = dirid;
				(void) PBHSetFInfo(&pb, false);
			}
			/*
			 * retry open
			 */
			if ((rf = HOpenResFile(vref, dirid, prefsFilename, fsRdWrPerm)) == -1) {
				s = ResError();
				return -1;
			}
		} else {
			return -1;
		}
	}
	return rf;
}


Boolean trapAvailable (int theTrap)
{
	int tType, numToolBoxTraps;
	
	if (theTrap & 0x800) {
		tType = ToolTrap;
		theTrap &= 0x7ff;
		if (NGetTrapAddress(_InitGraf, ToolTrap) == NGetTrapAddress(0xaa6e, ToolTrap))
			numToolBoxTraps = 0x200;
		else
			numToolBoxTraps = 0x400;
		if (theTrap > numToolBoxTraps)
			theTrap = _Unimplemented;
	} else {
		tType = OSTrap;
	}
	
	return (NGetTrapAddress(theTrap, tType) != NGetTrapAddress(_Unimplemented, ToolTrap));
}


/*
 * Junk so Emacs will set local variables to be compatible with Mac/MPW.
 * Should be at end of file.
 * 
 * Local Variables:
 * tab-width: 4
 * End:
 */

