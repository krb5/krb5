#include "kerberos.h"
#define KRB_DEFS
#include "krb_driver.h"

#include <Types.h>
#include <Dialogs.h>
#include <Controls.h>
#include <ToolUtils.h>
#include <OSUtils.h>
#include <Resources.h>

/* 	added for OpenInitRF.c
 	FIXME jcm - should check that they are not in c-mac 
	or other included file
*/

#include <Errors.h>
#include <Files.h>
#include <Memory.h>
#include <Traps.h>
#include <GestaltEqu.h>
#include <Folders.h>


// #include "debug.h"

#define kLoginDLOGID		-4081
#define kErrorALERTID		-4082
#define kLoginOKItem		1
#define kLoginCnclItem		2
#define kLoginNameItem		10
#define kLoginVisPwItem		9
#define kLoginFrameItem		5
#define kLoginIvisPwItem	6
#define kBadUserError		1
#define kNotUniqueError		2
#define kGenError			3
#define kIntegrityError		4
#define kBadPasswordError	5
#define cr 					0x0D
#define enter 				0x03
#define bs 					0x08
#define tab 				0x09
#define larrow 				0x1C
#define rarrow 				0x1D
#define uarrow 				0x1E
#define darrow 				0x1F
#define DialogNotDone 		1

typedef union {								// used to convert ProcPtr to Handle
	Handle		H;
	ProcPtr		P;
} Proc2Hand;

static char gPassword [MAX_K_NAME_SZ]	= "\0";

pascal void FrameOKbtn( WindowPtr myWindow, short itemNo );
pascal Boolean TwoItemFilter( DialogPtr dlog, EventRecord *event, short *itemHit );

/* 
	FIXME jcm - begin OpenInitRF
	Mac_store thinks that it is managing the open resource file
	is this code in conflict?
*/

void GetExtensionsFolder(short *vRefNumP, long *dirIDP)
{
	Boolean hasFolderMgr = false;
	long feature;
	
/*	
	FIXME Error:   ‘_GestaltDispatch’ has not been declared - not needed now? - jcm
	if (TrapAvailable(_GestaltDispatch)) 
*/
	if (Gestalt(gestaltFindFolderAttr, &feature) == noErr) hasFolderMgr = true;
	if (!hasFolderMgr) {
		GetSystemFolder(vRefNumP, dirIDP);
		return;
	}
	else {
		if (FindFolder(kOnSystemDisk, kExtensionFolderType, kDontCreateFolder, vRefNumP, dirIDP) != noErr) {
			*vRefNumP = 0;
			*dirIDP = 0;
		}
	}
}
	
short SearchFolderForINIT(long targetType, long targetCreator, short vRefNum, long dirID)
{
	HParamBlockRec fi;
	Str255 filename;
	short refnum;
	
	fi.fileParam.ioCompletion = nil;
	fi.fileParam.ioNamePtr = filename;
	fi.fileParam.ioVRefNum = vRefNum;
	fi.fileParam.ioDirID = dirID;
	fi.fileParam.ioFDirIndex = 1;
	
	while (PBHGetFInfo(&fi, false) == noErr) {
		/* scan system folder for driver resource files of specific type & creator */
		if (fi.fileParam.ioFlFndrInfo.fdType == targetType &&
			fi.fileParam.ioFlFndrInfo.fdCreator == targetCreator) {
			refnum = HOpenResFile(vRefNum, dirID, filename, fsRdPerm);
			return refnum;
			}
		/* check next file in folder */
		fi.fileParam.ioFDirIndex++;
		fi.fileParam.ioDirID = dirID;	/* PBHGetFInfo() clobbers ioDirID */
		}
	return(-1);
}	

short OpenInitRF()
{
	short refnum;
	short vRefNum;
	long dirID;
	
	/* first search Extensions Panels */
	GetExtensionsFolder(&vRefNum, &dirID);
	refnum = SearchFolderForINIT('INIT', 'krbL', vRefNum, dirID);
	if (refnum != -1) return(refnum);
		
	/* next search System Folder  */
	GetSystemFolder(&vRefNum, &dirID);
	refnum = SearchFolderForINIT('INIT', 'krbL', vRefNum, dirID);
	if (refnum != -1) return(refnum);
		
	/* finally, search Control Panels */
	GetCPanelFolder(&vRefNum, &dirID);
	refnum = SearchFolderForINIT('INIT', 'krbL', vRefNum, dirID);
	if (refnum != -1) return(refnum);
		
	return -1;
}	

int DisplayError( short errorID )
{
	OSErr			err;
	Str255			errText;
	
	GetIndString(errText,kErrorALERTID,errorID);
	if (errText[0] == 0) {
		SysBeep(1);		// nothing else we can do
		return cKrbCorruptedFile;
	}

	ParamText(errText,"\p","\p","\p");
	err = StopAlert(kErrorALERTID,nil);
	
	return DialogNotDone;
}



OSErr GetUserInfo( char *password )
{
	DialogPtr		myDLOG;
	short			itemHit;
	short			itemType;
	Handle			itemHandle;
	Rect			itemRect;
	OSErr			rc = DialogNotDone;
	Str255			tempStr,tpswd,tuser;
	Proc2Hand		procConv;
	short			rf;
	char uname[ANAME_SZ]="\0";
	char uinst[INST_SZ]="\0";
	char realm[REALM_SZ]="\0";
	char UserName[MAX_K_NAME_SZ]="\0";
	CursHandle		aCursor;
	
	krb_get_lrealm (realm, 1);

	//////////////////////////////////////////////////////
	// already got a password, just get the initial ticket
	//////////////////////////////////////////////////////
	if (*gPassword)	{
		strncpy (UserName, krb_get_default_user( ), sizeof(UserName)-1);
		UserName[sizeof(UserName) - 1] = '\0';
		/* FIXME jcm - if we have a password then no dialog 
		   comes up for setting the uinstance. */
		rc = kname_parse(uname, uinst, realm, UserName);
			if (rc) return rc;
		(void) dest_all_tkts();		// start from scratch
		rc = krb_get_pw_in_tkt(uname,uinst,realm,"krbtgt",realm,DEFAULT_TKT_LIFE,gPassword);
		*gPassword = 0;		// Always clear, password only good for one shot
		return rc;
	}
	
	/////////////////////////
	// Ask user for password
	/////////////////////////
	rf = OpenInitRF();		// need the resource file for the dialog resources
	if (rf<=0) return rf;
	password[0] = 0;
	myDLOG = GetNewDialog( kLoginDLOGID, (void *) NULL, (WindowPtr) -1 );
	if( myDLOG == NULL ) {
		CloseResFile(rf);
		return cKrbCorruptedFile;
	}

	// Insert user's name in dialog
	strncpy (UserName, krb_get_default_user( ), sizeof(UserName) - 1);
	UserName[sizeof(UserName) - 1] = '\0';
	if (*UserName) {
		tempStr[0] = strlen(UserName);
		memcpy( &(tempStr[1]), UserName, tempStr[0]);
		GetDItem( myDLOG, kLoginNameItem, &itemType, &itemHandle, &itemRect );
		SetIText( itemHandle, tempStr );
		SelIText( myDLOG, kLoginVisPwItem,0,0 );
	}
	else SelIText( myDLOG, kLoginNameItem,0,0 );
	
	// Establish a user item around the OK button to draw the default button frame in
	GetDItem( myDLOG, kLoginOKItem, &itemType, &itemHandle, &itemRect );
	InsetRect( &itemRect, -4, -4 );				// position user item around OK button
	procConv.P = (ProcPtr) FrameOKbtn;			// convert ProcPtr to a Handle
	SetDItem( myDLOG, kLoginFrameItem, userItem, procConv.H, &itemRect );
	
	InitCursor();
	do {
		do {										// display the dialog & handle events
			SetOKEnable(myDLOG);
			ModalDialog( (ModalFilterProcPtr) TwoItemFilter, (short *) &itemHit );
		} while( itemHit != kLoginOKItem && itemHit != kLoginCnclItem );
		
		if( itemHit == kLoginOKItem ) {				// OK button pressed?			
			GetDItem( myDLOG, kLoginNameItem, &itemType, &itemHandle, &itemRect );
			GetIText( itemHandle, tempStr );
		
			tempStr[0] = ( tempStr[0] < MAX_K_NAME_SZ ) ? tempStr[0] : MAX_K_NAME_SZ-1 ;
			memcpy ((void*) UserName, (void*) &(tempStr[1]), tempStr[0]);
			UserName[tempStr[0]] = 0;
			
			GetDItem( myDLOG, kLoginIvisPwItem, &itemType, &itemHandle, &itemRect );
			GetIText( itemHandle, tempStr );
		
			tempStr[0] = ( tempStr[0] < ANAME_SZ ) ? tempStr[0] : ANAME_SZ-1 ;
			memcpy( (void*) password, (void*) &(tempStr[1]), tempStr[0]);
			password[tempStr[0]] = 0;

			//----------------------------------------------------
			// Get the ticket
			//----------------------------------------------------
			aCursor = GetCursor(watchCursor);
			SetCursor(*aCursor);
			ShowCursor();
			
			rc = kname_parse(uname, uinst, realm, UserName);
			if (rc) return rc;

			(void) dest_all_tkts();		// start from scratch
			rc = krb_get_pw_in_tkt(uname,uinst,realm,"krbtgt",realm,DEFAULT_TKT_LIFE,password);
			InitCursor();
			if (!rc) 
			switch (rc) {
				case KDC_PR_UNKNOWN:
				case KDC_NULL_KEY:
					rc = DisplayError(kBadUserError);
					SelIText( myDLOG, kLoginNameItem,0,256 );
					break;
				case KDC_PR_N_UNIQUE:
					rc = DisplayError(kNotUniqueError);
					SelIText( myDLOG, kLoginNameItem,0,256 );
					break;
				case KDC_GEN_ERR:
					rc = DisplayError(kGenError);
					SelIText( myDLOG, kLoginNameItem,0,256 );
					break;
				case RD_AP_MODIFIED:
					rc = DisplayError(kIntegrityError);
					SelIText( myDLOG, kLoginNameItem,0,256 );
					break;
				case INTK_BADPW:
					rc = DisplayError(kBadPasswordError);
					SelIText( myDLOG, kLoginVisPwItem,0,256 );
					break;
				default:
					break;
			}
			//----------------------------------------------------
		}
		else rc = cKrbUserCancelled;						// pressed the Cancel button
	} while( rc == DialogNotDone );

	DisposDialog( myDLOG );
	CloseResFile(rf);
	return rc;
}


static pascal void FrameOKbtn( WindowPtr myWindow, short itemNo )
{
	short		tempType;
	Handle		tempHandle;
	Rect		itemRect;

	GetDItem( (DialogPtr) myWindow, itemNo, &tempType, &tempHandle, &itemRect );
	PenSize( 3, 3 );
	FrameRoundRect( &itemRect, 16, 16 );		// make it an OK button suitable for framing
}


static pascal Boolean TwoItemFilter( DialogPtr dlog, EventRecord *event, short *itemHit )
{
	DialogPtr	evtDlog;
	short		selStart, selEnd;
	Handle		okBtnHandle;
	short		tempType;
	Rect		tempRect;
	long		tempTicks;

	if( event->what != keyDown && event->what != autoKey )
		return false;				// don't care about this event

	switch( event->message & charCodeMask )
	{
	case cr:						// Return  (hitting return or enter is the same as hitting the OK button)
	case enter:						// Enter
	
		if (!OKIsEnabled(dlog)) {
			event->what = nullEvent;
			return false;
		}
		
		GetDItem( dlog, kLoginOKItem, &tempType, &okBtnHandle, &tempRect );
		HiliteControl( (ControlHandle) okBtnHandle, 1 );	// hilite the OK button
		Delay( 10, &tempTicks );	// wait a little while
		HiliteControl( (ControlHandle) okBtnHandle, 0 );

		*itemHit = kLoginOKItem;		// OK Button
		return true;				// We handled the event

	case tab:						// Tab
	case larrow:					// Left arrow  (Keys that just change the selection)
	case rarrow:					// Right arrow
	case uarrow:					// Up arrow
	case darrow:					// Down arrow
		return false;				// Let ModalDialog handle them

	default:
	
		// First see if we're in password field, do stuff to make • displayed
		
		if( ((DialogPeek) dlog)->editField == kLoginVisPwItem - 1 ) {

			selStart = (**((DialogPeek) dlog)->textH).selStart;	// Get the selection in the visible item
			selEnd = (**((DialogPeek) dlog)->textH).selEnd;

			SelIText( dlog, kLoginIvisPwItem, selStart, selEnd );	// Select text in invisible item
			DialogSelect( event,&evtDlog, itemHit );			// Input key

			SelIText( dlog, kLoginVisPwItem, selStart, selEnd );	// Select same area in visible item
			if( ( event->message & charCodeMask ) != bs )		// If it's not a backspace (backspace is the only key that can affect both the text and the selection- thus we need to process it in both fields, but not change it for the hidden field.
				event->message = '•';							// Replace with character to use
		}
		
		// Do the key event and set the hilite on the OK button accordingly
		
		DialogSelect( event,&evtDlog, itemHit );			// Input key
		SetOKEnable(dlog);
		
		// Pass a NULL event back to DialogMgr
		
		event->what = nullEvent;
		
		return false;
	}
}

static int SetOKEnable( DialogPtr dlog )
{
	short		itemType,state;
	Handle		itemHandle;
	Rect		itemRect;
	Str255		tpswd,tuser;
	ControlHandle okButton;

	GetDItem( dlog, kLoginNameItem, &itemType, &itemHandle, &itemRect );
	GetIText( itemHandle, tuser );
	GetDItem( dlog, kLoginVisPwItem, &itemType, &itemHandle, &itemRect );
	GetIText( itemHandle, tpswd );
	GetDItem( dlog, kLoginOKItem, &itemType, (Handle *) &okButton, &itemRect );
	state = (tuser[0] && tpswd[0]) ? 0 : 255;
	HiliteControl(okButton,state);
}

static int OKIsEnabled( DialogPtr dlog )
{
	short		itemType;
	Rect		itemRect;
	ControlHandle okButton;

	GetDItem( dlog, kLoginOKItem, &itemType, (Handle *) &okButton, &itemRect );
	return ((**okButton).contrlHilite != 255);
}


extern OSErr INTERFACE 
CacheInitialTicket( serviceName )
     char *serviceName;
{
	char service[ANAME_SZ]="\0";
	char instance[INST_SZ]="\0";
	char realm[REALM_SZ]="\0";
	OSErr err = noErr;
	char uname[ANAME_SZ]="\0";
	char uinst[INST_SZ]="\0";
	char urealm[REALM_SZ]="\0";
	char password[KKEY_SZ]="\0";
	char UserName[MAX_K_NAME_SZ]="\0";
	char oldName[120]="\0";	
								
	err = GetUserInfo( password );
	if (err) return err;
	
	if (!serviceName || (serviceName[0] == '\0'))
		return err;
	
	strncpy (UserName, krb_get_default_user(), sizeof(UserName) - 1);
	UserName[sizeof(UserName) - 1] = '\0';
			
 	err = kname_parse(uname, uinst, urealm, UserName);
 	if (err) return err;
 	
 	if (urealm[0] == '\0')
 		krb_get_lrealm (urealm, 1);
	
	err = kname_parse(service, instance, realm, serviceName); // check if there is a service name
	if (err) return err;
	
	err = krb_get_pw_in_tkt(uname,uinst,urealm,service,instance,DEFAULT_TKT_LIFE,password);
	return err;
}
