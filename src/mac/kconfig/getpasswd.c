/*
 * getpasswd.c
 * ripped from krb4
 */

#define cKrbUserCancelled	2
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
	
		// First see if we're in password field, do stuff to make ¥ displayed
		
		if( ((DialogPeek) dlog)->editField == kLoginVisPwItem - 1 ) {

			selStart = (**((DialogPeek) dlog)->textH).selStart;	// Get the selection in the visible item
			selEnd = (**((DialogPeek) dlog)->textH).selEnd;

			SelIText( dlog, kLoginIvisPwItem, selStart, selEnd );	// Select text in invisible item
			DialogSelect( event,&evtDlog, itemHit );			// Input key

			SelIText( dlog, kLoginVisPwItem, selStart, selEnd );	// Select same area in visible item
			if( ( event->message & charCodeMask ) != bs )		// If it's not a backspace (backspace is the only key that can affect both the text and the selection- thus we need to process it in both fields, but not change it for the hidden field.
				event->message = '¥';							// Replace with character to use
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

#define ANAME_SZ	100
#define	INST_SZ		100
#define REALM_SZ	100
#define MAX_K_NAME_SZ	100

OSErr GetUserInfo( char *UserName, char *password )
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
	CursHandle		aCursor;
		
	/////////////////////////
	// Ask user for password
	/////////////////////////
	password[0] = 0;
	myDLOG = GetNewDialog( kLoginDLOGID, (void *) NULL, (WindowPtr) -1 );
	if( myDLOG == NULL ) {
		return -1;
	}

	// Insert user's name in dialog
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

			rc = !DialogNotDone;
		}
		else rc = cKrbUserCancelled;						// pressed the Cancel button
	} while( rc == DialogNotDone );

	DisposDialog( myDLOG );
	return rc;
}
