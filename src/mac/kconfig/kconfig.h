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

typedef void *queuetype;

/*
 * Resource ids
 */
#define ALERT_DOALERT	128
#define DLOG_ABOUT		129
#define DLOG_MAIN		130				/* main dialog box */
#define DLOG_DEDIT		131				/* domain edit */
#define DLOG_SEDIT		132				/* server edit */
#define DLOG_KLIST		133				/* credentials edit */
#define DLOG_KPASS		134				/* password change */

/*
 * Menu resources
 */
#define MENU_OFFSET 128					/* offset to real menu id */
enum MENUS {
	APPL_MENU = 0,						/* must be first */
	FILE_MENU,
	EDIT_MENU,
	NUM_MENUS							/* must be last */
}; 
#define MENU_SUBMENUS NUM_MENUS			/* first submenu in list */

enum FILE_MENU {
	LOGIN_FILE = 1,						/* login */
	LOGOUT_FILE,						/* logout */
	PASSWORD_FILE,						/* change password */
	LIST_FILE,							/* show credentials */
	S1_FILE,							/* --- */
	CLOSE_FILE,							/* Close Window */
	QUIT_FILE							/* Quit */
};

enum EDIT_MENU {
	UNDO_EDIT = 1,						/* undo */
	SPACE1_EDIT,						/* --- */
	CUT_EDIT,							/* cut */
	COPY_EDIT,							/* copy */
	PASTE_EDIT,							/* paste */
	CLEAR_EDIT							/* clear */
};

enum MAIN {								/* main dialog */
	MAIN_REALM = 1, 					/* realm static text */
	MAIN_L1,							/* realm label */
	MAIN_USER,							/* user static text */
	MAIN_L2,							/* user label */
	MAIN_LABEL,							/* title static text */
	MAIN_LOGIN,							/* login button */
	MAIN_LOGOUT, 						/* logout button */
	MAIN_DMAP,							/* domain map ui */
	MAIN_SERVERS,						/* servers map ui */
	MAIN_PASSWORD,						/* change password button */
	MAIN_DNEW,							/* domain new */
	MAIN_DDELETE,						/* domain delete */
	MAIN_DEDIT,							/* domain edit */
	MAIN_SNEW,							/* server new */
	MAIN_SDELETE,						/* server delete */
	MAIN_SEDIT							/* server edit */
};


/*
 * D/S EDIT DITL
 */
enum EDIT {
	EDIT_OK = 1,					/* ok button */
	EDIT_OUT,						/* button outline */
	EDIT_CANCEL,					/* cancel button */
	EDIT_E1,						/* edit field 1 */
	EDIT_L1,
	EDIT_E2,						/* edit field 2 */
	EDIT_L2,
	EDIT_ADMIN						/* admin checkbox (server only) */
};

/*
 * KLIST DITL definition
 */
enum KLIST {
	KLIST_OK = 1,					/* ok button */
	KLIST_TITLE,					/* static text title */
	KLIST_DELETE,					/* delete button */
	KLIST_LIST,						/* listing ui */
	KLIST_OUT						/* ok button outline */
};

/*
 * About picts
 */
#define PICT_ABOUT_C	128
#define PICT_ABOUT_BW	129

enum ABOUT {							/* about dialog item list */
	ABOUT_OK = 1,						/* ok button */
	ABOUT_OUT, 							/* outline ui */
	ABOUT_PICT							/* pict */
};


typedef struct domaintype_ {
	struct domaintype_ *next;
	Str255 host;
	Str255 realm;
} domaintype;

typedef struct servertype_ {
	struct servertype_ *next;
	Str255 host;
	Str255 realm;
	int admin;
} servertype;

typedef struct credentials_ {
	struct credentials_ *next;
	Str255 name;
	Str255 instance;
	Str255 realm;
	Str255 sname;
	Str255 sinstance;
	Str255 srealm;
} credentialstype;


/*
 * struct for list filter
 */
#define NNL 2
struct listfilter {
	int nlists;							/* number of lists */
	int listitem[NNL];					/* item number of list */
	int edititem[NNL];					/* item number of edit button */
	ListHandle list[NNL];				/* list handle */
};


/*
 * KPASS DITL definition
 */
enum KPASS {
	KPASS_OK = 1,					/* ok button */
	KPASS_OUT,						/* ok button outline */
	KPASS_CANCEL,					/* cancel button */
	KPASS_TITLE,					/* title static text */
	KPASS_USER,						/* username ei */
	KPASS_L1,
	KPASS_PASS,						/* password ei */
	KPASS_L3,

	KPASS_NEW,						/* new password ei */
	KPASS_L4,
	KPASS_NEW2,						/* verify password ei */
	KPASS_L5,

	KPASS_JPW = 30,					/* pseudo item to force password field */
	KPASS_JNEW,						/* pseudo item to force new pw field */
	KPASS_JNEW2
};


/*
 * struct for password hiding filter
 */
#define VCL 255							/* length of buffer */
struct valcruft {						/* for password filter */
	int flags;
	unsigned char buffer1[VCL+1+1];
	unsigned char buffer2[VCL+1+1];
	unsigned char buffer3[VCL+1+1];
};


enum EV {								/* edit menu */
	EV_UNDO = 1,
	EV_BAR,
	EV_CUT,
	EV_COPY,
	EV_PASTE
};


/*
 * Preferences
 */
#define PVERS		1
#define PREFS_ID	1
#define PREFS_TYPE 'Pref'

typedef struct prefs_ {
	unsigned short version;				/* prefs version */
	Rect wrect;							/* position rect for main window */
} preferences;



/*
 * Junk so Emacs will set local variables to be compatible with Mac/MPW.
 * Should be at end of file.
 * 
 * Local Variables:
 * tab-width: 4
 * End:
 */
