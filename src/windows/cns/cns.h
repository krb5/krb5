/*
 * cns.h
 *
 * Public Domain -- written by Cygnus Support.
 */

/* Only one time, please */
#ifndef	KWIN_DEFS
#define KWIN_DEFS

/*
 * Menu items
 */
#define FILE_MENU_ITEMS 3
#define FILE_MENU_MAX_LOGINS 5
#define IDM_KWIN 1000
	#define IDM_OPTIONS 1001
	#define IDM_EXIT 1002
	#define IDM_FIRST_LOGIN 1003

	#define IDM_HELP_INDEX 1020
	#define IDM_ABOUT 1021

/*
 * Accelerator
 */
#define IDA_KWIN 2000

/*
 * Dialog and dialog item ids
 */
#define KWIN_DIALOG_CLASS "KERBEROS"	/* class for kerberos dialog */
#define KWIN_DIALOG_NAME "Kerberos"		/* name for kerberos dialog */

#define ID_KWIN 100						/* the main kerberos dialog */
	#define IDD_KWIN_FIRST 101
		#define IDD_TICKET_LIST_TITLE 101
		#define IDD_TICKET_LIST 102

   #ifdef KRB4

      #define IDD_MIN_TITLE 103
		   #define IDD_LOGIN_NAME_TITLE 103
		   #define IDD_LOGIN_INSTANCE_TITLE 104
		   #define IDD_LOGIN_REALM_TITLE 105
		   #define IDD_LOGIN_PASSWORD_TITLE 106
	   #define IDD_MAX_TITLE 106

	   #define IDD_MIN_EDIT 107
		   #define IDD_LOGIN_NAME 107
		   #define IDD_LOGIN_INSTANCE 108
		   #define IDD_LOGIN_REALM 109
		   #define IDD_LOGIN_PASSWORD 110
	   #define IDD_MAX_EDIT 110

   #endif

   #ifdef KRB5

	   #define IDD_MIN_TITLE 103
		   #define IDD_LOGIN_NAME_TITLE 103
		   #define IDD_LOGIN_PASSWORD_TITLE 104
		   #define IDD_LOGIN_REALM_TITLE 105
	   #define IDD_MAX_TITLE 105

	   #define IDD_MIN_EDIT 107
		   #define IDD_LOGIN_NAME 107
		   #define IDD_LOGIN_PASSWORD 108
		   #define IDD_LOGIN_REALM 109
	   #define IDD_MAX_EDIT 109

   #endif

	#define IDD_MIN_BUTTON 111
		#define IDD_CHANGE_PASSWORD 111
		#define IDD_TICKET_DELETE 112
		#define IDD_LOGIN 113
	#define IDD_MAX_BUTTON 113
	#define IDD_PASSWORD_CR2 114                 // For better cr handling

	#define IDD_KWIN_LAST 114


#define ID_PASSWORD 200
	#define IDD_PASSWORD_NAME 204
	#define IDD_PASSWORD_INSTANCE 205
	#define IDD_PASSWORD_REALM 206
	#define IDD_OLD_PASSWORD 207
	#define IDD_NEW_PASSWORD1 208
	#define IDD_NEW_PASSWORD2 209
	#define IDD_PASSWORD_CR 210


#define ID_OPTS 300
	#define IDD_CONF 301
	#define IDD_REALMS 302
	#define IDD_LIFETIME 303
	#define IDD_BEEP 304
	#define IDD_ALERT 305
   #define IDD_CCACHE 306
/*
 * Dialog dimensions
 */
#define KWIN_MIN_WIDTH 180
#define KWIN_MIN_HEIGHT 110

/*
 * Icons
 */
#define IDI_KWIN 1		/* The program icon */

#define ICON_WIDTH 30	/* Width used with icons */
#define ICON_HEIGHT 20	/* Height used with icons */

#define IDI_FIRST_CLOCK 2
#define IDI_0_MIN 2		/* < 5 minutes left */
#define IDI_5_MIN 3
#define IDI_10_MIN 4
#define IDI_15_MIN 5
#define IDI_20_MIN 6
#define IDI_25_MIN 7
#define IDI_30_MIN 8
#define IDI_35_MIN 9
#define IDI_40_MIN 10
#define IDI_45_MIN 11
#define IDI_50_MIN 12
#define IDI_55_MIN 13
#define IDI_60_MIN 14
#define IDI_EXPIRED 15
#define IDI_TICKET 16
#define IDI_LAST_CLOCK 16
#define MAX_ICONS (IDI_LAST_CLOCK - IDI_FIRST_CLOCK + 1)

#ifndef RC_INVOKED

#ifdef KRB5
	extern krb5_context k5_context;
	extern krb5_ccache k5_ccache;
#endif

/*
 * Prototypes
 */

static void kwin_init_name (HWND hwnd, char *fullname);
void kwin_set_default_focus (HWND hwnd);
time_t kwin_get_epoch(void);

#ifdef KRB5
   static krb5_error_code k5_dest_tkt (void);
   static int k5_get_num_cred (int verbose);
   static int k5_kname_parse (char *name, char *realm, char *fullname);
   static int k5_get_lrealm (char *realm);
   static krb5_error_code k5_init_ccache (krb5_ccache *ccache);
   static int k5_name_from_ccache (krb5_ccache k5_ccache);
	krb5_error_code k5_change_password (
		krb5_context context,
		char *user,
		char *realm,
	   char *old_password,
	   char *new_password,
		char **text);

#endif

HICON kwin_get_icon(time_t expiration);

#endif /* RC_INVOKED */

#endif
