/*
 * tktlist.h
 *
 * Handle all actions of the Kerberos ticket list.
 *
 * Copyright 1994 by the Massachusetts Institute of Technology. 
 *
 * For copying and distribution information, please see the file
 * <mit-copyright.h>. 
 */

/* Only one time, please */
#ifndef	TKTLIST_DEFS
#define TKTLIST_DEFS

/*
 * Prototypes
 */
BOOL ticket_init_list(
	HWND hwnd);

void ticket_destroy(
	HWND hwnd);

LONG ticket_measureitem(
	HWND hwnd,
	WPARAM wparam,
	LPARAM lparam);

LONG ticket_drawitem(
	HWND hwnd,
	WPARAM wparam,
	LPARAM lparam);

#endif
