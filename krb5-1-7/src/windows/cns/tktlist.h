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
BOOL ticket_init_list(HWND);

void ticket_destroy(HWND);

void ticket_measureitem(HWND, MEASUREITEMSTRUCT *);

void ticket_drawitem(HWND, const DRAWITEMSTRUCT *);

#endif
