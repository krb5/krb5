/*
 * Copyright 1993 OpenVision Technologies, Inc., All Rights Reserved
 *
 * $Header$
 * 
 * $Log$
 * Revision 1.4  1996/07/22 20:26:31  marc
 * this commit includes all the changes on the OV_9510_INTEGRATION and
 * OV_MERGE branches.  This includes, but is not limited to, the new openvision
 * admin system, and major changes to gssapi to add functionality, and bring
 * the implementation in line with rfc1964.  before committing, the
 * code was built and tested for netbsd and solaris.
 *
 * Revision 1.3.4.1  1996/07/18 03:02:26  marc
 * merged in changes from OV_9510_BP to OV_9510_FINAL1
 *
 * Revision 1.3.2.1  1996/06/20  21:48:39  marc
 * File added to the repository on a branch
 *
 * Revision 1.3  1994/04/11  23:52:10  jik
 * Sandbox:
 *
 *  Include <com_err.h> to get the declaration of error_message.
 *
 * Revision 1.3  1994/03/29  21:18:54  jik
 * Include <com_err.h> to get the declaration of error_message.
 *
 * Revision 1.2  1993/12/21  18:59:25  shanzer
 * make sure we prompt for input from /dev/tty
 *
 * Revision 1.1  1993/11/14  23:51:04  shanzer
 * Initial revision
 *
 */

#if !defined(lint) && !defined(__CODECENTER__)
static char *rcsid = "$Header$";
#endif

#include    <stdio.h>
#include    <com_err.h> /* for error_message() */
#include    "import_err.h"

#ifndef TRUE
#define TRUE (1);
#endif
#ifndef FALSE
#define	FALSE (0);
#endif

/*
 * Function: confirm
 * 
 * Purpose: ask a yes or no question you must answer
 *	    with a 'y|n|Y|n'
 *
 * Arguments:
 *	(input) none
 *	<return value> 1 if answered yes. 0 if no.
 *
 * Requires:
 *	IMPORT_CONFIRM be be defined. and com_err be init.
 * 
 * Effects:
 *	none
 *
 * Modifies:
 *	nuttin
 * 
 */

int
confirm(void)
{
    char    buf[BUFSIZ];    /* can we say overkill ... */
    FILE    *fp;

    if ((fp = fopen("/dev/tty", "r")) == NULL) {
	fprintf(stderr, error_message(IMPORT_TTY));
	return FALSE;
    }
    while(1) {
	fprintf(stderr, error_message(IMPORT_CONFIRM));
	fgets(buf, BUFSIZ, fp);
	if(buf[0] == 'y' || buf[0] == 'Y') {
	    fclose(fp);
	    return TRUE;
	}
	if(buf[0] == 'n' || buf[0] == 'N') {
	    fclose(fp);
	    return FALSE;
	}
    }
}
    
