/*
 * admin/edit/ss_wrapper.c
 *
 * Copyright 1990,1991 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * Export of this software from the United States of America may
 *   require a specific license from the United States Government.
 *   It is the responsibility of any person or organization contemplating
 *   export to obtain such a license before exporting.
 * 
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of M.I.T. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 * 
 *
 * ss wrapper for kdb5_edit
 */

#include "k5-int.h"
#include "kdb5_edit.h"
#include <ss/ss.h>
#include <stdio.h>

extern ss_request_table kdb5_edit_cmds;
extern int exit_status;
extern FILE *scriptfile;

int sci_idx;

int main(argc, argv)
    int argc;
    char *argv[];
{
    char *request;
    krb5_error_code retval;
    int code = 0;

    request = kdb5_edit_Init(argc, argv);
    sci_idx = ss_create_invocation("kdb5_edit", "5.0", (char *) NULL,
				   &kdb5_edit_cmds, &retval);
    if (retval) {
	ss_perror(sci_idx, retval, "creating invocation");
	exit(1);
    }

    if (request) {
	    code = ss_execute_line(sci_idx, request, &code);
	    if (code != 0) {
		    ss_perror(sci_idx, code, request);
		    exit_status++;
	    }
    } else if (scriptfile) {
	char *command;
	int nread;

	/* Get a buffer */
	if ((command = (char *) malloc(BUFSIZ))) {
	    /* Process commands from the script until end-of-file or error */
	    while (!feof(scriptfile) &&
		   (fgets(command, BUFSIZ, scriptfile))) {

		/* Strip trailing newline */
		if (command[strlen(command)-1] == '\n')
		    command[strlen(command)-1] = '\0';

		/* Execute the command */
		code = ss_execute_line(sci_idx, command, &code);
		if (code != 0) {
		    ss_perror(sci_idx, code, command);
		    exit_status++;
		    break;
		}
	    }
	    free(command);
	}
    } else
	    ss_listen(sci_idx, &retval);
    return quit() ? 1 : exit_status;
}
