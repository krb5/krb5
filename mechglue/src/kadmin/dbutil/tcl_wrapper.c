/*
 * admin/edit/tcl_wrapper.c
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
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 * 
 *
 * Tcl wrapper for kdb5_edit
 */

#include "k5-int.h"
#include "kdb5_edit.h"
#ifdef HAVE_TCL_H
#include <tcl.h>
#elif defined(HAVE_TCL_TCL_H)
#include <tcl/tcl.h>
#endif

#define CMDDECL(x) int x(clientData, interp, argc, argv)\
    ClientData clientData;\
    Tcl_Interp * interp;\
    int argc;\
    char ** argv;
#define CMDPROTO(x) int x (ClientData, Tcl_Interp, int, char **)
#define MKCMD(name,cmd) Tcl_CreateCommand(interp, name, cmd,\
					 (ClientData)NULL,\
					 (Tcl_CmdDeleteProc *)NULL)

extern int main();
int *tclDummyMainPtr = (int *) main; /* force ld to suck in main()
					from libtcl.a */
extern Tcl_Interp *interp;	/* XXX yes, this is gross,
				   but we do need it for some things */
extern int exit_status;

void show_principal (int, char **);
void add_new_key (int, char **);
void change_pwd_key (int, char **);
void add_rnd_key (int, char **);
void change_rnd_key (int, char **);
void delete_entry (int, char **);
void extract_srvtab (krb5_context, int, char **);
void extract_v4_srvtab (int, char **);
void list_db (int, char **);
void dump_db (int, char **);
void load_db (int, char **);
void set_dbname (krb5_context, int, char **);
void enter_master_key (krb5_context, int, char **);

/*
 * this is mostly stolen from tcl_ExitCmd()
 * we need to do a few extra things, though...
 */
int doquit(clientData, interp, argc, argv)
    ClientData clientData;
    Tcl_Interp *interp;
    int argc;
    char *argv[];
{
    int value;

    if ((argc != 1) && (argc != 2)) {
	Tcl_AppendResult(interp, "wrong # args: should be \"", argv[0],
		" ?returnCode?\"", (char *) NULL);
	return TCL_ERROR;
    }
    if (argc == 1) {
	exit(quit() ? 1 : exit_status);
    }
    if (Tcl_GetInt(interp, argv[1], &value) != TCL_OK) {
	return TCL_ERROR;
    }
    (void)quit();
    exit(value);
    /*NOTREACHED*/
    return TCL_OK;			/* Better not ever reach this! */
}

int list_requests(clientData, interp, argc, argv)
    ClientData clientData;
    Tcl_Interp *interp;
    int argc;
    char *argv[];
{
    Tcl_SetResult(interp, "show_principal, show: Show the Kerberos database entry for a principal\nadd_new_key, ank: Add new entry to the Kerberos database (prompting for password\nchange_pwd_key, cpw: Change key of an entry in the Kerberos database (prompting for password)\nadd_rnd_key, ark: Add new entry to Kerberos database, using a random key\nchange_rnd_key, crk: Change key of an entry in the Kerberos database (select a random key)\ndelete_entry, delent: Delete an entry from the database\nextract_srvtab, xst, ex_st: Extract service key table\nextract_v4_srvtab, xst4: Extract service key table\nlist_db, ldb: List database entries\nset_dbname, sdbn: Change database name\nenter_master_key, emk: Enter the master key for a database\nchange_working_directory, cwd, cd: Change working directory\nprint_working_directory, pwd: Print working directory\nlist_requests, lr: List available requests\nquit, exit: Exit program", TCL_STATIC);
    return TCL_OK;
}

int wrapper(func, interp, argc, argv)
    void (*func)();
    Tcl_Interp *interp;
    int argc;
    char *argv[];
{
    (*func)(argc, argv);
    return TCL_OK;
}

int Tcl_AppInit(interp)
    Tcl_Interp *interp;
{
    int argc;
    char **argv, **mostly_argv;
    char *interp_argv, *interp_argv0, *request;
    Tcl_CmdInfo cmdInfo;

    if (Tcl_Init(interp) == TCL_ERROR)
	return TCL_ERROR;
    /*
     * the following is, admittedly, sorta gross, but the only way
     * to grab the original argc, argv once the interpreter is running
     */
    interp_argv = Tcl_GetVar(interp, "argv", 0);
    if (interp_argv == NULL)
	return TCL_ERROR;
    else if (Tcl_SplitList(interp, interp_argv,
			   &argc, &mostly_argv) != TCL_OK)
	return TCL_ERROR;
    interp_argv0 = Tcl_GetVar(interp, "argv0", 0);
    if (interp_argv0 == NULL)
	return TCL_ERROR;
    if ((argv = (char **)malloc((argc + 1) * sizeof (char *))) == NULL)
	return TCL_ERROR;
    argv[0] = interp_argv0;
    memcpy(argv + 1, mostly_argv, argc++ * sizeof (char *));
    /*
     * set up a prompt
     */
    if (Tcl_SetVar(interp, "tcl_prompt1",
		   "puts -nonewline \"kdb5_edit: \"", 0) == NULL)
	return TCL_ERROR;
    /*
     * we don't want arbitrary programs to get exec'd by accident
     */
    if (Tcl_SetVar(interp, "auto_noexec", "{}", 0) == NULL)
	return TCL_ERROR;
    request = kdb5_edit_Init(argc, argv);
    Tcl_CallWhenDeleted(interp, doquit,
			(ClientData)0);
    Tcl_CreateCommand(interp, "quit", doquit,
		      (ClientData)0,
		      (Tcl_CmdDeleteProc *)0);
    Tcl_CreateCommand(interp, "exit", doquit,
		      (ClientData)0,
		      (Tcl_CmdDeleteProc *)0);
    Tcl_CreateCommand(interp, "list_requests", list_requests,
		      (ClientData)0,
		      (Tcl_CmdDeleteProc *)0);
    Tcl_CreateCommand(interp, "lr", list_requests,
		      (ClientData)0,
		      (Tcl_CmdDeleteProc *)0);
    if (Tcl_GetCommandInfo(interp, "cd", &cmdInfo)) {
	Tcl_CreateCommand(interp, "cwd", cmdInfo.proc,
			  (ClientData)0,
			  (Tcl_CmdDeleteProc *)0);
	Tcl_CreateCommand(interp, "change_working_directory", cmdInfo.proc,
			  (ClientData)0,
			  (Tcl_CmdDeleteProc *)0);
    }
    if (Tcl_GetCommandInfo(interp, "pwd", &cmdInfo)) {
	Tcl_CreateCommand(interp, "print_working_directory", cmdInfo.proc,
			  (ClientData)0,
			  (Tcl_CmdDeleteProc *)0);
    }
    Tcl_CreateCommand(interp, "show_principal", wrapper, show_principal,
		      (Tcl_CmdDeleteProc *)0);
    Tcl_CreateCommand(interp, "show", wrapper, show_principal,
		      (Tcl_CmdDeleteProc *)0);
    Tcl_CreateCommand(interp, "add_new_key", wrapper, add_new_key,
		      (Tcl_CmdDeleteProc *)0);
    Tcl_CreateCommand(interp, "ank", wrapper, add_new_key,
		      (Tcl_CmdDeleteProc *)0);
    Tcl_CreateCommand(interp, "change_pwd_key", wrapper, change_pwd_key,
		      (Tcl_CmdDeleteProc *)0);
    Tcl_CreateCommand(interp, "cpw", wrapper, change_pwd_key,
		      (Tcl_CmdDeleteProc *)0);
    Tcl_CreateCommand(interp, "add_rnd_key", wrapper, add_rnd_key,
		      (Tcl_CmdDeleteProc *)0);
    Tcl_CreateCommand(interp, "ark", wrapper, add_rnd_key,
		      (Tcl_CmdDeleteProc *)0);
    Tcl_CreateCommand(interp, "change_rnd_key", wrapper, change_rnd_key,
		      (Tcl_CmdDeleteProc *)0);
    Tcl_CreateCommand(interp, "crk", wrapper, change_rnd_key,
		      (Tcl_CmdDeleteProc *)0);
    Tcl_CreateCommand(interp, "delete_entry", wrapper, delete_entry,
		      (Tcl_CmdDeleteProc *)0);
    Tcl_CreateCommand(interp, "delent", wrapper, delete_entry,
		      (Tcl_CmdDeleteProc *)0);
    Tcl_CreateCommand(interp, "extract_srvtab", wrapper, extract_srvtab,
		      (Tcl_CmdDeleteProc *)0);
    Tcl_CreateCommand(interp, "xst", wrapper, extract_srvtab,
		      (Tcl_CmdDeleteProc *)0);
    Tcl_CreateCommand(interp, "ex_st", wrapper, extract_srvtab,
		      (Tcl_CmdDeleteProc *)0);
    Tcl_CreateCommand(interp, "extract_v4_srvtab", wrapper, extract_v4_srvtab,
		      (Tcl_CmdDeleteProc *)0);
    Tcl_CreateCommand(interp, "xv4st", wrapper, extract_v4_srvtab,
		      (Tcl_CmdDeleteProc *)0);
    Tcl_CreateCommand(interp, "list_db", wrapper, list_db,
		      (Tcl_CmdDeleteProc *)0);
    Tcl_CreateCommand(interp, "ldb", wrapper, list_db,
		      (Tcl_CmdDeleteProc *)0);
    Tcl_CreateCommand(interp, "dump_db", wrapper, dump_db,
		      (Tcl_CmdDeleteProc *)0);
    Tcl_CreateCommand(interp, "ddb", wrapper, dump_db,
		      (Tcl_CmdDeleteProc *)0);
    Tcl_CreateCommand(interp, "load_db", wrapper, load_db,
		      (Tcl_CmdDeleteProc *)0);
    Tcl_CreateCommand(interp, "lddb", wrapper, load_db,
		      (Tcl_CmdDeleteProc *)0);
    Tcl_CreateCommand(interp, "set_dbname", wrapper, set_dbname,
		      (Tcl_CmdDeleteProc *)0);
    Tcl_CreateCommand(interp, "sdbn", wrapper, set_dbname,
		      (Tcl_CmdDeleteProc *)0);
    Tcl_CreateCommand(interp, "enter_master_key", wrapper, enter_master_key,
		      (Tcl_CmdDeleteProc *)0);
    Tcl_CreateCommand(interp, "emk", wrapper, enter_master_key,
		      (Tcl_CmdDeleteProc *)0);
    if (request && (Tcl_Eval(interp, request) == TCL_ERROR))
	return TCL_ERROR;
    return TCL_OK;
}
