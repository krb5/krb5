/*
 * (c) Copyright 1994 HEWLETT-PACKARD COMPANY
 * 
 * To anyone who acknowledges that this file is provided 
 * "AS IS" without any express or implied warranty:
 * permission to use, copy, modify, and distribute this 
 * file for any purpose is hereby granted without fee, 
 * provided that the above copyright notice and this 
 * notice appears in all copies, and that the name of 
 * Hewlett-Packard Company not be used in advertising or 
 * publicity pertaining to distribution of the software 
 * without specific, written prior permission.  Hewlett-
 * Packard Company makes no representations about the 
 * suitability of this software for any purpose.
 *
 */

/* defines for pop library */

#define NOTOK (-1)
#define OK 0
#define DONE 1

#define DEFMAILHOST "mailhost"

int pop_init(), pop_getline();
char *get_errmsg();
int pop_command();
int pop_stat();
int pop_retr();
int pop_query();
char *concat();
void fatal(), error(), pfatal_with_name();

extern char Errmsg[];
